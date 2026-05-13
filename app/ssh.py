import base64
import hashlib
import io
import json
import logging
import os
import shlex

import paramiko

import db


# ---------------------------------------------------------------------------
# SSH exceptions - typed hierarchy for safer error handling
# ---------------------------------------------------------------------------

class SSHError(RuntimeError):
    """Base SSH error - catch this to handle all SSH failures."""
    error_code = "SSH_FAILED"


class SSHAuthError(SSHError):
    error_code = "SSH_AUTH_FAILED"


class SSHTimeoutError(SSHError):
    error_code = "SSH_TIMEOUT"


class SSHUnreachableError(SSHError):
    error_code = "SSH_UNREACHABLE"


class SSHPortRefusedError(SSHError):
    error_code = "SSH_PORT_REFUSED"


class SSHSudoError(SSHError):
    error_code = "SSH_SUDO_FAILED"


class SSHScriptError(SSHError):
    error_code = "SSH_SCRIPT_FAILED"


# Aliases for backward compatibility
SudoError = SSHSudoError
ScriptError = SSHScriptError


KNOWN_HOSTS = os.environ.get("KNOWN_HOSTS", "/data/keys/known_hosts")
SSH_USER = os.environ.get("SSH_USER", "audit-collector")
PER_SERVER_KEYS_DIR = "/data/keys/per-server"

SAM_COLLECT_PATH = "/usr/local/bin/sam-collect"
SAM_REVOKE_PATH = "/usr/local/bin/sam-revoke"
SAM_ADD_PATH = "/usr/local/bin/sam-add"
SAM_LOCK_USER_PATH = "/usr/local/bin/sam-lock-user"
SAM_UNLOCK_USER_PATH = "/usr/local/bin/sam-unlock-user"

# ---------------------------------------------------------------------------
# Remote scripts - versioned as Python constants.
# Deployed via SFTP if absent or if SHA256 hash differs.
# ---------------------------------------------------------------------------

SAM_COLLECT = b"""#!/bin/sh
# sam-collect - list all authorized_keys on the system
set -e

# Some distros pre-create system accounts that share a home directory
# (notably `operator:x:11:0:operator:/root:...` on RHEL/Rocky, sometimes
# additional ones with home=`/`). Without deduplication every key in
# /root/.ssh/authorized_keys would also be attributed to operator,
# inflating the anomaly list with phantom rows.
#
# Strategy: track the realpath of each authorized_keys we've already
# emitted and skip if it has been seen -- the FIRST user encountered
# with that file owns it. /etc/passwd iteration order is stable per scan.
seen_files=""

emit_file() {
    user="$1"
    keyfile="$2"
    [ -f "$keyfile" ] || return 0
    real=$(readlink -f "$keyfile" 2>/dev/null || echo "$keyfile")
    case " ${seen_files} " in
        *" ${real} "*) return 0 ;;
    esac
    seen_files="${seen_files} ${real}"
    while IFS= read -r line || [ -n "$line" ]; do
        [ -z "$line" ] && continue
        case "$line" in '#'*) continue ;; esac
        printf '%s\\t%s\\n' "$user" "$line"
    done < "$keyfile"
}

# Root first so /root/.ssh/authorized_keys is always attributed to
# the root account, even if another system user (e.g. operator)
# shares home=/root and would otherwise win the iteration race.
emit_file root /root/.ssh/authorized_keys

getent passwd | while IFS=: read user _ _ _ _ home _; do
    [ "$user" = "root" ] && continue
    emit_file "$user" "${home}/.ssh/authorized_keys"
done
"""

SAM_REVOKE = b"""#!/bin/sh
# sam-revoke <fingerprint> [unix_user]
# If unix_user is given: revoke only from that user's authorized_keys.
# Otherwise: revoke from all users (global).
set -e

TARGET_FP="${1}"
TARGET_USER="${2}"

if [ -z "$TARGET_FP" ]; then
    echo "Usage: sam-revoke <SHA256:base64> [unix_user]" >&2
    exit 1
fi

revoke_from_file() {
    keyfile="$1"
    [ -f "$keyfile" ] || return 0
    tmp=$(mktemp /tmp/sam-XXXXXX)
    changed=0
    while IFS= read -r line || [ -n "$line" ]; do
        case "$line" in
            ''|'#'*) printf '%s\\n' "$line" >> "$tmp"; continue ;;
        esac
        ktmp=$(mktemp /tmp/sam-XXXXXX)
        printf '%s\\n' "$line" > "$ktmp"
        fp=$(ssh-keygen -l -E sha256 -f "$ktmp" 2>/dev/null | awk '{print $2}')
        rm -f "$ktmp"
        if [ "$fp" = "$TARGET_FP" ]; then
            changed=1
        else
            printf '%s\\n' "$line" >> "$tmp"
        fi
    done < "$keyfile"
    if [ "$changed" -eq 1 ]; then
        dir_owner=$(stat -c '%u:%g' "$(dirname "$keyfile")")
        chmod 600 "$tmp"
        chown "$dir_owner" "$tmp"
        mv "$tmp" "$keyfile"
    else
        rm -f "$tmp"
    fi
}

if [ -n "$TARGET_USER" ]; then
    if [ "$TARGET_USER" = "root" ]; then
        revoke_from_file "/root/.ssh/authorized_keys"
    else
        home=$(getent passwd "$TARGET_USER" | cut -d: -f6)
        [ -n "$home" ] && revoke_from_file "${home}/.ssh/authorized_keys"
    fi
else
    getent passwd | while IFS=: read user _ _ _ _ home _; do
        revoke_from_file "${home}/.ssh/authorized_keys"
    done
    revoke_from_file "/root/.ssh/authorized_keys"
fi
"""

SAM_ADD = b"""#!/bin/sh
# sam-add <username> <pubkey> [group] - create user if absent, add pubkey, set SAM group
set -e

TARGET_USER="${1}"
PUBKEY="${2}"
TARGET_GROUP="${3:-}"

if [ -z "$TARGET_USER" ] || [ -z "$PUBKEY" ]; then
    echo "Usage: sam-add <username> <pubkey> [group]" >&2
    exit 1
fi

TMPPASS=""
if ! id "$TARGET_USER" >/dev/null 2>&1; then
    useradd -m -s /bin/bash "$TARGET_USER"
    TMPPASS=$(openssl rand -base64 12 | tr -d '\\n')
    printf '%s:%s\\n' "$TARGET_USER" "$TMPPASS" | chpasswd
    gpasswd -a "$TARGET_USER" sam-users 2>/dev/null || true
fi

for grp in sam-operator sam-pkg sam-root; do
    getent group "$grp" >/dev/null 2>&1 && gpasswd -d "$TARGET_USER" "$grp" 2>/dev/null || true
done
if [ -n "$TARGET_GROUP" ]; then
    gpasswd -a "$TARGET_USER" "$TARGET_GROUP"
fi

home=$(getent passwd "$TARGET_USER" | cut -d: -f6)
if [ -z "$home" ]; then
    echo "Cannot get home for $TARGET_USER" >&2
    exit 1
fi

if [ -n "$TMPPASS" ]; then
    printf 'Temporary password: %s\\nType it below as "Current password" to set your permanent password.\\n' "$TMPPASS" > "${home}/README_first_login.txt"
    chmod 600 "${home}/README_first_login.txt"
    chown "${TARGET_USER}:${TARGET_USER}" "${home}/README_first_login.txt"
    # bash login shells read ~/.bash_profile first (RHEL/Rocky/Alma skel),
    # then ~/.bash_login, then ~/.profile (Debian/Ubuntu skel). Pick the
    # first existing one so the hook fires on the actual login shell.
    if [ -f "${home}/.bash_profile" ]; then
        profile="${home}/.bash_profile"
    elif [ -f "${home}/.bash_login" ]; then
        profile="${home}/.bash_login"
    else
        profile="${home}/.profile"
        touch "$profile"
    fi
    printf '\\n# ssh-access-manager\\nif [ -f "$HOME/README_first_login.txt" ]; then\\n    echo ""; cat "$HOME/README_first_login.txt"; echo ""\\n    passwd && rm -f "$HOME/README_first_login.txt"\\nfi\\n' >> "$profile"
    chown "${TARGET_USER}:${TARGET_USER}" "$profile"
fi

ssh_dir="${home}/.ssh"
auth_keys="${ssh_dir}/authorized_keys"

mkdir -p "$ssh_dir"
chmod 700 "$ssh_dir"
chown "${TARGET_USER}:${TARGET_USER}" "$ssh_dir"

touch "$auth_keys"
if ! grep -qF "$PUBKEY" "$auth_keys" 2>/dev/null; then
    printf '%s\\n' "$PUBKEY" >> "$auth_keys"
fi
chmod 600 "$auth_keys"
chown "${TARGET_USER}:${TARGET_USER}" "$auth_keys"
"""

SAM_LOCK_USER = b"""#!/bin/sh
# sam-lock-user <username> - lock Unix user account
set -e
USER="$1"
if [ -z "$USER" ]; then
    echo "Usage: sam-lock-user <username>" >&2
    exit 1
fi
usermod -L -s /sbin/nologin "$USER"
"""

SAM_UNLOCK_USER = b"""#!/bin/sh
# sam-unlock-user <username> - unlock Unix user account
set -e
USER="$1"
if [ -z "$USER" ]; then
    echo "Usage: sam-unlock-user <username>" >&2
    exit 1
fi
usermod -U -s /bin/bash "$USER"
"""

SAM_SESSIONS_PATH = "/usr/local/bin/sam-sessions"
SAM_GRANT_GROUP_PATH = "/usr/local/bin/sam-grant-group"
SAM_REVOKE_GROUP_PATH = "/usr/local/bin/sam-revoke-group"
SAM_SELF_UPDATE_PATH = "/usr/local/bin/sam-self-update"

SAM_SESSIONS = b"""#!/bin/sh
# sam-sessions - collect SSH session data
# Outputs tab-separated lines:
#   A\\tuser\\ttty\\tip\\t<ISO8601>            (active, utmpdump /var/run/utmp)
#   H\\tuser\\ttty\\tip\\t<ISO8601> - <ISO8601> (history, utmpdump /var/log/wtmp)
# Falls back to who + LANG=C last -F when utmpdump is unavailable (busybox/Alpine).
#
# utmpdump output format (8 bracket-delimited fields per line):
#   [type] [pid] [id] [user] [line] [host] [addr] [time]
# type 7=USER_PROCESS (login), type 8=DEAD_PROCESS (logout)
# Parsing: replace all [ and ] with tab, then split on tab.

if command -v utmpdump >/dev/null 2>&1 && [ -r /var/run/utmp ]; then
    utmpdump /var/run/utmp 2>/dev/null | awk '{
        s=$0; gsub(/\\[|\\]/, "\\t", s); split(s, f, "\\t");
        type=f[2]+0;
        user=f[8];  gsub(/^ +| +$/, "", user);
        line=f[10]; gsub(/^ +| +$/, "", line);
        host=f[12]; gsub(/^ +| +$/, "", host);
        time=f[16]; gsub(/^ +| +$/, "", time);
        if(type!=7 || user=="") next;
        ip=host; if(ip=="" || ip=="0.0.0.0") ip="local";
        print "A\\t"user"\\t"line"\\t"ip"\\t"time;
    }'
    if [ -r /var/log/wtmp ]; then
        utmpdump /var/log/wtmp 2>/dev/null | tail -n 300 | awk '{
            s=$0; gsub(/\\[|\\]/, "\\t", s); split(s, f, "\\t");
            type=f[2]+0;
            pid=f[4];   gsub(/^ +| +$/, "", pid);
            user=f[8];  gsub(/^ +| +$/, "", user);
            line=f[10]; gsub(/^ +| +$/, "", line);
            host=f[12]; gsub(/^ +| +$/, "", host);
            time=f[16]; gsub(/^ +| +$/, "", time);
            if(line=="") next;
            if(type==7 && user!="") {
                key=line":"pid;
                ltime[key]=time; luser[key]=user; lhost[key]=host;
            } else if(type==8) {
                key=line":"pid;
                if(key in ltime) {
                    ip=lhost[key]; if(ip=="" || ip=="0.0.0.0") ip="local";
                    print "H\\t"luser[key]"\\t"line"\\t"ip"\\t"ltime[key]" - "time;
                    delete ltime[key]; delete luser[key]; delete lhost[key];
                }
            }
        }'
    fi
else
    # Fallback: who (active) + LANG=C last -F (history, English forced, year included)
    who 2>/dev/null | awk '{
        user=$1; tty=$2;
        if($3 ~ /^[0-9]{4}-/) {
            login=$3" "$4;
            ip=$5; gsub(/[()]/,"",ip);
        } else {
            login=$3" "$4" "$5;
            ip="";
        }
        if(ip=="" || ip==user) ip="local";
        print "A\\t"user"\\t"tty"\\t"ip"\\t"login;
    }'
    { LANG=C last -F -n 100 2>/dev/null || LANG=C last -n 100 2>/dev/null; } | \\
        grep -v "^$\\|^reboot\\|^wtmp\\|^btmp" | awk '{
        if(NF<3) next;
        user=$1; tty=$2;
        if($3 ~ /[.:]/) { ip=$3; start=4; } else { ip=""; start=3; }
        rest="";
        for(i=start;i<=NF;i++) rest=rest$i(i<NF?" ":"");
        print "H\\t"user"\\t"tty"\\t"ip"\\t"rest;
    }'
fi
"""

SAM_GRANT_GROUP = b"""#!/bin/sh
# sam-grant-group <unix_user> <group> - add unix_user to a sam-* group
set -e
USERNAME="$1"
GROUP="$2"
if [ -z "$USERNAME" ] || [ -z "$GROUP" ]; then
    echo "Usage: sam-grant-group <unix_user> <group>" >&2
    exit 1
fi
case "$GROUP" in
    sam-operator|sam-pkg|sam-root) ;;
    *) echo "Error: group must be sam-operator, sam-pkg or sam-root" >&2; exit 1 ;;
esac
gpasswd -a "$USERNAME" "$GROUP"
printf 'GROUPS:%s\\n' "$(id -Gn "$USERNAME" 2>/dev/null || echo '')"
"""

SAM_REVOKE_GROUP = b"""#!/bin/sh
# sam-revoke-group <unix_user> [group]
# If group given: remove from that group only.
# If no group: remove from all sam-* groups (sync to none).
set -e
USERNAME="$1"
GROUP="${2:-}"
if [ -z "$USERNAME" ]; then
    echo "Usage: sam-revoke-group <unix_user> [group]" >&2
    exit 1
fi
if [ -n "$GROUP" ]; then
    case "$GROUP" in
        sam-operator|sam-pkg|sam-root) ;;
        *) echo "Error: group must be sam-operator, sam-pkg or sam-root" >&2; exit 1 ;;
    esac
    gpasswd -d "$USERNAME" "$GROUP" 2>/dev/null || true
else
    for grp in sam-operator sam-pkg sam-root; do
        getent group "$grp" >/dev/null 2>&1 && gpasswd -d "$USERNAME" "$grp" 2>/dev/null || true
    done
fi
printf 'GROUPS:%s\\n' "$(id -Gn "$USERNAME" 2>/dev/null || echo '')"
"""

SAM_SELF_UPDATE = b"""#!/bin/sh
# sam-self-update [version] [--dry-run]
# Apply dynamic provisioning configuration (SAM groups, sudoers, sshd drop-in).
# This script is deployed and invoked by the collector key after initial bootstrap.
# If version is given, it is written to /etc/sam-provision-version on success.

VERSION="${1}"
DRY_RUN=0
[ "${2}" = "--dry-run" ] && DRY_RUN=1

# Detect sshd binary path
SSHD_BIN=$(command -v sshd 2>/dev/null || echo /usr/sbin/sshd)

# Helper: detect binary path
_bin() {
    local p
    p=$(command -v "$1" 2>/dev/null)
    [ -n "$p" ] && echo "$p" && return
    [ -x "/usr/local/bin/$1" ] && echo "/usr/local/bin/$1" && return
    echo "/usr/bin/$1"
}

# Helper: append sudoers rule (bare command + wildcard variant)
_rule() {
    local file="$1" group="$2" cmd="$3"
    printf "%%${group} ALL=(root) PASSWD: ${cmd}\\n"     >> "${file}"
    printf "%%${group} ALL=(root) PASSWD: ${cmd} *\\n"   >> "${file}"
}

# Step 1: Create SAM groups idempotently
for grp in sam-operator sam-pkg sam-root sam-users; do
    if ! getent group "$grp" >/dev/null 2>&1; then
        if [ "$DRY_RUN" -eq 1 ]; then
            echo "[DRY-RUN] Would create group $grp"
        else
            groupadd "$grp"
            echo "[sam-self-update] Group $grp created."
        fi
    fi
done

# Step 2: Detect binaries for sudoers rules
SYSTEMCTL=$(_bin systemctl)
JOURNALCTL=$(_bin journalctl)
SS=$(_bin ss)
DMESG=$(_bin dmesg)
LSOF=$(_bin lsof)
DU=$(_bin du)

# Step 3: Build and install sudoers files with transactional rollback
_install_sudoers() {
    local target="$1"
    local tmp="${target}.tmp"
    local backup="${target}.bak"
    local had_previous=0

    # Backup existing file
    if [ -f "$target" ]; then
        cp -p "$target" "$backup"
        had_previous=1
    fi

    # Validate with visudo
    if ! visudo -c -f "$tmp" 2>/dev/null; then
        echo "[sam-self-update] ERROR: invalid sudoers ${target} - rolling back" >&2
        if [ "$had_previous" -eq 1 ]; then
            mv "$backup" "$target"
        else
            rm -f "$target"
        fi
        exit 1
    fi

    # Install
    install -m 440 -o root -g root "$tmp" "$target"
    rm -f "$backup" "$tmp"
}

# sam-operator sudoers
OP_FILE="/etc/sudoers.d/sam-operator"
if [ "$DRY_RUN" -eq 1 ] && [ -f "$OP_FILE" ]; then
    printf "# ssh-access-manager - sam-operator sudo rights\\n" > "${OP_FILE}.tmp"
    printf "Defaults:%%sam-operator secure_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\\n" >> "${OP_FILE}.tmp"
    _rule "${OP_FILE}.tmp" "sam-operator" "${SYSTEMCTL} restart"
    _rule "${OP_FILE}.tmp" "sam-operator" "${SYSTEMCTL} reload"
    _rule "${OP_FILE}.tmp" "sam-operator" "${SYSTEMCTL} status"
    _rule "${OP_FILE}.tmp" "sam-operator" "${SYSTEMCTL} start"
    _rule "${OP_FILE}.tmp" "sam-operator" "${JOURNALCTL} -u"
    _rule "${OP_FILE}.tmp" "sam-operator" "${JOURNALCTL} -f"
    _rule "${OP_FILE}.tmp" "sam-operator" "${JOURNALCTL} -n"
    _rule "${OP_FILE}.tmp" "sam-operator" "${JOURNALCTL} --since"
    _rule "${OP_FILE}.tmp" "sam-operator" "${JOURNALCTL} -b"
    _rule "${OP_FILE}.tmp" "sam-operator" "${JOURNALCTL} -e"
    printf "%%sam-operator ALL=(root) PASSWD: ${SS} -tlnp\\n"                    >> "${OP_FILE}.tmp"
    printf "%%sam-operator ALL=(root) PASSWD: ${DMESG}\\n"                       >> "${OP_FILE}.tmp"
    printf "%%sam-operator ALL=(root) PASSWD: ${LSOF}\\n"                        >> "${OP_FILE}.tmp"
    printf "%%sam-operator ALL=(root) PASSWD: ${LSOF} -i\\n"                     >> "${OP_FILE}.tmp"
    printf "%%sam-operator ALL=(root) PASSWD: ${DU} -sh /var/* /opt/* /home/*\\n" >> "${OP_FILE}.tmp"
    for bin in runagent; do
        bin_path=$(_bin "$bin")
        [ -x "$bin_path" ] && _rule "${OP_FILE}.tmp" "sam-operator" "${bin_path}"
    done
    echo "--- ${OP_FILE} diff:"
    diff -u "$OP_FILE" "${OP_FILE}.tmp" || true
    rm -f "${OP_FILE}.tmp"
else
    printf "# ssh-access-manager - sam-operator sudo rights\\n" > "${OP_FILE}.tmp"
    printf "Defaults:%%sam-operator secure_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\\n" >> "${OP_FILE}.tmp"
    _rule "${OP_FILE}.tmp" "sam-operator" "${SYSTEMCTL} restart"
    _rule "${OP_FILE}.tmp" "sam-operator" "${SYSTEMCTL} reload"
    _rule "${OP_FILE}.tmp" "sam-operator" "${SYSTEMCTL} status"
    _rule "${OP_FILE}.tmp" "sam-operator" "${SYSTEMCTL} start"
    _rule "${OP_FILE}.tmp" "sam-operator" "${JOURNALCTL} -u"
    _rule "${OP_FILE}.tmp" "sam-operator" "${JOURNALCTL} -f"
    _rule "${OP_FILE}.tmp" "sam-operator" "${JOURNALCTL} -n"
    _rule "${OP_FILE}.tmp" "sam-operator" "${JOURNALCTL} --since"
    _rule "${OP_FILE}.tmp" "sam-operator" "${JOURNALCTL} -b"
    _rule "${OP_FILE}.tmp" "sam-operator" "${JOURNALCTL} -e"
    printf "%%sam-operator ALL=(root) PASSWD: ${SS} -tlnp\\n"                    >> "${OP_FILE}.tmp"
    printf "%%sam-operator ALL=(root) PASSWD: ${DMESG}\\n"                       >> "${OP_FILE}.tmp"
    printf "%%sam-operator ALL=(root) PASSWD: ${LSOF}\\n"                        >> "${OP_FILE}.tmp"
    printf "%%sam-operator ALL=(root) PASSWD: ${LSOF} -i\\n"                     >> "${OP_FILE}.tmp"
    printf "%%sam-operator ALL=(root) PASSWD: ${DU} -sh /var/* /opt/* /home/*\\n" >> "${OP_FILE}.tmp"
    for bin in runagent; do
        bin_path=$(_bin "$bin")
        [ -x "$bin_path" ] && _rule "${OP_FILE}.tmp" "sam-operator" "${bin_path}"
    done
    _install_sudoers "$OP_FILE"
    echo "[sam-self-update] Sudoers sam-operator configured."
fi

# sam-pkg sudoers
PKG_FILE="/etc/sudoers.d/sam-pkg"
if [ "$DRY_RUN" -eq 1 ] && [ -f "$PKG_FILE" ]; then
    printf "# ssh-access-manager - sam-pkg sudo rights\\n" > "${PKG_FILE}.tmp"
    printf "Defaults:%%sam-pkg secure_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\\n" >> "${PKG_FILE}.tmp"
    _rule "${PKG_FILE}.tmp" "sam-pkg" "${SYSTEMCTL} restart"
    _rule "${PKG_FILE}.tmp" "sam-pkg" "${SYSTEMCTL} reload"
    _rule "${PKG_FILE}.tmp" "sam-pkg" "${SYSTEMCTL} status"
    _rule "${PKG_FILE}.tmp" "sam-pkg" "${SYSTEMCTL} start"
    _rule "${PKG_FILE}.tmp" "sam-pkg" "${JOURNALCTL} -u"
    _rule "${PKG_FILE}.tmp" "sam-pkg" "${JOURNALCTL} -f"
    _rule "${PKG_FILE}.tmp" "sam-pkg" "${JOURNALCTL} -n"
    _rule "${PKG_FILE}.tmp" "sam-pkg" "${JOURNALCTL} --since"
    _rule "${PKG_FILE}.tmp" "sam-pkg" "${JOURNALCTL} -b"
    _rule "${PKG_FILE}.tmp" "sam-pkg" "${JOURNALCTL} -e"
    printf "%%sam-pkg ALL=(root) PASSWD: ${SS} -tlnp\\n"                    >> "${PKG_FILE}.tmp"
    printf "%%sam-pkg ALL=(root) PASSWD: ${DMESG}\\n"                       >> "${PKG_FILE}.tmp"
    printf "%%sam-pkg ALL=(root) PASSWD: ${LSOF}\\n"                        >> "${PKG_FILE}.tmp"
    printf "%%sam-pkg ALL=(root) PASSWD: ${LSOF} -i\\n"                     >> "${PKG_FILE}.tmp"
    printf "%%sam-pkg ALL=(root) PASSWD: ${DU} -sh /var/* /opt/* /home/*\\n" >> "${PKG_FILE}.tmp"
    for bin in runagent api-cli; do
        bin_path=$(_bin "$bin")
        [ -x "$bin_path" ] && _rule "${PKG_FILE}.tmp" "sam-pkg" "${bin_path}"
    done
    if command -v apt >/dev/null 2>&1; then
        APT=$(_bin apt)
        _rule "${PKG_FILE}.tmp" "sam-pkg" "${APT} install"
        _rule "${PKG_FILE}.tmp" "sam-pkg" "${APT} upgrade"
    elif command -v dnf >/dev/null 2>&1; then
        DNF=$(_bin dnf)
        _rule "${PKG_FILE}.tmp" "sam-pkg" "${DNF} install"
        _rule "${PKG_FILE}.tmp" "sam-pkg" "${DNF} upgrade"
    elif command -v yum >/dev/null 2>&1; then
        YUM=$(_bin yum)
        _rule "${PKG_FILE}.tmp" "sam-pkg" "${YUM} install"
        _rule "${PKG_FILE}.tmp" "sam-pkg" "${YUM} update"
    elif command -v zypper >/dev/null 2>&1; then
        ZYPPER=$(_bin zypper)
        _rule "${PKG_FILE}.tmp" "sam-pkg" "${ZYPPER} install"
        _rule "${PKG_FILE}.tmp" "sam-pkg" "${ZYPPER} update"
    elif command -v apk >/dev/null 2>&1; then
        APK=$(_bin apk)
        _rule "${PKG_FILE}.tmp" "sam-pkg" "${APK} add"
        _rule "${PKG_FILE}.tmp" "sam-pkg" "${APK} upgrade"
    elif command -v pacman >/dev/null 2>&1; then
        PACMAN=$(_bin pacman)
        _rule "${PKG_FILE}.tmp" "sam-pkg" "${PACMAN} -S"
        _rule "${PKG_FILE}.tmp" "sam-pkg" "${PACMAN} -Syu"
        _rule "${PKG_FILE}.tmp" "sam-pkg" "${PACMAN} -Sy"
    fi
    for bin in add-module remove-module; do
        bin_path="/usr/local/bin/$bin"
        [ -x "$bin_path" ] && _rule "${PKG_FILE}.tmp" "sam-pkg" "${bin_path}"
    done
    echo "--- ${PKG_FILE} diff:"
    diff -u "$PKG_FILE" "${PKG_FILE}.tmp" || true
    rm -f "${PKG_FILE}.tmp"
else
    printf "# ssh-access-manager - sam-pkg sudo rights\\n" > "${PKG_FILE}.tmp"
    printf "Defaults:%%sam-pkg secure_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\\n" >> "${PKG_FILE}.tmp"
    _rule "${PKG_FILE}.tmp" "sam-pkg" "${SYSTEMCTL} restart"
    _rule "${PKG_FILE}.tmp" "sam-pkg" "${SYSTEMCTL} reload"
    _rule "${PKG_FILE}.tmp" "sam-pkg" "${SYSTEMCTL} status"
    _rule "${PKG_FILE}.tmp" "sam-pkg" "${SYSTEMCTL} start"
    _rule "${PKG_FILE}.tmp" "sam-pkg" "${JOURNALCTL} -u"
    _rule "${PKG_FILE}.tmp" "sam-pkg" "${JOURNALCTL} -f"
    _rule "${PKG_FILE}.tmp" "sam-pkg" "${JOURNALCTL} -n"
    _rule "${PKG_FILE}.tmp" "sam-pkg" "${JOURNALCTL} --since"
    _rule "${PKG_FILE}.tmp" "sam-pkg" "${JOURNALCTL} -b"
    _rule "${PKG_FILE}.tmp" "sam-pkg" "${JOURNALCTL} -e"
    printf "%%sam-pkg ALL=(root) PASSWD: ${SS} -tlnp\\n"                    >> "${PKG_FILE}.tmp"
    printf "%%sam-pkg ALL=(root) PASSWD: ${DMESG}\\n"                       >> "${PKG_FILE}.tmp"
    printf "%%sam-pkg ALL=(root) PASSWD: ${LSOF}\\n"                        >> "${PKG_FILE}.tmp"
    printf "%%sam-pkg ALL=(root) PASSWD: ${LSOF} -i\\n"                     >> "${PKG_FILE}.tmp"
    printf "%%sam-pkg ALL=(root) PASSWD: ${DU} -sh /var/* /opt/* /home/*\\n" >> "${PKG_FILE}.tmp"
    for bin in runagent api-cli; do
        bin_path=$(_bin "$bin")
        [ -x "$bin_path" ] && _rule "${PKG_FILE}.tmp" "sam-pkg" "${bin_path}"
    done
    if command -v apt >/dev/null 2>&1; then
        APT=$(_bin apt)
        _rule "${PKG_FILE}.tmp" "sam-pkg" "${APT} install"
        _rule "${PKG_FILE}.tmp" "sam-pkg" "${APT} upgrade"
    elif command -v dnf >/dev/null 2>&1; then
        DNF=$(_bin dnf)
        _rule "${PKG_FILE}.tmp" "sam-pkg" "${DNF} install"
        _rule "${PKG_FILE}.tmp" "sam-pkg" "${DNF} upgrade"
    elif command -v yum >/dev/null 2>&1; then
        YUM=$(_bin yum)
        _rule "${PKG_FILE}.tmp" "sam-pkg" "${YUM} install"
        _rule "${PKG_FILE}.tmp" "sam-pkg" "${YUM} update"
    elif command -v zypper >/dev/null 2>&1; then
        ZYPPER=$(_bin zypper)
        _rule "${PKG_FILE}.tmp" "sam-pkg" "${ZYPPER} install"
        _rule "${PKG_FILE}.tmp" "sam-pkg" "${ZYPPER} update"
    elif command -v apk >/dev/null 2>&1; then
        APK=$(_bin apk)
        _rule "${PKG_FILE}.tmp" "sam-pkg" "${APK} add"
        _rule "${PKG_FILE}.tmp" "sam-pkg" "${APK} upgrade"
    elif command -v pacman >/dev/null 2>&1; then
        PACMAN=$(_bin pacman)
        _rule "${PKG_FILE}.tmp" "sam-pkg" "${PACMAN} -S"
        _rule "${PKG_FILE}.tmp" "sam-pkg" "${PACMAN} -Syu"
        _rule "${PKG_FILE}.tmp" "sam-pkg" "${PACMAN} -Sy"
    fi
    for bin in add-module remove-module; do
        bin_path="/usr/local/bin/$bin"
        [ -x "$bin_path" ] && _rule "${PKG_FILE}.tmp" "sam-pkg" "${bin_path}"
    done
    _install_sudoers "$PKG_FILE"
    echo "[sam-self-update] Sudoers sam-pkg configured."
fi

# sam-root sudoers
ROOT_FILE="/etc/sudoers.d/sam-root"
if [ "$DRY_RUN" -eq 1 ] && [ -f "$ROOT_FILE" ]; then
    printf "# ssh-access-manager - sam-root sudo rights\\n" > "${ROOT_FILE}.tmp"
    printf "%%sam-root ALL=(ALL) ALL\\n" >> "${ROOT_FILE}.tmp"
    echo "--- ${ROOT_FILE} diff:"
    diff -u "$ROOT_FILE" "${ROOT_FILE}.tmp" || true
    rm -f "${ROOT_FILE}.tmp"
else
    printf "# ssh-access-manager - sam-root sudo rights\\n" > "${ROOT_FILE}.tmp"
    printf "%%sam-root ALL=(ALL) ALL\\n" >> "${ROOT_FILE}.tmp"
    _install_sudoers "$ROOT_FILE"
    echo "[sam-self-update] Sudoers sam-root configured."
fi

# Step 4: sshd drop-in configuration
SAM_SSHD_CONF="Match Group sam-users
    PasswordAuthentication no
    PermitEmptyPasswords no
    KbdInteractiveAuthentication no
    PubkeyAuthentication yes
    AuthenticationMethods publickey"
SSHD_D="/etc/ssh/sshd_config.d"
SSHD_INSTALLED=0

_install_sam_sshd_dropin() {
    local target="${SSHD_D}/50-sam-users.conf"
    local backup="${target}.bak"
    local had_previous=0
    if [ -f "$target" ]; then
        cp -p "$target" "$backup"
        had_previous=1
    fi
    printf '%s\\n' "${SAM_SSHD_CONF}" > "$target"
    chown root:root "$target"
    chmod 600 "$target"
    if ! "$SSHD_BIN" -t 2>/dev/null; then
        echo "[sam-self-update] ERROR: sshd -t rejected ${target} - rolling back" >&2
        if [ "$had_previous" -eq 1 ]; then
            mv "$backup" "$target"
        else
            rm -f "$target"
        fi
        exit 1
    fi
    rm -f "$backup"
    echo "[sam-self-update] ${target} written and validated by sshd -t."
    SSHD_INSTALLED=1
}

SSHD_DROPIN_ENABLED=0
if [ -d "$SSHD_D" ]; then
    for cfg in /etc/ssh/sshd_config /usr/etc/ssh/sshd_config; do
        if [ -f "$cfg" ] && grep -qE "^Include.*sshd_config\\.d" "$cfg" 2>/dev/null; then
            SSHD_DROPIN_ENABLED=1
            break
        fi
    done
fi

if [ "$DRY_RUN" -eq 1 ]; then
    if [ "$SSHD_DROPIN_ENABLED" -eq 1 ]; then
        target="${SSHD_D}/50-sam-users.conf"
        if [ -f "$target" ]; then
            printf '%s\\n' "${SAM_SSHD_CONF}" > "${target}.tmp"
            echo "--- ${target} diff:"
            diff -u "$target" "${target}.tmp" || true
            rm -f "${target}.tmp"
        else
            echo "[DRY-RUN] Would create ${target}"
        fi
    elif [ -f /etc/ssh/sshd_config ] && ! grep -q "Match Group sam-users" /etc/ssh/sshd_config 2>/dev/null; then
        echo "[DRY-RUN] Would append to /etc/ssh/sshd_config"
    fi
elif [ "$SSHD_DROPIN_ENABLED" -eq 1 ]; then
    _install_sam_sshd_dropin
elif [ -f /etc/ssh/sshd_config ] && ! grep -q "Match Group sam-users" /etc/ssh/sshd_config 2>/dev/null; then
    # Fallback for distros without working sshd_config.d include
    cp -p /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
    printf '\\n# ssh-access-manager\\n%s\\n' "${SAM_SSHD_CONF}" >> /etc/ssh/sshd_config
    if ! "$SSHD_BIN" -t 2>/dev/null; then
        echo "[sam-self-update] ERROR: sshd -t rejected /etc/ssh/sshd_config - rolling back" >&2
        mv /etc/ssh/sshd_config.bak /etc/ssh/sshd_config
        exit 1
    fi
    rm -f /etc/ssh/sshd_config.bak
    echo "[sam-self-update] /etc/ssh/sshd_config updated and validated by sshd -t."
    SSHD_INSTALLED=1
elif [ ! -f /etc/ssh/sshd_config ] && [ ! -d "$SSHD_D" ]; then
    echo "[sam-self-update] ERROR: neither /etc/ssh/sshd_config nor ${SSHD_D} exists" >&2
    echo "[sam-self-update]        cannot pose the sam-users SSH restriction" >&2
    exit 1
fi

# Step 5: Reload sshd if we just changed the config
if [ "$DRY_RUN" -eq 0 ] && [ "$SSHD_INSTALLED" -eq 1 ] && command -v systemctl >/dev/null 2>&1; then
    systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || true
fi

# Step 6: Write version marker on success
if [ "$DRY_RUN" -eq 0 ] && [ -n "$VERSION" ]; then
    printf '%s\\n' "$VERSION" > /etc/sam-provision-version
    echo "[sam-self-update] Version ${VERSION} written to /etc/sam-provision-version."
fi

if [ "$DRY_RUN" -eq 1 ]; then
    echo "[DRY-RUN] No changes applied."
fi
"""

# Provision version tracking — auto-update orchestration
PROVISION_VERSION = hashlib.sha256(SAM_SELF_UPDATE).hexdigest()[:16]
PROVISION_VERSION_PATH = "/etc/sam-provision-version"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _parse_groups_output(out: str) -> list[str]:
    """Parse GROUPS: line from SAM script output and return list of groups."""
    for line in out.splitlines():
        if line.startswith("GROUPS:"):
            return line[7:].split()
    return []


def _read_provision_version(client) -> str | None:
    """Read /etc/sam-provision-version from the remote host.

    Returns None if the file is missing (host newly provisioned, never updated yet).
    """
    stdout, _stderr, exit_code = _run(client, f"cat {PROVISION_VERSION_PATH} 2>/dev/null")
    if exit_code != 0:
        return None
    value = stdout.strip()
    return value or None


def _resolve_key_path(server_id: str) -> str:
    """Return the path to the per-server collector key for this server.

    Raises KeyError with a clear admin-facing message if the key file does
    not exist (server provisioned before per-server keys, or filesystem
    corruption / restore inconsistency). The scan layer turns this into a
    SCAN_FAILED audit entry.
    """
    path = os.path.join(PER_SERVER_KEYS_DIR, f"{server_id}.key")
    if not os.path.isfile(path):
        raise KeyError(
            f"no per-server collector key for server {server_id} — please re-add this server"
        )
    return path


def _generate_keypair(target_path_no_ext: str) -> tuple[str, str]:
    """Generate an ed25519 keypair at <target_path_no_ext>{,.pub}.

    Empty SSH comment (no `-C` data) — files must be anonymous on disk so
    that a stolen .key file cannot be correlated to a hostname/IP. The
    server identity lives in the filename (server UUID, random v4).

    Returns (path_to_private_key, public_key_content). Public key content
    is the single-line `ssh-ed25519 AAAA... ` string ready to put into
    authorized_keys.

    chmod 600 on private, 644 on public, chown nobody on both (Flask
    process must be able to read them).
    """
    import subprocess
    private_path = target_path_no_ext + ".key"
    public_path = target_path_no_ext + ".key.pub"

    # Generate keypair with no passphrase and no comment
    subprocess.run(
        ["ssh-keygen", "-t", "ed25519", "-N", "", "-C", "", "-f", private_path],
        check=True,
        capture_output=True,
    )

    # Per-server pubkey is only consumed by Flask (nobody) for display and
    # remote provisioning — no other local user needs read access.
    os.chmod(private_path, 0o600)
    os.chmod(public_path, 0o600)

    # Chown to nobody (user running Flask)
    import pwd
    nobody_uid = pwd.getpwnam("nobody").pw_uid
    nobody_gid = pwd.getpwnam("nobody").pw_gid
    os.chown(private_path, nobody_uid, nobody_gid)
    os.chown(public_path, nobody_uid, nobody_gid)

    # Read public key
    with open(public_path, "r") as fh:
        public_key = fh.read().strip()

    return private_path, public_key


def _compute_pubkey_fingerprint(pubkey_line: str) -> str:
    """Return the SHA256 fingerprint string (`SHA256:abc...`) of an SSH
    public key line. Same format as ssh-keygen -lf and `ssh.compute_fingerprint`
    in actions.py — verify the existing helper, reuse if possible."""
    # Parse pubkey line: "ssh-ed25519 AAAA... [comment]"
    parts = pubkey_line.strip().split()
    if len(parts) < 2:
        raise ValueError("Invalid public key format")
    key_b64 = parts[1]

    # Compute SHA256 fingerprint
    raw = base64.b64decode(key_b64)
    digest = hashlib.sha256(raw).digest()
    b64 = base64.b64encode(digest).decode().rstrip("=")
    return f"SHA256:{b64}"


def _append_pubkey_remote(client: paramiko.SSHClient, pubkey: str) -> None:
    """Append pubkey to ~audit-collector/.ssh/authorized_keys if not already present."""
    # Check if key already present
    check_cmd = f"grep -qxF {shlex.quote(pubkey)} ~/.ssh/authorized_keys 2>/dev/null"
    _, _, rc = _run(client, check_cmd)
    if rc == 0:
        # Already present, skip
        return

    # Append the key
    append_cmd = f"echo {shlex.quote(pubkey)} >> ~/.ssh/authorized_keys"
    _, err, rc = _run(client, append_cmd)
    if rc != 0:
        raise SSHError(f"Failed to append pubkey: {err}")


def _remove_pubkey_remote(client: paramiko.SSHClient, pubkey: str) -> None:
    """Remove pubkey line from ~audit-collector/.ssh/authorized_keys atomically."""
    # Use grep -vxF to filter out the exact line, atomic with mv
    remove_cmd = (
        f"grep -vxF {shlex.quote(pubkey)} ~/.ssh/authorized_keys > ~/.ssh/authorized_keys.tmp && "
        f"mv ~/.ssh/authorized_keys.tmp ~/.ssh/authorized_keys"
    )
    _, err, rc = _run(client, remove_cmd)
    if rc != 0:
        raise SSHError(f"Failed to remove pubkey: {err}")


def _replace_authorized_keys_remote(client: paramiko.SSHClient, pubkey: str) -> None:
    """Replace ~/.ssh/authorized_keys with exactly one line: `pubkey`.

    Used at the end of a key rotation to guarantee the audit-collector
    account ends up with ONLY the freshly-generated collector key.

    The audit-collector Unix account is dedicated to SAM — it has no
    legitimate human user, no shell login besides this key, and no
    reason to hold any other entry. Historical accumulation we have
    observed in the wild (early provision-host.sh deployments + partial
    rotations + manually-added probe keys) leaves multiple stale lines
    in authorized_keys. The previous "grep -vxF current" approach only
    removed the SINGLE line the local <uuid>.key.pub file knew about,
    leaving everything else untouched.

    Truncating is safe at this point because the rotation flow has
    already verified that `pubkey` works (step 6 connected with it and
    ran `true`). The write uses tmp+mv so a failed write keeps the
    pre-existing multi-line file intact — SAM is never locked out.

    chmod 600 is reapplied since `>` may not preserve the previous
    permissions when followed by `mv` on a freshly-created tmp file.
    """
    cmd = (
        f"printf '%s\\n' {shlex.quote(pubkey)} > ~/.ssh/authorized_keys.tmp && "
        f"chmod 600 ~/.ssh/authorized_keys.tmp && "
        f"mv ~/.ssh/authorized_keys.tmp ~/.ssh/authorized_keys"
    )
    _, err, rc = _run(client, cmd)
    if rc != 0:
        raise SSHError(f"Failed to replace authorized_keys: {err}")


def rotate_per_server_key(hostname: str, ip: str, port: int, server_id: str) -> str:
    """Rotate the collector key for one server, atomically with rollback.

    Workflow:
    1. Check current per-server key exists (raise if not)
    2. Read current pubkey content
    3. Generate new keypair at <id>.key.new and <id>.key.new.pub
    4. SSH to host with CURRENT key (key_filename=<id>.key)
    5. Append new pubkey to ~audit-collector/.ssh/authorized_keys
    6. Disconnect, reconnect with NEW key — verify connectivity
    7. If OK: SSH again with new key, remove the OLD pubkey line from
       authorized_keys (grep -vF on the exact line)
    8. Move files: <id>.key -> <id>.key.old, <id>.key.new -> <id>.key,
       <id>.key.new.pub -> <id>.key.pub, then remove .old files
    9. Return new fingerprint

    On error at any step: try to remove the new pubkey from
    authorized_keys (with old key if it's still working), delete the
    .new files locally, raise SSHError with original cause.

    No sudo needed for any step — audit-collector writes directly to its
    own ~/.ssh/authorized_keys.
    """
    # Step 1: verify current key exists
    current_key_path = _resolve_key_path(server_id)
    current_pubkey_path = current_key_path + ".pub"

    # Step 2: read current pubkey
    with open(current_pubkey_path, "r") as fh:
        current_pubkey = fh.read().strip()

    # Step 3: generate new keypair
    new_key_base = os.path.join(PER_SERVER_KEYS_DIR, f"{server_id}.key.new")
    new_key_path, new_pubkey = _generate_keypair(new_key_base[:-4])  # Strip .key to get base
    new_pubkey_path = new_key_path + ".pub"

    new_fingerprint = None
    client_old = None
    client_new = None

    try:
        # Step 4: connect with current key
        client_old = _connect(ip, port, key_path=current_key_path)

        # Step 5: append new pubkey
        _append_pubkey_remote(client_old, new_pubkey)
        client_old.close()
        client_old = None

        # Step 6: test connectivity with new key
        try:
            client_new = _connect(ip, port, key_path=new_key_path)
            # Run a no-op to verify
            _, _, rc = _run(client_new, "true")
            if rc != 0:
                raise SSHError("New key test failed")
        except Exception as exc:
            raise SSHError(f"New key verification failed: {exc}")

        # Step 7: replace authorized_keys with ONLY the new pubkey.
        # See _replace_authorized_keys_remote for the rationale on why
        # we don't just `grep -vxF current` here: any stale keys that
        # accumulated from previous (partial) rotations or from manual
        # operator additions would otherwise survive forever.
        _replace_authorized_keys_remote(client_new, new_pubkey)
        client_new.close()
        client_new = None

        # Step 8: atomic file rotation
        old_backup_path = current_key_path + ".old"
        old_backup_pub_path = current_pubkey_path + ".old"

        os.rename(current_key_path, old_backup_path)
        os.rename(current_pubkey_path, old_backup_pub_path)
        os.rename(new_key_path, current_key_path)
        os.rename(new_pubkey_path, current_pubkey_path)

        # Cleanup old backup
        os.remove(old_backup_path)
        os.remove(old_backup_pub_path)

        # Step 9: compute and return new fingerprint
        new_fingerprint = _compute_pubkey_fingerprint(new_pubkey)
        return new_fingerprint

    except Exception as exc:
        # Rollback: try to remove new pubkey from authorized_keys
        try:
            if client_new is None and os.path.isfile(current_key_path):
                # Try with old key
                rollback_client = _connect(ip, port, key_path=current_key_path)
                try:
                    _remove_pubkey_remote(rollback_client, new_pubkey)
                finally:
                    rollback_client.close()
        except Exception:
            pass  # Best effort

        # Cleanup .new files
        for path in [new_key_path, new_pubkey_path]:
            try:
                if os.path.isfile(path):
                    os.remove(path)
            except Exception:
                pass

        raise SSHError(f"Key rotation failed: {exc}")
    finally:
        if client_old is not None:
            client_old.close()
        if client_new is not None:
            client_new.close()


def apply_provision_update(hostname: str, ip: str, port: int = 22, *, key_path: str) -> str:
    """Run `sudo sam-self-update <version>` on the remote host.

    Returns the applied version on success. Raises SSHSudoError if the script
    exits non-zero (the script itself has already rolled back any partial
    change on its end before exiting).
    """
    client = _connect(ip, port, key_path=key_path)
    try:
        cmd = f"sudo {SAM_SELF_UPDATE_PATH} {PROVISION_VERSION}"
        stdout, stderr, exit_code = _run(client, cmd)
        if exit_code != 0:
            raise SSHSudoError(
                f"sam-self-update failed (exit {exit_code}): {stderr.strip() or stdout.strip()}"
            )
        return PROVISION_VERSION
    finally:
        client.close()


def _connect(ip: str, port: int = 22, *, key_path: str) -> paramiko.SSHClient:
    """Connect to a remote host using a per-server collector key.

    key_path is required (keyword-only) — no global default key.
    """
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    client.load_host_keys(KNOWN_HOSTS)
    client.connect(hostname=ip, port=port, username=SSH_USER, key_filename=key_path, timeout=15)
    return client


def _run(client: paramiko.SSHClient, cmd: str) -> tuple[str, str, int]:
    _, stdout, stderr = client.exec_command(cmd)
    out = stdout.read().decode()
    err = stderr.read().decode()
    rc = stdout.channel.recv_exit_status()
    return out, err, rc


def _remote_sha256(client: paramiko.SSHClient, remote_path: str) -> str | None:
    out, _, rc = _run(client, f"sha256sum {shlex.quote(remote_path)} 2>/dev/null")
    if rc != 0 or not out.strip():
        return None
    return out.split()[0]


def _deploy_script(
    client: paramiko.SSHClient,
    sftp: paramiko.SFTPClient,
    content: bytes,
    remote_path: str,
    tmp_path: str,
) -> None:
    sftp.putfo(io.BytesIO(content), tmp_path)
    sftp.chmod(tmp_path, 0o600)
    _run(client, f"sudo /usr/bin/install -m 750 -o root -g root {shlex.quote(tmp_path)} {shlex.quote(remote_path)}")
    _run(client, f"rm -f {shlex.quote(tmp_path)}")


def ensure_scripts(hostname: str, server_id: str, ip: str, port: int = 22, *, key_path: str) -> None:
    """
    Deploy all SAM_* scripts on the remote host if absent or outdated.
    Logs SCRIPT_DEPLOYED to audit_log for each script actually deployed.
    """
    client = _connect(ip, port, key_path=key_path)
    try:
        sftp = client.open_sftp()
        for content, remote_path in (
            (SAM_COLLECT, SAM_COLLECT_PATH),
            (SAM_REVOKE, SAM_REVOKE_PATH),
            (SAM_ADD, SAM_ADD_PATH),
            (SAM_LOCK_USER, SAM_LOCK_USER_PATH),
            (SAM_UNLOCK_USER, SAM_UNLOCK_USER_PATH),
            (SAM_SESSIONS, SAM_SESSIONS_PATH),
            (SAM_GRANT_GROUP, SAM_GRANT_GROUP_PATH),
            (SAM_REVOKE_GROUP, SAM_REVOKE_GROUP_PATH),
            (SAM_SELF_UPDATE, SAM_SELF_UPDATE_PATH),
        ):
            local_hash = _sha256(content)
            remote_hash = _remote_sha256(client, remote_path)
            if remote_hash == local_hash:
                continue
            name = os.path.basename(remote_path)
            tmp_path = f"/home/{SSH_USER}/{name}"
            _deploy_script(client, sftp, content, remote_path, tmp_path)
            db.execute(
                """
                INSERT INTO audit_log (action, target_server, details)
                VALUES (%s, %s, %s::jsonb)
                """,
                (
                    "SCRIPT_DEPLOYED",
                    server_id,
                    json.dumps({"script": name, "hostname": hostname}),
                ),
            )
        sftp.close()
    finally:
        client.close()


def revoke_on_server(hostname: str, fingerprint: str, ip: str, unix_user: str = None, port: int = 22, *, key_path: str) -> None:
    """Run sam-revoke on the remote host.
    If unix_user is given, revokes only from that user's authorized_keys.
    Otherwise revokes globally (all users on the server).
    """
    import shlex
    client = _connect(ip, port, key_path=key_path)
    try:
        cmd = f"sudo {SAM_REVOKE_PATH} {shlex.quote(fingerprint)}"
        if unix_user:
            cmd += f" {shlex.quote(unix_user)}"
        _, err, rc = _run(client, cmd)
        if rc != 0:
            raise SSHError(
                f"sam-revoke failed on {hostname} (rc={rc}): {err}"
            )
    finally:
        client.close()


def collect_keys(hostname: str, ip: str, port: int = 22, *, key_path: str) -> list[str]:
    """Run sam-collect on the remote host and return raw output lines."""
    client = _connect(ip, port, key_path=key_path)
    try:
        out, _, rc = _run(client, f"sudo {SAM_COLLECT_PATH}")
        if rc != 0:
            raise SSHError(f"sam-collect failed on {hostname}")
        return [line for line in out.splitlines() if line.strip()]
    finally:
        client.close()


def add_key_on_server(hostname: str, unix_user: str, public_key: str, ip: str, port: int = 22, sam_group: str = None, *, key_path: str) -> None:
    """Run sam-add on the remote host to deploy a public key and set the SAM group."""
    import shlex
    cmd = f"sudo {SAM_ADD_PATH} {shlex.quote(unix_user)} {shlex.quote(public_key)}"
    if sam_group:
        cmd += f" {shlex.quote(sam_group)}"
    client = _connect(ip, port, key_path=key_path)
    try:
        _, err, rc = _run(client, cmd)
        if rc != 0:
            raise SSHError(f"sam-add failed on {hostname} (rc={rc}): {err}")
    finally:
        client.close()


def lock_user_on_server(hostname: str, unix_user: str, ip: str, port: int = 22, *, key_path: str) -> None:
    """Run sam-lock-user on the remote host to lock a Unix user account."""
    import shlex
    client = _connect(ip, port, key_path=key_path)
    try:
        _, err, rc = _run(
            client, f"sudo {SAM_LOCK_USER_PATH} {shlex.quote(unix_user)}"
        )
        if rc != 0:
            raise SSHError(f"sam-lock-user failed on {hostname} (rc={rc}): {err}")
    finally:
        client.close()


def unlock_user_on_server(hostname: str, unix_user: str, ip: str, port: int = 22, *, key_path: str) -> None:
    """Run sam-unlock-user on the remote host to unlock a Unix user account."""
    import shlex
    client = _connect(ip, port, key_path=key_path)
    try:
        _, err, rc = _run(
            client, f"sudo {SAM_UNLOCK_USER_PATH} {shlex.quote(unix_user)}"
        )
        if rc != 0:
            raise SSHError(f"sam-unlock-user failed on {hostname} (rc={rc}): {err}")
    finally:
        client.close()


def grant_group_on_server(hostname: str, unix_user: str, group: str, ip: str, port: int = 22, *, key_path: str) -> list[str]:
    """Run sam-grant-group on the remote host. Returns actual groups of unix_user after change."""
    client = _connect(ip, port, key_path=key_path)
    try:
        out, err, rc = _run(
            client,
            f"sudo {SAM_GRANT_GROUP_PATH} {shlex.quote(unix_user)} {shlex.quote(group)}",
        )
        if rc != 0:
            raise SSHError(f"sam-grant-group failed on {hostname} (rc={rc}): {err}")
        return _parse_groups_output(out)
    finally:
        client.close()


def revoke_group_on_server(hostname: str, unix_user: str, group: str | None, ip: str, port: int = 22, *, key_path: str) -> list[str]:
    """Run sam-revoke-group on the remote host. group=None strips all sam-* groups. Returns actual groups."""
    cmd = f"sudo {SAM_REVOKE_GROUP_PATH} {shlex.quote(unix_user)}"
    if group:
        cmd += f" {shlex.quote(group)}"
    client = _connect(ip, port, key_path=key_path)
    try:
        out, err, rc = _run(client, cmd)
        if rc != 0:
            raise SSHError(f"sam-revoke-group failed on {hostname} (rc={rc}): {err}")
        return _parse_groups_output(out)
    finally:
        client.close()


def _parse_session_datetime(s: str, now) -> "datetime | None":
    """Parse date strings from sam-sessions output. Returns UTC datetime or None.

    Handles three sources:
    - utmpdump ISO 8601:  2026-05-01T07:35:23,000000+0000  (primary path)
    - who ISO date:       2026-05-01 07:35                  (fallback active)
    - last -F / last:     Mon Apr 27 08:00:01 2026          (fallback history)
    """
    import re
    from datetime import datetime, timezone
    s = s.strip()
    if not s:
        return None
    # ISO 8601 from utmpdump (contains 'T' and timezone offset)
    if 'T' in s:
        try:
            return datetime.fromisoformat(s.replace(',', '.')).astimezone(timezone.utc)
        except ValueError:
            pass
    # ISO date from who: 2026-05-01 07:35 (no timezone - treat as UTC)
    if re.match(r'^\d{4}-\d{2}-\d{2} \d{2}:\d{2}', s):
        try:
            dt = datetime.strptime(s[:16], "%Y-%m-%d %H:%M")
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    # last / last -F fallback: strip leading weekday abbreviation (Mon, Fri, …)
    # then inject current year when absent - avoids DeprecationWarning in Python
    # 3.12 and the upcoming ValueError in Python 3.15 for year-less formats.
    s = re.sub(r'^[A-Z][a-z]{2}\s+', '', s)
    has_year = bool(re.search(r'\b\d{4}\b', s))
    s_parse = f"{s} {now.year}" if not has_year else s
    for fmt in ("%b %d %H:%M:%S %Y", "%b  %d %H:%M:%S %Y", "%b %d %H:%M %Y", "%b  %d %H:%M %Y"):
        try:
            dt = datetime.strptime(s_parse, fmt)
            if not has_year and dt.date() > now.date():
                dt = dt.replace(year=now.year - 1)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    # Pure HH:MM logout time from legacy last output (no date context available)
    if re.match(r'^\d{1,2}:\d{2}$', s):
        try:
            t = datetime.strptime(s, "%H:%M")
            return now.replace(hour=t.hour, minute=t.minute, second=0, microsecond=0)
        except ValueError:
            pass
    return None


def _is_valid_ip(s: str) -> bool:
    """Return True if s is a valid IPv4 or IPv6 address."""
    import ipaddress
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def audit_sshd_config(hostname: str, ip: str, port: int = 22, *, key_path: str) -> dict[str, str]:
    """Run `sudo sshd -T` on the remote host and return the parsed config.

    Each line of sshd -T output is `<directive_lower> <value...>`. Returns
    a dict {directive_lower: value_str}. Multi-value directives (Ciphers,
    MACs...) are returned as-is (space-joined string).

    Raises SSHSudoError if sudo sshd -T exits non-zero, SSHScriptError on parse
    failure.
    """
    client = _connect(ip, port, key_path=key_path)
    try:
        stdout, stderr, exit_code = _run(client, "sudo sshd -T")
        if exit_code != 0:
            raise SSHSudoError(f"sshd -T failed (exit {exit_code}): {stderr.strip()}")
        result = {}
        for line in stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 1)
            if not parts:
                continue
            key = parts[0].lower()
            value = parts[1] if len(parts) > 1 else ""
            result[key] = value
        if not result:
            raise SSHScriptError("sshd -T produced no parseable output")
        return result
    finally:
        client.close()


def collect_sessions_on_server(hostname: str, server_id: str, ip: str, port: int = 22, *, key_path: str) -> None:
    """Collect SSH sessions via sam-sessions and upsert into ssh_sessions table."""
    import socket
    from datetime import datetime, timezone
    try:
        client = _connect(ip, port, key_path=key_path)
    except paramiko.AuthenticationException:
        raise SSHAuthError("Authentication failed - check collector key authorization")
    except paramiko.SSHException as exc:
        raise SSHError(f"SSH error connecting to {hostname}: {exc}")
    except socket.timeout:
        raise SSHTimeoutError("Connection timed out - server did not respond within 15 seconds")
    except OSError as exc:
        if "Connection refused" in str(exc):
            raise SSHUnreachableError("Server unreachable - check the IP and network connectivity")
        raise SSHError(f"Connection failed: {exc}")
    try:
        out, err, rc = _run(client, f"sudo {SAM_SESSIONS_PATH}")
        if rc != 0:
            logging.warning("sam-sessions returned rc=%d on %s: %s", rc, hostname.replace("\n", "").replace("\r", ""), err.strip().replace("\n", " ").replace("\r", ""))
            return
        now = datetime.now(timezone.utc)
        db.execute(
            "UPDATE ssh_sessions SET is_active = false WHERE server_id = %s AND is_active = true",
            (server_id,),
        )
        active_count = 0
        for line in out.splitlines():
            parts = line.split('\t')
            if len(parts) < 4:
                continue
            session_type = parts[0]
            unix_user = parts[1].strip()
            tty = parts[2].strip()
            raw_ip = parts[3].strip()
            if not unix_user or unix_user in ('USER', 'user', ''):
                continue
            login_ip = raw_ip if _is_valid_ip(raw_ip) else None
            if session_type == 'A':
                login_at_str = parts[4].strip() if len(parts) > 4 else ''
                login_at = _parse_session_datetime(login_at_str, now)
                if not login_at:
                    logging.debug("sam-sessions: could not parse login_at %r on %s", login_at_str.replace("\n", " ").replace("\r", ""), hostname.replace("\n", "").replace("\r", ""))
                    continue
                db.execute(
                    """
                    INSERT INTO ssh_sessions (server_id, unix_user, tty, login_ip, login_at, is_active)
                    VALUES (%s, %s, %s, %s, %s, true)
                    ON CONFLICT (server_id, unix_user, tty, login_at)
                    DO UPDATE SET is_active = true, collected_at = now()
                    """,
                    (server_id, unix_user, tty, login_ip, login_at),
                )
                active_count += 1
            elif session_type == 'H':
                rest = parts[4].strip() if len(parts) > 4 else ''
                is_still_active = 'still' in rest.lower()
                if ' - ' in rest:
                    login_str, logout_str = rest.split(' - ', 1)
                elif is_still_active:
                    import re as _re
                    login_str = _re.split(r'\s{2,}still|\sstill\s', rest, maxsplit=1)[0].strip()
                    logout_str = ''
                else:
                    login_str = rest
                    logout_str = ''
                login_at = _parse_session_datetime(login_str.strip(), now)
                if not login_at:
                    continue
                logout_at = None
                if not is_still_active and logout_str.strip():
                    logout_at = _parse_session_datetime(logout_str.split('(')[0].strip(), now)
                db.execute(
                    """
                    INSERT INTO ssh_sessions
                        (server_id, unix_user, tty, login_ip, login_at, logout_at, is_active)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (server_id, unix_user, tty, login_at)
                    DO UPDATE SET
                        logout_at = EXCLUDED.logout_at,
                        is_active = EXCLUDED.is_active,
                        collected_at = now()
                    """,
                    (server_id, unix_user, tty, login_ip, login_at, logout_at, is_still_active),
                )
        logging.debug("collect_sessions_on_server: %d active sessions on %s", active_count, hostname.replace("\n", " ").replace("\r", ""))
    finally:
        client.close()


def _fetch_host_key(ip: str, port: int, known_hosts_path: str | None = None) -> None:
    """Fetch the server host key via a single Paramiko Transport connection and append to known_hosts."""
    t = None
    try:
        t = paramiko.Transport((ip, port))
        t.start_client(timeout=10)
        key = t.get_remote_server_key()
    except Exception as exc:
        msg = str(exc)
        if "Connection refused" in msg or "refused" in msg:
            raise SSHPortRefusedError(
                f"SSH port {port} refused - check that SSH is running on that port"
            ) from exc
        raise SSHUnreachableError(
            f"Server unreachable - could not get host key on port {port}. "
            "Check the IP address and that SSH is running."
        ) from exc
    finally:
        if t is not None:
            t.close()
    host = f"[{ip}]:{port}" if port != 22 else ip
    path = known_hosts_path if known_hosts_path is not None else KNOWN_HOSTS
    with open(path, "a") as fh:
        fh.write(f"{host} {key.get_name()} {key.get_base64()}\n")


def provision_server(ip: str, ssh_user: str, ssh_password: str, ssh_port: int = 22, pubkey: str = None) -> None:
    """Connect and provision the server.

    pubkey: the per-server public key content to deploy (required in per-server key mode).
    If ssh_password is empty, verify that the collector key already works (server was
    provisioned manually via ssh-copy-id or provision-host.sh). Otherwise connect with
    password auth and run the provision script.
    """
    import socket

    if pubkey is None:
        raise ValueError("pubkey parameter is required (per-server collector key)")

    # Step 1 - fetch host key via single Paramiko Transport (1 TCP connection, no preauth events)
    _fetch_host_key(ip, ssh_port)

    if not ssh_password:
        raise SSHAuthError(
            "Password is required for provisioning. Use activate_server() for manual provision verification."
        )

    # Step 2 - connect with password auth
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    client.load_host_keys(KNOWN_HOSTS)

    try:
        client.connect(
            hostname=ip,
            port=ssh_port,
            username=ssh_user,
            password=ssh_password,
            timeout=15,
            look_for_keys=False,
            allow_agent=False,
        )
    except paramiko.AuthenticationException:
        raise SSHAuthError("Authentication failed - check your username and password")
    except socket.timeout:
        raise SSHTimeoutError("Connection timed out - server did not respond within 15 seconds")
    except Exception as exc:
        msg = str(exc)
        if any(k in msg for k in ("No route to host", "Network unreachable", "No address associated")):
            raise SSHUnreachableError("Server unreachable - check the IP and network connectivity")
        if "Connection refused" in msg:
            raise SSHPortRefusedError(
                f"SSH port {ssh_port} refused - check that SSH is running on that port"
            )
        raise SSHError(f"Connection failed: {exc}")

    try:
        # Step 3 - read provision script
        with open("/app/provision-host.sh", "rb") as fh:
            script = fh.read()

        # Step 4 - upload provision script via SFTP
        sftp = client.open_sftp()
        sftp.putfo(io.BytesIO(script), "/tmp/sam-provision.sh")
        sftp.chmod("/tmp/sam-provision.sh", 0o700)
        sftp.close()

        # Step 5 - execute via sudo -S (password on stdin)
        cmd = (
            f"sudo -S bash /tmp/sam-provision.sh "
            f"{shlex.quote(pubkey)} {shlex.quote(SSH_USER)}"
        )
        stdin, stdout, stderr = client.exec_command(cmd, timeout=60)
        stdin.write(ssh_password + "\n")
        stdin.flush()
        stdin.channel.shutdown_write()

        exit_code = stdout.channel.recv_exit_status()
        err_out = stderr.read().decode(errors="replace")

        # Step 6 - cleanup (best-effort)
        try:
            client.exec_command("rm -f /tmp/sam-provision.sh")
        except Exception:
            pass

        if exit_code != 0:
            if "sudo:" in err_out and any(
                k in err_out.lower() for k in ("incorrect password", "no password", "not allowed")
            ):
                raise SSHSudoError(
                    "Provisioning failed - check that the user has sudo privileges"
                )
            raise SSHScriptError(
                f"Provisioning script failed (exit {exit_code}): {err_out[:300]}"
            )
    finally:
        client.close()
