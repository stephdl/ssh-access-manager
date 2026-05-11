import hashlib
import io
import json
import logging
import os
import shlex

import paramiko

import db


# ---------------------------------------------------------------------------
# SSH exceptions — typed hierarchy for safer error handling
# ---------------------------------------------------------------------------

class SSHError(RuntimeError):
    """Base SSH error — catch this to handle all SSH failures."""
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


KNOWN_HOSTS = os.environ.get("KNOWN_HOSTS", "/data/keys/known_hosts")
COLLECTOR_KEY = os.environ.get("COLLECTOR_KEY", "/data/keys/collector_key")
SSH_USER = os.environ.get("SSH_USER", "audit-collector")

SAM_COLLECT_PATH = "/usr/local/bin/sam-collect"
SAM_REVOKE_PATH = "/usr/local/bin/sam-revoke"
SAM_ADD_PATH = "/usr/local/bin/sam-add"
SAM_LOCK_USER_PATH = "/usr/local/bin/sam-lock-user"
SAM_UNLOCK_USER_PATH = "/usr/local/bin/sam-unlock-user"

# ---------------------------------------------------------------------------
# Remote scripts — versioned as Python constants.
# Deployed via SFTP if absent or if SHA256 hash differs.
# ---------------------------------------------------------------------------

SAM_COLLECT = b"""#!/bin/sh
# sam-collect - list all authorized_keys on the system
set -e

getent passwd | while IFS=: read user _ _ _ _ home _; do
    keyfile="${home}/.ssh/authorized_keys"
    [ -f "$keyfile" ] || continue
    while IFS= read -r line || [ -n "$line" ]; do
        [ -z "$line" ] && continue
        case "$line" in '#'*) continue ;; esac
        printf '%s\\t%s\\n' "$user" "$line"
    done < "$keyfile"
done

rootkeys="/root/.ssh/authorized_keys"
if [ -f "$rootkeys" ]; then
    while IFS= read -r line || [ -n "$line" ]; do
        [ -z "$line" ] && continue
        case "$line" in '#'*) continue ;; esac
        printf 'root\\t%s\\n' "$line"
    done < "$rootkeys"
fi
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
# sam-add <username> <pubkey> - create user if absent, add pubkey to authorized_keys
set -e

TARGET_USER="${1}"
PUBKEY="${2}"

if [ -z "$TARGET_USER" ] || [ -z "$PUBKEY" ]; then
    echo "Usage: sam-add <username> <pubkey>" >&2
    exit 1
fi

if ! id "$TARGET_USER" >/dev/null 2>&1; then
    useradd -m -s /bin/bash "$TARGET_USER"
    passwd -d "$TARGET_USER" >/dev/null 2>&1 || true
    usermod -aG sam-users "$TARGET_USER" 2>/dev/null || true
fi

home=$(getent passwd "$TARGET_USER" | cut -d: -f6)
if [ -z "$home" ]; then
    echo "Cannot get home for $TARGET_USER" >&2
    exit 1
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
usermod -aG "$GROUP" "$USERNAME"
"""

SAM_REVOKE_GROUP = b"""#!/bin/sh
# sam-revoke-group <unix_user> <group> - remove unix_user from a sam-* group
set -e
USERNAME="$1"
GROUP="$2"
if [ -z "$USERNAME" ] || [ -z "$GROUP" ]; then
    echo "Usage: sam-revoke-group <unix_user> <group>" >&2
    exit 1
fi
case "$GROUP" in
    sam-operator|sam-pkg|sam-root) ;;
    *) echo "Error: group must be sam-operator, sam-pkg or sam-root" >&2; exit 1 ;;
esac
gpasswd -d "$USERNAME" "$GROUP" 2>/dev/null || true
"""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _connect(ip: str, port: int = 22) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    client.load_host_keys(KNOWN_HOSTS)
    client.connect(hostname=ip, port=port, username=SSH_USER, key_filename=COLLECTOR_KEY, timeout=15)
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


def ensure_scripts(hostname: str, server_id: str, ip: str, port: int = 22) -> None:
    """
    Deploy all SAM_* scripts on the remote host if absent or outdated.
    Logs SCRIPT_DEPLOYED to audit_log for each script actually deployed.
    """
    client = _connect(ip, port)
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


def revoke_on_server(hostname: str, fingerprint: str, ip: str, unix_user: str = None, port: int = 22) -> None:
    """Run sam-revoke on the remote host.
    If unix_user is given, revokes only from that user's authorized_keys.
    Otherwise revokes globally (all users on the server).
    """
    import shlex
    client = _connect(ip, port)
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


def collect_keys(hostname: str, ip: str, port: int = 22) -> list[str]:
    """Run sam-collect on the remote host and return raw output lines."""
    client = _connect(ip, port)
    try:
        out, _, rc = _run(client, f"sudo {SAM_COLLECT_PATH}")
        if rc != 0:
            raise SSHError(f"sam-collect failed on {hostname}")
        return [line for line in out.splitlines() if line.strip()]
    finally:
        client.close()


def add_key_on_server(hostname: str, unix_user: str, public_key: str, ip: str, port: int = 22) -> None:
    """Run sam-add on the remote host to deploy a public key for the given Unix user."""
    import shlex
    client = _connect(ip, port)
    try:
        _, err, rc = _run(
            client, f"sudo {SAM_ADD_PATH} {shlex.quote(unix_user)} {shlex.quote(public_key)}"
        )
        if rc != 0:
            raise SSHError(f"sam-add failed on {hostname} (rc={rc}): {err}")
    finally:
        client.close()


def lock_user_on_server(hostname: str, unix_user: str, ip: str, port: int = 22) -> None:
    """Run sam-lock-user on the remote host to lock a Unix user account."""
    import shlex
    client = _connect(ip, port)
    try:
        _, err, rc = _run(
            client, f"sudo {SAM_LOCK_USER_PATH} {shlex.quote(unix_user)}"
        )
        if rc != 0:
            raise SSHError(f"sam-lock-user failed on {hostname} (rc={rc}): {err}")
    finally:
        client.close()


def unlock_user_on_server(hostname: str, unix_user: str, ip: str, port: int = 22) -> None:
    """Run sam-unlock-user on the remote host to unlock a Unix user account."""
    import shlex
    client = _connect(ip, port)
    try:
        _, err, rc = _run(
            client, f"sudo {SAM_UNLOCK_USER_PATH} {shlex.quote(unix_user)}"
        )
        if rc != 0:
            raise SSHError(f"sam-unlock-user failed on {hostname} (rc={rc}): {err}")
    finally:
        client.close()


def grant_group_on_server(hostname: str, unix_user: str, group: str, ip: str, port: int = 22) -> None:
    """Run sam-grant-group on the remote host to add unix_user to a sam-* group."""
    client = _connect(ip, port)
    try:
        _, err, rc = _run(
            client,
            f"sudo {SAM_GRANT_GROUP_PATH} {shlex.quote(unix_user)} {shlex.quote(group)}",
        )
        if rc != 0:
            raise SSHError(f"sam-grant-group failed on {hostname} (rc={rc}): {err}")
    finally:
        client.close()


def revoke_group_on_server(hostname: str, unix_user: str, group: str, ip: str, port: int = 22) -> None:
    """Run sam-revoke-group on the remote host to remove unix_user from a sam-* group."""
    client = _connect(ip, port)
    try:
        _, err, rc = _run(
            client,
            f"sudo {SAM_REVOKE_GROUP_PATH} {shlex.quote(unix_user)} {shlex.quote(group)}",
        )
        if rc != 0:
            raise SSHError(f"sam-revoke-group failed on {hostname} (rc={rc}): {err}")
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
    # ISO date from who: 2026-05-01 07:35 (no timezone — treat as UTC)
    if re.match(r'^\d{4}-\d{2}-\d{2} \d{2}:\d{2}', s):
        try:
            dt = datetime.strptime(s[:16], "%Y-%m-%d %H:%M")
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    # last / last -F fallback: strip leading weekday abbreviation (Mon, Fri, …)
    # then inject current year when absent — avoids DeprecationWarning in Python
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


def collect_sessions_on_server(hostname: str, server_id: str, ip: str, port: int = 22) -> None:
    """Collect SSH sessions via sam-sessions and upsert into ssh_sessions table."""
    import socket
    from datetime import datetime, timezone
    try:
        client = _connect(ip, port)
    except paramiko.AuthenticationException:
        raise SSHAuthError("Authentication failed — check collector key authorization")
    except paramiko.SSHException as exc:
        raise SSHError(f"SSH error connecting to {hostname}: {exc}")
    except socket.timeout:
        raise SSHTimeoutError("Connection timed out — server did not respond within 15 seconds")
    except OSError as exc:
        if "Connection refused" in str(exc):
            raise SSHUnreachableError("Server unreachable — check the IP and network connectivity")
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
                f"SSH port {port} refused — check that SSH is running on that port"
            ) from exc
        raise SSHUnreachableError(
            f"Server unreachable — could not get host key on port {port}. "
            "Check the IP address and that SSH is running."
        ) from exc
    finally:
        if t is not None:
            t.close()
    host = f"[{ip}]:{port}" if port != 22 else ip
    path = known_hosts_path if known_hosts_path is not None else KNOWN_HOSTS
    with open(path, "a") as fh:
        fh.write(f"{host} {key.get_name()} {key.get_base64()}\n")


def provision_server(ip: str, ssh_user: str, ssh_password: str, ssh_port: int = 22) -> None:
    """Connect and provision the server.

    If ssh_password is empty, verify that the collector key already works (server was
    provisioned manually via ssh-copy-id or provision-host.sh). Otherwise connect with
    password auth and run the provision script.
    """
    import socket

    # Step 1 — fetch host key via single Paramiko Transport (1 TCP connection, no preauth events)
    _fetch_host_key(ip, ssh_port)

    if not ssh_password:
        # Key-auth path: verify collector key works (server was provisioned manually)
        try:
            client = _connect(ip, ssh_port)
            client.close()
        except paramiko.AuthenticationException:
            raise SSHAuthError(
                "Key authentication failed — the collector key is not authorized on this server. "
                "Provide an SSH password to provision it automatically."
            )
        except socket.timeout:
            raise SSHTimeoutError("Connection timed out — server did not respond within 15 seconds")
        except Exception as exc:
            msg = str(exc)
            if any(k in msg for k in ("No route to host", "Network unreachable", "No address associated")):
                raise SSHUnreachableError("Server unreachable — check the IP and network connectivity")
            if "Connection refused" in msg:
                raise SSHPortRefusedError(
                    f"SSH port {ssh_port} refused — check that SSH is running on that port"
                )
            raise SSHError(f"Connection failed: {exc}")
        return

    # Step 2 — connect with password auth
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
        raise SSHAuthError("Authentication failed — check your username and password")
    except socket.timeout:
        raise SSHTimeoutError("Connection timed out — server did not respond within 15 seconds")
    except Exception as exc:
        msg = str(exc)
        if any(k in msg for k in ("No route to host", "Network unreachable", "No address associated")):
            raise SSHUnreachableError("Server unreachable — check the IP and network connectivity")
        if "Connection refused" in msg:
            raise SSHPortRefusedError(
                f"SSH port {ssh_port} refused — check that SSH is running on that port"
            )
        raise SSHError(f"Connection failed: {exc}")

    try:
        # Step 3 — read provision script and collector public key
        with open("/app/provision-host.sh", "rb") as fh:
            script = fh.read()
        with open(f"{COLLECTOR_KEY}.pub") as fh:
            collector_pubkey = fh.read().strip()

        # Step 4 — upload provision script via SFTP
        sftp = client.open_sftp()
        sftp.putfo(io.BytesIO(script), "/tmp/sam-provision.sh")
        sftp.chmod("/tmp/sam-provision.sh", 0o700)
        sftp.close()

        # Step 5 — execute via sudo -S (password on stdin)
        cmd = (
            f"sudo -S bash /tmp/sam-provision.sh "
            f"{shlex.quote(collector_pubkey)} {shlex.quote(SSH_USER)}"
        )
        stdin, stdout, stderr = client.exec_command(cmd, timeout=60)
        stdin.write(ssh_password + "\n")
        stdin.flush()
        stdin.channel.shutdown_write()

        exit_code = stdout.channel.recv_exit_status()
        err_out = stderr.read().decode(errors="replace")

        # Step 6 — cleanup (best-effort)
        try:
            client.exec_command("rm -f /tmp/sam-provision.sh")
        except Exception:
            pass

        if exit_code != 0:
            if "sudo:" in err_out and any(
                k in err_out.lower() for k in ("incorrect password", "no password", "not allowed")
            ):
                raise SSHSudoError(
                    "Provisioning failed — check that the user has sudo privileges"
                )
            raise SSHScriptError(
                f"Provisioning script failed (exit {exit_code}): {err_out[:300]}"
            )
    finally:
        client.close()
