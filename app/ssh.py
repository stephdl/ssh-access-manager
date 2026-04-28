import hashlib
import io
import json
import os

import paramiko

import db

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
usermod -s /bin/bash "$USER"
"""

SAM_SESSIONS_PATH = "/usr/local/bin/sam-sessions"

SAM_SESSIONS = b"""#!/bin/sh
# sam-sessions - collect SSH session data
# Outputs tab-separated lines:
#   A\\tuser\\ttty\\tip\\tlogin_str   (active, from 'who')
#   H\\tuser\\ttty\\tip\\trest        (history, from 'last')
set -e

# Active sessions from 'who'
# GNU who: alice pts/0 2024-03-01 10:00 (192.168.1.10)
# busybox who: alice pts/0 Mar  1 10:00
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

# Session history from 'last -F' (full timestamps including year).
# Falls back to 'last' if -F is unsupported (busybox targets).
# Local TTY: 'root tty1   Mon Apr 27 18:38:00 2026 ...'
# SSH:       'alice pts/0 192.168.1.10 Mon Apr 27 18:38:00 2026 ...'
# Detect IP by presence of '.' (IPv4) or ':' (IPv6) in field 3.
{ last -F -n 100 2>/dev/null || last -n 100 2>/dev/null; } | grep -v "^$\\|^reboot\\|^wtmp\\|^btmp" | awk '{
    if(NF<3) next;
    user=$1; tty=$2;
    if($3 ~ /[.:]/) { ip=$3; start=4; } else { ip=""; start=3; }
    rest="";
    for(i=start;i<=NF;i++) rest=rest$i(i<NF?" ":"");
    print "H\\t"user"\\t"tty"\\t"ip"\\t"rest;
}'
"""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _connect(ip: str) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    client.load_host_keys(KNOWN_HOSTS)
    client.connect(hostname=ip, username=SSH_USER, key_filename=COLLECTOR_KEY, timeout=15)
    return client


def _run(client: paramiko.SSHClient, cmd: str) -> tuple[str, str, int]:
    _, stdout, stderr = client.exec_command(cmd)
    out = stdout.read().decode()
    err = stderr.read().decode()
    rc = stdout.channel.recv_exit_status()
    return out, err, rc


def _remote_sha256(client: paramiko.SSHClient, remote_path: str) -> str | None:
    out, _, rc = _run(client, f"sha256sum {remote_path} 2>/dev/null")
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
    _run(client, f"sudo /usr/bin/install -m 755 -o root -g root {tmp_path} {remote_path}")


def ensure_scripts(hostname: str, server_id: str, ip: str) -> None:
    """
    Deploy SAM_COLLECT, SAM_REVOKE, SAM_ADD, SAM_LOCK_USER, and SAM_UNLOCK_USER on the remote host if absent or outdated.
    Logs SCRIPT_DEPLOYED to audit_log for each script actually deployed.
    """
    client = _connect(ip)
    try:
        sftp = client.open_sftp()
        for content, remote_path in (
            (SAM_COLLECT, SAM_COLLECT_PATH),
            (SAM_REVOKE, SAM_REVOKE_PATH),
            (SAM_ADD, SAM_ADD_PATH),
            (SAM_LOCK_USER, SAM_LOCK_USER_PATH),
            (SAM_UNLOCK_USER, SAM_UNLOCK_USER_PATH),
            (SAM_SESSIONS, SAM_SESSIONS_PATH),
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


def revoke_on_server(hostname: str, fingerprint: str, ip: str, unix_user: str = None) -> None:
    """Run sam-revoke on the remote host.
    If unix_user is given, revokes only from that user's authorized_keys.
    Otherwise revokes globally (all users on the server).
    """
    import shlex
    client = _connect(ip)
    try:
        cmd = f"sudo {SAM_REVOKE_PATH} {shlex.quote(fingerprint)}"
        if unix_user:
            cmd += f" {shlex.quote(unix_user)}"
        _, err, rc = _run(client, cmd)
        if rc != 0:
            raise RuntimeError(
                f"sam-revoke failed on {hostname} (rc={rc}): {err}"
            )
    finally:
        client.close()


def collect_keys(hostname: str, ip: str) -> list[str]:
    """Run sam-collect on the remote host and return raw output lines."""
    client = _connect(ip)
    try:
        out, _, rc = _run(client, f"sudo {SAM_COLLECT_PATH}")
        if rc != 0:
            raise RuntimeError(f"sam-collect failed on {hostname}")
        return [line for line in out.splitlines() if line.strip()]
    finally:
        client.close()


def add_key_on_server(hostname: str, unix_user: str, public_key: str, ip: str) -> None:
    """Run sam-add on the remote host to deploy a public key for the given Unix user."""
    import shlex
    client = _connect(ip)
    try:
        _, err, rc = _run(
            client, f"sudo {SAM_ADD_PATH} {shlex.quote(unix_user)} {shlex.quote(public_key)}"
        )
        if rc != 0:
            raise RuntimeError(f"sam-add failed on {hostname} (rc={rc}): {err}")
    finally:
        client.close()


def lock_user_on_server(hostname: str, unix_user: str, ip: str) -> None:
    """Run sam-lock-user on the remote host to lock a Unix user account."""
    import shlex
    client = _connect(ip)
    try:
        _, err, rc = _run(
            client, f"sudo {SAM_LOCK_USER_PATH} {shlex.quote(unix_user)}"
        )
        if rc != 0:
            raise RuntimeError(f"sam-lock-user failed on {hostname} (rc={rc}): {err}")
    finally:
        client.close()


def unlock_user_on_server(hostname: str, unix_user: str, ip: str) -> None:
    """Run sam-unlock-user on the remote host to unlock a Unix user account."""
    import shlex
    client = _connect(ip)
    try:
        _, err, rc = _run(
            client, f"sudo {SAM_UNLOCK_USER_PATH} {shlex.quote(unix_user)}"
        )
        if rc != 0:
            raise RuntimeError(f"sam-unlock-user failed on {hostname} (rc={rc}): {err}")
    finally:
        client.close()


def _parse_session_datetime(s: str, now) -> "datetime | None":
    """Parse various date formats from who/last output. Returns UTC datetime or None."""
    import re
    from datetime import datetime, timezone
    s = s.strip()
    if not s:
        return None
    formats = [
        "%a %b %d %H:%M:%S %Y",
        "%a %b  %d %H:%M:%S %Y",
        "%a %b %d %H:%M %Y",
        "%a %b  %d %H:%M %Y",
        "%a %b %d %H:%M",
        "%a %b  %d %H:%M",
        "%Y-%m-%d %H:%M",
        "%b %d %H:%M",
        "%b  %d %H:%M",
    ]
    for fmt in formats:
        try:
            dt = datetime.strptime(s, fmt)
            if dt.year == 1900:
                dt = dt.replace(year=now.year)
                if dt.date() > now.date():
                    dt = dt.replace(year=now.year - 1)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
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


def collect_sessions_on_server(hostname: str, server_id: str, ip: str) -> None:
    """Collect SSH sessions via sam-sessions and upsert into ssh_sessions table."""
    from datetime import datetime, timezone
    client = _connect(ip)
    try:
        out, _, rc = _run(client, f"sudo {SAM_SESSIONS_PATH}")
        if rc != 0:
            return
        now = datetime.now(timezone.utc)
        db.execute(
            "UPDATE ssh_sessions SET is_active = false WHERE server_id = %s AND is_active = true",
            (server_id,),
        )
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
            elif session_type == 'H':
                rest = parts[4].strip() if len(parts) > 4 else ''
                is_still_active = 'still' in rest.lower()
                if ' - ' in rest:
                    login_str, logout_str = rest.split(' - ', 1)
                else:
                    login_str = rest.split('  still')[0].strip() if is_still_active else rest
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
    finally:
        client.close()
