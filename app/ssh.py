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
# sam-revoke <fingerprint> - revoke a key by SHA256 fingerprint
# fingerprint format: SHA256:<base64>
set -e

TARGET_FP="${1}"
if [ -z "$TARGET_FP" ]; then
    echo "Usage: sam-revoke <SHA256:base64>" >&2
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

getent passwd | while IFS=: read user _ _ _ _ home _; do
    revoke_from_file "${home}/.ssh/authorized_keys"
done
revoke_from_file "/root/.ssh/authorized_keys"
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
    Deploy SAM_COLLECT, SAM_REVOKE, and SAM_ADD on the remote host if absent or outdated.
    Logs SCRIPT_DEPLOYED to audit_log for each script actually deployed.
    """
    client = _connect(ip)
    try:
        sftp = client.open_sftp()
        for content, remote_path in (
            (SAM_COLLECT, SAM_COLLECT_PATH),
            (SAM_REVOKE, SAM_REVOKE_PATH),
            (SAM_ADD, SAM_ADD_PATH),
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


def revoke_on_server(hostname: str, fingerprint: str, ip: str) -> None:
    """Run sam-revoke on the remote host to remove the key with given fingerprint."""
    client = _connect(ip)
    try:
        _, err, rc = _run(
            client, f"sudo {SAM_REVOKE_PATH} '{fingerprint}'"
        )
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
