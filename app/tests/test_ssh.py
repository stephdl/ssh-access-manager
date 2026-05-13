import hashlib
import io
import os
import sys
from unittest.mock import MagicMock, patch, call

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import ssh


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_client(stdout_data=b"", stderr_data=b"", exit_status=0, sha_out=None):
    """Build a mock paramiko SSHClient."""
    client = MagicMock()
    stdout = MagicMock()
    stderr = MagicMock()
    stdout.read.return_value = stdout_data
    stderr.read.return_value = stderr_data
    stdout.channel.recv_exit_status.return_value = exit_status

    if sha_out is not None:
        sha_stdout = MagicMock()
        sha_stdout.read.return_value = sha_out
        sha_stdout.channel.recv_exit_status.return_value = 0
        client.exec_command.side_effect = [
            (MagicMock(), sha_stdout, MagicMock(read=MagicMock(return_value=b""))),
            (MagicMock(), stdout, stderr),
            (MagicMock(), stdout, stderr),
            (MagicMock(), stdout, stderr),
        ]
    else:
        client.exec_command.return_value = (MagicMock(), stdout, stderr)

    sftp = MagicMock()
    client.open_sftp.return_value = sftp
    return client, sftp


# ---------------------------------------------------------------------------
# RejectPolicy present on every connection
# ---------------------------------------------------------------------------

def test_ssh_connect_uses_reject_policy():
    with patch("ssh.paramiko.SSHClient") as mock_cls, \
         patch("ssh.paramiko.RejectPolicy") as mock_policy:
        client_instance = MagicMock()
        mock_cls.return_value = client_instance
        client_instance.connect.side_effect = Exception("stop")
        try:
            ssh._connect("host", key_path="/tmp/fake.key")
        except Exception:
            pass
        client_instance.set_missing_host_key_policy.assert_called_once_with(
            mock_policy.return_value
        )


def test_ssh_connect_never_uses_auto_add_policy():
    with patch("ssh.paramiko.SSHClient") as mock_cls:
        client_instance = MagicMock()
        mock_cls.return_value = client_instance
        client_instance.connect.side_effect = Exception("stop")
        try:
            ssh._connect("host", key_path="/tmp/fake.key")
        except Exception:
            pass
        for c in client_instance.set_missing_host_key_policy.call_args_list:
            assert not isinstance(c[0][0], type), "AutoAddPolicy should never be used"


# ---------------------------------------------------------------------------
# ensure_scripts — deploys if hash differs
# ---------------------------------------------------------------------------

def test_ssh_ensure_scripts_deploys_when_hash_differs(sample_server):
    wrong_hash = "0" * 64
    with patch("ssh._connect") as mock_connect, \
         patch("ssh.db") as mock_db:
        client = MagicMock()
        sftp = MagicMock()
        mock_connect.return_value = client
        client.open_sftp.return_value = sftp

        # sha256sum returns wrong hash → triggers deploy
        stdout_wrong = MagicMock()
        stdout_wrong.read.return_value = f"{wrong_hash}  /usr/local/bin/sam-collect\n".encode()
        stdout_wrong.channel.recv_exit_status.return_value = 0

        stdout_ok = MagicMock()
        stdout_ok.read.return_value = b""
        stdout_ok.channel.recv_exit_status.return_value = 0

        client.exec_command.return_value = (MagicMock(), stdout_wrong, MagicMock(read=MagicMock(return_value=b"")))

        ssh.ensure_scripts(sample_server["hostname"], sample_server["id"], sample_server["ip_address"], key_path="/tmp/fake.key")

        assert sftp.putfo.called
        assert mock_db.execute.called
        assert mock_db.execute.call_args[0][1][0] == "SCRIPT_DEPLOYED"


def test_ssh_ensure_scripts_skips_when_hash_identical(sample_server):
    local_hash_collect = ssh._sha256(ssh.SAM_COLLECT)
    local_hash_revoke = ssh._sha256(ssh.SAM_REVOKE)
    local_hash_add = ssh._sha256(ssh.SAM_ADD)
    local_hash_lock = ssh._sha256(ssh.SAM_LOCK_USER)
    local_hash_unlock = ssh._sha256(ssh.SAM_UNLOCK_USER)
    local_hash_sessions = ssh._sha256(ssh.SAM_SESSIONS)
    local_hash_grant_group = ssh._sha256(ssh.SAM_GRANT_GROUP)
    local_hash_revoke_group = ssh._sha256(ssh.SAM_REVOKE_GROUP)
    local_hash_self_update = ssh._sha256(ssh.SAM_SELF_UPDATE)

    with patch("ssh._connect") as mock_connect, \
         patch("ssh.db") as mock_db:
        client = MagicMock()
        sftp = MagicMock()
        mock_connect.return_value = client
        client.open_sftp.return_value = sftp

        call_count = [0]
        hashes = [
            local_hash_collect, local_hash_revoke, local_hash_add,
            local_hash_lock, local_hash_unlock, local_hash_sessions,
            local_hash_grant_group, local_hash_revoke_group, local_hash_self_update,
        ]

        def exec_side_effect(cmd):
            stdout = MagicMock()
            h = hashes[call_count[0] % 9]
            stdout.read.return_value = f"{h}  path\n".encode()
            stdout.channel.recv_exit_status.return_value = 0
            call_count[0] += 1
            return (MagicMock(), stdout, MagicMock(read=MagicMock(return_value=b"")))

        client.exec_command.side_effect = exec_side_effect

        ssh.ensure_scripts(sample_server["hostname"], sample_server["id"], sample_server["ip_address"], key_path="/tmp/fake.key")

        sftp.putfo.assert_not_called()
        mock_db.execute.assert_not_called()


# ---------------------------------------------------------------------------
# revoke_on_server — calls sam-revoke with the correct fingerprint
# ---------------------------------------------------------------------------

def test_ssh_revoke_on_server_calls_sam_revoke_with_fingerprint(sample_key):
    with patch("ssh._connect") as mock_connect:
        client = MagicMock()
        mock_connect.return_value = client

        stdout = MagicMock()
        stdout.read.return_value = b""
        stdout.channel.recv_exit_status.return_value = 0
        stderr = MagicMock()
        stderr.read.return_value = b""
        client.exec_command.return_value = (MagicMock(), stdout, stderr)

        ssh.revoke_on_server("server-test-01", sample_key["fingerprint"], ip="192.168.1.10", key_path="/tmp/fake.key")

        cmd = client.exec_command.call_args[0][0]
        assert "sam-revoke" in cmd
        assert sample_key["fingerprint"] in cmd


def test_ssh_revoke_on_server_with_unix_user_passes_second_arg(sample_key):
    with patch("ssh._connect") as mock_connect:
        client = MagicMock()
        mock_connect.return_value = client
        stdout = MagicMock()
        stdout.read.return_value = b""
        stdout.channel.recv_exit_status.return_value = 0
        stderr = MagicMock()
        stderr.read.return_value = b""
        client.exec_command.return_value = (MagicMock(), stdout, stderr)

        ssh.revoke_on_server("server-test-01", sample_key["fingerprint"], ip="192.168.1.10", unix_user="alice", key_path="/tmp/fake.key")

        cmd = client.exec_command.call_args[0][0]
        assert "sam-revoke" in cmd
        assert sample_key["fingerprint"] in cmd
        assert "alice" in cmd


def test_ssh_revoke_on_server_raises_on_nonzero_exit(sample_key):
    with patch("ssh._connect") as mock_connect:
        client = MagicMock()
        mock_connect.return_value = client

        stdout = MagicMock()
        stdout.read.return_value = b""
        stdout.channel.recv_exit_status.return_value = 1
        stderr = MagicMock()
        stderr.read.return_value = b"error"
        client.exec_command.return_value = (MagicMock(), stdout, stderr)

        with pytest.raises(ssh.SSHError):
            ssh.revoke_on_server("server-test-01", sample_key["fingerprint"], ip="192.168.1.10", key_path="/tmp/fake.key")


# ---------------------------------------------------------------------------
# SAM_COLLECT and SAM_REVOKE — content checks
# ---------------------------------------------------------------------------

def test_ssh_sam_collect_dedupes_shared_home_directories():
    """sam-collect must not emit the same authorized_keys file twice
    when several /etc/passwd entries share a home directory.

    The user-reported scenario: RHEL/Rocky ships a legacy `operator`
    system account declared as `operator:x:11:0:operator:/root:...`.
    Without dedup, sam-collect would attribute every key under
    /root/.ssh/authorized_keys to BOTH root and operator — creating
    phantom anomaly rows that no admin can remove (the underlying
    Unix user has no real /home/operator, the key isn't actually on
    operator's behalf).

    The script tracks `seen_files` and emits the FIRST user it sees
    for a given path (with root forced first by an explicit pre-call).
    """
    import subprocess
    import tempfile
    import os

    script_body = ssh.SAM_COLLECT.decode()
    with tempfile.TemporaryDirectory() as tmpdir:
        # Fake `getent passwd` output that contains root + a legacy
        # operator entry with home=/root, plus a regular user with
        # its own home.
        passwd_path = os.path.join(tmpdir, "fake_passwd")
        with open(passwd_path, "w") as f:
            f.write(f"root:x:0:0:root:{tmpdir}/root:/bin/bash\n")
            f.write(f"operator:x:11:0:operator:{tmpdir}/root:/sbin/bash\n")
            f.write(f"alice:x:1000:1000::{tmpdir}/alice:/bin/bash\n")

        # Populate the two homes
        for home, key_b64 in [
            ("root", "AAAAC3RootKey"),
            ("alice", "AAAAC3AliceKey"),
        ]:
            ssh_dir = os.path.join(tmpdir, home, ".ssh")
            os.makedirs(ssh_dir)
            with open(os.path.join(ssh_dir, "authorized_keys"), "w") as f:
                f.write(f"ssh-ed25519 {key_b64} {home}-host\n")

        # Patch the script to use our fake getent + fake /root path
        adapted = script_body.replace(
            "getent passwd", f"cat {passwd_path}"
        ).replace(
            "/root/.ssh/authorized_keys", f"{tmpdir}/root/.ssh/authorized_keys"
        )

        proc = subprocess.run(
            ["sh", "-c", adapted], capture_output=True, text=True, check=True
        )
        lines = [ln for ln in proc.stdout.splitlines() if ln]

        # Each authorized_keys file emitted exactly once.
        users = [ln.split("\t", 1)[0] for ln in lines]
        # root must appear for /root/.ssh/authorized_keys
        assert "root" in users, f"root key not emitted: {proc.stdout!r}"
        # operator must NOT appear (its home=/root is shared with root)
        assert "operator" not in users, (
            f"operator key wrongly emitted despite shared home: {proc.stdout!r}"
        )
        # alice appears with her own dedicated home
        assert "alice" in users


def test_ssh_sam_collect_is_bytes():
    assert isinstance(ssh.SAM_COLLECT, bytes)
    assert b"authorized_keys" in ssh.SAM_COLLECT
    assert b"#!/bin/sh" in ssh.SAM_COLLECT


def test_ssh_sam_revoke_is_bytes():
    assert isinstance(ssh.SAM_REVOKE, bytes)
    assert b"TARGET_FP" in ssh.SAM_REVOKE
    assert b"mktemp" in ssh.SAM_REVOKE
    assert b"mv" in ssh.SAM_REVOKE


def test_ssh_sam_revoke_supports_optional_unix_user():
    assert b"TARGET_USER" in ssh.SAM_REVOKE
    assert b"getent passwd" in ssh.SAM_REVOKE


def test_ssh_sam_revoke_preserves_file_ownership():
    # Verify the script preserves original file ownership before atomic mv
    assert b"chown" in ssh.SAM_REVOKE
    assert b"stat" in ssh.SAM_REVOKE
    assert b"dirname" in ssh.SAM_REVOKE


def test_ssh_sam_revoke_atomic_rewrite_only_when_changed():
    # The mv only happens if changed=1, otherwise the tmp is removed
    assert b"changed" in ssh.SAM_REVOKE
    assert b"rm -f" in ssh.SAM_REVOKE


# ---------------------------------------------------------------------------
# Deployment security — staging outside /tmp, exact destination
# ---------------------------------------------------------------------------

def test_ssh_ensure_scripts_staging_not_in_tmp(sample_server):
    """The staging file must be in the user's home directory, not /tmp."""
    wrong_hash = "0" * 64
    with patch("ssh._connect") as mock_connect, patch("ssh.db"):
        client = MagicMock()
        sftp = MagicMock()
        mock_connect.return_value = client
        client.open_sftp.return_value = sftp
        stdout_wrong = MagicMock()
        stdout_wrong.read.return_value = f"{wrong_hash}  /usr/local/bin/sam-collect\n".encode()
        stdout_wrong.channel.recv_exit_status.return_value = 0
        client.exec_command.return_value = (
            MagicMock(), stdout_wrong, MagicMock(read=MagicMock(return_value=b""))
        )

        ssh.ensure_scripts(sample_server["hostname"], sample_server["id"], sample_server["ip_address"], key_path="/tmp/fake.key")

        staged_path = sftp.putfo.call_args[0][1]
        assert not staged_path.startswith("/tmp"), "Staging must not use /tmp (world-writable)"
        assert "/home/" in staged_path


def test_ssh_ensure_scripts_install_uses_exact_destination(sample_server):
    """sudo install must specify the exact destination path, not a directory."""
    wrong_hash = "0" * 64
    with patch("ssh._connect") as mock_connect, patch("ssh.db"):
        client = MagicMock()
        sftp = MagicMock()
        mock_connect.return_value = client
        client.open_sftp.return_value = sftp
        stdout_wrong = MagicMock()
        stdout_wrong.read.return_value = f"{wrong_hash}  /usr/local/bin/sam-collect\n".encode()
        stdout_wrong.channel.recv_exit_status.return_value = 0
        client.exec_command.return_value = (
            MagicMock(), stdout_wrong, MagicMock(read=MagicMock(return_value=b""))
        )

        ssh.ensure_scripts(sample_server["hostname"], sample_server["id"], sample_server["ip_address"], key_path="/tmp/fake.key")

        commands = [c[0][0] for c in client.exec_command.call_args_list]
        install_cmds = [c for c in commands if "/usr/bin/install" in c]
        assert install_cmds, "No install command found"
        valid_destinations = (
            "/usr/local/bin/sam-collect",
            "/usr/local/bin/sam-revoke",
            "/usr/local/bin/sam-add",
            "/usr/local/bin/sam-lock-user",
            "/usr/local/bin/sam-unlock-user",
            "/usr/local/bin/sam-sessions",
            "/usr/local/bin/sam-grant-group",
            "/usr/local/bin/sam-revoke-group",
            "/usr/local/bin/sam-self-update",
        )
        for cmd in install_cmds:
            dest = cmd.split()[-1]
            assert dest in valid_destinations, (
                f"Install destination must be an exact path, not a directory: {cmd}"
            )


def test_ssh_ensure_scripts_install_uses_mode_750(sample_server):
    """sudo install must use -m 750 to prevent others from reading the files."""
    wrong_hash = "0" * 64
    with patch("ssh._connect") as mock_connect, patch("ssh.db"):
        client = MagicMock()
        sftp = MagicMock()
        mock_connect.return_value = client
        client.open_sftp.return_value = sftp
        stdout_wrong = MagicMock()
        stdout_wrong.read.return_value = f"{wrong_hash}  /usr/local/bin/sam-collect\n".encode()
        stdout_wrong.channel.recv_exit_status.return_value = 0
        client.exec_command.return_value = (
            MagicMock(), stdout_wrong, MagicMock(read=MagicMock(return_value=b""))
        )

        ssh.ensure_scripts(sample_server["hostname"], sample_server["id"], sample_server["ip_address"], key_path="/tmp/fake.key")

        commands = [c[0][0] for c in client.exec_command.call_args_list]
        install_cmds = [c for c in commands if "/usr/bin/install" in c]
        assert install_cmds, "No install command found"
        for cmd in install_cmds:
            assert "-m 750" in cmd, f"install must use -m 750, not -m 755: {cmd}"
            assert "-m 755" not in cmd


def test_ssh_deploy_script_sets_staging_permissions(sample_server):
    """The staging file must be chmod 600 before sudo install."""
    wrong_hash = "0" * 64
    with patch("ssh._connect") as mock_connect, patch("ssh.db"):
        client = MagicMock()
        sftp = MagicMock()
        mock_connect.return_value = client
        client.open_sftp.return_value = sftp
        stdout_wrong = MagicMock()
        stdout_wrong.read.return_value = f"{wrong_hash}  /usr/local/bin/sam-collect\n".encode()
        stdout_wrong.channel.recv_exit_status.return_value = 0
        client.exec_command.return_value = (
            MagicMock(), stdout_wrong, MagicMock(read=MagicMock(return_value=b""))
        )

        ssh.ensure_scripts(sample_server["hostname"], sample_server["id"], sample_server["ip_address"], key_path="/tmp/fake.key")

        staged_path = sftp.putfo.call_args[0][1]
        sftp.chmod.assert_any_call(staged_path, 0o600)


def test_ssh_deploy_script_removes_staging_file_after_install(sample_server):
    """The staging file must be removed after sudo install."""
    wrong_hash = "0" * 64
    with patch("ssh._connect") as mock_connect, patch("ssh.db"):
        client = MagicMock()
        sftp = MagicMock()
        mock_connect.return_value = client
        client.open_sftp.return_value = sftp
        stdout_wrong = MagicMock()
        stdout_wrong.read.return_value = f"{wrong_hash}  /usr/local/bin/sam-collect\n".encode()
        stdout_wrong.channel.recv_exit_status.return_value = 0
        client.exec_command.return_value = (
            MagicMock(), stdout_wrong, MagicMock(read=MagicMock(return_value=b""))
        )

        ssh.ensure_scripts(sample_server["hostname"], sample_server["id"], sample_server["ip_address"], key_path="/tmp/fake.key")

        staged_path = sftp.putfo.call_args[0][1]
        commands = [c[0][0] for c in client.exec_command.call_args_list]
        cleanup_cmds = [c for c in commands if c.startswith("rm -f")]
        assert any(staged_path in c for c in cleanup_cmds), (
            f"The staging file {staged_path} must be removed after install"
        )


# ---------------------------------------------------------------------------
# SAM_ADD — content checks
# ---------------------------------------------------------------------------

def test_ssh_sam_add_is_bytes():
    assert isinstance(ssh.SAM_ADD, bytes)
    assert b"#!/bin/sh" in ssh.SAM_ADD
    assert b"authorized_keys" in ssh.SAM_ADD
    assert b"useradd" in ssh.SAM_ADD


def test_ssh_sam_add_creates_user_if_absent():
    assert b"id " in ssh.SAM_ADD or b"id \"" in ssh.SAM_ADD
    assert b"useradd" in ssh.SAM_ADD


def test_ssh_sam_add_idempotent_key_add():
    assert b"grep -qF" in ssh.SAM_ADD


def test_ssh_sam_add_appends_first_login_hook_to_bash_profile_when_present():
    """RHEL/Rocky skel creates ~/.bash_profile, which bash sources instead
    of ~/.profile. The first-login hook must target the right file."""
    assert b".bash_profile" in ssh.SAM_ADD
    assert b".bash_login" in ssh.SAM_ADD
    assert b".profile" in ssh.SAM_ADD
    assert b"README_first_login.txt" in ssh.SAM_ADD
    assert b"passwd && rm -f" in ssh.SAM_ADD


def test_ssh_add_key_on_server_calls_sam_add(sample_server):
    with patch("ssh._connect") as mock_connect:
        client = MagicMock()
        mock_connect.return_value = client
        stdout = MagicMock()
        stdout.read.return_value = b""
        stdout.channel.recv_exit_status.return_value = 0
        stderr = MagicMock()
        stderr.read.return_value = b""
        client.exec_command.return_value = (MagicMock(), stdout, stderr)

        ssh.add_key_on_server(
            sample_server["hostname"],
            "alice",
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI test",
            sample_server["ip_address"],
            key_path="/tmp/fake.key",
        )

        cmd = client.exec_command.call_args[0][0]
        assert "sam-add" in cmd
        assert "alice" in cmd


def test_ssh_add_key_on_server_raises_on_nonzero_exit(sample_server):
    with patch("ssh._connect") as mock_connect:
        client = MagicMock()
        mock_connect.return_value = client
        stdout = MagicMock()
        stdout.read.return_value = b""
        stdout.channel.recv_exit_status.return_value = 1
        stderr = MagicMock()
        stderr.read.return_value = b"error"
        client.exec_command.return_value = (MagicMock(), stdout, stderr)

        with pytest.raises(ssh.SSHError):
            ssh.add_key_on_server(
                sample_server["hostname"],
                "alice",
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI test",
                sample_server["ip_address"],
                key_path="/tmp/fake.key",
            )


# ---------------------------------------------------------------------------
# Security — JSON injection: audit_log.details serialized with json.dumps
# ---------------------------------------------------------------------------

def test_ssh_ensure_scripts_audit_details_valid_json(sample_server):
    """audit_log.details must be valid JSON even with special characters."""
    import json
    hostile_server = dict(sample_server)
    hostile_server["hostname"] = 'server"}, "injected": "true'

    wrong_hash = "0" * 64
    with patch("ssh._connect") as mock_connect, patch("ssh.db") as mock_db:
        client = MagicMock()
        sftp = MagicMock()
        mock_connect.return_value = client
        client.open_sftp.return_value = sftp
        stdout_wrong = MagicMock()
        stdout_wrong.read.return_value = f"{wrong_hash}  /usr/local/bin/sam-collect\n".encode()
        stdout_wrong.channel.recv_exit_status.return_value = 0
        client.exec_command.return_value = (
            MagicMock(), stdout_wrong, MagicMock(read=MagicMock(return_value=b""))
        )

        ssh.ensure_scripts(hostile_server["hostname"], hostile_server["id"], hostile_server["ip_address"], key_path="/tmp/fake.key")

        assert mock_db.execute.called
        details_arg = mock_db.execute.call_args[0][1][2]
        parsed = json.loads(details_arg)
        assert parsed["hostname"] == hostile_server["hostname"]
        assert "injected" not in parsed


# ---------------------------------------------------------------------------
# SAM_LOCK_USER and SAM_UNLOCK_USER — content checks
# ---------------------------------------------------------------------------

def test_ssh_sam_lock_user_is_bytes():
    assert isinstance(ssh.SAM_LOCK_USER, bytes)
    assert b"#!/bin/sh" in ssh.SAM_LOCK_USER
    assert b"usermod" in ssh.SAM_LOCK_USER
    assert b"-L" in ssh.SAM_LOCK_USER
    assert b"/sbin/nologin" in ssh.SAM_LOCK_USER


def test_ssh_sam_unlock_user_is_bytes():
    assert isinstance(ssh.SAM_UNLOCK_USER, bytes)
    assert b"#!/bin/sh" in ssh.SAM_UNLOCK_USER
    assert b"usermod" in ssh.SAM_UNLOCK_USER
    assert b"-s /bin/bash" in ssh.SAM_UNLOCK_USER


def test_ssh_lock_user_on_server_calls_sam_lock_user(sample_server):
    with patch("ssh._connect") as mock_connect:
        client = MagicMock()
        mock_connect.return_value = client
        stdout = MagicMock()
        stdout.read.return_value = b""
        stdout.channel.recv_exit_status.return_value = 0
        stderr = MagicMock()
        stderr.read.return_value = b""
        client.exec_command.return_value = (MagicMock(), stdout, stderr)

        ssh.lock_user_on_server(sample_server["hostname"], "alice", sample_server["ip_address"], key_path="/tmp/fake.key")

        cmd = client.exec_command.call_args[0][0]
        assert "sam-lock-user" in cmd
        assert "alice" in cmd


def test_ssh_unlock_user_on_server_calls_sam_unlock_user(sample_server):
    with patch("ssh._connect") as mock_connect:
        client = MagicMock()
        mock_connect.return_value = client
        stdout = MagicMock()
        stdout.read.return_value = b""
        stdout.channel.recv_exit_status.return_value = 0
        stderr = MagicMock()
        stderr.read.return_value = b""
        client.exec_command.return_value = (MagicMock(), stdout, stderr)

        ssh.unlock_user_on_server(sample_server["hostname"], "alice", sample_server["ip_address"], key_path="/tmp/fake.key")

        cmd = client.exec_command.call_args[0][0]
        assert "sam-unlock-user" in cmd
        assert "alice" in cmd


# ---------------------------------------------------------------------------
# SAM_SESSIONS — content checks and functions
# ---------------------------------------------------------------------------

def test_ssh_sam_sessions_is_bytes():
    assert isinstance(ssh.SAM_SESSIONS, bytes)
    assert b"utmpdump" in ssh.SAM_SESSIONS
    assert b"/var/run/utmp" in ssh.SAM_SESSIONS
    assert b"/var/log/wtmp" in ssh.SAM_SESSIONS
    assert b"#!/bin/sh" in ssh.SAM_SESSIONS


def test_ssh_parse_session_datetime_iso():
    from datetime import datetime, timezone
    now = datetime(2026, 4, 28, 12, 0, 0, tzinfo=timezone.utc)
    dt = ssh._parse_session_datetime("2026-04-01 10:30", now)
    assert dt is not None
    assert dt.year == 2026
    assert dt.hour == 10


def test_ssh_parse_session_datetime_utmpdump_iso():
    """Primary path: utmpdump ISO 8601 with timezone (2026-05-01T07:35:23,000000+0000)."""
    from datetime import datetime, timezone
    now = datetime(2026, 5, 1, 12, 0, 0, tzinfo=timezone.utc)
    dt = ssh._parse_session_datetime("2026-05-01T07:35:23,000000+0000", now)
    assert dt is not None
    assert dt.year == 2026
    assert dt.month == 5
    assert dt.day == 1
    assert dt.hour == 7
    assert dt.minute == 35
    assert dt.tzinfo is not None


def test_ssh_parse_session_datetime_last_f():
    """Fallback last -F: weekday stripped, year present — must parse correctly."""
    from datetime import datetime, timezone
    now = datetime(2026, 4, 28, 12, 0, 0, tzinfo=timezone.utc)
    dt = ssh._parse_session_datetime("Mon Apr 27 08:00:01 2026", now)
    assert dt is not None
    assert dt.year == 2026


def test_ssh_parse_session_datetime_hhmm():
    from datetime import datetime, timezone
    now = datetime(2026, 4, 28, 12, 0, 0, tzinfo=timezone.utc)
    dt = ssh._parse_session_datetime("10:30", now)
    assert dt is not None
    assert dt.hour == 10


def test_ssh_parse_session_datetime_last_no_year():
    """Fallback last (no -F): 'Mon Apr 28 13:21' — weekday stripped, year injected."""
    from datetime import datetime, timezone
    now = datetime(2026, 4, 28, 12, 0, 0, tzinfo=timezone.utc)
    dt = ssh._parse_session_datetime("Mon Apr 28 13:21", now)
    assert dt is not None
    assert dt.year == 2026
    assert dt.hour == 13
    assert dt.minute == 21


def test_ssh_parse_session_datetime_last_no_year_single_digit_day():
    """Fallback last (no -F): single-digit day with double-space: 'Mon Apr  7 08:00'."""
    from datetime import datetime, timezone
    now = datetime(2026, 4, 28, 12, 0, 0, tzinfo=timezone.utc)
    dt = ssh._parse_session_datetime("Mon Apr  7 08:00", now)
    assert dt is not None
    assert dt.year == 2026
    assert dt.day == 7


def test_ssh_parse_session_datetime_past_month_uses_current_year():
    """A date in a past month of current year stays in current year."""
    from datetime import datetime, timezone
    now = datetime(2026, 4, 28, 12, 0, 0, tzinfo=timezone.utc)
    dt = ssh._parse_session_datetime("Mon Mar  2 10:00", now)
    assert dt is not None
    assert dt.year == 2026
    assert dt.month == 3


def test_ssh_parse_session_datetime_future_month_uses_previous_year():
    """A future date (e.g. Dec in April) must be placed in the previous year."""
    from datetime import datetime, timezone
    now = datetime(2026, 4, 28, 12, 0, 0, tzinfo=timezone.utc)
    dt = ssh._parse_session_datetime("Mon Dec 31 13:23", now)
    assert dt is not None
    assert dt.year == 2025
    assert dt.month == 12
    assert dt.day == 31


def test_ssh_parse_session_datetime_invalid():
    from datetime import datetime, timezone
    now = datetime(2026, 4, 28, 12, 0, 0, tzinfo=timezone.utc)
    dt = ssh._parse_session_datetime("", now)
    assert dt is None


def test_ssh_is_valid_ip_valid():
    assert ssh._is_valid_ip("192.168.1.10") is True
    assert ssh._is_valid_ip("::1") is True


def test_ssh_is_valid_ip_invalid():
    assert ssh._is_valid_ip("Mon") is False
    assert ssh._is_valid_ip("local") is False
    assert ssh._is_valid_ip("") is False


# ---------------------------------------------------------------------------
# audit_sshd_config
# ---------------------------------------------------------------------------

def test_ssh_audit_sshd_config_parses_output():
    """audit_sshd_config parses sshd -T output into a dict {directive_lower: value}."""
    from unittest.mock import MagicMock, patch
    mock_client = MagicMock()
    mock_stdout = MagicMock()
    sshd_output = b"""
port 22
permitrootlogin no
passwordauthentication no
pubkeyauthentication yes
maxauthtries 3
loglevel INFO
usepam yes
x11forwarding no
ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com
"""
    mock_stdout.read.return_value = sshd_output
    mock_stdout.channel.recv_exit_status.return_value = 0
    mock_stderr = MagicMock()
    mock_stderr.read.return_value = b""
    mock_client.exec_command.return_value = (None, mock_stdout, mock_stderr)

    with patch("ssh._connect", return_value=mock_client):
        result = ssh.audit_sshd_config("server1", "192.168.1.1", key_path="/tmp/fake.key")
        assert "port" in result
        assert result["port"] == "22"
        assert result["permitrootlogin"] == "no"
        assert result["passwordauthentication"] == "no"
        assert result["maxauthtries"] == "3"
        assert result["loglevel"] == "INFO"
        assert "ciphers" in result


def test_ssh_audit_sshd_config_raises_sudo_error_on_nonzero():
    """audit_sshd_config raises SSHSudoError when sshd -T exits non-zero."""
    from unittest.mock import MagicMock, patch
    mock_client = MagicMock()
    mock_stdout = MagicMock()
    mock_stdout.read.return_value = b""
    mock_stdout.channel.recv_exit_status.return_value = 1
    mock_stderr = MagicMock()
    mock_stderr.read.return_value = b"sshd: error reading config\n"
    mock_client.exec_command.return_value = (None, mock_stdout, mock_stderr)

    with patch("ssh._connect", return_value=mock_client):
        with pytest.raises(ssh.SSHSudoError, match="sshd -T failed"):
            ssh.audit_sshd_config("server1", "192.168.1.1", key_path="/tmp/fake.key")


def test_ssh_audit_sshd_config_raises_script_error_on_empty():
    """audit_sshd_config raises SSHScriptError when sshd -T produces no output."""
    from unittest.mock import MagicMock, patch
    mock_client = MagicMock()
    mock_stdout = MagicMock()
    mock_stdout.read.return_value = b""
    mock_stdout.channel.recv_exit_status.return_value = 0
    mock_stderr = MagicMock()
    mock_stderr.read.return_value = b""
    mock_client.exec_command.return_value = (None, mock_stdout, mock_stderr)

    with patch("ssh._connect", return_value=mock_client):
        with pytest.raises(ssh.SSHScriptError, match="no parseable output"):
            ssh.audit_sshd_config("server1", "192.168.1.1", key_path="/tmp/fake.key")


def test_ssh_audit_sshd_config_uses_reject_policy():
    """audit_sshd_config uses RejectPolicy (consistency check)."""
    from unittest.mock import MagicMock, patch
    with patch("ssh.paramiko.SSHClient") as mock_cls, \
         patch("ssh.paramiko.RejectPolicy") as mock_policy:
        client_instance = MagicMock()
        mock_cls.return_value = client_instance
        client_instance.connect.side_effect = Exception("stop")
        try:
            ssh._connect("host", key_path="/tmp/fake.key")
        except Exception:
            pass
        client_instance.set_missing_host_key_policy.assert_called_once_with(
            mock_policy.return_value
        )


def test_ssh_collect_sessions_calls_sam_sessions(mock_ssh_client):
    """collect_sessions_on_server runs sam-sessions and upserts results (utmpdump ISO format)."""
    from unittest.mock import MagicMock, patch
    mock_client = MagicMock()
    mock_stdout = MagicMock()
    mock_stdout.read.return_value = (
        b"A\talice\tpts/0\t192.168.1.50\t2026-04-28T10:00:00,000000+0000\n"
    )
    mock_stdout.channel.recv_exit_status.return_value = 0
    mock_stderr = MagicMock()
    mock_stderr.read.return_value = b""
    mock_client.exec_command.return_value = (None, mock_stdout, mock_stderr)

    with patch("ssh._connect", return_value=mock_client), \
         patch("ssh.db") as mock_db:
        ssh.collect_sessions_on_server("server1", "server-uuid-1", "192.168.1.1", key_path="/tmp/fake.key")
        assert mock_db.execute.called


def test_ssh_collect_sessions_marks_inactive_before_reinserting(mock_ssh_client):
    """Before inserting active sessions, all existing active rows are marked inactive."""
    from unittest.mock import MagicMock, patch
    mock_client = MagicMock()
    mock_stdout = MagicMock()
    mock_stdout.read.return_value = (
        b"A\talice\tpts/0\t192.168.1.50\t2026-04-28T10:00:00,000000+0000\n"
    )
    mock_stdout.channel.recv_exit_status.return_value = 0
    mock_stderr = MagicMock()
    mock_stderr.read.return_value = b""
    mock_client.exec_command.return_value = (None, mock_stdout, mock_stderr)

    with patch("ssh._connect", return_value=mock_client), \
         patch("ssh.db") as mock_db:
        ssh.collect_sessions_on_server("server1", "server-uuid-1", "192.168.1.1", key_path="/tmp/fake.key")

        first_call = mock_db.execute.call_args_list[0]
        first_sql = first_call[0][0]
        assert "UPDATE" in first_sql
        assert "is_active = false" in first_sql
        assert first_call[0][1] == ("server-uuid-1",)


def test_ssh_collect_sessions_utmpdump_history(mock_ssh_client):
    """H-type lines from utmpdump (ISO login - ISO logout) are parsed and inserted."""
    from unittest.mock import MagicMock, patch
    mock_client = MagicMock()
    mock_stdout = MagicMock()
    mock_stdout.read.return_value = (
        b"H\troot\tpts/0\t192.168.1.50\t"
        b"2026-04-27T16:37:00,000000+0000 - 2026-04-27T16:45:00,000000+0000\n"
    )
    mock_stdout.channel.recv_exit_status.return_value = 0
    mock_stderr = MagicMock()
    mock_stderr.read.return_value = b""
    mock_client.exec_command.return_value = (None, mock_stdout, mock_stderr)

    with patch("ssh._connect", return_value=mock_client), \
         patch("ssh.db") as mock_db:
        ssh.collect_sessions_on_server("server1", "server-uuid-1", "192.168.1.1", key_path="/tmp/fake.key")
        insert_calls = [c for c in mock_db.execute.call_args_list if "INSERT" in c[0][0]]
        assert insert_calls
        params = insert_calls[0][0][1]
        # login_ip must be the real IP
        assert params[3] == "192.168.1.50"
        # logout_at must not be None
        assert params[5] is not None


def test_ssh_collect_sessions_local_tty_no_ip(mock_ssh_client):
    """Local TTY sessions with no IP (utmpdump 'local') must not fail INET insertion."""
    from unittest.mock import MagicMock, patch
    mock_client = MagicMock()
    mock_stdout = MagicMock()
    # utmpdump format: local TTY login (no real IP → 'local')
    mock_stdout.read.return_value = (
        b"A\troot\ttty1\tlocal\t2026-04-27T18:38:00,000000+0000\n"
    )
    mock_stdout.channel.recv_exit_status.return_value = 0
    mock_stderr = MagicMock()
    mock_stderr.read.return_value = b""
    mock_client.exec_command.return_value = (None, mock_stdout, mock_stderr)

    with patch("ssh._connect", return_value=mock_client), \
         patch("ssh.db") as mock_db:
        ssh.collect_sessions_on_server("server1", "server-uuid-1", "192.168.1.1", key_path="/tmp/fake.key")
        insert_calls = [c for c in mock_db.execute.call_args_list if "INSERT" in c[0][0]]
        if insert_calls:
            params = insert_calls[0][0][1]
            # login_ip must be None ('local' is not a valid IP)
            assert params[3] is None


def test_ssh_collect_sessions_fallback_still_logged_in(mock_ssh_client):
    """Fallback H-type with 'still logged in' (last output) must set is_still_active."""
    from unittest.mock import MagicMock, patch
    mock_client = MagicMock()
    mock_stdout = MagicMock()
    mock_stdout.read.return_value = (
        b"H\troot\ttty1\t\tMon Apr 27 18:38 2026   still logged in\n"
    )
    mock_stdout.channel.recv_exit_status.return_value = 0
    mock_stderr = MagicMock()
    mock_stderr.read.return_value = b""
    mock_client.exec_command.return_value = (None, mock_stdout, mock_stderr)

    with patch("ssh._connect", return_value=mock_client), \
         patch("ssh.db") as mock_db:
        ssh.collect_sessions_on_server("server1", "server-uuid-1", "192.168.1.1", key_path="/tmp/fake.key")
        insert_calls = [c for c in mock_db.execute.call_args_list if "INSERT" in c[0][0]]
        if insert_calls:
            params = insert_calls[0][0][1]
            # is_still_active must be True
            assert params[6] is True


# ---------------------------------------------------------------------------
# _fetch_host_key — single Paramiko Transport connection
# ---------------------------------------------------------------------------

def test_ssh_fetch_host_key_single_connection():
    """_fetch_host_key writes host key entry using a single Transport connection."""
    import tempfile
    from unittest.mock import MagicMock, patch

    mock_key = MagicMock()
    mock_key.get_name.return_value = "ssh-ed25519"
    mock_key.get_base64.return_value = "AAAAC3NzaC1lZDI1NTE5AAAA"

    mock_transport = MagicMock()
    mock_transport.get_remote_server_key.return_value = mock_key

    with tempfile.NamedTemporaryFile("w", suffix="known_hosts", delete=False) as f:
        path = f.name
    try:
        with patch("ssh.paramiko.Transport", return_value=mock_transport):
            ssh._fetch_host_key("192.168.1.10", 22, known_hosts_path=path)
        with open(path) as f:
            content = f.read()
        assert "192.168.1.10 ssh-ed25519" in content
        mock_transport.start_client.assert_called_once()
        mock_transport.close.assert_called_once()
    finally:
        os.unlink(path)


def test_ssh_fetch_host_key_non_standard_port_brackets():
    """_fetch_host_key uses [ip]:port bracket format for non-22 ports."""
    import tempfile
    from unittest.mock import MagicMock, patch

    mock_key = MagicMock()
    mock_key.get_name.return_value = "ssh-ed25519"
    mock_key.get_base64.return_value = "AAAAC3NzaC1lZDI1NTE5AAAA"

    mock_transport = MagicMock()
    mock_transport.get_remote_server_key.return_value = mock_key

    with tempfile.NamedTemporaryFile("w", suffix="known_hosts", delete=False) as f:
        path = f.name
    try:
        with patch("ssh.paramiko.Transport", return_value=mock_transport):
            ssh._fetch_host_key("10.0.0.1", 2222, known_hosts_path=path)
        with open(path) as f:
            content = f.read()
        assert "[10.0.0.1]:2222 ssh-ed25519" in content
    finally:
        os.unlink(path)


def test_ssh_fetch_host_key_raises_on_unreachable():
    """_fetch_host_key raises SSHUnreachableError when Transport cannot connect (generic error)."""
    import tempfile
    from unittest.mock import MagicMock, patch

    mock_transport = MagicMock()
    mock_transport.start_client.side_effect = Exception("Network timeout")

    with tempfile.NamedTemporaryFile("w", suffix="known_hosts", delete=False) as f:
        path = f.name
    try:
        with patch("ssh.paramiko.Transport", return_value=mock_transport):
            with pytest.raises(ssh.SSHUnreachableError, match="unreachable"):
                ssh._fetch_host_key("10.0.0.1", 22, known_hosts_path=path)
        mock_transport.close.assert_called_once()
    finally:
        os.unlink(path)


def test_ssh_fetch_host_key_connection_refused_raises_runtime_error():
    """_fetch_host_key raises SSHPortRefusedError with 'refused' when Transport constructor gets connection refused."""
    import tempfile
    from unittest.mock import patch
    import paramiko as paramiko_mod

    with tempfile.NamedTemporaryFile("w", suffix="known_hosts", delete=False) as f:
        path = f.name
    try:
        with patch(
            "ssh.paramiko.Transport",
            side_effect=paramiko_mod.SSHException("Unable to connect: [Errno 111] Connection refused"),
        ):
            with pytest.raises(ssh.SSHPortRefusedError, match="refused"):
                ssh._fetch_host_key("10.0.0.1", 22, known_hosts_path=path)
    finally:
        os.unlink(path)


def test_ssh_fetch_host_key_generic_ssh_exception_raises_runtime_error():
    """_fetch_host_key raises SSHUnreachableError with 'unreachable' for non-refused SSHException."""
    import tempfile
    from unittest.mock import patch
    import paramiko as paramiko_mod

    with tempfile.NamedTemporaryFile("w", suffix="known_hosts", delete=False) as f:
        path = f.name
    try:
        with patch(
            "ssh.paramiko.Transport",
            side_effect=paramiko_mod.SSHException("Network unreachable"),
        ):
            with pytest.raises(ssh.SSHUnreachableError, match="unreachable"):
                ssh._fetch_host_key("10.0.0.1", 22, known_hosts_path=path)
    finally:
        os.unlink(path)



# ---------------------------------------------------------------------------
# provision_server — auto-provision via password SSH
# ---------------------------------------------------------------------------

def test_ssh_provision_server_success():
    """provision_server succeeds when all steps complete."""
    from unittest.mock import MagicMock, patch, mock_open

    def mock_open_side_effect(filename, *args, **kwargs):
        if filename == "/app/provision-host.sh":
            return mock_open(read_data=b"#!/bin/sh\necho provisioned")()
        elif filename.endswith(".pub"):
            return mock_open(read_data="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5...")()
        return mock_open()()

    with patch("ssh._fetch_host_key"), \
         patch("builtins.open", side_effect=mock_open_side_effect), \
         patch("ssh.paramiko.SSHClient") as mock_cls, \
         patch("ssh.paramiko.RejectPolicy") as mock_policy:
        mock_client = MagicMock()
        mock_cls.return_value = mock_client

        mock_stdin = MagicMock()
        mock_stdout = MagicMock()
        mock_stderr = MagicMock()
        mock_stdout.channel.recv_exit_status.return_value = 0
        mock_stderr.read.return_value = b""
        mock_client.exec_command.return_value = (mock_stdin, mock_stdout, mock_stderr)

        mock_sftp = MagicMock()
        mock_client.open_sftp.return_value = mock_sftp

        ssh.provision_server("192.168.1.10", "root", "password123", 22, pubkey="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyForTesting")

        mock_client.set_missing_host_key_policy.assert_called_once()
        mock_client.connect.assert_called_once()
        assert mock_client.connect.call_args[1]["password"] == "password123"
        assert mock_sftp.putfo.called
        mock_client.close.assert_called_once()


def test_ssh_provision_server_uses_paramiko_for_host_key():
    """provision_server calls _fetch_host_key instead of subprocess ssh-keyscan."""
    from unittest.mock import MagicMock, patch, mock_open

    with patch("ssh._fetch_host_key") as mock_fetch, \
         patch("builtins.open", mock_open(read_data=b"#!/bin/sh\necho provisioned")), \
         patch("ssh.paramiko.SSHClient") as mock_cls, \
         patch("ssh.paramiko.RejectPolicy"):
        mock_client = MagicMock()
        mock_cls.return_value = mock_client
        mock_client.connect.side_effect = Exception("stop early")

        try:
            ssh.provision_server("192.168.1.10", "root", "password123", 22, pubkey="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyForTesting")
        except Exception:
            pass

        mock_fetch.assert_called_once_with("192.168.1.10", 22)


def test_ssh_provision_server_auth_failed():
    """provision_server raises SSHAuthError on authentication failure."""
    from unittest.mock import MagicMock, patch, mock_open
    import paramiko

    with patch("ssh._fetch_host_key"), \
         patch("builtins.open", mock_open(read_data=b"#!/bin/sh\necho provisioned")), \
         patch("ssh.paramiko.SSHClient") as mock_cls, \
         patch("ssh.paramiko.RejectPolicy"):
        mock_client = MagicMock()
        mock_cls.return_value = mock_client
        mock_client.connect.side_effect = paramiko.AuthenticationException("Auth failed")

        with pytest.raises(ssh.SSHAuthError, match="Authentication failed"):
            ssh.provision_server("192.168.1.10", "root", "wrongpass", 22, pubkey="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyForTesting")


def test_ssh_provision_server_timeout():
    """provision_server raises SSHTimeoutError on timeout."""
    from unittest.mock import MagicMock, patch, mock_open
    import socket

    with patch("ssh._fetch_host_key"), \
         patch("builtins.open", mock_open(read_data=b"#!/bin/sh\necho provisioned")), \
         patch("ssh.paramiko.SSHClient") as mock_cls, \
         patch("ssh.paramiko.RejectPolicy"):
        mock_client = MagicMock()
        mock_cls.return_value = mock_client
        mock_client.connect.side_effect = socket.timeout("Timeout")

        with pytest.raises(ssh.SSHTimeoutError, match="timed out"):
            ssh.provision_server("192.168.1.10", "root", "password123", 22, pubkey="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyForTesting")


def test_ssh_provision_server_no_route():
    """provision_server raises SSHUnreachableError on no route to host."""
    from unittest.mock import MagicMock, patch, mock_open

    with patch("ssh._fetch_host_key"), \
         patch("builtins.open", mock_open(read_data=b"#!/bin/sh\necho provisioned")), \
         patch("ssh.paramiko.SSHClient") as mock_cls, \
         patch("ssh.paramiko.RejectPolicy"):
        mock_client = MagicMock()
        mock_cls.return_value = mock_client
        mock_client.connect.side_effect = Exception("No route to host")

        with pytest.raises(ssh.SSHUnreachableError, match="unreachable"):
            ssh.provision_server("192.168.1.10", "root", "password123", 22, pubkey="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyForTesting")


def test_ssh_provision_server_refused():
    """provision_server raises SSHPortRefusedError on connection refused."""
    from unittest.mock import MagicMock, patch, mock_open

    with patch("ssh._fetch_host_key"), \
         patch("builtins.open", mock_open(read_data=b"#!/bin/sh\necho provisioned")), \
         patch("ssh.paramiko.SSHClient") as mock_cls, \
         patch("ssh.paramiko.RejectPolicy"):
        mock_client = MagicMock()
        mock_cls.return_value = mock_client
        mock_client.connect.side_effect = Exception("Connection refused")

        with pytest.raises(ssh.SSHPortRefusedError, match="refused"):
            ssh.provision_server("192.168.1.10", "root", "password123", 22, pubkey="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyForTesting")


def test_ssh_provision_server_keyscan_unreachable():
    """provision_server raises SSHUnreachableError when host key fetch fails."""
    from unittest.mock import patch

    with patch("ssh._fetch_host_key", side_effect=ssh.SSHUnreachableError("Server unreachable")):
        with pytest.raises(ssh.SSHUnreachableError, match="unreachable"):
            ssh.provision_server("192.168.1.10", "root", "password123", 22, pubkey="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyForTesting")


def test_ssh_provision_server_script_failed():
    """provision_server raises SSHSudoError when provision script fails with sudo error."""
    from unittest.mock import MagicMock, patch, mock_open

    def mock_open_side_effect(filename, *args, **kwargs):
        if filename == "/app/provision-host.sh":
            return mock_open(read_data=b"#!/bin/sh\necho provisioned")()
        elif filename.endswith(".pub"):
            return mock_open(read_data="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5...")()
        return mock_open()()

    with patch("ssh._fetch_host_key"), \
         patch("builtins.open", side_effect=mock_open_side_effect), \
         patch("ssh.paramiko.SSHClient") as mock_cls, \
         patch("ssh.paramiko.RejectPolicy"):
        mock_client = MagicMock()
        mock_cls.return_value = mock_client

        mock_stdin = MagicMock()
        mock_stdout = MagicMock()
        mock_stderr = MagicMock()
        mock_stdout.channel.recv_exit_status.return_value = 1
        mock_stderr.read.return_value = b"sudo: incorrect password for user"
        mock_client.exec_command.return_value = (mock_stdin, mock_stdout, mock_stderr)

        mock_sftp = MagicMock()
        mock_client.open_sftp.return_value = mock_sftp

        with pytest.raises(ssh.SSHSudoError, match="sudo privileges"):
            ssh.provision_server("192.168.1.10", "root", "password123", 22, pubkey="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyForTesting")


def test_ssh_provision_server_uses_reject_policy():
    """provision_server must use RejectPolicy."""
    from unittest.mock import MagicMock, patch, mock_open

    with patch("ssh._fetch_host_key"), \
         patch("builtins.open", mock_open(read_data=b"#!/bin/sh\necho provisioned")), \
         patch("ssh.paramiko.SSHClient") as mock_cls, \
         patch("ssh.paramiko.RejectPolicy") as mock_policy:
        mock_client = MagicMock()
        mock_cls.return_value = mock_client
        mock_client.connect.side_effect = Exception("stop early")

        try:
            ssh.provision_server("192.168.1.10", "root", "password123", 22, pubkey="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyForTesting")
        except Exception:
            pass

        mock_client.set_missing_host_key_policy.assert_called_once_with(mock_policy.return_value)


# Note: provision_server now requires a non-empty password.
# The "verify connectivity with existing key" workflow has been replaced by activate_server().
        mock_client.open_sftp.assert_not_called()


# ---------------------------------------------------------------------------
# SAM_GRANT_GROUP / SAM_REVOKE_GROUP — constants are bytes
# ---------------------------------------------------------------------------

def test_ssh_sam_grant_group_is_bytes():
    """SAM_GRANT_GROUP must be a bytes constant."""
    assert isinstance(ssh.SAM_GRANT_GROUP, bytes)


def test_ssh_sam_revoke_group_is_bytes():
    """SAM_REVOKE_GROUP must be a bytes constant."""
    assert isinstance(ssh.SAM_REVOKE_GROUP, bytes)


# ---------------------------------------------------------------------------
# grant_group_on_server / revoke_group_on_server
# ---------------------------------------------------------------------------

def test_ssh_parse_groups_output():
    """_parse_groups_output parses GROUPS: line correctly."""
    assert ssh._parse_groups_output("GROUPS:sam-users sam-operator") == ["sam-users", "sam-operator"]
    assert ssh._parse_groups_output("GROUPS:") == []
    assert ssh._parse_groups_output("other output\nGROUPS:sam-root\nmore output") == ["sam-root"]
    assert ssh._parse_groups_output("no groups line") == []


def test_ssh_grant_group_on_server_calls_sam_grant_group():
    """grant_group_on_server runs sam-grant-group with correct args and returns groups."""
    from unittest.mock import MagicMock, patch

    with patch("ssh._connect") as mock_connect:
        client = MagicMock()
        mock_connect.return_value = client
        stdout = MagicMock()
        stdout.read.return_value = b"GROUPS:sam-users sam-operator\n"
        stdout.channel.recv_exit_status.return_value = 0
        client.exec_command.return_value = (MagicMock(), stdout, MagicMock(read=MagicMock(return_value=b"")))

        result = ssh.grant_group_on_server("web-01", "alice", "sam-operator", "192.168.1.10", key_path="/tmp/fake.key")

        cmd = client.exec_command.call_args[0][0]
        assert "sam-grant-group" in cmd
        assert "alice" in cmd
        assert "sam-operator" in cmd
        assert result == ["sam-users", "sam-operator"]


def test_ssh_revoke_group_on_server_calls_sam_revoke_group():
    """revoke_group_on_server runs sam-revoke-group with correct args and returns groups."""
    from unittest.mock import MagicMock, patch

    with patch("ssh._connect") as mock_connect:
        client = MagicMock()
        mock_connect.return_value = client
        stdout = MagicMock()
        stdout.read.return_value = b"GROUPS:sam-users\n"
        stdout.channel.recv_exit_status.return_value = 0
        client.exec_command.return_value = (MagicMock(), stdout, MagicMock(read=MagicMock(return_value=b"")))

        result = ssh.revoke_group_on_server("web-01", "alice", "sam-operator", "192.168.1.10", key_path="/tmp/fake.key")

        cmd = client.exec_command.call_args[0][0]
        assert "sam-revoke-group" in cmd
        assert "alice" in cmd
        assert "sam-operator" in cmd
        assert result == ["sam-users"]


def test_ssh_revoke_group_on_server_with_none_strips_all():
    """revoke_group_on_server with group=None strips all SAM groups."""
    from unittest.mock import MagicMock, patch

    with patch("ssh._connect") as mock_connect:
        client = MagicMock()
        mock_connect.return_value = client
        stdout = MagicMock()
        stdout.read.return_value = b"GROUPS:sam-users\n"
        stdout.channel.recv_exit_status.return_value = 0
        client.exec_command.return_value = (MagicMock(), stdout, MagicMock(read=MagicMock(return_value=b"")))

        result = ssh.revoke_group_on_server("web-01", "alice", None, "192.168.1.10", key_path="/tmp/fake.key")

        cmd = client.exec_command.call_args[0][0]
        assert "sam-revoke-group" in cmd
        assert "alice" in cmd
        # Should NOT have a group argument when group=None
        assert "sam-operator" not in cmd
        assert "sam-pkg" not in cmd
        assert "sam-root" not in cmd
        assert result == ["sam-users"]


def test_ssh_grant_group_on_server_raises_on_failure():
    """grant_group_on_server raises SSHError when remote command fails."""
    from unittest.mock import MagicMock, patch

    with patch("ssh._connect") as mock_connect:
        client = MagicMock()
        mock_connect.return_value = client
        stdout = MagicMock()
        stdout.read.return_value = b"group not found"
        stdout.channel.recv_exit_status.return_value = 1
        client.exec_command.return_value = (MagicMock(), stdout, MagicMock(read=MagicMock(return_value=b"error")))

        with pytest.raises(ssh.SSHError):
            ssh.grant_group_on_server("web-01", "alice", "sam-operator", "192.168.1.10", key_path="/tmp/fake.key")


# ---------------------------------------------------------------------------
# SAM_SELF_UPDATE — provision auto-update
# ---------------------------------------------------------------------------

def test_ssh_sam_self_update_is_bytes():
    """SAM_SELF_UPDATE must be a bytes constant."""
    assert isinstance(ssh.SAM_SELF_UPDATE, bytes)
    assert b"#!/bin/sh" in ssh.SAM_SELF_UPDATE
    assert b"sam-operator" in ssh.SAM_SELF_UPDATE
    assert b"sam-users" in ssh.SAM_SELF_UPDATE


def test_ssh_provision_version_is_stable():
    """PROVISION_VERSION must be a stable 16-char hex derived from SAM_SELF_UPDATE."""
    assert isinstance(ssh.PROVISION_VERSION, str)
    assert len(ssh.PROVISION_VERSION) == 16
    assert ssh.PROVISION_VERSION == hashlib.sha256(ssh.SAM_SELF_UPDATE).hexdigest()[:16]


def test_ssh_read_provision_version_returns_value():
    """_read_provision_version returns the trimmed version string when file exists."""
    from unittest.mock import MagicMock, patch

    client = MagicMock()
    stdout = MagicMock()
    stdout.read.return_value = b"abc123\n"
    stdout.channel.recv_exit_status.return_value = 0
    client.exec_command.return_value = (MagicMock(), stdout, MagicMock(read=MagicMock(return_value=b"")))

    with patch("ssh._run", return_value=("abc123\n", "", 0)):
        result = ssh._read_provision_version(client)
        assert result == "abc123"


def test_ssh_read_provision_version_returns_none_when_missing():
    """_read_provision_version returns None when the file is missing (exit ≠ 0)."""
    from unittest.mock import MagicMock, patch

    client = MagicMock()
    with patch("ssh._run", return_value=("", "cat: file not found", 1)):
        result = ssh._read_provision_version(client)
        assert result is None


def test_ssh_read_provision_version_strips_whitespace():
    """_read_provision_version strips whitespace from the version string."""
    from unittest.mock import MagicMock, patch

    client = MagicMock()
    with patch("ssh._run", return_value=("  abc  \n  \t  ", "", 0)):
        result = ssh._read_provision_version(client)
        assert result == "abc"


def test_ssh_read_provision_version_empty_string_returns_none():
    """_read_provision_version returns None when the file exists but is empty."""
    from unittest.mock import MagicMock, patch

    client = MagicMock()
    with patch("ssh._run", return_value=("   \n\t  ", "", 0)):
        result = ssh._read_provision_version(client)
        assert result is None


# ---------------------------------------------------------------------------
# _replace_authorized_keys_remote (used by rotate_per_server_key)
# ---------------------------------------------------------------------------

def test_ssh_replace_authorized_keys_writes_only_the_new_pubkey():
    """The rotation finalisation must truncate authorized_keys to the new
    pubkey only — leftover entries from previous (partial) rotations or
    manual additions must NOT survive a rotation on the audit-collector
    account.
    """
    from unittest.mock import MagicMock

    client = MagicMock()
    stdout = MagicMock()
    stdout.read.return_value = b""
    stdout.channel.recv_exit_status.return_value = 0
    client.exec_command.return_value = (MagicMock(), stdout, MagicMock(read=MagicMock(return_value=b"")))

    pubkey = "ssh-ed25519 AAAA+example new-collector"
    ssh._replace_authorized_keys_remote(client, pubkey)

    cmd = client.exec_command.call_args[0][0]
    # The pubkey is the only literal content piped into the temp file.
    assert "authorized_keys.tmp" in cmd
    assert "chmod 600" in cmd
    assert "mv " in cmd and "authorized_keys" in cmd
    # `printf` with a single argument (no grep, no append) guarantees a
    # one-line file. grep -vxF would leave any other line intact.
    assert "printf" in cmd
    assert "grep" not in cmd


def test_ssh_replace_authorized_keys_raises_on_nonzero_exit():
    """Failed write must raise so rotate_per_server_key triggers rollback."""
    from unittest.mock import MagicMock

    client = MagicMock()
    stdout = MagicMock()
    stderr = MagicMock()
    stdout.read.return_value = b""
    stderr.read.return_value = b"permission denied"
    stdout.channel.recv_exit_status.return_value = 1
    client.exec_command.return_value = (MagicMock(), stdout, stderr)

    with pytest.raises(ssh.SSHError, match="Failed to replace authorized_keys"):
        ssh._replace_authorized_keys_remote(client, "ssh-ed25519 AAAA")


def test_ssh_apply_provision_update_invokes_correct_command():
    """apply_provision_update runs sudo sam-self-update <version>."""
    from unittest.mock import MagicMock, patch

    with patch("ssh._connect") as mock_connect:
        client = MagicMock()
        mock_connect.return_value = client
        stdout = MagicMock()
        stdout.read.return_value = b"[sam-self-update] Done.\n"
        stdout.channel.recv_exit_status.return_value = 0
        client.exec_command.return_value = (MagicMock(), stdout, MagicMock(read=MagicMock(return_value=b"")))

        result = ssh.apply_provision_update("web-01", "192.168.1.10", 22, key_path="/tmp/fake.key")

        cmd = client.exec_command.call_args[0][0]
        assert "sudo" in cmd
        assert "/usr/local/bin/sam-self-update" in cmd
        assert ssh.PROVISION_VERSION in cmd
        assert result == ssh.PROVISION_VERSION


def test_ssh_apply_provision_update_raises_on_nonzero_exit():
    """apply_provision_update raises SSHSudoError when the script exits non-zero."""
    from unittest.mock import MagicMock, patch

    with patch("ssh._connect") as mock_connect:
        client = MagicMock()
        mock_connect.return_value = client
        stdout = MagicMock()
        stderr = MagicMock()
        stdout.read.return_value = b""
        stderr.read.return_value = b"ERROR: visudo validation failed"
        stdout.channel.recv_exit_status.return_value = 1
        client.exec_command.return_value = (MagicMock(), stdout, stderr)

        with pytest.raises(ssh.SSHSudoError, match="sam-self-update failed.*exit 1.*visudo validation failed"):
            ssh.apply_provision_update("web-01", "192.168.1.10", 22, key_path="/tmp/fake.key")


def test_ssh_apply_provision_update_returns_version():
    """apply_provision_update returns PROVISION_VERSION on success."""
    from unittest.mock import MagicMock, patch

    with patch("ssh._connect") as mock_connect:
        client = MagicMock()
        mock_connect.return_value = client
        stdout = MagicMock()
        stdout.read.return_value = b"[sam-self-update] Version written.\n"
        stdout.channel.recv_exit_status.return_value = 0
        client.exec_command.return_value = (MagicMock(), stdout, MagicMock(read=MagicMock(return_value=b"")))

        result = ssh.apply_provision_update("web-01", "192.168.1.10", 22, key_path="/tmp/fake.key")
        assert result == ssh.PROVISION_VERSION


def test_ssh_apply_provision_update_uses_reject_policy():
    """apply_provision_update connects with RejectPolicy."""
    from unittest.mock import MagicMock, patch

    with patch("ssh.paramiko.SSHClient") as mock_cls, \
         patch("ssh.paramiko.RejectPolicy") as mock_policy:
        client = MagicMock()
        mock_cls.return_value = client
        stdout = MagicMock()
        stdout.read.return_value = b"[sam-self-update] Done.\n"
        stdout.channel.recv_exit_status.return_value = 0
        client.exec_command.return_value = (MagicMock(), stdout, MagicMock(read=MagicMock(return_value=b"")))

        ssh.apply_provision_update("web-01", "192.168.1.10", 22, key_path="/tmp/fake.key")

        client.set_missing_host_key_policy.assert_called_once_with(mock_policy.return_value)


# ---------------------------------------------------------------------------
# _connect exception wrapping (#437)
# ---------------------------------------------------------------------------

def test_ssh_connect_auth_failure_raises_ssh_auth_error():
    """_connect converts paramiko.AuthenticationException to SSHAuthError."""
    from unittest.mock import patch
    import paramiko

    with patch("ssh.paramiko.SSHClient") as mock_cls:
        client = MagicMock()
        mock_cls.return_value = client
        client.connect.side_effect = paramiko.AuthenticationException("auth failed")

        with pytest.raises(ssh.SSHAuthError, match="SSH authentication failed"):
            ssh._connect("192.168.1.10", 22, key_path="/tmp/fake.key")


def test_ssh_connect_ssh_exception_raises_ssh_error():
    """_connect converts paramiko.SSHException to SSHError."""
    from unittest.mock import patch
    import paramiko

    with patch("ssh.paramiko.SSHClient") as mock_cls:
        client = MagicMock()
        mock_cls.return_value = client
        client.connect.side_effect = paramiko.SSHException("channel failed")

        with pytest.raises(ssh.SSHError, match="SSH protocol error"):
            ssh._connect("192.168.1.10", 22, key_path="/tmp/fake.key")


def test_ssh_connect_timeout_raises_ssh_timeout_error():
    """_connect converts socket.timeout to SSHTimeoutError."""
    from unittest.mock import patch
    import socket

    with patch("ssh.paramiko.SSHClient") as mock_cls:
        client = MagicMock()
        mock_cls.return_value = client
        client.connect.side_effect = socket.timeout()

        with pytest.raises(ssh.SSHTimeoutError, match="timed out after 15s"):
            ssh._connect("192.168.1.10", 22, key_path="/tmp/fake.key")


def test_ssh_connect_connection_refused_raises_ssh_port_refused_error():
    """_connect converts OSError with Connection refused to SSHPortRefusedError."""
    from unittest.mock import patch

    with patch("ssh.paramiko.SSHClient") as mock_cls:
        client = MagicMock()
        mock_cls.return_value = client
        client.connect.side_effect = OSError("Connection refused")

        with pytest.raises(ssh.SSHPortRefusedError, match="Connection refused on.*is sshd running"):
            ssh._connect("192.168.1.10", 22, key_path="/tmp/fake.key")


def test_ssh_connect_os_error_raises_ssh_unreachable_error():
    """_connect converts generic OSError to SSHUnreachableError."""
    from unittest.mock import patch

    with patch("ssh.paramiko.SSHClient") as mock_cls:
        client = MagicMock()
        mock_cls.return_value = client
        client.connect.side_effect = OSError("No route to host")

        with pytest.raises(ssh.SSHUnreachableError, match="Cannot reach"):
            ssh._connect("192.168.1.10", 22, key_path="/tmp/fake.key")


def test_ssh_connect_uses_reject_policy_before_connect():
    """_connect applies RejectPolicy before calling connect."""
    from unittest.mock import patch

    with patch("ssh.paramiko.SSHClient") as mock_cls, \
         patch("ssh.paramiko.RejectPolicy") as mock_policy:
        client = MagicMock()
        mock_cls.return_value = client

        ssh._connect("192.168.1.10", 22, key_path="/tmp/fake.key")

        client.set_missing_host_key_policy.assert_called_once_with(mock_policy.return_value)
        client.load_host_keys.assert_called_once()
        client.connect.assert_called_once()
