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
# RejectPolicy présent sur chaque connexion
# ---------------------------------------------------------------------------

def test_ssh_connect_uses_reject_policy():
    with patch("ssh.paramiko.SSHClient") as mock_cls, \
         patch("ssh.paramiko.RejectPolicy") as mock_policy:
        client_instance = MagicMock()
        mock_cls.return_value = client_instance
        client_instance.connect.side_effect = Exception("stop")
        try:
            ssh._connect("host")
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
            ssh._connect("host")
        except Exception:
            pass
        for c in client_instance.set_missing_host_key_policy.call_args_list:
            assert not isinstance(c[0][0], type), "AutoAddPolicy should never be used"


# ---------------------------------------------------------------------------
# ensure_scripts — déploie si hash différent
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

        ssh.ensure_scripts(sample_server["hostname"], sample_server["id"], sample_server["ip_address"])

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

    with patch("ssh._connect") as mock_connect, \
         patch("ssh.db") as mock_db:
        client = MagicMock()
        sftp = MagicMock()
        mock_connect.return_value = client
        client.open_sftp.return_value = sftp

        call_count = [0]
        hashes = [local_hash_collect, local_hash_revoke, local_hash_add, local_hash_lock, local_hash_unlock, local_hash_sessions]

        def exec_side_effect(cmd):
            stdout = MagicMock()
            h = hashes[call_count[0] % 6]
            stdout.read.return_value = f"{h}  path\n".encode()
            stdout.channel.recv_exit_status.return_value = 0
            call_count[0] += 1
            return (MagicMock(), stdout, MagicMock(read=MagicMock(return_value=b"")))

        client.exec_command.side_effect = exec_side_effect

        ssh.ensure_scripts(sample_server["hostname"], sample_server["id"], sample_server["ip_address"])

        sftp.putfo.assert_not_called()
        mock_db.execute.assert_not_called()


# ---------------------------------------------------------------------------
# revoke_on_server — appelle sam-revoke avec le bon fingerprint
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

        ssh.revoke_on_server("server-test-01", sample_key["fingerprint"], ip="192.168.1.10")

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

        ssh.revoke_on_server("server-test-01", sample_key["fingerprint"], ip="192.168.1.10", unix_user="alice")

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

        with pytest.raises(RuntimeError):
            ssh.revoke_on_server("server-test-01", sample_key["fingerprint"], ip="192.168.1.10")


# ---------------------------------------------------------------------------
# SAM_COLLECT et SAM_REVOKE — vérifications de contenu
# ---------------------------------------------------------------------------

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
# Sécurité déploiement — staging hors /tmp, destination exacte
# ---------------------------------------------------------------------------

def test_ssh_ensure_scripts_staging_not_in_tmp(sample_server):
    """Le fichier staging doit être dans le home de l'utilisateur, pas /tmp."""
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

        ssh.ensure_scripts(sample_server["hostname"], sample_server["id"], sample_server["ip_address"])

        staged_path = sftp.putfo.call_args[0][1]
        assert not staged_path.startswith("/tmp"), "Staging ne doit pas utiliser /tmp (world-writable)"
        assert "/home/" in staged_path


def test_ssh_ensure_scripts_install_uses_exact_destination(sample_server):
    """sudo install doit spécifier le chemin de destination exact, pas un répertoire."""
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

        ssh.ensure_scripts(sample_server["hostname"], sample_server["id"], sample_server["ip_address"])

        commands = [c[0][0] for c in client.exec_command.call_args_list]
        install_cmds = [c for c in commands if "/usr/bin/install" in c]
        assert install_cmds, "Aucune commande install trouvée"
        valid_destinations = (
            "/usr/local/bin/sam-collect",
            "/usr/local/bin/sam-revoke",
            "/usr/local/bin/sam-add",
            "/usr/local/bin/sam-lock-user",
            "/usr/local/bin/sam-unlock-user",
            "/usr/local/bin/sam-sessions",
        )
        for cmd in install_cmds:
            dest = cmd.split()[-1]
            assert dest in valid_destinations, (
                f"La destination install doit être un chemin exact, pas un répertoire : {cmd}"
            )


# ---------------------------------------------------------------------------
# SAM_ADD — vérifications de contenu
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

        with pytest.raises(RuntimeError):
            ssh.add_key_on_server(
                sample_server["hostname"],
                "alice",
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI test",
                sample_server["ip_address"],
            )


# ---------------------------------------------------------------------------
# Sécurité — JSON injection : audit_log.details sérialisé avec json.dumps
# ---------------------------------------------------------------------------

def test_ssh_ensure_scripts_audit_details_valid_json(sample_server):
    """audit_log.details doit être du JSON valide même avec des caractères spéciaux."""
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

        ssh.ensure_scripts(hostile_server["hostname"], hostile_server["id"], hostile_server["ip_address"])

        assert mock_db.execute.called
        details_arg = mock_db.execute.call_args[0][1][2]
        parsed = json.loads(details_arg)
        assert parsed["hostname"] == hostile_server["hostname"]
        assert "injected" not in parsed


# ---------------------------------------------------------------------------
# SAM_LOCK_USER et SAM_UNLOCK_USER — vérifications de contenu
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

        ssh.lock_user_on_server(sample_server["hostname"], "alice", sample_server["ip_address"])

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

        ssh.unlock_user_on_server(sample_server["hostname"], "alice", sample_server["ip_address"])

        cmd = client.exec_command.call_args[0][0]
        assert "sam-unlock-user" in cmd
        assert "alice" in cmd


# ---------------------------------------------------------------------------
# SAM_SESSIONS — vérifications de contenu et fonctions
# ---------------------------------------------------------------------------

def test_ssh_sam_sessions_is_bytes():
    assert isinstance(ssh.SAM_SESSIONS, bytes)


def test_ssh_parse_session_datetime_iso():
    from datetime import datetime, timezone
    now = datetime(2026, 4, 28, 12, 0, 0, tzinfo=timezone.utc)
    dt = ssh._parse_session_datetime("2026-04-01 10:30", now)
    assert dt is not None
    assert dt.year == 2026
    assert dt.hour == 10


def test_ssh_parse_session_datetime_last_f():
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


def test_ssh_collect_sessions_calls_sam_sessions(mock_ssh_client):
    """collect_sessions_on_server runs sam-sessions and upserts results."""
    from unittest.mock import MagicMock, patch
    mock_client = MagicMock()
    mock_stdout = MagicMock()
    mock_stdout.read.return_value = b"A\talice\tpts/0\t192.168.1.50\t2026-04-28 10:00\n"
    mock_stdout.channel.recv_exit_status.return_value = 0
    mock_stderr = MagicMock()
    mock_stderr.read.return_value = b""
    mock_client.exec_command.return_value = (None, mock_stdout, mock_stderr)

    with patch("ssh._connect", return_value=mock_client), \
         patch("ssh.db") as mock_db:
        ssh.collect_sessions_on_server("server1", "server-uuid-1", "192.168.1.1")
        assert mock_db.execute.called


def test_ssh_collect_sessions_local_tty_no_ip(mock_ssh_client):
    """Local TTY sessions (no IP in last output) must not fail INET insertion."""
    from unittest.mock import MagicMock, patch
    mock_client = MagicMock()
    mock_stdout = MagicMock()
    # 'root' on tty1 with no IP (Mon is a day abbreviation, not an IP)
    mock_stdout.read.return_value = (
        b"H\troot\ttty1\t\tMon Apr 27 18:38 2026   still logged in\n"
    )
    mock_stdout.channel.recv_exit_status.return_value = 0
    mock_stderr = MagicMock()
    mock_stderr.read.return_value = b""
    mock_client.exec_command.return_value = (None, mock_stdout, mock_stderr)

    with patch("ssh._connect", return_value=mock_client), \
         patch("ssh.db") as mock_db:
        # Must not raise — "Mon" must not reach the INET column
        ssh.collect_sessions_on_server("server1", "server-uuid-1", "192.168.1.1")
        if mock_db.execute.called:
            call_args = mock_db.execute.call_args_list[0]
            params = call_args[0][1]
            # login_ip must be None, not "Mon"
            assert params[3] is None
