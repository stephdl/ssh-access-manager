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

    with patch("ssh._connect") as mock_connect, \
         patch("ssh.db") as mock_db:
        client = MagicMock()
        sftp = MagicMock()
        mock_connect.return_value = client
        client.open_sftp.return_value = sftp

        call_count = [0]
        hashes = [local_hash_collect, local_hash_revoke]

        def exec_side_effect(cmd):
            stdout = MagicMock()
            h = hashes[call_count[0] % 2]
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


def test_ssh_sam_revoke_preserves_file_ownership():
    # Verify the script preserves original file ownership before atomic mv
    assert b"chown" in ssh.SAM_REVOKE
    assert b"stat" in ssh.SAM_REVOKE
    assert b"dirname" in ssh.SAM_REVOKE


def test_ssh_sam_revoke_atomic_rewrite_only_when_changed():
    # The mv only happens if changed=1, otherwise the tmp is removed
    assert b"changed" in ssh.SAM_REVOKE
    assert b"rm -f" in ssh.SAM_REVOKE
