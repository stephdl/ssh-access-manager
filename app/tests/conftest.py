import base64
import hashlib
import os
import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

os.environ.setdefault("FLASK_SECRET_KEY", "test-secret-key-for-testing")


def _compute_fingerprint(key_b64: str) -> str:
    raw = base64.b64decode(key_b64)
    digest = hashlib.sha256(raw).digest()
    b64 = base64.b64encode(digest).decode().rstrip("=")
    return f"SHA256:{b64}"


# ---------------------------------------------------------------------------
# Fixture: mock psycopg2 connection
# ---------------------------------------------------------------------------
@pytest.fixture
def mock_db():
    """Returns a mock psycopg2 connection with cursor and helpers."""
    conn = MagicMock()
    cursor = MagicMock()
    conn.cursor.return_value.__enter__ = MagicMock(return_value=cursor)
    conn.cursor.return_value.__exit__ = MagicMock(return_value=False)
    cursor.fetchone.return_value = None
    cursor.fetchall.return_value = []
    cursor.rowcount = 1
    return conn


# ---------------------------------------------------------------------------
# Fixture: mock paramiko.SSHClient with RejectPolicy
# ---------------------------------------------------------------------------
@pytest.fixture
def mock_ssh_client():
    """Returns a mock paramiko.SSHClient configured with RejectPolicy."""
    with patch("paramiko.SSHClient") as mock_cls:
        client = MagicMock()
        mock_cls.return_value = client
        client.get_transport.return_value = MagicMock()
        client.exec_command.return_value = (
            MagicMock(),   # stdin
            MagicMock(read=MagicMock(return_value=b"")),   # stdout
            MagicMock(read=MagicMock(return_value=b"")),   # stderr
        )
        yield client


# ---------------------------------------------------------------------------
# Fixture: mock subprocess for msmtp
# ---------------------------------------------------------------------------
@pytest.fixture
def mock_smtp():
    """Returns a mock subprocess for msmtp — no real email sent."""
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        yield mock_run


# ---------------------------------------------------------------------------
# Fixture: standard test server
# ---------------------------------------------------------------------------
@pytest.fixture
def sample_server():
    """Returns a dict representing a standard test server."""
    return {
        "id": str(uuid.uuid4()),
        "hostname": "server-test-01",
        "ip_address": "192.168.1.10",
        "ssh_port": 22,
        "os_family": "rhel",
        "os_version": "RHEL 9.3",
        "environment": "lab",
        "is_active": True,
        "added_at": datetime.now(tz=timezone.utc),
    }


# ---------------------------------------------------------------------------
# Fixture: test ED25519 SSH key with computed fingerprint
# ---------------------------------------------------------------------------
@pytest.fixture
def sample_key():
    """Returns a dict test ED25519 SSH key with SHA256 fingerprint."""
    # Synthetic ED25519 public key (valid base64, non-functional)
    key_b64 = (
        "AAAAC3NzaC1lZDI1NTE5AAAAIBqGBCEpGAhHTB0s"
        "klNmFpRGoXv7K3p9iFaQJoWqYmcX"
    )
    fingerprint = _compute_fingerprint(key_b64)
    return {
        "id": str(uuid.uuid4()),
        "fingerprint": fingerprint,
        "key_type": "ssh-ed25519",
        "key_size_bits": None,
        "public_key": f"ssh-ed25519 {key_b64} test@ssh-access-manager",
        "comment": "test@ssh-access-manager",
        "owner_id": None,
        "is_compliant": True,
        "first_seen": datetime.now(tz=timezone.utc),
        "last_seen": datetime.now(tz=timezone.utc),
    }
