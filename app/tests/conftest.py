import base64
import hashlib
import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest


def _compute_fingerprint(key_b64: str) -> str:
    raw = base64.b64decode(key_b64)
    digest = hashlib.sha256(raw).digest()
    b64 = base64.b64encode(digest).decode().rstrip("=")
    return f"SHA256:{b64}"


# ---------------------------------------------------------------------------
# Fixture : mock connexion psycopg2
# ---------------------------------------------------------------------------
@pytest.fixture
def mock_db():
    """Retourne un mock de connexion psycopg2 avec cursor et helpers."""
    conn = MagicMock()
    cursor = MagicMock()
    conn.cursor.return_value.__enter__ = MagicMock(return_value=cursor)
    conn.cursor.return_value.__exit__ = MagicMock(return_value=False)
    cursor.fetchone.return_value = None
    cursor.fetchall.return_value = []
    cursor.rowcount = 1
    return conn


# ---------------------------------------------------------------------------
# Fixture : mock paramiko.SSHClient avec RejectPolicy
# ---------------------------------------------------------------------------
@pytest.fixture
def mock_ssh_client():
    """Retourne un mock paramiko.SSHClient configuré avec RejectPolicy."""
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
# Fixture : mock subprocess pour msmtp
# ---------------------------------------------------------------------------
@pytest.fixture
def mock_smtp():
    """Retourne un mock subprocess pour msmtp — aucun email réel envoyé."""
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        yield mock_run


# ---------------------------------------------------------------------------
# Fixture : serveur de test standard
# ---------------------------------------------------------------------------
@pytest.fixture
def sample_server():
    """Retourne un dict représentant un serveur de test standard."""
    return {
        "id": str(uuid.uuid4()),
        "hostname": "server-test-01",
        "ip_address": "192.168.1.10",
        "os_family": "rhel",
        "os_version": "RHEL 9.3",
        "environment": "lab",
        "is_active": True,
        "added_at": datetime.now(tz=timezone.utc),
    }


# ---------------------------------------------------------------------------
# Fixture : clé SSH ED25519 de test avec fingerprint calculé
# ---------------------------------------------------------------------------
@pytest.fixture
def sample_key():
    """Retourne un dict clé SSH ED25519 de test avec fingerprint SHA256."""
    # Clé publique ED25519 synthétique (base64 valide, non fonctionnelle)
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
