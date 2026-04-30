import os
import sys
import tempfile
from unittest.mock import MagicMock, patch, call

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import servers


SAMPLE_YML = """
servers:
  - hostname: server-prod-01
    ip: 192.168.1.10
    environment: production
    os_family: rhel
  - hostname: server-staging
    ip: 192.168.1.20
    environment: staging
    os_family: debian
"""


# ---------------------------------------------------------------------------
# Tests load_servers_yml()
# ---------------------------------------------------------------------------

def test_servers_load_yml_returns_list():
    with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as f:
        f.write(SAMPLE_YML)
        path = f.name
    try:
        result = servers.load_servers_yml(path)
        assert isinstance(result, list)
        assert len(result) == 2
        assert result[0]["hostname"] == "server-prod-01"
        assert result[1]["ip"] == "192.168.1.20"
    finally:
        os.unlink(path)


def test_servers_load_yml_empty_file_returns_empty_list():
    with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as f:
        f.write("servers:\n")
        path = f.name
    try:
        result = servers.load_servers_yml(path)
        assert result == []
    finally:
        os.unlink(path)


def test_servers_load_yml_missing_file_raises():
    with pytest.raises(FileNotFoundError):
        servers.load_servers_yml("/nonexistent/path/servers.yml")


# ---------------------------------------------------------------------------
# Tests add_to_known_hosts()
# ---------------------------------------------------------------------------

def test_servers_add_known_hosts_skips_if_already_present():
    with tempfile.NamedTemporaryFile("w", suffix="known_hosts", delete=False) as f:
        f.write("|1|abc= ssh-ed25519 AAAA server-prod-01\n")
        path = f.name
    try:
        with patch("subprocess.run") as mock_run:
            servers.add_to_known_hosts("server-prod-01", known_hosts=path)
            mock_run.assert_not_called()
    finally:
        os.unlink(path)


def test_servers_add_known_hosts_calls_ssh_keyscan_if_absent():
    with tempfile.NamedTemporaryFile("w", suffix="known_hosts", delete=False) as f:
        path = f.name
    try:
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                stdout="|1|hash= ssh-ed25519 AAAA\n", returncode=0
            )
            servers.add_to_known_hosts("new-host", known_hosts=path)
            mock_run.assert_called_once()
            args = mock_run.call_args[0][0]
            assert "ssh-keyscan" in args
            assert "new-host" in args
            assert "-p" not in args
    finally:
        os.unlink(path)


def test_servers_add_known_hosts_uses_custom_port():
    with tempfile.NamedTemporaryFile("w", suffix="known_hosts", delete=False) as f:
        path = f.name
    try:
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                stdout="|1|hash= ssh-ed25519 AAAA\n", returncode=0
            )
            servers.add_to_known_hosts("new-host", port=65500, known_hosts=path)
            args = mock_run.call_args[0][0]
            assert "-p" in args
            assert "65500" in args
            assert "new-host" in args
    finally:
        os.unlink(path)


def test_servers_add_known_hosts_appends_output_to_file():
    with tempfile.NamedTemporaryFile("w", suffix="known_hosts", delete=False) as f:
        path = f.name
    try:
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                stdout="|1|hash= ssh-ed25519 KEY new-host\n", returncode=0
            )
            servers.add_to_known_hosts("new-host", known_hosts=path)
        with open(path) as f:
            content = f.read()
        assert "new-host" in content
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# Tests sync_servers()
# ---------------------------------------------------------------------------

def test_servers_sync_calls_upsert_for_each_server():
    with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as f:
        f.write(SAMPLE_YML)
        path = f.name
    try:
        with patch("servers.db") as mock_db:
            result = servers.sync_servers(path)
            assert mock_db.execute.call_count == 2
            first_call_params = mock_db.execute.call_args_list[0][0][1]
            assert first_call_params[0] == "server-prod-01"
            assert first_call_params[1] == "192.168.1.10"
    finally:
        os.unlink(path)


def test_servers_sync_returns_server_list():
    with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as f:
        f.write(SAMPLE_YML)
        path = f.name
    try:
        with patch("servers.db") as mock_db:
            result = servers.sync_servers(path)
            assert len(result) == 2
            assert result[0]["hostname"] == "server-prod-01"
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# Tests get_active_servers()
# ---------------------------------------------------------------------------

def test_servers_get_active_servers_returns_db_result(sample_server):
    with patch("servers.db") as mock_db:
        mock_db.query.return_value = [sample_server]
        result = servers.get_active_servers()
        assert result == [sample_server]
        mock_db.query.assert_called_once()
        assert "is_active = true" in mock_db.query.call_args[0][0]
