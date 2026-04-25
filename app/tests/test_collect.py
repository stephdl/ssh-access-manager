import os
import sys
import uuid
from unittest.mock import MagicMock, patch, call

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import collect


SERVER_ID = str(uuid.uuid4())
KEY_ID = str(uuid.uuid4())

SAMPLE_SERVER = {
    "id": SERVER_ID,
    "hostname": "server-test-01",
    "ip_address": "192.168.1.10",
    "is_active": True,
}

ED25519_B64 = "AAAAC3NzaC1lZDI1NTE5AAAAIBqGBCEpGAhHTB0sklNmFpRGoXv7K3p9iFaQJoWqYmcX"
SAMPLE_LINE = f"testuser\tssh-ed25519 {ED25519_B64} testuser@host"


# ---------------------------------------------------------------------------
# Tests _parse_key_line()
# ---------------------------------------------------------------------------

def test_collect_parse_key_line_valid_ed25519():
    result = collect._parse_key_line(SAMPLE_LINE)
    assert result is not None
    assert result["key_type"] == "ssh-ed25519"
    assert result["fingerprint"].startswith("SHA256:")
    assert result["comment"] == "testuser@host"
    assert result["key_size_bits"] is None


def test_collect_parse_key_line_no_tab_returns_none():
    assert collect._parse_key_line("no tab here") is None


def test_collect_parse_key_line_malformed_key_part_returns_none():
    assert collect._parse_key_line("user\tonlyonefield") is None


def test_collect_parse_key_line_no_comment():
    line = f"root\tssh-ed25519 {ED25519_B64}"
    result = collect._parse_key_line(line)
    assert result is not None
    assert result["comment"] is None


# ---------------------------------------------------------------------------
# Tests scan_server() — scenario 3 (cle inconnue)
# ---------------------------------------------------------------------------

def test_collect_scan_server_scenario3_unknown_key_calls_handle_unknown_key():
    with patch("collect.ssh") as mock_ssh, \
         patch("collect.db") as mock_db, \
         patch("collect.actions") as mock_actions, \
         patch("collect.alerts") as mock_alerts:

        mock_ssh.collect_keys.return_value = [SAMPLE_LINE]
        mock_db.query_one.side_effect = [
            None,   # key not in DB → unknown
        ]
        mock_db.query.return_value = []  # no active keys on server

        result = collect.scan_server(SAMPLE_SERVER)

        mock_actions.handle_unknown_key.assert_called_once()
        assert result["new"] == 1
        assert result["error"] is None


def test_collect_scan_server_scenario3_logs_scan_completed():
    with patch("collect.ssh") as mock_ssh, \
         patch("collect.db") as mock_db, \
         patch("collect.actions") as mock_actions, \
         patch("collect.alerts"):

        mock_ssh.collect_keys.return_value = [SAMPLE_LINE]
        mock_db.query_one.return_value = None
        mock_db.query.return_value = []

        collect.scan_server(SAMPLE_SERVER)

        last_sql = mock_db.execute.call_args_list[-1][0][0]
        assert "SCAN_COMPLETED" in last_sql


# ---------------------------------------------------------------------------
# Tests scan_server() — scenario 2 (cle disparue)
# ---------------------------------------------------------------------------

def test_collect_scan_server_scenario2_disappeared_key_calls_handle_disappeared():
    fp = collect._compute_fingerprint(ED25519_B64)
    with patch("collect.ssh") as mock_ssh, \
         patch("collect.db") as mock_db, \
         patch("collect.actions") as mock_actions, \
         patch("collect.alerts"):

        mock_ssh.collect_keys.return_value = []  # empty scan — key disappeared
        mock_db.query_one.return_value = None
        mock_db.query.return_value = [
            {"key_id": KEY_ID, "fingerprint": fp}  # was ACTIVE
        ]

        result = collect.scan_server(SAMPLE_SERVER)

        mock_actions.handle_disappeared_key.assert_called_once_with(
            KEY_ID, SERVER_ID, "server-test-01", ip="192.168.1.10"
        )
        assert result["disappeared"] == 1


# ---------------------------------------------------------------------------
# Tests scan_server() — cle connue et ACTIVE (mise a jour last_seen)
# ---------------------------------------------------------------------------

def test_collect_scan_server_known_active_key_updates_last_seen():
    with patch("collect.ssh") as mock_ssh, \
         patch("collect.db") as mock_db, \
         patch("collect.actions") as mock_actions, \
         patch("collect.alerts"):

        mock_ssh.collect_keys.return_value = [SAMPLE_LINE]
        mock_db.query_one.side_effect = [
            {"id": KEY_ID},                  # key found in DB
            {"status": "ACTIVE"},            # authorization found
        ]
        mock_db.query.return_value = []      # no disappeared keys

        result = collect.scan_server(SAMPLE_SERVER)

        update_calls = [c[0][0] for c in mock_db.execute.call_args_list]
        assert any("last_seen" in sql for sql in update_calls)
        assert result["known"] == 1
        mock_actions.handle_unknown_key.assert_not_called()
        mock_actions.handle_disappeared_key.assert_not_called()


# ---------------------------------------------------------------------------
# Tests scan_server() — scan echoue (SCAN_FAILED + alerte CRITICAL)
# ---------------------------------------------------------------------------

def test_collect_scan_server_scan_failed_logs_scan_failed():
    with patch("collect.ssh") as mock_ssh, \
         patch("collect.db") as mock_db, \
         patch("collect.actions") as mock_actions, \
         patch("collect.alerts") as mock_alerts:

        mock_ssh.ensure_scripts.side_effect = Exception("Connection refused")

        result = collect.scan_server(SAMPLE_SERVER)

        assert result["error"] == "Connection refused"
        audit_sql = mock_db.execute.call_args_list[0][0][0]
        assert "SCAN_FAILED" in audit_sql


def test_collect_scan_server_scan_failed_sends_critical_alert():
    with patch("collect.ssh") as mock_ssh, \
         patch("collect.db") as mock_db, \
         patch("collect.alerts") as mock_alerts:

        mock_ssh.ensure_scripts.side_effect = Exception("Timeout")

        collect.scan_server(SAMPLE_SERVER)

        mock_alerts.send_alert.assert_called_once()
        assert mock_alerts.send_alert.call_args[0][0] == "CRITICAL"


# ---------------------------------------------------------------------------
# Tests run_scan()
# ---------------------------------------------------------------------------

def test_collect_run_scan_iterates_all_active_servers():
    servers = [SAMPLE_SERVER, {**SAMPLE_SERVER, "hostname": "server-02", "id": str(uuid.uuid4())}]
    with patch("collect.servers_mod") as mock_srv, \
         patch("collect.scan_server") as mock_scan:

        mock_srv.get_active_servers.return_value = servers
        mock_scan.return_value = {"hostname": "x", "new": 0, "disappeared": 0, "known": 0, "error": None}

        collect.run_scan()

        assert mock_scan.call_count == 2


def test_collect_run_scan_filters_by_hostname():
    servers = [SAMPLE_SERVER, {**SAMPLE_SERVER, "hostname": "server-02", "id": str(uuid.uuid4())}]
    with patch("collect.servers_mod") as mock_srv, \
         patch("collect.scan_server") as mock_scan:

        mock_srv.get_active_servers.return_value = servers
        mock_scan.return_value = {"hostname": "server-test-01", "new": 0, "disappeared": 0, "known": 0, "error": None}

        collect.run_scan(hostname="server-test-01")

        assert mock_scan.call_count == 1
        assert mock_scan.call_args[0][0]["hostname"] == "server-test-01"
