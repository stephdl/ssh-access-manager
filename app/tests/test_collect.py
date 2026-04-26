import base64
import os
import struct
import sys
import uuid
from unittest.mock import MagicMock, patch, call

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import collect


def _make_rsa_b64(bits: int) -> str:
    """Build a minimal SSH RSA wire-format base64 blob with an exact modulus bit length."""
    key_type = b"ssh-rsa"
    exponent = b"\x01\x00\x01"  # 65537
    # Leading 0x00 makes it positive; 0x80 + zeros gives bit_length == bits exactly
    modulus = b"\x00" + b"\x80" + b"\x00" * ((bits // 8) - 1)

    def pf(data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + data

    wire = pf(key_type) + pf(exponent) + pf(modulus)
    return base64.b64encode(wire).decode()


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
         patch("collect.scan_server") as mock_scan, \
         patch("collect.alerts"):

        mock_srv.get_active_servers.return_value = servers
        mock_scan.return_value = {"hostname": "x", "new": 0, "disappeared": 0, "known": 0, "error": None, "anomalies": []}

        collect.run_scan()

        assert mock_scan.call_count == 2


def test_collect_run_scan_filters_by_hostname():
    servers = [SAMPLE_SERVER, {**SAMPLE_SERVER, "hostname": "server-02", "id": str(uuid.uuid4())}]
    with patch("collect.servers_mod") as mock_srv, \
         patch("collect.scan_server") as mock_scan, \
         patch("collect.alerts"):

        mock_srv.get_active_servers.return_value = servers
        mock_scan.return_value = {"hostname": "server-test-01", "new": 0, "disappeared": 0, "known": 0, "error": None, "anomalies": []}

        collect.run_scan(hostname="server-test-01")

        assert mock_scan.call_count == 1
        assert mock_scan.call_args[0][0]["hostname"] == "server-test-01"


def test_collect_run_scan_sends_one_grouped_critical_when_anomalies():
    anomaly = {"type": "unknown", "fingerprint": "SHA256:abc", "hostname": "server-test-01", "key_type": "ssh-ed25519", "comment": None}
    with patch("collect.servers_mod") as mock_srv, \
         patch("collect.scan_server") as mock_scan, \
         patch("collect.alerts") as mock_alerts:

        mock_srv.get_active_servers.return_value = [SAMPLE_SERVER]
        mock_scan.return_value = {"hostname": "server-test-01", "new": 1, "disappeared": 0, "known": 0, "error": None, "anomalies": [anomaly]}

        collect.run_scan()

        mock_alerts.send_alert.assert_called_once()
        assert mock_alerts.send_alert.call_args[0][0] == "CRITICAL"
        assert "1 anomalie" in mock_alerts.send_alert.call_args[0][1]


def test_collect_run_scan_no_email_when_no_anomalies():
    with patch("collect.servers_mod") as mock_srv, \
         patch("collect.scan_server") as mock_scan, \
         patch("collect.alerts") as mock_alerts:

        mock_srv.get_active_servers.return_value = [SAMPLE_SERVER]
        mock_scan.return_value = {"hostname": "server-test-01", "new": 0, "disappeared": 0, "known": 3, "error": None, "anomalies": []}

        collect.run_scan()

        mock_alerts.send_alert.assert_not_called()


def test_collect_run_scan_groups_anomalies_from_multiple_servers():
    a1 = {"type": "unknown", "fingerprint": "SHA256:aaa", "hostname": "server-01", "key_type": "ssh-ed25519", "comment": None}
    a2 = {"type": "disappeared", "fingerprint": "SHA256:bbb", "hostname": "server-02"}
    with patch("collect.servers_mod") as mock_srv, \
         patch("collect.scan_server") as mock_scan, \
         patch("collect.alerts") as mock_alerts:

        mock_srv.get_active_servers.return_value = [SAMPLE_SERVER, {**SAMPLE_SERVER, "hostname": "server-02"}]
        mock_scan.side_effect = [
            {"hostname": "server-01", "new": 1, "disappeared": 0, "known": 0, "error": None, "anomalies": [a1]},
            {"hostname": "server-02", "new": 0, "disappeared": 1, "known": 0, "error": None, "anomalies": [a2]},
        ]

        collect.run_scan()

        mock_alerts.send_alert.assert_called_once()
        assert "2 anomalie" in mock_alerts.send_alert.call_args[0][1]


# ---------------------------------------------------------------------------
# Tests _parse_key_line() — RSA key size via SSH wire format
# ---------------------------------------------------------------------------

def test_collect_parse_key_line_rsa_2048_bits():
    b64 = _make_rsa_b64(2048)
    line = f"root\tssh-rsa {b64} user@host"
    result = collect._parse_key_line(line)
    assert result is not None
    assert result["key_type"] == "ssh-rsa"
    assert result["key_size_bits"] == 2048


def test_collect_parse_key_line_rsa_4096_bits():
    b64 = _make_rsa_b64(4096)
    line = f"root\tssh-rsa {b64} user@host"
    result = collect._parse_key_line(line)
    assert result is not None
    assert result["key_size_bits"] == 4096


def test_collect_parse_key_line_rsa_malformed_base64_returns_none_bits():
    line = "root\tssh-rsa NOT_VALID_BASE64!!! user@host"
    result = collect._parse_key_line(line)
    # fingerprint computation will fail → None result
    assert result is None


def test_collect_parse_key_line_rsa_truncated_wire_sets_bits_none():
    # Valid base64 but too short to parse SSH wire format → key_size_bits stays None
    short_b64 = base64.b64encode(b"\x00\x01\x02\x03").decode()
    line = f"root\tssh-rsa {short_b64} user@host"
    result = collect._parse_key_line(line)
    # fingerprint succeeds but RSA size parsing fails silently
    assert result is not None
    assert result["key_size_bits"] is None


# ---------------------------------------------------------------------------
# Tests scan_server() — key_size_bits updated on rescan (existing key path)
# ---------------------------------------------------------------------------

def test_collect_scan_server_updates_key_size_bits_on_rescan():
    rsa_b64 = _make_rsa_b64(2048)
    rsa_line = f"root\tssh-rsa {rsa_b64} user@host"
    with patch("collect.ssh") as mock_ssh, \
         patch("collect.db") as mock_db, \
         patch("collect.actions") as mock_actions, \
         patch("collect.alerts"):

        mock_ssh.collect_keys.return_value = [rsa_line]
        mock_db.query_one.side_effect = [
            {"id": KEY_ID},           # key found in DB
            {"status": "ACTIVE"},     # authorization found
        ]
        mock_db.query.return_value = []  # no disappeared keys

        collect.scan_server(SAMPLE_SERVER)

        # First execute call must update key_size_bits
        update_call = mock_db.execute.call_args_list[0]
        assert "key_size_bits" in update_call[0][0]
        assert 2048 in update_call[0][1]
