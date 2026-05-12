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


def _setup_ssh_mocks(mock_ssh):
    """Helper to setup default SSH mocks for scan_server tests."""
    mock_ssh.ensure_scripts.return_value = None
    mock_ssh.collect_sessions_on_server.return_value = None
    client_mock = MagicMock()
    mock_ssh._connect.return_value = client_mock
    mock_ssh.PROVISION_VERSION = "test-version"
    mock_ssh._read_provision_version.return_value = "test-version"  # version matches by default


# ---------------------------------------------------------------------------
# Tests _parse_key_line()
# ---------------------------------------------------------------------------

def test_collect_parse_key_line_valid_ed25519():
    result = collect._parse_key_line(SAMPLE_LINE)
    assert result is not None
    assert result["unix_user"] == "testuser"
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
    assert result["unix_user"] == "root"
    assert result["comment"] is None


def test_collect_parse_key_line_root_user():
    line = f"root\tssh-ed25519 {ED25519_B64} root@server"
    result = collect._parse_key_line(line)
    assert result is not None
    assert result["unix_user"] == "root"


# ---------------------------------------------------------------------------
# Tests unix_user — same key for multiple users
# ---------------------------------------------------------------------------

def test_collect_scan_server_same_key_two_users_creates_two_auth_rows():
    """The same key deployed for alice and bob → two key_authorizations rows."""
    alice_line = f"alice\tssh-ed25519 {ED25519_B64} alice@host"
    bob_line = f"bob\tssh-ed25519 {ED25519_B64} bob@host"

    with patch("collect.ssh") as mock_ssh, \
         patch("collect.db") as mock_db, \
         patch("collect.actions") as mock_actions, \
         patch("collect.alerts"):

        _setup_ssh_mocks(mock_ssh)
        mock_ssh.collect_keys.return_value = [alice_line, bob_line]
        # same key_id for both (same fingerprint)
        mock_db.query_one.side_effect = [
            {"id": KEY_ID},       # key found for alice
            None,                  # no auth for alice → PENDING_REVIEW
            {"id": KEY_ID},       # key found for bob
            None,                  # no auth for bob → PENDING_REVIEW
            {"n": 0},             # sessions count (at end of scan)
        ]
        mock_db.query.return_value = []  # no disappeared keys

        result = collect.scan_server(SAMPLE_SERVER)

        insert_calls = [
            c[0][0] for c in mock_db.execute.call_args_list
            if "PENDING_REVIEW" in c[0][0]
        ]
        assert len(insert_calls) == 2, "Should insert two PENDING_REVIEW rows (alice + bob)"
        assert result["new"] == 2


def test_collect_scan_server_unix_user_passed_to_handle_unknown_key():
    """unix_user is passed to handle_unknown_key for unknown keys."""
    with patch("collect.ssh") as mock_ssh, \
         patch("collect.db") as mock_db, \
         patch("collect.actions") as mock_actions, \
         patch("collect.alerts"):

        _setup_ssh_mocks(mock_ssh)
        mock_ssh.collect_keys.return_value = [SAMPLE_LINE]
        mock_db.query_one.return_value = None   # unknown key
        mock_db.query.return_value = []

        collect.scan_server(SAMPLE_SERVER)

        call_kwargs = mock_actions.handle_unknown_key.call_args[1]
        assert call_kwargs.get("unix_user") == "testuser"


def test_collect_scan_server_only_disappeared_unix_user_row_triggers_scenario2():
    """
    If alice disappears but bob remains present, only alice is detected as disappeared.
    """
    fp = collect._compute_fingerprint(ED25519_B64)
    bob_line = f"bob\tssh-ed25519 {ED25519_B64} bob@host"

    with patch("collect.ssh") as mock_ssh, \
         patch("collect.db") as mock_db, \
         patch("collect.actions") as mock_actions, \
         patch("collect.alerts"):

        _setup_ssh_mocks(mock_ssh)
        mock_ssh.collect_keys.return_value = [bob_line]  # only bob remains
        mock_db.query_one.side_effect = [
            {"id": KEY_ID},        # key found for bob
            {"status": "ACTIVE"},  # bob's auth found
        ]
        # active_on_server: both alice and bob were ACTIVE
        mock_db.query.return_value = [
            {"key_id": KEY_ID, "fingerprint": fp, "unix_user": "alice"},
            {"key_id": KEY_ID, "fingerprint": fp, "unix_user": "bob"},
        ]

        result = collect.scan_server(SAMPLE_SERVER)

        # only alice triggered disappearance
        assert result["disappeared"] == 1
        mock_actions.handle_disappeared_key.assert_called_once_with(
            KEY_ID, SERVER_ID, "server-test-01", ip="192.168.1.10", unix_user="alice"
        )


# ---------------------------------------------------------------------------
# Tests scan_server() — scenario 3 (unknown key)
# ---------------------------------------------------------------------------

def test_collect_scan_server_scenario3_unknown_key_calls_handle_unknown_key():
    with patch("collect.ssh") as mock_ssh, \
         patch("collect.db") as mock_db, \
         patch("collect.actions") as mock_actions, \
         patch("collect.alerts") as mock_alerts:

        _setup_ssh_mocks(mock_ssh)
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

        _setup_ssh_mocks(mock_ssh)
        mock_ssh.collect_keys.return_value = [SAMPLE_LINE]
        mock_db.query_one.return_value = None
        mock_db.query.return_value = []

        collect.scan_server(SAMPLE_SERVER)

        last_sql = mock_db.execute.call_args_list[-1][0][0]
        assert "SCAN_COMPLETED" in last_sql


# ---------------------------------------------------------------------------
# Tests scan_server() — scenario 2 (disappeared key)
# ---------------------------------------------------------------------------

def test_collect_scan_server_scenario2_disappeared_key_calls_handle_disappeared():
    fp = collect._compute_fingerprint(ED25519_B64)
    with patch("collect.ssh") as mock_ssh, \
         patch("collect.db") as mock_db, \
         patch("collect.actions") as mock_actions, \
         patch("collect.alerts"):

        _setup_ssh_mocks(mock_ssh)
        mock_ssh.collect_keys.return_value = []  # empty scan — key disappeared
        mock_db.query_one.return_value = None
        mock_db.query.return_value = [
            {"key_id": KEY_ID, "fingerprint": fp, "unix_user": "alice"}  # was ACTIVE
        ]

        result = collect.scan_server(SAMPLE_SERVER)

        mock_actions.handle_disappeared_key.assert_called_once_with(
            KEY_ID, SERVER_ID, "server-test-01", ip="192.168.1.10", unix_user="alice"
        )
        assert result["disappeared"] == 1


# ---------------------------------------------------------------------------
# Tests scan_server() — scenario 5 (revoked/expired key reappeared)
# ---------------------------------------------------------------------------

def test_collect_scan_server_scenario5_revoked_key_reappeared_calls_handle_reappeared():
    with patch("collect.ssh") as mock_ssh, \
         patch("collect.db") as mock_db, \
         patch("collect.actions") as mock_actions, \
         patch("collect.alerts"):

        _setup_ssh_mocks(mock_ssh)
        mock_ssh.collect_keys.return_value = [SAMPLE_LINE]
        mock_db.query_one.side_effect = [
            {"id": KEY_ID},              # key found in DB
            {"status": "REVOKED"},       # authorization exists but REVOKED
        ]
        mock_db.query.return_value = []  # no disappeared keys
        mock_actions.handle_reappeared_key.return_value = {
            "type": "reappeared", "fingerprint": "SHA256:abc", "hostname": "server-test-01"
        }

        result = collect.scan_server(SAMPLE_SERVER)

        mock_actions.handle_reappeared_key.assert_called_once_with(
            KEY_ID, SERVER_ID, "server-test-01", unix_user="testuser"
        )
        assert result["new"] == 1
        assert len(result["anomalies"]) == 1
        assert result["anomalies"][0]["type"] == "reappeared"


def test_collect_scan_server_scenario5_expired_key_reappeared_calls_handle_reappeared():
    with patch("collect.ssh") as mock_ssh, \
         patch("collect.db") as mock_db, \
         patch("collect.actions") as mock_actions, \
         patch("collect.alerts"):

        _setup_ssh_mocks(mock_ssh)
        mock_ssh.collect_keys.return_value = [SAMPLE_LINE]
        mock_db.query_one.side_effect = [
            {"id": KEY_ID},              # key found in DB
            {"status": "EXPIRED"},       # authorization exists but EXPIRED
        ]
        mock_db.query.return_value = []
        mock_actions.handle_reappeared_key.return_value = {
            "type": "reappeared", "fingerprint": "SHA256:abc", "hostname": "server-test-01"
        }

        result = collect.scan_server(SAMPLE_SERVER)

        mock_actions.handle_reappeared_key.assert_called_once()
        assert result["anomalies"][0]["type"] == "reappeared"


def test_collect_scan_server_scenario5_active_key_not_treated_as_reappeared():
    with patch("collect.ssh") as mock_ssh, \
         patch("collect.db") as mock_db, \
         patch("collect.actions") as mock_actions, \
         patch("collect.alerts"):

        _setup_ssh_mocks(mock_ssh)
        mock_ssh.collect_keys.return_value = [SAMPLE_LINE]
        mock_db.query_one.side_effect = [
            {"id": KEY_ID},
            {"status": "ACTIVE"},        # ACTIVE → should remain known, not reappeared
        ]
        mock_db.query.return_value = []

        result = collect.scan_server(SAMPLE_SERVER)

        mock_actions.handle_reappeared_key.assert_not_called()
        assert result["known"] == 1
        assert result["anomalies"] == []


def test_collect_scan_server_scenario5_pending_review_not_treated_as_reappeared():
    with patch("collect.ssh") as mock_ssh, \
         patch("collect.db") as mock_db, \
         patch("collect.actions") as mock_actions, \
         patch("collect.alerts"):

        _setup_ssh_mocks(mock_ssh)
        mock_ssh.collect_keys.return_value = [SAMPLE_LINE]
        mock_db.query_one.side_effect = [
            {"id": KEY_ID},
            {"status": "PENDING_REVIEW"},  # already pending → unchanged
        ]
        mock_db.query.return_value = []

        result = collect.scan_server(SAMPLE_SERVER)

        mock_actions.handle_reappeared_key.assert_not_called()
        assert result["known"] == 1
        assert result["anomalies"] == []


# ---------------------------------------------------------------------------
# Tests run_scan() — email groupe inclut les reapparitions
# ---------------------------------------------------------------------------

def test_collect_run_scan_includes_reappeared_in_grouped_critical_email():
    anomaly = {"type": "reappeared", "fingerprint": "SHA256:abc", "hostname": "server-test-01"}
    with patch("collect._should_run", return_value=True), \
         patch("collect.servers_mod") as mock_srv, \
         patch("collect.scan_server") as mock_scan, \
         patch("collect.alerts") as mock_alerts:

        mock_srv.get_active_servers.return_value = [SAMPLE_SERVER]
        mock_scan.return_value = {
            "hostname": "server-test-01", "new": 1, "disappeared": 0,
            "known": 0, "error": None, "anomalies": [anomaly]
        }

        collect.run_scan()

        mock_alerts.send_alert.assert_called_once()
        assert mock_alerts.send_alert.call_args[0][0] == "CRITICAL"
        body = mock_alerts.send_alert.call_args[0][2]
        assert "reappeared" in body
        assert "SHA256:abc" in body


# ---------------------------------------------------------------------------
# Tests scan_server() — cle connue et ACTIVE (mise a jour last_seen)
# ---------------------------------------------------------------------------

def test_collect_scan_server_known_active_key_updates_last_seen():
    with patch("collect.ssh") as mock_ssh, \
         patch("collect.db") as mock_db, \
         patch("collect.actions") as mock_actions, \
         patch("collect.alerts"):

        _setup_ssh_mocks(mock_ssh)
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

        _setup_ssh_mocks(mock_ssh)
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


def test_collect_scan_server_missing_per_server_key_logs_scan_failed():
    with patch("collect.ssh") as mock_ssh, \
         patch("collect.db") as mock_db:
        mock_ssh._resolve_key_path.side_effect = KeyError(
            f"no per-server collector key for server {SERVER_ID}; please re-provision"
        )

        result = collect.scan_server(SAMPLE_SERVER)

        assert "no per-server collector key" in result["error"]
        audit_sql = mock_db.execute.call_args_list[0][0][0]
        assert "SCAN_FAILED" in audit_sql
        mock_ssh.ensure_scripts.assert_not_called()
        mock_ssh.collect_keys.assert_not_called()


def test_collect_scan_server_passes_per_server_key_path_to_ssh():
    with patch("collect.ssh") as mock_ssh, \
         patch("collect.db") as mock_db, \
         patch("collect.actions"), \
         patch("collect.alerts"):
        _setup_ssh_mocks(mock_ssh)
        mock_ssh._resolve_key_path.return_value = "/data/keys/per-server/abc.key"
        mock_ssh.collect_keys.return_value = []
        mock_db.query.return_value = []

        collect.scan_server(SAMPLE_SERVER)

        mock_ssh._resolve_key_path.assert_called_once_with(SERVER_ID)
        kwargs = mock_ssh.collect_keys.call_args.kwargs
        assert kwargs["key_path"] == "/data/keys/per-server/abc.key"


# ---------------------------------------------------------------------------
# Tests run_scan()
# ---------------------------------------------------------------------------

def test_collect_run_scan_iterates_all_active_servers():
    servers = [SAMPLE_SERVER, {**SAMPLE_SERVER, "hostname": "server-02", "id": str(uuid.uuid4())}]
    with patch("collect._should_run", return_value=True), \
         patch("collect.servers_mod") as mock_srv, \
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
    with patch("collect._should_run", return_value=True), \
         patch("collect.servers_mod") as mock_srv, \
         patch("collect.scan_server") as mock_scan, \
         patch("collect.alerts") as mock_alerts:

        mock_srv.get_active_servers.return_value = [SAMPLE_SERVER]
        mock_scan.return_value = {"hostname": "server-test-01", "new": 1, "disappeared": 0, "known": 0, "error": None, "anomalies": [anomaly]}

        collect.run_scan()

        mock_alerts.send_alert.assert_called_once()
        assert mock_alerts.send_alert.call_args[0][0] == "CRITICAL"
        assert "1 anomaly" in mock_alerts.send_alert.call_args[0][1]


def test_collect_run_scan_no_email_when_no_anomalies():
    with patch("collect._should_run", return_value=True), \
         patch("collect.servers_mod") as mock_srv, \
         patch("collect.scan_server") as mock_scan, \
         patch("collect.alerts") as mock_alerts:

        mock_srv.get_active_servers.return_value = [SAMPLE_SERVER]
        mock_scan.return_value = {"hostname": "server-test-01", "new": 0, "disappeared": 0, "known": 3, "error": None, "anomalies": []}

        collect.run_scan()

        mock_alerts.send_alert.assert_not_called()


def test_collect_run_scan_groups_anomalies_from_multiple_servers():
    a1 = {"type": "unknown", "fingerprint": "SHA256:aaa", "hostname": "server-01", "key_type": "ssh-ed25519", "comment": None}
    a2 = {"type": "disappeared", "fingerprint": "SHA256:bbb", "hostname": "server-02"}
    with patch("collect._should_run", return_value=True), \
         patch("collect.servers_mod") as mock_srv, \
         patch("collect.scan_server") as mock_scan, \
         patch("collect.alerts") as mock_alerts:

        mock_srv.get_active_servers.return_value = [SAMPLE_SERVER, {**SAMPLE_SERVER, "hostname": "server-02"}]
        mock_scan.side_effect = [
            {"hostname": "server-01", "new": 1, "disappeared": 0, "known": 0, "error": None, "anomalies": [a1]},
            {"hostname": "server-02", "new": 0, "disappeared": 1, "known": 0, "error": None, "anomalies": [a2]},
        ]

        collect.run_scan()

        mock_alerts.send_alert.assert_called_once()
        assert "2 anomalies" in mock_alerts.send_alert.call_args[0][1]


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

        _setup_ssh_mocks(mock_ssh)
        mock_ssh.collect_keys.return_value = [rsa_line]
        mock_db.query_one.side_effect = [
            {"id": KEY_ID},           # key found in DB
            {"status": "ACTIVE"},     # authorization found
        ]
        mock_db.query.return_value = []  # no disappeared keys

        collect.scan_server(SAMPLE_SERVER)

        # An execute call must update key_size_bits with the new size
        update_calls = [c for c in mock_db.execute.call_args_list if "key_size_bits" in c[0][0]]
        assert update_calls, "expected an UPDATE with key_size_bits"
        assert 2048 in update_calls[0][0][1]


# ---------------------------------------------------------------------------
# Tests _should_run() — skip if last scan is too recent
# ---------------------------------------------------------------------------

def test_collect_should_run_true_when_no_scan_completed():
    with patch("collect.db") as mock_db:
        mock_db.query_one.side_effect = [
            {"value": "4"},   # settings
            {"t": None},      # audit_log
        ]
        assert collect._should_run() is True


def test_collect_should_run_false_when_scan_too_recent():
    from datetime import datetime, timezone, timedelta
    recent = datetime.now(tz=timezone.utc) - timedelta(hours=1)
    with patch("collect.db") as mock_db:
        mock_db.query_one.side_effect = [
            {"value": "4"},
            {"t": recent},
        ]
        assert collect._should_run() is False


def test_collect_should_run_true_when_interval_elapsed():
    from datetime import datetime, timezone, timedelta
    old = datetime.now(tz=timezone.utc) - timedelta(hours=5)
    with patch("collect.db") as mock_db:
        mock_db.query_one.side_effect = [
            {"value": "4"},
            {"t": old},
        ]
        assert collect._should_run() is True


def test_collect_run_scan_skips_when_should_not_run():
    with patch("collect._should_run", return_value=False), \
         patch("collect.servers_mod") as mock_srv:
        result = collect.run_scan()
        assert result == []
        mock_srv.get_active_servers.assert_not_called()


def test_collect_run_scan_bypasses_timer_when_admin_id_provided():
    """Manual scans (admin_id set) always run regardless of _should_run."""
    with patch("collect._should_run", return_value=False), \
         patch("collect.servers_mod") as mock_srv, \
         patch("collect.scan_server", return_value={"anomalies": [], "new": 0, "disappeared": 0}), \
         patch("collect.alerts"):
        mock_srv.get_active_servers.return_value = [{"hostname": "h", "ip": "1.2.3.4"}]
        result = collect.run_scan(admin_id="some-admin-id")
        assert result != []
        mock_srv.get_active_servers.assert_called_once()


def test_collect_run_scan_does_not_skip_for_manual_hostname():
    with patch("collect._should_run") as mock_check, \
         patch("collect.servers_mod") as mock_srv, \
         patch("collect.scan_server") as mock_scan:
        mock_srv.get_active_servers.return_value = [SAMPLE_SERVER]
        mock_scan.return_value = {"hostname": "server-test-01", "new": 0, "disappeared": 0, "known": 0, "error": None, "anomalies": []}
        collect.run_scan(hostname="server-test-01")
        mock_check.assert_not_called()


# ---------------------------------------------------------------------------
# Tests provision auto-update orchestration
# ---------------------------------------------------------------------------

def test_collect_skips_provision_update_when_version_matches():
    """scan_server skips apply_provision_update when remote version matches PROVISION_VERSION."""
    with patch("collect.ssh") as mock_ssh, \
         patch("collect.db") as mock_db, \
         patch("collect.actions"), \
         patch("collect.alerts"):

        _setup_ssh_mocks(mock_ssh)
        mock_ssh.ensure_scripts.return_value = None
        mock_ssh.collect_keys.return_value = []
        mock_ssh.collect_sessions_on_server.return_value = None
        mock_db.query_one.return_value = {"n": 0}
        mock_db.query.return_value = []

        # _connect returns a client mock
        client_mock = MagicMock()
        mock_ssh._connect.return_value = client_mock
        # Remote version matches current PROVISION_VERSION → no update
        mock_ssh.PROVISION_VERSION = "abc123def456"
        mock_ssh._read_provision_version.return_value = "abc123def456"

        collect.scan_server(SAMPLE_SERVER)

        mock_ssh.apply_provision_update.assert_not_called()


def test_collect_triggers_provision_update_when_version_differs():
    """scan_server triggers apply_provision_update when remote version differs."""
    with patch("collect.ssh") as mock_ssh, \
         patch("collect.db") as mock_db, \
         patch("collect.actions"), \
         patch("collect.alerts"):

        _setup_ssh_mocks(mock_ssh)
        mock_ssh.ensure_scripts.return_value = None
        mock_ssh.collect_keys.return_value = []
        mock_ssh.collect_sessions_on_server.return_value = None
        mock_db.query_one.return_value = {"n": 0}
        mock_db.query.return_value = []

        client_mock = MagicMock()
        mock_ssh._connect.return_value = client_mock
        mock_ssh._read_provision_version.return_value = "old-version"
        mock_ssh.PROVISION_VERSION = "new-version"
        mock_ssh.apply_provision_update.return_value = "new-version"

        collect.scan_server(SAMPLE_SERVER)

        mock_ssh.apply_provision_update.assert_called_once()
        args, kwargs = mock_ssh.apply_provision_update.call_args
        assert args[:3] == ("server-test-01", "192.168.1.10", 22)
        assert "key_path" in kwargs
        # Check UPDATE servers was called
        update_calls = [c[0][0] for c in mock_db.execute.call_args_list]
        assert any("provision_version" in sql and "provision_drift = FALSE" in sql for sql in update_calls)
        # Check audit log PROVISION_UPDATED
        assert any("PROVISION_UPDATED" in str(c) for c in mock_db.execute.call_args_list)


def test_collect_triggers_provision_update_when_version_absent():
    """scan_server triggers apply_provision_update when remote version is None (never updated)."""
    with patch("collect.ssh") as mock_ssh, \
         patch("collect.db") as mock_db, \
         patch("collect.actions"), \
         patch("collect.alerts"):

        _setup_ssh_mocks(mock_ssh)
        mock_ssh.ensure_scripts.return_value = None
        mock_ssh.collect_keys.return_value = []
        mock_ssh.collect_sessions_on_server.return_value = None
        mock_db.query_one.return_value = {"n": 0}
        mock_db.query.return_value = []

        client_mock = MagicMock()
        mock_ssh._connect.return_value = client_mock
        mock_ssh._read_provision_version.return_value = None
        mock_ssh.PROVISION_VERSION = "new-version"
        mock_ssh.apply_provision_update.return_value = "new-version"

        collect.scan_server(SAMPLE_SERVER)

        mock_ssh.apply_provision_update.assert_called_once()


def test_collect_marks_drift_on_failure():
    """scan_server sets provision_drift=TRUE when apply_provision_update fails."""
    import ssh as ssh_mod
    with patch("collect.ssh") as mock_ssh, \
         patch("collect.db") as mock_db, \
         patch("collect.actions"), \
         patch("collect.alerts"):

        _setup_ssh_mocks(mock_ssh)
        mock_ssh.ensure_scripts.return_value = None
        mock_ssh.collect_keys.return_value = []
        mock_ssh.collect_sessions_on_server.return_value = None
        mock_db.query_one.return_value = {"n": 0}
        mock_db.query.return_value = []

        client_mock = MagicMock()
        mock_ssh._connect.return_value = client_mock
        mock_ssh._read_provision_version.return_value = "old-version"
        mock_ssh.PROVISION_VERSION = "new-version"
        mock_ssh.SSHError = ssh_mod.SSHError
        mock_ssh.apply_provision_update.side_effect = ssh_mod.SSHError("visudo validation failed")

        collect.scan_server(SAMPLE_SERVER)

        # Check UPDATE servers set drift=TRUE
        update_calls = [c[0][0] for c in mock_db.execute.call_args_list]
        assert any("provision_drift = TRUE" in sql for sql in update_calls)
        # Check audit log PROVISION_UPDATE_FAILED
        assert any("PROVISION_UPDATE_FAILED" in str(c) for c in mock_db.execute.call_args_list)


def test_collect_clears_drift_on_success_after_previous_failure():
    """scan_server sets provision_drift=FALSE when update succeeds after previous failure."""
    with patch("collect.ssh") as mock_ssh, \
         patch("collect.db") as mock_db, \
         patch("collect.actions"), \
         patch("collect.alerts"):

        _setup_ssh_mocks(mock_ssh)
        mock_ssh.ensure_scripts.return_value = None
        mock_ssh.collect_keys.return_value = []
        mock_ssh.collect_sessions_on_server.return_value = None
        mock_db.query_one.return_value = {"n": 0}
        mock_db.query.return_value = []

        client_mock = MagicMock()
        mock_ssh._connect.return_value = client_mock
        mock_ssh._read_provision_version.return_value = "old-version"
        mock_ssh.PROVISION_VERSION = "new-version"
        mock_ssh.apply_provision_update.return_value = "new-version"

        collect.scan_server(SAMPLE_SERVER)

        # Check UPDATE servers set drift=FALSE
        update_calls = [c[0][0] for c in mock_db.execute.call_args_list]
        assert any("provision_drift = FALSE" in sql for sql in update_calls)


def test_collect_continues_scan_after_provision_failure():
    """scan_server continues to collect_keys even when apply_provision_update fails."""
    import ssh as ssh_mod
    with patch("collect.ssh") as mock_ssh, \
         patch("collect.db") as mock_db, \
         patch("collect.actions"), \
         patch("collect.alerts"):

        _setup_ssh_mocks(mock_ssh)
        mock_ssh.ensure_scripts.return_value = None
        mock_ssh.collect_keys.return_value = []
        mock_ssh.collect_sessions_on_server.return_value = None
        mock_db.query_one.return_value = {"n": 0}
        mock_db.query.return_value = []

        client_mock = MagicMock()
        mock_ssh._connect.return_value = client_mock
        mock_ssh._read_provision_version.return_value = "old-version"
        mock_ssh.PROVISION_VERSION = "new-version"
        mock_ssh.SSHError = ssh_mod.SSHError
        mock_ssh.apply_provision_update.side_effect = ssh_mod.SSHError("failed")

        collect.scan_server(SAMPLE_SERVER)

        # collect_keys() must be called despite the provision update failure
        mock_ssh.collect_keys.assert_called_once()
