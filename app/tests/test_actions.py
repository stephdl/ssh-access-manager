import os
import sys
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch, call

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import actions
from actions import UserError


ADMIN_ID = str(uuid.uuid4())
KEY_ID = str(uuid.uuid4())
SERVER_ID = str(uuid.uuid4())
REQUEST_ID = str(uuid.uuid4())


def _future(hours=24):
    return datetime.now(tz=timezone.utc) + timedelta(hours=hours)


# ---------------------------------------------------------------------------
# validate_key
# ---------------------------------------------------------------------------

def test_actions_validate_key_sets_active(sample_key, sample_server):
    with patch("actions.db") as mock_db:
        mock_db.query_one.return_value = {"id": KEY_ID}
        mock_db.query.return_value = [{"key_id": KEY_ID, "server_id": SERVER_ID, "unix_user": "alice"}]
        actions.validate_key(sample_key["fingerprint"], ADMIN_ID)
        update_call = mock_db.execute.call_args_list[0]
        assert "ACTIVE" in update_call[0][0]
        audit_call = mock_db.execute.call_args_list[1]
        assert "KEY_ADDED" in audit_call[0][0]


def test_actions_validate_key_raises_if_key_not_found(sample_key):
    with patch("actions.db") as mock_db:
        mock_db.query_one.return_value = None
        with pytest.raises(UserError, match="not found"):
            actions.validate_key(sample_key["fingerprint"], ADMIN_ID)


def test_actions_validate_key_raises_if_no_pending(sample_key):
    with patch("actions.db") as mock_db:
        mock_db.query_one.return_value = {"id": KEY_ID}
        mock_db.query.return_value = []
        with pytest.raises(UserError, match="PENDING_REVIEW"):
            actions.validate_key(sample_key["fingerprint"], ADMIN_ID)


# ---------------------------------------------------------------------------
# revoke_key — scenario 1 (via systeme, revoked_by=admin_id)
# ---------------------------------------------------------------------------

def test_actions_revoke_key_scenario1_calls_sam_revoke(sample_key):
    auth = {"server_id": SERVER_ID, "hostname": "server-test-01", "ip_address": "192.168.1.10", "ssh_port": 22}
    with patch("actions.db") as mock_db, patch("actions.ssh") as mock_ssh:
        mock_db.query_one.return_value = {"id": KEY_ID}
        mock_db.query.return_value = [auth]
        actions.revoke_key(sample_key["fingerprint"], ADMIN_ID, "test reason")
        mock_ssh.revoke_on_server.assert_called_once_with(
            "server-test-01", sample_key["fingerprint"], ip="192.168.1.10", port=22
        )


def test_actions_revoke_key_scenario1_sets_revoked_by_admin(sample_key):
    auth = {"server_id": SERVER_ID, "hostname": "server-test-01", "ip_address": "192.168.1.10", "ssh_port": 22}
    with patch("actions.db") as mock_db, patch("actions.ssh") as mock_ssh:
        mock_db.query_one.return_value = {"id": KEY_ID}
        mock_db.query.return_value = [auth]
        actions.revoke_key(sample_key["fingerprint"], ADMIN_ID, "test reason")
        update_call = mock_db.execute.call_args_list[0]
        assert "REVOKED" in update_call[0][0]
        assert ADMIN_ID in update_call[0][1]


def test_actions_revoke_key_scenario1_logs_key_revoked(sample_key):
    auth = {"server_id": SERVER_ID, "hostname": "server-test-01", "ip_address": "192.168.1.10", "ssh_port": 22}
    with patch("actions.db") as mock_db, patch("actions.ssh") as mock_ssh:
        mock_db.query_one.return_value = {"id": KEY_ID}
        mock_db.query.return_value = [auth]
        actions.revoke_key(sample_key["fingerprint"], ADMIN_ID, "test reason")
        audit_call = mock_db.execute.call_args_list[1]
        assert "KEY_REVOKED" in audit_call[0][0]


def test_actions_revoke_key_raises_if_key_not_found(sample_key):
    with patch("actions.db") as mock_db:
        mock_db.query_one.return_value = None
        with pytest.raises(UserError, match="not found"):
            actions.revoke_key(sample_key["fingerprint"], ADMIN_ID, "reason")


def test_actions_revoke_key_scoped_calls_sam_revoke_with_unix_user(sample_key):
    """Targeted revocation (hostname + unix_user) calls revoke_on_server with unix_user."""
    server = {"id": SERVER_ID, "ip_address": "192.168.1.10", "ssh_port": 22}
    auth = {"status": "ACTIVE"}
    with patch("actions.db") as mock_db, patch("actions.ssh") as mock_ssh:
        mock_db.query_one.side_effect = [{"id": KEY_ID}, server, auth]
        actions.revoke_key(
            sample_key["fingerprint"], ADMIN_ID, "test",
            hostname="server-test-01", unix_user="alice",
        )
        mock_ssh.revoke_on_server.assert_called_once_with(
            "server-test-01", sample_key["fingerprint"],
            ip="192.168.1.10", unix_user="alice", port=22,
        )


def test_actions_revoke_key_scoped_sets_revoked_for_unix_user_only(sample_key):
    """Targeted revocation — the UPDATE includes unix_user in the WHERE clause."""
    server = {"id": SERVER_ID, "ip_address": "192.168.1.10", "ssh_port": 22}
    auth = {"status": "ACTIVE"}
    with patch("actions.db") as mock_db, patch("actions.ssh"):
        mock_db.query_one.side_effect = [{"id": KEY_ID}, server, auth]
        actions.revoke_key(
            sample_key["fingerprint"], ADMIN_ID, "test",
            hostname="server-test-01", unix_user="alice",
        )
        update_call = mock_db.execute.call_args_list[0]
        assert "unix_user" in update_call[0][0]
        assert "alice" in update_call[0][1]


# ---------------------------------------------------------------------------
# handle_disappeared_key — scenario 2 (out-of-system, revoked_automatically=True)
# ---------------------------------------------------------------------------

def test_actions_handle_disappeared_key_scenario2_sets_revoked_automatically():
    with patch("actions.db") as mock_db, patch("actions.alerts") as mock_alerts:
        mock_db.query_one.return_value = {"fingerprint": "SHA256:abc"}
        actions.handle_disappeared_key(KEY_ID, SERVER_ID, "server-test-01", ip="192.168.1.10")
        update_call = mock_db.execute.call_args_list[0]
        assert "revoked_automatically = true" in update_call[0][0]
        assert "NULL" in update_call[0][0]


def test_actions_handle_disappeared_key_scenario2_logs_anomaly_detected():
    with patch("actions.db") as mock_db, patch("actions.alerts") as mock_alerts:
        mock_db.query_one.return_value = {"fingerprint": "SHA256:abc"}
        actions.handle_disappeared_key(KEY_ID, SERVER_ID, "server-test-01", ip="192.168.1.10")
        audit_call = mock_db.execute.call_args_list[1]
        assert "ANOMALY_DETECTED" in audit_call[0][0]


def test_actions_handle_disappeared_key_scenario2_returns_info_dict():
    with patch("actions.db") as mock_db:
        mock_db.query_one.return_value = {"fingerprint": "SHA256:abc"}
        info = actions.handle_disappeared_key(KEY_ID, SERVER_ID, "server-test-01", ip="192.168.1.10")
        assert info["type"] == "disappeared"
        assert info["fingerprint"] == "SHA256:abc"
        assert info["hostname"] == "server-test-01"


# ---------------------------------------------------------------------------
# handle_unknown_key — scenario 3 (cle inconnue → PENDING_REVIEW)
# ---------------------------------------------------------------------------

def test_actions_handle_unknown_key_scenario3_inserts_pending_review(sample_key):
    with patch("actions.db") as mock_db, patch("actions.alerts") as mock_alerts:
        mock_db.query_one.return_value = {"id": KEY_ID}
        actions.handle_unknown_key(
            "ssh-ed25519", None,
            sample_key["public_key"], sample_key["fingerprint"],
            "test@host", SERVER_ID, "server-test-01",
        )
        insert_auth_call = mock_db.execute.call_args_list[1]
        assert "PENDING_REVIEW" in insert_auth_call[0][0]


def test_actions_handle_unknown_key_scenario3_logs_anomaly_detected(sample_key):
    with patch("actions.db") as mock_db, patch("actions.alerts") as mock_alerts:
        mock_db.query_one.return_value = {"id": KEY_ID}
        actions.handle_unknown_key(
            "ssh-ed25519", None,
            sample_key["public_key"], sample_key["fingerprint"],
            "test@host", SERVER_ID, "server-test-01",
        )
        audit_call = mock_db.execute.call_args_list[2]
        assert "ANOMALY_DETECTED" in audit_call[0][0]


def test_actions_handle_unknown_key_scenario3_returns_info_dict(sample_key):
    with patch("actions.db") as mock_db:
        mock_db.query_one.return_value = {"id": KEY_ID}
        info = actions.handle_unknown_key(
            "ssh-ed25519", None,
            sample_key["public_key"], sample_key["fingerprint"],
            "test@host", SERVER_ID, "server-test-01",
        )
        assert info["type"] == "unknown"
        assert info["fingerprint"] == sample_key["fingerprint"]
        assert info["hostname"] == "server-test-01"
        assert info["key_type"] == "ssh-ed25519"


# ---------------------------------------------------------------------------
# handle_reappeared_key — scenario 5 (cle revoquee/expiree reapparue)
# ---------------------------------------------------------------------------

def test_actions_handle_reappeared_key_scenario5_sets_pending_review():
    with patch("actions.db") as mock_db:
        mock_db.query_one.return_value = {"fingerprint": "SHA256:abc"}
        actions.handle_reappeared_key(KEY_ID, SERVER_ID, "server-test-01")
        update_call = mock_db.execute.call_args_list[0]
        assert "PENDING_REVIEW" in update_call[0][0]
        assert "REVOKED" in update_call[0][0]
        assert "EXPIRED" in update_call[0][0]


def test_actions_handle_reappeared_key_scenario5_logs_anomaly_detected():
    with patch("actions.db") as mock_db:
        mock_db.query_one.return_value = {"fingerprint": "SHA256:abc"}
        actions.handle_reappeared_key(KEY_ID, SERVER_ID, "server-test-01")
        audit_call = mock_db.execute.call_args_list[1]
        assert "ANOMALY_DETECTED" in audit_call[0][0]
        params_json = audit_call[0][1][2]
        assert "revoked_key_reappeared" in params_json


def test_actions_handle_reappeared_key_scenario5_returns_info_dict():
    with patch("actions.db") as mock_db:
        mock_db.query_one.return_value = {"fingerprint": "SHA256:testfp"}
        info = actions.handle_reappeared_key(KEY_ID, SERVER_ID, "server-test-01")
        assert info["type"] == "reappeared"
        assert info["fingerprint"] == "SHA256:testfp"
        assert info["hostname"] == "server-test-01"


# ---------------------------------------------------------------------------
# warn_expiring_key — anti-spam EXPIRY_WARNING 24h
# ---------------------------------------------------------------------------

def test_actions_warn_expiring_key_returns_info_dict_first_call():
    expires_at = _future(hours=48)
    with patch("actions.db") as mock_db:
        mock_db.query_one.side_effect = [
            None,  # no existing warning
            {"fingerprint": "SHA256:abc"},  # key lookup
            {"hostname": "server-test-01"},  # server lookup
        ]
        info = actions.warn_expiring_key(KEY_ID, SERVER_ID, expires_at)
        assert info is not None
        assert info["fingerprint"] == "SHA256:abc"
        assert info["hostname"] == "server-test-01"
        assert info["expires_at"] == expires_at


def test_actions_warn_expiring_key_antispam_returns_none():
    expires_at = _future(hours=48)
    with patch("actions.db") as mock_db:
        mock_db.query_one.return_value = {"id": str(uuid.uuid4())}
        info = actions.warn_expiring_key(KEY_ID, SERVER_ID, expires_at)
        assert info is None
        mock_db.execute.assert_not_called()


# ---------------------------------------------------------------------------
# assign_key
# ---------------------------------------------------------------------------

def test_actions_assign_key_updates_owner(sample_key):
    with patch("actions.db") as mock_db:
        mock_db.query_one.return_value = {"id": KEY_ID}
        actions.assign_key(sample_key["fingerprint"], "Alice Martin")
        mock_db.execute.assert_called_once()
        assert "Alice Martin" in mock_db.execute.call_args[0][1]


def test_actions_assign_key_raises_if_key_not_found():
    with patch("actions.db") as mock_db:
        mock_db.query_one.return_value = None
        with pytest.raises(UserError, match="Key not found"):
            actions.assign_key("SHA256:xxx", "Alice Martin")


# ---------------------------------------------------------------------------
# set_key_expiry / remove_key_expiry
# ---------------------------------------------------------------------------

def test_actions_set_key_expiry_updates_active_auths(sample_key):
    expires_at = _future()
    with patch("actions.db") as mock_db:
        mock_db.query_one.return_value = {"id": KEY_ID}
        actions.set_key_expiry(sample_key["fingerprint"], expires_at)
        assert expires_at in mock_db.execute.call_args[0][1]


def test_actions_set_key_expiry_raises_if_key_not_found(sample_key):
    with patch("actions.db") as mock_db:
        mock_db.query_one.return_value = None
        with pytest.raises(UserError):
            actions.set_key_expiry(sample_key["fingerprint"], _future())


def test_actions_remove_key_expiry_sets_null(sample_key):
    with patch("actions.db") as mock_db:
        mock_db.query_one.return_value = {"id": KEY_ID}
        actions.remove_key_expiry(sample_key["fingerprint"])
        assert "NULL" in mock_db.execute.call_args[0][0]


# ---------------------------------------------------------------------------
# grant_access
# ---------------------------------------------------------------------------

def test_actions_grant_access_returns_ids(sample_key, sample_server):
    expires_at = _future()
    with patch("actions.db") as mock_db:
        mock_db.query_one.side_effect = [
            {"id": KEY_ID},
            {"id": SERVER_ID},
        ]
        result = actions.grant_access(
            sample_key["fingerprint"], sample_server["hostname"],
            expires_at, "maintenance", ADMIN_ID,
        )
        assert result["key_id"] == KEY_ID
        assert result["server_id"] == SERVER_ID


def test_actions_grant_access_raises_if_server_not_found(sample_key):
    with patch("actions.db") as mock_db:
        mock_db.query_one.side_effect = [{"id": KEY_ID}, None]
        with pytest.raises(UserError, match="Server not found"):
            actions.grant_access(sample_key["fingerprint"], "ghost", _future(), "x", ADMIN_ID)


# ---------------------------------------------------------------------------
# approve_request / reject_request / revoke_request
# ---------------------------------------------------------------------------

def test_actions_approve_request_sets_approved_and_creates_auth():
    req = {
        "key_id": KEY_ID, "server_id": SERVER_ID,
        "expires_at_requested": _future(), "duration_hours": None,
    }
    with patch("actions.db") as mock_db:
        mock_db.query_one.return_value = req
        actions.approve_request(REQUEST_ID, ADMIN_ID)
        calls = [c[0][0] for c in mock_db.execute.call_args_list]
        assert any("APPROVED" in c for c in calls)
        assert any("REQUEST_APPROVED" in c for c in calls)


def test_actions_approve_request_raises_if_not_pending():
    with patch("actions.db") as mock_db:
        mock_db.query_one.return_value = None
        with pytest.raises(UserError, match="not PENDING"):
            actions.approve_request(REQUEST_ID, ADMIN_ID)


def test_actions_approve_request_computes_expires_at_from_duration():
    req = {
        "key_id": KEY_ID, "server_id": SERVER_ID,
        "expires_at_requested": None, "duration_hours": 8,
    }
    with patch("actions.db") as mock_db:
        mock_db.query_one.return_value = req
        actions.approve_request(REQUEST_ID, ADMIN_ID)
        update_params = mock_db.execute.call_args_list[0][0][1]
        assert update_params[1] is not None  # expires_at computed


def test_actions_reject_request_sets_rejected():
    req = {"key_id": KEY_ID, "server_id": SERVER_ID}
    with patch("actions.db") as mock_db:
        mock_db.query_one.return_value = req
        actions.reject_request(REQUEST_ID, ADMIN_ID)
        calls = [c[0][0] for c in mock_db.execute.call_args_list]
        assert any("REJECTED" in c for c in calls)


def test_actions_reject_request_raises_if_not_pending():
    with patch("actions.db") as mock_db:
        mock_db.query_one.return_value = None
        with pytest.raises(UserError):
            actions.reject_request(REQUEST_ID, ADMIN_ID)


def test_actions_revoke_request_calls_sam_revoke():
    req = {"key_id": KEY_ID, "server_id": SERVER_ID}
    with patch("actions.db") as mock_db, patch("actions.ssh") as mock_ssh:
        mock_db.query_one.side_effect = [
            req,
            {"fingerprint": "SHA256:abc"},
            {"hostname": "server-test-01", "ip_address": "192.168.1.10", "ssh_port": 22},
        ]
        actions.revoke_request(REQUEST_ID, ADMIN_ID)
        mock_ssh.revoke_on_server.assert_called_once_with(
            "server-test-01", "SHA256:abc", ip="192.168.1.10", port=22
        )


# ---------------------------------------------------------------------------
# add_server / disable_server
# ---------------------------------------------------------------------------

def test_actions_add_server_logs_server_added(sample_server):
    with patch("actions.db") as mock_db, patch("actions.ssh"):
        mock_db.query_one.side_effect = [None, {"id": SERVER_ID}]
        actions.add_server("new-host", "10.0.0.1", "root", "pass123", "lab", "rhel", 22, ADMIN_ID)
        calls = [c[0][0] for c in mock_db.execute.call_args_list]
        assert any("SERVER_ADDED" in c for c in calls)


def test_actions_add_server_provisions_before_insert(sample_server):
    """SSH provisioning must happen before INSERT."""
    call_order = []
    with patch("actions.db") as mock_db, \
         patch("actions.ssh") as mock_ssh:
        mock_db.query_one.side_effect = [None, {"id": SERVER_ID}]
        mock_ssh.provision_server.side_effect = lambda *a, **kw: call_order.append("ssh")
        def track_execute(*args, **kwargs):
            call_order.append("db")
        mock_db.execute.side_effect = track_execute
        actions.add_server("new-host", "10.0.0.1", "root", "pass", "lab", None, 22, ADMIN_ID)
        ssh_idx = call_order.index("ssh")
        db_idx = call_order.index("db")
        assert ssh_idx < db_idx, "SSH must be called before first DB write"


def test_actions_add_server_ssh_failure_no_db_write(sample_server):
    """If SSH provisioning fails, nothing is written to DB."""
    with patch("actions.db") as mock_db, \
         patch("actions.ssh") as mock_ssh:
        mock_db.query_one.return_value = None
        mock_ssh.provision_server.side_effect = RuntimeError("Auth failed")
        with pytest.raises(RuntimeError, match="Auth failed"):
            actions.add_server("new-host", "10.0.0.1", "root", "wrong", "lab", None, 22, ADMIN_ID)
        mock_db.execute.assert_not_called()


def test_actions_add_server_logs_provisioned(sample_server):
    """SERVER_PROVISIONED audit entry must be created after success."""
    with patch("actions.db") as mock_db, \
         patch("actions.ssh"):
        mock_db.query_one.side_effect = [None, {"id": SERVER_ID}]
        actions.add_server("new-host", "10.0.0.1", "root", "pass", "lab", None, 22, ADMIN_ID)
        calls = [c[0][0] for c in mock_db.execute.call_args_list]
        assert any("SERVER_PROVISIONED" in c for c in calls)


def test_actions_add_server_password_not_in_db(sample_server):
    """Password must never appear in any DB call."""
    secret = "SuperSecret123!"
    with patch("actions.db") as mock_db, \
         patch("actions.ssh"):
        mock_db.query_one.side_effect = [None, {"id": SERVER_ID}]
        actions.add_server("new-host", "10.0.0.1", "root", secret, "lab", None, 22, ADMIN_ID)
        for call_args in mock_db.execute.call_args_list:
            params = call_args[0][1] if len(call_args[0]) > 1 else ()
            for param in params:
                if isinstance(param, str) and secret in param:
                    raise AssertionError(f"Password found in DB call: {param}")


def test_actions_add_server_env_optional(sample_server):
    """Environment can be None."""
    with patch("actions.db") as mock_db, \
         patch("actions.ssh"):
        mock_db.query_one.side_effect = [None, {"id": SERVER_ID}]
        actions.add_server("new-host", "10.0.0.1", "root", "pass", None, None, 22, ADMIN_ID)
        insert_call = mock_db.execute.call_args_list[0]
        assert None in insert_call[0][1]


def test_actions_add_server_no_password_calls_provision_with_empty(sample_server):
    """add_server with empty password passes empty string to provision_server (key-auth path)."""
    with patch("actions.db") as mock_db, \
         patch("actions.ssh") as mock_ssh:
        mock_db.query_one.side_effect = [None, {"id": SERVER_ID}]
        actions.add_server("new-host", "10.0.0.1", "root", "", "lab", None, 22, ADMIN_ID)
        mock_ssh.provision_server.assert_called_once_with("10.0.0.1", "root", "", 22)


def test_actions_disable_server_sets_inactive(sample_server):
    with patch("actions.db") as mock_db:
        mock_db.query_one.return_value = {"id": SERVER_ID}
        actions.disable_server("server-test-01", ADMIN_ID)
        update_call = mock_db.execute.call_args_list[0][0][0]
        assert "is_active = false" in update_call


def test_actions_disable_server_raises_if_not_found():
    with patch("actions.db") as mock_db:
        mock_db.query_one.return_value = None
        with pytest.raises(UserError, match="not found"):
            actions.disable_server("ghost")


# ---------------------------------------------------------------------------
# provision_server
# ---------------------------------------------------------------------------

def test_actions_provision_server_calls_ssh_provision(sample_server):
    with patch("actions.db") as mock_db, patch("actions.ssh") as mock_ssh:
        mock_db.query_one.return_value = {"id": SERVER_ID, "ip_address": "192.168.1.10"}
        actions.provision_server("server-test-01", "root", "password123", 22, ADMIN_ID)
        mock_ssh.provision_server.assert_called_once_with("192.168.1.10", "root", "password123", 22)


def test_actions_provision_server_logs_provisioned(sample_server):
    with patch("actions.db") as mock_db, patch("actions.ssh"):
        mock_db.query_one.return_value = {"id": SERVER_ID, "ip_address": "192.168.1.10"}
        actions.provision_server("server-test-01", "root", "password123", 22, ADMIN_ID)
        calls = [c[0][0] for c in mock_db.execute.call_args_list]
        assert any("SERVER_PROVISIONED" in c for c in calls)


def test_actions_provision_server_password_not_logged(sample_server):
    """Password must never appear in audit_log."""
    secret_password = "SuperSecret123!"
    with patch("actions.db") as mock_db, patch("actions.ssh"):
        mock_db.query_one.return_value = {"id": SERVER_ID, "ip_address": "192.168.1.10"}
        actions.provision_server("server-test-01", "root", secret_password, 22, ADMIN_ID)

        # Check all db.execute calls
        for call_args in mock_db.execute.call_args_list:
            sql = call_args[0][0] if call_args[0] else ""
            params = call_args[0][1] if len(call_args[0]) > 1 else ()
            for param in params:
                if isinstance(param, str) and secret_password in param:
                    raise AssertionError(f"Password found in audit_log: {param}")


def test_actions_provision_server_raises_if_not_found():
    with patch("actions.db") as mock_db:
        mock_db.query_one.return_value = None
        with pytest.raises(UserError, match="not found"):
            actions.provision_server("ghost", "root", "password", 22, ADMIN_ID)


# ---------------------------------------------------------------------------
# add_admin / disable_admin
# ---------------------------------------------------------------------------

def test_actions_add_admin_logs_admin_added():
    with patch("actions.db") as mock_db:
        mock_db.query_one.side_effect = [None, {"id": ADMIN_ID}]
        actions.add_admin("newuser", "new@example.com", "Str0ng#Pass!", ADMIN_ID)
        calls = [c[0][0] for c in mock_db.execute.call_args_list]
        assert any("ADMIN_ADDED" in c for c in calls)


def test_actions_disable_admin_sets_inactive():
    with patch("actions.db") as mock_db:
        mock_db.query_one.return_value = {"id": ADMIN_ID, "role": "operator"}
        actions.disable_admin("someuser", ADMIN_ID)
        update_call = mock_db.execute.call_args_list[0][0][0]
        assert "is_active = false" in update_call


def test_actions_disable_admin_raises_if_not_found():
    with patch("actions.db") as mock_db:
        mock_db.query_one.return_value = None
        with pytest.raises(UserError, match="not found"):
            actions.disable_admin("ghost")


def test_actions_disable_admin_prevents_last_sysadmin():
    """Cannot disable the last active sysadmin."""
    with patch("actions.db") as mock_db:
        mock_db.query_one.side_effect = [
            {"id": ADMIN_ID, "role": "sysadmin"},
            {"n": 0},
        ]
        with pytest.raises(UserError, match="Cannot disable last active sysadmin"):
            actions.disable_admin("admin", ADMIN_ID)


def test_actions_disable_admin_allows_sysadmin_with_other_active():
    """Can disable a sysadmin when at least one other active sysadmin exists."""
    with patch("actions.db") as mock_db:
        mock_db.query_one.side_effect = [
            {"id": ADMIN_ID, "role": "sysadmin"},
            {"n": 1},
        ]
        actions.disable_admin("admin", ADMIN_ID)
        update_call = mock_db.execute.call_args_list[0][0][0]
        assert "is_active = false" in update_call


# ---------------------------------------------------------------------------
# enable_server
# ---------------------------------------------------------------------------

def test_actions_enable_server_sets_active():
    with patch("actions.db") as mock_db:
        mock_db.query_one.return_value = {"id": SERVER_ID}
        actions.enable_server("server-test-01", ADMIN_ID)
        update_call = mock_db.execute.call_args_list[0][0][0]
        assert "is_active = true" in update_call


def test_actions_enable_server_logs_server_added():
    with patch("actions.db") as mock_db:
        mock_db.query_one.return_value = {"id": SERVER_ID}
        actions.enable_server("server-test-01", ADMIN_ID)
        calls = [c[0][0] for c in mock_db.execute.call_args_list]
        assert any("SERVER_ADDED" in c for c in calls)


def test_actions_enable_server_raises_if_not_found():
    with patch("actions.db") as mock_db:
        mock_db.query_one.return_value = None
        with pytest.raises(UserError, match="not found"):
            actions.enable_server("ghost")


# ---------------------------------------------------------------------------
# delete_server
# ---------------------------------------------------------------------------

def test_actions_delete_server_removes_server_row():
    with patch("actions.db") as mock_db:
        mock_db.query_one.return_value = {"id": SERVER_ID}
        actions.delete_server("server-test-01", ADMIN_ID)
        delete_calls = [c[0][0] for c in mock_db.execute.call_args_list]
        assert any("DELETE FROM servers" in c for c in delete_calls)


def test_actions_delete_server_removes_authorizations_and_requests():
    with patch("actions.db") as mock_db:
        mock_db.query_one.return_value = {"id": SERVER_ID}
        actions.delete_server("server-test-01", ADMIN_ID)
        delete_calls = [c[0][0] for c in mock_db.execute.call_args_list]
        assert any("key_authorizations" in c for c in delete_calls)
        assert any("access_requests" in c for c in delete_calls)


def test_actions_delete_server_raises_if_not_found():
    with patch("actions.db") as mock_db:
        mock_db.query_one.return_value = None
        with pytest.raises(UserError, match="not found"):
            actions.delete_server("ghost")


# ---------------------------------------------------------------------------
# enable_admin
# ---------------------------------------------------------------------------

def test_actions_enable_admin_sets_active():
    with patch("actions.db") as mock_db:
        mock_db.query_one.return_value = {"id": ADMIN_ID}
        actions.enable_admin("someuser", ADMIN_ID)
        update_sql = mock_db.execute.call_args_list[0][0][0]
        assert "is_active = true" in update_sql


def test_actions_enable_admin_logs_admin_enabled():
    with patch("actions.db") as mock_db:
        mock_db.query_one.return_value = {"id": ADMIN_ID}
        actions.enable_admin("someuser", ADMIN_ID)
        audit_sql = mock_db.execute.call_args_list[1][0][0]
        assert "ADMIN_ENABLED" in audit_sql


def test_actions_enable_admin_raises_if_not_found():
    with patch("actions.db") as mock_db:
        mock_db.query_one.return_value = None
        with pytest.raises(UserError, match="not found"):
            actions.enable_admin("ghost")


# ---------------------------------------------------------------------------
# delete_admin
# ---------------------------------------------------------------------------

def test_actions_delete_admin_removes_row():
    with patch("actions.db") as mock_db:
        mock_db.query_one.return_value = {"id": ADMIN_ID}
        actions.delete_admin("someuser", ADMIN_ID)
        sqls = [c[0][0] for c in mock_db.execute.call_args_list]
        assert any("DELETE FROM administrators" in s for s in sqls)


def test_actions_delete_admin_logs_admin_deleted():
    with patch("actions.db") as mock_db:
        mock_db.query_one.return_value = {"id": ADMIN_ID}
        actions.delete_admin("someuser", ADMIN_ID)
        sqls = [c[0][0] for c in mock_db.execute.call_args_list]
        assert any("ADMIN_DELETED" in s for s in sqls)


def test_actions_delete_admin_raises_if_not_found():
    with patch("actions.db") as mock_db:
        mock_db.query_one.return_value = None
        with pytest.raises(UserError, match="Admin not found"):
            actions.delete_admin("ghost")


# ---------------------------------------------------------------------------
# update_admin
# ---------------------------------------------------------------------------

def test_actions_update_admin_success():
    """update_admin updates email and role, logs ADMIN_UPDATED."""
    admin = {"id": ADMIN_ID, "email": "old@example.com", "role": "sysadmin"}
    current_admin = {"username": "admin"}
    with patch("actions.db") as mock_db:
        mock_db.query_one.side_effect = [admin, current_admin, {"n": 1}]
        result = actions.update_admin("testuser", "new@example.com", "operator", ADMIN_ID)
        update_sql = mock_db.execute.call_args_list[0][0][0]
        update_params = mock_db.execute.call_args_list[0][0][1]
        assert "UPDATE administrators" in update_sql
        assert "new@example.com" in update_params
        assert "operator" in update_params
        assert "testuser" in update_params
        audit_sql = mock_db.execute.call_args_list[1][0][0]
        assert "ADMIN_UPDATED" in audit_sql
        assert result["username"] == "testuser"
        assert result["email"] == "new@example.com"
        assert result["role"] == "operator"


def test_actions_update_admin_not_found():
    """update_admin raises UserError if admin not found."""
    with patch("actions.db") as mock_db:
        mock_db.query_one.return_value = None
        with pytest.raises(UserError, match="Admin not found"):
            actions.update_admin("ghost", "new@example.com", "operator", ADMIN_ID)


def test_actions_update_admin_self_role_change_raises():
    """update_admin raises UserError if admin changes their own role."""
    admin = {"id": ADMIN_ID, "email": "admin@example.com", "role": "sysadmin"}
    current_admin = {"username": "admin"}
    with patch("actions.db") as mock_db:
        mock_db.query_one.side_effect = [admin, current_admin]
        with pytest.raises(UserError, match="Cannot change your own role"):
            actions.update_admin("admin", "admin@example.com", "operator", ADMIN_ID)


def test_actions_update_admin_prevents_demoting_last_sysadmin():
    """update_admin raises UserError when demoting the last active sysadmin."""
    admin = {"id": ADMIN_ID, "email": "admin@example.com", "role": "sysadmin"}
    current_admin = {"username": "other-admin"}
    with patch("actions.db") as mock_db:
        mock_db.query_one.side_effect = [admin, current_admin, {"n": 0}]
        with pytest.raises(UserError, match="Cannot demote last active sysadmin"):
            actions.update_admin("admin", "admin@example.com", "operator", ADMIN_ID)


def test_actions_update_admin_allows_demotion_with_other_sysadmin():
    """update_admin allows demotion if another active sysadmin exists."""
    admin = {"id": ADMIN_ID, "email": "admin@example.com", "role": "sysadmin"}
    current_admin = {"username": "other-admin"}
    with patch("actions.db") as mock_db:
        mock_db.query_one.side_effect = [admin, current_admin, {"n": 1}]
        result = actions.update_admin("admin", "admin@example.com", "operator", ADMIN_ID)
        assert result["role"] == "operator"


# ---------------------------------------------------------------------------
# deploy_key
# ---------------------------------------------------------------------------

def test_actions_deploy_key_success(sample_server, sample_key):
    with patch("actions.db") as mock_db, patch("actions.ssh") as mock_ssh:
        mock_db.query_one.side_effect = [
            {"id": sample_server["id"], "ip_address": sample_server["ip_address"], "ssh_port": 22},
            {"id": sample_key["id"]},
            {"id": sample_server["id"]},  # _get_current_group: server
            None,                          # _get_current_group: no current group
        ]
        mock_db.execute.return_value = None

        result = actions.deploy_key(
            public_key=sample_key["public_key"],
            unix_user="alice",
            hostname=sample_server["hostname"],
            expires_at=None,
            justification="Test deploy",
            admin_id=ADMIN_ID,
        )

        assert result["fingerprint"] == sample_key["fingerprint"]
        assert result["unix_user"] == "alice"
        assert result["hostname"] == sample_server["hostname"]
        assert result["expires_at"] is None
        mock_ssh.add_key_on_server.assert_called_once()


def test_actions_deploy_key_invalid_key_type(sample_server):
    with patch("actions.db") as mock_db:
        mock_db.query_one.return_value = {
            "id": sample_server["id"], "ip_address": sample_server["ip_address"], "ssh_port": 22
        }
        with pytest.raises(UserError, match="Unsupported key type"):
            actions.deploy_key(
                public_key="ssh-dss AAAA test",
                unix_user="alice",
                hostname=sample_server["hostname"],
                expires_at=None,
                justification="Test",
                admin_id=ADMIN_ID,
            )


def test_actions_deploy_key_server_not_found(sample_key):
    with patch("actions.db") as mock_db:
        mock_db.query_one.return_value = None
        with pytest.raises(UserError, match="Server not found"):
            actions.deploy_key(
                public_key=sample_key["public_key"],
                unix_user="alice",
                hostname="unknown-server",
                expires_at=None,
                justification="Test",
                admin_id=ADMIN_ID,
            )


def test_actions_deploy_key_invalid_format():
    with pytest.raises(UserError, match="Invalid key format"):
        actions.deploy_key(
            public_key="notakey",
            unix_user="alice",
            hostname="server",
            expires_at=None,
            justification="Test",
            admin_id=ADMIN_ID,
        )


def test_actions_deploy_key_invalid_unix_user_with_space():
    with pytest.raises(UserError, match="Invalid Unix username"):
        actions.deploy_key(
            public_key="ssh-ed25519 AAAA test",
            unix_user="zoor dupont",
            hostname="server",
            expires_at=None,
            justification="Test",
            admin_id=ADMIN_ID,
        )


def test_actions_deploy_key_invalid_unix_user_uppercase():
    with pytest.raises(UserError, match="Invalid Unix username"):
        actions.deploy_key(
            public_key="ssh-ed25519 AAAA test",
            unix_user="Alice",
            hostname="server",
            expires_at=None,
            justification="Test",
            admin_id=ADMIN_ID,
        )


def test_actions_deploy_key_valid_unix_user_passes_check(sample_server, sample_key):
    with patch("actions.db") as mock_db, patch("actions.ssh") as mock_ssh:
        mock_db.query_one.side_effect = [sample_server, {"id": KEY_ID}, {"id": sample_server["id"]}, None]
        mock_db.execute.return_value = None
        mock_ssh.ensure_scripts.return_value = None
        mock_ssh.add_key_on_server.return_value = None
        result = actions.deploy_key(
            public_key=sample_key["public_key"],
            unix_user="alice_01",
            hostname="server-prod-01",
            expires_at=None,
            justification="Test",
            admin_id=ADMIN_ID,
        )
        assert result["unix_user"] == "alice_01"


# ---------------------------------------------------------------------------
# Validation format fingerprint SHA256
# ---------------------------------------------------------------------------

def test_actions_validate_key_rejects_invalid_fingerprint_format():
    with pytest.raises(UserError, match="Invalid fingerprint format"):
        actions.validate_key("not-a-fingerprint", ADMIN_ID)


def test_actions_revoke_key_rejects_invalid_fingerprint_format():
    with pytest.raises(UserError, match="Invalid fingerprint format"):
        actions.revoke_key("INVALID:abc", ADMIN_ID, "test")


def test_actions_assign_key_rejects_invalid_fingerprint_format():
    with pytest.raises(UserError, match="Invalid fingerprint format"):
        actions.assign_key("sha256:lowercase", "alice")


def test_actions_set_expiry_rejects_invalid_fingerprint_format():
    from datetime import datetime, timezone
    with pytest.raises(UserError, match="Invalid fingerprint format"):
        actions.set_key_expiry("bad\nfingerprint", datetime.now(tz=timezone.utc))


def test_actions_remove_expiry_rejects_invalid_fingerprint_format():
    with pytest.raises(UserError, match="Invalid fingerprint format"):
        actions.remove_key_expiry("SHA256:bad/char!")


def test_actions_fingerprint_valid_format_passes_check():
    """A valid SHA256 fingerprint does not raise a formatting error."""
    import actions as act
    act._check_fingerprint("SHA256:abc123+/=ABCXYZ")


# ---------------------------------------------------------------------------
# lock_user / unlock_user
# ---------------------------------------------------------------------------

def test_actions_lock_user_success():
    with patch("actions.db") as mock_db, patch("actions.ssh") as mock_ssh:
        mock_db.query_one.return_value = {"id": SERVER_ID, "ip_address": "192.168.1.10", "ssh_port": 22}
        result = actions.lock_user("alice", "server-test-01", ADMIN_ID)
        mock_ssh.ensure_scripts.assert_called_once_with("server-test-01", SERVER_ID, "192.168.1.10", port=22)
        mock_ssh.lock_user_on_server.assert_called_once_with("server-test-01", "alice", "192.168.1.10", port=22)
        assert result["unix_user"] == "alice"
        assert result["hostname"] == "server-test-01"
        assert result["status"] == "locked"
        audit_call = mock_db.execute.call_args[0]
        assert "USER_LOCKED" in audit_call[0]


def test_actions_lock_user_invalid_username():
    with pytest.raises(UserError, match="Invalid Unix username"):
        actions.lock_user("bad user", "server-test-01", ADMIN_ID)


def test_actions_lock_user_server_not_found():
    with patch("actions.db") as mock_db:
        mock_db.query_one.return_value = None
        with pytest.raises(UserError, match="Server not found or inactive"):
            actions.lock_user("alice", "unknown-server", ADMIN_ID)


def test_actions_unlock_user_success():
    with patch("actions.db") as mock_db, patch("actions.ssh") as mock_ssh:
        mock_db.query_one.return_value = {"id": SERVER_ID, "ip_address": "192.168.1.10", "ssh_port": 22}
        result = actions.unlock_user("alice", "server-test-01", ADMIN_ID)
        mock_ssh.ensure_scripts.assert_called_once_with("server-test-01", SERVER_ID, "192.168.1.10", port=22)
        mock_ssh.unlock_user_on_server.assert_called_once_with("server-test-01", "alice", "192.168.1.10", port=22)
        assert result["unix_user"] == "alice"
        assert result["hostname"] == "server-test-01"
        assert result["status"] == "unlocked"
        audit_call = mock_db.execute.call_args[0]
        assert "USER_UNLOCKED" in audit_call[0]


def test_actions_unlock_user_invalid_username():
    with pytest.raises(UserError, match="Invalid Unix username"):
        actions.unlock_user("bad@user", "server-test-01", ADMIN_ID)


def test_actions_lock_user_ssh_user_raises():
    with patch("actions.ssh") as mock_ssh:
        mock_ssh.SSH_USER = "audit-collector"
        with pytest.raises(UserError, match="Cannot lock the collector account"):
            actions.lock_user("audit-collector", "server-test-01", ADMIN_ID)


def test_actions_unlock_user_ssh_user_raises():
    with patch("actions.ssh") as mock_ssh:
        mock_ssh.SSH_USER = "audit-collector"
        with pytest.raises(UserError, match="Cannot unlock the collector account"):
            actions.unlock_user("audit-collector", "server-test-01", ADMIN_ID)


# ---------------------------------------------------------------------------
# unix_user dans key_authorizations
# ---------------------------------------------------------------------------

def test_actions_deploy_key_includes_unix_user_in_key_authorization(sample_server, sample_key):
    """deploy_key inserts unix_user into key_authorizations."""
    with patch("actions.db") as mock_db, patch("actions.ssh"):
        mock_db.query_one.side_effect = [
            {"id": sample_server["id"], "ip_address": sample_server["ip_address"], "ssh_port": 22},
            {"id": sample_key["id"]},
            {"id": sample_server["id"]},
            None,
        ]
        actions.deploy_key(
            public_key=sample_key["public_key"],
            unix_user="charlie",
            hostname=sample_server["hostname"],
            expires_at=None,
            justification="Test",
            admin_id=ADMIN_ID,
        )
        insert_call = mock_db.execute.call_args_list[1]
        sql = insert_call[0][0]
        params = insert_call[0][1]
        assert "unix_user" in sql
        assert "charlie" in params


def test_actions_deploy_key_on_conflict_uses_three_column_pk(sample_server, sample_key):
    """ON CONFLICT must reference (key_id, server_id, unix_user)."""
    with patch("actions.db") as mock_db, patch("actions.ssh"):
        mock_db.query_one.side_effect = [
            {"id": sample_server["id"], "ip_address": sample_server["ip_address"], "ssh_port": 22},
            {"id": sample_key["id"]},
            {"id": sample_server["id"]},
            None,
        ]
        actions.deploy_key(
            public_key=sample_key["public_key"],
            unix_user="alice",
            hostname=sample_server["hostname"],
            expires_at=None,
            justification="Test",
            admin_id=ADMIN_ID,
        )
        insert_call = mock_db.execute.call_args_list[1]
        sql = insert_call[0][0]
        assert "unix_user" in sql
        assert "ON CONFLICT" in sql


def test_actions_handle_unknown_key_includes_unix_user(sample_key):
    """handle_unknown_key passe unix_user dans l'INSERT key_authorizations."""
    with patch("actions.db") as mock_db:
        mock_db.query_one.return_value = {"id": KEY_ID}
        actions.handle_unknown_key(
            "ssh-ed25519", None,
            sample_key["public_key"], sample_key["fingerprint"],
            "test@host", SERVER_ID, "server-test-01",
            unix_user="dave",
        )
        insert_auth_call = mock_db.execute.call_args_list[1]
        sql = insert_auth_call[0][0]
        params = insert_auth_call[0][1]
        assert "unix_user" in sql
        assert "dave" in params


def test_actions_handle_disappeared_key_includes_unix_user_in_where():
    """handle_disappeared_key filtre par unix_user dans le WHERE."""
    with patch("actions.db") as mock_db:
        mock_db.query_one.return_value = {"fingerprint": "SHA256:abc"}
        actions.handle_disappeared_key(KEY_ID, SERVER_ID, "server-test-01", ip="192.168.1.10", unix_user="eve")
        update_call = mock_db.execute.call_args_list[0]
        sql = update_call[0][0]
        params = update_call[0][1]
        assert "unix_user" in sql
        assert "eve" in params


def test_actions_handle_reappeared_key_includes_unix_user_in_where():
    """handle_reappeared_key filtre par unix_user dans le WHERE."""
    with patch("actions.db") as mock_db:
        mock_db.query_one.return_value = {"fingerprint": "SHA256:abc"}
        actions.handle_reappeared_key(KEY_ID, SERVER_ID, "server-test-01", unix_user="frank")
        update_call = mock_db.execute.call_args_list[0]
        sql = update_call[0][0]
        params = update_call[0][1]
        assert "unix_user" in sql
        assert "frank" in params


def test_actions_validate_key_includes_unix_user_in_update(sample_key):
    """validate_key updates each row by (key_id, server_id, unix_user)."""
    with patch("actions.db") as mock_db:
        mock_db.query_one.return_value = {"id": KEY_ID}
        mock_db.query.return_value = [
            {"key_id": KEY_ID, "server_id": SERVER_ID, "unix_user": "alice"},
            {"key_id": KEY_ID, "server_id": SERVER_ID, "unix_user": "root"},
        ]
        actions.validate_key(sample_key["fingerprint"], ADMIN_ID)
        # alternating: UPDATE, audit INSERT, UPDATE, audit INSERT
        assert mock_db.execute.call_count == 4
        update_calls = [c for c in mock_db.execute.call_args_list if "UPDATE" in c[0][0]]
        assert len(update_calls) == 2
        for call in update_calls:
            sql = call[0][0]
            assert "unix_user" in sql


def test_actions_validate_key_scoped_only_validates_target_unix_user(sample_key):
    """With unix_user+hostname, only the targeted authorization is validated."""
    with patch("actions.db") as mock_db:
        mock_db.query_one.side_effect = [
            {"id": KEY_ID},          # ssh_keys
            {"id": SERVER_ID},        # servers
        ]
        mock_db.query.return_value = [
            {"key_id": KEY_ID, "server_id": SERVER_ID, "unix_user": "alice"},
        ]
        actions.validate_key(sample_key["fingerprint"], ADMIN_ID, unix_user="alice", hostname="server-01")
        # 1 UPDATE + 1 audit INSERT
        assert mock_db.execute.call_count == 2
        update_sql = mock_db.execute.call_args_list[0][0][0]
        assert "UPDATE" in update_sql


def test_actions_validate_key_scoped_raises_if_server_not_found(sample_key):
    """With unknown hostname, ValueError is raised."""
    with patch("actions.db") as mock_db:
        mock_db.query_one.side_effect = [
            {"id": KEY_ID},  # ssh_keys found
            None,            # server not found
        ]
        with pytest.raises(UserError, match="Server not found"):
            actions.validate_key(sample_key["fingerprint"], ADMIN_ID, unix_user="alice", hostname="unknown")


# ---------------------------------------------------------------------------
# update_server
# ---------------------------------------------------------------------------

def test_actions_update_server_success():
    """update_server updates fields and logs SERVER_UPDATED."""
    server = {"id": SERVER_ID, "ip_address": "192.168.1.10", "environment": "lab", "os_family": "rhel", "ssh_port": 22, "max_sessions": 2}
    with patch("actions.db") as mock_db, patch("servers.add_to_known_hosts"):
        mock_db.query_one.side_effect = [server, None]
        actions.update_server("server-test-01", "192.168.1.20", "production", "debian", 22, ADMIN_ID, 2)
        update_call = mock_db.execute.call_args_list[0]
        assert "UPDATE servers" in update_call[0][0]
        assert "192.168.1.20" in update_call[0][1]
        assert "production" in update_call[0][1]
        assert "debian" in update_call[0][1]
        audit_call = mock_db.execute.call_args_list[1]
        assert "SERVER_UPDATED" in audit_call[0][0]


def test_actions_update_server_blank_environment_is_stored_as_null():
    server = {"id": SERVER_ID, "ip_address": "192.168.1.10", "environment": "lab", "os_family": "rhel", "ssh_port": 22, "max_sessions": 2}
    with patch("actions.db") as mock_db, patch("servers.add_to_known_hosts"):
        mock_db.query_one.side_effect = [server, None]
        actions.update_server("server-test-01", "192.168.1.10", "   ", "debian", 22, ADMIN_ID, 4)
        update_call = mock_db.execute.call_args_list[0]
        assert update_call[0][1][1] is None


def test_actions_update_server_ip_change_calls_keyscan():
    """If the IP changes, add_to_known_hosts is called."""
    server = {"id": SERVER_ID, "ip_address": "192.168.1.10", "environment": "lab", "os_family": "rhel", "ssh_port": 22, "max_sessions": 2}
    with patch("actions.db") as mock_db, patch("servers.add_to_known_hosts") as mock_keyscan:
        mock_db.query_one.side_effect = [server, None]
        actions.update_server("server-test-01", "192.168.1.99", "lab", "rhel", 22, ADMIN_ID, 2)
        mock_keyscan.assert_called_once_with("192.168.1.99", 22)


def test_actions_update_server_not_found():
    """If the server does not exist, ValueError is raised."""
    with patch("actions.db") as mock_db:
        mock_db.query_one.return_value = None
        with pytest.raises(UserError, match="Server not found"):
            actions.update_server("unknown-server", "10.0.0.1", "lab", "rhel", ADMIN_ID)


def test_actions_add_server_rejects_invalid_ip():
    for bad in ["notanip", "999.1.1.1", "192.168.1", "hello world"]:
        with pytest.raises(UserError, match="Invalid IP"):
            actions.add_server("h", bad, "root", "x", "lab", None, 22, ADMIN_ID)


def test_actions_update_server_rejects_invalid_ip():
    with pytest.raises(UserError, match="Invalid IP"):
        actions.update_server("h", "not-an-ip", "lab", None, ADMIN_ID)


def test_actions_add_server_rejects_duplicate_ip():
    with patch("actions.db") as mock_db:
        mock_db.query_one.return_value = {"hostname": "existing-server"}
        with pytest.raises(UserError, match="already used by server"):
            actions.add_server("new-host", "10.0.0.1", "root", "x", "lab", None, 22, ADMIN_ID)


def test_actions_update_server_rejects_duplicate_ip():
    server = {"id": SERVER_ID, "ip_address": "192.168.1.10", "environment": "lab", "os_family": "rhel", "ssh_port": 22, "max_sessions": 2}
    with patch("actions.db") as mock_db:
        mock_db.query_one.side_effect = [server, {"hostname": "other-server"}]
        with pytest.raises(UserError, match="already used by server"):
            actions.update_server("server-test-01", "10.0.0.2", "lab", None, 22, ADMIN_ID)


def test_actions_update_server_rejects_invalid_environment():
    server = {"id": SERVER_ID, "ip_address": "192.168.1.10", "environment": "lab", "os_family": "rhel", "ssh_port": 22, "max_sessions": 2}
    with patch("actions.db") as mock_db:
        mock_db.query_one.return_value = server
        with pytest.raises(UserError, match="Invalid environment"):
            actions.update_server("server-test-01", "192.168.1.10", "dev", None, 22, ADMIN_ID, 2)


# ---------------------------------------------------------------------------
# RBAC — email mandatory and role validation
# ---------------------------------------------------------------------------

def test_actions_add_admin_empty_email_raises():
    with patch("actions.db") as mock_db:
        with pytest.raises(UserError, match="email required"):
            actions.add_admin("user", "", "P@ssw0rd1!", None)


def test_actions_add_admin_invalid_role_raises():
    with patch("actions.db") as mock_db:
        with pytest.raises(UserError, match="Invalid role"):
            actions.add_admin("user", "x@x.com", "P@ssw0rd1!", None, role="superadmin")


def test_actions_update_admin_empty_email_raises():
    with patch("actions.db") as mock_db:
        with pytest.raises(UserError, match="email required"):
            actions.update_admin("user", "", "operator", ADMIN_ID)


def test_actions_update_admin_invalid_role_raises():
    with patch("actions.db") as mock_db:
        mock_db.query_one.return_value = {"id": ADMIN_ID, "email": "test@example.com", "role": "operator"}
        with pytest.raises(UserError, match="Invalid role"):
            actions.update_admin("user", "x@x.com", "superadmin", ADMIN_ID)


# ---------------------------------------------------------------------------
# toggle_alerts
# ---------------------------------------------------------------------------

def test_actions_toggle_alerts_enable():
    with patch("actions.db") as mock_db:
        mock_db.query_one.return_value = {"id": ADMIN_ID}
        result = actions.toggle_alerts("alice", True)
        sql = mock_db.execute.call_args[0][0]
        params = mock_db.execute.call_args[0][1]
        assert "receive_alerts" in sql
        assert True in params
        assert ADMIN_ID in params
    assert result == {"username": "alice", "receive_alerts": True}


def test_actions_toggle_alerts_disable():
    with patch("actions.db") as mock_db:
        mock_db.query_one.return_value = {"id": ADMIN_ID}
        result = actions.toggle_alerts("bob", False)
        params = mock_db.execute.call_args[0][1]
        assert False in params
    assert result == {"username": "bob", "receive_alerts": False}


def test_actions_toggle_alerts_unknown_admin_raises():
    with patch("actions.db") as mock_db:
        mock_db.query_one.return_value = None
        with pytest.raises(UserError, match="Active admin not found"):
            actions.toggle_alerts("ghost", True)


# ---------------------------------------------------------------------------
# reset_password
# ---------------------------------------------------------------------------

def test_actions_reset_password_updates_hash():
    with patch("actions.db") as mock_db:
        mock_db.query_one.return_value = {"id": ADMIN_ID}
        actions.reset_password("alice", "N3wStr0ng#Pass!")
        sql = mock_db.execute.call_args_list[0][0][0]
        assert "password_hash" in sql


def test_actions_reset_password_writes_audit_log():
    with patch("actions.db") as mock_db:
        mock_db.query_one.return_value = {"id": ADMIN_ID}
        actions.reset_password("alice", "N3wStr0ng#Pass!")
        audit_sql = mock_db.execute.call_args_list[1][0][0]
        assert "PASSWORD_RESET" in audit_sql


def test_actions_reset_password_works_for_disabled_admin():
    """reset_password does not filter by is_active — works on disabled admins."""
    with patch("actions.db") as mock_db:
        mock_db.query_one.return_value = {"id": ADMIN_ID}
        actions.reset_password("disabled_user", "N3wStr0ng#Pass!")
        sql = mock_db.query_one.call_args[0][0]
        assert "is_active" not in sql


def test_actions_reset_password_raises_if_not_found():
    with patch("actions.db") as mock_db:
        mock_db.query_one.return_value = None
        with pytest.raises(UserError, match="Admin not found"):
            actions.reset_password("ghost", "N3wStr0ng#Pass!")


def test_actions_reset_password_rejects_weak_password():
    with patch("actions.db") as mock_db:
        mock_db.query_one.return_value = {"id": ADMIN_ID}
        with pytest.raises(UserError):
            actions.reset_password("alice", "weak")


# ---------------------------------------------------------------------------
# bulk_validate_keys
# ---------------------------------------------------------------------------

def test_actions_bulk_validate_calls_validate_for_each():
    fp1 = "SHA256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    fp2 = "SHA256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    with patch("actions.validate_key") as mock_validate:
        mock_validate.return_value = {"id": KEY_ID}
        result = actions.bulk_validate_keys([fp1, fp2], ADMIN_ID)
        assert mock_validate.call_count == 2
        assert result["validated"] == 2
        assert result["skipped"] == 0


def test_actions_bulk_validate_skips_on_user_error():
    fp1 = "SHA256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    fp2 = "SHA256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    with patch("actions.validate_key") as mock_validate:
        mock_validate.side_effect = [UserError("no pending"), {"id": KEY_ID}]
        result = actions.bulk_validate_keys([fp1, fp2], ADMIN_ID)
        assert result["validated"] == 1
        assert result["skipped"] == 1


def test_actions_bulk_validate_rejects_empty_list():
    with pytest.raises(UserError, match="At least one"):
        actions.bulk_validate_keys([], ADMIN_ID)


def test_actions_bulk_validate_rejects_over_200():
    fps = [f"SHA256:{'a' * 43}"] * 201
    with pytest.raises(UserError, match="200"):
        actions.bulk_validate_keys(fps, ADMIN_ID)


# ---------------------------------------------------------------------------
# bulk_revoke_keys
# ---------------------------------------------------------------------------

def test_actions_bulk_revoke_calls_revoke_for_each():
    fp1 = "SHA256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    fp2 = "SHA256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    with patch("actions.revoke_key") as mock_revoke:
        result = actions.bulk_revoke_keys([fp1, fp2], "security audit", ADMIN_ID)
        assert mock_revoke.call_count == 2
        assert result["revoked"] == 2
        assert result["skipped"] == 0


def test_actions_bulk_revoke_skips_on_user_error():
    fp1 = "SHA256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    fp2 = "SHA256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    with patch("actions.revoke_key") as mock_revoke:
        mock_revoke.side_effect = [UserError("not found"), None]
        result = actions.bulk_revoke_keys([fp1, fp2], "audit", ADMIN_ID)
        assert result["revoked"] == 1
        assert result["skipped"] == 1


def test_actions_bulk_revoke_rejects_empty_list():
    with pytest.raises(UserError, match="At least one"):
        actions.bulk_revoke_keys([], "reason", ADMIN_ID)


def test_actions_bulk_revoke_rejects_over_200():
    fps = [f"SHA256:{'a' * 43}"] * 201
    with pytest.raises(UserError, match="200"):
        actions.bulk_revoke_keys(fps, "reason", ADMIN_ID)


def test_actions_bulk_revoke_rejects_empty_reason():
    fp = "SHA256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    with pytest.raises(UserError, match="reason"):
        actions.bulk_revoke_keys([fp], "", ADMIN_ID)


# ---------------------------------------------------------------------------
# check_session_limit
# ---------------------------------------------------------------------------

def test_check_session_limit_under_limit_returns_false():
    """No alert when session_count <= max_sessions."""
    with patch("actions.db") as mock_db, patch("actions.alerts") as mock_alerts:
        result = actions.check_session_limit(SERVER_ID, "server-test-01", 2, 2)
        assert result is False
        mock_alerts.send_alert.assert_not_called()
        mock_db.execute.assert_not_called()


def test_check_session_limit_exceeded_sends_warning():
    """Alert sent and audit logged when session_count > max_sessions."""
    with patch("actions.db") as mock_db, patch("actions.alerts") as mock_alerts:
        mock_db.query_one.return_value = None  # no prior warning in last 24h
        result = actions.check_session_limit(SERVER_ID, "server-test-01", 5, 2)
        assert result is True
        mock_alerts.send_alert.assert_called_once()
        call_args = mock_alerts.send_alert.call_args[0]
        assert call_args[0] == "WARNING"
        assert "server-test-01" in call_args[1]
        assert "server-test-01" in call_args[2]
        # audit log must include SESSION_LIMIT_EXCEEDED
        logged_sql = mock_db.execute.call_args_list[0][0][0]
        assert "SESSION_LIMIT_EXCEEDED" in logged_sql


def test_check_session_limit_anti_spam_blocks_second_alert():
    """No second alert when already warned within 24h."""
    with patch("actions.db") as mock_db, patch("actions.alerts") as mock_alerts:
        mock_db.query_one.return_value = {"id": "existing-log-id"}
        result = actions.check_session_limit(SERVER_ID, "server-test-01", 5, 2)
        assert result is False
        mock_alerts.send_alert.assert_not_called()
        mock_db.execute.assert_not_called()


def test_check_session_limit_exactly_one_over_triggers():
    """Alert fires when session count is exactly one above the limit."""
    with patch("actions.db") as mock_db, patch("actions.alerts") as mock_alerts:
        mock_db.query_one.return_value = None
        result = actions.check_session_limit(SERVER_ID, "server-test-01", 3, 2)
        assert result is True
        mock_alerts.send_alert.assert_called_once()


def test_check_session_limit_details_logged_correctly():
    """Audit log details include hostname, session_count and max_sessions."""
    import json as _json
    with patch("actions.db") as mock_db, patch("actions.alerts"):
        mock_db.query_one.return_value = None
        actions.check_session_limit(SERVER_ID, "my-server", 7, 3)
        logged_params = mock_db.execute.call_args_list[0][0][1]
        # logged_params: (server_id, json_details)
        details = _json.loads(logged_params[1])
        assert details["hostname"] == "my-server"
        assert details["session_count"] == 7
        assert details["max_sessions"] == 3


# ---------------------------------------------------------------------------
# _get_current_group
# ---------------------------------------------------------------------------

def test_actions_get_current_group_returns_group(sample_server):
    with patch("actions.db") as mock_db:
        mock_db.query_one.side_effect = [
            {"id": sample_server["id"]},
            {"sam_group": "sam-operator"},
        ]
        result = actions._get_current_group("alice", sample_server["hostname"])
        assert result == "sam-operator"


def test_actions_get_current_group_returns_none_no_server():
    with patch("actions.db") as mock_db:
        mock_db.query_one.return_value = None
        result = actions._get_current_group("alice", "unknown-server")
        assert result is None


def test_actions_get_current_group_returns_none_no_row(sample_server):
    with patch("actions.db") as mock_db:
        mock_db.query_one.side_effect = [
            {"id": sample_server["id"]},
            None,
        ]
        result = actions._get_current_group("alice", sample_server["hostname"])
        assert result is None


def test_actions_get_current_group_returns_none_when_null(sample_server):
    with patch("actions.db") as mock_db:
        mock_db.query_one.side_effect = [
            {"id": sample_server["id"]},
            {"sam_group": None},
        ]
        result = actions._get_current_group("alice", sample_server["hostname"])
        assert result is None


# ---------------------------------------------------------------------------
# deploy_key — sam_group parameter
# ---------------------------------------------------------------------------

def test_actions_deploy_key_with_sam_group_calls_grant(sample_server, sample_key):
    with patch("actions.db") as mock_db, patch("actions.ssh") as mock_ssh:
        mock_db.query_one.side_effect = [
            {"id": sample_server["id"], "ip_address": sample_server["ip_address"], "ssh_port": 22},
            {"id": sample_key["id"]},
            {"id": sample_server["id"]},  # _get_current_group: server
            None,                          # _get_current_group: no previous group
        ]
        result = actions.deploy_key(
            public_key=sample_key["public_key"],
            unix_user="alice",
            hostname=sample_server["hostname"],
            expires_at=None,
            justification="Test",
            admin_id=ADMIN_ID,
            sam_group="sam-operator",
        )
        assert result["sam_group"] == "sam-operator"
        mock_ssh.grant_group_on_server.assert_called_once_with(
            sample_server["hostname"], "alice", "sam-operator",
            sample_server["ip_address"], port=22,
        )


def test_actions_deploy_key_invalid_sam_group_raises(sample_server, sample_key):
    with patch("actions.db") as mock_db:
        mock_db.query_one.return_value = {
            "id": sample_server["id"], "ip_address": sample_server["ip_address"], "ssh_port": 22
        }
        with pytest.raises(UserError, match="Invalid SAM group"):
            actions.deploy_key(
                public_key=sample_key["public_key"],
                unix_user="alice",
                hostname=sample_server["hostname"],
                expires_at=None,
                justification="Test",
                admin_id=ADMIN_ID,
                sam_group="sam-invalid",
            )


def test_actions_deploy_key_no_sam_group_does_not_call_grant(sample_server, sample_key):
    with patch("actions.db") as mock_db, patch("actions.ssh") as mock_ssh:
        mock_db.query_one.side_effect = [
            {"id": sample_server["id"], "ip_address": sample_server["ip_address"], "ssh_port": 22},
            {"id": sample_key["id"]},
            {"id": sample_server["id"]},  # _get_current_group: server
            None,                          # _get_current_group: no current group → no revoke/grant
        ]
        actions.deploy_key(
            public_key=sample_key["public_key"],
            unix_user="alice",
            hostname=sample_server["hostname"],
            expires_at=None,
            justification="Test",
            admin_id=ADMIN_ID,
        )
        mock_ssh.grant_group_on_server.assert_not_called()


def test_actions_deploy_key_changes_group_revokes_old_and_grants_new(sample_server, sample_key):
    """Redeploying with a different group revokes the previous one then grants the new one."""
    with patch("actions.db") as mock_db, patch("actions.ssh") as mock_ssh:
        mock_db.query_one.side_effect = [
            {"id": sample_server["id"], "ip_address": sample_server["ip_address"], "ssh_port": 22},
            {"id": sample_key["id"]},
            {"id": sample_server["id"]},                 # _get_current_group: server
            {"sam_group": "sam-root"},                   # _get_current_group: previous group
        ]
        result = actions.deploy_key(
            public_key=sample_key["public_key"],
            unix_user="alice",
            hostname=sample_server["hostname"],
            expires_at=None,
            justification="Change group",
            admin_id=ADMIN_ID,
            sam_group="sam-operator",
        )
        assert result["sam_group"] == "sam-operator"
        mock_ssh.revoke_group_on_server.assert_called_once_with(
            sample_server["hostname"], "alice", "sam-root",
            sample_server["ip_address"], port=22,
        )
        mock_ssh.grant_group_on_server.assert_called_once_with(
            sample_server["hostname"], "alice", "sam-operator",
            sample_server["ip_address"], port=22,
        )


def test_actions_deploy_key_removes_group_when_none_selected(sample_server, sample_key):
    """Redeploying with no group revokes the previous group without granting a new one."""
    with patch("actions.db") as mock_db, patch("actions.ssh") as mock_ssh:
        mock_db.query_one.side_effect = [
            {"id": sample_server["id"], "ip_address": sample_server["ip_address"], "ssh_port": 22},
            {"id": sample_key["id"]},
            {"id": sample_server["id"]},
            {"sam_group": "sam-root"},                   # had sam-root previously
        ]
        result = actions.deploy_key(
            public_key=sample_key["public_key"],
            unix_user="alice",
            hostname=sample_server["hostname"],
            expires_at=None,
            justification="Remove group",
            admin_id=ADMIN_ID,
            sam_group=None,
        )
        assert result["sam_group"] is None
        mock_ssh.revoke_group_on_server.assert_called_once_with(
            sample_server["hostname"], "alice", "sam-root",
            sample_server["ip_address"], port=22,
        )
        mock_ssh.grant_group_on_server.assert_not_called()


# ---------------------------------------------------------------------------
# grant_group
# ---------------------------------------------------------------------------

def test_actions_grant_group_success(sample_server):
    with patch("actions.db") as mock_db, patch("actions.ssh") as mock_ssh:
        mock_db.query_one.side_effect = [
            {"id": sample_server["id"], "ip_address": sample_server["ip_address"], "ssh_port": 22},
            {"id": "ka-id"},
        ]
        result = actions.grant_group("alice", sample_server["hostname"], "sam-operator", ADMIN_ID)
        assert result["sam_group"] == "sam-operator"
        assert result["unix_user"] == "alice"
        mock_ssh.grant_group_on_server.assert_called_once_with(
            sample_server["hostname"], "alice", "sam-operator",
            sample_server["ip_address"], port=22,
        )


def test_actions_grant_group_invalid_group_raises():
    with pytest.raises(UserError, match="Invalid SAM group"):
        actions.grant_group("alice", "server", "sam-hacker", ADMIN_ID)


def test_actions_grant_group_server_not_found_raises():
    with patch("actions.db") as mock_db:
        mock_db.query_one.return_value = None
        with pytest.raises(actions.NotFoundError, match="Server not found"):
            actions.grant_group("alice", "unknown-server", "sam-pkg", ADMIN_ID)


def test_actions_grant_group_no_active_deployment_raises(sample_server):
    with patch("actions.db") as mock_db:
        mock_db.query_one.side_effect = [
            {"id": sample_server["id"], "ip_address": sample_server["ip_address"], "ssh_port": 22},
            None,
        ]
        with pytest.raises(UserError, match="No active key deployment"):
            actions.grant_group("alice", sample_server["hostname"], "sam-root", ADMIN_ID)


def test_actions_grant_group_logs_group_granted(sample_server):
    with patch("actions.db") as mock_db, patch("actions.ssh"):
        mock_db.query_one.side_effect = [
            {"id": sample_server["id"], "ip_address": sample_server["ip_address"], "ssh_port": 22},
            {"id": "ka-id"},
        ]
        actions.grant_group("alice", sample_server["hostname"], "sam-pkg", ADMIN_ID)
        audit_call = mock_db.execute.call_args_list[-1]
        assert "GROUP_GRANTED" in audit_call[0][0]


# ---------------------------------------------------------------------------
# revoke_group
# ---------------------------------------------------------------------------

def test_actions_revoke_group_success(sample_server):
    with patch("actions.db") as mock_db, patch("actions.ssh") as mock_ssh:
        mock_db.query_one.side_effect = [
            {"id": sample_server["id"], "ip_address": sample_server["ip_address"], "ssh_port": 22},
            {"sam_group": "sam-operator"},
        ]
        result = actions.revoke_group("alice", sample_server["hostname"], ADMIN_ID)
        assert result["sam_group"] is None
        mock_ssh.revoke_group_on_server.assert_called_once_with(
            sample_server["hostname"], "alice", "sam-operator",
            sample_server["ip_address"], port=22,
        )


def test_actions_revoke_group_server_not_found_raises():
    with patch("actions.db") as mock_db:
        mock_db.query_one.return_value = None
        with pytest.raises(actions.NotFoundError, match="Server not found"):
            actions.revoke_group("alice", "unknown-server", ADMIN_ID)


def test_actions_revoke_group_no_group_raises(sample_server):
    with patch("actions.db") as mock_db:
        mock_db.query_one.side_effect = [
            {"id": sample_server["id"], "ip_address": sample_server["ip_address"], "ssh_port": 22},
            None,
        ]
        with pytest.raises(UserError, match="no SAM group assigned"):
            actions.revoke_group("alice", sample_server["hostname"], ADMIN_ID)


def test_actions_revoke_group_logs_group_revoked(sample_server):
    with patch("actions.db") as mock_db, patch("actions.ssh"):
        mock_db.query_one.side_effect = [
            {"id": sample_server["id"], "ip_address": sample_server["ip_address"], "ssh_port": 22},
            {"sam_group": "sam-root"},
        ]
        actions.revoke_group("alice", sample_server["hostname"], ADMIN_ID)
        audit_call = mock_db.execute.call_args_list[-1]
        assert "GROUP_REVOKED" in audit_call[0][0]


# ---------------------------------------------------------------------------
# change_group
# ---------------------------------------------------------------------------

def test_actions_change_group_success(sample_server):
    with patch("actions.db") as mock_db, patch("actions.ssh") as mock_ssh:
        mock_db.query_one.side_effect = [
            {"id": sample_server["id"], "ip_address": sample_server["ip_address"], "ssh_port": 22},
            {"sam_group": "sam-operator"},
        ]
        result = actions.change_group("alice", sample_server["hostname"], "sam-pkg", ADMIN_ID)
        assert result["sam_group"] == "sam-pkg"
        mock_ssh.revoke_group_on_server.assert_called_once()
        mock_ssh.grant_group_on_server.assert_called_once()


def test_actions_change_group_noop_when_same(sample_server):
    with patch("actions.db") as mock_db, patch("actions.ssh") as mock_ssh:
        mock_db.query_one.side_effect = [
            {"id": sample_server["id"], "ip_address": sample_server["ip_address"], "ssh_port": 22},
            {"sam_group": "sam-pkg"},
        ]
        result = actions.change_group("alice", sample_server["hostname"], "sam-pkg", ADMIN_ID)
        assert result["sam_group"] == "sam-pkg"
        mock_ssh.revoke_group_on_server.assert_not_called()
        mock_ssh.grant_group_on_server.assert_not_called()


def test_actions_change_group_from_none_does_not_revoke(sample_server):
    with patch("actions.db") as mock_db, patch("actions.ssh") as mock_ssh:
        mock_db.query_one.side_effect = [
            {"id": sample_server["id"], "ip_address": sample_server["ip_address"], "ssh_port": 22},
            {"sam_group": None},
        ]
        actions.change_group("alice", sample_server["hostname"], "sam-root", ADMIN_ID)
        mock_ssh.revoke_group_on_server.assert_not_called()
        mock_ssh.grant_group_on_server.assert_called_once()


def test_actions_change_group_invalid_group_raises():
    with pytest.raises(UserError, match="Invalid SAM group"):
        actions.change_group("alice", "server", "sam-xyz", ADMIN_ID)


def test_actions_change_group_server_not_found_raises():
    with patch("actions.db") as mock_db:
        mock_db.query_one.return_value = None
        with pytest.raises(actions.NotFoundError, match="Server not found"):
            actions.change_group("alice", "unknown-server", "sam-operator", ADMIN_ID)


def test_actions_change_group_no_deployment_raises(sample_server):
    with patch("actions.db") as mock_db:
        mock_db.query_one.side_effect = [
            {"id": sample_server["id"], "ip_address": sample_server["ip_address"], "ssh_port": 22},
            None,
        ]
        with pytest.raises(UserError, match="No active key deployment"):
            actions.change_group("alice", sample_server["hostname"], "sam-operator", ADMIN_ID)


def test_actions_change_group_logs_group_changed(sample_server):
    with patch("actions.db") as mock_db, patch("actions.ssh"):
        mock_db.query_one.side_effect = [
            {"id": sample_server["id"], "ip_address": sample_server["ip_address"], "ssh_port": 22},
            {"sam_group": "sam-operator"},
        ]
        actions.change_group("alice", sample_server["hostname"], "sam-pkg", ADMIN_ID)
        audit_call = mock_db.execute.call_args_list[-1]
        assert "GROUP_CHANGED" in audit_call[0][0]
