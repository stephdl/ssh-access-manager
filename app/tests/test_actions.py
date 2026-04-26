import os
import sys
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch, call

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import actions


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
        mock_db.query.return_value = [{"key_id": KEY_ID, "server_id": SERVER_ID}]
        actions.validate_key(sample_key["fingerprint"], ADMIN_ID)
        update_call = mock_db.execute.call_args_list[0]
        assert "ACTIVE" in update_call[0][0]
        audit_call = mock_db.execute.call_args_list[1]
        assert "KEY_ADDED" in audit_call[0][0]


def test_actions_validate_key_raises_if_key_not_found(sample_key):
    with patch("actions.db") as mock_db:
        mock_db.query_one.return_value = None
        with pytest.raises(ValueError, match="not found"):
            actions.validate_key(sample_key["fingerprint"], ADMIN_ID)


def test_actions_validate_key_raises_if_no_pending(sample_key):
    with patch("actions.db") as mock_db:
        mock_db.query_one.return_value = {"id": KEY_ID}
        mock_db.query.return_value = []
        with pytest.raises(ValueError, match="PENDING_REVIEW"):
            actions.validate_key(sample_key["fingerprint"], ADMIN_ID)


# ---------------------------------------------------------------------------
# revoke_key — scenario 1 (via systeme, revoked_by=admin_id)
# ---------------------------------------------------------------------------

def test_actions_revoke_key_scenario1_calls_sam_revoke(sample_key):
    auth = {"server_id": SERVER_ID, "hostname": "server-test-01", "ip_address": "192.168.1.10"}
    with patch("actions.db") as mock_db, patch("actions.ssh") as mock_ssh:
        mock_db.query_one.return_value = {"id": KEY_ID}
        mock_db.query.return_value = [auth]
        actions.revoke_key(sample_key["fingerprint"], ADMIN_ID, "test reason")
        mock_ssh.revoke_on_server.assert_called_once_with(
            "server-test-01", sample_key["fingerprint"], ip="192.168.1.10"
        )


def test_actions_revoke_key_scenario1_sets_revoked_by_admin(sample_key):
    auth = {"server_id": SERVER_ID, "hostname": "server-test-01", "ip_address": "192.168.1.10"}
    with patch("actions.db") as mock_db, patch("actions.ssh") as mock_ssh:
        mock_db.query_one.return_value = {"id": KEY_ID}
        mock_db.query.return_value = [auth]
        actions.revoke_key(sample_key["fingerprint"], ADMIN_ID, "test reason")
        update_call = mock_db.execute.call_args_list[0]
        assert "REVOKED" in update_call[0][0]
        assert ADMIN_ID in update_call[0][1]


def test_actions_revoke_key_scenario1_logs_key_revoked(sample_key):
    auth = {"server_id": SERVER_ID, "hostname": "server-test-01", "ip_address": "192.168.1.10"}
    with patch("actions.db") as mock_db, patch("actions.ssh") as mock_ssh:
        mock_db.query_one.return_value = {"id": KEY_ID}
        mock_db.query.return_value = [auth]
        actions.revoke_key(sample_key["fingerprint"], ADMIN_ID, "test reason")
        audit_call = mock_db.execute.call_args_list[1]
        assert "KEY_REVOKED" in audit_call[0][0]


def test_actions_revoke_key_raises_if_key_not_found(sample_key):
    with patch("actions.db") as mock_db:
        mock_db.query_one.return_value = None
        with pytest.raises(ValueError, match="not found"):
            actions.revoke_key(sample_key["fingerprint"], ADMIN_ID, "reason")


# ---------------------------------------------------------------------------
# handle_disappeared_key — scenario 2 (hors systeme, revoked_automatically=True)
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
        with pytest.raises(ValueError, match="Key not found"):
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
        with pytest.raises(ValueError):
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
        with pytest.raises(ValueError, match="Server not found"):
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
        with pytest.raises(ValueError, match="not PENDING"):
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
        with pytest.raises(ValueError):
            actions.reject_request(REQUEST_ID, ADMIN_ID)


def test_actions_revoke_request_calls_sam_revoke():
    req = {"key_id": KEY_ID, "server_id": SERVER_ID}
    with patch("actions.db") as mock_db, patch("actions.ssh") as mock_ssh:
        mock_db.query_one.side_effect = [
            req,
            {"fingerprint": "SHA256:abc"},
            {"hostname": "server-test-01", "ip_address": "192.168.1.10"},
        ]
        actions.revoke_request(REQUEST_ID, ADMIN_ID)
        mock_ssh.revoke_on_server.assert_called_once_with(
            "server-test-01", "SHA256:abc", ip="192.168.1.10"
        )


# ---------------------------------------------------------------------------
# add_server / disable_server
# ---------------------------------------------------------------------------

def test_actions_add_server_logs_server_added(sample_server):
    with patch("actions.db") as mock_db, patch("servers.add_to_known_hosts"):
        mock_db.query_one.return_value = {"id": SERVER_ID}
        actions.add_server("new-host", "10.0.0.1", "lab", "rhel", ADMIN_ID)
        calls = [c[0][0] for c in mock_db.execute.call_args_list]
        assert any("SERVER_ADDED" in c for c in calls)


def test_actions_disable_server_sets_inactive(sample_server):
    with patch("actions.db") as mock_db:
        mock_db.query_one.return_value = {"id": SERVER_ID}
        actions.disable_server("server-test-01", ADMIN_ID)
        update_call = mock_db.execute.call_args_list[0][0][0]
        assert "is_active = false" in update_call


def test_actions_disable_server_raises_if_not_found():
    with patch("actions.db") as mock_db:
        mock_db.query_one.return_value = None
        with pytest.raises(ValueError, match="not found"):
            actions.disable_server("ghost")


# ---------------------------------------------------------------------------
# add_admin / disable_admin
# ---------------------------------------------------------------------------

def test_actions_add_admin_logs_admin_added():
    with patch("actions.db") as mock_db:
        mock_db.query_one.return_value = {"id": ADMIN_ID}
        actions.add_admin("newuser", "new@example.com", "Str0ng#Pass!", ADMIN_ID)
        calls = [c[0][0] for c in mock_db.execute.call_args_list]
        assert any("ADMIN_ADDED" in c for c in calls)


def test_actions_disable_admin_sets_inactive():
    with patch("actions.db") as mock_db:
        mock_db.query_one.return_value = {"id": ADMIN_ID}
        actions.disable_admin("someuser", ADMIN_ID)
        update_call = mock_db.execute.call_args_list[0][0][0]
        assert "is_active = false" in update_call


def test_actions_disable_admin_raises_if_not_found():
    with patch("actions.db") as mock_db:
        mock_db.query_one.return_value = None
        with pytest.raises(ValueError, match="not found"):
            actions.disable_admin("ghost")


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
        with pytest.raises(ValueError, match="not found"):
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
        with pytest.raises(ValueError, match="not found"):
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
        with pytest.raises(ValueError, match="not found"):
            actions.enable_admin("ghost")


# ---------------------------------------------------------------------------
# delete_admin
# ---------------------------------------------------------------------------

def test_actions_delete_admin_removes_row():
    with patch("actions.db") as mock_db:
        mock_db.query_one.side_effect = [{"id": ADMIN_ID}, None]
        actions.delete_admin("someuser", ADMIN_ID)
        sqls = [c[0][0] for c in mock_db.execute.call_args_list]
        assert any("DELETE FROM administrators" in s for s in sqls)


def test_actions_delete_admin_logs_admin_deleted():
    with patch("actions.db") as mock_db:
        mock_db.query_one.side_effect = [{"id": ADMIN_ID}, None]
        actions.delete_admin("someuser", ADMIN_ID)
        sqls = [c[0][0] for c in mock_db.execute.call_args_list]
        assert any("ADMIN_DELETED" in s for s in sqls)


def test_actions_delete_admin_raises_if_not_found():
    with patch("actions.db") as mock_db:
        mock_db.query_one.return_value = None
        with pytest.raises(ValueError, match="Admin not found"):
            actions.delete_admin("ghost")


def test_actions_delete_admin_raises_if_has_references():
    with patch("actions.db") as mock_db:
        mock_db.query_one.side_effect = [{"id": ADMIN_ID}, {"1": 1}]
        with pytest.raises(ValueError, match="existing audit records"):
            actions.delete_admin("someuser")


# ---------------------------------------------------------------------------
# deploy_key
# ---------------------------------------------------------------------------

def test_actions_deploy_key_success(sample_server, sample_key):
    with patch("actions.db") as mock_db, patch("actions.ssh") as mock_ssh:
        mock_db.query_one.side_effect = [
            {"id": sample_server["id"], "ip_address": sample_server["ip_address"]},
            {"id": sample_key["id"]},
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
            "id": sample_server["id"], "ip_address": sample_server["ip_address"]
        }
        with pytest.raises(ValueError, match="Type de clé non supporté"):
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
        with pytest.raises(ValueError, match="Serveur introuvable"):
            actions.deploy_key(
                public_key=sample_key["public_key"],
                unix_user="alice",
                hostname="unknown-server",
                expires_at=None,
                justification="Test",
                admin_id=ADMIN_ID,
            )


def test_actions_deploy_key_invalid_format():
    with pytest.raises(ValueError, match="Format de clé invalide"):
        actions.deploy_key(
            public_key="notakey",
            unix_user="alice",
            hostname="server",
            expires_at=None,
            justification="Test",
            admin_id=ADMIN_ID,
        )
