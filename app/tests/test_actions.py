import os
import sys
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch, call, ANY

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
        mock_db.query_one.side_effect = [{"id": KEY_ID}, None]  # key found, no root auth
        mock_db.query.return_value = [auth]
        actions.revoke_key(sample_key["fingerprint"], ADMIN_ID, "test reason")
        mock_ssh.revoke_on_server.assert_called_once_with(
            "server-test-01", sample_key["fingerprint"], ip="192.168.1.10", port=22
        , key_path=ANY)


def test_actions_revoke_key_scenario1_sets_revoked_by_admin(sample_key):
    auth = {"server_id": SERVER_ID, "hostname": "server-test-01", "ip_address": "192.168.1.10", "ssh_port": 22}
    with patch("actions.db") as mock_db, patch("actions.ssh") as mock_ssh:
        mock_db.query_one.side_effect = [{"id": KEY_ID}, None]
        mock_db.query.return_value = [auth]
        actions.revoke_key(sample_key["fingerprint"], ADMIN_ID, "test reason")
        update_call = mock_db.execute.call_args_list[0]
        assert "REVOKED" in update_call[0][0]
        assert ADMIN_ID in update_call[0][1]


def test_actions_revoke_key_scenario1_logs_key_revoked(sample_key):
    auth = {"server_id": SERVER_ID, "hostname": "server-test-01", "ip_address": "192.168.1.10", "ssh_port": 22}
    with patch("actions.db") as mock_db, patch("actions.ssh") as mock_ssh:
        mock_db.query_one.side_effect = [{"id": KEY_ID}, None]
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
         key_path=ANY)


def test_actions_revoke_key_targeted_refreshes_scripts_before_sam_revoke(sample_key):
    """ensure_scripts must be called BEFORE revoke_on_server.

    An older sam-revoke deployed on the host (before the [unix_user]
    second-arg support landed) silently ignores the second argument
    and runs the GLOBAL branch — stripping the key from every user's
    authorized_keys (including root). ensure_scripts upgrades the
    binary first so the targeted revoke stays scoped to the requested
    user.
    """
    server = {"id": SERVER_ID, "ip_address": "192.168.1.10", "ssh_port": 22}
    auth = {"status": "ACTIVE"}
    call_order = []
    with patch("actions.db") as mock_db, patch("actions.ssh") as mock_ssh:
        mock_db.query_one.side_effect = [{"id": KEY_ID}, server, auth]
        mock_ssh.ensure_scripts.side_effect = lambda *a, **kw: call_order.append("ensure_scripts")
        mock_ssh.revoke_on_server.side_effect = lambda *a, **kw: call_order.append("revoke_on_server")
        actions.revoke_key(
            sample_key["fingerprint"], ADMIN_ID, "test",
            hostname="server-test-01", unix_user="alice",
        )
        assert call_order == ["ensure_scripts", "revoke_on_server"], (
            f"expected ensure_scripts then revoke_on_server, got {call_order}"
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
# try_recognize_collector_key — short-circuit known SAM-generated keys
# ---------------------------------------------------------------------------

def test_actions_try_recognize_collector_key_returns_false_for_non_collector_user():
    """A line under any unix_user other than audit-collector must NOT
    be auto-recognised — it has to go through the normal anomaly flow.
    """
    parsed = {"unix_user": "alice", "fingerprint": "SHA256:abc"}
    with patch("actions.db"), patch("actions.ssh") as mock_ssh:
        mock_ssh.SSH_USER = "audit-collector"
        assert actions.try_recognize_collector_key(parsed, SERVER_ID) is False


def test_actions_try_recognize_collector_key_returns_false_when_local_pubkey_missing():
    """If the per-server <uuid>.key.pub file doesn't exist, we can't
    verify the key is ours — fall back to the anomaly path.
    """
    parsed = {"unix_user": "audit-collector", "fingerprint": "SHA256:abc"}
    with patch("actions.db"), patch("actions.ssh") as mock_ssh, \
         patch("os.path.isfile", return_value=False):
        mock_ssh.SSH_USER = "audit-collector"
        mock_ssh.PER_SERVER_KEYS_DIR = "/data/keys/per-server"
        assert actions.try_recognize_collector_key(parsed, SERVER_ID) is False


def test_actions_try_recognize_collector_key_returns_false_on_fingerprint_mismatch(tmp_path, monkeypatch):
    """A foreign key under audit-collector (fingerprint doesn't match
    the local per-server pubkey) is still an anomaly — return False so
    the caller treats it as unknown.
    """
    parsed = {
        "unix_user": "audit-collector",
        "fingerprint": "SHA256:WRONG",
        "key_type": "ssh-ed25519",
        "public_key": "ssh-ed25519 AAAA",
        "comment": "",
        "key_size_bits": None,
    }
    pubkey_path = tmp_path / f"{SERVER_ID}.key.pub"
    pubkey_path.write_text("ssh-ed25519 AAAA legit-collector\n")
    with patch("actions.db") as mock_db, patch("actions.ssh") as mock_ssh:
        mock_ssh.SSH_USER = "audit-collector"
        mock_ssh.PER_SERVER_KEYS_DIR = str(tmp_path)
        mock_ssh._compute_pubkey_fingerprint.return_value = "SHA256:RIGHT"
        assert actions.try_recognize_collector_key(parsed, SERVER_ID) is False
        mock_db.execute.assert_not_called()


def test_actions_try_recognize_collector_key_inserts_active_on_match(tmp_path):
    """Matching fingerprint under audit-collector → insert as ACTIVE,
    no PENDING_REVIEW, no anomaly emission.
    """
    parsed = {
        "unix_user": "audit-collector",
        "fingerprint": "SHA256:MATCH",
        "key_type": "ssh-ed25519",
        "public_key": "ssh-ed25519 AAAA",
        "comment": "",
        "key_size_bits": None,
    }
    pubkey_path = tmp_path / f"{SERVER_ID}.key.pub"
    pubkey_path.write_text("ssh-ed25519 AAAA legit-collector\n")
    with patch("actions.db") as mock_db, patch("actions.ssh") as mock_ssh:
        mock_ssh.SSH_USER = "audit-collector"
        mock_ssh.PER_SERVER_KEYS_DIR = str(tmp_path)
        mock_ssh._compute_pubkey_fingerprint.return_value = "SHA256:MATCH"
        mock_db.query_one.return_value = {"id": KEY_ID}
        assert actions.try_recognize_collector_key(parsed, SERVER_ID) is True
        statements = " ".join(c.args[0] for c in mock_db.execute.call_args_list)
        assert "INSERT INTO ssh_keys" in statements
        assert "'ACTIVE'" in statements
        # MUST NOT log an ANOMALY_DETECTED row.
        assert "ANOMALY_DETECTED" not in statements


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

def test_actions_set_key_expiry_root_raises():
    with pytest.raises(UserError, match="Cannot set an expiry on root"):
        actions.set_key_expiry("SHA256:abc", datetime.now(), unix_user="root", hostname="server")


def test_actions_set_key_expiry_updates_active_auths(sample_key):
    """set_key_expiry without unix_user/hostname updates all ACTIVE auths."""
    expires_at = _future()
    with patch("actions.db") as mock_db:
        mock_db.query_one.return_value = {"id": KEY_ID}
        actions.set_key_expiry(sample_key["fingerprint"], expires_at)
        sql = mock_db.execute.call_args[0][0]
        params = mock_db.execute.call_args[0][1]
        assert "UPDATE key_authorizations" in sql
        assert "status = 'ACTIVE'" in sql
        assert "unix_user != 'root'" in sql
        assert expires_at in params


def test_actions_set_key_expiry_scoped_to_unix_user(sample_key, sample_server):
    """set_key_expiry with unix_user and hostname updates only that specific auth."""
    expires_at = _future()
    with patch("actions.db") as mock_db:
        mock_db.query_one.side_effect = [
            {"id": KEY_ID},
            {"id": SERVER_ID},
        ]
        actions.set_key_expiry(
            sample_key["fingerprint"], expires_at, unix_user="alice", hostname=sample_server["hostname"]
        )
        sql = mock_db.execute.call_args[0][0]
        params = mock_db.execute.call_args[0][1]
        assert "UPDATE key_authorizations" in sql
        assert "WHERE key_id = %s AND unix_user = %s AND server_id = %s AND status = 'ACTIVE'" in sql
        assert params == (expires_at, KEY_ID, "alice", SERVER_ID)


def test_actions_set_key_expiry_raises_if_key_not_found(sample_key):
    with patch("actions.db") as mock_db:
        mock_db.query_one.return_value = None
        with pytest.raises(UserError):
            actions.set_key_expiry(sample_key["fingerprint"], _future())


def test_actions_set_key_expiry_raises_if_server_not_found(sample_key):
    """set_key_expiry raises NotFoundError if hostname doesn't exist."""
    with patch("actions.db") as mock_db:
        mock_db.query_one.side_effect = [
            {"id": KEY_ID},
            None,
        ]
        with pytest.raises(UserError, match="Server not found"):
            actions.set_key_expiry(sample_key["fingerprint"], _future(), unix_user="alice", hostname="ghost")


def test_actions_remove_key_expiry_sets_null(sample_key):
    """remove_key_expiry without unix_user/hostname updates all ACTIVE auths."""
    with patch("actions.db") as mock_db:
        mock_db.query_one.return_value = {"id": KEY_ID}
        actions.remove_key_expiry(sample_key["fingerprint"])
        sql = mock_db.execute.call_args[0][0]
        assert "NULL" in sql
        assert "status = 'ACTIVE'" in sql
        assert "unix_user != 'root'" in sql


def test_actions_remove_key_expiry_scoped_to_unix_user(sample_key, sample_server):
    """remove_key_expiry with unix_user and hostname updates only that specific auth."""
    with patch("actions.db") as mock_db:
        mock_db.query_one.side_effect = [
            {"id": KEY_ID},
            {"id": SERVER_ID},
        ]
        actions.remove_key_expiry(
            sample_key["fingerprint"], unix_user="bob", hostname=sample_server["hostname"]
        )
        sql = mock_db.execute.call_args[0][0]
        params = mock_db.execute.call_args[0][1]
        assert "UPDATE key_authorizations" in sql
        assert "expires_at = NULL" in sql
        assert "WHERE key_id = %s AND unix_user = %s AND server_id = %s AND status = 'ACTIVE'" in sql
        assert params == (KEY_ID, "bob", SERVER_ID)


def test_actions_remove_key_expiry_raises_if_server_not_found(sample_key):
    """remove_key_expiry raises NotFoundError if hostname doesn't exist."""
    with patch("actions.db") as mock_db:
        mock_db.query_one.side_effect = [
            {"id": KEY_ID},
            None,
        ]
        with pytest.raises(UserError, match="Server not found"):
            actions.remove_key_expiry(sample_key["fingerprint"], unix_user="alice", hostname="ghost")


def test_actions_set_key_expiry_global_excludes_root(sample_key):
    """set_key_expiry global UPDATE must exclude unix_user = 'root'."""
    from datetime import datetime, timezone
    expires = datetime.now(tz=timezone.utc)
    with patch("actions.db") as mock_db:
        mock_db.query_one.return_value = {"id": KEY_ID}
        actions.set_key_expiry(sample_key["fingerprint"], expires)
        sql = mock_db.execute.call_args[0][0]
        assert "unix_user != 'root'" in sql


def test_actions_set_key_expiry_root_targeted_raises(sample_key):
    """set_key_expiry with unix_user=root must raise UserError."""
    from datetime import datetime, timezone
    with pytest.raises(UserError, match="root"):
        actions.set_key_expiry(sample_key["fingerprint"], datetime.now(tz=timezone.utc), unix_user="root")


def test_actions_remove_key_expiry_root_targeted_raises(sample_key):
    """remove_key_expiry with unix_user=root must raise UserError."""
    with pytest.raises(UserError, match="root"):
        actions.remove_key_expiry(sample_key["fingerprint"], unix_user="root")


def test_actions_remove_key_expiry_global_excludes_root(sample_key):
    """remove_key_expiry global UPDATE must exclude unix_user = 'root'."""
    with patch("actions.db") as mock_db:
        mock_db.query_one.return_value = {"id": KEY_ID}
        actions.remove_key_expiry(sample_key["fingerprint"])
        sql = mock_db.execute.call_args[0][0]
        assert "unix_user != 'root'" in sql


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
            {"id": SERVER_ID, "hostname": "server-test-01", "ip_address": "192.168.1.10", "ssh_port": 22},
        ]
        actions.revoke_request(REQUEST_ID, ADMIN_ID)
        mock_ssh.revoke_on_server.assert_called_once_with(
            "server-test-01", "SHA256:abc", ip="192.168.1.10", port=22
        , key_path=ANY)


# ---------------------------------------------------------------------------
# add_server / disable_server
# ---------------------------------------------------------------------------

def test_actions_add_server_logs_server_added(sample_server):
    with patch("actions.db") as mock_db, patch("actions.ssh") as mock_ssh:
        mock_ssh._generate_keypair.return_value = ("/tmp/fake.key", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyForTesting")
        mock_ssh._compute_pubkey_fingerprint.return_value = "SHA256:abc"
        mock_db.query_one.side_effect = [None, {"id": SERVER_ID}]
        actions.add_server("new-host", "10.0.0.1", "root", "pass123", "lab", "rhel", 22, ADMIN_ID)
        calls = [c[0][0] for c in mock_db.execute.call_args_list]
        assert any("SERVER_ADDED" in c for c in calls)


def test_actions_add_server_provisions_before_insert(sample_server):
    """SSH provisioning must happen before INSERT."""
    call_order = []
    with patch("actions.db") as mock_db, \
         patch("actions.ssh") as mock_ssh:
        mock_ssh._generate_keypair.return_value = ("/tmp/fake.key", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKey")
        mock_ssh._compute_pubkey_fingerprint.return_value = "SHA256:abc"
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
        mock_ssh._generate_keypair.return_value = ("/tmp/fake.key", "ssh-ed25519 AAAA")
        mock_db.query_one.return_value = None
        mock_ssh.provision_server.side_effect = RuntimeError("Auth failed")
        with pytest.raises(RuntimeError, match="Auth failed"):
            actions.add_server("new-host", "10.0.0.1", "root", "wrong", "lab", None, 22, ADMIN_ID)
        mock_db.execute.assert_not_called()


def test_actions_add_server_logs_provisioned(sample_server):
    """SERVER_PROVISIONED audit entry must be created after success."""
    with patch("actions.db") as mock_db, \
         patch("actions.ssh") as mock_ssh:
        mock_ssh._generate_keypair.return_value = ("/tmp/fake.key", "ssh-ed25519 AAAA")
        mock_ssh._compute_pubkey_fingerprint.return_value = "SHA256:abc"
        mock_db.query_one.side_effect = [None, {"id": SERVER_ID}]
        actions.add_server("new-host", "10.0.0.1", "root", "pass", "lab", None, 22, ADMIN_ID)
        calls = [c[0][0] for c in mock_db.execute.call_args_list]
        assert any("SERVER_PROVISIONED" in c for c in calls)


def test_actions_add_server_password_not_in_db(sample_server):
    """Password must never appear in any DB call."""
    secret = "SuperSecret123!"
    with patch("actions.db") as mock_db, \
         patch("actions.ssh") as mock_ssh:
        mock_ssh._generate_keypair.return_value = ("/tmp/fake.key", "ssh-ed25519 AAAA")
        mock_ssh._compute_pubkey_fingerprint.return_value = "SHA256:abc"
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
         patch("actions.ssh") as mock_ssh:
        mock_ssh._generate_keypair.return_value = ("/tmp/fake.key", "ssh-ed25519 AAAA")
        mock_ssh._compute_pubkey_fingerprint.return_value = "SHA256:abc"
        mock_db.query_one.side_effect = [None, {"id": SERVER_ID}]
        actions.add_server("new-host", "10.0.0.1", "root", "pass", None, None, 22, ADMIN_ID)
        insert_call = mock_db.execute.call_args_list[0]
        assert None in insert_call[0][1]


def test_actions_add_server_no_password_calls_provision_with_pubkey(sample_server):
    """add_server with empty password passes per-server pubkey to provision_server (key-auth path)."""
    with patch("actions.db") as mock_db, \
         patch("actions.ssh") as mock_ssh:
        mock_ssh._generate_keypair.return_value = ("/tmp/fake.key", "ssh-ed25519 AAAA")
        mock_ssh._compute_pubkey_fingerprint.return_value = "SHA256:abc"
        mock_db.query_one.side_effect = [None, {"id": SERVER_ID}]
        actions.add_server("new-host", "10.0.0.1", "root", "", "lab", None, 22, ADMIN_ID)
        mock_ssh.provision_server.assert_called_once_with("10.0.0.1", "root", "", 22, pubkey="ssh-ed25519 AAAA")


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
    from unittest.mock import mock_open
    with patch("actions.db") as mock_db, patch("actions.ssh") as mock_ssh, \
         patch("os.path.isfile", return_value=True), \
         patch("builtins.open", mock_open(read_data="ssh-ed25519 AAAA")):
        mock_db.query_one.return_value = {"id": SERVER_ID, "ip_address": "192.168.1.10"}
        actions.provision_server("server-test-01", "root", "password123", 22, ADMIN_ID)
        mock_ssh.provision_server.assert_called_once_with("192.168.1.10", "root", "password123", 22, pubkey="ssh-ed25519 AAAA")


def test_actions_provision_server_logs_provisioned(sample_server):
    from unittest.mock import mock_open
    with patch("actions.db") as mock_db, patch("actions.ssh"), \
         patch("os.path.isfile", return_value=True), \
         patch("builtins.open", mock_open(read_data="ssh-ed25519 AAAA")):
        mock_db.query_one.return_value = {"id": SERVER_ID, "ip_address": "192.168.1.10"}
        actions.provision_server("server-test-01", "root", "password123", 22, ADMIN_ID)
        calls = [c[0][0] for c in mock_db.execute.call_args_list]
        assert any("SERVER_PROVISIONED" in c for c in calls)


def test_actions_provision_server_password_not_logged(sample_server):
    """Password must never appear in audit_log."""
    from unittest.mock import mock_open
    secret_password = "SuperSecret123!"
    with patch("actions.db") as mock_db, patch("actions.ssh"), \
         patch("os.path.isfile", return_value=True), \
         patch("builtins.open", mock_open(read_data="ssh-ed25519 AAAA")):
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


def test_actions_revoke_key_targeted_root_raises():
    """Targeted revoke with unix_user=root must be rejected."""
    fp = "SHA256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    with patch("actions.db") as mock_db:
        mock_db.query_one.return_value = {"id": "key-uuid"}
        with pytest.raises(UserError, match="root"):
            actions.revoke_key(fp, ADMIN_ID, "test", hostname="server-01", unix_user="root")


def test_actions_revoke_key_global_blocks_when_root_has_key():
    """Global revoke must be rejected if root has this key deployed."""
    fp = "SHA256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    with patch("actions.db") as mock_db:
        mock_db.query_one.side_effect = [
            {"id": "key-uuid"},                # ssh_keys lookup
            {"unix_user": "root"},             # protected_auth → root holds the key
        ]
        with pytest.raises(UserError, match="root"):
            actions.revoke_key(fp, ADMIN_ID, "test")


def test_actions_revoke_key_global_blocks_when_collector_has_key():
    """Global revoke must also reject when audit-collector holds the key."""
    fp = "SHA256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    with patch("actions.db") as mock_db:
        mock_db.query_one.side_effect = [
            {"id": "key-uuid"},
            {"unix_user": "audit-collector"},
        ]
        with pytest.raises(UserError, match="audit-collector"):
            actions.revoke_key(fp, ADMIN_ID, "test")


def test_actions_revoke_key_targeted_blocks_audit_collector():
    """Targeted revoke must refuse to remove the audit-collector key.

    The only legitimate path to change this key is rotate_collector_key,
    which does an atomic generate-test-replace.
    """
    fp = "SHA256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    with patch("actions.db") as mock_db:
        mock_db.query_one.side_effect = [
            {"id": "key-uuid"},   # ssh_keys lookup
        ]
        with pytest.raises(UserError, match="Rotate Collector Key"):
            actions.revoke_key(fp, ADMIN_ID, "test", hostname="srv1", unix_user="audit-collector")


def test_actions_revoke_key_global_proceeds_when_no_root_auth():
    """Global revoke proceeds normally when root does not have this key."""
    fp = "SHA256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    with patch("actions.db") as mock_db, patch("actions.ssh") as mock_ssh:
        mock_db.query_one.side_effect = [
            {"id": "key-uuid"},   # ssh_keys lookup
            None,                 # root_auth check → root does NOT have this key
        ]
        mock_db.query.return_value = []
        actions.revoke_key(fp, ADMIN_ID, "test")
        mock_db.query.assert_called_once()


# ---------------------------------------------------------------------------
# rotate_collector_key
# ---------------------------------------------------------------------------

def test_actions_rotate_collector_key_marks_old_revoked_and_inserts_new_active():
    """A successful rotation should:
      - mark the previous audit-collector authorization REVOKED
      - INSERT the new ssh_keys row + ACTIVE authorization
      - trigger an async scan
      - log COLLECTOR_KEY_ROTATED
    """
    new_fp = "SHA256:newKEYnewKEYnewKEYnewKEYnewKEYnewKEYnewKEY"
    with patch("actions.db") as mock_db, \
         patch("actions.ssh") as mock_ssh, \
         patch("actions.get_collector_key_for_server") as mock_get, \
         patch("actions._trigger_initial_scan") as mock_scan:
        mock_db.query_one.side_effect = [
            {"id": "srv-1", "ip_address": "10.0.0.1", "ssh_port": 22, "is_active": True},
            {"id": "key-new-uuid"},
            {"id": "srv-1", "hostname": "srv1", "ip_address": "10.0.0.1", "ssh_port": 22},
        ]
        mock_ssh.SSH_USER = "audit-collector"
        mock_ssh.rotate_per_server_key.return_value = new_fp
        mock_get.return_value = {"public_key": f"ssh-ed25519 AAAA {new_fp}"}

        result = actions.rotate_collector_key("srv1", ADMIN_ID)
        assert result == {"status": "rotated", "fingerprint": new_fp}

        # Three execute calls expected: revoke-old UPDATE, insert-new
        # INSERT into ssh_keys, INSERT into key_authorizations, audit log INSERT.
        statements = " ".join(c.args[0] for c in mock_db.execute.call_args_list)
        assert "UPDATE key_authorizations" in statements
        assert "Collector key rotated" in statements
        assert "INSERT INTO ssh_keys" in statements
        assert "INSERT INTO key_authorizations" in statements
        assert "COLLECTOR_KEY_ROTATED" in statements

        # Async scan was triggered for fresh state.
        mock_scan.assert_called_once()
        assert mock_scan.call_args.kwargs["sync"] is False


def test_actions_rotate_collector_key_logs_failure_and_raises_on_ssh_error():
    with patch("actions.db") as mock_db, patch("actions.ssh") as mock_ssh:
        mock_db.query_one.return_value = {
            "id": "srv-1", "ip_address": "10.0.0.1", "ssh_port": 22, "is_active": True,
        }
        # Use a real-looking class hierarchy: rotate raises an SSHError.
        class _SSHError(Exception):
            pass
        mock_ssh.SSHError = _SSHError
        mock_ssh.rotate_per_server_key.side_effect = _SSHError("network unreachable")

        with pytest.raises(UserError, match="Rotation failed"):
            actions.rotate_collector_key("srv1", ADMIN_ID)

        statements = " ".join(c.args[0] for c in mock_db.execute.call_args_list)
        assert "COLLECTOR_KEY_ROTATION_FAILED" in statements
        # No UPDATE / new INSERT happened — the SSHError occurred before
        # any of our DB mutations.
        assert "UPDATE key_authorizations" not in statements


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
        mock_ssh.ensure_scripts.assert_called_once_with("server-test-01", SERVER_ID, "192.168.1.10", port=22, key_path=ANY)
        mock_ssh.lock_user_on_server.assert_called_once_with("server-test-01", "alice", "192.168.1.10", port=22, key_path=ANY)
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
        mock_ssh.ensure_scripts.assert_called_once_with("server-test-01", SERVER_ID, "192.168.1.10", port=22, key_path=ANY)
        mock_ssh.unlock_user_on_server.assert_called_once_with("server-test-01", "alice", "192.168.1.10", port=22, key_path=ANY)
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
        mock_ssh._generate_keypair.return_value = ("/tmp/fake.key", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyForTesting")
        mock_ssh.SSH_USER = "audit-collector"
        with pytest.raises(UserError, match="Cannot lock the collector account"):
            actions.lock_user("audit-collector", "server-test-01", ADMIN_ID)


def test_actions_unlock_user_ssh_user_raises():
    with patch("actions.ssh") as mock_ssh:
        mock_ssh.SSH_USER = "audit-collector"
        with pytest.raises(UserError, match="Cannot unlock the collector account"):
            actions.unlock_user("audit-collector", "server-test-01", ADMIN_ID)


def test_actions_lock_user_root_raises():
    with pytest.raises(UserError, match="Cannot lock the root account"):
        actions.lock_user("root", "server-test-01", ADMIN_ID)


def test_actions_unlock_user_root_raises():
    with pytest.raises(UserError, match="Cannot unlock the root account"):
        actions.unlock_user("root", "server-test-01", ADMIN_ID)


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
        # New params order: (hostname, ip, env, os, port, max_sessions, server_id)
        assert update_call[0][1][2] is None


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


def test_actions_bulk_revoke_skips_on_ssh_error():
    """SSH failure on one fingerprint must not abort the whole bulk operation.

    Without the dedicated except branch, a single network glitch on one
    server would let ssh.SSHError propagate to the route handler, which
    would return HTTP 500 to the UI — even though the other fingerprints
    in the batch were perfectly revocable.
    """
    import ssh as ssh_mod
    fp1 = "SHA256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    fp2 = "SHA256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    with patch("actions.revoke_key") as mock_revoke:
        mock_revoke.side_effect = [ssh_mod.SSHTimeoutError("server2 unreachable"), None]
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

def test_actions_deploy_key_with_sam_group_passes_group_to_add_key(sample_server, sample_key):
    """deploy_key passes sam_group to add_key_on_server — sam-add handles group assignment."""
    with patch("actions.db") as mock_db, patch("actions.ssh") as mock_ssh:
        mock_db.query_one.side_effect = [
            {"id": sample_server["id"], "ip_address": sample_server["ip_address"], "ssh_port": 22},
            {"id": sample_key["id"]},
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
        mock_ssh.add_key_on_server.assert_called_once_with(
            sample_server["hostname"], "alice", sample_key["public_key"],
            sample_server["ip_address"], port=22, sam_group="sam-operator",
         key_path=ANY)
        mock_ssh.grant_group_on_server.assert_not_called()


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


def test_actions_deploy_key_justification_stored_in_audit_log(sample_server, sample_key):
    """deploy_key must include justification in the KEY_ADDED audit_log details."""
    with patch("actions.db") as mock_db, patch("actions.ssh"):
        mock_ssh = patch("actions.ssh").__enter__()
        mock_ssh._generate_keypair.return_value = ("/tmp/fake.key", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyForTesting")
        mock_db.query_one.side_effect = [
            {"id": sample_server["id"], "ip_address": sample_server["ip_address"], "ssh_port": 22},
            {"id": sample_key["id"]},
        ]
        actions.deploy_key(
            public_key=sample_key["public_key"],
            unix_user="alice",
            hostname=sample_server["hostname"],
            expires_at=None,
            justification="Security audit Q2",
            admin_id=ADMIN_ID,
        )
        audit_call = mock_db.execute.call_args_list[-1]
        assert "KEY_ADDED" in audit_call[0][0]
        import json
        details = json.loads(audit_call[0][1][-1])
        assert details["justification"] == "Security audit Q2"


def test_actions_deploy_key_no_sam_group_passes_none_to_add_key(sample_server, sample_key):
    """deploy_key with no group passes sam_group=None — sam-add strips all SAM groups."""
    with patch("actions.db") as mock_db, patch("actions.ssh") as mock_ssh:
        mock_db.query_one.side_effect = [
            {"id": sample_server["id"], "ip_address": sample_server["ip_address"], "ssh_port": 22},
            {"id": sample_key["id"]},
        ]
        actions.deploy_key(
            public_key=sample_key["public_key"],
            unix_user="alice",
            hostname=sample_server["hostname"],
            expires_at=None,
            justification="Test",
            admin_id=ADMIN_ID,
        )


# ---------------------------------------------------------------------------
# check_sshd_compliance — pure logic
# ---------------------------------------------------------------------------

def test_check_sshd_compliance_all_ok():
    """All hardening parameters correct → overall=ok, summary.ok=14."""
    parsed = {
        "permitrootlogin": "no",
        "passwordauthentication": "no",
        "permitemptypasswords": "no",
        "kbdinteractiveauthentication": "no",
        "challengeresponseauthentication": "no",
        "hostbasedauthentication": "no",
        "ignorerhosts": "yes",
        "x11forwarding": "no",
        "allowtcpforwarding": "no",
        "maxauthtries": "3",
        "logingracetime": "60",
        "clientaliveinterval": "300",
        "loglevel": "INFO",
        "usepam": "yes",
    }
    result = actions.check_sshd_compliance(parsed)
    assert result["overall"] == "ok"
    assert result["summary"]["ok"] == 14
    assert result["summary"]["critical"] == 0
    assert result["summary"]["warning"] == 0


def test_check_sshd_compliance_permitrootlogin_yes_is_critical():
    """permitrootlogin=yes → status=critical, overall=critical."""
    parsed = {
        "permitrootlogin": "yes",
        "passwordauthentication": "no",
        "permitemptypasswords": "no",
        "kbdinteractiveauthentication": "no",
        "hostbasedauthentication": "no",
        "ignorerhosts": "yes",
        "x11forwarding": "no",
        "allowtcpforwarding": "no",
        "maxauthtries": "3",
        "logingracetime": "60",
        "clientaliveinterval": "300",
        "loglevel": "INFO",
        "usepam": "yes",
    }
    result = actions.check_sshd_compliance(parsed)
    assert result["overall"] == "critical"
    assert result["summary"]["critical"] == 1
    check = [c for c in result["checks"] if c["directive"] == "permitrootlogin"][0]
    assert check["status"] == "critical"
    assert check["actual"] == "yes"


def test_check_sshd_compliance_maxauthtries_4_is_warning():
    """maxauthtries=4 (>3) → status=warning, overall=warning."""
    parsed = {
        "permitrootlogin": "no",
        "passwordauthentication": "no",
        "permitemptypasswords": "no",
        "kbdinteractiveauthentication": "no",
        "hostbasedauthentication": "no",
        "ignorerhosts": "yes",
        "x11forwarding": "no",
        "allowtcpforwarding": "no",
        "maxauthtries": "4",
        "logingracetime": "60",
        "clientaliveinterval": "300",
        "loglevel": "INFO",
        "usepam": "yes",
    }
    result = actions.check_sshd_compliance(parsed)
    assert result["overall"] == "warning"
    assert result["summary"]["warning"] == 1
    check = [c for c in result["checks"] if c["directive"] == "maxauthtries"][0]
    assert check["status"] == "warning"


def test_check_sshd_compliance_clientaliveinterval_0_is_info():
    """clientaliveinterval=0 (not >0) → status=info, overall=warning (info fails count in summary and overall)."""
    parsed = {
        "permitrootlogin": "no",
        "passwordauthentication": "no",
        "permitemptypasswords": "no",
        "kbdinteractiveauthentication": "no",
        "hostbasedauthentication": "no",
        "ignorerhosts": "yes",
        "x11forwarding": "no",
        "allowtcpforwarding": "no",
        "maxauthtries": "3",
        "logingracetime": "60",
        "clientaliveinterval": "0",
        "loglevel": "INFO",
        "usepam": "yes",
    }
    result = actions.check_sshd_compliance(parsed)
    assert result["summary"]["info"] == 1  # info failure counts in summary
    check = [c for c in result["checks"] if c["directive"] == "clientaliveinterval"][0]
    assert check["status"] == "info"
    assert check["severity"] == "info"


def test_check_sshd_compliance_directive_missing():
    """permitrootlogin missing from parsed → status=missing."""
    parsed = {
        "passwordauthentication": "no",
        "permitemptypasswords": "no",
        "kbdinteractiveauthentication": "no",
        "hostbasedauthentication": "no",
        "ignorerhosts": "yes",
        "x11forwarding": "no",
        "allowtcpforwarding": "no",
        "maxauthtries": "3",
        "logingracetime": "60",
        "clientaliveinterval": "300",
        "loglevel": "INFO",
        "usepam": "yes",
    }
    result = actions.check_sshd_compliance(parsed)
    assert result["summary"]["missing"] == 1
    check = [c for c in result["checks"] if c["directive"] == "permitrootlogin"][0]
    assert check["status"] == "missing"


def test_check_sshd_compliance_optional_directive_missing_is_skipped():
    """challengeresponseauthentication missing → not in checks (optional=True)."""
    parsed = {
        "permitrootlogin": "no",
        "passwordauthentication": "no",
        "permitemptypasswords": "no",
        "kbdinteractiveauthentication": "no",
        # challengeresponseauthentication missing (optional)
        "hostbasedauthentication": "no",
        "ignorerhosts": "yes",
        "x11forwarding": "no",
        "allowtcpforwarding": "no",
        "maxauthtries": "3",
        "logingracetime": "60",
        "clientaliveinterval": "300",
        "loglevel": "INFO",
        "usepam": "yes",
    }
    result = actions.check_sshd_compliance(parsed)
    challenge_checks = [c for c in result["checks"] if c["directive"] == "challengeresponseauthentication"]
    assert len(challenge_checks) == 0


# ---------------------------------------------------------------------------
# audit_server_sshd — integration
# ---------------------------------------------------------------------------

def test_audit_server_sshd_server_not_found_raises_userrror():
    with patch("actions.db") as mock_db:
        mock_db.query_one.return_value = None
        with pytest.raises(actions.NotFoundError, match="not found"):
            actions.audit_server_sshd("unknown-server")


def test_audit_server_sshd_disabled_server_raises_userrror():
    with patch("actions.db") as mock_db:
        mock_db.query_one.return_value = {
            "id": SERVER_ID,
            "ip_address": "192.168.1.1",
            "ssh_port": 22,
            "is_active": False,
        }
        with pytest.raises(UserError, match="disabled"):
            actions.audit_server_sshd("disabled-server")


def test_audit_server_sshd_ssh_failure_raises_userrror():
    import ssh as ssh_mod
    with patch("actions.db") as mock_db, patch("actions.ssh") as mock_ssh:
        mock_db.query_one.return_value = {
            "id": SERVER_ID,
            "ip_address": "192.168.1.1",
            "ssh_port": 22,
            "is_active": True,
        }
        mock_ssh.audit_sshd_config.side_effect = ssh_mod.SSHError("Connection failed")
        mock_ssh.SSHError = ssh_mod.SSHError
        with pytest.raises(UserError, match="SSH audit failed"):
            actions.audit_server_sshd("server-test-01")


def test_audit_server_sshd_happy_path():
    """audit_server_sshd returns check_sshd_compliance result."""
    with patch("actions.db") as mock_db, patch("actions.ssh") as mock_ssh:
        mock_db.query_one.return_value = {
            "id": SERVER_ID,
            "ip_address": "192.168.1.1",
            "ssh_port": 22,
            "is_active": True,
        }
        mock_ssh.audit_sshd_config.return_value = {
            "permitrootlogin": "no",
            "passwordauthentication": "no",
            "permitemptypasswords": "no",
            "kbdinteractiveauthentication": "no",
            "hostbasedauthentication": "no",
            "ignorerhosts": "yes",
            "x11forwarding": "no",
            "allowtcpforwarding": "no",
            "maxauthtries": "3",
            "logingracetime": "60",
            "clientaliveinterval": "300",
            "loglevel": "INFO",
            "usepam": "yes",
        }
        result = actions.audit_server_sshd("server-test-01")
        assert "checks" in result
        assert "summary" in result
        assert "overall" in result
        assert result["overall"] == "ok"
        mock_ssh.grant_group_on_server.assert_not_called()
        mock_ssh.revoke_group_on_server.assert_not_called()


# ---------------------------------------------------------------------------
# grant_group
# ---------------------------------------------------------------------------

def test_actions_grant_group_success(sample_server):
    with patch("actions.db") as mock_db, patch("actions.ssh") as mock_ssh:
        mock_ssh.grant_group_on_server.return_value = []
        mock_db.query_one.side_effect = [
            {"id": sample_server["id"], "ip_address": sample_server["ip_address"], "ssh_port": 22},
            None,  # no active session
            {"id": "ka-id"},
        ]
        result = actions.grant_group("alice", sample_server["hostname"], "sam-operator", ADMIN_ID)
        assert result["sam_group"] == "sam-operator"
        assert result["unix_user"] == "alice"
        mock_ssh.grant_group_on_server.assert_called_once_with(
            sample_server["hostname"], "alice", "sam-operator",
            sample_server["ip_address"], port=22,
         key_path=ANY)


def test_actions_grant_group_root_raises():
    with pytest.raises(UserError, match="Cannot assign a SAM group to the root account"):
        actions.grant_group("root", "server", "sam-pkg", ADMIN_ID)


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
            None,  # no active session
            None,  # no key_authorization
        ]
        with pytest.raises(UserError, match="No active key deployment"):
            actions.grant_group("alice", sample_server["hostname"], "sam-root", ADMIN_ID)


def test_actions_grant_group_logs_group_granted(sample_server):
    with patch("actions.db") as mock_db, patch("actions.ssh") as mock_ssh:
        mock_ssh.grant_group_on_server.return_value = []
        mock_db.query_one.side_effect = [
            {"id": sample_server["id"], "ip_address": sample_server["ip_address"], "ssh_port": 22},
            None,  # no active session
            {"id": "ka-id"},
        ]
        actions.grant_group("alice", sample_server["hostname"], "sam-pkg", ADMIN_ID)
        audit_call = mock_db.execute.call_args_list[-1]
        assert "GROUP_GRANTED" in audit_call[0][0]


# ---------------------------------------------------------------------------
# grant_group — active session blocking
# ---------------------------------------------------------------------------

def test_actions_grant_group_active_session_blocks(sample_server):
    with patch("actions.db") as mock_db:
        mock_db.query_one.side_effect = [
            {"id": sample_server["id"], "ip_address": sample_server["ip_address"], "ssh_port": 22},
            {"unix_user": "alice"},  # active session found
        ]
        with pytest.raises(UserError, match="active session"):
            actions.grant_group("alice", sample_server["hostname"], "sam-operator", ADMIN_ID)


# ---------------------------------------------------------------------------
# revoke_group
# ---------------------------------------------------------------------------

def test_actions_revoke_group_success(sample_server):
    with patch("actions.db") as mock_db, patch("actions.ssh") as mock_ssh:
        mock_ssh.revoke_group_on_server.return_value = []
        mock_db.query_one.side_effect = [
            {"id": sample_server["id"], "ip_address": sample_server["ip_address"], "ssh_port": 22},
            None,  # no active session
            {"sam_group": "sam-operator"},
        ]
        result = actions.revoke_group("alice", sample_server["hostname"], ADMIN_ID)
        assert result["sam_group"] is None
        mock_ssh.revoke_group_on_server.assert_called_once_with(
            sample_server["hostname"], "alice", "sam-operator",
            sample_server["ip_address"], port=22,
         key_path=ANY)


def test_actions_revoke_group_root_raises():
    with pytest.raises(UserError, match="Cannot modify the SAM group of the root account"):
        actions.revoke_group("root", "server", ADMIN_ID)


def test_actions_revoke_group_server_not_found_raises():
    with patch("actions.db") as mock_db:
        mock_db.query_one.return_value = None
        with pytest.raises(actions.NotFoundError, match="Server not found"):
            actions.revoke_group("alice", "unknown-server", ADMIN_ID)


def test_actions_revoke_group_no_deployment_raises(sample_server):
    with patch("actions.db") as mock_db:
        mock_db.query_one.side_effect = [
            {"id": sample_server["id"], "ip_address": sample_server["ip_address"], "ssh_port": 22},
            None,  # no active session
            None,  # no key_authorization at all
        ]
        with pytest.raises(UserError, match="No active key deployment"):
            actions.revoke_group("alice", sample_server["hostname"], ADMIN_ID)


def test_actions_revoke_group_logs_group_revoked(sample_server):
    with patch("actions.db") as mock_db, patch("actions.ssh") as mock_ssh:
        mock_ssh.revoke_group_on_server.return_value = []
        mock_db.query_one.side_effect = [
            {"id": sample_server["id"], "ip_address": sample_server["ip_address"], "ssh_port": 22},
            None,  # no active session
            {"sam_group": "sam-root"},
        ]
        actions.revoke_group("alice", sample_server["hostname"], ADMIN_ID)
        audit_call = mock_db.execute.call_args_list[-1]
        assert "GROUP_REVOKED" in audit_call[0][0]


def test_actions_revoke_group_active_session_blocks(sample_server):
    with patch("actions.db") as mock_db:
        mock_db.query_one.side_effect = [
            {"id": sample_server["id"], "ip_address": sample_server["ip_address"], "ssh_port": 22},
            {"unix_user": "alice"},  # active session found
        ]
        with pytest.raises(UserError, match="active session"):
            actions.revoke_group("alice", sample_server["hostname"], ADMIN_ID)


def test_actions_revoke_group_no_group_in_db_still_strips_server(sample_server):
    """revoke_group with sam_group=None in DB should still run strip command on server."""
    with patch("actions.db") as mock_db, patch("actions.ssh") as mock_ssh:
        mock_ssh.revoke_group_on_server.return_value = ["sam-users"]
        mock_db.query_one.side_effect = [
            {"id": sample_server["id"], "ip_address": sample_server["ip_address"], "ssh_port": 22},
            None,  # no active session
            {"sam_group": None},  # no group in DB
        ]
        result = actions.revoke_group("alice", sample_server["hostname"], ADMIN_ID)
        assert result["sam_group"] is None
        mock_ssh.revoke_group_on_server.assert_called_once_with(
            sample_server["hostname"], "alice", None,
            sample_server["ip_address"], port=22,
         key_path=ANY)


# ---------------------------------------------------------------------------
# change_group
# ---------------------------------------------------------------------------

def test_actions_change_group_root_raises():
    with pytest.raises(UserError, match="Cannot modify the SAM group of the root account"):
        actions.change_group("root", "server", "sam-pkg", ADMIN_ID)


def test_actions_change_group_success(sample_server):
    with patch("actions.db") as mock_db, patch("actions.ssh") as mock_ssh:
        mock_ssh.grant_group_on_server.return_value = []
        mock_ssh.revoke_group_on_server.return_value = []
        mock_db.query_one.side_effect = [
            {"id": sample_server["id"], "ip_address": sample_server["ip_address"], "ssh_port": 22},
            None,  # no active session
            {"sam_group": "sam-operator"},
        ]
        result = actions.change_group("alice", sample_server["hostname"], "sam-pkg", ADMIN_ID)
        assert result["sam_group"] == "sam-pkg"
        mock_ssh.revoke_group_on_server.assert_called_once()
        mock_ssh.grant_group_on_server.assert_called_once()


def test_actions_change_group_reapplies_when_same(sample_server):
    """change_group should re-apply even when group is identical (force sync)."""
    with patch("actions.db") as mock_db, patch("actions.ssh") as mock_ssh:
        mock_ssh.grant_group_on_server.return_value = ["sam-users", "sam-pkg"]
        mock_db.query_one.side_effect = [
            {"id": sample_server["id"], "ip_address": sample_server["ip_address"], "ssh_port": 22},
            None,  # no active session
            {"sam_group": "sam-pkg"},
        ]
        result = actions.change_group("alice", sample_server["hostname"], "sam-pkg", ADMIN_ID)
        assert result["sam_group"] == "sam-pkg"
        mock_ssh.grant_group_on_server.assert_called_once()


def test_actions_change_group_from_none_does_not_revoke(sample_server):
    with patch("actions.db") as mock_db, patch("actions.ssh") as mock_ssh:
        mock_ssh.grant_group_on_server.return_value = []
        mock_db.query_one.side_effect = [
            {"id": sample_server["id"], "ip_address": sample_server["ip_address"], "ssh_port": 22},
            None,  # no active session
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
            None,  # no active session
            None,  # no key_authorization
        ]
        with pytest.raises(UserError, match="No active key deployment"):
            actions.change_group("alice", sample_server["hostname"], "sam-operator", ADMIN_ID)


def test_actions_change_group_logs_group_changed(sample_server):
    with patch("actions.db") as mock_db, patch("actions.ssh") as mock_ssh:
        mock_ssh.grant_group_on_server.return_value = []
        mock_ssh.revoke_group_on_server.return_value = []
        mock_db.query_one.side_effect = [
            {"id": sample_server["id"], "ip_address": sample_server["ip_address"], "ssh_port": 22},
            None,  # no active session
            {"sam_group": "sam-operator"},
        ]
        actions.change_group("alice", sample_server["hostname"], "sam-pkg", ADMIN_ID)
        audit_call = mock_db.execute.call_args_list[-1]
        assert "GROUP_CHANGED" in audit_call[0][0]


def test_actions_change_group_active_session_blocks(sample_server):
    with patch("actions.db") as mock_db:
        mock_db.query_one.side_effect = [
            {"id": sample_server["id"], "ip_address": sample_server["ip_address"], "ssh_port": 22},
            {"unix_user": "alice"},  # active session found
        ]
        with pytest.raises(UserError, match="active session"):
            actions.change_group("alice", sample_server["hostname"], "sam-operator", ADMIN_ID)


# ---------------------------------------------------------------------------
# list_audit_logs
# ---------------------------------------------------------------------------

def test_actions_list_audit_logs_returns_expected_shape():
    """list_audit_logs returns {rows, total, facets} structure."""
    with patch("actions.db") as mock_db:
        mock_db.query_one.return_value = {"n": 0}
        mock_db.query.return_value = []
        result = actions.list_audit_logs()
        assert "rows" in result
        assert "total" in result
        assert "facets" in result
        assert "servers" in result["facets"]
        assert "actions" in result["facets"]


def test_actions_list_audit_logs_no_filters():
    """list_audit_logs without filters queries all records."""
    with patch("actions.db") as mock_db:
        mock_db.query_one.return_value = {"n": 5}
        mock_db.query.side_effect = [
            [{"id": "1", "action": "KEY_ADDED", "details": "test"},
             {"id": "2", "action": "KEY_REVOKED", "details": "test"}],  # main rows
            [{"hostname": "srv-01"}],  # servers facet
            [{"action": "KEY_ADDED"}, {"action": "KEY_REVOKED"}],  # actions facet
        ]
        result = actions.list_audit_logs()
        assert result["total"] == 5
        assert len(result["rows"]) == 2
        # Main query should not have filter clauses except WHERE 1=1
        main_sql = mock_db.query.call_args_list[0][0][0]
        assert "WHERE 1=1" in main_sql
        assert " AND s.hostname = " not in main_sql
        assert " AND al.action = " not in main_sql


def test_actions_list_audit_logs_filter_server():
    """list_audit_logs filters by server hostname."""
    with patch("actions.db") as mock_db:
        mock_db.query_one.return_value = {"n": 2}
        mock_db.query.side_effect = [[], [], []]  # rows, servers facet, actions facet
        actions.list_audit_logs(server="srv-01")
        main_sql = mock_db.query.call_args_list[0][0][0]
        assert " AND s.hostname = " in main_sql


def test_actions_list_audit_logs_filter_action():
    """list_audit_logs filters by action type."""
    with patch("actions.db") as mock_db:
        mock_db.query_one.return_value = {"n": 1}
        mock_db.query.side_effect = [[], [], []]
        actions.list_audit_logs(action="KEY_REVOKED")
        main_sql = mock_db.query.call_args_list[0][0][0]
        assert " AND al.action = " in main_sql


def test_actions_list_audit_logs_filter_since():
    """list_audit_logs filters by timestamp."""
    with patch("actions.db") as mock_db:
        mock_db.query_one.return_value = {"n": 0}
        mock_db.query.side_effect = [[], [], []]
        actions.list_audit_logs(since="2025-01-01T00:00:00Z")
        main_sql = mock_db.query.call_args_list[0][0][0]
        assert " AND al.performed_at >= " in main_sql


def test_actions_list_audit_logs_fulltext_search_q():
    """list_audit_logs applies ILIKE OR when q is provided."""
    with patch("actions.db") as mock_db:
        mock_db.query_one.return_value = {"n": 3}
        mock_db.query.side_effect = [[], [], []]
        actions.list_audit_logs(q="admin")
        main_sql = mock_db.query.call_args_list[0][0][0]
        # details is jsonb in PG → must cast to text before ILIKE (fix bug
        # where /api/audit?q=g returned 500: "operator does not exist: jsonb ~~* unknown")
        assert "al.details::text ILIKE" in main_sql
        assert "al.action ILIKE" in main_sql
        assert "adm.username ILIKE" in main_sql
        assert "sk.fingerprint ILIKE" in main_sql
        assert "s.hostname ILIKE" in main_sql


def test_actions_list_audit_logs_q_escapes_wildcards():
    """list_audit_logs escapes % and _ in q parameter."""
    with patch("actions.db") as mock_db:
        mock_db.query_one.return_value = {"n": 0}
        mock_db.query.side_effect = [[], [], []]
        actions.list_audit_logs(q="test%_string")
        params = mock_db.query.call_args_list[0][0][1]
        # The pattern should be %test\%\_string% (escaped)
        assert any("test\\%\\_string" in str(p) for p in params)


def test_actions_list_audit_logs_q_case_insensitive():
    """list_audit_logs uses ILIKE for case-insensitive search."""
    with patch("actions.db") as mock_db:
        mock_db.query_one.return_value = {"n": 0}
        mock_db.query.side_effect = [[], [], []]
        actions.list_audit_logs(q="ADMIN")
        main_sql = mock_db.query.call_args_list[0][0][0]
        # ILIKE is case-insensitive
        assert "ILIKE" in main_sql
        assert "LIKE" in main_sql  # ILIKE contains LIKE


def test_actions_list_audit_logs_facets_servers_excludes_server_filter():
    """facets.servers applies all filters EXCEPT server (filter-minus-self)."""
    with patch("actions.db") as mock_db:
        mock_db.query_one.return_value = {"n": 0}
        mock_db.query.side_effect = [
            [],  # main rows
            [{"hostname": "srv-01"}, {"hostname": "srv-02"}],  # servers facet
            [],  # actions facet
        ]
        result = actions.list_audit_logs(server="srv-01", action="KEY_REVOKED", q="admin")
        # Facet query should NOT have server filter
        facet_servers_sql = mock_db.query.call_args_list[1][0][0]
        assert " AND al.action = " in facet_servers_sql  # action IS applied
        assert "al.details::text ILIKE" in facet_servers_sql  # q IS applied
        assert " AND s.hostname = " not in facet_servers_sql  # server NOT applied
        assert result["facets"]["servers"] == ["srv-01", "srv-02"]


def test_actions_list_audit_logs_facets_actions_excludes_action_filter():
    """facets.actions applies all filters EXCEPT action (filter-minus-self)."""
    with patch("actions.db") as mock_db:
        mock_db.query_one.return_value = {"n": 0}
        mock_db.query.side_effect = [
            [],  # main rows
            [],  # servers facet
            [{"action": "KEY_ADDED"}, {"action": "KEY_REVOKED"}],  # actions facet
        ]
        result = actions.list_audit_logs(server="srv-01", action="KEY_REVOKED", q="admin")
        # Facet query should NOT have action filter
        facet_actions_sql = mock_db.query.call_args_list[2][0][0]
        assert " AND s.hostname = " in facet_actions_sql  # server IS applied
        assert "al.details::text ILIKE" in facet_actions_sql  # q IS applied
        assert " AND al.action = " not in facet_actions_sql  # action NOT applied
        assert result["facets"]["actions"] == ["KEY_ADDED", "KEY_REVOKED"]


def test_actions_list_audit_logs_facets_sorted_alphabetically():
    """facets.servers and facets.actions are sorted alphabetically."""
    with patch("actions.db") as mock_db:
        mock_db.query_one.return_value = {"n": 0}
        mock_db.query.side_effect = [
            [],  # main rows
            [{"hostname": "z-server"}, {"hostname": "a-server"}],  # servers
            [{"action": "SCAN_COMPLETED"}, {"action": "KEY_ADDED"}],  # actions
        ]
        result = actions.list_audit_logs()
        # Check SQL has ORDER BY
        facet_servers_sql = mock_db.query.call_args_list[1][0][0]
        facet_actions_sql = mock_db.query.call_args_list[2][0][0]
        assert "ORDER BY s.hostname" in facet_servers_sql
        assert "ORDER BY al.action" in facet_actions_sql


def test_actions_list_audit_logs_limit_500():
    """list_audit_logs limits main query to 500 rows."""
    with patch("actions.db") as mock_db:
        mock_db.query_one.return_value = {"n": 1000}
        mock_db.query.side_effect = [[], [], []]
        actions.list_audit_logs()
        main_sql = mock_db.query.call_args_list[0][0][0]
        assert "LIMIT 500" in main_sql


def test_actions_list_audit_logs_combined_filters():
    """list_audit_logs applies all filters together."""
    with patch("actions.db") as mock_db:
        mock_db.query_one.return_value = {"n": 1}
        mock_db.query.side_effect = [[], [], []]
        actions.list_audit_logs(
            server="srv-01",
            action="KEY_REVOKED",
            since="2025-01-01T00:00:00Z",
            q="admin"
        )
        main_sql = mock_db.query.call_args_list[0][0][0]
        assert " AND s.hostname = " in main_sql
        assert " AND al.action = " in main_sql
        assert " AND al.performed_at >= " in main_sql
        assert "ILIKE" in main_sql
