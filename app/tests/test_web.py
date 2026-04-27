import base64
import os
import sys
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import web

ADMIN_ID = str(uuid.uuid4())
KEY_ID = str(uuid.uuid4())
SERVER_ID = str(uuid.uuid4())
REQUEST_ID = str(uuid.uuid4())
FINGERPRINT = "SHA256:testABCDEF1234"


def _admin_row():
    return {"id": ADMIN_ID, "username": "admin", "role": "sysadmin"}


@pytest.fixture
def client():
    web.app.config["TESTING"] = True
    with web.app.test_client() as c:
        yield c


@pytest.fixture
def auth_client(client):
    """Client with an active admin session."""
    with client.session_transaction() as sess:
        sess["admin_id"] = ADMIN_ID
        sess["admin_username"] = "admin"
    return client


# ---------------------------------------------------------------------------
# Authentification
# ---------------------------------------------------------------------------

def test_web_no_auth_returns_401(client):
    with patch("web.db") as mock_db:
        resp = client.get("/api/keys")
        assert resp.status_code == 401


def test_web_invalid_admin_returns_401(auth_client):
    with patch("web.db") as mock_db:
        mock_db.query_one.return_value = None  # admin not found in DB
        resp = auth_client.get("/api/keys")
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# GET /api/keys — retourne 200 + liste JSON
# ---------------------------------------------------------------------------

def test_web_get_keys_returns_200_and_list(auth_client):
    key_row = {
        "id": KEY_ID, "fingerprint": FINGERPRINT,
        "key_type": "ssh-ed25519", "is_compliant": True, "owner": None,
    }
    with patch("web.db") as mock_db:
        mock_db.query_one.return_value = _admin_row()
        mock_db.query.return_value = [key_row]
        resp = auth_client.get("/api/keys")
        assert resp.status_code == 200
        data = resp.get_json()
        assert isinstance(data, list)
        assert data[0]["fingerprint"] == FINGERPRINT


def test_web_get_keys_with_status_filter(auth_client):
    with patch("web.db") as mock_db:
        mock_db.query_one.return_value = _admin_row()
        mock_db.query.return_value = []
        resp = auth_client.get("/api/keys?status=ACTIVE")
        assert resp.status_code == 200
        sql = mock_db.query.call_args[0][0]
        assert "status" in sql


# ---------------------------------------------------------------------------
# GET /api/keys — champ owner présent dans la réponse
# ---------------------------------------------------------------------------

def test_web_get_keys_includes_owner_field(auth_client):
    key_row = {
        "id": KEY_ID, "fingerprint": FINGERPRINT,
        "key_type": "ssh-ed25519", "is_compliant": True, "owner": "alice",
    }
    with patch("web.db") as mock_db:
        mock_db.query_one.return_value = _admin_row()
        mock_db.query.return_value = [key_row]
        resp = auth_client.get("/api/keys")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data[0].get("owner") == "alice"


def test_web_get_keys_owner_is_none_when_unassigned(auth_client):
    key_row = {
        "id": KEY_ID, "fingerprint": FINGERPRINT,
        "key_type": "ssh-ed25519", "is_compliant": True, "owner": None,
    }
    with patch("web.db") as mock_db:
        mock_db.query_one.return_value = _admin_row()
        mock_db.query.return_value = [key_row]
        resp = auth_client.get("/api/keys")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data[0].get("owner") is None


def test_web_get_keys_sql_includes_revocation_and_server_fields(auth_client):
    with patch("web.db") as mock_db:
        mock_db.query_one.return_value = _admin_row()
        mock_db.query.return_value = []
        auth_client.get("/api/keys")
        sql = mock_db.query.call_args[0][0]
        assert "revoked_automatically" in sql
        assert "revoked_by" in sql
        assert "revoked_at" in sql
        assert "revocation_justification" in sql
        assert "server_hostname" in sql


# ---------------------------------------------------------------------------
# POST /api/keys/validate/<fp> — 200 si authentifié, 401 sinon, scoped
# ---------------------------------------------------------------------------

def test_web_validate_key_returns_200_if_authenticated(auth_client):
    with patch("web.db") as mock_db, patch("web.actions") as mock_actions:
        mock_db.query_one.return_value = _admin_row()
        resp = auth_client.post(
            f"/api/keys/validate/{FINGERPRINT}",
            json={"unix_user": "alice", "hostname": "server-01"},
        )
        assert resp.status_code == 200
        mock_actions.validate_key.assert_called_once_with(
            FINGERPRINT, ADMIN_ID, unix_user="alice", hostname="server-01"
        )


def test_web_validate_key_returns_401_if_not_authenticated(client):
    resp = client.post(f"/api/keys/validate/{FINGERPRINT}", json={})
    assert resp.status_code == 401


def test_web_validate_key_passes_none_when_fields_absent(auth_client):
    with patch("web.db") as mock_db, patch("web.actions") as mock_actions:
        mock_db.query_one.return_value = _admin_row()
        resp = auth_client.post(f"/api/keys/validate/{FINGERPRINT}", json={})
        assert resp.status_code == 200
        mock_actions.validate_key.assert_called_once_with(
            FINGERPRINT, ADMIN_ID, unix_user=None, hostname=None
        )


# ---------------------------------------------------------------------------
# POST /api/keys/revoke/<fp> — fingerprint malformé rejeté avec 400
# ---------------------------------------------------------------------------

def test_web_revoke_key_rejects_invalid_fingerprint_format(auth_client):
    with patch("web.db") as mock_db:
        mock_db.query_one.return_value = _admin_row()
        for bad_fp in ["not-a-fingerprint", "SHA256:has_invalid_chars!", "MD5:abcdef"]:
            resp = auth_client.post(
                f"/api/keys/revoke/{bad_fp}",
                json={"reason": "test"},
            )
            assert resp.status_code == 400, f"Expected 400 for fp={bad_fp}"


# ---------------------------------------------------------------------------
# POST /api/keys/revoke/<fp> — 200 si authentifie, 401 si non authentifie
# ---------------------------------------------------------------------------

def test_web_revoke_key_returns_200_if_authenticated(auth_client):
    with patch("web.db") as mock_db, patch("web.actions") as mock_actions:
        mock_db.query_one.return_value = _admin_row()
        resp = auth_client.post(
            f"/api/keys/revoke/{FINGERPRINT}",
            json={"reason": "test"},
        )
        assert resp.status_code == 200
        mock_actions.revoke_key.assert_called_once_with(
            FINGERPRINT, ADMIN_ID, "test", hostname=None, unix_user=None
        )


def test_web_revoke_key_passes_unix_user_and_hostname(auth_client):
    with patch("web.db") as mock_db, patch("web.actions") as mock_actions:
        mock_db.query_one.return_value = _admin_row()
        resp = auth_client.post(
            f"/api/keys/revoke/{FINGERPRINT}",
            json={"reason": "test", "hostname": "server-01", "unix_user": "alice"},
        )
        assert resp.status_code == 200
        mock_actions.revoke_key.assert_called_once_with(
            FINGERPRINT, ADMIN_ID, "test", hostname="server-01", unix_user="alice"
        )


def test_web_revoke_key_returns_401_if_not_authenticated(client):
    resp = client.post(f"/api/keys/revoke/{FINGERPRINT}", json={"reason": "test"})
    assert resp.status_code == 401


def test_web_revoke_key_returns_404_if_key_not_found(auth_client):
    with patch("web.db") as mock_db, patch("web.actions") as mock_actions:
        mock_db.query_one.return_value = _admin_row()
        mock_actions.revoke_key.side_effect = ValueError("Key not found")
        resp = auth_client.post(
            f"/api/keys/revoke/{FINGERPRINT}",
            json={"reason": "x"},
        )
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# POST /api/access/grant — 201 avec expires_at calculé
# ---------------------------------------------------------------------------

def test_web_grant_access_returns_201_with_expires_at(auth_client):
    expires_at = datetime.now(tz=timezone.utc) + timedelta(hours=8)
    with patch("web.db") as mock_db, patch("web.actions") as mock_actions:
        mock_db.query_one.return_value = _admin_row()
        mock_actions.grant_access.return_value = {
            "key_id": KEY_ID,
            "server_id": SERVER_ID,
            "expires_at": expires_at,
        }
        resp = auth_client.post(
            "/api/access/grant",
            json={
                "key_fp": FINGERPRINT,
                "hostname": "server-test-01",
                "duration_hours": 8,
                "justification": "maintenance",
            },
        )
        assert resp.status_code == 201
        data = resp.get_json()
        assert "expires_at" in data
        assert data["key_id"] == KEY_ID


def test_web_grant_access_returns_400_without_expiry(auth_client):
    with patch("web.db") as mock_db:
        mock_db.query_one.return_value = _admin_row()
        resp = auth_client.post(
            "/api/access/grant",
            json={"key_fp": FINGERPRINT, "hostname": "host", "justification": "x"},
        )
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# POST /api/keys/set-expiry — datetime-local format (sans secondes)
# ---------------------------------------------------------------------------

def test_web_set_expiry_accepts_datetime_local_format(auth_client):
    with patch("web.db") as mock_db, patch("web.actions") as mock_actions:
        mock_db.query_one.return_value = _admin_row()
        resp = auth_client.post(
            f"/api/keys/set-expiry/{FINGERPRINT}",
            json={"date": "2099-12-31T23:59"},
        )
        assert resp.status_code == 200
        mock_actions.set_key_expiry.assert_called_once()


def test_web_set_expiry_rejects_no_date_or_hours(auth_client):
    with patch("web.db") as mock_db:
        mock_db.query_one.return_value = _admin_row()
        resp = auth_client.post(
            f"/api/keys/set-expiry/{FINGERPRINT}",
            json={},
        )
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# GET /api/servers
# ---------------------------------------------------------------------------

def test_web_get_servers_returns_200(auth_client):
    with patch("web.db") as mock_db:
        mock_db.query_one.return_value = _admin_row()
        mock_db.query.return_value = [{"hostname": "srv-01"}]
        resp = auth_client.get("/api/servers")
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# POST /api/servers
# ---------------------------------------------------------------------------

def test_web_add_server_returns_201(auth_client):
    with patch("web.db") as mock_db, patch("web.actions") as mock_actions:
        mock_db.query_one.return_value = _admin_row()
        mock_actions.add_server.return_value = {"id": SERVER_ID}
        resp = auth_client.post(
            "/api/servers",
            json={"hostname": "new-srv", "ip": "10.0.0.1", "environment": "lab"},
        )
        assert resp.status_code == 201


# ---------------------------------------------------------------------------
# PUT /api/servers/<hostname> — update server
# ---------------------------------------------------------------------------

def test_web_update_server_authenticated_returns_200(auth_client):
    with patch("web.db") as mock_db, patch("web.actions") as mock_actions:
        mock_db.query_one.return_value = _admin_row()
        resp = auth_client.put(
            "/api/servers/server-test-01",
            json={"ip": "10.0.0.2", "environment": "production", "os_family": "debian"},
        )
        assert resp.status_code == 200
        mock_actions.update_server.assert_called_once_with(
            "server-test-01", "10.0.0.2", "production", "debian", ADMIN_ID
        )


def test_web_update_server_unauthenticated_returns_401(client):
    resp = client.put(
        "/api/servers/server-test-01",
        json={"ip": "10.0.0.2", "environment": "production"},
    )
    assert resp.status_code == 401


def test_web_update_server_not_found_returns_404(auth_client):
    with patch("web.db") as mock_db, patch("web.actions") as mock_actions:
        mock_db.query_one.return_value = _admin_row()
        mock_actions.update_server.side_effect = ValueError("Server not found")
        resp = auth_client.put(
            "/api/servers/ghost",
            json={"ip": "10.0.0.2", "environment": "lab"},
        )
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# PUT /api/servers/<hostname>/enable
# ---------------------------------------------------------------------------

def test_web_enable_server_returns_200(auth_client):
    with patch("web.db") as mock_db, patch("web.actions") as mock_actions:
        mock_db.query_one.return_value = _admin_row()
        resp = auth_client.put("/api/servers/server-test-01/enable")
        assert resp.status_code == 200
        mock_actions.enable_server.assert_called_once_with("server-test-01", ADMIN_ID)


def test_web_enable_server_returns_404_if_not_found(auth_client):
    with patch("web.db") as mock_db, patch("web.actions") as mock_actions:
        mock_db.query_one.return_value = _admin_row()
        mock_actions.enable_server.side_effect = ValueError("not found")
        resp = auth_client.put("/api/servers/ghost/enable")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# DELETE /api/servers/<hostname>
# ---------------------------------------------------------------------------

def test_web_delete_server_returns_200(auth_client):
    with patch("web.db") as mock_db, patch("web.actions") as mock_actions:
        mock_db.query_one.return_value = _admin_row()
        resp = auth_client.delete("/api/servers/server-test-01")
        assert resp.status_code == 200
        mock_actions.delete_server.assert_called_once_with("server-test-01", ADMIN_ID)


def test_web_delete_server_returns_404_if_not_found(auth_client):
    with patch("web.db") as mock_db, patch("web.actions") as mock_actions:
        mock_db.query_one.return_value = _admin_row()
        mock_actions.delete_server.side_effect = ValueError("not found")
        resp = auth_client.delete("/api/servers/ghost")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# GET /api/audit
# ---------------------------------------------------------------------------

def test_web_get_audit_returns_200(auth_client):
    with patch("web.db") as mock_db:
        mock_db.query_one.return_value = _admin_row()
        mock_db.query.return_value = []
        resp = auth_client.get("/api/audit")
        assert resp.status_code == 200


def test_web_get_audit_filters_by_action(auth_client):
    with patch("web.db") as mock_db:
        mock_db.query_one.return_value = _admin_row()
        mock_db.query.return_value = []
        resp = auth_client.get("/api/audit?action=KEY_REVOKED")
        assert resp.status_code == 200
        sql = mock_db.query.call_args[0][0]
        assert "action" in sql


# ---------------------------------------------------------------------------
# GET /api/system/status
# ---------------------------------------------------------------------------

def test_web_system_status_returns_200(auth_client):
    with patch("web.db") as mock_db:
        mock_db.query_one.side_effect = [
            _admin_row(),
            {"n": 3},   # servers_active
            {"n": 1},   # keys_pending
            {"n": 10},  # keys_active
            None,       # last_scan
        ]
        resp = auth_client.get("/api/system/status")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "servers_active" in data
        assert "keys_pending_review" in data


def test_web_collector_key_includes_ssh_user(auth_client, tmp_path):
    pub_key_file = tmp_path / "collector_key.pub"
    pub_key_file.write_text("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 test")
    with patch("web.db") as mock_db, patch("web.ssh.SSH_USER", "custom-collector"), \
         patch.dict("os.environ", {"COLLECTOR_KEY": str(tmp_path / "collector_key")}):
        mock_db.query_one.return_value = _admin_row()
        resp = auth_client.get("/api/system/collector-key")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["ssh_user"] == "custom-collector"
        assert "ssh-ed25519" in data["public_key"]


# ---------------------------------------------------------------------------
# PUT /api/admins/<username>/disable
# ---------------------------------------------------------------------------

def test_web_disable_admin_returns_200(auth_client):
    with patch("web.db") as mock_db, patch("web.actions") as mock_actions:
        mock_db.query_one.return_value = _admin_row()
        resp = auth_client.put("/api/admins/someuser/disable")
        assert resp.status_code == 200
        mock_actions.disable_admin.assert_called_once_with("someuser", ADMIN_ID)


def test_web_disable_admin_self_returns_403(auth_client):
    with patch("web.db") as mock_db:
        mock_db.query_one.return_value = _admin_row()
        resp = auth_client.put("/api/admins/admin/disable")
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# GET /api/admins/me
# ---------------------------------------------------------------------------

def test_web_get_me_returns_current_admin(auth_client):
    with patch("web.db") as mock_db:
        mock_db.query_one.return_value = _admin_row()
        resp = auth_client.get("/api/admins/me")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["username"] == "admin"
        assert data["id"] == ADMIN_ID


# ---------------------------------------------------------------------------
# PUT /api/admins/<username>/enable
# ---------------------------------------------------------------------------

def test_web_enable_admin_returns_200(auth_client):
    with patch("web.db") as mock_db, patch("web.actions") as mock_actions:
        mock_db.query_one.return_value = _admin_row()
        resp = auth_client.put("/api/admins/someuser/enable")
        assert resp.status_code == 200
        mock_actions.enable_admin.assert_called_once_with("someuser", ADMIN_ID)


def test_web_enable_admin_self_returns_403(auth_client):
    with patch("web.db") as mock_db:
        mock_db.query_one.return_value = _admin_row()
        resp = auth_client.put("/api/admins/admin/enable")
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# DELETE /api/admins/<username>
# ---------------------------------------------------------------------------

def test_web_delete_admin_returns_200(auth_client):
    with patch("web.db") as mock_db, patch("web.actions") as mock_actions:
        mock_db.query_one.return_value = _admin_row()
        resp = auth_client.delete("/api/admins/someuser")
        assert resp.status_code == 200
        mock_actions.delete_admin.assert_called_once_with("someuser", ADMIN_ID)


def test_web_delete_admin_self_returns_403(auth_client):
    with patch("web.db") as mock_db:
        mock_db.query_one.return_value = _admin_row()
        resp = auth_client.delete("/api/admins/admin")
        assert resp.status_code == 403


def test_web_delete_admin_with_references_returns_400(auth_client):
    with patch("web.db") as mock_db, patch("web.actions") as mock_actions:
        mock_db.query_one.return_value = _admin_row()
        mock_actions.delete_admin.side_effect = ValueError("existing audit records reference this account")
        resp = auth_client.delete("/api/admins/someuser")
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# PUT /api/admins/<username> — update email/role
# ---------------------------------------------------------------------------

def test_web_update_admin_returns_200(auth_client):
    with patch("web.db") as mock_db, patch("web.actions") as mock_actions:
        mock_db.query_one.return_value = _admin_row()
        mock_actions.update_admin.return_value = {
            "username": "testuser", "email": "new@example.com", "role": "operator"
        }
        resp = auth_client.put("/api/admins/testuser", json={
            "email": "new@example.com",
            "role": "operator"
        })
        assert resp.status_code == 200
        assert resp.get_json()["message"] == "Admin updated"
        mock_actions.update_admin.assert_called_once_with(
            "testuser", "new@example.com", "operator", ADMIN_ID
        )


def test_web_update_admin_returns_401_unauthenticated(client):
    resp = client.put("/api/admins/testuser", json={
        "email": "new@example.com",
        "role": "operator"
    })
    assert resp.status_code == 401


def test_web_update_admin_returns_404_not_found(auth_client):
    with patch("web.db") as mock_db, patch("web.actions") as mock_actions:
        mock_db.query_one.return_value = _admin_row()
        mock_actions.update_admin.side_effect = ValueError("Admin not found: ghost")
        resp = auth_client.put("/api/admins/ghost", json={
            "email": "new@example.com",
            "role": "operator"
        })
        assert resp.status_code == 404


def test_web_update_admin_returns_403_self_role(auth_client):
    with patch("web.db") as mock_db, patch("web.actions") as mock_actions:
        mock_db.query_one.return_value = _admin_row()
        mock_actions.update_admin.side_effect = ValueError("Cannot change your own role")
        resp = auth_client.put("/api/admins/admin", json={
            "email": "admin@example.com",
            "role": "operator"
        })
        assert resp.status_code == 403


def test_web_update_admin_null_email_returns_200(auth_client):
    with patch("web.db") as mock_db, patch("web.actions") as mock_actions:
        mock_db.query_one.return_value = _admin_row()
        mock_actions.update_admin.return_value = {
            "username": "testuser", "email": None, "role": "operator"
        }
        resp = auth_client.put("/api/admins/testuser", json={
            "email": None,
            "role": "operator"
        })
        assert resp.status_code == 200
        mock_actions.update_admin.assert_called_once_with(
            "testuser", None, "operator", ADMIN_ID
        )


def test_web_update_admin_missing_role_returns_400(auth_client):
    with patch("web.db") as mock_db:
        mock_db.query_one.return_value = _admin_row()
        resp = auth_client.put("/api/admins/testuser", json={"email": "x@x.com"})
        assert resp.status_code == 400
        assert "role" in resp.get_json()["error"]


# ---------------------------------------------------------------------------
# GET/PUT /api/system/config
# ---------------------------------------------------------------------------

def test_web_get_config_returns_settings(auth_client):
    with patch("web.db") as mock_db:
        mock_db.query_one.return_value = {"id": "admin-id", "username": "admin", "role": "sysadmin"}
        mock_db.query.return_value = [
            {"key": "scan_interval_hours", "value": "4"},
            {"key": "expire_warn_days", "value": "7"},
            {"key": "expire_warn_days_2", "value": "2"},
        ]
        resp = auth_client.get("/api/system/config")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["scan_interval_hours"] == "4"
        assert data["expire_warn_days"] == "7"
        assert data["expire_warn_days_2"] == "2"


def test_web_put_config_updates_interval(auth_client):
    with patch("web.db") as mock_db:
        mock_db.query_one.side_effect = [
            {"id": "admin-id", "username": "admin", "role": "sysadmin"},
            {"value": "7"},  # current expire_warn_days
            {"value": "2"},  # current expire_warn_days_2
        ]
        mock_db.query.return_value = [
            {"key": "scan_interval_hours", "value": "6"},
            {"key": "expire_warn_days", "value": "7"},
            {"key": "expire_warn_days_2", "value": "2"},
        ]
        resp = auth_client.put("/api/system/config", json={"scan_interval_hours": 6})
        assert resp.status_code == 200
        assert resp.get_json()["scan_interval_hours"] == 6


def test_web_put_config_rejects_out_of_range(auth_client):
    with patch("web.db") as mock_db:
        mock_db.query_one.return_value = {"id": "admin-id", "username": "admin", "role": "sysadmin"}
        resp = auth_client.put("/api/system/config", json={"scan_interval_hours": 99})
        assert resp.status_code == 400


def test_web_put_config_rejects_missing_field(auth_client):
    with patch("web.db") as mock_db:
        mock_db.query_one.return_value = {"id": "admin-id", "username": "admin", "role": "sysadmin"}
        resp = auth_client.put("/api/system/config", json={})
        assert resp.status_code == 400
        assert "At least one setting" in resp.get_json()["error"]


def test_web_put_config_updates_expire_warn_days(auth_client):
    with patch("web.db") as mock_db:
        mock_db.query_one.side_effect = [
            {"id": "admin-id", "username": "admin", "role": "sysadmin"},
            {"value": "7"},  # current expire_warn_days
            {"value": "2"},  # current expire_warn_days_2
        ]
        mock_db.query.return_value = [
            {"key": "scan_interval_hours", "value": "4"},
            {"key": "expire_warn_days", "value": "10"},
            {"key": "expire_warn_days_2", "value": "2"},
        ]
        resp = auth_client.put("/api/system/config", json={"expire_warn_days": 10})
        assert resp.status_code == 200
        assert resp.get_json()["expire_warn_days"] == 10


def test_web_put_config_rejects_when_warn_days_not_greater_than_warn_days_2(auth_client):
    with patch("web.db") as mock_db:
        mock_db.query_one.side_effect = [
            {"id": "admin-id", "username": "admin", "role": "sysadmin"},
            {"value": "7"},  # current expire_warn_days
            {"value": "2"},  # current expire_warn_days_2
        ]
        resp = auth_client.put("/api/system/config", json={"expire_warn_days": 2})
        assert resp.status_code == 400
        assert "greater than" in resp.get_json()["error"]


def test_web_put_config_rejects_out_of_range_expire_warn_days(auth_client):
    with patch("web.db") as mock_db:
        mock_db.query_one.side_effect = [
            {"id": "admin-id", "username": "admin", "role": "sysadmin"},
            {"value": "7"},
            {"value": "2"},
        ]
        resp = auth_client.put("/api/system/config", json={"expire_warn_days": 0})
        assert resp.status_code == 400
        assert "between 1 and 30" in resp.get_json()["error"]


def test_web_put_config_rejects_out_of_range_expire_warn_days_2(auth_client):
    with patch("web.db") as mock_db:
        mock_db.query_one.side_effect = [
            {"id": "admin-id", "username": "admin", "role": "sysadmin"},
            {"value": "7"},
            {"value": "2"},
        ]
        resp = auth_client.put("/api/system/config", json={"expire_warn_days_2": 31})
        assert resp.status_code == 400
        assert "between 1 and 30" in resp.get_json()["error"]


def test_web_put_config_updates_multiple_settings(auth_client):
    with patch("web.db") as mock_db:
        mock_db.query_one.side_effect = [
            {"id": "admin-id", "username": "admin", "role": "sysadmin"},
            {"value": "7"},  # current expire_warn_days
            {"value": "2"},  # current expire_warn_days_2
        ]
        mock_db.query.return_value = [
            {"key": "scan_interval_hours", "value": "6"},
            {"key": "expire_warn_days", "value": "14"},
            {"key": "expire_warn_days_2", "value": "3"},
        ]
        resp = auth_client.put("/api/system/config", json={
            "scan_interval_hours": 6,
            "expire_warn_days": 14,
            "expire_warn_days_2": 3,
        })
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["scan_interval_hours"] == 6
        assert data["expire_warn_days"] == 14
        assert data["expire_warn_days_2"] == 3


# ---------------------------------------------------------------------------
# POST /api/access/deploy — deploy_key
# ---------------------------------------------------------------------------

def test_web_deploy_key_returns_201(auth_client):
    with patch("web.db") as mock_db, patch("web.actions.deploy_key") as mock_deploy:
        mock_db.query_one.return_value = {"id": ADMIN_ID, "username": "admin", "role": "sysadmin"}
        mock_deploy.return_value = {
            "fingerprint": "SHA256:test",
            "key_type": "ssh-ed25519",
            "unix_user": "alice",
            "hostname": "server-01",
            "expires_at": None,
        }
        resp = auth_client.post(
            "/api/access/deploy",
            json={
                "public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI test",
                "unix_user": "alice",
                "hostname": "server-01",
                "justification": "Accès maintenance",
            },
        )
        assert resp.status_code == 201
        data = resp.get_json()
        assert data["fingerprint"] == "SHA256:test"


def test_web_deploy_key_returns_401_unauthenticated(client):
    resp = client.post(
        "/api/access/deploy",
        json={
            "public_key": "ssh-ed25519 AAAA test",
            "unix_user": "alice",
            "hostname": "server-01",
            "justification": "Test",
        },
    )
    assert resp.status_code == 401


def test_web_deploy_key_returns_400_missing_fields(auth_client):
    with patch("web.db") as mock_db:
        mock_db.query_one.return_value = {"id": ADMIN_ID, "username": "admin", "role": "sysadmin"}
        resp = auth_client.post(
            "/api/access/deploy",
            json={"public_key": "ssh-ed25519 AAAA test"},
        )
        assert resp.status_code == 400


def test_web_deploy_key_hours_out_of_range_returns_400(auth_client):
    with patch("web.db") as mock_db:
        mock_db.query_one.return_value = {"id": ADMIN_ID, "username": "admin", "role": "sysadmin"}
        for bad_hours in [0, -1, 8761, 99999]:
            resp = auth_client.post(
                "/api/access/deploy",
                json={
                    "public_key": "ssh-ed25519 AAAA test",
                    "unix_user": "alice",
                    "hostname": "server-01",
                    "justification": "Test",
                    "hours": bad_hours,
                },
            )
            assert resp.status_code == 400, f"Expected 400 for hours={bad_hours}"


def test_web_deploy_key_hours_not_integer_returns_400(auth_client):
    with patch("web.db") as mock_db:
        mock_db.query_one.return_value = {"id": ADMIN_ID, "username": "admin", "role": "sysadmin"}
        resp = auth_client.post(
            "/api/access/deploy",
            json={
                "public_key": "ssh-ed25519 AAAA test",
                "unix_user": "alice",
                "hostname": "server-01",
                "justification": "Test",
                "hours": "abc",
            },
        )
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Sécurité — log injection : newlines sanitisées avant logging
# ---------------------------------------------------------------------------

def test_web_log_injection_newlines_sanitized_in_warning(auth_client):
    """Une ValueError avec \\n ne doit pas produire de fausses lignes de log."""
    with patch("web.db") as mock_db, patch("web.actions") as mock_actions, \
         patch("web.logging") as mock_logging:
        mock_db.query_one.return_value = _admin_row()
        mock_actions.revoke_key.side_effect = ValueError(
            "Key not found: SHA256:test\nWARNING:root:FAKE_ALERT"
        )
        resp = auth_client.post(
            f"/api/keys/revoke/{FINGERPRINT}",
            json={"reason": "x"},
        )
        assert resp.status_code == 404
        assert mock_logging.warning.called
        logged_msg = mock_logging.warning.call_args[0][1]
        assert "\n" not in logged_msg
        assert "\\n" in logged_msg


def test_web_log_injection_carriage_return_sanitized(auth_client):
    """Une ValueError avec \\r ne doit pas produire de fausses lignes de log."""
    with patch("web.db") as mock_db, patch("web.actions") as mock_actions, \
         patch("web.logging") as mock_logging:
        mock_db.query_one.return_value = _admin_row()
        mock_actions.revoke_key.side_effect = ValueError(
            "Key not found: SHA256:test\rINJECTED"
        )
        resp = auth_client.post(
            f"/api/keys/revoke/{FINGERPRINT}",
            json={"reason": "x"},
        )
        assert resp.status_code == 404
        logged_msg = mock_logging.warning.call_args[0][1]
        assert "\r" not in logged_msg
        assert "\\r" in logged_msg


# ---------------------------------------------------------------------------
# Sécurité — GET /api/admins ne doit pas exposer password_hash
# ---------------------------------------------------------------------------

def test_web_list_admins_does_not_expose_password_hash(auth_client):
    with patch("web.db") as mock_db:
        mock_db.query_one.return_value = _admin_row()
        mock_db.query.return_value = []
        resp = auth_client.get("/api/admins")
        assert resp.status_code == 200
        sql = mock_db.query.call_args[0][0]
        assert "password_hash" not in sql
        assert "SELECT *" not in sql


# ---------------------------------------------------------------------------
# lock-user / unlock-user
# ---------------------------------------------------------------------------

def test_web_lock_user_returns_200(auth_client):
    with patch("web.db") as mock_db, patch("web.actions") as mock_actions:
        mock_db.query_one.return_value = _admin_row()
        mock_actions.lock_user.return_value = {
            "unix_user": "alice",
            "hostname": "server-test-01",
            "status": "locked"
        }
        resp = auth_client.post("/api/access/lock-user", json={
            "unix_user": "alice",
            "hostname": "server-test-01"
        })
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "locked"


def test_web_lock_user_returns_401_unauthenticated(client):
    resp = client.post("/api/access/lock-user", json={
        "unix_user": "alice",
        "hostname": "server-test-01"
    })
    assert resp.status_code == 401


def test_web_lock_user_returns_400_missing_fields(auth_client):
    with patch("web.db") as mock_db:
        mock_db.query_one.return_value = _admin_row()
        resp = auth_client.post("/api/access/lock-user", json={"unix_user": "alice"})
        assert resp.status_code == 400


def test_web_unlock_user_returns_200(auth_client):
    with patch("web.db") as mock_db, patch("web.actions") as mock_actions:
        mock_db.query_one.return_value = _admin_row()
        mock_actions.unlock_user.return_value = {
            "unix_user": "alice",
            "hostname": "server-test-01",
            "status": "unlocked"
        }
        resp = auth_client.post("/api/access/unlock-user", json={
            "unix_user": "alice",
            "hostname": "server-test-01"
        })
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "unlocked"


def test_web_unlock_user_returns_401_unauthenticated(client):
    resp = client.post("/api/access/unlock-user", json={
        "unix_user": "alice",
        "hostname": "server-test-01"
    })
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# GET /api/access/deployed-users
# ---------------------------------------------------------------------------

def test_web_get_deployed_users_returns_200(auth_client):
    with patch("web.db") as mock_db:
        mock_db.query_one.return_value = _admin_row()
        mock_db.query.return_value = [
            {
                "unix_user": "alice",
                "hostname": "server-01",
                "ip_address": "192.168.1.10",
                "expires_at": datetime.now(tz=timezone.utc) + timedelta(hours=8),
                "fingerprint": "SHA256:abc123"
            },
            {
                "unix_user": "bob",
                "hostname": "server-02",
                "ip_address": "192.168.1.20",
                "expires_at": None,
                "fingerprint": "SHA256:def456"
            }
        ]
        resp = auth_client.get("/api/access/deployed-users")
        assert resp.status_code == 200
        data = resp.get_json()
        assert isinstance(data, list)
        assert len(data) == 2
        assert data[0]["unix_user"] == "alice"
        assert data[0]["hostname"] == "server-01"
        assert data[1]["expires_at"] is None


def test_web_get_deployed_users_returns_401_unauthenticated(client):
    resp = client.get("/api/access/deployed-users")
    assert resp.status_code == 401


def test_web_deployed_users_excludes_ssh_user(auth_client):
    with patch("web.db") as mock_db, patch("web.ssh.SSH_USER", "audit-collector"):
        mock_db.query_one.return_value = _admin_row()
        mock_db.query.return_value = []
        auth_client.get("/api/access/deployed-users")
        call_args = mock_db.query.call_args
        params = call_args[0][1]
        assert "audit-collector" in params


# ---------------------------------------------------------------------------
# RBAC tests
# ---------------------------------------------------------------------------

def test_web_rbac_operator_cannot_create_admin(client):
    with patch("web.db") as mock_db:
        mock_db.query_one.return_value = {"id": ADMIN_ID, "username": "op", "role": "operator"}
        with client.session_transaction() as sess:
            sess["admin_id"] = ADMIN_ID
        resp = client.post("/api/admins", json={"username": "new", "email": "x@x.com", "password": "P@ssw0rd!"})
        assert resp.status_code == 403


def test_web_rbac_viewer_cannot_disable_admin(client):
    with patch("web.db") as mock_db:
        mock_db.query_one.return_value = {"id": ADMIN_ID, "username": "viewer", "role": "viewer"}
        with client.session_transaction() as sess:
            sess["admin_id"] = ADMIN_ID
        resp = client.put("/api/admins/someuser/disable")
        assert resp.status_code == 403


def test_web_rbac_sysadmin_can_create_admin(auth_client):
    with patch("web.db") as mock_db, patch("web.actions") as mock_actions:
        mock_db.query_one.return_value = {"id": ADMIN_ID, "username": "admin", "role": "sysadmin"}
        mock_actions.add_admin.return_value = {"username": "new", "email": "x@x.com", "role": "operator"}
        resp = auth_client.post("/api/admins", json={"username": "new", "email": "x@x.com", "password": "P@ssw0rd!"})
        assert resp.status_code == 201


def test_web_rbac_operator_can_change_own_password(client):
    with patch("web.db") as mock_db, patch("web.actions") as mock_actions:
        mock_db.query_one.return_value = {"id": ADMIN_ID, "username": "op", "role": "operator"}
        with client.session_transaction() as sess:
            sess["admin_id"] = ADMIN_ID
        mock_actions.change_password.return_value = {"username": "op"}
        resp = client.put("/api/admins/op/password", json={"password": "NewP@ss1!"})
        assert resp.status_code == 200


def test_web_rbac_operator_cannot_change_other_password(client):
    with patch("web.db") as mock_db:
        mock_db.query_one.return_value = {"id": ADMIN_ID, "username": "op", "role": "operator"}
        with client.session_transaction() as sess:
            sess["admin_id"] = ADMIN_ID
        resp = client.put("/api/admins/other_user/password", json={"password": "NewP@ss1!"})
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# RBAC — viewer blocked on write routes
# ---------------------------------------------------------------------------

def test_web_rbac_viewer_cannot_add_server(client):
    with patch("web.db") as mock_db:
        mock_db.query_one.return_value = {"id": ADMIN_ID, "username": "viewer_user", "role": "viewer"}
        with client.session_transaction() as sess:
            sess["admin_id"] = ADMIN_ID
        resp = client.post("/api/servers", json={"hostname": "h", "ip": "1.2.3.4", "environment": "lab"})
        assert resp.status_code == 403


def test_web_rbac_viewer_cannot_revoke_key(client):
    with patch("web.db") as mock_db:
        mock_db.query_one.return_value = {"id": ADMIN_ID, "username": "viewer_user", "role": "viewer"}
        with client.session_transaction() as sess:
            sess["admin_id"] = ADMIN_ID
        resp = client.post("/api/keys/revoke/SHA256:abc123", json={})
        assert resp.status_code == 403


def test_web_rbac_viewer_cannot_deploy_key(client):
    with patch("web.db") as mock_db:
        mock_db.query_one.return_value = {"id": ADMIN_ID, "username": "viewer_user", "role": "viewer"}
        with client.session_transaction() as sess:
            sess["admin_id"] = ADMIN_ID
        resp = client.post("/api/access/deploy", json={})
        assert resp.status_code == 403


def test_web_rbac_viewer_cannot_update_config(client):
    with patch("web.db") as mock_db:
        mock_db.query_one.return_value = {"id": ADMIN_ID, "username": "viewer_user", "role": "viewer"}
        with client.session_transaction() as sess:
            sess["admin_id"] = ADMIN_ID
        resp = client.put("/api/system/config", json={"scan_interval_hours": 2})
        assert resp.status_code == 403


def test_web_rbac_operator_cannot_add_server(client):
    with patch("web.db") as mock_db:
        mock_db.query_one.return_value = {"id": ADMIN_ID, "username": "op_user", "role": "operator"}
        with client.session_transaction() as sess:
            sess["admin_id"] = ADMIN_ID
        resp = client.post("/api/servers", json={"hostname": "h", "ip": "1.2.3.4", "environment": "lab"})
        assert resp.status_code == 403


def test_web_rbac_operator_can_revoke_key(client):
    with patch("web.db") as mock_db, patch("web.actions") as mock_actions:
        mock_db.query_one.return_value = {"id": ADMIN_ID, "username": "op_user", "role": "operator"}
        mock_actions.revoke_key.return_value = None
        with client.session_transaction() as sess:
            sess["admin_id"] = ADMIN_ID
        resp = client.post("/api/keys/revoke/SHA256:validfp123456789012345678901234567890123", json={})
        assert resp.status_code == 200


def test_web_rbac_operator_cannot_update_config(client):
    with patch("web.db") as mock_db:
        mock_db.query_one.return_value = {"id": ADMIN_ID, "username": "op_user", "role": "operator"}
        with client.session_transaction() as sess:
            sess["admin_id"] = ADMIN_ID
        resp = client.put("/api/system/config", json={"scan_interval_hours": 2})
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# PUT /api/admins/<username>/alerts — toggle receive_alerts
# ---------------------------------------------------------------------------

def test_web_toggle_alerts_enable_returns_200(auth_client):
    with patch("web.db") as mock_db, patch("web.actions") as mock_actions:
        mock_db.query_one.return_value = _admin_row()
        mock_actions.toggle_alerts.return_value = {"username": "alice", "receive_alerts": True}
        resp = auth_client.put("/api/admins/alice/alerts", json={"receive_alerts": True})
    assert resp.status_code == 200
    assert resp.get_json()["receive_alerts"] is True


def test_web_toggle_alerts_disable_returns_200(auth_client):
    with patch("web.db") as mock_db, patch("web.actions") as mock_actions:
        mock_db.query_one.return_value = _admin_row()
        mock_actions.toggle_alerts.return_value = {"username": "alice", "receive_alerts": False}
        resp = auth_client.put("/api/admins/alice/alerts", json={"receive_alerts": False})
    assert resp.status_code == 200
    assert resp.get_json()["receive_alerts"] is False


def test_web_toggle_alerts_missing_field_returns_400(auth_client):
    with patch("web.db") as mock_db:
        mock_db.query_one.return_value = _admin_row()
        resp = auth_client.put("/api/admins/alice/alerts", json={})
    assert resp.status_code == 400


def test_web_toggle_alerts_non_bool_returns_400(auth_client):
    with patch("web.db") as mock_db:
        mock_db.query_one.return_value = _admin_row()
        resp = auth_client.put("/api/admins/alice/alerts", json={"receive_alerts": "yes"})
    assert resp.status_code == 400


def test_web_toggle_alerts_unknown_admin_returns_404(auth_client):
    with patch("web.db") as mock_db, patch("web.actions") as mock_actions:
        mock_db.query_one.return_value = _admin_row()
        mock_actions.toggle_alerts.side_effect = ValueError("Active admin not found")
        resp = auth_client.put("/api/admins/ghost/alerts", json={"receive_alerts": True})
    assert resp.status_code == 404


def test_web_toggle_alerts_unauthenticated_returns_401(client):
    resp = client.put("/api/admins/alice/alerts", json={"receive_alerts": True})
    assert resp.status_code == 401


def test_web_toggle_alerts_operator_returns_403(client):
    with patch("web.db") as mock_db:
        mock_db.query_one.return_value = {"id": ADMIN_ID, "username": "op_user", "role": "operator"}
        with client.session_transaction() as sess:
            sess["admin_id"] = ADMIN_ID
        resp = client.put("/api/admins/alice/alerts", json={"receive_alerts": True})
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# POST /api/system/test-smtp
# ---------------------------------------------------------------------------

def test_web_test_smtp_returns_200_when_sent(auth_client):
    with patch("web.db") as mock_db, patch("web.alerts") as mock_alerts:
        mock_db.query_one.side_effect = [_admin_row(), {"email": "admin@example.com"}]
        mock_alerts.send_test_email.return_value = None
        resp = auth_client.post("/api/system/test-smtp")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "sent"
    assert data["to"] == "admin@example.com"


def test_web_test_smtp_returns_400_when_no_email(auth_client):
    with patch("web.db") as mock_db:
        mock_db.query_one.side_effect = [_admin_row(), {"email": None}]
        resp = auth_client.post("/api/system/test-smtp")
    assert resp.status_code == 400


def test_web_test_smtp_returns_502_on_msmtp_error(auth_client):
    with patch("web.db") as mock_db, patch("web.alerts") as mock_alerts:
        mock_db.query_one.side_effect = [_admin_row(), {"email": "admin@example.com"}]
        mock_alerts.send_test_email.side_effect = RuntimeError("connection refused")
        resp = auth_client.post("/api/system/test-smtp")
    assert resp.status_code == 502
    assert "connection refused" in resp.get_json()["error"]


def test_web_test_smtp_returns_500_when_msmtp_not_found(auth_client):
    with patch("web.db") as mock_db, patch("web.alerts") as mock_alerts:
        mock_db.query_one.side_effect = [_admin_row(), {"email": "admin@example.com"}]
        mock_alerts.send_test_email.side_effect = FileNotFoundError("msmtp not found")
        resp = auth_client.post("/api/system/test-smtp")
    assert resp.status_code == 500


def test_web_test_smtp_returns_401_when_unauthenticated(client):
    resp = client.post("/api/system/test-smtp")
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Rate limiting — /api/auth/login brute-force protection
# ---------------------------------------------------------------------------

def _login_settings_side_effect(query, params=None):
    """Mock db.query_one for settings table during login."""
    if params and "login_max_attempts" in str(params):
        return {"value": "3"}
    if params and "login_ban_seconds" in str(params):
        return {"value": "300"}
    return None


def test_web_login_success_returns_200(client):
    """Successful login returns 200 and resets attempt counter."""
    web._login_attempts.clear()
    with patch("web.db") as mock_db:
        mock_db.query_one.side_effect = [
            {"value": "3"},    # login_max_attempts (check_rate_limit)
            {"value": "300"},  # login_ban_seconds  (check_rate_limit)
            {"id": ADMIN_ID, "username": "admin", "password_hash": "pbkdf2:sha256:hash"},
        ]
        with patch("web.check_password_hash", return_value=True):
            resp = client.post(
                "/api/auth/login",
                json={"username": "admin", "password": "correct"},
            )
    assert resp.status_code == 200
    assert "127.0.0.1" not in web._login_attempts


def test_web_login_failure_returns_401(client):
    """Wrong password returns 401 and records failure."""
    web._login_attempts.clear()
    with patch("web.db") as mock_db:
        mock_db.query_one.side_effect = [
            {"value": "10"},   # login_max_attempts (check_rate_limit)
            {"value": "300"},  # login_ban_seconds  (check_rate_limit)
            {"id": ADMIN_ID, "username": "admin", "password_hash": "hash"},
            {"value": "10"},   # login_max_attempts (_record_failure)
            {"value": "300"},  # login_ban_seconds  (_record_failure)
        ]
        with patch("web.check_password_hash", return_value=False):
            resp = client.post(
                "/api/auth/login",
                json={"username": "admin", "password": "wrong"},
            )
    assert resp.status_code == 401


def test_web_login_missing_credentials_returns_400(client):
    """Missing username or password returns 400 before rate-limit check."""
    web._login_attempts.clear()
    resp = client.post("/api/auth/login", json={"username": "admin"})
    assert resp.status_code == 400


def test_web_login_banned_ip_returns_429(client):
    """IP with active ban returns 429."""
    web._login_attempts.clear()
    future = datetime.now(timezone.utc).timestamp() + 300
    web._login_attempts["127.0.0.1"] = {"count": 5, "banned_until": future}
    with patch("web.db") as mock_db:
        mock_db.query_one.side_effect = [
            {"value": "3"},    # login_max_attempts (check_rate_limit)
            {"value": "300"},  # login_ban_seconds  (check_rate_limit)
        ]
        resp = client.post(
            "/api/auth/login",
            json={"username": "admin", "password": "any"},
        )
    web._login_attempts.clear()
    assert resp.status_code == 429


def test_web_login_ban_lifted_after_timeout(client):
    """Expired ban entry is cleared and request proceeds."""
    web._login_attempts.clear()
    past = datetime.now(timezone.utc).timestamp() - 1
    web._login_attempts["127.0.0.1"] = {"count": 5, "banned_until": past}
    with patch("web.db") as mock_db:
        mock_db.query_one.side_effect = [
            {"value": "3"},    # login_max_attempts (check_rate_limit)
            {"value": "300"},  # login_ban_seconds  (check_rate_limit)
            {"id": ADMIN_ID, "username": "admin", "password_hash": "pbkdf2:sha256:hash"},
        ]
        with patch("web.check_password_hash", return_value=True):
            resp = client.post(
                "/api/auth/login",
                json={"username": "admin", "password": "correct"},
            )
    web._login_attempts.clear()
    assert resp.status_code == 200


def test_web_login_max_attempts_triggers_ban(client):
    """Reaching max_attempts on the last failure triggers ban."""
    web._login_attempts.clear()
    # 2 failures already recorded, max_attempts=3 → 3rd failure triggers ban
    web._login_attempts["127.0.0.1"] = {"count": 2, "banned_until": 0}
    with patch("web.db") as mock_db:
        # check_rate_limit: max_attempts, ban_seconds
        # _record_failure:  max_attempts, ban_seconds
        mock_db.query_one.side_effect = [
            {"value": "3"},    # check_rate_limit: login_max_attempts
            {"value": "300"},  # check_rate_limit: login_ban_seconds
            {"id": ADMIN_ID, "username": "admin", "password_hash": "hash"},
            {"value": "3"},    # _record_failure:  login_max_attempts
            {"value": "300"},  # _record_failure:  login_ban_seconds
        ]
        mock_db.execute.return_value = None
        with patch("web.check_password_hash", return_value=False):
            resp = client.post(
                "/api/auth/login",
                json={"username": "admin", "password": "wrong"},
            )
    entry = web._login_attempts.get("127.0.0.1")
    web._login_attempts.clear()
    assert resp.status_code == 401
    assert entry is not None
    assert entry["banned_until"] > 0


def test_web_config_update_login_max_attempts(auth_client):
    """PUT /api/system/config accepts login_max_attempts."""
    with patch("web.db") as mock_db:
        mock_db.query_one.side_effect = [
            _admin_row(),
            {"value": "7"},   # current expire_warn_days
            {"value": "2"},   # current expire_warn_days_2
        ]
        mock_db.query.return_value = [
            {"key": "scan_interval_hours", "value": "4"},
            {"key": "expire_warn_days", "value": "7"},
            {"key": "expire_warn_days_2", "value": "2"},
            {"key": "login_max_attempts", "value": "5"},
            {"key": "login_ban_seconds", "value": "300"},
        ]
        resp = auth_client.put("/api/system/config", json={"login_max_attempts": 5})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["login_max_attempts"] == 5


def test_web_config_update_login_ban_seconds(auth_client):
    """PUT /api/system/config accepts login_ban_seconds."""
    with patch("web.db") as mock_db:
        mock_db.query_one.side_effect = [
            _admin_row(),
            {"value": "7"},
            {"value": "2"},
        ]
        mock_db.query.return_value = [
            {"key": "scan_interval_hours", "value": "4"},
            {"key": "expire_warn_days", "value": "7"},
            {"key": "expire_warn_days_2", "value": "2"},
            {"key": "login_max_attempts", "value": "10"},
            {"key": "login_ban_seconds", "value": "600"},
        ]
        resp = auth_client.put("/api/system/config", json={"login_ban_seconds": 600})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["login_ban_seconds"] == 600


def test_web_config_login_max_attempts_out_of_range(auth_client):
    """PUT /api/system/config rejects login_max_attempts > 100."""
    with patch("web.db") as mock_db:
        mock_db.query_one.return_value = _admin_row()
        resp = auth_client.put("/api/system/config", json={"login_max_attempts": 200})
    assert resp.status_code == 400


def test_web_config_login_ban_seconds_too_low(auth_client):
    """PUT /api/system/config rejects login_ban_seconds < 30."""
    with patch("web.db") as mock_db:
        mock_db.query_one.return_value = _admin_row()
        resp = auth_client.put("/api/system/config", json={"login_ban_seconds": 10})
    assert resp.status_code == 400
