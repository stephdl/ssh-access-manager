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
    return {"id": ADMIN_ID, "username": "admin"}


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
        mock_actions.revoke_key.assert_called_once_with(FINGERPRINT, ADMIN_ID, "test")


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
# GET/PUT /api/system/config
# ---------------------------------------------------------------------------

def test_web_get_config_returns_settings(auth_client):
    with patch("web.db") as mock_db:
        mock_db.query_one.return_value = {"id": "admin-id", "username": "admin"}
        mock_db.query.return_value = [{"key": "scan_interval_hours", "value": "4"}]
        resp = auth_client.get("/api/system/config")
        assert resp.status_code == 200
        assert resp.get_json()["scan_interval_hours"] == "4"


def test_web_put_config_updates_interval(auth_client):
    with patch("web.db") as mock_db:
        mock_db.query_one.return_value = {"id": "admin-id", "username": "admin"}
        resp = auth_client.put("/api/system/config", json={"scan_interval_hours": 6})
        assert resp.status_code == 200
        assert resp.get_json()["scan_interval_hours"] == 6


def test_web_put_config_rejects_out_of_range(auth_client):
    with patch("web.db") as mock_db:
        mock_db.query_one.return_value = {"id": "admin-id", "username": "admin"}
        resp = auth_client.put("/api/system/config", json={"scan_interval_hours": 99})
        assert resp.status_code == 400


def test_web_put_config_rejects_missing_field(auth_client):
    with patch("web.db") as mock_db:
        mock_db.query_one.return_value = {"id": "admin-id", "username": "admin"}
        resp = auth_client.put("/api/system/config", json={})
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# POST /api/access/deploy — deploy_key
# ---------------------------------------------------------------------------

def test_web_deploy_key_returns_201(auth_client):
    with patch("web.db") as mock_db, patch("web.actions.deploy_key") as mock_deploy:
        mock_db.query_one.return_value = {"id": ADMIN_ID, "username": "admin"}
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
        mock_db.query_one.return_value = {"id": ADMIN_ID, "username": "admin"}
        resp = auth_client.post(
            "/api/access/deploy",
            json={"public_key": "ssh-ed25519 AAAA test"},
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
