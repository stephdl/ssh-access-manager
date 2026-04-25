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
    with client.session_transaction() as sess:
        sess["admin_id"] = ADMIN_ID
    return client


# ---------------------------------------------------------------------------
# Authentification
# ---------------------------------------------------------------------------

def test_web_no_auth_returns_401(client):
    resp = client.get("/api/keys")
    assert resp.status_code == 401


def test_web_authenticated_returns_200(auth_client):
    with patch("web.db") as mock_db:
        mock_db.query.return_value = []
        resp = auth_client.get("/api/keys")
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# GET /api/keys — retourne 200 + liste JSON
# ---------------------------------------------------------------------------

def test_web_get_keys_returns_200_and_list(auth_client):
    key_row = {
        "id": KEY_ID, "fingerprint": FINGERPRINT,
        "key_type": "ssh-ed25519", "is_compliant": True,
    }
    with patch("web.db") as mock_db:
        mock_db.query.return_value = [key_row]
        resp = auth_client.get("/api/keys")
        assert resp.status_code == 200
        data = resp.get_json()
        assert isinstance(data, list)
        assert data[0]["fingerprint"] == FINGERPRINT


def test_web_get_keys_with_status_filter(auth_client):
    with patch("web.db") as mock_db:
        mock_db.query.return_value = []
        resp = auth_client.get("/api/keys?status=ACTIVE")
        assert resp.status_code == 200
        sql = mock_db.query.call_args[0][0]
        assert "status" in sql


# ---------------------------------------------------------------------------
# POST /api/keys/<fp>/revoke — 200 si authentifié, 401 si non authentifié
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
        mock_db.query.return_value = [{"hostname": "srv-01"}]
        resp = auth_client.get("/api/servers")
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# POST /api/servers
# ---------------------------------------------------------------------------

def test_web_add_server_returns_201(auth_client):
    with patch("web.db") as mock_db, patch("web.actions") as mock_actions:
        mock_actions.add_server.return_value = {"id": SERVER_ID}
        resp = auth_client.post(
            "/api/servers",
            json={"hostname": "new-srv", "ip": "10.0.0.1", "environment": "lab"},
        )
        assert resp.status_code == 201


# ---------------------------------------------------------------------------
# GET /api/audit
# ---------------------------------------------------------------------------

def test_web_get_audit_returns_200(auth_client):
    with patch("web.db") as mock_db:
        mock_db.query.return_value = []
        resp = auth_client.get("/api/audit")
        assert resp.status_code == 200


def test_web_get_audit_filters_by_action(auth_client):
    with patch("web.db") as mock_db:
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
            _admin_row(),   # require_auth
            {"n": 3},       # servers_active
            {"n": 1},       # keys_pending
            {"n": 10},      # keys_active
            None,           # last_scan
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
