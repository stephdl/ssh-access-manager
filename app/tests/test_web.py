import base64
import os
import sys
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import ssh
import web
from actions import ForbiddenError, NotFoundError, UserError

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
# Authentication
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
# GET /api/keys — returns 200 + JSON list
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
# GET /api/keys — owner field present in response
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
# POST /api/keys/validate/<fp> — 200 if authenticated, 401 otherwise, scoped
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
# POST /api/keys/revoke/<fp> — malformed fingerprint rejected with 400
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
# POST /api/keys/revoke/<fp> — 200 if authenticated, 401 if not authenticated
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
        mock_actions.revoke_key.side_effect = NotFoundError("Key not found")
        resp = auth_client.post(
            f"/api/keys/revoke/{FINGERPRINT}",
            json={"reason": "x"},
        )
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# POST /api/access/grant — 201 with expires_at computed
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
# POST /api/keys/set-expiry — datetime-local format (without seconds)
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


def test_web_set_expiry_duration_hours_not_integer_returns_400(auth_client):
    """duration_hours type validation — string should return 400."""
    with patch("web.db") as mock_db:
        mock_db.query_one.return_value = _admin_row()
        resp = auth_client.post(
            f"/api/keys/set-expiry/{FINGERPRINT}",
            json={"duration_hours": "not-a-number"},
        )
        assert resp.status_code == 400
        assert "must be an integer" in resp.json["error"] or "error" in resp.json


def test_web_set_expiry_scoped_to_unix_user_and_hostname(auth_client):
    """set-expiry with unix_user and hostname passes them to actions."""
    with patch("web.db") as mock_db, patch("web.actions") as mock_actions:
        mock_db.query_one.return_value = _admin_row()
        resp = auth_client.post(
            f"/api/keys/set-expiry/{FINGERPRINT}",
            json={"hours": 24, "unix_user": "alice", "hostname": "server-01"},
        )
        assert resp.status_code == 200
        mock_actions.set_key_expiry.assert_called_once()
        call_args = mock_actions.set_key_expiry.call_args
        assert call_args[0][0] == FINGERPRINT
        assert call_args[1]["unix_user"] == "alice"
        assert call_args[1]["hostname"] == "server-01"


def test_web_remove_expiry_scoped_to_unix_user_and_hostname(auth_client):
    """remove-expiry with unix_user and hostname passes them to actions."""
    with patch("web.db") as mock_db, patch("web.actions") as mock_actions:
        mock_db.query_one.return_value = _admin_row()
        resp = auth_client.post(
            f"/api/keys/remove-expiry/{FINGERPRINT}",
            json={"unix_user": "bob", "hostname": "server-02"},
        )
        assert resp.status_code == 200
        mock_actions.remove_key_expiry.assert_called_once()
        call_args = mock_actions.remove_key_expiry.call_args
        assert call_args[0][0] == FINGERPRINT
        assert call_args[1]["unix_user"] == "bob"
        assert call_args[1]["hostname"] == "server-02"


def test_web_set_expiry_without_scoping_params(auth_client):
    """set-expiry without unix_user/hostname calls actions with None."""
    with patch("web.db") as mock_db, patch("web.actions") as mock_actions:
        mock_db.query_one.return_value = _admin_row()
        resp = auth_client.post(
            f"/api/keys/set-expiry/{FINGERPRINT}",
            json={"hours": 48},
        )
        assert resp.status_code == 200
        mock_actions.set_key_expiry.assert_called_once()
        call_args = mock_actions.set_key_expiry.call_args
        assert call_args[1]["unix_user"] is None
        assert call_args[1]["hostname"] is None


def test_web_remove_expiry_without_scoping_params(auth_client):
    """remove-expiry without unix_user/hostname calls actions with None."""
    with patch("web.db") as mock_db, patch("web.actions") as mock_actions:
        mock_db.query_one.return_value = _admin_row()
        resp = auth_client.post(
            f"/api/keys/remove-expiry/{FINGERPRINT}",
            json={},
        )
        assert resp.status_code == 200
        mock_actions.remove_key_expiry.assert_called_once()
        call_args = mock_actions.remove_key_expiry.call_args
        assert call_args[1]["unix_user"] is None
        assert call_args[1]["hostname"] is None


# ---------------------------------------------------------------------------
# GET /api/servers
# ---------------------------------------------------------------------------

def test_web_get_servers_returns_200(auth_client):
    with patch("web.db") as mock_db:
        mock_db.query_one.return_value = _admin_row()
        mock_db.query.return_value = [{"hostname": "srv-01", "last_scan_action": "SCAN_COMPLETED"}]
        resp = auth_client.get("/api/servers")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data[0]["last_scan_ok"] is True
        assert "last_scan_action" not in data[0]


def test_web_get_servers_last_scan_ok_false(auth_client):
    """GET /api/servers includes last_scan_ok=False when last_scan_action is SCAN_FAILED."""
    with patch("web.db") as mock_db:
        mock_db.query_one.return_value = _admin_row()
        mock_db.query.return_value = [{"hostname": "srv-01", "last_scan_action": "SCAN_FAILED"}]
        resp = auth_client.get("/api/servers")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data[0]["last_scan_ok"] is False


def test_web_get_servers_last_scan_ok_none(auth_client):
    """GET /api/servers includes last_scan_ok=None when no scan has run (last_scan_action absent)."""
    with patch("web.db") as mock_db:
        mock_db.query_one.return_value = _admin_row()
        mock_db.query.return_value = [{"hostname": "srv-01", "last_scan_action": None}]
        resp = auth_client.get("/api/servers")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data[0]["last_scan_ok"] is None


def test_web_get_servers_propagates_has_anomalies(auth_client):
    """GET /api/servers propagates the SQL-computed has_anomalies field."""
    with patch("web.db") as mock_db:
        mock_db.query_one.return_value = _admin_row()
        mock_db.query.return_value = [
            {"hostname": "srv-01", "last_scan_action": "SCAN_COMPLETED", "has_anomalies": True},
            {"hostname": "srv-02", "last_scan_action": "SCAN_COMPLETED", "has_anomalies": False},
        ]
        resp = auth_client.get("/api/servers")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data[0]["has_anomalies"] is True
        assert data[1]["has_anomalies"] is False


def test_web_get_servers_has_anomalies_query_excludes_audit_log():
    """Regression guard for #396 — has_anomalies must NOT read audit_log.

    audit_log is immutable; reading ANOMALY_DETECTED from it kept the server
    flagged for 30 days even after pending keys had been validated. The query
    must derive has_anomalies from key_authorizations only.
    """
    import inspect
    import web
    source = inspect.getsource(web.list_servers)
    # The has_anomalies subquery itself must not reference ANOMALY_DETECTED.
    # (The LATERAL join below references SCAN_COMPLETED/SCAN_FAILED — those
    # are unrelated and stay on audit_log.)
    assert "ANOMALY_DETECTED" not in source, (
        "has_anomalies must not depend on audit_log.ANOMALY_DETECTED — see #396"
    )
    # Must derive out-of-system revocations from key_authorizations.
    assert "revoked_automatically = TRUE" in source
    assert "revoked_by IS NULL" in source


# ---------------------------------------------------------------------------
# GET /api/servers/<hostname>
# ---------------------------------------------------------------------------

def test_web_get_server_last_scan_ok_true(auth_client):
    """GET /api/servers/<hostname> includes last_scan_ok=True when last audit is SCAN_COMPLETED."""
    with patch("web.db") as mock_db:
        mock_db.query_one.side_effect = [
            _admin_row(),
            {"id": SERVER_ID, "hostname": "srv-01", "ip_address": "10.0.0.1",
             "ssh_port": 22, "is_active": True, "environment": "lab",
             "os_family": None, "os_version": None, "added_at": None},
            {"action": "SCAN_COMPLETED", "scan_error": None},
        ]
        resp = auth_client.get("/api/servers/srv-01")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["last_scan_ok"] is True
        assert data["last_scan_error"] is None


def test_web_get_server_last_scan_ok_false(auth_client):
    """GET /api/servers/<hostname> includes last_scan_ok=False and error when last audit is SCAN_FAILED."""
    with patch("web.db") as mock_db:
        mock_db.query_one.side_effect = [
            _admin_row(),
            {"id": SERVER_ID, "hostname": "srv-01", "ip_address": "10.0.0.1",
             "ssh_port": 22, "is_active": True, "environment": "lab",
             "os_family": None, "os_version": None, "added_at": None},
            {"action": "SCAN_FAILED", "scan_error": "Connection timed out"},
        ]
        resp = auth_client.get("/api/servers/srv-01")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["last_scan_ok"] is False
        assert data["last_scan_error"] == "Connection timed out"


def test_web_get_server_no_scan_yet(auth_client):
    """GET /api/servers/<hostname> includes last_scan_ok=None when no scan has run yet."""
    with patch("web.db") as mock_db:
        mock_db.query_one.side_effect = [
            _admin_row(),
            {"id": SERVER_ID, "hostname": "srv-01", "ip_address": "10.0.0.1",
             "ssh_port": 22, "is_active": True, "environment": "lab",
             "os_family": None, "os_version": None, "added_at": None},
            None,
        ]
        resp = auth_client.get("/api/servers/srv-01")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["last_scan_ok"] is None
        assert data["last_scan_error"] is None


# ---------------------------------------------------------------------------
# POST /api/servers
# ---------------------------------------------------------------------------

def test_web_add_server_returns_201(auth_client):
    with patch("web.db") as mock_db, patch("web.actions") as mock_actions:
        mock_db.query_one.return_value = _admin_row()
        mock_actions.add_server.return_value = {"id": SERVER_ID}
        resp = auth_client.post(
            "/api/servers",
            json={"hostname": "new-srv", "ip": "10.0.0.1", "environment": "lab",
                  "ssh_user": "root", "ssh_password": "Str0ng#Pass!"},
        )
        assert resp.status_code == 201


def test_web_add_server_no_password_succeeds(auth_client):
    """ssh_password is optional — empty password uses collector key auth."""
    with patch("web.db") as mock_db, patch("web.actions") as mock_actions:
        mock_db.query_one.return_value = _admin_row()
        mock_actions.add_server.return_value = {"id": SERVER_ID}
        resp = auth_client.post(
            "/api/servers",
            json={"hostname": "new-srv", "ip": "10.0.0.1", "ssh_user": "root"},
        )
        assert resp.status_code == 201
        assert mock_actions.add_server.call_args[0][3] == ""


def test_web_add_server_ssh_failure_returns_422(auth_client):
    with patch("web.db") as mock_db, patch("web.actions") as mock_actions:
        mock_db.query_one.return_value = _admin_row()
        mock_actions.add_server.side_effect = ssh.SSHAuthError("Authentication failed")
        resp = auth_client.post(
            "/api/servers",
            json={"hostname": "new-srv", "ip": "10.0.0.1",
                  "ssh_user": "root", "ssh_password": "wrong"},
        )
        assert resp.status_code == 422


def test_web_add_server_ssh_port_refused_returns_422(auth_client):
    """POST /api/servers returns 422 with SSH_PORT_REFUSED when port is refused."""
    with patch("web.db") as mock_db, patch("web.actions") as mock_actions:
        mock_db.query_one.return_value = _admin_row()
        mock_actions.add_server.side_effect = ssh.SSHPortRefusedError(
            "SSH port 22 refused — check that SSH is running on that port"
        )
        resp = auth_client.post(
            "/api/servers",
            json={"hostname": "new-srv", "ip": "10.0.0.1",
                  "ssh_user": "root", "ssh_password": "pass"},
        )
        assert resp.status_code == 422
        data = resp.get_json()
        assert data["error_code"] == "SSH_PORT_REFUSED"


def test_web_add_server_env_optional(auth_client):
    """environment field is optional — server can be created without it."""
    with patch("web.db") as mock_db, patch("web.actions") as mock_actions:
        mock_db.query_one.return_value = _admin_row()
        mock_actions.add_server.return_value = {"id": SERVER_ID}
        resp = auth_client.post(
            "/api/servers",
            json={"hostname": "new-srv", "ip": "10.0.0.1",
                  "ssh_user": "root", "ssh_password": "Str0ng#Pass!"},
        )
        assert resp.status_code == 201
        call_args = mock_actions.add_server.call_args
        assert call_args[0][4] is None


def test_web_add_server_ssh_port_not_integer(auth_client):
    """ssh_port type validation — string should return 400."""
    with patch("web.db") as mock_db:
        mock_db.query_one.return_value = _admin_row()
        resp = auth_client.post(
            "/api/servers",
            json={"hostname": "new-srv", "ip": "10.0.0.1",
                  "ssh_user": "root", "ssh_password": "Str0ng#Pass!", "ssh_port": "not-a-number"},
        )
        assert resp.status_code == 400
        assert "ssh_port must be an integer" in resp.json["error"]


# ---------------------------------------------------------------------------
# PUT /api/servers/<hostname> — update server
# ---------------------------------------------------------------------------

def test_web_update_server_authenticated_returns_200(auth_client):
    with patch("web.db") as mock_db, patch("web.actions") as mock_actions:
        mock_db.query_one.return_value = _admin_row()
        mock_actions.update_server.return_value = {"hostname": "server-test-01"}
        resp = auth_client.put(
            "/api/servers/server-test-01",
            json={"ip": "10.0.0.2", "environment": "production", "os_family": "debian"},
        )
        assert resp.status_code == 200
        mock_actions.update_server.assert_called_once_with(
            "server-test-01", "10.0.0.2", "production", "debian", 22, ADMIN_ID, 2,
            new_hostname=None,
        )


def test_web_update_server_blank_environment_is_normalized_to_none(auth_client):
    with patch("web.db") as mock_db, patch("web.actions") as mock_actions:
        mock_db.query_one.return_value = _admin_row()
        mock_actions.update_server.return_value = {"hostname": "server-test-01"}
        resp = auth_client.put(
            "/api/servers/server-test-01",
            json={"ip": "10.0.0.2", "environment": "", "os_family": None},
        )
        assert resp.status_code == 200
        mock_actions.update_server.assert_called_once_with(
            "server-test-01", "10.0.0.2", None, None, 22, ADMIN_ID, 2,
            new_hostname=None,
        )


def test_web_update_server_rename_forwards_new_hostname(auth_client):
    with patch("web.db") as mock_db, patch("web.actions") as mock_actions:
        mock_db.query_one.return_value = _admin_row()
        mock_actions.update_server.return_value = {"hostname": "renamed"}
        resp = auth_client.put(
            "/api/servers/server-test-01",
            json={"hostname": "renamed", "ip": "10.0.0.2", "environment": "lab"},
        )
        assert resp.status_code == 200
        assert resp.get_json()["hostname"] == "renamed"
        mock_actions.update_server.assert_called_once_with(
            "server-test-01", "10.0.0.2", "lab", None, 22, ADMIN_ID, 2,
            new_hostname="renamed",
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
        mock_actions.update_server.side_effect = NotFoundError("Server not found")
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
        mock_actions.enable_server.side_effect = NotFoundError("not found")
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
        mock_actions.delete_server.side_effect = NotFoundError("not found")
        resp = auth_client.delete("/api/servers/ghost")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# POST /api/servers/<hostname>/provision
# ---------------------------------------------------------------------------

def test_web_provision_server_success(auth_client):
    with patch("web.db") as mock_db, patch("web.actions") as mock_actions:
        mock_db.query_one.return_value = _admin_row()
        resp = auth_client.post(
            "/api/servers/server-test-01/provision",
            json={"ssh_user": "root", "ssh_password": "secret", "ssh_port": 22},
        )
        assert resp.status_code == 200
        assert resp.json["message"] == "Server provisioned successfully"
        mock_actions.provision_server.assert_called_once_with(
            "server-test-01", "root", "secret", 22, ADMIN_ID
        )


def test_web_provision_server_no_password_uses_key_auth(auth_client):
    """ssh_password is optional — empty password triggers collector key auth path."""
    with patch("web.db") as mock_db, patch("web.actions") as mock_actions:
        mock_db.query_one.return_value = _admin_row()
        resp = auth_client.post(
            "/api/servers/server-test-01/provision",
            json={"ssh_user": "root"},
        )
        assert resp.status_code == 200
        assert mock_actions.provision_server.call_args[0][2] == ""


def test_web_provision_server_invalid_port(auth_client):
    with patch("web.db") as mock_db:
        mock_db.query_one.return_value = _admin_row()
        resp = auth_client.post(
            "/api/servers/server-test-01/provision",
            json={"ssh_user": "root", "ssh_password": "secret", "ssh_port": 99999},
        )
        assert resp.status_code == 400
        assert "ssh_port must be between 1 and 65535" in resp.json["error"]


def test_web_provision_server_ssh_port_not_integer(auth_client):
    """ssh_port type validation — string should return 400."""
    with patch("web.db") as mock_db:
        mock_db.query_one.return_value = _admin_row()
        resp = auth_client.post(
            "/api/servers/server-test-01/provision",
            json={"ssh_user": "root", "ssh_password": "secret", "ssh_port": "abc"},
        )
        assert resp.status_code == 400
        assert "ssh_port must be an integer" in resp.json["error"]


def test_web_provision_server_not_found(auth_client):
    with patch("web.db") as mock_db, patch("web.actions") as mock_actions:
        mock_db.query_one.return_value = _admin_row()
        mock_actions.provision_server.side_effect = NotFoundError("Server not found")
        resp = auth_client.post(
            "/api/servers/ghost/provision",
            json={"ssh_user": "root", "ssh_password": "secret", "ssh_port": 22},
        )
        assert resp.status_code == 404


def test_web_provision_server_ssh_error(auth_client):
    with patch("web.db") as mock_db, patch("web.actions") as mock_actions:
        mock_db.query_one.return_value = _admin_row()
        mock_actions.provision_server.side_effect = ssh.SSHError("Connection failed")
        resp = auth_client.post(
            "/api/servers/server-test-01/provision",
            json={"ssh_user": "root", "ssh_password": "secret", "ssh_port": 22},
        )
        assert resp.status_code == 422


def test_web_provision_server_viewer_forbidden(client):
    """Viewers cannot provision servers."""
    viewer_id = str(uuid.uuid4())
    with client.session_transaction() as sess:
        sess["admin_id"] = viewer_id
        sess["admin_username"] = "viewer"
    with patch("web.db") as mock_db:
        mock_db.query_one.return_value = {"id": viewer_id, "username": "viewer", "role": "viewer"}
        resp = client.post(
            "/api/servers/server-test-01/provision",
            json={"ssh_user": "root", "ssh_password": "secret", "ssh_port": 22},
        )
        assert resp.status_code == 403


def test_web_provision_server_password_not_logged(auth_client):
    """Password must never appear in audit_log or exceptions."""
    with patch("web.db") as mock_db, patch("web.actions") as mock_actions:
        mock_db.query_one.return_value = _admin_row()
        secret_password = "SuperSecret123!"

        # Capture all db.execute calls via actions.provision_server
        def check_no_password(*args, **kwargs):
            sql = args[0] if args else ""
            params = args[1] if len(args) > 1 else ()
            for param in params:
                if isinstance(param, str) and secret_password in param:
                    raise AssertionError(f"Password found in audit_log: {param}")

        mock_actions.provision_server.side_effect = check_no_password

        resp = auth_client.post(
            "/api/servers/server-test-01/provision",
            json={"ssh_user": "root", "ssh_password": secret_password, "ssh_port": 22},
        )
        # The mock will raise if password is logged
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# GET /api/audit
# ---------------------------------------------------------------------------

def test_web_get_audit_returns_new_shape(auth_client):
    """GET /api/audit always returns {rows, total, facets}."""
    with patch("web.actions.list_audit_logs") as mock_list:
        mock_list.return_value = {
            "rows": [],
            "total": 0,
            "facets": {"servers": [], "actions": []},
        }
        with patch("web.db.query_one", return_value=_admin_row()):
            resp = auth_client.get("/api/audit")
            assert resp.status_code == 200
            data = resp.get_json()
            assert "rows" in data
            assert "total" in data
            assert "facets" in data
            assert "servers" in data["facets"]
            assert "actions" in data["facets"]


def test_web_get_audit_calls_actions_with_params(auth_client):
    """GET /api/audit passes all query params to actions.list_audit_logs."""
    with patch("web.actions.list_audit_logs") as mock_list, \
         patch("web.db.query_one", return_value=_admin_row()), \
         patch("web._parse_datetime", return_value=datetime(2025, 1, 1, tzinfo=timezone.utc)):
        mock_list.return_value = {
            "rows": [],
            "total": 0,
            "facets": {"servers": [], "actions": []},
        }
        auth_client.get("/api/audit?server=srv-01&action=KEY_REVOKED&since=2025-01-01T00:00:00Z&q=admin")
        mock_list.assert_called_once_with(
            server="srv-01",
            action="KEY_REVOKED",
            since="2025-01-01T00:00:00+00:00",
            q="admin",
        )


def test_web_get_audit_no_params(auth_client):
    """GET /api/audit without params passes None for all filters."""
    with patch("web.actions.list_audit_logs") as mock_list, \
         patch("web.db.query_one", return_value=_admin_row()):
        mock_list.return_value = {
            "rows": [],
            "total": 0,
            "facets": {"servers": [], "actions": []},
        }
        auth_client.get("/api/audit")
        mock_list.assert_called_once_with(
            server=None,
            action=None,
            since=None,
            q=None,
        )


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


def test_web_system_status_smtp_enabled_default(auth_client):
    with patch("web.db") as mock_db, patch.dict(os.environ, {"SMTP_HOST": "mail.example.com"}, clear=False):
        if "SMTP_ENABLED" in os.environ:
            del os.environ["SMTP_ENABLED"]
        mock_db.query_one.side_effect = [
            _admin_row(),
            {"n": 1},
            {"n": 0},
            {"n": 0},
            None,
        ]
        resp = auth_client.get("/api/system/status")
        assert resp.status_code == 200
        assert resp.get_json()["smtp_enabled"] is True


def test_web_system_status_smtp_enabled_set_one(auth_client):
    with patch("web.db") as mock_db, patch.dict(os.environ, {"SMTP_ENABLED": "1", "SMTP_HOST": "mail.example.com"}):
        mock_db.query_one.side_effect = [
            _admin_row(),
            {"n": 1},
            {"n": 0},
            {"n": 0},
            None,
        ]
        resp = auth_client.get("/api/system/status")
        assert resp.status_code == 200
        assert resp.get_json()["smtp_enabled"] is True


def test_web_system_status_smtp_disabled_no_host(auth_client):
    with patch("web.db") as mock_db, patch.dict(os.environ, {"SMTP_ENABLED": "1", "SMTP_HOST": ""}):
        mock_db.query_one.side_effect = [
            _admin_row(),
            {"n": 1},
            {"n": 0},
            {"n": 0},
            None,
        ]
        resp = auth_client.get("/api/system/status")
        assert resp.status_code == 200
        assert resp.get_json()["smtp_enabled"] is False


def test_web_system_status_smtp_disabled_empty(auth_client):
    with patch("web.db") as mock_db, patch.dict(os.environ, {"SMTP_ENABLED": ""}):
        mock_db.query_one.side_effect = [
            _admin_row(),
            {"n": 1},
            {"n": 0},
            {"n": 0},
            None,
        ]
        resp = auth_client.get("/api/system/status")
        assert resp.status_code == 200
        assert resp.get_json()["smtp_enabled"] is False


def test_web_system_status_smtp_disabled_zero(auth_client):
    with patch("web.db") as mock_db, patch.dict(os.environ, {"SMTP_ENABLED": "0"}):
        mock_db.query_one.side_effect = [
            _admin_row(),
            {"n": 1},
            {"n": 0},
            {"n": 0},
            None,
        ]
        resp = auth_client.get("/api/system/status")
        assert resp.status_code == 200
        assert resp.get_json()["smtp_enabled"] is False


def test_web_legacy_global_collector_key_route_removed(auth_client):
    with patch("web.db") as mock_db:
        mock_db.query_one.return_value = _admin_row()
        resp = auth_client.get("/api/system/collector-key")
        assert resp.status_code == 404


def test_web_rotate_key_sysadmin_returns_200(auth_client):
    with patch("web.db") as mock_db, patch("web.actions") as mock_actions:
        mock_db.query_one.return_value = _admin_row()
        mock_actions.rotate_collector_key.return_value = {"status": "rotated", "fingerprint": "SHA256:abc"}
        resp = auth_client.post("/api/servers/srv-01/rotate-key")
        assert resp.status_code == 200
        assert resp.get_json()["fingerprint"] == "SHA256:abc"
        mock_actions.rotate_collector_key.assert_called_once_with("srv-01", ADMIN_ID)


def test_web_rotate_key_operator_forbidden(auth_client):
    with patch("web.db") as mock_db:
        row = _admin_row()
        row["role"] = "operator"
        mock_db.query_one.return_value = row
        resp = auth_client.post("/api/servers/srv-01/rotate-key")
        assert resp.status_code == 403


def test_web_rotate_key_failure_returns_502(auth_client):
    from actions import UserError
    with patch("web.db") as mock_db, patch("web.actions") as mock_actions:
        mock_db.query_one.return_value = _admin_row()
        mock_actions.rotate_collector_key.side_effect = UserError("Rotation failed: boom", status=502)
        resp = auth_client.post("/api/servers/srv-01/rotate-key")
        assert resp.status_code == 502
        assert "boom" in resp.get_json()["error"]


def test_web_get_server_collector_key_returns_pubkey(auth_client):
    with patch("web.db") as mock_db, patch("web.actions") as mock_actions:
        mock_db.query_one.return_value = _admin_row()
        mock_actions.get_collector_key_for_server.return_value = {
            "fingerprint": "SHA256:abc",
            "public_key": "ssh-ed25519 AAAA...",
        }
        resp = auth_client.get("/api/servers/srv-01/collector-key")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["fingerprint"] == "SHA256:abc"
        assert data["public_key"].startswith("ssh-ed25519")


def test_web_get_server_collector_key_404(auth_client):
    from actions import NotFoundError
    with patch("web.db") as mock_db, patch("web.actions") as mock_actions:
        mock_db.query_one.return_value = _admin_row()
        mock_actions.get_collector_key_for_server.side_effect = NotFoundError("Server not found: srv-x")
        resp = auth_client.get("/api/servers/srv-x/collector-key")
        assert resp.status_code == 404


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
        mock_actions.delete_admin.side_effect = UserError("existing audit records reference this account")
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
        mock_actions.update_admin.side_effect = NotFoundError("Admin not found: ghost")
        resp = auth_client.put("/api/admins/ghost", json={
            "email": "new@example.com",
            "role": "operator"
        })
        assert resp.status_code == 404


def test_web_update_admin_returns_403_self_role(auth_client):
    with patch("web.db") as mock_db, patch("web.actions") as mock_actions:
        mock_db.query_one.return_value = _admin_row()
        mock_actions.update_admin.side_effect = ForbiddenError("Cannot change your own role")
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
                "justification": "Maintenance access",
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


def test_web_deploy_key_expires_at_invalid_format_returns_400(auth_client):
    """expires_at must be in ISO 8601 format — invalid format should return 400."""
    with patch("web.db") as mock_db:
        mock_db.query_one.return_value = {"id": ADMIN_ID, "username": "admin", "role": "sysadmin"}
        for bad_date in ["invalid-date", "2026-99-99T25:00:00Z", "12345", "2026/05/07"]:
            resp = auth_client.post(
                "/api/access/deploy",
                json={
                    "public_key": "ssh-ed25519 AAAA test",
                    "unix_user": "alice",
                    "hostname": "server-01",
                    "justification": "Test",
                    "expires_at": bad_date,
                },
            )
            assert resp.status_code == 400, f"Expected 400 for expires_at={bad_date!r}"
            assert "ISO 8601" in resp.json["error"] or "format" in resp.json["error"]


# ---------------------------------------------------------------------------
# Security — log injection: newlines sanitized before logging
# ---------------------------------------------------------------------------

def test_web_log_injection_newlines_sanitized_in_warning(auth_client):
    """A ValueError containing \n must not produce fake log lines."""
    with patch("web.db") as mock_db, patch("web.actions") as mock_actions, \
         patch("web.logging") as mock_logging:
        mock_db.query_one.return_value = _admin_row()
        mock_actions.revoke_key.side_effect = NotFoundError(
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
    """A ValueError containing \r must not produce fake log lines."""
    with patch("web.db") as mock_db, patch("web.actions") as mock_actions, \
         patch("web.logging") as mock_logging:
        mock_db.query_one.return_value = _admin_row()
        mock_actions.revoke_key.side_effect = NotFoundError(
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
# Security — GET /api/admins must not expose password_hash
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
        mock_actions.toggle_alerts.side_effect = NotFoundError("Active admin not found")
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
    assert resp.get_json()["error"] == "SMTP test failed"


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


def test_web_get_client_ip_prefers_x_real_ip(client):
    """X-Real-IP (set by Nginx, not spoofable) takes priority over X-Forwarded-For."""
    with client.application.test_request_context(
        headers={"X-Real-IP": "203.0.113.5", "X-Forwarded-For": "1.2.3.4, 5.6.7.8"}
    ):
        assert web._get_client_ip() == "203.0.113.5"


def test_web_get_client_ip_fallback_rightmost_forwarded(client):
    """Without X-Real-IP, take the rightmost X-Forwarded-For entry (most trustworthy)."""
    with client.application.test_request_context(
        headers={"X-Forwarded-For": "1.1.1.1, 203.0.113.5"}
    ):
        assert web._get_client_ip() == "203.0.113.5"


def test_web_get_client_ip_fallback_remote_addr(client):
    """Without any proxy headers, use remote_addr."""
    with client.application.test_request_context("/", environ_base={"REMOTE_ADDR": "10.0.0.1"}):
        assert web._get_client_ip() == "10.0.0.1"


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


def test_web_config_update_audit_retention_days(auth_client):
    """PUT /api/system/config accepts audit_retention_days."""
    with patch("web.db") as mock_db:
        mock_db.query_one.side_effect = [
            _admin_row(),
            {"value": "7"},
            {"value": "2"},
        ]
        mock_db.query.return_value = [
            {"key": "scan_interval_hours", "value": "4"},
            {"key": "audit_retention_days", "value": "180"},
        ]
        resp = auth_client.put("/api/system/config", json={"audit_retention_days": 180})
    assert resp.status_code == 200
    assert resp.get_json()["audit_retention_days"] == 180


def test_web_config_audit_retention_days_too_low(auth_client):
    """PUT /api/system/config rejects audit_retention_days < 30."""
    with patch("web.db") as mock_db:
        mock_db.query_one.return_value = _admin_row()
        resp = auth_client.put("/api/system/config", json={"audit_retention_days": 0})
    assert resp.status_code == 400
    assert "audit_retention_days" in resp.get_json()["error"]


def test_web_config_audit_retention_days_too_high(auth_client):
    """PUT /api/system/config rejects audit_retention_days > 3650."""
    with patch("web.db") as mock_db:
        mock_db.query_one.return_value = _admin_row()
        resp = auth_client.put("/api/system/config", json={"audit_retention_days": 9999})
    assert resp.status_code == 400
    assert "audit_retention_days" in resp.get_json()["error"]


# ---------------------------------------------------------------------------
# Session timeout
# ---------------------------------------------------------------------------

def test_web_session_expired_returns_401(client):
    """Expired session returns 401."""
    past = datetime.now(timezone.utc).timestamp() - 1
    with client.session_transaction() as sess:
        sess["admin_id"] = ADMIN_ID
        sess["admin_username"] = "admin"
        sess["expires_at"] = past
    with patch("web.db") as mock_db:
        resp = client.get("/api/keys")
    assert resp.status_code == 401
    data = resp.get_json()
    assert data["error"] == "Session expired"


def test_web_session_not_expired_passes(client):
    """Session with future expiry passes through require_auth."""
    future = datetime.now(timezone.utc).timestamp() + 3600
    with client.session_transaction() as sess:
        sess["admin_id"] = ADMIN_ID
        sess["admin_username"] = "admin"
        sess["expires_at"] = future
    with patch("web.db") as mock_db:
        mock_db.query_one.return_value = _admin_row()
        mock_db.query.return_value = []
        resp = client.get("/api/keys")
    assert resp.status_code == 200


def test_web_session_no_expiry_field_passes(client):
    """Session without expires_at (legacy) passes — no regression."""
    with client.session_transaction() as sess:
        sess["admin_id"] = ADMIN_ID
        sess["admin_username"] = "admin"
        # no expires_at
    with patch("web.db") as mock_db:
        mock_db.query_one.return_value = _admin_row()
        mock_db.query.return_value = []
        resp = client.get("/api/keys")
    assert resp.status_code == 200


def test_web_login_without_remember_me_sets_short_expiry(client):
    """Login without remember_me sets expires_at ~30 minutes from now."""
    web._login_attempts.clear()
    with patch("web.db") as mock_db:
        mock_db.query_one.side_effect = [
            {"value": "10"},
            {"value": "300"},
            {"id": ADMIN_ID, "username": "admin", "password_hash": "pbkdf2:sha256:hash"},
        ]
        with patch("web.check_password_hash", return_value=True):
            resp = client.post(
                "/api/auth/login",
                json={"username": "admin", "password": "correct"},
            )
    assert resp.status_code == 200
    with client.session_transaction() as sess:
        expires_at = sess.get("expires_at")
    now = datetime.now(timezone.utc).timestamp()
    expected = now + web.SESSION_SHORT_MINUTES * 60
    assert abs(expires_at - expected) < 5  # within 5 seconds


def test_web_login_with_remember_me_sets_long_expiry(client):
    """Login with remember_me=True sets expires_at ~8 hours from now."""
    web._login_attempts.clear()
    with patch("web.db") as mock_db:
        mock_db.query_one.side_effect = [
            {"value": "10"},
            {"value": "300"},
            {"id": ADMIN_ID, "username": "admin", "password_hash": "pbkdf2:sha256:hash"},
        ]
        with patch("web.check_password_hash", return_value=True):
            resp = client.post(
                "/api/auth/login",
                json={"username": "admin", "password": "correct", "remember_me": True},
            )
    assert resp.status_code == 200
    with client.session_transaction() as sess:
        expires_at = sess.get("expires_at")
    now = datetime.now(timezone.utc).timestamp()
    expected = now + web.SESSION_LONG_HOURS * 3600
    assert abs(expires_at - expected) < 5


# ---------------------------------------------------------------------------
# SSH Sessions routes
# ---------------------------------------------------------------------------

def test_web_get_sessions_operator_200(client):
    """GET /api/servers/<hostname>/sessions returns 200 for operator."""
    with patch("web.db") as mock_db:
        mock_db.query_one.side_effect = [
            {"id": ADMIN_ID, "username": "op", "role": "operator"},
            {"id": SERVER_ID}
        ]
        mock_db.query.return_value = []
        with client.session_transaction() as sess:
            sess["admin_id"] = ADMIN_ID
        res = client.get("/api/servers/server1/sessions")
        assert res.status_code == 200
        data = res.get_json()
        assert "active" in data
        assert "recent" in data


def test_web_get_sessions_viewer_403(client):
    """GET /api/servers/<hostname>/sessions returns 403 for viewer."""
    with patch("web.db") as mock_db:
        mock_db.query_one.return_value = {"id": ADMIN_ID, "username": "viewer", "role": "viewer"}
        with client.session_transaction() as sess:
            sess["admin_id"] = ADMIN_ID
        res = client.get("/api/servers/server1/sessions")
        assert res.status_code == 403


def test_web_get_sessions_unauthenticated_401(client):
    """GET /api/servers/<hostname>/sessions returns 401 when not logged in."""
    res = client.get("/api/servers/server1/sessions")
    assert res.status_code == 401


def test_web_refresh_sessions_operator_200(client):
    """POST /api/servers/<hostname>/sessions/refresh returns 200 for operator."""
    with patch("web.db") as mock_db, patch("web.ssh") as mock_ssh:
        mock_db.query_one.side_effect = [
            {"id": ADMIN_ID, "username": "op", "role": "operator"},
            {"id": SERVER_ID, "ip_address": "192.168.1.1"}
        ]
        with client.session_transaction() as sess:
            sess["admin_id"] = ADMIN_ID
        res = client.post("/api/servers/server1/sessions/refresh")
        assert res.status_code == 200


def test_web_sessions_history_operator_200(client):
    """GET /api/servers/<hostname>/sessions/history returns 200 for operator."""
    with patch("web.db") as mock_db:
        mock_db.query_one.side_effect = [
            {"id": ADMIN_ID, "username": "op", "role": "operator"},
            {"id": SERVER_ID}
        ]
        mock_db.query.return_value = []
        with client.session_transaction() as sess:
            sess["admin_id"] = ADMIN_ID
        res = client.get("/api/servers/server1/sessions/history")
        assert res.status_code == 200


# ---------------------------------------------------------------------------
# GET /api/servers/<hostname>/sshd-audit — hardening audit
# ---------------------------------------------------------------------------

def test_web_sshd_audit_sysadmin_200(auth_client):
    """GET /api/servers/<hostname>/sshd-audit returns 200 for sysadmin."""
    with patch("web.db") as mock_db, patch("web.actions") as mock_actions:
        mock_db.query_one.return_value = _admin_row()
        mock_actions.audit_server_sshd.return_value = {
            "checks": [],
            "summary": {"ok": 14, "warning": 0, "critical": 0, "missing": 0},
            "overall": "ok"
        }
        resp = auth_client.get("/api/servers/server1/sshd-audit")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "checks" in data
    assert "summary" in data
    assert "overall" in data


def test_web_sshd_audit_operator_200(client):
    """GET /api/servers/<hostname>/sshd-audit returns 200 for operator."""
    with client.session_transaction() as sess:
        sess["admin_id"] = ADMIN_ID
        sess["admin_username"] = "operator"
    with patch("web.db") as mock_db, patch("web.actions") as mock_actions:
        mock_db.query_one.return_value = {"id": ADMIN_ID, "username": "operator", "role": "operator"}
        mock_actions.audit_server_sshd.return_value = {
            "checks": [],
            "summary": {"ok": 14, "warning": 0, "critical": 0, "missing": 0},
            "overall": "ok"
        }
        resp = client.get("/api/servers/server1/sshd-audit")
    assert resp.status_code == 200


def test_web_sshd_audit_viewer_200(client):
    """GET /api/servers/<hostname>/sshd-audit returns 200 for viewer (read-only)."""
    with client.session_transaction() as sess:
        sess["admin_id"] = ADMIN_ID
        sess["admin_username"] = "viewer"
    with patch("web.db") as mock_db, patch("web.actions") as mock_actions:
        mock_db.query_one.return_value = {"id": ADMIN_ID, "username": "viewer", "role": "viewer"}
        mock_actions.audit_server_sshd.return_value = {
            "checks": [],
            "summary": {"ok": 14, "warning": 0, "critical": 0, "missing": 0},
            "overall": "ok"
        }
        resp = client.get("/api/servers/server1/sshd-audit")
    assert resp.status_code == 200


def test_web_sshd_audit_no_session_returns_401(client):
    """GET /api/servers/<hostname>/sshd-audit without session returns 401."""
    with patch("web.db") as mock_db:
        resp = client.get("/api/servers/server1/sshd-audit")
    assert resp.status_code == 401


def test_web_sshd_audit_server_not_found_returns_404(auth_client):
    """GET /api/servers/<hostname>/sshd-audit returns 404 if server does not exist."""
    with patch("web.db") as mock_db, patch("web.actions") as mock_actions:
        mock_db.query_one.return_value = _admin_row()
        mock_actions.audit_server_sshd.side_effect = web.NotFoundError("Server not found")
        resp = auth_client.get("/api/servers/unknown-server/sshd-audit")
    assert resp.status_code == 404


def test_web_sshd_audit_ssh_failure_returns_502(auth_client):
    """GET /api/servers/<hostname>/sshd-audit returns 502 if SSH fails."""
    with patch("web.db") as mock_db, patch("web.actions") as mock_actions:
        mock_db.query_one.return_value = _admin_row()
        mock_actions.audit_server_sshd.side_effect = web.UserError("SSH audit failed", status=502)
        resp = auth_client.get("/api/servers/server1/sshd-audit")
    assert resp.status_code == 502


# ---------------------------------------------------------------------------
# POST /api/keys/bulk-validate
# ---------------------------------------------------------------------------

def test_web_bulk_validate_returns_200(auth_client):
    fps = ["SHA256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]
    with patch("web.db") as mock_db, patch("web.actions") as mock_actions:
        mock_db.query_one.return_value = _admin_row()
        mock_actions.bulk_validate_keys.return_value = {"validated": 1, "skipped": 0}
        resp = auth_client.post("/api/keys/bulk-validate", json={"fingerprints": fps})
    assert resp.status_code == 200
    assert resp.get_json()["validated"] == 1


def test_web_bulk_validate_rejects_missing_fingerprints(auth_client):
    with patch("web.db") as mock_db:
        mock_db.query_one.return_value = _admin_row()
        resp = auth_client.post("/api/keys/bulk-validate", json={})
    assert resp.status_code == 400


def test_web_bulk_validate_rejects_non_list(auth_client):
    with patch("web.db") as mock_db:
        mock_db.query_one.return_value = _admin_row()
        resp = auth_client.post("/api/keys/bulk-validate", json={"fingerprints": "notalist"})
    assert resp.status_code == 400


def test_web_bulk_validate_viewer_returns_403(client):
    with client.session_transaction() as sess:
        sess["admin_id"] = ADMIN_ID
        sess["admin_username"] = "viewer"
    with patch("web.db") as mock_db:
        mock_db.query_one.return_value = {"id": ADMIN_ID, "username": "viewer", "role": "viewer"}
        resp = client.post("/api/keys/bulk-validate", json={"fingerprints": []})
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# POST /api/keys/bulk-revoke
# ---------------------------------------------------------------------------

def test_web_bulk_revoke_returns_200(auth_client):
    fps = ["SHA256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]
    with patch("web.db") as mock_db, patch("web.actions") as mock_actions:
        mock_db.query_one.return_value = _admin_row()
        mock_actions.bulk_revoke_keys.return_value = {"revoked": 1, "skipped": 0}
        resp = auth_client.post("/api/keys/bulk-revoke", json={"fingerprints": fps, "reason": "audit"})
    assert resp.status_code == 200
    assert resp.get_json()["revoked"] == 1


def test_web_bulk_revoke_rejects_missing_reason(auth_client):
    fps = ["SHA256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]
    with patch("web.db") as mock_db:
        mock_db.query_one.return_value = _admin_row()
        resp = auth_client.post("/api/keys/bulk-revoke", json={"fingerprints": fps})
    assert resp.status_code == 400
    assert "reason" in resp.get_json()["error"]


def test_web_bulk_revoke_rejects_missing_fingerprints(auth_client):
    with patch("web.db") as mock_db:
        mock_db.query_one.return_value = _admin_row()
        resp = auth_client.post("/api/keys/bulk-revoke", json={"reason": "audit"})
    assert resp.status_code == 400


def test_web_bulk_revoke_viewer_returns_403(client):
    with client.session_transaction() as sess:
        sess["admin_id"] = ADMIN_ID
        sess["admin_username"] = "viewer"
    with patch("web.db") as mock_db:
        mock_db.query_one.return_value = {"id": ADMIN_ID, "username": "viewer", "role": "viewer"}
        resp = client.post("/api/keys/bulk-revoke", json={"fingerprints": [], "reason": "x"})
    assert resp.status_code == 403


def test_web_bulk_validate_rejects_empty_list(auth_client):
    with patch("web.db") as mock_db:
        mock_db.query_one.return_value = _admin_row()
        resp = auth_client.post("/api/keys/bulk-validate", json={"fingerprints": []})
    assert resp.status_code == 400


def test_web_bulk_validate_rejects_over_200(auth_client):
    fps = ["SHA256:" + "a" * 43] * 201
    with patch("web.db") as mock_db:
        mock_db.query_one.return_value = _admin_row()
        resp = auth_client.post("/api/keys/bulk-validate", json={"fingerprints": fps})
    assert resp.status_code == 400


def test_web_bulk_revoke_rejects_empty_list(auth_client):
    with patch("web.db") as mock_db:
        mock_db.query_one.return_value = _admin_row()
        resp = auth_client.post("/api/keys/bulk-revoke", json={"fingerprints": [], "reason": "audit"})
    assert resp.status_code == 400


def test_web_bulk_revoke_rejects_over_200(auth_client):
    fps = ["SHA256:" + "a" * 43] * 201
    with patch("web.db") as mock_db:
        mock_db.query_one.return_value = _admin_row()
        resp = auth_client.post("/api/keys/bulk-revoke", json={"fingerprints": fps, "reason": "audit"})
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# POST /api/access/grant-group
# ---------------------------------------------------------------------------

def test_web_grant_group_sysadmin_success(auth_client):
    with patch("web.db") as mock_db, patch("web.actions") as mock_actions:
        mock_db.query_one.return_value = _admin_row()
        mock_actions.grant_group.return_value = {
            "unix_user": "alice", "hostname": "server-01", "sam_group": "sam-operator"
        }
        resp = auth_client.post("/api/access/grant-group", json={
            "unix_user": "alice", "hostname": "server-01", "sam_group": "sam-operator"
        })
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["sam_group"] == "sam-operator"
        mock_actions.grant_group.assert_called_once_with("alice", "server-01", "sam-operator", ADMIN_ID)


def test_web_grant_group_operator_can_assign_sam_operator(client):
    operator_id = str(uuid.uuid4())
    with client.session_transaction() as sess:
        sess["admin_id"] = operator_id
        sess["admin_username"] = "operator"
    with patch("web.db") as mock_db, patch("web.actions") as mock_actions:
        mock_db.query_one.return_value = {"id": operator_id, "username": "operator", "role": "operator"}
        mock_actions.grant_group.return_value = {
            "unix_user": "alice", "hostname": "server-01", "sam_group": "sam-operator"
        }
        resp = client.post("/api/access/grant-group", json={
            "unix_user": "alice", "hostname": "server-01", "sam_group": "sam-operator"
        })
        assert resp.status_code == 200


def test_web_grant_group_operator_cannot_assign_sam_root(client):
    operator_id = str(uuid.uuid4())
    with client.session_transaction() as sess:
        sess["admin_id"] = operator_id
        sess["admin_username"] = "operator"
    with patch("web.db") as mock_db:
        mock_db.query_one.return_value = {"id": operator_id, "username": "operator", "role": "operator"}
        resp = client.post("/api/access/grant-group", json={
            "unix_user": "alice", "hostname": "server-01", "sam_group": "sam-root"
        })
        assert resp.status_code == 403


def test_web_grant_group_viewer_forbidden(client):
    viewer_id = str(uuid.uuid4())
    with client.session_transaction() as sess:
        sess["admin_id"] = viewer_id
        sess["admin_username"] = "viewer"
    with patch("web.db") as mock_db:
        mock_db.query_one.return_value = {"id": viewer_id, "username": "viewer", "role": "viewer"}
        resp = client.post("/api/access/grant-group", json={
            "unix_user": "alice", "hostname": "server-01", "sam_group": "sam-operator"
        })
        assert resp.status_code == 403


def test_web_grant_group_missing_fields_returns_400(auth_client):
    with patch("web.db") as mock_db:
        mock_db.query_one.return_value = _admin_row()
        resp = auth_client.post("/api/access/grant-group", json={"unix_user": "alice"})
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# POST /api/access/revoke-group
# ---------------------------------------------------------------------------

def test_web_revoke_group_sysadmin_success(auth_client):
    with patch("web.db") as mock_db, patch("web.actions") as mock_actions:
        mock_db.query_one.return_value = _admin_row()
        mock_actions._get_current_group.return_value = "sam-operator"
        mock_actions.revoke_group.return_value = {
            "unix_user": "alice", "hostname": "server-01", "sam_group": None
        }
        resp = auth_client.post("/api/access/revoke-group", json={
            "unix_user": "alice", "hostname": "server-01"
        })
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["sam_group"] is None


def test_web_revoke_group_operator_cannot_revoke_sam_root(client):
    operator_id = str(uuid.uuid4())
    with client.session_transaction() as sess:
        sess["admin_id"] = operator_id
        sess["admin_username"] = "operator"
    with patch("web.db") as mock_db, patch("web.actions") as mock_actions:
        mock_db.query_one.return_value = {"id": operator_id, "username": "operator", "role": "operator"}
        mock_actions._get_current_group.return_value = "sam-root"
        resp = client.post("/api/access/revoke-group", json={
            "unix_user": "alice", "hostname": "server-01"
        })
        assert resp.status_code == 403


def test_web_revoke_group_operator_can_revoke_sam_operator(client):
    operator_id = str(uuid.uuid4())
    with client.session_transaction() as sess:
        sess["admin_id"] = operator_id
        sess["admin_username"] = "operator"
    with patch("web.db") as mock_db, patch("web.actions") as mock_actions:
        mock_db.query_one.return_value = {"id": operator_id, "username": "operator", "role": "operator"}
        mock_actions._get_current_group.return_value = "sam-operator"
        mock_actions.revoke_group.return_value = {
            "unix_user": "alice", "hostname": "server-01", "sam_group": None
        }
        resp = client.post("/api/access/revoke-group", json={
            "unix_user": "alice", "hostname": "server-01"
        })
        assert resp.status_code == 200


def test_web_revoke_group_missing_fields_returns_400(auth_client):
    with patch("web.db") as mock_db:
        mock_db.query_one.return_value = _admin_row()
        resp = auth_client.post("/api/access/revoke-group", json={"unix_user": "alice"})
        assert resp.status_code == 400


def test_web_revoke_group_viewer_forbidden(client):
    viewer_id = str(uuid.uuid4())
    with client.session_transaction() as sess:
        sess["admin_id"] = viewer_id
        sess["admin_username"] = "viewer"
    with patch("web.db") as mock_db:
        mock_db.query_one.return_value = {"id": viewer_id, "username": "viewer", "role": "viewer"}
        resp = client.post("/api/access/revoke-group", json={
            "unix_user": "alice", "hostname": "server-01"
        })
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# PUT /api/access/change-group
# ---------------------------------------------------------------------------

def test_web_change_group_sysadmin_success(auth_client):
    with patch("web.db") as mock_db, patch("web.actions") as mock_actions:
        mock_db.query_one.return_value = _admin_row()
        mock_actions._get_current_group.return_value = "sam-operator"
        mock_actions.change_group.return_value = {
            "unix_user": "alice", "hostname": "server-01", "sam_group": "sam-pkg"
        }
        resp = auth_client.put("/api/access/change-group", json={
            "unix_user": "alice", "hostname": "server-01", "sam_group": "sam-pkg"
        })
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["sam_group"] == "sam-pkg"


def test_web_change_group_operator_cannot_assign_sam_root(client):
    operator_id = str(uuid.uuid4())
    with client.session_transaction() as sess:
        sess["admin_id"] = operator_id
        sess["admin_username"] = "operator"
    with patch("web.db") as mock_db, patch("web.actions") as mock_actions:
        mock_db.query_one.return_value = {"id": operator_id, "username": "operator", "role": "operator"}
        mock_actions._get_current_group.return_value = "sam-operator"
        resp = client.put("/api/access/change-group", json={
            "unix_user": "alice", "hostname": "server-01", "sam_group": "sam-root"
        })
        assert resp.status_code == 403


def test_web_change_group_operator_cannot_change_from_sam_root(client):
    operator_id = str(uuid.uuid4())
    with client.session_transaction() as sess:
        sess["admin_id"] = operator_id
        sess["admin_username"] = "operator"
    with patch("web.db") as mock_db, patch("web.actions") as mock_actions:
        mock_db.query_one.return_value = {"id": operator_id, "username": "operator", "role": "operator"}
        mock_actions._get_current_group.return_value = "sam-root"
        resp = client.put("/api/access/change-group", json={
            "unix_user": "alice", "hostname": "server-01", "sam_group": "sam-pkg"
        })
        assert resp.status_code == 403


def test_web_change_group_missing_fields_returns_400(auth_client):
    with patch("web.db") as mock_db:
        mock_db.query_one.return_value = _admin_row()
        resp = auth_client.put("/api/access/change-group", json={"unix_user": "alice"})
        assert resp.status_code == 400


def test_web_change_group_viewer_forbidden(client):
    viewer_id = str(uuid.uuid4())
    with client.session_transaction() as sess:
        sess["admin_id"] = viewer_id
        sess["admin_username"] = "viewer"
    with patch("web.db") as mock_db:
        mock_db.query_one.return_value = {"id": viewer_id, "username": "viewer", "role": "viewer"}
        resp = client.put("/api/access/change-group", json={
            "unix_user": "alice", "hostname": "server-01", "sam_group": "sam-pkg"
        })
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# GET /api/servers — provision_version and provision_drift fields
# ---------------------------------------------------------------------------

def test_web_get_servers_includes_provision_fields(auth_client):
    """GET /api/servers includes provision_version and provision_drift in response."""
    server_row = {
        "id": SERVER_ID, "hostname": "server-01", "ip_address": "192.168.1.10",
        "is_active": True, "provision_version": "abc123", "provision_drift": False,
        "last_scan_action": "SCAN_COMPLETED", "has_anomalies": False,
    }
    with patch("web.db") as mock_db:
        mock_db.query_one.return_value = _admin_row()
        mock_db.query.return_value = [server_row]
        resp = auth_client.get("/api/servers")
        assert resp.status_code == 200
        data = resp.get_json()
        assert isinstance(data, list)
        assert "provision_version" in data[0]
        assert "provision_drift" in data[0]
        assert data[0]["provision_version"] == "abc123"
        assert data[0]["provision_drift"] is False


# ---------------------------------------------------------------------------
# POST /api/servers/<hostname>/sync — force provision update
# ---------------------------------------------------------------------------

def test_web_force_provision_sync_sysadmin_returns_200(auth_client):
    """POST /api/servers/<hostname>/sync returns 200 for sysadmin."""
    with patch("web.db") as mock_db, patch("web.ssh") as mock_ssh:
        mock_db.query_one.side_effect = [
            _admin_row(),
            {"id": SERVER_ID, "ip_address": "192.168.1.10", "ssh_port": 22},
        ]
        mock_ssh.apply_provision_update.return_value = "new-version"
        mock_ssh.PROVISION_VERSION = "new-version"

        resp = auth_client.post("/api/servers/server-01/sync")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "updated"
        assert data["version"] == "new-version"


def test_web_force_provision_sync_operator_forbidden(client):
    """POST /api/servers/<hostname>/sync returns 403 for operator."""
    operator_id = str(uuid.uuid4())
    with client.session_transaction() as sess:
        sess["admin_id"] = operator_id
        sess["admin_username"] = "operator"
    with patch("web.db") as mock_db:
        mock_db.query_one.return_value = {"id": operator_id, "username": "operator", "role": "operator"}
        resp = client.post("/api/servers/server-01/sync")
        assert resp.status_code == 403


def test_web_force_provision_sync_viewer_forbidden(client):
    """POST /api/servers/<hostname>/sync returns 403 for viewer."""
    viewer_id = str(uuid.uuid4())
    with client.session_transaction() as sess:
        sess["admin_id"] = viewer_id
        sess["admin_username"] = "viewer"
    with patch("web.db") as mock_db:
        mock_db.query_one.return_value = {"id": viewer_id, "username": "viewer", "role": "viewer"}
        resp = client.post("/api/servers/server-01/sync")
        assert resp.status_code == 403


def test_web_force_provision_sync_ssh_error_returns_502(auth_client):
    """POST /api/servers/<hostname>/sync returns 502 when SSH fails."""
    with patch("web.db") as mock_db, patch("web.ssh") as mock_ssh:
        mock_db.query_one.side_effect = [
            _admin_row(),
            {"id": SERVER_ID, "ip_address": "192.168.1.10", "ssh_port": 22},
        ]
        mock_ssh.SSHError = ssh.SSHError
        mock_ssh.SSHSudoError = ssh.SSHSudoError
        mock_ssh.PROVISION_VERSION = "test-version"
        mock_ssh.apply_provision_update.side_effect = ssh.SSHSudoError("visudo validation failed")

        resp = auth_client.post("/api/servers/server-01/sync")
        assert resp.status_code == 502
        data = resp.get_json()
        assert "error" in data
        assert "error_code" in data


def test_web_force_provision_sync_unknown_server_returns_404(auth_client):
    """POST /api/servers/<hostname>/sync returns 404 when server not found."""
    with patch("web.db") as mock_db:
        mock_db.query_one.side_effect = [
            _admin_row(),
            None,  # server not found
        ]
        resp = auth_client.post("/api/servers/unknown-server/sync")
        assert resp.status_code == 404
