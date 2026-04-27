"""
RBAC matrix — exhaustive tests: all protected routes × all roles.

- SYSADMIN_ONLY_ROUTES: operator AND viewer must get 403
- OPERATOR_ALLOWED_ROUTES: viewer must get 403, operator must NOT get 403
"""

import os
import sys
import uuid
from unittest.mock import patch, MagicMock
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import web

ADMIN_ID = str(uuid.uuid4())
REQUEST_ID = str(uuid.uuid4())
FP = "SHA256:testABCDEF1234567890"

# Routes requiring sysadmin role exclusively
SYSADMIN_ONLY_ROUTES = [
    ("post", "/api/servers", {"hostname": "h", "ip": "1.2.3.4", "environment": "lab"}),
    (
        "put",
        "/api/servers/some-host",
        {"ip": "1.2.3.4", "environment": "lab"},
    ),
    ("put", "/api/servers/some-host/disable", {}),
    ("put", "/api/servers/some-host/enable", {}),
    ("delete", "/api/servers/some-host", {}),
    (
        "post",
        "/api/admins",
        {"username": "new", "email": "x@x.com", "password": "P@ssw0rd!"},
    ),
    ("put", "/api/admins/someuser", {"email": "x@x.com", "role": "operator"}),
    ("put", "/api/admins/someuser/disable", {}),
    ("put", "/api/admins/someuser/enable", {}),
    ("delete", "/api/admins/someuser", {}),
    ("put", "/api/admins/someuser/alerts", {"receive_alerts": True}),
    ("put", "/api/system/config", {"scan_interval_hours": 4}),
]

# Routes allowing both sysadmin and operator (viewer must get 403)
OPERATOR_ALLOWED_ROUTES = [
    ("post", "/api/servers/some-host/scan", {}),
    ("post", f"/api/keys/validate/{FP}", {}),
    ("post", f"/api/keys/revoke/{FP}", {"reason": "test"}),
    ("post", f"/api/keys/assign/{FP}", {"owner": "alice"}),
    ("post", f"/api/keys/set-expiry/{FP}", {"hours": 24}),
    ("post", f"/api/keys/remove-expiry/{FP}", {}),
    (
        "post",
        "/api/access/grant",
        {
            "key_fp": FP,
            "hostname": "h",
            "hours": 1,
            "justification": "x",
        },
    ),
    (
        "post",
        "/api/access/deploy",
        {
            "public_key": "ssh-ed25519 AAAA x",
            "unix_user": "alice",
            "hostname": "h",
            "justification": "x",
        },
    ),
    ("post", "/api/access/lock-user", {"unix_user": "alice", "hostname": "h"}),
    ("post", "/api/access/unlock-user", {"unix_user": "alice", "hostname": "h"}),
    (
        "post",
        "/api/access/request",
        {
            "key_fp": FP,
            "hostname": "h",
            "hours": 1,
            "justification": "x",
        },
    ),
    ("post", f"/api/access/{REQUEST_ID}/approve", {}),
    ("post", f"/api/access/{REQUEST_ID}/reject", {}),
    ("post", f"/api/access/{REQUEST_ID}/revoke", {}),
    ("post", "/api/system/scan", {}),
]


@pytest.fixture
def client():
    web.app.config["TESTING"] = True
    with web.app.test_client() as c:
        yield c


@pytest.mark.parametrize("role", ["operator", "viewer"])
@pytest.mark.parametrize(
    "method,url,body",
    SYSADMIN_ONLY_ROUTES,
    ids=[f"{m.upper()} {u}" for m, u, _ in SYSADMIN_ONLY_ROUTES],
)
def test_rbac_sysadmin_only_returns_403(client, method, url, body, role):
    """Sysadmin-only routes must return 403 for operator and viewer."""
    with patch("web.db") as mock_db:
        with client.session_transaction() as sess:
            sess["admin_id"] = ADMIN_ID
        mock_db.query_one.return_value = {
            "id": ADMIN_ID,
            "username": "testuser",
            "role": role,
        }

        if method == "post":
            resp = client.post(url, json=body)
        elif method == "put":
            resp = client.put(url, json=body)
        elif method == "delete":
            resp = client.delete(url, json=body)
        else:
            raise ValueError(f"Unsupported method {method}")

        assert (
            resp.status_code == 403
        ), f"{method.upper()} {url} must return 403 for role '{role}'"


@pytest.mark.parametrize(
    "method,url,body",
    OPERATOR_ALLOWED_ROUTES,
    ids=[f"{m.upper()} {u}" for m, u, _ in OPERATOR_ALLOWED_ROUTES],
)
def test_rbac_viewer_blocked_on_operator_routes(client, method, url, body):
    """Viewer must get 403 on routes that allow operator."""
    with patch("web.db") as mock_db:
        with client.session_transaction() as sess:
            sess["admin_id"] = ADMIN_ID
        mock_db.query_one.return_value = {
            "id": ADMIN_ID,
            "username": "testuser",
            "role": "viewer",
        }

        if method == "post":
            resp = client.post(url, json=body)
        elif method == "put":
            resp = client.put(url, json=body)
        elif method == "delete":
            resp = client.delete(url, json=body)
        else:
            raise ValueError(f"Unsupported method {method}")

        assert (
            resp.status_code == 403
        ), f"{method.upper()} {url} must return 403 for viewer"


@pytest.mark.parametrize(
    "method,url,body",
    OPERATOR_ALLOWED_ROUTES,
    ids=[f"{m.upper()} {u}" for m, u, _ in OPERATOR_ALLOWED_ROUTES],
)
def test_rbac_operator_not_blocked_on_operator_routes(client, method, url, body):
    """Operator must NOT get 403 on operator-allowed routes."""
    with patch("web.db") as mock_db, patch("web.actions") as mock_actions, patch(
        "web.collect_mod"
    ) as mock_collect:
        with client.session_transaction() as sess:
            sess["admin_id"] = ADMIN_ID

        mock_db.query_one.return_value = {
            "id": ADMIN_ID,
            "username": "testuser",
            "role": "operator",
        }
        mock_db.query.return_value = []

        # Mock action functions to prevent internal errors
        mock_actions.validate_key = MagicMock()
        mock_actions.revoke_key = MagicMock()
        mock_actions.assign_key = MagicMock()
        mock_actions.set_key_expiry = MagicMock()
        mock_actions.remove_key_expiry = MagicMock()
        mock_actions.grant_access = MagicMock()
        mock_actions.deploy_key = MagicMock()
        mock_actions.lock_user = MagicMock()
        mock_actions.unlock_user = MagicMock()
        mock_actions.approve_request = MagicMock()
        mock_actions.reject_request = MagicMock()
        mock_actions.revoke_request = MagicMock()
        mock_collect.run_scan = MagicMock(return_value={"status": "ok", "scanned": 0})

        if method == "post":
            resp = client.post(url, json=body)
        elif method == "put":
            resp = client.put(url, json=body)
        elif method == "delete":
            resp = client.delete(url, json=body)
        else:
            raise ValueError(f"Unsupported method {method}")

        assert (
            resp.status_code != 403
        ), f"{method.upper()} {url} must NOT return 403 for operator"
