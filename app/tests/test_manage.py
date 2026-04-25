import os
import sys
import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import manage

ADMIN_ID = str(uuid.uuid4())
KEY_ID = str(uuid.uuid4())
SERVER_ID = str(uuid.uuid4())
REQUEST_ID = str(uuid.uuid4())
FINGERPRINT = "SHA256:testABCDEF1234"
HOSTNAME = "server-test-01"


@pytest.fixture
def runner():
    return CliRunner()


def _admin():
    return {"id": ADMIN_ID}


# ---------------------------------------------------------------------------
# servers
# ---------------------------------------------------------------------------

def test_manage_servers_list(runner):
    rows = [{"hostname": HOSTNAME, "ip_address": "192.168.1.10", "environment": "lab", "is_active": True}]
    with patch("manage.db") as mock_db:
        mock_db.query.return_value = rows
        result = runner.invoke(manage.cli, ["servers", "list"])
        assert result.exit_code == 0
        assert HOSTNAME in result.output


def test_manage_servers_add(runner):
    with patch("manage.db") as mock_db, patch("manage.actions") as mock_actions:
        mock_db.query_one.return_value = _admin()
        mock_actions.add_server.return_value = {"id": SERVER_ID}
        result = runner.invoke(manage.cli, [
            "servers", "add",
            "--hostname", HOSTNAME, "--ip", "10.0.0.1", "--env", "lab",
        ])
        assert result.exit_code == 0
        mock_actions.add_server.assert_called_once()
        assert HOSTNAME in result.output


def test_manage_servers_disable(runner):
    with patch("manage.db") as mock_db, patch("manage.actions") as mock_actions:
        mock_db.query_one.return_value = _admin()
        result = runner.invoke(manage.cli, ["servers", "disable", HOSTNAME])
        assert result.exit_code == 0
        mock_actions.disable_server.assert_called_once_with(HOSTNAME, ADMIN_ID)


def test_manage_servers_show(runner):
    row = {"hostname": HOSTNAME, "ip_address": "10.0.0.1", "environment": "lab",
           "is_active": True, "added_at": datetime.now(tz=timezone.utc), "id": SERVER_ID,
           "os_family": "rhel", "os_version": None}
    with patch("manage.db") as mock_db:
        mock_db.query_one.return_value = row
        result = runner.invoke(manage.cli, ["servers", "show", HOSTNAME])
        assert result.exit_code == 0
        assert HOSTNAME in result.output


def test_manage_servers_scan(runner):
    with patch("manage.collect_mod") as mock_collect:
        mock_collect.run_scan.return_value = [
            {"hostname": HOSTNAME, "new": 0, "disappeared": 0, "known": 2, "error": None}
        ]
        result = runner.invoke(manage.cli, ["servers", "scan"])
        assert result.exit_code == 0
        assert "OK" in result.output


# ---------------------------------------------------------------------------
# keys
# ---------------------------------------------------------------------------

def test_manage_keys_list(runner):
    with patch("manage.db") as mock_db:
        mock_db.query.return_value = []
        result = runner.invoke(manage.cli, ["keys", "list"])
        assert result.exit_code == 0


def test_manage_keys_validate(runner):
    with patch("manage.db") as mock_db, patch("manage.actions") as mock_actions:
        mock_db.query_one.return_value = _admin()
        result = runner.invoke(manage.cli, ["keys", "validate", FINGERPRINT])
        assert result.exit_code == 0
        mock_actions.validate_key.assert_called_once_with(FINGERPRINT, ADMIN_ID)


def test_manage_keys_revoke(runner):
    with patch("manage.db") as mock_db, patch("manage.actions") as mock_actions:
        mock_db.query_one.return_value = _admin()
        result = runner.invoke(manage.cli, [
            "keys", "revoke", FINGERPRINT, "--reason", "test"
        ])
        assert result.exit_code == 0
        mock_actions.revoke_key.assert_called_once_with(FINGERPRINT, ADMIN_ID, "test")


def test_manage_keys_assign(runner):
    with patch("manage.actions") as mock_actions:
        result = runner.invoke(manage.cli, [
            "keys", "assign", FINGERPRINT, "--owner", "admin"
        ])
        assert result.exit_code == 0
        mock_actions.assign_key.assert_called_once_with(FINGERPRINT, "admin")


def test_manage_keys_set_expiry_hours(runner):
    with patch("manage.db") as mock_db, patch("manage.actions") as mock_actions:
        mock_db.query_one.return_value = _admin()
        result = runner.invoke(manage.cli, [
            "keys", "set-expiry", FINGERPRINT, "--hours", "24"
        ])
        assert result.exit_code == 0
        mock_actions.set_key_expiry.assert_called_once()


def test_manage_keys_set_expiry_date(runner):
    with patch("manage.db") as mock_db, patch("manage.actions") as mock_actions:
        mock_db.query_one.return_value = _admin()
        result = runner.invoke(manage.cli, [
            "keys", "set-expiry", FINGERPRINT, "--date", "2026-12-31 10:00"
        ])
        assert result.exit_code == 0
        mock_actions.set_key_expiry.assert_called_once()


def test_manage_keys_set_expiry_requires_hours_or_date(runner):
    result = runner.invoke(manage.cli, ["keys", "set-expiry", FINGERPRINT])
    assert result.exit_code != 0


def test_manage_keys_remove_expiry(runner):
    with patch("manage.db") as mock_db, patch("manage.actions") as mock_actions:
        mock_db.query_one.return_value = _admin()
        result = runner.invoke(manage.cli, ["keys", "remove-expiry", FINGERPRINT])
        assert result.exit_code == 0
        mock_actions.remove_key_expiry.assert_called_once_with(FINGERPRINT)


def test_manage_keys_search(runner):
    with patch("manage.db") as mock_db:
        mock_db.query.return_value = []
        result = runner.invoke(manage.cli, ["keys", "search", "admin"])
        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# access
# ---------------------------------------------------------------------------

def test_manage_access_list(runner):
    with patch("manage.db") as mock_db:
        mock_db.query.return_value = []
        result = runner.invoke(manage.cli, ["access", "list"])
        assert result.exit_code == 0


def test_manage_access_grant_hours(runner):
    with patch("manage.db") as mock_db, patch("manage.actions") as mock_actions:
        mock_db.query_one.return_value = _admin()
        mock_actions.grant_access.return_value = {
            "key_id": KEY_ID, "server_id": SERVER_ID,
            "expires_at": datetime.now(tz=timezone.utc),
        }
        result = runner.invoke(manage.cli, [
            "access", "grant",
            "--key", FINGERPRINT, "--server", HOSTNAME,
            "--hours", "8", "--reason", "maintenance",
        ])
        assert result.exit_code == 0
        mock_actions.grant_access.assert_called_once()


def test_manage_access_approve(runner):
    with patch("manage.db") as mock_db, patch("manage.actions") as mock_actions:
        mock_db.query_one.return_value = _admin()
        result = runner.invoke(manage.cli, ["access", "approve", REQUEST_ID])
        assert result.exit_code == 0
        mock_actions.approve_request.assert_called_once_with(REQUEST_ID, ADMIN_ID)


def test_manage_access_reject(runner):
    with patch("manage.db") as mock_db, patch("manage.actions") as mock_actions:
        mock_db.query_one.return_value = _admin()
        result = runner.invoke(manage.cli, ["access", "reject", REQUEST_ID])
        assert result.exit_code == 0
        mock_actions.reject_request.assert_called_once_with(REQUEST_ID, ADMIN_ID)


def test_manage_access_revoke(runner):
    with patch("manage.db") as mock_db, patch("manage.actions") as mock_actions:
        mock_db.query_one.return_value = _admin()
        result = runner.invoke(manage.cli, ["access", "revoke", REQUEST_ID])
        assert result.exit_code == 0
        mock_actions.revoke_request.assert_called_once_with(REQUEST_ID, ADMIN_ID)


# ---------------------------------------------------------------------------
# admin
# ---------------------------------------------------------------------------

def test_manage_admin_list(runner):
    with patch("manage.db") as mock_db:
        mock_db.query.return_value = [{"username": "admin", "email": "a@b.c", "role": "sysadmin", "is_active": True}]
        result = runner.invoke(manage.cli, ["admin", "list"])
        assert result.exit_code == 0
        assert "admin" in result.output


def test_manage_admin_add(runner):
    with patch("manage.db") as mock_db, patch("manage.actions") as mock_actions:
        mock_db.query_one.return_value = _admin()
        mock_actions.add_admin.return_value = {"id": ADMIN_ID}
        result = runner.invoke(manage.cli, [
            "admin", "add", "--username", "newuser", "--email", "new@example.com"
        ])
        assert result.exit_code == 0
        mock_actions.add_admin.assert_called_once_with("newuser", "new@example.com", ADMIN_ID)


def test_manage_admin_disable(runner):
    with patch("manage.db") as mock_db, patch("manage.actions") as mock_actions:
        mock_db.query_one.return_value = _admin()
        result = runner.invoke(manage.cli, ["admin", "disable", "someuser"])
        assert result.exit_code == 0
        mock_actions.disable_admin.assert_called_once_with("someuser", ADMIN_ID)


# ---------------------------------------------------------------------------
# audit
# ---------------------------------------------------------------------------

def test_manage_audit_list(runner):
    with patch("manage.db") as mock_db:
        mock_db.query.return_value = []
        result = runner.invoke(manage.cli, ["audit", "list"])
        assert result.exit_code == 0


def test_manage_audit_list_with_filters(runner):
    with patch("manage.db") as mock_db:
        mock_db.query.return_value = []
        result = runner.invoke(manage.cli, [
            "audit", "list", "--server", HOSTNAME, "--action", "KEY_REVOKED"
        ])
        assert result.exit_code == 0
        sql = mock_db.query.call_args[0][0]
        assert "hostname" in sql or "action" in sql


# ---------------------------------------------------------------------------
# system
# ---------------------------------------------------------------------------

def test_manage_system_status(runner):
    with patch("manage.db") as mock_db:
        mock_db.query_one.side_effect = [
            {"n": 3}, {"n": 1}, {"n": 10}, None
        ]
        result = runner.invoke(manage.cli, ["system", "status"])
        assert result.exit_code == 0
        assert "Serveurs actifs" in result.output


def test_manage_system_report(runner):
    with patch("manage.db") as mock_db:
        mock_db.query.return_value = []
        result = runner.invoke(manage.cli, ["system", "report"])
        assert result.exit_code == 0
        assert "conformes" in result.output


# ---------------------------------------------------------------------------
# --help disponible sur chaque commande
# ---------------------------------------------------------------------------

def test_manage_help_available(runner):
    result = runner.invoke(manage.cli, ["--help"])
    assert result.exit_code == 0
    assert "Usage" in result.output


def test_manage_servers_help(runner):
    result = runner.invoke(manage.cli, ["servers", "--help"])
    assert result.exit_code == 0


def test_manage_keys_help(runner):
    result = runner.invoke(manage.cli, ["keys", "--help"])
    assert result.exit_code == 0
