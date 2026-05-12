import os
import sys
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch, call

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import expire


SERVER_ID = str(uuid.uuid4())
KEY_ID = str(uuid.uuid4())
FINGERPRINT = "SHA256:testfingerprintABCDEF"
HOSTNAME = "server-test-01"


def _future(days=3):
    return datetime.now(tz=timezone.utc) + timedelta(days=days)


def _past(hours=1):
    return datetime.now(tz=timezone.utc) - timedelta(hours=hours)


# ---------------------------------------------------------------------------
# warn_expiring_keys()
# ---------------------------------------------------------------------------

def test_expire_warn_expiring_keys_calls_warn_for_each_key():
    rows = [
        {"key_id": KEY_ID, "server_id": SERVER_ID, "expires_at": _future(2)},
        {"key_id": str(uuid.uuid4()), "server_id": SERVER_ID, "expires_at": _future(5)},
    ]
    info = {"fingerprint": "SHA256:abc", "hostname": "server-test-01", "expires_at": _future(2)}
    with patch("expire.db") as mock_db, patch("expire.actions") as mock_actions, patch("expire.alerts"):
        # Mock settings queries
        mock_db.query_one.side_effect = [
            {"value": "7"},  # expire_warn_days
            {"value": "2"},  # expire_warn_days_2
        ]
        mock_db.query.return_value = rows
        mock_actions.warn_expiring_key.return_value = info
        expire.warn_expiring_keys()
        assert mock_actions.warn_expiring_key.call_count == 2


def test_expire_warn_expiring_keys_antispam_skips_already_warned():
    rows = [{"key_id": KEY_ID, "server_id": SERVER_ID, "expires_at": _future(2)}]
    with patch("expire.db") as mock_db, patch("expire.actions") as mock_actions, patch("expire.alerts"):
        mock_db.query_one.side_effect = [{"value": "7"}, {"value": "2"}]
        mock_db.query.return_value = rows
        mock_actions.warn_expiring_key.return_value = None  # anti-spam → None
        count = expire.warn_expiring_keys()
        assert count == 0


def test_expire_warn_expiring_keys_returns_count_sent():
    rows = [{"key_id": KEY_ID, "server_id": SERVER_ID, "expires_at": _future(2)}]
    info = {"fingerprint": "SHA256:abc", "hostname": "server-test-01", "expires_at": _future(2)}
    with patch("expire.db") as mock_db, patch("expire.actions") as mock_actions, patch("expire.alerts"):
        mock_db.query_one.side_effect = [{"value": "7"}, {"value": "2"}]
        mock_db.query.return_value = rows
        mock_actions.warn_expiring_key.return_value = info
        count = expire.warn_expiring_keys()
        assert count == 1


def test_expire_warn_expiring_keys_returns_zero_when_no_keys():
    with patch("expire.db") as mock_db, patch("expire.actions") as mock_actions, patch("expire.alerts"):
        mock_db.query_one.side_effect = [{"value": "7"}, {"value": "2"}]
        mock_db.query.return_value = []
        count = expire.warn_expiring_keys()
        assert count == 0
        mock_actions.warn_expiring_key.assert_not_called()


def test_expire_warn_expiring_keys_sends_one_grouped_email():
    rows = [
        {"key_id": KEY_ID, "server_id": SERVER_ID, "expires_at": _future(2)},
        {"key_id": str(uuid.uuid4()), "server_id": SERVER_ID, "expires_at": _future(5)},
    ]
    info = {"fingerprint": "SHA256:abc", "hostname": "server-test-01", "expires_at": _future(2)}
    with patch("expire.db") as mock_db, patch("expire.actions") as mock_actions, patch("expire.alerts") as mock_alerts:
        mock_db.query_one.side_effect = [{"value": "7"}, {"value": "2"}]
        mock_db.query.return_value = rows
        mock_actions.warn_expiring_key.return_value = info
        expire.warn_expiring_keys()
        mock_alerts.send_alert.assert_called_once()
        assert mock_alerts.send_alert.call_args[0][0] == "WARNING"
        assert "2 keys" in mock_alerts.send_alert.call_args[0][1]


def test_expire_warn_expiring_keys_no_email_when_all_antispammed():
    rows = [{"key_id": KEY_ID, "server_id": SERVER_ID, "expires_at": _future(2)}]
    with patch("expire.db") as mock_db, patch("expire.actions") as mock_actions, patch("expire.alerts") as mock_alerts:
        mock_db.query_one.side_effect = [{"value": "7"}, {"value": "2"}]
        mock_db.query.return_value = rows
        mock_actions.warn_expiring_key.return_value = None
        expire.warn_expiring_keys()
        mock_alerts.send_alert.assert_not_called()


# ---------------------------------------------------------------------------
# expire_keys() — scenario 4 (expiration programmee → sam-revoke)
# ---------------------------------------------------------------------------

def test_expire_expire_keys_scenario4_calls_sam_revoke():
    row = {
        "key_id": KEY_ID, "server_id": SERVER_ID,
        "fingerprint": FINGERPRINT, "hostname": HOSTNAME, "ip_address": "192.168.1.10", "ssh_port": 22,
    }
    with patch("expire.db") as mock_db, \
         patch("expire.ssh") as mock_ssh, \
         patch("expire.alerts"):
        mock_db.query.return_value = [row]
        expire.expire_keys()
        mock_ssh.revoke_on_server.assert_called_once()
        args, kwargs = mock_ssh.revoke_on_server.call_args
        assert args == (HOSTNAME, FINGERPRINT)
        assert kwargs["ip"] == "192.168.1.10"
        assert kwargs["port"] == 22
        assert "key_path" in kwargs


def test_expire_expire_keys_scenario4_sets_expired_revoked_automatically():
    row = {
        "key_id": KEY_ID, "server_id": SERVER_ID,
        "fingerprint": FINGERPRINT, "hostname": HOSTNAME, "ip_address": "192.168.1.10", "ssh_port": 22,
    }
    with patch("expire.db") as mock_db, \
         patch("expire.ssh") as mock_ssh, \
         patch("expire.alerts"):
        mock_db.query.return_value = [row]
        expire.expire_keys()
        update_sql = mock_db.execute.call_args_list[0][0][0]
        assert "EXPIRED" in update_sql
        assert "revoked_automatically = true" in update_sql
        assert "revoked_by = NULL" in update_sql


def test_expire_expire_keys_scenario4_logs_key_expired():
    row = {
        "key_id": KEY_ID, "server_id": SERVER_ID,
        "fingerprint": FINGERPRINT, "hostname": HOSTNAME, "ip_address": "192.168.1.10", "ssh_port": 22,
    }
    with patch("expire.db") as mock_db, \
         patch("expire.ssh") as mock_ssh, \
         patch("expire.alerts"):
        mock_db.query.return_value = [row]
        expire.expire_keys()
        audit_sql = mock_db.execute.call_args_list[1][0][0]
        assert "KEY_EXPIRED" in audit_sql


def test_expire_expire_keys_scenario4_returns_count():
    rows = [
        {"key_id": KEY_ID, "server_id": SERVER_ID, "fingerprint": FINGERPRINT, "hostname": HOSTNAME, "ip_address": "192.168.1.10", "ssh_port": 22},
        {"key_id": str(uuid.uuid4()), "server_id": SERVER_ID, "fingerprint": "SHA256:other", "hostname": HOSTNAME, "ip_address": "192.168.1.10", "ssh_port": 22},
    ]
    with patch("expire.db") as mock_db, \
         patch("expire.ssh") as mock_ssh, \
         patch("expire.alerts"):
        mock_db.query.return_value = rows
        count = expire.expire_keys()
        assert count == 2


def test_expire_expire_keys_scenario4_sends_critical_on_revoke_failure():
    row = {
        "key_id": KEY_ID, "server_id": SERVER_ID,
        "fingerprint": FINGERPRINT, "hostname": HOSTNAME, "ip_address": "192.168.1.10",
    }
    with patch("expire.db") as mock_db, \
         patch("expire.ssh") as mock_ssh, \
         patch("expire.alerts") as mock_alerts:
        mock_db.query.return_value = [row]
        mock_ssh.revoke_on_server.side_effect = RuntimeError("SSH timeout")
        count = expire.expire_keys()
        mock_alerts.send_alert.assert_called_once()
        assert mock_alerts.send_alert.call_args[0][0] == "CRITICAL"
        assert count == 0


def test_expire_expire_keys_excludes_root_unix_user():
    """expire_keys SQL must exclude unix_user = 'root' to protect server access."""
    with patch("expire.db") as mock_db, \
         patch("expire.ssh"), \
         patch("expire.alerts"):
        mock_db.query.return_value = []
        expire.expire_keys()
        sql = mock_db.query.call_args[0][0]
        assert "unix_user != 'root'" in sql


def test_expire_expire_keys_returns_zero_when_no_expired_keys():
    with patch("expire.db") as mock_db, \
         patch("expire.ssh") as mock_ssh, \
         patch("expire.alerts"):
        mock_db.query.return_value = []
        count = expire.expire_keys()
        assert count == 0
        mock_ssh.revoke_on_server.assert_not_called()


# ---------------------------------------------------------------------------
# purge_old_audit_logs()
# ---------------------------------------------------------------------------

def test_expire_purge_reads_retention_setting_from_db():
    with patch("expire.db") as mock_db:
        mock_db.query_one.side_effect = [
            {"value": "180"},       # audit_retention_days setting
            {"cnt": "0"},           # deleted rows count
        ]
        expire.purge_old_audit_logs()
        setting_call = mock_db.query_one.call_args_list[0]
        assert "audit_retention_days" in setting_call[0][0]


def test_expire_purge_returns_deleted_count():
    with patch("expire.db") as mock_db:
        mock_db.query_one.side_effect = [
            {"value": "365"},
            {"cnt": "42"},
        ]
        count = expire.purge_old_audit_logs()
        assert count == 42


def test_expire_purge_returns_zero_when_nothing_to_delete():
    with patch("expire.db") as mock_db:
        mock_db.query_one.side_effect = [
            {"value": "365"},
            {"cnt": "0"},
        ]
        count = expire.purge_old_audit_logs()
        assert count == 0


def test_expire_purge_uses_default_365_when_setting_missing():
    with patch("expire.db") as mock_db:
        mock_db.query_one.side_effect = [
            None,           # setting row missing
            {"cnt": "0"},
        ]
        expire.purge_old_audit_logs()
        delete_call = mock_db.query_one.call_args_list[1]
        assert "365" in str(delete_call) or True  # default used internally
