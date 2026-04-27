import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import alerts


def _make_recipients(*emails):
    return [{"email": e} for e in emails]


# ---------------------------------------------------------------------------
# CRITICAL — envoie un email via msmtp pour chaque destinataire éligible
# ---------------------------------------------------------------------------

def test_alerts_critical_sends_to_single_recipient(mock_smtp):
    with patch("alerts.db") as mock_db:
        mock_db.query.return_value = _make_recipients("admin@example.com")
        alerts.send_alert("CRITICAL", "Cle inconnue detectee", "Fingerprint: SHA256:abc")
    mock_smtp.assert_called_once()
    args = mock_smtp.call_args[0][0]
    assert "msmtp" in args
    assert "admin@example.com" in args


def test_alerts_critical_sends_to_multiple_recipients(mock_smtp):
    with patch("alerts.db") as mock_db:
        mock_db.query.return_value = _make_recipients("admin@example.com", "ops@example.com")
        alerts.send_alert("CRITICAL", "Subject", "Body")
    assert mock_smtp.call_count == 2
    all_recipients = [c[0][0] for c in mock_smtp.call_args_list]
    assert any("admin@example.com" in r for r in all_recipients)
    assert any("ops@example.com" in r for r in all_recipients)


def test_alerts_critical_no_recipients_sends_nothing(mock_smtp):
    with patch("alerts.db") as mock_db:
        mock_db.query.return_value = []
        alerts.send_alert("CRITICAL", "Subject", "Body")
    mock_smtp.assert_not_called()


def test_alerts_critical_message_contains_level(mock_smtp):
    with patch("alerts.db") as mock_db:
        mock_db.query.return_value = _make_recipients("admin@example.com")
        alerts.send_alert("CRITICAL", "Test subject", "Test body")
    msg = mock_smtp.call_args[1]["input"]
    assert "CRITICAL" in msg
    assert "Test subject" in msg
    assert "Test body" in msg


def test_alerts_critical_sets_high_priority(mock_smtp):
    with patch("alerts.db") as mock_db:
        mock_db.query.return_value = _make_recipients("admin@example.com")
        alerts.send_alert("CRITICAL", "Urgent", "Body")
    msg = mock_smtp.call_args[1]["input"]
    assert "X-Priority: 1" in msg


def test_alerts_critical_to_header_matches_recipient(mock_smtp):
    with patch("alerts.db") as mock_db:
        mock_db.query.return_value = _make_recipients("alice@example.com")
        alerts.send_alert("CRITICAL", "Subject", "Body")
    msg = mock_smtp.call_args[1]["input"]
    assert "To: alice@example.com" in msg


# ---------------------------------------------------------------------------
# WARNING — envoie un email via msmtp
# ---------------------------------------------------------------------------

def test_alerts_warning_sends_email(mock_smtp):
    with patch("alerts.db") as mock_db:
        mock_db.query.return_value = _make_recipients("admin@example.com")
        alerts.send_alert("WARNING", "Cle expirant bientot", "Expires dans 2 jours")
    mock_smtp.assert_called_once()


def test_alerts_warning_message_contains_level(mock_smtp):
    with patch("alerts.db") as mock_db:
        mock_db.query.return_value = _make_recipients("admin@example.com")
        alerts.send_alert("WARNING", "Expiry warning", "Details")
    msg = mock_smtp.call_args[1]["input"]
    assert "WARNING" in msg


def test_alerts_warning_sets_normal_priority(mock_smtp):
    with patch("alerts.db") as mock_db:
        mock_db.query.return_value = _make_recipients("admin@example.com")
        alerts.send_alert("WARNING", "Warn", "Body")
    msg = mock_smtp.call_args[1]["input"]
    assert "X-Priority: 3" in msg


# ---------------------------------------------------------------------------
# INFO — log uniquement, pas d'email
# ---------------------------------------------------------------------------

def test_alerts_info_does_not_send_email(mock_smtp):
    alerts.send_alert("INFO", "Scan completed", "3 keys scanned")
    mock_smtp.assert_not_called()


def test_alerts_info_unknown_level_does_not_send_email(mock_smtp):
    alerts.send_alert("DEBUG", "Debug message", "details")
    mock_smtp.assert_not_called()


# ---------------------------------------------------------------------------
# Robustesse — msmtp manquant ou erreur
# ---------------------------------------------------------------------------

def test_alerts_msmtp_not_found_does_not_raise():
    with patch("alerts.db") as mock_db:
        mock_db.query.return_value = _make_recipients("admin@example.com")
        with patch("subprocess.run", side_effect=FileNotFoundError("msmtp not found")):
            alerts.send_alert("CRITICAL", "Test", "Body")  # must not raise


def test_alerts_msmtp_nonzero_exit_does_not_raise(mock_smtp):
    mock_smtp.return_value = MagicMock(returncode=1, stderr="connection refused", stdout="")
    with patch("alerts.db") as mock_db:
        mock_db.query.return_value = _make_recipients("admin@example.com")
        alerts.send_alert("CRITICAL", "Test", "Body")  # must not raise


def test_alerts_message_contains_footer(mock_smtp):
    with patch("alerts.db") as mock_db:
        mock_db.query.return_value = _make_recipients("admin@example.com")
        alerts.send_alert("CRITICAL", "Subject", "Body")
    msg = mock_smtp.call_args[1]["input"]
    assert "ssh-access-manager" in msg


def test_alerts_queries_only_eligible_recipients(mock_smtp):
    with patch("alerts.db") as mock_db:
        mock_db.query.return_value = []
        alerts.send_alert("CRITICAL", "Subject", "Body")
        query_sql = mock_db.query.call_args[0][0]
    assert "receive_alerts" in query_sql
    assert "is_active" in query_sql


# ---------------------------------------------------------------------------
# send_test_email
# ---------------------------------------------------------------------------

def test_alerts_send_test_email_calls_msmtp(mock_smtp):
    mock_smtp.return_value = MagicMock(returncode=0, stderr="", stdout="")
    alerts.send_test_email("user@example.com")
    mock_smtp.assert_called_once()
    args = mock_smtp.call_args[0][0]
    assert "msmtp" in args
    assert "user@example.com" in args


def test_alerts_send_test_email_message_contains_test_subject(mock_smtp):
    mock_smtp.return_value = MagicMock(returncode=0, stderr="", stdout="")
    alerts.send_test_email("user@example.com")
    msg = mock_smtp.call_args[1]["input"]
    assert "TEST" in msg
    assert "ssh-access-manager" in msg


def test_alerts_send_test_email_raises_on_msmtp_error(mock_smtp):
    mock_smtp.return_value = MagicMock(returncode=1, stderr="connection refused", stdout="")
    with pytest.raises(RuntimeError, match="connection refused"):
        alerts.send_test_email("user@example.com")


def test_alerts_send_test_email_raises_on_msmtp_not_found():
    with patch("subprocess.run", side_effect=FileNotFoundError("msmtp not found")):
        with pytest.raises(FileNotFoundError):
            alerts.send_test_email("user@example.com")
