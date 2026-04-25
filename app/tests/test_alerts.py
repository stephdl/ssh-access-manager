import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import alerts


# ---------------------------------------------------------------------------
# CRITICAL — envoie un email via msmtp
# ---------------------------------------------------------------------------

def test_alerts_critical_sends_email(mock_smtp):
    alerts.send_alert("CRITICAL", "Cle inconnue detectee", "Fingerprint: SHA256:abc")
    mock_smtp.assert_called_once()
    args = mock_smtp.call_args[0][0]
    assert "msmtp" in args


def test_alerts_critical_uses_correct_recipient(mock_smtp):
    with patch.dict(os.environ, {"SMTP_TO": "admin@example.com"}):
        import importlib
        importlib.reload(alerts)
        alerts.send_alert("CRITICAL", "Subject", "Body")
    args = mock_smtp.call_args[0][0]
    assert "admin@example.com" in args


def test_alerts_critical_message_contains_level(mock_smtp):
    alerts.send_alert("CRITICAL", "Test subject", "Test body")
    msg = mock_smtp.call_args[1]["input"]
    assert "CRITICAL" in msg
    assert "Test subject" in msg
    assert "Test body" in msg


def test_alerts_critical_sets_high_priority(mock_smtp):
    alerts.send_alert("CRITICAL", "Urgent", "Body")
    msg = mock_smtp.call_args[1]["input"]
    assert "X-Priority: 1" in msg


# ---------------------------------------------------------------------------
# WARNING — envoie un email via msmtp
# ---------------------------------------------------------------------------

def test_alerts_warning_sends_email(mock_smtp):
    alerts.send_alert("WARNING", "Cle expirant bientot", "Expires dans 2 jours")
    mock_smtp.assert_called_once()


def test_alerts_warning_message_contains_level(mock_smtp):
    alerts.send_alert("WARNING", "Expiry warning", "Details")
    msg = mock_smtp.call_args[1]["input"]
    assert "WARNING" in msg


def test_alerts_warning_sets_normal_priority(mock_smtp):
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
    with patch("subprocess.run", side_effect=FileNotFoundError("msmtp not found")):
        alerts.send_alert("CRITICAL", "Test", "Body")  # must not raise


def test_alerts_msmtp_nonzero_exit_does_not_raise(mock_smtp):
    mock_smtp.return_value = MagicMock(returncode=1, stderr="connection refused", stdout="")
    alerts.send_alert("CRITICAL", "Test", "Body")  # must not raise


def test_alerts_message_contains_footer(mock_smtp):
    alerts.send_alert("CRITICAL", "Subject", "Body")
    msg = mock_smtp.call_args[1]["input"]
    assert "ssh-access-manager" in msg
