"""
alerts.py — envoi d'emails via msmtp.

Niveaux :
  CRITICAL  → email immediat
  WARNING   → email immediat (anti-spam 24h gere par actions.py)
  INFO      → log uniquement, pas d'email

Les destinataires sont les administrateurs actifs avec receive_alerts=true.
"""
import logging
import os
import subprocess

import db

SMTP_FROM = os.environ.get("SMTP_FROM", "ssh-manager@example.com")

_EMAIL_LEVELS = {"CRITICAL", "WARNING"}

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)


def _get_alert_recipients() -> list[str]:
    rows = db.query(
        "SELECT email FROM administrators WHERE receive_alerts = true AND is_active = true AND email IS NOT NULL"
    )
    return [r["email"] for r in rows]


def _build_message(level: str, subject: str, body: str, to_email: str) -> str:
    priority = "1 (Highest)" if level == "CRITICAL" else "3 (Normal)"
    return (
        f"From: {SMTP_FROM}\n"
        f"To: {to_email}\n"
        f"Subject: [{level}] {subject}\n"
        f"X-Priority: {priority}\n"
        f"\n"
        f"{body}\n"
        f"\n--\nssh-access-manager\n"
    )


def send_test_email(to_email: str) -> None:
    """Send a test email to verify SMTP configuration. Raises on failure."""
    message = (
        f"From: {SMTP_FROM}\n"
        f"To: {to_email}\n"
        f"Subject: [TEST] ssh-access-manager SMTP test\n"
        f"X-Priority: 3 (Normal)\n"
        f"\n"
        f"This is a test email sent from ssh-access-manager.\n"
        f"If you received this message, your SMTP configuration is working correctly.\n"
        f"\n--\nssh-access-manager\n"
    )
    result = subprocess.run(
        ["msmtp", "--", to_email],
        input=message,
        text=True,
        capture_output=True,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or f"msmtp exited with code {result.returncode}")


def send_alert(level: str, subject: str, body: str) -> None:
    """
    Send an alert at the given level.
    CRITICAL/WARNING → email via msmtp to all admins with receive_alerts=true.
    INFO             → log only, no email.
    """
    log.info("[%s] %s", level, subject)

    if level not in _EMAIL_LEVELS:
        return

    recipients = _get_alert_recipients()
    if not recipients:
        log.warning("No alert recipients configured — alert not sent: %s", subject)
        return

    for to_email in recipients:
        message = _build_message(level, subject, body, to_email)
        try:
            result = subprocess.run(
                ["msmtp", "--", to_email],
                input=message,
                text=True,
                capture_output=True,
            )
            if result.returncode != 0:
                log.error("msmtp failed for %s (rc=%d): %s", to_email, result.returncode, result.stderr)
        except FileNotFoundError:
            log.error("msmtp not found — alert not sent: %s", subject)
            return
        except Exception as exc:
            log.error("Failed to send alert to %s: %s", to_email, exc)
