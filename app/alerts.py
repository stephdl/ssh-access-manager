"""
alerts.py — envoi d'emails via msmtp.

Niveaux :
  CRITICAL  → email immediat
  WARNING   → email immediat (anti-spam 24h gere par actions.py)
  INFO      → log uniquement, pas d'email
"""
import logging
import os
import subprocess

SMTP_TO = os.environ.get("SMTP_TO", "admin@example.com")
SMTP_FROM = os.environ.get("SMTP_FROM", "ssh-manager@example.com")

_EMAIL_LEVELS = {"CRITICAL", "WARNING"}

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)


def _build_message(level: str, subject: str, body: str) -> str:
    priority = "1 (Highest)" if level == "CRITICAL" else "3 (Normal)"
    return (
        f"From: {SMTP_FROM}\n"
        f"To: {SMTP_TO}\n"
        f"Subject: [{level}] {subject}\n"
        f"X-Priority: {priority}\n"
        f"\n"
        f"{body}\n"
        f"\n--\nssh-access-manager\n"
    )


def send_alert(level: str, subject: str, body: str) -> None:
    """
    Send an alert at the given level.
    CRITICAL/WARNING → email via msmtp.
    INFO             → log only, no email.
    """
    log.info("[%s] %s", level, subject)

    if level not in _EMAIL_LEVELS:
        return

    message = _build_message(level, subject, body)
    try:
        result = subprocess.run(
            ["msmtp", "--", SMTP_TO],
            input=message,
            text=True,
            capture_output=True,
        )
        if result.returncode != 0:
            log.error("msmtp failed (rc=%d): %s", result.returncode, result.stderr)
    except FileNotFoundError:
        log.error("msmtp not found — alert not sent: %s", subject)
    except Exception as exc:
        log.error("Failed to send alert: %s", exc)
