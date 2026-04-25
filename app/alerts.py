"""
alerts.py — envoi d'emails via msmtp.
Stub minimal — implementation complete dans Issue #11.
"""
import os
import subprocess


SMTP_TO = os.environ.get("SMTP_TO", "admin@example.com")
SMTP_FROM = os.environ.get("SMTP_FROM", "ssh-manager@example.com")


def send_alert(level: str, subject: str, body: str) -> None:
    """Send an email alert via msmtp. level: CRITICAL | WARNING | INFO."""
    message = f"From: {SMTP_FROM}\nTo: {SMTP_TO}\nSubject: {subject}\n\n{body}\n"
    subprocess.run(
        ["msmtp", "--", SMTP_TO],
        input=message,
        text=True,
        capture_output=True,
    )
