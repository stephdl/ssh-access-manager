"""
expire.py — gestion des expirations de cles SSH.
Appelee par cron a chaque cycle (SCAN_INTERVAL_HOURS).

warn_expiring_keys() : alerte J-7 et J-2 avec anti-spam 24h
expire_keys()        : scenario 4 — revocation automatique a echeance
"""
import json

import actions
import alerts
import db
import ssh


def warn_expiring_keys() -> int:
    """
    Find ACTIVE keys expiring within expire_warn_days or expire_warn_days_2 days.
    Sends one grouped WARNING email for all keys needing a warning (24h anti-spam via actions).
    Returns the number of warnings logged.
    """
    warn_days_row = db.query_one("SELECT value FROM settings WHERE key = 'expire_warn_days'")
    warn_days_2_row = db.query_one("SELECT value FROM settings WHERE key = 'expire_warn_days_2'")
    warn_days = int(warn_days_row["value"]) if warn_days_row else 7
    warn_days_2 = int(warn_days_2_row["value"]) if warn_days_2_row else 2

    rows = db.query(
        """
        SELECT ka.key_id, ka.server_id, ka.expires_at
        FROM key_authorizations ka
        WHERE ka.status = 'ACTIVE'
          AND ka.expires_at IS NOT NULL
          AND ka.expires_at > now()
          AND ka.expires_at <= now() + make_interval(days => %s)
        """,
        (max(warn_days, warn_days_2),),
    )
    warnings = []
    for row in rows:
        info = actions.warn_expiring_key(row["key_id"], row["server_id"], row["expires_at"])
        if info:
            warnings.append(info)
    if warnings:
        body_lines = ["=== Keys expiring soon ==="]
        for w in warnings:
            expires_at = w["expires_at"]
            expires_str = expires_at.strftime("%Y-%m-%d %H:%M UTC") if hasattr(expires_at, "strftime") else str(expires_at)
            body_lines.append(f"  {w['fingerprint']} — {w['hostname']} — expires {expires_str}")
        n = len(warnings)
        alerts.send_alert(
            "WARNING",
            f"[ssh-access-manager] {n} {'key' if n == 1 else 'keys'} expiring soon",
            "\n".join(body_lines),
        )
    return len(warnings)


def expire_keys() -> int:
    """
    Scenario 4 — revoke all ACTIVE keys whose expires_at < NOW().
    Calls sam-revoke on each server, sets EXPIRED + revoked_automatically=True.
    Returns the number of keys expired.
    """
    rows = db.query(
        """
        SELECT DISTINCT ka.key_id, ka.server_id, sk.fingerprint, s.hostname, s.ip_address, s.ssh_port
        FROM key_authorizations ka
        JOIN ssh_keys sk ON sk.id = ka.key_id
        JOIN servers s ON s.id = ka.server_id
        WHERE ka.status = 'ACTIVE'
          AND ka.expires_at IS NOT NULL
          AND ka.expires_at <= now()
        """,
        (),
    )
    expired = 0
    for row in rows:
        try:
            ssh.revoke_on_server(row["hostname"], row["fingerprint"], ip=row["ip_address"], port=row["ssh_port"])
        except Exception as exc:
            alerts.send_alert(
                "CRITICAL",
                f"[ssh-access-manager] Expired key revocation failed on {row['hostname']}",
                f"Fingerprint: {row['fingerprint']}\nError: {exc}",
            )
            continue

        db.execute(
            """
            UPDATE key_authorizations
            SET status = 'EXPIRED',
                revoked_at = now(),
                revoked_by = NULL,
                revoked_automatically = true,
                revocation_justification = 'Scheduled expiration reached'
            WHERE key_id = %s AND server_id = %s AND status = 'ACTIVE'
            """,
            (row["key_id"], row["server_id"]),
        )
        db.execute(
            """
            INSERT INTO audit_log (action, target_key, target_server, details)
            VALUES ('KEY_EXPIRED', %s, %s, %s::jsonb)
            """,
            (
                row["key_id"],
                row["server_id"],
                json.dumps({
                    "fingerprint": row["fingerprint"],
                    "hostname": row["hostname"],
                    "reason": "scheduled_expiration",
                }),
            ),
        )
        expired += 1
    return expired


def purge_old_audit_logs() -> int:
    """
    Delete audit_log entries older than audit_retention_days (default 365).
    Returns the count of deleted rows.
    """
    row = db.query_one("SELECT value FROM settings WHERE key = 'audit_retention_days'")
    retention_days = int(row["value"]) if row else 365
    result = db.query_one(
        """
        WITH deleted AS (
            DELETE FROM audit_log
            WHERE performed_at < NOW() - make_interval(days => %s)
            RETURNING id
        )
        SELECT count(*) AS cnt FROM deleted
        """,
        (retention_days,),
    )
    count = int(result["cnt"]) if result else 0
    if count:
        import logging
        logging.getLogger(__name__).info(
            "Purged %d audit log entries older than %d days", count, retention_days
        )
    return count


if __name__ == "__main__":
    warned = warn_expiring_keys()
    expired = expire_keys()
    purged = purge_old_audit_logs()
    print(f"expire.py: {warned} warnings sent, {expired} keys expired, {purged} audit entries purged")
