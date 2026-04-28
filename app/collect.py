"""
collect.py — orchestration du scan SSH complet.
Appelee par cron et via manage.py / web.py.
"""
import base64
import hashlib
import json
import os
import struct
from datetime import datetime, timezone

import actions
import alerts
import db
import servers as servers_mod
import ssh

SERVERS_YML = os.environ.get("SERVERS_YML", "/data/config/servers.yml")


def _compute_fingerprint(key_b64: str) -> str:
    raw = base64.b64decode(key_b64)
    digest = hashlib.sha256(raw).digest()
    b64 = base64.b64encode(digest).decode().rstrip("=")
    return f"SHA256:{b64}"


def _parse_key_line(line: str) -> dict | None:
    """
    Parse a sam-collect line: 'username\\tkey_type key_b64 [comment]'
    Returns a dict with unix_user or None if the line is malformed.
    """
    parts = line.split("\t", 1)
    if len(parts) != 2:
        return None
    unix_user = parts[0].strip()
    key_parts = parts[1].strip().split()
    if len(key_parts) < 2:
        return None

    key_type = key_parts[0]
    key_b64 = key_parts[1]
    comment = key_parts[2] if len(key_parts) > 2 else None
    public_key = parts[1].strip()

    key_size_bits = None
    if key_type == "ssh-rsa":
        try:
            raw = base64.b64decode(key_b64)
            # SSH wire format: 3 length-prefixed fields (key_type, exponent, modulus)
            # key size = bit length of the modulus (3rd field)
            offset = 0
            for _ in range(3):
                length = struct.unpack(">I", raw[offset:offset + 4])[0]
                offset += 4
                data = raw[offset:offset + length]
                offset += length
            key_size_bits = int.from_bytes(data, "big").bit_length()
        except Exception:
            pass

    try:
        fingerprint = _compute_fingerprint(key_b64)
    except Exception:
        return None

    return {
        "unix_user": unix_user,
        "key_type": key_type,
        "key_b64": key_b64,
        "public_key": public_key,
        "fingerprint": fingerprint,
        "comment": comment,
        "key_size_bits": key_size_bits,
    }


def scan_server(server: dict, admin_id: str | None = None) -> dict:
    """
    Scan one server: ensure scripts, collect keys, reconcile with DB.
    Returns a result dict with counts and optional error.
    admin_id is stored in performed_by when the scan is triggered manually.
    """
    hostname = server["hostname"]
    ip = server["ip_address"]
    server_id = server["id"]
    result = {"hostname": hostname, "new": 0, "disappeared": 0, "known": 0, "error": None, "anomalies": []}

    try:
        ssh.ensure_scripts(hostname, server_id, ip=ip)
        raw_lines = ssh.collect_keys(hostname, ip=ip)
    except Exception as exc:
        result["error"] = str(exc)
        db.execute(
            """
            INSERT INTO audit_log (action, target_server, details)
            VALUES ('SCAN_FAILED', %s, %s::jsonb)
            """,
            (server_id, json.dumps({"hostname": hostname, "error": str(exc)})),
        )
        alerts.send_alert(
            "CRITICAL",
            f"[ssh-access-manager] Scan failed on {hostname}",
            f"Server: {hostname}\nError: {exc}",
        )
        return result

    # Track (fingerprint, unix_user) pairs seen on the server
    collected_pairs: set[tuple[str, str]] = set()

    for line in raw_lines:
        parsed = _parse_key_line(line)
        if not parsed:
            continue

        fp = parsed["fingerprint"]
        unix_user = parsed["unix_user"]
        collected_pairs.add((fp, unix_user))

        existing_key = db.query_one(
            "SELECT id FROM ssh_keys WHERE fingerprint = %s", (fp,)
        )

        if not existing_key:
            # Scenario 3 — unknown key present on server but absent from DB
            info = actions.handle_unknown_key(
                parsed["key_type"],
                parsed["key_size_bits"],
                parsed["public_key"],
                fp,
                parsed["comment"],
                server_id,
                hostname,
                unix_user=unix_user,
            )
            result["anomalies"].append(info)
            result["new"] += 1
        else:
            db.execute(
                "UPDATE ssh_keys SET last_seen = now(), key_size_bits = %s WHERE id = %s",
                (parsed["key_size_bits"], existing_key["id"]),
            )
            auth = db.query_one(
                """
                SELECT status FROM key_authorizations
                WHERE key_id = %s AND server_id = %s AND unix_user = %s
                """,
                (existing_key["id"], server_id, unix_user),
            )
            if not auth:
                db.execute(
                    """
                    INSERT INTO key_authorizations (key_id, server_id, unix_user, status)
                    VALUES (%s, %s, %s, 'PENDING_REVIEW')
                    ON CONFLICT (key_id, server_id, unix_user) DO NOTHING
                    """,
                    (existing_key["id"], server_id, unix_user),
                )
                result["new"] += 1
            elif auth["status"] in ("REVOKED", "EXPIRED"):
                # Scenario 5 — revoked/expired key reappeared on the server
                info = actions.handle_reappeared_key(
                    existing_key["id"], server_id, hostname, unix_user=unix_user
                )
                result["anomalies"].append(info)
                result["new"] += 1
            else:
                result["known"] += 1

    # Scenario 2 — detect ACTIVE (fp, unix_user) pairs that disappeared from server
    active_on_server = db.query(
        """
        SELECT ka.key_id, ka.unix_user, sk.fingerprint
        FROM key_authorizations ka
        JOIN ssh_keys sk ON sk.id = ka.key_id
        WHERE ka.server_id = %s AND ka.status = 'ACTIVE'
        """,
        (server_id,),
    )
    for row in active_on_server:
        if (row["fingerprint"], row["unix_user"]) not in collected_pairs:
            info = actions.handle_disappeared_key(
                row["key_id"], server_id, hostname, ip=ip, unix_user=row["unix_user"]
            )
            result["anomalies"].append(info)
            result["disappeared"] += 1

    # Collect SSH sessions (non-fatal)
    try:
        ssh.collect_sessions_on_server(hostname, server_id, ip=ip)
    except Exception:
        pass

    db.execute(
        """
        INSERT INTO audit_log (action, performed_by, target_server, details)
        VALUES ('SCAN_COMPLETED', %s, %s, %s::jsonb)
        """,
        (
            admin_id,
            server_id,
            json.dumps({
                "hostname": hostname,
                "new": result["new"],
                "disappeared": result["disappeared"],
                "known": result["known"],
            }),
        ),
    )
    return result


def _should_run() -> bool:
    row = db.query_one("SELECT value FROM settings WHERE key = 'scan_interval_hours'")
    interval_hours = int(row["value"]) if row else 4
    last = db.query_one(
        "SELECT MAX(performed_at) AS t FROM audit_log WHERE action = 'SCAN_COMPLETED'"
    )
    if not last or not last["t"]:
        return True
    elapsed = (datetime.now(tz=timezone.utc) - last["t"]).total_seconds()
    return elapsed >= interval_hours * 3600


def run_scan(hostname: str | None = None, admin_id: str | None = None) -> list[dict]:
    """Scan all active servers (or one). Sends one grouped CRITICAL email if any anomalies."""
    if hostname is None and not _should_run():
        return []
    active_servers = servers_mod.get_active_servers()
    if hostname:
        active_servers = [s for s in active_servers if s["hostname"] == hostname]
    results = [scan_server(s, admin_id=admin_id) for s in active_servers]

    all_anomalies = [a for r in results for a in r.get("anomalies", [])]
    if all_anomalies:
        unknowns = [a for a in all_anomalies if a["type"] == "unknown"]
        disappeared = [a for a in all_anomalies if a["type"] == "disappeared"]
        reappeared = [a for a in all_anomalies if a["type"] == "reappeared"]
        body_lines = []
        if unknowns:
            body_lines.append(f"=== Unknown keys ({len(unknowns)}) ===")
            for a in unknowns:
                body_lines.append(
                    f"  {a['hostname']} — {a['fingerprint']} ({a['key_type']}, {a['comment'] or '—'}) → PENDING_REVIEW"
                )
        if disappeared:
            if body_lines:
                body_lines.append("")
            body_lines.append(f"=== Out-of-system revocations ({len(disappeared)}) ===")
            for a in disappeared:
                body_lines.append(f"  {a['hostname']} — {a['fingerprint']} → REVOKED automatically")
        if reappeared:
            if body_lines:
                body_lines.append("")
            body_lines.append(f"=== Revoked/expired keys reappeared ({len(reappeared)}) ===")
            for a in reappeared:
                body_lines.append(f"  {a['hostname']} — {a['fingerprint']} → PENDING_REVIEW (was REVOKED/EXPIRED)")
        n = len(all_anomalies)
        alerts.send_alert(
            "CRITICAL",
            f"[ssh-access-manager] Scan — {n} {'anomaly' if n == 1 else 'anomalies'} detected",
            "\n".join(body_lines),
        )
    return results


if __name__ == "__main__":
    results = run_scan()
    for r in results:
        if r["error"]:
            print(f"FAILED  {r['hostname']}: {r['error']}")
        else:
            print(
                f"OK      {r['hostname']}: "
                f"{r['new']} new, {r['disappeared']} disappeared, {r['known']} known"
            )
