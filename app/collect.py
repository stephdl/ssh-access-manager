"""
collect.py — orchestration du scan SSH complet.
Appelee par cron et via manage.py / web.py.
"""
import base64
import hashlib
import json
import os

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
    Returns a dict or None if the line is malformed.
    """
    parts = line.split("\t", 1)
    if len(parts) != 2:
        return None
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
            key_size_bits = (len(raw) - 11) * 8 // 10
        except Exception:
            pass

    try:
        fingerprint = _compute_fingerprint(key_b64)
    except Exception:
        return None

    return {
        "key_type": key_type,
        "key_b64": key_b64,
        "public_key": public_key,
        "fingerprint": fingerprint,
        "comment": comment,
        "key_size_bits": key_size_bits,
    }


def scan_server(server: dict) -> dict:
    """
    Scan one server: ensure scripts, collect keys, reconcile with DB.
    Returns a result dict with counts and optional error.
    """
    hostname = server["hostname"]
    ip = server["ip_address"]
    server_id = server["id"]
    result = {"hostname": hostname, "new": 0, "disappeared": 0, "known": 0, "error": None}

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
            f"[ssh-access-manager] Scan echoue sur {hostname}",
            f"Serveur: {hostname}\nErreur: {exc}",
        )
        return result

    collected_fps: set[str] = set()

    for line in raw_lines:
        parsed = _parse_key_line(line)
        if not parsed:
            continue

        fp = parsed["fingerprint"]
        collected_fps.add(fp)

        existing_key = db.query_one(
            "SELECT id FROM ssh_keys WHERE fingerprint = %s", (fp,)
        )

        if not existing_key:
            # Scenario 3 — unknown key present on server but absent from DB
            actions.handle_unknown_key(
                parsed["key_type"],
                parsed["key_size_bits"],
                parsed["public_key"],
                fp,
                parsed["comment"],
                server_id,
                hostname,
            )
            result["new"] += 1
        else:
            db.execute(
                "UPDATE ssh_keys SET last_seen = now() WHERE id = %s",
                (existing_key["id"],),
            )
            auth = db.query_one(
                """
                SELECT status FROM key_authorizations
                WHERE key_id = %s AND server_id = %s
                """,
                (existing_key["id"], server_id),
            )
            if not auth:
                db.execute(
                    """
                    INSERT INTO key_authorizations (key_id, server_id, status)
                    VALUES (%s, %s, 'PENDING_REVIEW')
                    ON CONFLICT (key_id, server_id) DO NOTHING
                    """,
                    (existing_key["id"], server_id),
                )
                result["new"] += 1
            else:
                result["known"] += 1

    # Scenario 2 — detect ACTIVE keys that disappeared from server
    active_on_server = db.query(
        """
        SELECT ka.key_id, sk.fingerprint
        FROM key_authorizations ka
        JOIN ssh_keys sk ON sk.id = ka.key_id
        WHERE ka.server_id = %s AND ka.status = 'ACTIVE'
        """,
        (server_id,),
    )
    for row in active_on_server:
        if row["fingerprint"] not in collected_fps:
            actions.handle_disappeared_key(row["key_id"], server_id, hostname, ip=ip)
            result["disappeared"] += 1

    db.execute(
        """
        INSERT INTO audit_log (action, target_server, details)
        VALUES ('SCAN_COMPLETED', %s, %s::jsonb)
        """,
        (
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


def run_scan(hostname: str | None = None) -> list[dict]:
    """Scan all active servers, or a specific one if hostname is provided."""
    active_servers = servers_mod.get_active_servers()
    if hostname:
        active_servers = [s for s in active_servers if s["hostname"] == hostname]
    return [scan_server(s) for s in active_servers]


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
