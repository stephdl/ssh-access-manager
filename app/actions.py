"""
actions.py — logique metier partagee entre web.py (API) et manage.py (CLI).
Jamais de duplication entre les deux consommateurs.
"""
import json
from datetime import datetime, timedelta, timezone

import alerts
import db
import ssh


# ---------------------------------------------------------------------------
# Cles SSH
# ---------------------------------------------------------------------------

def validate_key(fingerprint: str, admin_id: str) -> dict:
    """PENDING_REVIEW → ACTIVE. Logs KEY_ADDED for each authorization."""
    key = db.query_one("SELECT id FROM ssh_keys WHERE fingerprint = %s", (fingerprint,))
    if not key:
        raise ValueError(f"Key not found: {fingerprint}")

    rows = db.query(
        """
        SELECT key_id, server_id FROM key_authorizations
        WHERE key_id = %s AND status = 'PENDING_REVIEW'
        """,
        (key["id"],),
    )
    if not rows:
        raise ValueError(f"No PENDING_REVIEW authorization for key: {fingerprint}")

    for row in rows:
        db.execute(
            """
            UPDATE key_authorizations
            SET status = 'ACTIVE', authorized_by = %s, authorized_at = now()
            WHERE key_id = %s AND server_id = %s
            """,
            (admin_id, row["key_id"], row["server_id"]),
        )
        db.execute(
            """
            INSERT INTO audit_log (action, performed_by, target_key, target_server)
            VALUES ('KEY_ADDED', %s, %s, %s)
            """,
            (admin_id, key["id"], row["server_id"]),
        )
    return key


def revoke_key(fingerprint: str, admin_id: str, reason: str) -> None:
    """
    Scenario 1 — revocation via le systeme.
    Calls sam-revoke on each active server, sets REVOKED, logs KEY_REVOKED.
    """
    key = db.query_one("SELECT id FROM ssh_keys WHERE fingerprint = %s", (fingerprint,))
    if not key:
        raise ValueError(f"Key not found: {fingerprint}")

    active_auths = db.query(
        """
        SELECT ka.server_id, s.hostname, s.ip_address
        FROM key_authorizations ka
        JOIN servers s ON s.id = ka.server_id
        WHERE ka.key_id = %s AND ka.status IN ('ACTIVE', 'PENDING_REVIEW')
        """,
        (key["id"],),
    )

    for auth in active_auths:
        ssh.revoke_on_server(auth["hostname"], fingerprint, ip=auth["ip_address"])
        db.execute(
            """
            UPDATE key_authorizations
            SET status = 'REVOKED',
                revoked_at = now(),
                revoked_by = %s,
                revoked_automatically = false,
                revocation_justification = %s
            WHERE key_id = %s AND server_id = %s
            """,
            (admin_id, reason, key["id"], auth["server_id"]),
        )
        db.execute(
            """
            INSERT INTO audit_log (action, performed_by, target_key, target_server, details)
            VALUES ('KEY_REVOKED', %s, %s, %s, %s::jsonb)
            """,
            (
                admin_id,
                key["id"],
                auth["server_id"],
                json.dumps({"reason": reason, "fingerprint": fingerprint}),
            ),
        )


def handle_disappeared_key(key_id: str, server_id: str, hostname: str, ip: str) -> dict:
    """
    Scenario 2 — key was ACTIVE but disappeared from server (out-of-system revocation).
    Sets REVOKED + revoked_automatically=True, logs ANOMALY_DETECTED.
    Returns info dict for grouped alert in caller.
    """
    db.execute(
        """
        UPDATE key_authorizations
        SET status = 'REVOKED',
            revoked_at = now(),
            revoked_by = NULL,
            revoked_automatically = true,
            revocation_justification = 'Key disappeared from server — out-of-system revocation'
        WHERE key_id = %s AND server_id = %s AND status = 'ACTIVE'
        """,
        (key_id, server_id),
    )
    db.execute(
        """
        INSERT INTO audit_log (action, target_key, target_server, details)
        VALUES ('ANOMALY_DETECTED', %s, %s, %s::jsonb)
        """,
        (
            key_id,
            server_id,
            json.dumps({"reason": "out_of_system_revocation", "hostname": hostname}),
        ),
    )
    key = db.query_one("SELECT fingerprint FROM ssh_keys WHERE id = %s", (key_id,))
    fp = key["fingerprint"] if key else "unknown"
    return {"type": "disappeared", "fingerprint": fp, "hostname": hostname}


def handle_unknown_key(
    key_type: str,
    key_size_bits: int | None,
    public_key: str,
    fingerprint: str,
    comment: str | None,
    server_id: str,
    hostname: str,
) -> dict:
    """
    Scenario 3 — key present on server but absent from DB.
    Inserts with PENDING_REVIEW, logs ANOMALY_DETECTED.
    Returns info dict for grouped alert in caller.
    """
    db.execute(
        """
        INSERT INTO ssh_keys (fingerprint, key_type, key_size_bits, public_key, comment)
        VALUES (%s, %s, %s, %s, %s)
        ON CONFLICT (fingerprint) DO UPDATE SET
            key_size_bits = EXCLUDED.key_size_bits,
            last_seen = now()
        """,
        (fingerprint, key_type, key_size_bits, public_key, comment),
    )
    key = db.query_one("SELECT id FROM ssh_keys WHERE fingerprint = %s", (fingerprint,))
    db.execute(
        """
        INSERT INTO key_authorizations (key_id, server_id, status)
        VALUES (%s, %s, 'PENDING_REVIEW')
        ON CONFLICT (key_id, server_id) DO NOTHING
        """,
        (key["id"], server_id),
    )
    db.execute(
        """
        INSERT INTO audit_log (action, target_key, target_server, details)
        VALUES ('ANOMALY_DETECTED', %s, %s, %s::jsonb)
        """,
        (
            key["id"],
            server_id,
            json.dumps({"reason": "unknown_key", "fingerprint": fingerprint, "hostname": hostname}),
        ),
    )
    return {"type": "unknown", "fingerprint": fingerprint, "hostname": hostname, "key_type": key_type, "comment": comment}


def handle_reappeared_key(key_id: str, server_id: str, hostname: str) -> dict:
    """
    Scenario 5 — key was REVOKED or EXPIRED but reappeared on the server.
    Sets PENDING_REVIEW, logs ANOMALY_DETECTED.
    Returns info dict for grouped alert in caller.
    """
    db.execute(
        """
        UPDATE key_authorizations
        SET status = 'PENDING_REVIEW',
            revoked_at = NULL,
            revoked_by = NULL,
            revoked_automatically = false,
            revocation_justification = NULL
        WHERE key_id = %s AND server_id = %s AND status IN ('REVOKED', 'EXPIRED')
        """,
        (key_id, server_id),
    )
    db.execute(
        """
        INSERT INTO audit_log (action, target_key, target_server, details)
        VALUES ('ANOMALY_DETECTED', %s, %s, %s::jsonb)
        """,
        (
            key_id,
            server_id,
            json.dumps({"reason": "revoked_key_reappeared", "hostname": hostname}),
        ),
    )
    key = db.query_one("SELECT fingerprint FROM ssh_keys WHERE id = %s", (key_id,))
    fp = key["fingerprint"] if key else "unknown"
    return {"type": "reappeared", "fingerprint": fp, "hostname": hostname}


def warn_expiring_key(key_id: str, server_id: str, expires_at: datetime) -> dict | None:
    """
    Log EXPIRY_WARNING with 24h anti-spam.
    Returns info dict for grouped alert in caller, or None if already warned.
    """
    already_warned = db.query_one(
        """
        SELECT id FROM audit_log
        WHERE action = 'EXPIRY_WARNING'
          AND target_key = %s
          AND target_server = %s
          AND performed_at > now() - INTERVAL '24 hours'
        """,
        (key_id, server_id),
    )
    if already_warned:
        return None

    key = db.query_one("SELECT fingerprint FROM ssh_keys WHERE id = %s", (key_id,))
    server = db.query_one("SELECT hostname FROM servers WHERE id = %s", (server_id,))
    fp = key["fingerprint"] if key else "unknown"
    hostname = server["hostname"] if server else "unknown"

    db.execute(
        """
        INSERT INTO audit_log (action, target_key, target_server, details)
        VALUES ('EXPIRY_WARNING', %s, %s, %s::jsonb)
        """,
        (
            key_id,
            server_id,
            json.dumps({"fingerprint": fp, "hostname": hostname, "expires_at": str(expires_at)}),
        ),
    )
    return {"fingerprint": fp, "hostname": hostname, "expires_at": expires_at}


def assign_key(fingerprint: str, owner_name: str) -> None:
    """Set the free-text owner of a key."""
    key = db.query_one("SELECT id FROM ssh_keys WHERE fingerprint = %s", (fingerprint,))
    if not key:
        raise ValueError(f"Key not found: {fingerprint}")
    db.execute(
        "UPDATE ssh_keys SET owner = %s WHERE id = %s",
        (owner_name, key["id"]),
    )


def set_key_expiry(fingerprint: str, expires_at: datetime) -> None:
    """Set expiration on all ACTIVE authorizations for a key."""
    key = db.query_one("SELECT id FROM ssh_keys WHERE fingerprint = %s", (fingerprint,))
    if not key:
        raise ValueError(f"Key not found: {fingerprint}")
    db.execute(
        "UPDATE key_authorizations SET expires_at = %s WHERE key_id = %s AND status = 'ACTIVE'",
        (expires_at, key["id"]),
    )


def remove_key_expiry(fingerprint: str) -> None:
    """Remove expiration from all ACTIVE authorizations for a key."""
    key = db.query_one("SELECT id FROM ssh_keys WHERE fingerprint = %s", (fingerprint,))
    if not key:
        raise ValueError(f"Key not found: {fingerprint}")
    db.execute(
        "UPDATE key_authorizations SET expires_at = NULL WHERE key_id = %s AND status = 'ACTIVE'",
        (key["id"],),
    )


# ---------------------------------------------------------------------------
# Acces temporaires
# ---------------------------------------------------------------------------

def grant_access(
    key_fp: str,
    hostname: str,
    expires_at: datetime,
    justification: str,
    admin_id: str,
) -> dict:
    """Create or update a key_authorization as ACTIVE for a given server."""
    key = db.query_one("SELECT id FROM ssh_keys WHERE fingerprint = %s", (key_fp,))
    if not key:
        raise ValueError(f"Key not found: {key_fp}")
    server = db.query_one(
        "SELECT id FROM servers WHERE hostname = %s AND is_active = true", (hostname,)
    )
    if not server:
        raise ValueError(f"Server not found: {hostname}")

    db.execute(
        """
        INSERT INTO key_authorizations (key_id, server_id, authorized_by, status, expires_at)
        VALUES (%s, %s, %s, 'ACTIVE', %s)
        ON CONFLICT (key_id, server_id) DO UPDATE SET
            status = 'ACTIVE',
            authorized_by = EXCLUDED.authorized_by,
            authorized_at = now(),
            expires_at = EXCLUDED.expires_at
        """,
        (key["id"], server["id"], admin_id, expires_at),
    )
    db.execute(
        """
        INSERT INTO access_requests
            (requested_by, approved_by, key_id, server_id, justification, status, approved_at, expires_at)
        VALUES (%s, %s, %s, %s, %s, 'APPROVED', now(), %s)
        """,
        (admin_id, admin_id, key["id"], server["id"], justification, expires_at),
    )
    return {"key_id": key["id"], "server_id": server["id"], "expires_at": expires_at}


def deploy_key(
    public_key: str,
    unix_user: str,
    hostname: str,
    expires_at,
    justification: str,
    admin_id: str,
) -> dict:
    """
    Register public key in ssh_keys (if not exists), deploy via sam-add,
    create key_authorization ACTIVE with optional expiry.
    """
    parts = public_key.strip().split()
    if len(parts) < 2:
        raise ValueError("Format de clé invalide")
    key_type = parts[0]
    key_b64 = parts[1]
    comment = parts[2] if len(parts) > 2 else unix_user

    valid_types = ("ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256")
    if key_type not in valid_types:
        raise ValueError(f"Type de clé non supporté: {key_type}")

    import base64, hashlib
    raw = base64.b64decode(key_b64)
    digest = hashlib.sha256(raw).digest()
    fingerprint = "SHA256:" + base64.b64encode(digest).decode().rstrip("=")

    key_size_bits = None
    if key_type == "ssh-rsa":
        # parse wire format to get exact modulus bit length
        import struct
        data = base64.b64decode(key_b64)
        pos = 0
        while pos < len(data):
            (length,) = struct.unpack(">I", data[pos:pos+4])
            pos += 4
            field = data[pos:pos+length]
            pos += length
        key_size_bits = int.from_bytes(field, "big").bit_length()

    server = db.query_one(
        "SELECT id, ip_address FROM servers WHERE hostname = %s AND is_active = true",
        (hostname,),
    )
    if not server:
        raise ValueError(f"Serveur introuvable ou inactif: {hostname}")

    db.execute(
        """
        INSERT INTO ssh_keys (fingerprint, key_type, key_size_bits, public_key, comment, owner)
        VALUES (%s, %s, %s, %s, %s, %s)
        ON CONFLICT (fingerprint) DO UPDATE SET
            last_seen = now(),
            owner = COALESCE(ssh_keys.owner, EXCLUDED.owner)
        """,
        (fingerprint, key_type, key_size_bits, public_key.strip(), comment, unix_user),
    )
    key = db.query_one("SELECT id FROM ssh_keys WHERE fingerprint = %s", (fingerprint,))

    ssh.add_key_on_server(hostname, unix_user, public_key.strip(), server["ip_address"])

    db.execute(
        """
        INSERT INTO key_authorizations (key_id, server_id, authorized_by, status, expires_at)
        VALUES (%s, %s, %s, 'ACTIVE', %s)
        ON CONFLICT (key_id, server_id) DO UPDATE SET
            status = 'ACTIVE',
            authorized_by = EXCLUDED.authorized_by,
            authorized_at = now(),
            expires_at = EXCLUDED.expires_at
        """,
        (key["id"], server["id"], admin_id, expires_at),
    )
    db.execute(
        """
        INSERT INTO audit_log (action, performed_by, target_key, target_server, details)
        VALUES ('KEY_ADDED', %s, %s, %s, %s::jsonb)
        """,
        (
            admin_id,
            key["id"],
            server["id"],
            json.dumps({"unix_user": unix_user, "fingerprint": fingerprint, "hostname": hostname}),
        ),
    )
    return {
        "fingerprint": fingerprint,
        "key_type": key_type,
        "unix_user": unix_user,
        "hostname": hostname,
        "expires_at": expires_at.isoformat() if expires_at else None,
    }


def approve_request(request_id: str, admin_id: str) -> None:
    """PENDING → APPROVED. Creates/updates the key_authorization."""
    req = db.query_one(
        "SELECT * FROM access_requests WHERE id = %s AND status = 'PENDING'",
        (request_id,),
    )
    if not req:
        raise ValueError(f"Request not found or not PENDING: {request_id}")

    expires_at = req.get("expires_at_requested")
    if req.get("duration_hours") and not expires_at:
        expires_at = datetime.now(tz=timezone.utc) + timedelta(hours=req["duration_hours"])

    db.execute(
        """
        UPDATE access_requests
        SET status = 'APPROVED', approved_by = %s, approved_at = now(), expires_at = %s
        WHERE id = %s
        """,
        (admin_id, expires_at, request_id),
    )
    db.execute(
        """
        INSERT INTO key_authorizations (key_id, server_id, authorized_by, status, expires_at)
        VALUES (%s, %s, %s, 'ACTIVE', %s)
        ON CONFLICT (key_id, server_id) DO UPDATE SET
            status = 'ACTIVE',
            authorized_by = EXCLUDED.authorized_by,
            authorized_at = now(),
            expires_at = EXCLUDED.expires_at
        """,
        (req["key_id"], req["server_id"], admin_id, expires_at),
    )
    db.execute(
        """
        INSERT INTO audit_log (action, performed_by, target_key, target_server)
        VALUES ('REQUEST_APPROVED', %s, %s, %s)
        """,
        (admin_id, req["key_id"], req["server_id"]),
    )


def reject_request(request_id: str, admin_id: str) -> None:
    """PENDING → REJECTED."""
    req = db.query_one(
        "SELECT * FROM access_requests WHERE id = %s AND status = 'PENDING'",
        (request_id,),
    )
    if not req:
        raise ValueError(f"Request not found or not PENDING: {request_id}")
    db.execute(
        """
        UPDATE access_requests
        SET status = 'REJECTED', approved_by = %s, approved_at = now()
        WHERE id = %s
        """,
        (admin_id, request_id),
    )
    db.execute(
        """
        INSERT INTO audit_log (action, performed_by, target_key, target_server)
        VALUES ('REQUEST_REJECTED', %s, %s, %s)
        """,
        (admin_id, req["key_id"], req["server_id"]),
    )


def revoke_request(request_id: str, admin_id: str) -> None:
    """Revoke the key_authorization associated with an APPROVED request."""
    req = db.query_one(
        "SELECT * FROM access_requests WHERE id = %s AND status = 'APPROVED'",
        (request_id,),
    )
    if not req:
        raise ValueError(f"Request not found or not APPROVED: {request_id}")

    key = db.query_one("SELECT fingerprint FROM ssh_keys WHERE id = %s", (req["key_id"],))
    if key:
        server = db.query_one("SELECT hostname, ip_address FROM servers WHERE id = %s", (req["server_id"],))
        if server:
            ssh.revoke_on_server(server["hostname"], key["fingerprint"], ip=server["ip_address"])

    db.execute(
        """
        UPDATE key_authorizations
        SET status = 'REVOKED', revoked_at = now(), revoked_by = %s, revoked_automatically = false
        WHERE key_id = %s AND server_id = %s
        """,
        (admin_id, req["key_id"], req["server_id"]),
    )
    db.execute(
        "UPDATE access_requests SET status = 'EXPIRED' WHERE id = %s",
        (request_id,),
    )


# ---------------------------------------------------------------------------
# Serveurs
# ---------------------------------------------------------------------------

def add_server(
    hostname: str, ip: str, env: str, os_family: str | None = None,
    admin_id: str | None = None,
) -> dict:
    """Insert a new server, run ssh-keyscan, and log SERVER_ADDED."""
    import servers as servers_mod
    try:
        servers_mod.add_to_known_hosts(ip)
    except Exception as e:
        raise ValueError(f"Impossible de joindre {hostname} ({ip}) pour le keyscan : {e}") from e
    db.execute(
        "INSERT INTO servers (hostname, ip_address, environment, os_family) VALUES (%s, %s, %s, %s)",
        (hostname, ip, env, os_family),
    )
    server = db.query_one("SELECT id FROM servers WHERE hostname = %s", (hostname,))
    db.execute(
        """
        INSERT INTO audit_log (action, performed_by, target_server, details)
        VALUES ('SERVER_ADDED', %s, %s, %s::jsonb)
        """,
        (admin_id, server["id"], json.dumps({"hostname": hostname, "ip": ip, "environment": env})),
    )
    return server


def disable_server(hostname: str, admin_id: str | None = None) -> None:
    """Set is_active=false and log SERVER_DISABLED."""
    server = db.query_one(
        "SELECT id FROM servers WHERE hostname = %s AND is_active = true", (hostname,)
    )
    if not server:
        raise ValueError(f"Active server not found: {hostname}")
    db.execute("UPDATE servers SET is_active = false WHERE id = %s", (server["id"],))
    db.execute(
        """
        INSERT INTO audit_log (action, performed_by, target_server, details)
        VALUES ('SERVER_DISABLED', %s, %s, %s::jsonb)
        """,
        (admin_id, server["id"], json.dumps({"hostname": hostname})),
    )


def enable_server(hostname: str, admin_id: str | None = None) -> None:
    """Set is_active=true and log SERVER_ADDED."""
    server = db.query_one(
        "SELECT id FROM servers WHERE hostname = %s AND is_active = false", (hostname,)
    )
    if not server:
        raise ValueError(f"Inactive server not found: {hostname}")
    db.execute("UPDATE servers SET is_active = true WHERE id = %s", (server["id"],))
    db.execute(
        """
        INSERT INTO audit_log (action, performed_by, target_server, details)
        VALUES ('SERVER_ADDED', %s, %s, %s::jsonb)
        """,
        (admin_id, server["id"], json.dumps({"hostname": hostname, "reactivated": True})),
    )


def delete_server(hostname: str, admin_id: str | None = None) -> None:
    """Hard delete a server and all related data."""
    server = db.query_one("SELECT id FROM servers WHERE hostname = %s", (hostname,))
    if not server:
        raise ValueError(f"Server not found: {hostname}")
    sid = server["id"]
    db.execute("DELETE FROM audit_log WHERE target_server = %s", (sid,))
    db.execute("DELETE FROM access_requests WHERE server_id = %s", (sid,))
    db.execute("DELETE FROM key_authorizations WHERE server_id = %s", (sid,))
    db.execute("DELETE FROM servers WHERE id = %s", (sid,))


# ---------------------------------------------------------------------------
# Administrateurs
# ---------------------------------------------------------------------------

def _validate_password_strength(password: str) -> None:
    """Raise ValueError if password does not meet complexity requirements."""
    import re
    errors = []
    if len(password) < 8:
        errors.append("au moins 8 caractères")
    if not re.search(r"[A-Z]", password):
        errors.append("au moins une majuscule")
    if not re.search(r"[a-z]", password):
        errors.append("au moins une minuscule")
    if not re.search(r"\d", password):
        errors.append("au moins un chiffre")
    if not re.search(r"[!@#$%^&*()\-_=+\[\]{}|;:'\",.<>?/\\`~]", password):
        errors.append("au moins un caractère spécial")
    if errors:
        raise ValueError("Mot de passe insuffisant : " + ", ".join(errors))


def add_admin(username: str, email: str, password: str, admin_id: str | None = None) -> dict:
    """Insert a new administrator and log ADMIN_ADDED."""
    from werkzeug.security import generate_password_hash
    _validate_password_strength(password)
    password_hash = generate_password_hash(password)
    db.execute(
        "INSERT INTO administrators (username, email, password_hash) VALUES (%s, %s, %s)",
        (username, email, password_hash),
    )
    admin = db.query_one("SELECT id FROM administrators WHERE username = %s", (username,))
    db.execute(
        """
        INSERT INTO audit_log (action, performed_by, details)
        VALUES ('ADMIN_ADDED', %s, %s::jsonb)
        """,
        (admin_id, json.dumps({"username": username, "email": email})),
    )
    return admin


def change_password(username: str, new_password: str) -> None:
    """Update password_hash for an active administrator."""
    from werkzeug.security import generate_password_hash
    _validate_password_strength(new_password)
    admin = db.query_one(
        "SELECT id FROM administrators WHERE username = %s AND is_active = true", (username,)
    )
    if not admin:
        raise ValueError(f"Active admin not found: {username}")
    db.execute(
        "UPDATE administrators SET password_hash = %s WHERE id = %s",
        (generate_password_hash(new_password), admin["id"]),
    )


def disable_admin(username: str, admin_id: str | None = None) -> None:
    """Set is_active=false and log ADMIN_DISABLED."""
    admin = db.query_one(
        "SELECT id FROM administrators WHERE username = %s AND is_active = true", (username,)
    )
    if not admin:
        raise ValueError(f"Active admin not found: {username}")
    db.execute("UPDATE administrators SET is_active = false WHERE id = %s", (admin["id"],))
    db.execute(
        """
        INSERT INTO audit_log (action, performed_by, details)
        VALUES ('ADMIN_DISABLED', %s, %s::jsonb)
        """,
        (admin_id, json.dumps({"username": username})),
    )


def enable_admin(username: str, admin_id: str | None = None) -> None:
    """Set is_active=true and log ADMIN_ENABLED."""
    admin = db.query_one(
        "SELECT id FROM administrators WHERE username = %s AND is_active = false", (username,)
    )
    if not admin:
        raise ValueError(f"Inactive admin not found: {username}")
    db.execute("UPDATE administrators SET is_active = true WHERE id = %s", (admin["id"],))
    db.execute(
        """
        INSERT INTO audit_log (action, performed_by, details)
        VALUES ('ADMIN_ENABLED', %s, %s::jsonb)
        """,
        (admin_id, json.dumps({"username": username})),
    )


def delete_admin(username: str, admin_id: str | None = None) -> None:
    """Permanently delete an admin if no FK references exist. Log ADMIN_DELETED."""
    admin = db.query_one(
        "SELECT id FROM administrators WHERE username = %s", (username,)
    )
    if not admin:
        raise ValueError(f"Admin not found: {username}")
    ref = db.query_one(
        """
        SELECT 1 FROM (
            SELECT performed_by AS ref_id FROM audit_log WHERE performed_by = %s
            UNION ALL
            SELECT authorized_by FROM key_authorizations WHERE authorized_by = %s
            UNION ALL
            SELECT revoked_by    FROM key_authorizations WHERE revoked_by    = %s
            UNION ALL
            SELECT requested_by  FROM access_requests    WHERE requested_by  = %s
            UNION ALL
            SELECT approved_by   FROM access_requests    WHERE approved_by   = %s
        ) refs
        LIMIT 1
        """,
        (admin["id"],) * 5,
    )
    if ref:
        raise ValueError(f"Cannot delete admin '{username}': existing audit records reference this account")
    db.execute(
        """
        INSERT INTO audit_log (action, performed_by, details)
        VALUES ('ADMIN_DELETED', %s, %s::jsonb)
        """,
        (admin_id, json.dumps({"username": username})),
    )
    db.execute("DELETE FROM administrators WHERE id = %s", (admin["id"],))
