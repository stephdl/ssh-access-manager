"""
actions.py — logique metier partagee entre web.py (API) et manage.py (CLI).
Jamais de duplication entre les deux consommateurs.
"""
import ipaddress
import json
import re
from datetime import datetime, timedelta, timezone

import alerts
import db
import ssh

_FP_RE = re.compile(r"^SHA256:[A-Za-z0-9+/=]+$")
_UNIX_USER_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
VALID_ROLES = {"sysadmin", "operator", "viewer"}


class UserError(Exception):
    """User-facing error — safe to include in HTTP response."""

    status = 400


class NotFoundError(UserError):
    """Resource not found — HTTP 404."""

    status = 404


class ForbiddenError(UserError):
    """Forbidden action — HTTP 403."""

    status = 403


def _validate_ip(ip: str) -> str:
    try:
        return str(ipaddress.ip_address(ip.strip()))
    except ValueError:
        raise UserError(f"Invalid IP address: {ip!r} (expected IPv4 or IPv6)")


def _normalize_environment(environment: str | None) -> str | None:
    if environment is None:
        return None
    normalized = environment.strip()
    if not normalized:
        return None
    if normalized not in {"production", "staging", "lab"}:
        raise UserError(
            f"Invalid environment: {normalized!r}. Must be one of: production, staging, lab"
        )
    return normalized


def _check_fingerprint(fp: str) -> None:
    if not _FP_RE.match(fp):
        raise UserError(f"Invalid fingerprint format: {fp}")


# ---------------------------------------------------------------------------
# Cles SSH
# ---------------------------------------------------------------------------

def validate_key(
    fingerprint: str,
    admin_id: str,
    unix_user: str = None,
    hostname: str = None,
) -> dict:
    """PENDING_REVIEW → ACTIVE. Logs KEY_ADDED for each authorization.

    Si unix_user ET hostname sont fournis : validation ciblée — une seule
    autorisation (key_id, server_id, unix_user). Sinon : toutes les
    autorisations PENDING_REVIEW du fingerprint (usage CLI).
    """
    _check_fingerprint(fingerprint)
    key = db.query_one("SELECT id FROM ssh_keys WHERE fingerprint = %s", (fingerprint,))
    if not key:
        raise NotFoundError(f"Key not found: {fingerprint}")

    if unix_user is not None and hostname is not None:
        server = db.query_one("SELECT id FROM servers WHERE hostname = %s", (hostname,))
        if not server:
            raise NotFoundError(f"Server not found: {hostname}")
        rows = db.query(
            """
            SELECT key_id, server_id, unix_user FROM key_authorizations
            WHERE key_id = %s AND server_id = %s AND unix_user = %s
              AND status = 'PENDING_REVIEW'
            """,
            (key["id"], server["id"], unix_user),
        )
    else:
        rows = db.query(
            """
            SELECT key_id, server_id, unix_user FROM key_authorizations
            WHERE key_id = %s AND status = 'PENDING_REVIEW'
            """,
            (key["id"],),
        )
    if not rows:
        raise UserError(f"No PENDING_REVIEW authorization for key: {fingerprint}")

    for row in rows:
        db.execute(
            """
            UPDATE key_authorizations
            SET status = 'ACTIVE', authorized_by = %s, authorized_at = now()
            WHERE key_id = %s AND server_id = %s AND unix_user = %s
            """,
            (admin_id, row["key_id"], row["server_id"], row["unix_user"]),
        )
        db.execute(
            """
            INSERT INTO audit_log (action, performed_by, target_key, target_server)
            VALUES ('KEY_ADDED', %s, %s, %s)
            """,
            (admin_id, key["id"], row["server_id"]),
        )
    return key


def bulk_validate_keys(fingerprints: list, admin_id: str) -> dict:
    """Validate multiple keys (PENDING_REVIEW → ACTIVE) in one call.

    Skips fingerprints that have no PENDING_REVIEW authorization (no error).
    Returns {"validated": N, "skipped": N}.
    Max 200 fingerprints per call.
    """
    if len(fingerprints) > 200:
        raise UserError("Bulk operation limited to 200 keys at a time")
    if not fingerprints:
        raise UserError("At least one fingerprint is required")

    validated = 0
    skipped = 0
    for fp in fingerprints:
        try:
            _check_fingerprint(fp)
            validate_key(fp, admin_id)
            validated += 1
        except UserError:
            skipped += 1
    return {"validated": validated, "skipped": skipped}


def bulk_revoke_keys(fingerprints: list, reason: str, admin_id: str) -> dict:
    """Revoke multiple keys in one call.

    Skips fingerprints that have no ACTIVE/PENDING_REVIEW authorization.
    Returns {"revoked": N, "skipped": N}.
    Max 200 fingerprints per call.
    """
    if len(fingerprints) > 200:
        raise UserError("Bulk operation limited to 200 keys at a time")
    if not fingerprints:
        raise UserError("At least one fingerprint is required")
    if not reason or not reason.strip():
        raise UserError("A revocation reason is required")

    revoked = 0
    skipped = 0
    for fp in fingerprints:
        try:
            _check_fingerprint(fp)
            revoke_key(fp, admin_id, reason)
            revoked += 1
        except UserError:
            skipped += 1
    return {"revoked": revoked, "skipped": skipped}


def revoke_key(
    fingerprint: str,
    admin_id: str,
    reason: str,
    hostname: str = None,
    unix_user: str = None,
) -> None:
    """
    Scenario 1 — revocation via system.

    If hostname AND unix_user are provided: targeted revocation — removes key
    only from this Unix user's authorized_keys on this server.

    Otherwise: global revocation — removes key from all servers and for
    all Unix users (historical behavior).
    """
    _check_fingerprint(fingerprint)
    key = db.query_one("SELECT id FROM ssh_keys WHERE fingerprint = %s", (fingerprint,))
    if not key:
        raise NotFoundError(f"Key not found: {fingerprint}")

    if hostname and unix_user:
        # --- Targeted revocation (one user on one server) ---
        server = db.query_one(
            "SELECT id, ip_address, ssh_port FROM servers WHERE hostname = %s",
            (hostname,),
        )
        if not server:
            raise NotFoundError(f"Server not found: {hostname}")
        auth = db.query_one(
            """
            SELECT status FROM key_authorizations
            WHERE key_id = %s AND server_id = %s AND unix_user = %s
              AND status IN ('ACTIVE', 'PENDING_REVIEW')
            """,
            (key["id"], server["id"], unix_user),
        )
        if not auth:
            raise UserError(
                f"No active authorization for {fingerprint} / user {unix_user} on {hostname}"
            )
        ssh.revoke_on_server(hostname, fingerprint, ip=server["ip_address"], unix_user=unix_user, port=server["ssh_port"])
        db.execute(
            """
            UPDATE key_authorizations
            SET status = 'REVOKED',
                revoked_at = now(),
                revoked_by = %s,
                revoked_automatically = false,
                revocation_justification = %s
            WHERE key_id = %s AND server_id = %s AND unix_user = %s
            """,
            (admin_id, reason, key["id"], server["id"], unix_user),
        )
        db.execute(
            """
            INSERT INTO audit_log (action, performed_by, target_key, target_server, details)
            VALUES ('KEY_REVOKED', %s, %s, %s, %s::jsonb)
            """,
            (
                admin_id,
                key["id"],
                server["id"],
                json.dumps({"reason": reason, "fingerprint": fingerprint, "unix_user": unix_user}),
            ),
        )
    else:
        # --- Global revocation (all servers, all users) ---
        active_auths = db.query(
            """
            SELECT DISTINCT ka.server_id, s.hostname, s.ip_address, s.ssh_port
            FROM key_authorizations ka
            JOIN servers s ON s.id = ka.server_id
            WHERE ka.key_id = %s AND ka.status IN ('ACTIVE', 'PENDING_REVIEW')
            """,
            (key["id"],),
        )
        for auth in active_auths:
            ssh.revoke_on_server(auth["hostname"], fingerprint, ip=auth["ip_address"], port=auth["ssh_port"])
            db.execute(
                """
                UPDATE key_authorizations
                SET status = 'REVOKED',
                    revoked_at = now(),
                    revoked_by = %s,
                    revoked_automatically = false,
                    revocation_justification = %s
                WHERE key_id = %s AND server_id = %s
                  AND status IN ('ACTIVE', 'PENDING_REVIEW')
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


def handle_disappeared_key(
    key_id: str, server_id: str, hostname: str, ip: str, unix_user: str = ""
) -> dict:
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
        WHERE key_id = %s AND server_id = %s AND unix_user = %s AND status = 'ACTIVE'
        """,
        (key_id, server_id, unix_user),
    )
    db.execute(
        """
        INSERT INTO audit_log (action, target_key, target_server, details)
        VALUES ('ANOMALY_DETECTED', %s, %s, %s::jsonb)
        """,
        (
            key_id,
            server_id,
            json.dumps({"reason": "out_of_system_revocation", "hostname": hostname, "unix_user": unix_user}),
        ),
    )
    key = db.query_one("SELECT fingerprint FROM ssh_keys WHERE id = %s", (key_id,))
    fp = key["fingerprint"] if key else "unknown"
    return {"type": "disappeared", "fingerprint": fp, "hostname": hostname, "unix_user": unix_user}


def handle_unknown_key(
    key_type: str,
    key_size_bits: int | None,
    public_key: str,
    fingerprint: str,
    comment: str | None,
    server_id: str,
    hostname: str,
    unix_user: str = "",
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
        INSERT INTO key_authorizations (key_id, server_id, unix_user, status)
        VALUES (%s, %s, %s, 'PENDING_REVIEW')
        ON CONFLICT (key_id, server_id, unix_user) DO NOTHING
        """,
        (key["id"], server_id, unix_user),
    )
    db.execute(
        """
        INSERT INTO audit_log (action, target_key, target_server, details)
        VALUES ('ANOMALY_DETECTED', %s, %s, %s::jsonb)
        """,
        (
            key["id"],
            server_id,
            json.dumps({"reason": "unknown_key", "fingerprint": fingerprint, "hostname": hostname, "unix_user": unix_user}),
        ),
    )
    return {"type": "unknown", "fingerprint": fingerprint, "hostname": hostname, "key_type": key_type, "comment": comment, "unix_user": unix_user}


def handle_reappeared_key(
    key_id: str, server_id: str, hostname: str, unix_user: str = ""
) -> dict:
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
        WHERE key_id = %s AND server_id = %s AND unix_user = %s AND status IN ('REVOKED', 'EXPIRED')
        """,
        (key_id, server_id, unix_user),
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


def check_session_limit(server_id: str, hostname: str, session_count: int, max_sessions: int) -> bool:
    """
    Send a WARNING alert if session_count > max_sessions, with 24h anti-spam.
    Logs SESSION_LIMIT_EXCEEDED to audit_log.
    Returns True if an alert was sent, False if already warned within 24h or under limit.
    """
    if session_count <= max_sessions:
        return False

    already_warned = db.query_one(
        """
        SELECT id FROM audit_log
        WHERE action = 'SESSION_LIMIT_EXCEEDED'
          AND target_server = %s
          AND performed_at > now() - INTERVAL '24 hours'
        """,
        (server_id,),
    )
    if already_warned:
        return False

    db.execute(
        """
        INSERT INTO audit_log (action, target_server, details)
        VALUES ('SESSION_LIMIT_EXCEEDED', %s, %s::jsonb)
        """,
        (
            server_id,
            json.dumps({
                "hostname": hostname,
                "session_count": session_count,
                "max_sessions": max_sessions,
            }),
        ),
    )
    alerts.send_alert(
        "WARNING",
        f"[ssh-access-manager] Session limit exceeded on {hostname}",
        (
            f"Server: {hostname}\n"
            f"Active sessions: {session_count}\n"
            f"Configured limit: {max_sessions}\n\n"
            f"Please review active connections on this server."
        ),
    )
    return True


def assign_key(fingerprint: str, owner_name: str) -> None:
    """Set the free-text owner of a key."""
    _check_fingerprint(fingerprint)
    key = db.query_one("SELECT id FROM ssh_keys WHERE fingerprint = %s", (fingerprint,))
    if not key:
        raise NotFoundError(f"Key not found: {fingerprint}")
    db.execute(
        "UPDATE ssh_keys SET owner = %s WHERE id = %s",
        (owner_name, key["id"]),
    )


def set_key_expiry(fingerprint: str, expires_at: datetime) -> None:
    """Set expiration on all ACTIVE authorizations for a key."""
    _check_fingerprint(fingerprint)
    key = db.query_one("SELECT id FROM ssh_keys WHERE fingerprint = %s", (fingerprint,))
    if not key:
        raise NotFoundError(f"Key not found: {fingerprint}")
    db.execute(
        "UPDATE key_authorizations SET expires_at = %s WHERE key_id = %s AND status = 'ACTIVE'",
        (expires_at, key["id"]),
    )


def remove_key_expiry(fingerprint: str) -> None:
    """Remove expiration from all ACTIVE authorizations for a key."""
    _check_fingerprint(fingerprint)
    key = db.query_one("SELECT id FROM ssh_keys WHERE fingerprint = %s", (fingerprint,))
    if not key:
        raise NotFoundError(f"Key not found: {fingerprint}")
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
        raise NotFoundError(f"Key not found: {key_fp}")
    server = db.query_one(
        "SELECT id FROM servers WHERE hostname = %s AND is_active = true", (hostname,)
    )
    if not server:
        raise NotFoundError(f"Server not found: {hostname}")

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
    if not _UNIX_USER_RE.match(unix_user):
        raise UserError(
            f"Invalid Unix username: '{unix_user}' "
            "(lowercase letters, digits, _ and - only, max 32 chars)"
        )
    parts = public_key.strip().split()
    if len(parts) < 2:
        raise UserError("Invalid key format")
    key_type = parts[0]
    key_b64 = parts[1]
    comment = parts[2] if len(parts) > 2 else unix_user

    valid_types = ("ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256")
    if key_type not in valid_types:
        raise UserError(f"Unsupported key type: {key_type}")

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
        "SELECT id, ip_address, ssh_port FROM servers WHERE hostname = %s AND is_active = true",
        (hostname,),
    )
    if not server:
        raise NotFoundError(f"Server not found or inactive: {hostname}")

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

    ssh.ensure_scripts(hostname, server["id"], server["ip_address"], port=server["ssh_port"])
    ssh.add_key_on_server(hostname, unix_user, public_key.strip(), server["ip_address"], port=server["ssh_port"])

    db.execute(
        """
        INSERT INTO key_authorizations (key_id, server_id, unix_user, authorized_by, status, expires_at)
        VALUES (%s, %s, %s, %s, 'ACTIVE', %s)
        ON CONFLICT (key_id, server_id, unix_user) DO UPDATE SET
            status = 'ACTIVE',
            authorized_by = EXCLUDED.authorized_by,
            authorized_at = now(),
            expires_at = EXCLUDED.expires_at
        """,
        (key["id"], server["id"], unix_user, admin_id, expires_at),
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
        raise NotFoundError(f"Request not found or not PENDING: {request_id}")

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
        raise NotFoundError(f"Request not found or not PENDING: {request_id}")
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
        raise NotFoundError(f"Request not found or not APPROVED: {request_id}")

    key = db.query_one("SELECT fingerprint FROM ssh_keys WHERE id = %s", (req["key_id"],))
    if key:
        server = db.query_one("SELECT hostname, ip_address, ssh_port FROM servers WHERE id = %s", (req["server_id"],))
        if server:
            ssh.revoke_on_server(server["hostname"], key["fingerprint"], ip=server["ip_address"], port=server["ssh_port"])

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
    hostname: str, ip: str, ssh_user: str = "root", ssh_password: str = "",
    env: str | None = None, os_family: str | None = None,
    ssh_port: int = 22, admin_id: str | None = None,
) -> dict:
    """Add and provision a server atomically. Server is only created in DB if SSH provisioning succeeds."""
    ip = _validate_ip(ip)
    env = _normalize_environment(env)
    existing = db.query_one(
        "SELECT hostname FROM servers WHERE ip_address = %s", (ip,)
    )
    if existing:
        raise UserError(f"IP {ip} is already used by server '{existing['hostname']}'")
    ssh.provision_server(ip, ssh_user, ssh_password, ssh_port)
    db.execute(
        "INSERT INTO servers (hostname, ip_address, environment, os_family, ssh_port) VALUES (%s, %s, %s, %s, %s)",
        (hostname, ip, env, os_family, ssh_port),
    )
    server = db.query_one("SELECT id FROM servers WHERE hostname = %s", (hostname,))
    db.execute(
        """
        INSERT INTO audit_log (action, performed_by, target_server, details)
        VALUES ('SERVER_ADDED', %s, %s, %s::jsonb)
        """,
        (admin_id, server["id"], json.dumps({"hostname": hostname, "ip": ip, "environment": env, "ssh_port": ssh_port})),
    )
    db.execute(
        """
        INSERT INTO audit_log (action, performed_by, target_server, details)
        VALUES ('SERVER_PROVISIONED', %s, %s, %s::jsonb)
        """,
        (admin_id, server["id"], json.dumps({"hostname": hostname, "ssh_user": ssh_user, "ssh_port": ssh_port})),
    )
    return server


def provision_server(hostname: str, ssh_user: str = "root", ssh_password: str = "", ssh_port: int = 22, admin_id: str | None = None) -> None:
    """Provision a remote server. Never stores the password."""
    server = db.query_one(
        "SELECT id, ip_address FROM servers WHERE hostname = %s AND is_active = true",
        (hostname,),
    )
    if not server:
        raise NotFoundError(f"Server not found or inactive: {hostname}")
    ssh.provision_server(server["ip_address"], ssh_user, ssh_password, ssh_port)
    # Update ssh_port in DB after successful provisioning
    db.execute(
        "UPDATE servers SET ssh_port = %s WHERE id = %s",
        (ssh_port, server["id"]),
    )
    db.execute(
        """
        INSERT INTO audit_log (action, performed_by, target_server, details)
        VALUES ('SERVER_PROVISIONED', %s, %s, %s::jsonb)
        """,
        (
            admin_id,
            server["id"],
            json.dumps({"hostname": hostname, "ssh_user": ssh_user, "ssh_port": ssh_port}),
        ),
    )


def disable_server(hostname: str, admin_id: str | None = None) -> None:
    """Set is_active=false and log SERVER_DISABLED."""
    server = db.query_one(
        "SELECT id FROM servers WHERE hostname = %s AND is_active = true", (hostname,)
    )
    if not server:
        raise NotFoundError(f"Active server not found: {hostname}")
    db.execute("UPDATE servers SET is_active = false WHERE id = %s", (server["id"],))
    db.execute(
        """
        INSERT INTO audit_log (action, performed_by, target_server, details)
        VALUES ('SERVER_DISABLED', %s, %s, %s::jsonb)
        """,
        (admin_id, server["id"], json.dumps({"hostname": hostname})),
    )


def update_server(
    hostname: str, new_ip: str, new_env: str, new_os_family: str | None,
    ssh_port: int = 22, admin_id: str | None = None, max_sessions: int = 2,
) -> dict:
    """Update server IP, environment, OS, SSH port, max_sessions. If IP changes, run ssh-keyscan."""
    new_ip = _validate_ip(new_ip)
    new_env = _normalize_environment(new_env)
    import servers as servers_mod
    server = db.query_one(
        "SELECT id, ip_address, environment, os_family, ssh_port, max_sessions FROM servers WHERE hostname = %s",
        (hostname,),
    )
    if not server:
        raise NotFoundError(f"Server not found: {hostname}")

    existing = db.query_one(
        "SELECT hostname FROM servers WHERE ip_address = %s AND hostname != %s",
        (new_ip, hostname),
    )
    if existing:
        raise UserError(f"IP {new_ip} is already used by server '{existing['hostname']}'")

    old_ip = server["ip_address"]
    old_env = server["environment"]
    old_os = server["os_family"]
    old_port = server["ssh_port"]
    old_max_sessions = server["max_sessions"]

    if new_ip != old_ip:
        try:
            servers_mod.add_to_known_hosts(new_ip, ssh_port)
        except Exception as e:
            raise UserError(f"Cannot reach {hostname} ({new_ip}) for keyscan: {e}") from e

    db.execute(
        "UPDATE servers SET ip_address = %s, environment = %s, os_family = %s, ssh_port = %s, max_sessions = %s WHERE hostname = %s",
        (new_ip, new_env, new_os_family, ssh_port, max_sessions, hostname),
    )
    db.execute(
        """
        INSERT INTO audit_log (action, performed_by, target_server, details)
        VALUES ('SERVER_UPDATED', %s, %s, %s::jsonb)
        """,
        (
            admin_id,
            server["id"],
            json.dumps({
                "hostname": hostname,
                "old_ip": old_ip, "new_ip": new_ip,
                "old_env": old_env, "new_env": new_env,
                "old_os": old_os, "new_os": new_os_family,
                "old_port": old_port, "new_port": ssh_port,
                "old_max_sessions": old_max_sessions, "new_max_sessions": max_sessions,
            }),
        ),
    )
    return server


def enable_server(hostname: str, admin_id: str | None = None) -> None:
    """Set is_active=true and log SERVER_ADDED."""
    server = db.query_one(
        "SELECT id FROM servers WHERE hostname = %s AND is_active = false", (hostname,)
    )
    if not server:
        raise NotFoundError(f"Inactive server not found: {hostname}")
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
        raise NotFoundError(f"Server not found: {hostname}")
    sid = server["id"]
    db.execute("DELETE FROM audit_log WHERE target_server = %s", (sid,))
    db.execute("DELETE FROM access_requests WHERE server_id = %s", (sid,))
    db.execute("DELETE FROM key_authorizations WHERE server_id = %s", (sid,))
    db.execute("DELETE FROM servers WHERE id = %s", (sid,))


# ---------------------------------------------------------------------------
# Administrateurs
# ---------------------------------------------------------------------------

def _validate_password_strength(password: str) -> None:
    """Raise UserError if password does not meet complexity requirements."""
    import re
    errors = []
    if len(password) < 8:
        errors.append("at least 8 characters")
    if not re.search(r"[A-Z]", password):
        errors.append("at least one uppercase letter")
    if not re.search(r"[a-z]", password):
        errors.append("at least one lowercase letter")
    if not re.search(r"\d", password):
        errors.append("at least one digit")
    if not re.search(r"[!@#$%^&*()\-_=+\[\]{}|;:'\",.<>?/\\`~]", password):
        errors.append("at least one special character")
    if errors:
        raise UserError("Insufficient password: " + ", ".join(errors))


def add_admin(username: str, email: str, password: str, admin_id: str | None = None, role: str = "operator") -> dict:
    """Insert a new administrator and log ADMIN_ADDED."""
    from werkzeug.security import generate_password_hash
    if not email or not email.strip():
        raise UserError("email required")
    if role not in VALID_ROLES:
        raise UserError(f"Invalid role: {role}. Must be one of: {', '.join(sorted(VALID_ROLES))}")
    _validate_password_strength(password)
    if db.query_one("SELECT id FROM administrators WHERE username = %s", (username,)):
        raise UserError(f"Username '{username}' is already taken")
    password_hash = generate_password_hash(password)
    db.execute(
        "INSERT INTO administrators (username, email, password_hash, role) VALUES (%s, %s, %s, %s)",
        (username, email, password_hash, role),
    )
    admin = db.query_one("SELECT id FROM administrators WHERE username = %s", (username,))
    db.execute(
        """
        INSERT INTO audit_log (action, performed_by, details)
        VALUES ('ADMIN_ADDED', %s, %s::jsonb)
        """,
        (admin_id, json.dumps({"username": username, "email": email, "role": role})),
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
        raise NotFoundError(f"Active admin not found: {username}")
    db.execute(
        "UPDATE administrators SET password_hash = %s, password_changed_at = now() WHERE id = %s",
        (generate_password_hash(new_password), admin["id"]),
    )


def reset_password(username: str, new_password: str) -> None:
    """Reset password for any administrator (active or disabled). CLI use only."""
    from werkzeug.security import generate_password_hash

    _validate_password_strength(new_password)
    admin = db.query_one("SELECT id FROM administrators WHERE username = %s", (username,))
    if not admin:
        raise NotFoundError(f"Admin not found: {username}")
    db.execute(
        "UPDATE administrators SET password_hash = %s, password_changed_at = now() WHERE id = %s",
        (generate_password_hash(new_password), admin["id"]),
    )
    db.execute(
        "INSERT INTO audit_log (action, performed_by, details) VALUES ('PASSWORD_RESET', NULL, %s::jsonb)",
        (json.dumps({"username": username, "method": "cli"}),),
    )


def update_admin(username: str, email: str | None, role: str, admin_id: str) -> dict:
    """Update administrator email and role. Log ADMIN_UPDATED."""
    if not email or not email.strip():
        raise UserError("email required")
    if role not in VALID_ROLES:
        raise UserError(f"Invalid role: {role}. Must be one of: {', '.join(sorted(VALID_ROLES))}")
    admin = db.query_one(
        "SELECT id, email, role FROM administrators WHERE username = %s", (username,)
    )
    if not admin:
        raise NotFoundError(f"Admin not found: {username}")

    current_admin = db.query_one(
        "SELECT username FROM administrators WHERE id = %s", (admin_id,)
    )
    if current_admin and current_admin["username"] == username and admin["role"] != role:
        raise ForbiddenError("Cannot change your own role")

    if admin["role"] == "sysadmin" and role != "sysadmin":
        other_sysadmins = db.query_one(
            "SELECT COUNT(*) AS n FROM administrators WHERE role = 'sysadmin' AND is_active = true AND id != %s",
            (admin["id"],),
        )
        if not other_sysadmins or other_sysadmins["n"] == 0:
            raise ForbiddenError("Cannot demote last active sysadmin")

    old_email = admin["email"]
    old_role = admin["role"]

    db.execute(
        "UPDATE administrators SET email = %s, role = %s WHERE username = %s",
        (email, role, username),
    )
    db.execute(
        """
        INSERT INTO audit_log (action, performed_by, details)
        VALUES ('ADMIN_UPDATED', %s, %s::jsonb)
        """,
        (
            admin_id,
            json.dumps({
                "username": username,
                "old_email": old_email,
                "new_email": email,
                "old_role": old_role,
                "new_role": role,
            }),
        ),
    )
    return {"username": username, "email": email, "role": role}


def disable_admin(username: str, admin_id: str | None = None) -> None:
    """Set is_active=false and log ADMIN_DISABLED."""
    admin = db.query_one(
        "SELECT id, role FROM administrators WHERE username = %s AND is_active = true", (username,)
    )
    if not admin:
        raise NotFoundError(f"Active admin not found: {username}")
    if admin["role"] == "sysadmin":
        other_sysadmins = db.query_one(
            "SELECT COUNT(*) AS n FROM administrators WHERE role = 'sysadmin' AND is_active = true AND id != %s",
            (admin["id"],),
        )
        if not other_sysadmins or other_sysadmins["n"] == 0:
            raise ForbiddenError("Cannot disable last active sysadmin")
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
        raise NotFoundError(f"Inactive admin not found: {username}")
    db.execute("UPDATE administrators SET is_active = true WHERE id = %s", (admin["id"],))
    db.execute(
        """
        INSERT INTO audit_log (action, performed_by, details)
        VALUES ('ADMIN_ENABLED', %s, %s::jsonb)
        """,
        (admin_id, json.dumps({"username": username})),
    )


def toggle_alerts(username: str, receive_alerts: bool) -> dict:
    """Set receive_alerts flag for an active administrator."""
    admin = db.query_one(
        "SELECT id FROM administrators WHERE username = %s AND is_active = true", (username,)
    )
    if not admin:
        raise NotFoundError(f"Active admin not found: {username}")
    db.execute(
        "UPDATE administrators SET receive_alerts = %s WHERE id = %s",
        (receive_alerts, admin["id"]),
    )
    return {"username": username, "receive_alerts": receive_alerts}


def delete_admin(username: str, admin_id: str | None = None) -> None:
    """Permanently delete an admin. FK references in audit tables are set to NULL. Log ADMIN_DELETED."""
    admin = db.query_one(
        "SELECT id FROM administrators WHERE username = %s", (username,)
    )
    if not admin:
        raise NotFoundError(f"Admin not found: {username}")
    db.execute(
        """
        INSERT INTO audit_log (action, performed_by, details)
        VALUES ('ADMIN_DELETED', %s, %s::jsonb)
        """,
        (admin_id, json.dumps({"username": username})),
    )
    db.execute("DELETE FROM administrators WHERE id = %s", (admin["id"],))


# ---------------------------------------------------------------------------
# Gestion des comptes Unix
# ---------------------------------------------------------------------------

def lock_user(unix_user: str, hostname: str, admin_id: str) -> dict:
    """Lock a Unix user account on a remote server."""
    if unix_user == ssh.SSH_USER:
        raise UserError(f"Cannot lock the collector account '{ssh.SSH_USER}'")
    if not _UNIX_USER_RE.match(unix_user):
        raise UserError(f"Invalid Unix username: '{unix_user}'")
    server = db.query_one(
        "SELECT id, ip_address, ssh_port FROM servers WHERE hostname = %s AND is_active = true",
        (hostname,)
    )
    if not server:
        raise NotFoundError(f"Server not found or inactive: {hostname}")
    ssh.ensure_scripts(hostname, server["id"], server["ip_address"], port=server["ssh_port"])
    ssh.lock_user_on_server(hostname, unix_user, server["ip_address"], port=server["ssh_port"])
    db.execute(
        """INSERT INTO audit_log (action, performed_by, target_server, details)
           VALUES ('USER_LOCKED', %s, %s, %s::jsonb)""",
        (admin_id, server["id"], json.dumps({"unix_user": unix_user, "hostname": hostname}))
    )
    return {"unix_user": unix_user, "hostname": hostname, "status": "locked"}


def unlock_user(unix_user: str, hostname: str, admin_id: str) -> dict:
    """Unlock a Unix user account on a remote server."""
    if unix_user == ssh.SSH_USER:
        raise UserError(f"Cannot unlock the collector account '{ssh.SSH_USER}'")
    if not _UNIX_USER_RE.match(unix_user):
        raise UserError(f"Invalid Unix username: '{unix_user}'")
    server = db.query_one(
        "SELECT id, ip_address, ssh_port FROM servers WHERE hostname = %s AND is_active = true",
        (hostname,)
    )
    if not server:
        raise NotFoundError(f"Server not found or inactive: {hostname}")
    ssh.ensure_scripts(hostname, server["id"], server["ip_address"], port=server["ssh_port"])
    ssh.unlock_user_on_server(hostname, unix_user, server["ip_address"], port=server["ssh_port"])
    db.execute(
        """INSERT INTO audit_log (action, performed_by, target_server, details)
           VALUES ('USER_UNLOCKED', %s, %s, %s::jsonb)""",
        (admin_id, server["id"], json.dumps({"unix_user": unix_user, "hostname": hostname}))
    )
    return {"unix_user": unix_user, "hostname": hostname, "status": "unlocked"}
