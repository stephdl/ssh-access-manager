"""
actions.py — business logic shared between web.py (API) and manage.py (CLI).
Never duplicate logic between the two consumers.
"""
import ipaddress
import json
import logging
import re
from datetime import datetime, timedelta, timezone

import alerts
import db
import ssh

_FP_RE = re.compile(r"^SHA256:[A-Za-z0-9+/=]+$")
_UNIX_USER_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
VALID_ROLES = {"sysadmin", "operator", "viewer"}


def _get_key_path(server_id: str) -> str:
    """Helper to resolve per-server key path, wrapping ssh._resolve_key_path for consistent error handling."""
    try:
        return ssh._resolve_key_path(server_id)
    except KeyError as exc:
        raise UserError(str(exc), status=502)


class UserError(Exception):
    """User-facing error — safe to include in HTTP response."""

    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


class NotFoundError(UserError):
    """Resource not found — HTTP 404."""

    def __init__(self, message):
        super().__init__(message, status=404)


class ForbiddenError(UserError):
    """Forbidden action — HTTP 403."""

    def __init__(self, message):
        super().__init__(message, status=403)


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
# SSH Keys
# ---------------------------------------------------------------------------

def validate_key(
    fingerprint: str,
    admin_id: str,
    unix_user: str = None,
    hostname: str = None,
) -> dict:
    """PENDING_REVIEW → ACTIVE. Logs KEY_ADDED for each authorization.

    If unix_user AND hostname are provided: targeted validation — a single
    authorization (key_id, server_id, unix_user). Otherwise: all
    PENDING_REVIEW authorizations for the fingerprint (CLI usage).
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
            # Root-protected fingerprint, format error, unknown key, no
            # active authorization — already a user-meaningful skip.
            skipped += 1
        except ssh.SSHError:
            # Network/auth/timeout on one server during a bulk operation
            # must not 500 the whole call (the route would otherwise let
            # the exception propagate to the global handler). Skip this
            # fingerprint and continue — the per-server scan_failed audit
            # already records the SSH error elsewhere.
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
        if unix_user == "root":
            raise UserError("Cannot revoke the root account's SSH key — this would cause permanent loss of server access")
        if unix_user == ssh.SSH_USER:
            # The collector key is rotated, not revoked. A manual revoke
            # would cut SAM off the host with no way back (the rotation
            # button does an atomic generate-test-replace flow that
            # preserves access throughout).
            raise UserError(
                f"Cannot revoke the {ssh.SSH_USER} collector key directly — "
                "use the Rotate Collector Key button on the server detail page"
            )
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
        key_path = _get_key_path(server["id"])
        # Critical: refresh sam-* scripts on the host BEFORE invoking
        # sam-revoke. An older sam-revoke deployed before targeted-mode
        # support (no second arg handling) would silently ignore the
        # unix_user argument and run the GLOBAL branch, stripping the
        # key from every user's authorized_keys (including root). This
        # ensure_scripts call upgrades the deployed binary first so the
        # revoke really stays scoped to the requested user.
        ssh.ensure_scripts(hostname, server["id"], server["ip_address"], port=server["ssh_port"], key_path=key_path)
        ssh.revoke_on_server(hostname, fingerprint, ip=server["ip_address"], unix_user=unix_user, port=server["ssh_port"], key_path=key_path)
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
        protected_auth = db.query_one(
            """
            SELECT unix_user FROM key_authorizations
            WHERE key_id = %s AND unix_user IN ('root', %s)
              AND status IN ('ACTIVE', 'PENDING_REVIEW')
            LIMIT 1
            """,
            (key["id"], ssh.SSH_USER),
        )
        if protected_auth:
            who = protected_auth["unix_user"]
            raise UserError(
                f"Cannot revoke this key globally — it is deployed for the {who} account. "
                "Use targeted revocation for specific non-protected users."
            )
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
            key_path = _get_key_path(auth["server_id"])
            ssh.revoke_on_server(auth["hostname"], fingerprint, ip=auth["ip_address"], port=auth["ssh_port"], key_path=key_path)
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


def handle_pending_disappeared_key(
    key_id: str, server_id: str, hostname: str, unix_user: str = ""
) -> dict:
    """A PENDING_REVIEW row whose (fingerprint, unix_user) pair no longer
    appears on the server. Mark REVOKED with revoked_automatically=true
    and a justification — same shape as handle_disappeared_key but
    INFO-level (no ANOMALY_DETECTED, no CRITICAL email), because the
    key was never validated as legitimate in the first place. Often the
    Unix user itself was just removed from the host (the user-reported
    case), or an admin cleaned up authorized_keys directly before
    reviewing.
    """
    db.execute(
        """
        UPDATE key_authorizations
        SET status = 'REVOKED',
            revoked_at = now(),
            revoked_by = NULL,
            revoked_automatically = true,
            revocation_justification = 'Disappeared before validation'
        WHERE key_id = %s AND server_id = %s AND unix_user = %s AND status = 'PENDING_REVIEW'
        """,
        (key_id, server_id, unix_user),
    )
    db.execute(
        """
        INSERT INTO audit_log (action, target_key, target_server, details)
        VALUES ('KEY_REVOKED', %s, %s, %s::jsonb)
        """,
        (
            key_id,
            server_id,
            json.dumps({
                "reason": "pending_review_disappeared",
                "hostname": hostname,
                "unix_user": unix_user,
            }),
        ),
    )
    key = db.query_one("SELECT fingerprint FROM ssh_keys WHERE id = %s", (key_id,))
    fp = key["fingerprint"] if key else "unknown"
    return {
        "type": "pending_disappeared",
        "fingerprint": fp,
        "hostname": hostname,
        "unix_user": unix_user,
    }


def try_recognize_collector_key(parsed: dict, server_id: str) -> bool:
    """Recognise our own collector key on the audit-collector account and
    insert it directly as ACTIVE (no PENDING_REVIEW, no anomaly).

    Called by collect.scan_server BEFORE the scenario-3 unknown-key path.
    Returns True if the key was recognised and persisted; False otherwise
    (the caller then falls through to the normal anomaly handling).

    A key is recognised iff:
      - it sits under unix_user == ssh.SSH_USER ('audit-collector')
      - its fingerprint matches the local per-server pubkey
        (/data/keys/per-server/<server_id>.key.pub) that SAM itself
        generated and deployed via provision-host.sh / rotation

    Without this, the very first scan after add_server / rotate would
    list our own freshly-deployed collector key as PENDING_REVIEW and
    raise a CRITICAL anomaly — forcing the admin to validate something
    we already wrote. That's the bug the user observed in the screenshots.
    """
    import os
    if parsed.get("unix_user") != ssh.SSH_USER:
        return False
    pubkey_path = os.path.join(ssh.PER_SERVER_KEYS_DIR, f"{server_id}.key.pub")
    if not os.path.isfile(pubkey_path):
        return False
    try:
        with open(pubkey_path) as fh:
            local_pubkey = fh.read().strip()
        local_fp = ssh._compute_pubkey_fingerprint(local_pubkey)
    except Exception:
        return False
    if local_fp != parsed["fingerprint"]:
        # Different key on audit-collector — that IS an anomaly, let the
        # caller handle it via the normal unknown-key path.
        return False

    # Upsert ssh_keys + key_authorizations as ACTIVE.
    db.execute(
        """
        INSERT INTO ssh_keys (fingerprint, key_type, key_size_bits, public_key, comment)
        VALUES (%s, %s, %s, %s, %s)
        ON CONFLICT (fingerprint) DO UPDATE SET
            last_seen = now(),
            key_size_bits = EXCLUDED.key_size_bits
        """,
        (parsed["fingerprint"], parsed["key_type"], parsed["key_size_bits"],
         parsed["public_key"], parsed.get("comment") or ""),
    )
    key = db.query_one("SELECT id FROM ssh_keys WHERE fingerprint = %s", (parsed["fingerprint"],))
    db.execute(
        """
        INSERT INTO key_authorizations (key_id, server_id, unix_user, status)
        VALUES (%s, %s, %s, 'ACTIVE')
        ON CONFLICT (key_id, server_id, unix_user) DO UPDATE SET
            status = 'ACTIVE',
            authorized_at = now(),
            revoked_at = NULL,
            revoked_by = NULL,
            revoked_automatically = false,
            revocation_justification = NULL
        """,
        (key["id"], server_id, ssh.SSH_USER),
    )
    return True


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


def set_key_expiry(
    fingerprint: str,
    expires_at: datetime,
    unix_user: str | None = None,
    hostname: str | None = None,
) -> None:
    """Set expiration on ACTIVE authorizations for a key.

    If unix_user and hostname are provided, updates only the specific
    (key, server, unix_user) authorization. Otherwise, updates all
    ACTIVE authorizations for the key.
    """
    if unix_user == "root":
        raise UserError("Cannot set an expiry on root's SSH key — this would revoke root access automatically")
    _check_fingerprint(fingerprint)
    key = db.query_one("SELECT id FROM ssh_keys WHERE fingerprint = %s", (fingerprint,))
    if not key:
        raise NotFoundError(f"Key not found: {fingerprint}")

    if unix_user is not None and hostname is not None:
        server = db.query_one("SELECT id FROM servers WHERE hostname = %s", (hostname,))
        if not server:
            raise NotFoundError(f"Server not found: {hostname}")
        db.execute(
            "UPDATE key_authorizations SET expires_at = %s"
            " WHERE key_id = %s AND unix_user = %s AND server_id = %s AND status = 'ACTIVE'",
            (expires_at, key["id"], unix_user, server["id"]),
        )
    else:
        db.execute(
            "UPDATE key_authorizations SET expires_at = %s"
            " WHERE key_id = %s AND status = 'ACTIVE' AND unix_user != 'root'",
            (expires_at, key["id"]),
        )


def remove_key_expiry(
    fingerprint: str,
    unix_user: str | None = None,
    hostname: str | None = None,
) -> None:
    """Remove expiration from ACTIVE authorizations for a key.

    If unix_user and hostname are provided, updates only the specific
    (key, server, unix_user) authorization. Otherwise, updates all
    ACTIVE authorizations for the key (root excluded).
    """
    if unix_user == "root":
        raise UserError("Cannot modify the expiry of the root account's SSH key")
    _check_fingerprint(fingerprint)
    key = db.query_one("SELECT id FROM ssh_keys WHERE fingerprint = %s", (fingerprint,))
    if not key:
        raise NotFoundError(f"Key not found: {fingerprint}")

    if unix_user is not None and hostname is not None:
        server = db.query_one("SELECT id FROM servers WHERE hostname = %s", (hostname,))
        if not server:
            raise NotFoundError(f"Server not found: {hostname}")
        db.execute(
            "UPDATE key_authorizations SET expires_at = NULL"
            " WHERE key_id = %s AND unix_user = %s AND server_id = %s AND status = 'ACTIVE'",
            (key["id"], unix_user, server["id"]),
        )
    else:
        db.execute(
            "UPDATE key_authorizations SET expires_at = NULL"
            " WHERE key_id = %s AND status = 'ACTIVE' AND unix_user != 'root'",
            (key["id"],),
        )


# ---------------------------------------------------------------------------
# Temporary access
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


VALID_SAM_GROUPS = ("sam-operator", "sam-pkg", "sam-root")


def _get_current_group(unix_user: str, hostname: str) -> str | None:
    """Return current sam_group for (unix_user, hostname) or None."""
    server = db.query_one(
        "SELECT id FROM servers WHERE hostname = %s AND is_active = true", (hostname,)
    )
    if not server:
        return None
    row = db.query_one(
        "SELECT sam_group FROM key_authorizations WHERE server_id = %s AND unix_user = %s AND status = 'ACTIVE'",
        (server["id"], unix_user),
    )
    return row["sam_group"] if row else None


def _has_active_session(unix_user: str, server_id) -> bool:
    """Return True if unix_user has an active SSH session on this server (from last scan)."""
    row = db.query_one(
        "SELECT 1 FROM ssh_sessions WHERE server_id = %s AND unix_user = %s AND is_active = true LIMIT 1",
        (server_id, unix_user),
    )
    return row is not None


def deploy_key(
    public_key: str,
    unix_user: str,
    hostname: str,
    expires_at,
    justification: str,
    admin_id: str,
    sam_group: str = None,
) -> dict:
    """
    Register public key in ssh_keys (if not exists), deploy via sam-add,
    create key_authorization ACTIVE with optional expiry.
    """
    if unix_user == "root":
        raise UserError("Cannot deploy a key for the root account")
    if not _UNIX_USER_RE.match(unix_user):
        raise UserError(
            f"Invalid Unix username: '{unix_user}' "
            "(lowercase letters, digits, _ and - only, max 32 chars)"
        )
    if sam_group is not None and sam_group not in VALID_SAM_GROUPS:
        raise UserError(f"Invalid SAM group: '{sam_group}'. Must be one of: {', '.join(VALID_SAM_GROUPS)}")
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

    key_path = _get_key_path(server["id"])
    ssh.ensure_scripts(hostname, server["id"], server["ip_address"], port=server["ssh_port"], key_path=key_path)
    ssh.add_key_on_server(hostname, unix_user, public_key.strip(), server["ip_address"], port=server["ssh_port"], sam_group=sam_group, key_path=key_path)

    db.execute(
        """
        INSERT INTO key_authorizations (key_id, server_id, unix_user, authorized_by, status, expires_at, sam_group)
        VALUES (%s, %s, %s, %s, 'ACTIVE', %s, %s)
        ON CONFLICT (key_id, server_id, unix_user) DO UPDATE SET
            status = 'ACTIVE',
            authorized_by = EXCLUDED.authorized_by,
            authorized_at = now(),
            expires_at = EXCLUDED.expires_at,
            sam_group = EXCLUDED.sam_group
        """,
        (key["id"], server["id"], unix_user, admin_id, expires_at, sam_group),
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
            json.dumps({"unix_user": unix_user, "fingerprint": fingerprint, "hostname": hostname, "sam_group": sam_group, "justification": justification}),
        ),
    )
    return {
        "fingerprint": fingerprint,
        "key_type": key_type,
        "unix_user": unix_user,
        "hostname": hostname,
        "expires_at": expires_at.isoformat() if expires_at else None,
        "sam_group": sam_group,
    }


def grant_group(unix_user: str, hostname: str, group: str, admin_id: str) -> dict:
    """Assign a SAM sudo group to a unix_user on a server."""
    if unix_user == "root":
        raise UserError("Cannot assign a SAM group to the root account")
    if group not in VALID_SAM_GROUPS:
        raise UserError(f"Invalid SAM group: '{group}'. Must be one of: {', '.join(VALID_SAM_GROUPS)}")
    server = db.query_one(
        "SELECT id, ip_address, ssh_port FROM servers WHERE hostname = %s AND is_active = true",
        (hostname,),
    )
    if not server:
        raise NotFoundError(f"Server not found or inactive: {hostname}")
    if _has_active_session(unix_user, server["id"]):
        raise UserError(f"User '{unix_user}' has an active session on {hostname} — group change blocked to avoid interrupting ongoing operations")
    row = db.query_one(
        "SELECT 1 FROM key_authorizations WHERE server_id = %s AND unix_user = %s AND status = 'ACTIVE'",
        (server["id"], unix_user),
    )
    if not row:
        raise UserError(f"No active key deployment for {unix_user} on {hostname}")
    key_path = _get_key_path(server["id"])
    actual_groups = ssh.grant_group_on_server(hostname, unix_user, group, server["ip_address"], port=server["ssh_port"], key_path=key_path)
    db.execute(
        "UPDATE key_authorizations SET sam_group = %s WHERE server_id = %s AND unix_user = %s AND status = 'ACTIVE'",
        (group, server["id"], unix_user),
    )
    db.execute(
        """
        INSERT INTO audit_log (action, performed_by, target_server, details)
        VALUES ('GROUP_GRANTED', %s, %s, %s::jsonb)
        """,
        (admin_id, server["id"], json.dumps({"unix_user": unix_user, "hostname": hostname, "sam_group": group})),
    )
    return {"unix_user": unix_user, "hostname": hostname, "sam_group": group, "actual_groups": actual_groups}


def revoke_group(unix_user: str, hostname: str, admin_id: str) -> dict:
    """Remove SAM sudo group from unix_user on a server. Works even if no group is currently set (force-strips server)."""
    if unix_user == "root":
        raise UserError("Cannot modify the SAM group of the root account")
    server = db.query_one(
        "SELECT id, ip_address, ssh_port FROM servers WHERE hostname = %s AND is_active = true",
        (hostname,),
    )
    if not server:
        raise NotFoundError(f"Server not found or inactive: {hostname}")
    if _has_active_session(unix_user, server["id"]):
        raise UserError(f"User '{unix_user}' has an active session on {hostname} — group change blocked to avoid interrupting ongoing operations")
    row = db.query_one(
        "SELECT sam_group FROM key_authorizations WHERE server_id = %s AND unix_user = %s AND status = 'ACTIVE'",
        (server["id"], unix_user),
    )
    if not row:
        raise UserError(f"No active key deployment for {unix_user} on {hostname}")
    current_group = row["sam_group"]
    key_path = _get_key_path(server["id"])
    actual_groups = ssh.revoke_group_on_server(hostname, unix_user, current_group, server["ip_address"], port=server["ssh_port"], key_path=key_path)
    if current_group is not None:
        db.execute(
            "UPDATE key_authorizations SET sam_group = NULL WHERE server_id = %s AND unix_user = %s AND status = 'ACTIVE'",
            (server["id"], unix_user),
        )
        db.execute(
            """
            INSERT INTO audit_log (action, performed_by, target_server, details)
            VALUES ('GROUP_REVOKED', %s, %s, %s::jsonb)
            """,
            (admin_id, server["id"], json.dumps({"unix_user": unix_user, "hostname": hostname, "sam_group": current_group})),
        )
    return {"unix_user": unix_user, "hostname": hostname, "sam_group": None, "actual_groups": actual_groups}


def change_group(unix_user: str, hostname: str, new_group: str, admin_id: str) -> dict:
    """Change SAM sudo group for unix_user on a server. Re-applies even if same group."""
    if unix_user == "root":
        raise UserError("Cannot modify the SAM group of the root account")
    if new_group not in VALID_SAM_GROUPS:
        raise UserError(f"Invalid SAM group: '{new_group}'. Must be one of: {', '.join(VALID_SAM_GROUPS)}")
    server = db.query_one(
        "SELECT id, ip_address, ssh_port FROM servers WHERE hostname = %s AND is_active = true",
        (hostname,),
    )
    if not server:
        raise NotFoundError(f"Server not found or inactive: {hostname}")
    if _has_active_session(unix_user, server["id"]):
        raise UserError(f"User '{unix_user}' has an active session on {hostname} — group change blocked to avoid interrupting ongoing operations")
    row = db.query_one(
        "SELECT sam_group FROM key_authorizations WHERE server_id = %s AND unix_user = %s AND status = 'ACTIVE'",
        (server["id"], unix_user),
    )
    if not row:
        raise UserError(f"No active key deployment for {unix_user} on {hostname}")
    old_group = row["sam_group"]
    key_path = _get_key_path(server["id"])
    if old_group and old_group != new_group:
        ssh.revoke_group_on_server(hostname, unix_user, old_group, server["ip_address"], port=server["ssh_port"], key_path=key_path)
    actual_groups = ssh.grant_group_on_server(hostname, unix_user, new_group, server["ip_address"], port=server["ssh_port"], key_path=key_path)
    db.execute(
        "UPDATE key_authorizations SET sam_group = %s WHERE server_id = %s AND unix_user = %s AND status = 'ACTIVE'",
        (new_group, server["id"], unix_user),
    )
    db.execute(
        """
        INSERT INTO audit_log (action, performed_by, target_server, details)
        VALUES ('GROUP_CHANGED', %s, %s, %s::jsonb)
        """,
        (admin_id, server["id"], json.dumps({"unix_user": unix_user, "hostname": hostname, "old_group": old_group, "new_group": new_group})),
    )
    return {"unix_user": unix_user, "hostname": hostname, "sam_group": new_group, "actual_groups": actual_groups}


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
        server = db.query_one("SELECT id, hostname, ip_address, ssh_port FROM servers WHERE id = %s", (req["server_id"],))
        if server:
            key_path = _get_key_path(server["id"])
            ssh.revoke_on_server(server["hostname"], key["fingerprint"], ip=server["ip_address"], port=server["ssh_port"], key_path=key_path)

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
# Servers
# ---------------------------------------------------------------------------

def add_server(
    hostname: str, ip: str, ssh_user: str = "root", ssh_password: str = "",
    env: str | None = None, os_family: str | None = None,
    ssh_port: int = 22, admin_id: str | None = None,
    scan_sync: bool = False,
) -> dict:
    """Add and provision a server atomically. Server is only created in DB if SSH provisioning succeeds."""
    import uuid
    import os
    ip = _validate_ip(ip)
    env = _normalize_environment(env)
    existing = db.query_one(
        "SELECT hostname FROM servers WHERE ip_address = %s", (ip,)
    )
    if existing:
        raise UserError(f"IP {ip} is already used by server '{existing['hostname']}'")

    # Step 1: generate UUID and per-server keypair
    server_id = str(uuid.uuid4())
    keypair_base = os.path.join(ssh.PER_SERVER_KEYS_DIR, server_id)

    try:
        _, pubkey = ssh._generate_keypair(keypair_base)
    except Exception as exc:
        raise UserError(f"Failed to generate per-server keypair: {exc}")

    # Step 2: SSH provision with the per-server pubkey
    try:
        ssh.provision_server(ip, ssh_user, ssh_password, ssh_port, pubkey=pubkey)
    except Exception as exc:
        # Cleanup keypair on SSH failure
        for ext in (".key", ".key.pub"):
            try:
                os.remove(keypair_base + ext)
            except FileNotFoundError:
                pass
        raise

    # Step 3: INSERT with explicit UUID + is_provisioned=TRUE
    db.execute(
        """INSERT INTO servers (id, hostname, ip_address, environment, os_family, ssh_port, is_active, is_provisioned)
           VALUES (%s, %s, %s, %s, %s, %s, TRUE, TRUE)""",
        (server_id, hostname, ip, env, os_family, ssh_port),
    )

    # Step 4: Audit logs
    db.execute(
        """INSERT INTO audit_log (action, performed_by, target_server, details)
           VALUES ('SERVER_ADDED', %s, %s, %s::jsonb)""",
        (admin_id, server_id, json.dumps({"hostname": hostname, "ip": ip, "environment": env, "ssh_port": ssh_port})),
    )
    db.execute(
        """INSERT INTO audit_log (action, performed_by, target_server, details)
           VALUES ('SERVER_PROVISIONED', %s, %s, %s::jsonb)""",
        (admin_id, server_id, json.dumps({"hostname": hostname, "ssh_user": ssh_user, "ssh_port": ssh_port})),
    )

    fingerprint = ssh._compute_pubkey_fingerprint(pubkey)
    db.execute(
        """INSERT INTO audit_log (action, performed_by, target_server, details)
           VALUES ('COLLECTOR_KEY_GENERATED', %s, %s, %s::jsonb)""",
        (admin_id, server_id, json.dumps({"server_id": server_id, "fingerprint": fingerprint})),
    )

    server = db.query_one("SELECT * FROM servers WHERE id = %s", (server_id,))
    _trigger_initial_scan(server, admin_id, sync=scan_sync)
    return server


def _trigger_initial_scan(server: dict, admin_id: str | None, *, sync: bool = False) -> None:
    """Run an initial scan after provisioning.

    Used by add_server / activate_server so a fresh host shows up
    with its current authorized_keys without the admin needing to
    click 'Scan' manually.

    sync=False (default): fire-and-forget thread — for the web API
    where the HTTP response must return immediately.
    sync=True: blocking call — for the CLI, where a daemon thread
    would be killed when the process exits before the scan completes.
    """
    import collect

    def _run():
        try:
            collect.scan_server(dict(server), admin_id=admin_id)
        except Exception:
            logging.exception("Initial scan after provisioning failed for %s", server.get("hostname"))

    if sync:
        _run()
    else:
        import threading
        threading.Thread(target=_run, daemon=True).start()


def provision_server(hostname: str, ssh_user: str = "root", ssh_password: str = "", ssh_port: int = 22, admin_id: str | None = None) -> None:
    """Provision a remote server. Never stores the password."""
    import os
    server = db.query_one(
        "SELECT id, ip_address FROM servers WHERE hostname = %s AND is_active = true",
        (hostname,),
    )
    if not server:
        raise NotFoundError(f"Server not found or inactive: {hostname}")

    # Read the per-server pubkey
    pubkey_path = os.path.join(ssh.PER_SERVER_KEYS_DIR, f"{server['id']}.key.pub")
    if not os.path.isfile(pubkey_path):
        raise UserError("Per-server keypair not found - please delete and re-add this server")

    with open(pubkey_path, "r") as fh:
        pubkey = fh.read().strip()

    ssh.provision_server(server["ip_address"], ssh_user, ssh_password, ssh_port, pubkey=pubkey)

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


_HOSTNAME_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-.]*[a-zA-Z0-9])?$")


def _validate_hostname(hostname: str) -> str:
    h = (hostname or "").strip()
    if not h or len(h) > 253 or not _HOSTNAME_RE.match(h):
        raise UserError(f"Invalid hostname: {hostname!r}")
    return h


def update_server(
    hostname: str, new_ip: str, new_env: str, new_os_family: str | None,
    ssh_port: int = 22, admin_id: str | None = None, max_sessions: int = 2,
    new_hostname: str | None = None,
) -> dict:
    """Update server hostname, IP, environment, OS, SSH port, max_sessions.

    If IP changes, run ssh-keyscan. If hostname changes, log SERVER_RENAMED;
    historical audit_log entries keep the old hostname intentionally so the
    history remains accurate.
    """
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

    rename_to = None
    if new_hostname is not None:
        candidate = _validate_hostname(new_hostname)
        if candidate != hostname:
            clash = db.query_one(
                "SELECT id FROM servers WHERE hostname = %s AND id != %s",
                (candidate, server["id"]),
            )
            if clash:
                raise UserError(f"Hostname {candidate!r} is already used by another server")
            rename_to = candidate

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

    effective_hostname = rename_to or hostname
    db.execute(
        "UPDATE servers SET hostname = %s, ip_address = %s, environment = %s, os_family = %s, ssh_port = %s, max_sessions = %s WHERE id = %s",
        (effective_hostname, new_ip, new_env, new_os_family, ssh_port, max_sessions, server["id"]),
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
                "hostname": effective_hostname,
                "old_ip": old_ip, "new_ip": new_ip,
                "old_env": old_env, "new_env": new_env,
                "old_os": old_os, "new_os": new_os_family,
                "old_port": old_port, "new_port": ssh_port,
                "old_max_sessions": old_max_sessions, "new_max_sessions": max_sessions,
            }),
        ),
    )
    if rename_to:
        db.execute(
            """
            INSERT INTO audit_log (action, performed_by, target_server, details)
            VALUES ('SERVER_RENAMED', %s, %s, %s::jsonb)
            """,
            (admin_id, server["id"], json.dumps({"old_hostname": hostname, "new_hostname": rename_to})),
        )

    server = dict(server)
    server["hostname"] = effective_hostname
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
    import os
    server = db.query_one("SELECT id FROM servers WHERE hostname = %s", (hostname,))
    if not server:
        raise NotFoundError(f"Server not found: {hostname}")
    sid = server["id"]
    db.execute("DELETE FROM audit_log WHERE target_server = %s", (sid,))
    db.execute("DELETE FROM access_requests WHERE server_id = %s", (sid,))
    db.execute("DELETE FROM key_authorizations WHERE server_id = %s", (sid,))
    db.execute("DELETE FROM servers WHERE id = %s", (sid,))

    # Cleanup per-server keypair files
    for ext in (".key", ".key.pub"):
        try:
            path = os.path.join(ssh.PER_SERVER_KEYS_DIR, f"{sid}{ext}")
            if os.path.isfile(path):
                os.remove(path)
        except FileNotFoundError:
            pass


def register_server(
    hostname: str, ip: str, ssh_port: int = 22,
    env: str | None = None, os_family: str | None = None,
    admin_id: str | None = None,
) -> dict:
    """Create a server in DB and generate its keypair, without trying SSH.

    Status: is_provisioned=FALSE, is_active=TRUE.
    Use case: admin will provision the host manually with their own SSH
    credentials (bulk bootstrap workflow with cloud-init etc.).
    """
    import uuid
    import os
    ip = _validate_ip(ip)
    env = _normalize_environment(env)
    existing = db.query_one(
        "SELECT hostname FROM servers WHERE ip_address = %s", (ip,)
    )
    if existing:
        raise UserError(f"IP {ip} is already used by server '{existing['hostname']}'")

    # Generate UUID + keypair
    server_id = str(uuid.uuid4())
    keypair_base = os.path.join(ssh.PER_SERVER_KEYS_DIR, server_id)

    try:
        _, pubkey = ssh._generate_keypair(keypair_base)
    except Exception as exc:
        raise UserError(f"Failed to generate per-server keypair: {exc}")

    # INSERT with is_provisioned=FALSE
    db.execute(
        """INSERT INTO servers (id, hostname, ip_address, environment, os_family, ssh_port, is_active, is_provisioned)
           VALUES (%s, %s, %s, %s, %s, %s, TRUE, FALSE)""",
        (server_id, hostname, ip, env, os_family, ssh_port),
    )

    # Audit COLLECTOR_KEY_GENERATED
    fingerprint = ssh._compute_pubkey_fingerprint(pubkey)
    db.execute(
        """INSERT INTO audit_log (action, performed_by, target_server, details)
           VALUES ('COLLECTOR_KEY_GENERATED', %s, %s, %s::jsonb)""",
        (admin_id, server_id, json.dumps({"server_id": server_id, "fingerprint": fingerprint})),
    )

    return {"server_id": server_id, "hostname": hostname, "public_key": pubkey, "fingerprint": fingerprint}


def activate_server(hostname: str, admin_id: str | None = None, scan_sync: bool = False) -> dict:
    """Verify SSH connectivity with the per-server key, mark as provisioned.

    Use case: after the admin has deployed the pubkey manually on the host
    (step 2 of bulk bootstrap workflow), this confirms it works and
    triggers the first scan.
    """
    server = db.query_one(
        "SELECT id, ip_address, ssh_port, is_provisioned FROM servers WHERE hostname = %s",
        (hostname,),
    )
    if not server:
        raise NotFoundError(f"Server not found: {hostname}")
    if server["is_provisioned"]:
        raise UserError(f"Server {hostname} is already provisioned")

    key_path = _get_key_path(server["id"])
    # Ensure the host key is in known_hosts (RejectPolicy will refuse otherwise)
    try:
        ssh._fetch_host_key(server["ip_address"], server["ssh_port"])
    except Exception as exc:
        raise UserError(f"Failed to fetch host key for {server['ip_address']}: {exc}", status=502)

    try:
        # Test connectivity by running a no-op command
        client = ssh._connect(server["ip_address"], server["ssh_port"], key_path=key_path)
        client.exec_command("true")
        client.close()
    except ssh.SSHError as exc:
        raise UserError(f"SSH connectivity check failed: {exc}", status=502)
    except Exception as exc:
        raise UserError(f"SSH connectivity check failed: {exc}", status=502)

    db.execute("UPDATE servers SET is_provisioned = TRUE WHERE id = %s", (server["id"],))
    db.execute(
        """INSERT INTO audit_log (action, performed_by, target_server, details)
           VALUES ('SERVER_PROVISIONED', %s, %s, %s::jsonb)""",
        (admin_id, server["id"], json.dumps({"hostname": hostname, "method": "activate"})),
    )

    full_server = db.query_one("SELECT * FROM servers WHERE id = %s", (server["id"],))
    _trigger_initial_scan(full_server, admin_id, sync=scan_sync)
    return {"hostname": hostname, "status": "provisioned"}


def rotate_collector_key(hostname: str, admin_id: str) -> dict:
    """Manual rotation triggered from ServerDetail button.

    After ssh.rotate_per_server_key swaps the keypair on the host:
      - mark the previous audit-collector key_authorization on this
        server as REVOKED (reason "Collector key rotated") so the UI
        stops showing it as ACTIVE
      - INSERT the new ssh_keys row + ACTIVE authorization so the new
        key appears in the keys list immediately (without waiting for
        the next scan and without being flagged PENDING_REVIEW as an
        anomaly)
      - trigger an async scan to refresh last_seen and detect any
        unrelated drift introduced during the rotation window
    """
    server = db.query_one(
        "SELECT id, ip_address, ssh_port, is_active FROM servers WHERE hostname = %s",
        (hostname,),
    )
    if not server or not server["is_active"]:
        raise NotFoundError(f"Server not found or inactive: {hostname}")

    try:
        new_fp = ssh.rotate_per_server_key(
            hostname,
            server["ip_address"],
            server["ssh_port"],
            server["id"],
        )

        # Read the freshly-written pubkey on disk to get type + raw content.
        # ssh.rotate_per_server_key has already renamed <id>.key.new.pub
        # to <id>.key.pub, so the canonical path now holds the new key.
        pubkey_info = get_collector_key_for_server(hostname)
        new_pubkey = pubkey_info["public_key"]
        # Collector keys are always ed25519 (see ssh._generate_keypair),
        # so key_size_bits stays NULL — same as the initial insert in
        # add_server.
        key_type = new_pubkey.split()[0]

        # Mark previous ACTIVE audit-collector authorizations on this
        # server as REVOKED. There should be exactly one, but the loop
        # tolerates degenerate states (e.g. a manual DB tweak).
        db.execute(
            """
            UPDATE key_authorizations
            SET status = 'REVOKED',
                revoked_at = now(),
                revoked_by = %s,
                revoked_automatically = false,
                revocation_justification = 'Collector key rotated'
            WHERE server_id = %s AND unix_user = %s
              AND status IN ('ACTIVE', 'PENDING_REVIEW')
            """,
            (admin_id, server["id"], ssh.SSH_USER),
        )

        # Insert the new key + its ACTIVE authorization for audit-collector.
        db.execute(
            """
            INSERT INTO ssh_keys (fingerprint, key_type, public_key, comment)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (fingerprint) DO UPDATE SET last_seen = now()
            """,
            (new_fp, key_type, new_pubkey, ""),
        )
        new_key_row = db.query_one(
            "SELECT id FROM ssh_keys WHERE fingerprint = %s", (new_fp,)
        )
        db.execute(
            """
            INSERT INTO key_authorizations (key_id, server_id, unix_user, authorized_by, status)
            VALUES (%s, %s, %s, %s, 'ACTIVE')
            ON CONFLICT (key_id, server_id, unix_user) DO UPDATE SET
                status = 'ACTIVE',
                authorized_by = EXCLUDED.authorized_by,
                authorized_at = now(),
                revoked_at = NULL,
                revoked_by = NULL,
                revoked_automatically = false,
                revocation_justification = NULL
            """,
            (new_key_row["id"], server["id"], ssh.SSH_USER, admin_id),
        )

        db.execute(
            """INSERT INTO audit_log (action, performed_by, target_server, details)
               VALUES ('COLLECTOR_KEY_ROTATED', %s, %s, %s::jsonb)""",
            (admin_id, server["id"], json.dumps({"server_id": server["id"], "fingerprint": new_fp})),
        )

        # Refresh the rest of the host's state (last_seen on other keys,
        # detect any drift introduced during the rotation window).
        # Fire-and-forget — the caller is an HTTP request that should
        # return promptly, not block on a multi-second scan.
        full_server = db.query_one("SELECT * FROM servers WHERE id = %s", (server["id"],))
        _trigger_initial_scan(full_server, admin_id, sync=False)

        return {"status": "rotated", "fingerprint": new_fp}
    except ssh.SSHError as exc:
        db.execute(
            """INSERT INTO audit_log (action, performed_by, target_server, details)
               VALUES ('COLLECTOR_KEY_ROTATION_FAILED', %s, %s, %s::jsonb)""",
            (admin_id, server["id"], json.dumps({"error": str(exc)})),
        )
        raise UserError(f"Rotation failed: {exc}", status=502)


def get_collector_key_for_server(hostname: str) -> dict:
    """Return {fingerprint, public_key} for the per-server key (read-only)."""
    import os
    server = db.query_one("SELECT id FROM servers WHERE hostname = %s", (hostname,))
    if not server:
        raise NotFoundError(f"Server not found: {hostname}")

    pubkey_path = os.path.join(ssh.PER_SERVER_KEYS_DIR, f"{server['id']}.key.pub")
    if not os.path.isfile(pubkey_path):
        raise UserError("Per-server public key not found - server may not be provisioned")

    with open(pubkey_path, "r") as fh:
        pubkey = fh.read().strip()

    fingerprint = ssh._compute_pubkey_fingerprint(pubkey)
    return {"fingerprint": fingerprint, "public_key": pubkey}


# ---------------------------------------------------------------------------
# Administrators
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
        raise UserError(f"Username '{username}' is already taken", status=409)
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
    if unix_user == "root":
        raise UserError("Cannot lock the root account")
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
    key_path = _get_key_path(server["id"])
    ssh.ensure_scripts(hostname, server["id"], server["ip_address"], port=server["ssh_port"], key_path=key_path)
    ssh.lock_user_on_server(hostname, unix_user, server["ip_address"], port=server["ssh_port"], key_path=key_path)
    db.execute(
        """INSERT INTO audit_log (action, performed_by, target_server, details)
           VALUES ('USER_LOCKED', %s, %s, %s::jsonb)""",
        (admin_id, server["id"], json.dumps({"unix_user": unix_user, "hostname": hostname}))
    )
    return {"unix_user": unix_user, "hostname": hostname, "status": "locked"}


def unlock_user(unix_user: str, hostname: str, admin_id: str) -> dict:
    """Unlock a Unix user account on a remote server."""
    if unix_user == "root":
        raise UserError("Cannot unlock the root account")
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
    key_path = _get_key_path(server["id"])
    ssh.ensure_scripts(hostname, server["id"], server["ip_address"], port=server["ssh_port"], key_path=key_path)
    ssh.unlock_user_on_server(hostname, unix_user, server["ip_address"], port=server["ssh_port"], key_path=key_path)
    db.execute(
        """INSERT INTO audit_log (action, performed_by, target_server, details)
           VALUES ('USER_UNLOCKED', %s, %s, %s::jsonb)""",
        (admin_id, server["id"], json.dumps({"unix_user": unix_user, "hostname": hostname}))
    )
    return {"unix_user": unix_user, "hostname": hostname, "status": "unlocked"}


# ---------------------------------------------------------------------------
# Audit sshd config
# ---------------------------------------------------------------------------

# sshd hardening policy (read-only audit, not a conformance claim).
# Each entry: directive_lower, rule, severity, ref, optional
# rule is a tuple ("in", [values]) | ("le", n) | ("ge", n) | ("gt", n)
SSHD_HARDENING_POLICY = [
    {"directive": "permitrootlogin",                "rule": ("in", ["no"]),             "severity": "critical"},
    {"directive": "passwordauthentication",         "rule": ("in", ["no"]),             "severity": "critical"},
    {"directive": "permitemptypasswords",           "rule": ("in", ["no"]),             "severity": "critical"},
    {"directive": "kbdinteractiveauthentication",   "rule": ("in", ["no"]),             "severity": "warning"},
    {"directive": "challengeresponseauthentication","rule": ("in", ["no"]),             "severity": "warning", "optional": True},
    {"directive": "hostbasedauthentication",        "rule": ("in", ["no"]),             "severity": "critical"},
    {"directive": "ignorerhosts",                   "rule": ("in", ["yes"]),            "severity": "critical"},
    {"directive": "x11forwarding",                  "rule": ("in", ["no"]),             "severity": "warning"},
    {"directive": "allowtcpforwarding",             "rule": ("in", ["no", "local"]),    "severity": "warning"},
    {"directive": "maxauthtries",                   "rule": ("le", 3),                  "severity": "warning"},
    {"directive": "logingracetime",                 "rule": ("le", 60),                 "severity": "warning"},
    {"directive": "clientaliveinterval",            "rule": ("gt", 0),                  "severity": "info"},
    {"directive": "loglevel",                       "rule": ("in", ["INFO", "VERBOSE"]),"severity": "info"},
    {"directive": "usepam",                         "rule": ("in", ["yes"]),            "severity": "warning"},
]


def _evaluate_rule(rule, actual: str | None) -> str:
    """Return 'ok' | 'fail' | 'missing'. `actual` is the sshd -T value (lowercase for in-rules)."""
    if actual is None:
        return "missing"
    op, expected = rule
    if op == "in":
        return "ok" if actual.lower() in [str(v).lower() for v in expected] else "fail"
    try:
        n = int(actual)
    except (TypeError, ValueError):
        return "fail"
    if op == "le":
        return "ok" if n <= expected else "fail"
    if op == "ge":
        return "ok" if n >= expected else "fail"
    if op == "gt":
        return "ok" if n > expected else "fail"
    return "fail"


def _format_expected(rule) -> str:
    op, val = rule
    if op == "in":
        return " | ".join(str(v) for v in val)
    if op == "le": return f"<= {val}"
    if op == "ge": return f">= {val}"
    if op == "gt": return f"> {val}"
    return str(val)


def check_sshd_compliance(parsed: dict) -> dict:
    """Apply SSHD_HARDENING_POLICY to a sshd -T parsed dict.

    Returns {"checks": [...], "summary": {ok, warning, critical, info, missing}, "overall": ...}.
    No I/O, pure function.
    """
    checks = []
    summary = {"ok": 0, "warning": 0, "critical": 0, "info": 0, "missing": 0}
    for entry in SSHD_HARDENING_POLICY:
        directive = entry["directive"]
        actual = parsed.get(directive)
        verdict = _evaluate_rule(entry["rule"], actual)
        is_optional = entry.get("optional", False)
        if verdict == "missing" and is_optional:
            continue  # skip silently
        if verdict == "ok":
            status = "ok"
            summary["ok"] += 1
        elif verdict == "missing":
            status = "missing"
            summary["missing"] += 1
        else:
            # fail -> use declared severity
            status = entry["severity"]
            summary[status] += 1
        checks.append({
            "directive": directive,
            "expected": _format_expected(entry["rule"]),
            "actual": actual,
            "status": status,
            "severity": entry["severity"],
        })
    if summary["critical"]:
        overall = "critical"
    elif summary["warning"]:
        overall = "warning"
    elif summary["missing"]:
        overall = "warning"
    elif summary["info"]:
        overall = "warning"
    else:
        overall = "ok"
    return {"checks": checks, "summary": summary, "overall": overall}


def audit_server_sshd(hostname: str, admin_id: str | None = None) -> dict:
    """Read server (ip, port) from DB, call ssh.audit_sshd_config, apply policy.

    Raises UserError(404) if server unknown, UserError(503/502) if SSH fails.
    No DB write, no audit_log (read-only).
    """
    row = db.query_one(
        "SELECT id, ip_address, ssh_port, is_active FROM servers WHERE hostname = %s",
        (hostname,),
    )
    if not row:
        raise NotFoundError(f"Server {hostname!r} not found")
    if not row["is_active"]:
        raise UserError("Server is disabled", status=409)
    try:
        key_path = _get_key_path(row["id"])
        parsed = ssh.audit_sshd_config(hostname, row["ip_address"], row["ssh_port"], key_path=key_path)
    except ssh.SSHError as exc:
        raise UserError(f"SSH audit failed: {exc}", status=502)
    return check_sshd_compliance(parsed)
