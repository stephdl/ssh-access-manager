"""
web.py — API REST Flask JSON.
Toutes les routes retournent JSON. Prefixe /api/.
Importe actions.py pour la logique metier — jamais de duplication.
"""
import json
import logging
import os
import threading
from datetime import datetime, timezone
from functools import wraps

from flask import Flask, g, jsonify, request, session
from werkzeug.security import check_password_hash

import actions
import alerts
import collect as collect_mod
import db
import ssh

# ---------------------------------------------------------------------------
# Rate limiter — protection brute-force sur /api/auth/login
# Stockage en mémoire : {ip: {"count": N, "banned_until": timestamp}}
# ---------------------------------------------------------------------------
_login_attempts: dict = {}
_login_lock = threading.Lock()


def _get_client_ip() -> str:
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


def _load_login_settings() -> tuple[int, int]:
    try:
        row_attempts = db.query_one("SELECT value FROM settings WHERE key = 'login_max_attempts'")
        row_ban = db.query_one("SELECT value FROM settings WHERE key = 'login_ban_seconds'")
        max_attempts = int(row_attempts["value"]) if row_attempts else 10
        ban_seconds = int(row_ban["value"]) if row_ban else 300
    except Exception:
        max_attempts, ban_seconds = 10, 300
    return max_attempts, ban_seconds


def _check_rate_limit(ip: str) -> tuple[bool, int]:
    """Retourne (is_banned, seconds_remaining)."""
    _, ban_seconds = _load_login_settings()
    with _login_lock:
        entry = _login_attempts.get(ip)
        if not entry:
            return False, 0
        banned_until = entry.get("banned_until", 0)
        now = datetime.now(timezone.utc).timestamp()
        if banned_until and now < banned_until:
            return True, int(banned_until - now)
        if banned_until and now >= banned_until:
            _login_attempts.pop(ip, None)
        return False, 0


def _record_failure(ip: str, username: str) -> bool:
    """Incrémente le compteur. Retourne True si l'IP vient d'être bannie."""
    max_attempts, ban_seconds = _load_login_settings()
    now = datetime.now(timezone.utc).timestamp()
    with _login_lock:
        entry = _login_attempts.setdefault(ip, {"count": 0, "banned_until": 0})
        entry["count"] += 1
        count = entry["count"]
        if count >= max_attempts and not entry["banned_until"]:
            entry["banned_until"] = now + ban_seconds
            return True
    return False


def _reset_attempts(ip: str) -> None:
    with _login_lock:
        _login_attempts.pop(ip, None)


# ---------------------------------------------------------------------------
# Session timeout — constantes (pas de config DB, pas de UI)
# ---------------------------------------------------------------------------
SESSION_SHORT_MINUTES = 30   # sans "remember me"
SESSION_LONG_HOURS = 8       # avec "remember me"


app = Flask(__name__)
_flask_secret = os.environ.get("FLASK_SECRET_KEY")
if not _flask_secret:
    import warnings
    warnings.warn("FLASK_SECRET_KEY not set — sessions are insecure", RuntimeWarning, stacklevel=1)
    _flask_secret = "changeme"
app.secret_key = _flask_secret


# ---------------------------------------------------------------------------
# Authentification par session Flask
# ---------------------------------------------------------------------------

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        admin_id = session.get("admin_id")
        if not admin_id:
            return jsonify({"error": "Unauthorized"}), 401
        # Check session expiry
        expires_at = session.get("expires_at")
        if expires_at and datetime.now(timezone.utc).timestamp() > expires_at:
            session.clear()
            return jsonify({"error": "Session expired"}), 401
        admin = db.query_one(
            "SELECT id, username, role FROM administrators WHERE id = %s AND is_active = true",
            (admin_id,),
        )
        if not admin:
            return jsonify({"error": "Unauthorized"}), 401
        g.admin_id = admin["id"]
        g.admin_username = admin["username"]
        g.admin_role = admin["role"]
        return f(*args, **kwargs)
    return decorated


def require_role(*roles):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if g.admin_role not in roles:
                return jsonify({"error": "Insufficient permissions"}), 403
            return f(*args, **kwargs)
        return decorated
    return decorator


# ---------------------------------------------------------------------------
# Auth : login / logout / me
# ---------------------------------------------------------------------------

@app.route("/api/auth/login", methods=["POST"])
def auth_login():
    data = request.get_json(force=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")
    if not username or not password:
        return jsonify({"error": "username and password required"}), 400

    ip = _get_client_ip()

    # Check if IP is currently banned
    is_banned, retry_after = _check_rate_limit(ip)
    if is_banned:
        print(f"[LOGIN_BANNED] ip={ip} username={username} retry_after={retry_after}s", flush=True)
        return jsonify({"error": "Too many failed attempts. Try again later."}), 429

    admin = db.query_one(
        "SELECT id, username, password_hash FROM administrators WHERE username = %s AND is_active = true",
        (username,),
    )
    if not admin or not admin["password_hash"] or not check_password_hash(admin["password_hash"], password):
        just_banned = _record_failure(ip, username)
        print(f"[LOGIN_FAILED] ip={ip} username={username}", flush=True)
        try:
            db.execute(
                "INSERT INTO audit_log (action, details) VALUES ('LOGIN_FAILED', %s)",
                (json.dumps({"ip": ip, "username": username}),),
            )
        except Exception:
            pass
        if just_banned:
            _, ban_seconds = _load_login_settings()
            print(f"[LOGIN_BANNED] ip={ip} username={username} ban_seconds={ban_seconds}", flush=True)
            try:
                db.execute(
                    "INSERT INTO audit_log (action, details) VALUES ('LOGIN_BANNED', %s)",
                    (json.dumps({"ip": ip, "username": username, "ban_seconds": ban_seconds}),),
                )
            except Exception:
                pass
        return jsonify({"error": "Invalid credentials"}), 401

    _reset_attempts(ip)
    remember_me = bool(data.get("remember_me", False))
    expires_delta = SESSION_LONG_HOURS * 3600 if remember_me else SESSION_SHORT_MINUTES * 60
    expires_at = datetime.now(timezone.utc).timestamp() + expires_delta
    session.clear()
    session["admin_id"] = str(admin["id"])
    session["admin_username"] = admin["username"]
    session["expires_at"] = expires_at
    return jsonify({"username": admin["username"]}), 200


@app.route("/api/auth/logout", methods=["POST"])
def auth_logout():
    session.clear()
    return jsonify({"status": "logged out"}), 200


@app.route("/api/auth/me", methods=["GET"])
def auth_me():
    admin_id = session.get("admin_id")
    if not admin_id:
        return jsonify({"error": "Unauthorized"}), 401
    admin = db.query_one(
        "SELECT username, email, role FROM administrators WHERE id = %s AND is_active = true",
        (admin_id,),
    )
    if not admin:
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify(dict(admin)), 200


def _parse_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    for fmt in ("%Y-%m-%dT%H:%M", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


# ---------------------------------------------------------------------------
# Serveurs
# ---------------------------------------------------------------------------

@app.route("/api/servers", methods=["GET"])
@require_auth
def list_servers():
    rows = db.query("SELECT * FROM servers ORDER BY hostname")
    return jsonify(rows)


@app.route("/api/servers/<hostname>", methods=["GET"])
@require_auth
def get_server(hostname):
    row = db.query_one("SELECT * FROM servers WHERE hostname = %s", (hostname,))
    if not row:
        return jsonify({"error": "Not found"}), 404
    return jsonify(row)


@app.route("/api/servers", methods=["POST"])
@require_auth
@require_role("sysadmin")
def add_server():
    data = request.get_json(force=True) or {}
    try:
        server = actions.add_server(
            data["hostname"], data["ip"], data["environment"],
            data.get("os_family"), g.admin_id,
        )
        return jsonify(server), 201
    except (KeyError, ValueError) as e:
        logging.warning("%s", str(e).replace("\n", "\\n").replace("\r", "\\r"))
        return jsonify({"error": str(e)}), 400


@app.route("/api/servers/<hostname>", methods=["PUT"])
@require_auth
@require_role("sysadmin")
def update_server(hostname):
    data = request.get_json(force=True) or {}
    try:
        actions.update_server(
            hostname, data["ip"], data["environment"],
            data.get("os_family"), g.admin_id,
        )
        return jsonify({"message": "Server updated"})
    except (KeyError, ValueError) as e:
        logging.warning("%s", str(e).replace("\n", "\\n").replace("\r", "\\r"))
        return jsonify({"error": str(e)}), 404 if isinstance(e, ValueError) else 400


@app.route("/api/servers/<hostname>/disable", methods=["PUT"])
@require_auth
@require_role("sysadmin")
def disable_server(hostname):
    try:
        actions.disable_server(hostname, g.admin_id)
        return jsonify({"status": "disabled"})
    except ValueError as e:
        logging.warning("%s", str(e).replace("\n", "\\n").replace("\r", "\\r"))
        return jsonify({"error": str(e)}), 404


@app.route("/api/servers/<hostname>/enable", methods=["PUT"])
@require_auth
@require_role("sysadmin")
def enable_server(hostname):
    try:
        actions.enable_server(hostname, g.admin_id)
        return jsonify({"status": "enabled"})
    except ValueError as e:
        logging.warning("%s", str(e).replace("\n", "\\n").replace("\r", "\\r"))
        return jsonify({"error": str(e)}), 404


@app.route("/api/servers/<hostname>", methods=["DELETE"])
@require_auth
@require_role("sysadmin")
def delete_server(hostname):
    try:
        actions.delete_server(hostname, g.admin_id)
        return jsonify({"status": "deleted"})
    except ValueError as e:
        logging.warning("%s", str(e).replace("\n", "\\n").replace("\r", "\\r"))
        return jsonify({"error": str(e)}), 404


@app.route("/api/servers/<hostname>/scan", methods=["POST"])
@require_auth
@require_role("sysadmin", "operator")
def scan_server(hostname):
    results = collect_mod.run_scan(hostname=hostname)
    return jsonify(results)


def _serialize_session(row) -> dict:
    d = dict(row)
    for k in ('login_at', 'logout_at', 'collected_at'):
        if d.get(k):
            d[k] = d[k].isoformat()
    return d


@app.route("/api/servers/<hostname>/sessions", methods=["GET"])
@require_auth
@require_role("sysadmin", "operator")
def get_server_sessions(hostname):
    server = db.query_one("SELECT id FROM servers WHERE hostname = %s", (hostname,))
    if not server:
        return jsonify({"error": "Server not found"}), 404
    active = db.query(
        """
        SELECT unix_user, tty, host(login_ip) AS login_ip, login_at, collected_at
        FROM ssh_sessions
        WHERE server_id = %s AND is_active = true
        ORDER BY login_at DESC
        """,
        (server["id"],),
    )
    recent = db.query(
        """
        SELECT unix_user, tty, host(login_ip) AS login_ip, login_at, logout_at, collected_at
        FROM ssh_sessions
        WHERE server_id = %s AND is_active = false
        ORDER BY login_at DESC
        LIMIT 5
        """,
        (server["id"],),
    )
    return jsonify({
        "active": [_serialize_session(r) for r in active],
        "recent": [_serialize_session(r) for r in recent],
    })


@app.route("/api/servers/<hostname>/sessions/refresh", methods=["POST"])
@require_auth
@require_role("sysadmin", "operator")
def refresh_server_sessions(hostname):
    server = db.query_one(
        "SELECT id, host(ip_address) AS ip_address FROM servers WHERE hostname = %s AND is_active = true",
        (hostname,),
    )
    if not server:
        return jsonify({"error": "Server not found or inactive"}), 404
    ip = str(server["ip_address"])
    try:
        ssh.collect_sessions_on_server(hostname, server["id"], ip)
        return jsonify({"status": "refreshed"})
    except Exception as e:
        logging.exception("collect_sessions_on_server failed on %s (%s)", hostname, ip)
        return jsonify({"error": str(e) or repr(e)}), 502


@app.route("/api/servers/<hostname>/sessions/history", methods=["GET"])
@require_auth
@require_role("sysadmin", "operator")
def get_server_sessions_history(hostname):
    server = db.query_one("SELECT id FROM servers WHERE hostname = %s", (hostname,))
    if not server:
        return jsonify({"error": "Server not found"}), 404
    unix_user = request.args.get("user", "").strip()
    login_ip = request.args.get("ip", "").strip()
    since = request.args.get("since", "").strip()
    conditions = ["server_id = %s"]
    params = [server["id"]]
    if unix_user:
        conditions.append("unix_user ILIKE %s")
        params.append(f"%{unix_user}%")
    if login_ip:
        conditions.append("login_ip::text ILIKE %s")
        params.append(f"%{login_ip}%")
    if since:
        try:
            params.append(datetime.fromisoformat(since).replace(tzinfo=timezone.utc))
            conditions.append("login_at >= %s")
        except ValueError:
            pass
    rows = db.query(
        f"""
        SELECT unix_user, tty, host(login_ip) AS login_ip,
               login_at, logout_at, is_active, collected_at
        FROM ssh_sessions
        WHERE {' AND '.join(conditions)}
        ORDER BY login_at DESC
        LIMIT 200
        """,
        params,
    )
    return jsonify([_serialize_session(r) for r in rows])


# ---------------------------------------------------------------------------
# Cles SSH
# ---------------------------------------------------------------------------

@app.route("/api/keys", methods=["GET"])
@require_auth
def list_keys():
    status = request.args.get("status")
    server = request.args.get("server")
    sql = """
        SELECT sk.*, ka.status AS status, ka.unix_user, ka.server_id, ka.expires_at,
               ka.revoked_automatically, ka.revoked_by, ka.revoked_at,
               ka.revocation_justification, s.hostname AS server_hostname
        FROM ssh_keys sk
        LEFT JOIN key_authorizations ka ON ka.key_id = sk.id
        LEFT JOIN servers s ON s.id = ka.server_id
        WHERE 1=1
    """
    params = []
    if status:
        sql += " AND ka.status = %s"
        params.append(status)
    if server:
        sql += " AND s.hostname = %s"
        params.append(server)
    sql += " ORDER BY sk.last_seen DESC"
    return jsonify(db.query(sql, tuple(params)))


@app.route("/api/keys/search", methods=["GET"])
@require_auth
def search_keys():
    q = request.args.get("q", "")
    rows = db.query(
        """
        SELECT * FROM ssh_keys
        WHERE fingerprint ILIKE %s OR comment ILIKE %s
        ORDER BY last_seen DESC
        """,
        (f"%{q}%", f"%{q}%"),
    )
    return jsonify(rows)


@app.route("/api/keys/get/<path:fingerprint>", methods=["GET"])
@require_auth
def get_key(fingerprint):
    row = db.query_one("SELECT * FROM ssh_keys WHERE fingerprint = %s", (fingerprint,))
    if not row:
        return jsonify({"error": "Not found"}), 404
    return jsonify(row)


@app.route("/api/keys/validate/<path:fingerprint>", methods=["POST"])
@require_auth
@require_role("sysadmin", "operator")
def validate_key(fingerprint):
    data = request.get_json(silent=True) or {}
    unix_user = data.get("unix_user") or None
    hostname = data.get("hostname") or None
    try:
        actions.validate_key(fingerprint, g.admin_id, unix_user=unix_user, hostname=hostname)
        return jsonify({"status": "validated"})
    except ValueError as e:
        logging.warning("%s", str(e).replace("\n", "\\n").replace("\r", "\\r"))
        return jsonify({"error": str(e)}), 404


@app.route("/api/keys/revoke/<path:fingerprint>", methods=["POST"])
@require_auth
@require_role("sysadmin", "operator")
def revoke_key(fingerprint):
    data = request.get_json(force=True) or {}
    reason = data.get("reason", "Manual revocation via API")
    hostname = (data.get("hostname") or "").strip() or None
    unix_user = (data.get("unix_user") or "").strip() or None
    if not actions._FP_RE.match(fingerprint):
        return jsonify({"error": f"Invalid fingerprint format: {fingerprint}"}), 400
    try:
        actions.revoke_key(fingerprint, g.admin_id, reason, hostname=hostname, unix_user=unix_user)
        return jsonify({"status": "revoked"})
    except ValueError as e:
        logging.warning("%s", str(e).replace("\n", "\\n").replace("\r", "\\r"))
        return jsonify({"error": str(e)}), 404


@app.route("/api/keys/assign/<path:fingerprint>", methods=["POST"])
@require_auth
@require_role("sysadmin", "operator")
def assign_key(fingerprint):
    data = request.get_json(force=True) or {}
    try:
        actions.assign_key(fingerprint, data["owner_name"])
        return jsonify({"status": "assigned"})
    except (KeyError, ValueError) as e:
        logging.warning("%s", str(e).replace("\n", "\\n").replace("\r", "\\r"))
        return jsonify({"error": str(e)}), 400


@app.route("/api/keys/set-expiry/<path:fingerprint>", methods=["POST"])
@require_auth
@require_role("sysadmin", "operator")
def set_key_expiry(fingerprint):
    from datetime import timedelta
    data = request.get_json(force=True) or {}
    expires_at = _parse_datetime(data.get("expires_at") or data.get("date"))
    if not expires_at and data.get("hours"):
        expires_at = datetime.now(tz=timezone.utc) + timedelta(hours=int(data["hours"]))
    if not expires_at:
        return jsonify({"error": "hours or date required"}), 400
    try:
        actions.set_key_expiry(fingerprint, expires_at)
        return jsonify({"status": "expiry set", "expires_at": expires_at.isoformat()})
    except ValueError as e:
        logging.warning("%s", str(e).replace("\n", "\\n").replace("\r", "\\r"))
        return jsonify({"error": str(e)}), 404


@app.route("/api/keys/remove-expiry/<path:fingerprint>", methods=["POST"])
@require_auth
@require_role("sysadmin", "operator")
def remove_key_expiry(fingerprint):
    try:
        actions.remove_key_expiry(fingerprint)
        return jsonify({"status": "expiry removed"})
    except ValueError as e:
        logging.warning("%s", str(e).replace("\n", "\\n").replace("\r", "\\r"))
        return jsonify({"error": str(e)}), 404


# ---------------------------------------------------------------------------
# Acces temporaires
# ---------------------------------------------------------------------------

@app.route("/api/access", methods=["GET"])
@require_auth
def list_access():
    status = request.args.get("status")
    sql = "SELECT * FROM access_requests WHERE 1=1"
    params = []
    if status:
        sql += " AND status = %s"
        params.append(status)
    sql += " ORDER BY requested_at DESC"
    return jsonify(db.query(sql, tuple(params)))


@app.route("/api/access/<request_id>", methods=["GET"])
@require_auth
def get_access(request_id):
    row = db.query_one("SELECT * FROM access_requests WHERE id = %s", (request_id,))
    if not row:
        return jsonify({"error": "Not found"}), 404
    return jsonify(row)


@app.route("/api/access/grant", methods=["POST"])
@require_auth
@require_role("sysadmin", "operator")
def grant_access():
    data = request.get_json(force=True) or {}
    expires_at = _parse_datetime(data.get("expires_at"))
    if not expires_at and data.get("duration_hours"):
        from datetime import timedelta
        expires_at = datetime.now(tz=timezone.utc) + timedelta(
            hours=int(data["duration_hours"])
        )
    if not expires_at:
        return jsonify({"error": "expires_at or duration_hours required"}), 400
    try:
        result = actions.grant_access(
            data["key_fp"], data["hostname"], expires_at,
            data.get("justification", ""), g.admin_id,
        )
        result["expires_at"] = result["expires_at"].isoformat()
        return jsonify(result), 201
    except (KeyError, ValueError) as e:
        logging.warning("%s", str(e).replace("\n", "\\n").replace("\r", "\\r"))
        return jsonify({"error": str(e)}), 400


@app.route("/api/access/deploy", methods=["POST"])
@require_auth
@require_role("sysadmin", "operator")
def api_deploy_key():
    from datetime import timedelta
    data = request.json or {}
    public_key = (data.get("public_key") or "").strip()
    unix_user = (data.get("unix_user") or "").strip()
    hostname = (data.get("hostname") or "").strip()
    justification = (data.get("justification") or "").strip()

    if not all([public_key, unix_user, hostname, justification]):
        return jsonify({"error": "public_key, unix_user, hostname, justification required"}), 400

    hours = data.get("hours")
    date_str = data.get("expires_at")
    expires_at = None
    if hours is not None:
        try:
            hours = int(hours)
        except (ValueError, TypeError):
            return jsonify({"error": "hours must be an integer"}), 400
        if not (1 <= hours <= 8760):
            return jsonify({"error": "hours must be between 1 and 8760"}), 400
        expires_at = datetime.now(tz=timezone.utc) + timedelta(hours=hours)
    elif date_str:
        expires_at = datetime.fromisoformat(date_str).replace(tzinfo=timezone.utc)

    try:
        result = actions.deploy_key(
            public_key=public_key,
            unix_user=unix_user,
            hostname=hostname,
            expires_at=expires_at,
            justification=justification,
            admin_id=g.admin_id,
        )
        return jsonify(result), 201
    except ValueError as e:
        logging.warning("%s", str(e).replace("\n", "\\n").replace("\r", "\\r"))
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        logging.exception("deploy_key failed")
        return jsonify({"error": "internal server error"}), 500


@app.route("/api/access/lock-user", methods=["POST"])
@require_auth
@require_role("sysadmin", "operator")
def api_lock_user():
    data = request.json or {}
    unix_user = (data.get("unix_user") or "").strip()
    hostname = (data.get("hostname") or "").strip()
    if not unix_user or not hostname:
        return jsonify({"error": "unix_user and hostname required"}), 400
    try:
        result = actions.lock_user(unix_user, hostname, g.admin_id)
        return jsonify(result), 200
    except ValueError as e:
        logging.warning("%s", str(e).replace("\n", "\\n").replace("\r", "\\r"))
        return jsonify({"error": str(e)}), 400
    except Exception:
        logging.exception("lock_user failed")
        return jsonify({"error": "internal server error"}), 500


@app.route("/api/access/unlock-user", methods=["POST"])
@require_auth
@require_role("sysadmin", "operator")
def api_unlock_user():
    data = request.json or {}
    unix_user = (data.get("unix_user") or "").strip()
    hostname = (data.get("hostname") or "").strip()
    if not unix_user or not hostname:
        return jsonify({"error": "unix_user and hostname required"}), 400
    try:
        result = actions.unlock_user(unix_user, hostname, g.admin_id)
        return jsonify(result), 200
    except ValueError as e:
        logging.warning("%s", str(e).replace("\n", "\\n").replace("\r", "\\r"))
        return jsonify({"error": str(e)}), 400
    except Exception:
        logging.exception("unlock_user failed")
        return jsonify({"error": "internal server error"}), 500


@app.route("/api/access/deployed-users", methods=["GET"])
@require_auth
def list_deployed_users():
    rows = db.query(
        """
        SELECT ka.unix_user, s.hostname, s.ip_address,
               ka.expires_at, sk.fingerprint,
               (
                   SELECT al.action
                   FROM audit_log al
                   WHERE al.details->>'unix_user' = ka.unix_user
                     AND al.target_server = s.id
                     AND al.action IN ('USER_LOCKED', 'USER_UNLOCKED')
                   ORDER BY al.performed_at DESC
                   LIMIT 1
               ) AS lock_status
        FROM key_authorizations ka
        JOIN ssh_keys sk ON sk.id = ka.key_id
        JOIN servers s ON ka.server_id = s.id
        WHERE ka.unix_user != '' AND ka.unix_user != %s AND ka.status = 'ACTIVE'
        ORDER BY ka.unix_user, s.hostname
        """,
        (ssh.SSH_USER,)
    )
    results = []
    for r in rows:
        row_dict = dict(r)
        if row_dict.get("expires_at"):
            row_dict["expires_at"] = row_dict["expires_at"].isoformat()
        results.append(row_dict)
    return jsonify(results)


@app.route("/api/access/request", methods=["POST"])
@require_auth
@require_role("sysadmin", "operator")
def request_access():
    data = request.get_json(force=True) or {}
    try:
        db.execute(
            """
            INSERT INTO access_requests
                (requested_by, key_id, server_id, duration_hours,
                 expires_at_requested, justification)
            VALUES (
                %s,
                (SELECT id FROM ssh_keys WHERE fingerprint = %s),
                (SELECT id FROM servers WHERE hostname = %s),
                %s, %s, %s
            )
            """,
            (
                g.admin_id,
                data["key_fp"],
                data["hostname"],
                data.get("duration_hours"),
                _parse_datetime(data.get("expires_at")),
                data["justification"],
            ),
        )
        return jsonify({"status": "requested"}), 201
    except (KeyError, Exception) as e:
        logging.exception("%s", str(e).replace("\n", "\\n").replace("\r", "\\r"))
        return jsonify({"error": str(e)}), 400


@app.route("/api/access/<request_id>/approve", methods=["POST"])
@require_auth
@require_role("sysadmin", "operator")
def approve_request(request_id):
    try:
        actions.approve_request(request_id, g.admin_id)
        return jsonify({"status": "approved"})
    except ValueError as e:
        logging.warning("%s", str(e).replace("\n", "\\n").replace("\r", "\\r"))
        return jsonify({"error": str(e)}), 404


@app.route("/api/access/<request_id>/reject", methods=["POST"])
@require_auth
@require_role("sysadmin", "operator")
def reject_request(request_id):
    try:
        actions.reject_request(request_id, g.admin_id)
        return jsonify({"status": "rejected"})
    except ValueError as e:
        logging.warning("%s", str(e).replace("\n", "\\n").replace("\r", "\\r"))
        return jsonify({"error": str(e)}), 404


@app.route("/api/access/<request_id>/revoke", methods=["POST"])
@require_auth
@require_role("sysadmin", "operator")
def revoke_request(request_id):
    try:
        actions.revoke_request(request_id, g.admin_id)
        return jsonify({"status": "revoked"})
    except ValueError as e:
        logging.warning("%s", str(e).replace("\n", "\\n").replace("\r", "\\r"))
        return jsonify({"error": str(e)}), 404


# ---------------------------------------------------------------------------
# Administrateurs
# ---------------------------------------------------------------------------

@app.route("/api/admins", methods=["GET"])
@require_auth
def list_admins():
    return jsonify(db.query(
        "SELECT id, username, email, role, is_active, receive_alerts, created_at FROM administrators ORDER BY username"
    ))


@app.route("/api/admins", methods=["POST"])
@require_auth
@require_role("sysadmin")
def add_admin():
    data = request.get_json(force=True) or {}
    try:
        admin = actions.add_admin(
            data["username"],
            data.get("email", ""),
            data["password"],
            g.admin_id,
            role=data.get("role", "operator"),
        )
        return jsonify(admin), 201
    except (KeyError, Exception) as e:
        logging.exception("%s", str(e).replace("\n", "\\n").replace("\r", "\\r"))
        return jsonify({"error": str(e)}), 400


@app.route("/api/admins/<username>", methods=["PUT"])
@require_auth
@require_role("sysadmin")
def update_admin(username):
    data = request.get_json(force=True) or {}
    email = (data.get("email") or "").strip() or None
    role = (data.get("role") or "").strip()
    if not role:
        return jsonify({"error": "role required"}), 400
    try:
        result = actions.update_admin(username, email, role, g.admin_id)
        return jsonify({"message": "Admin updated"})
    except ValueError as e:
        err_msg = str(e)
        logging.warning("%s", err_msg.replace("\n", "\\n").replace("\r", "\\r"))
        if "own role" in err_msg:
            return jsonify({"error": err_msg}), 403
        return jsonify({"error": err_msg}), 404


@app.route("/api/admins/<username>/password", methods=["PUT"])
@require_auth
def change_admin_password(username):
    if g.admin_role != "sysadmin" and username != g.admin_username:
        return jsonify({"error": "Insufficient permissions"}), 403
    data = request.get_json(force=True) or {}
    password = data.get("password", "").strip()
    if not password:
        return jsonify({"error": "password required"}), 400
    try:
        actions.change_password(username, password)
        return jsonify({"status": "updated"})
    except ValueError as e:
        logging.warning("%s", str(e).replace("\n", "\\n").replace("\r", "\\r"))
        return jsonify({"error": str(e)}), 404


@app.route("/api/admins/me", methods=["GET"])
@require_auth
def get_me():
    return jsonify({"id": g.admin_id, "username": g.admin_username})


@app.route("/api/admins/<username>/disable", methods=["PUT"])
@require_auth
@require_role("sysadmin")
def disable_admin(username):
    if username == g.admin_username:
        return jsonify({"error": "Cannot disable your own account"}), 403
    try:
        actions.disable_admin(username, g.admin_id)
        return jsonify({"status": "disabled"})
    except ValueError as e:
        logging.warning("%s", str(e).replace("\n", "\\n").replace("\r", "\\r"))
        return jsonify({"error": str(e)}), 404


@app.route("/api/admins/<username>/enable", methods=["PUT"])
@require_auth
@require_role("sysadmin")
def enable_admin(username):
    if username == g.admin_username:
        return jsonify({"error": "Cannot enable your own account"}), 403
    try:
        actions.enable_admin(username, g.admin_id)
        return jsonify({"status": "enabled"})
    except ValueError as e:
        logging.warning("%s", str(e).replace("\n", "\\n").replace("\r", "\\r"))
        return jsonify({"error": str(e)}), 404


@app.route("/api/admins/<username>", methods=["DELETE"])
@require_auth
@require_role("sysadmin")
def delete_admin(username):
    if username == g.admin_username:
        return jsonify({"error": "Cannot delete your own account"}), 403
    try:
        actions.delete_admin(username, g.admin_id)
        return jsonify({"status": "deleted"})
    except ValueError as e:
        logging.warning("%s", str(e).replace("\n", "\\n").replace("\r", "\\r"))
        return jsonify({"error": str(e)}), 400


@app.route("/api/admins/<username>/alerts", methods=["PUT"])
@require_auth
@require_role("sysadmin")
def toggle_admin_alerts(username):
    data = request.get_json(force=True) or {}
    receive_alerts = data.get("receive_alerts")
    if not isinstance(receive_alerts, bool):
        return jsonify({"error": "receive_alerts (boolean) required"}), 400
    try:
        result = actions.toggle_alerts(username, receive_alerts)
        return jsonify(result)
    except ValueError as e:
        return jsonify({"error": str(e)}), 404


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------

@app.route("/api/audit", methods=["GET"])
@require_auth
def list_audit():
    server = request.args.get("server")
    action = request.args.get("action")
    since = request.args.get("since")
    sql = """
        SELECT al.*, sk.fingerprint, s.hostname
        FROM audit_log al
        LEFT JOIN ssh_keys sk ON sk.id = al.target_key
        LEFT JOIN servers s ON s.id = al.target_server
        WHERE 1=1
    """
    params = []
    if server:
        sql += " AND s.hostname = %s"
        params.append(server)
    if action:
        sql += " AND al.action = %s"
        params.append(action)
    if since:
        dt = _parse_datetime(since)
        if dt:
            sql += " AND al.performed_at >= %s"
            params.append(dt)
    sql += " ORDER BY al.performed_at DESC LIMIT 500"
    return jsonify(db.query(sql, tuple(params)))


# ---------------------------------------------------------------------------
# Systeme
# ---------------------------------------------------------------------------

@app.route("/api/system/status", methods=["GET"])
@require_auth
def system_status():
    servers_total = db.query_one("SELECT COUNT(*) AS n FROM servers WHERE is_active = true")
    keys_pending = db.query_one(
        "SELECT COUNT(*) AS n FROM key_authorizations WHERE status = 'PENDING_REVIEW'"
    )
    keys_active = db.query_one(
        "SELECT COUNT(*) AS n FROM key_authorizations WHERE status = 'ACTIVE'"
    )
    last_scan = db.query_one(
        "SELECT performed_at FROM audit_log WHERE action = 'SCAN_COMPLETED' ORDER BY performed_at DESC LIMIT 1"
    )
    return jsonify({
        "servers_active": servers_total["n"] if servers_total else 0,
        "keys_active": keys_active["n"] if keys_active else 0,
        "keys_pending_review": keys_pending["n"] if keys_pending else 0,
        "last_scan": last_scan["performed_at"].isoformat() if last_scan else None,
    })


@app.route("/api/system/scan", methods=["POST"])
@require_auth
@require_role("sysadmin", "operator")
def system_scan():
    results = collect_mod.run_scan()
    return jsonify(results)


@app.route("/api/system/collector-key", methods=["GET"])
@require_auth
def get_collector_key():
    keys_dir = os.path.dirname(os.environ.get("COLLECTOR_KEY", "/data/keys/collector_key"))
    pub_path = os.path.join(keys_dir, "collector_key.pub")
    try:
        with open(pub_path) as f:
            return jsonify({"public_key": f.read().strip(), "ssh_user": ssh.SSH_USER})
    except FileNotFoundError:
        return jsonify({"error": "Collector key not found"}), 404


@app.route("/api/system/config", methods=["GET"])
@require_auth
def get_config():
    rows = db.query("SELECT key, value FROM settings")
    return jsonify({r["key"]: r["value"] for r in rows})


@app.route("/api/system/config", methods=["PUT"])
@require_auth
@require_role("sysadmin")
def update_config():
    data = request.get_json(force=True) or {}

    # Extract optional values
    scan_interval_hours = data.get("scan_interval_hours")
    expire_warn_days = data.get("expire_warn_days")
    expire_warn_days_2 = data.get("expire_warn_days_2")
    login_max_attempts = data.get("login_max_attempts")
    login_ban_seconds = data.get("login_ban_seconds")

    # Must have at least one value
    if all(v is None for v in [scan_interval_hours, expire_warn_days, expire_warn_days_2,
                                login_max_attempts, login_ban_seconds]):
        return jsonify({"error": "At least one setting must be provided"}), 400

    # Validate scan_interval_hours if present
    if scan_interval_hours is not None:
        try:
            scan_interval_hours = int(scan_interval_hours)
            if not (1 <= scan_interval_hours <= 24):
                raise ValueError
        except (ValueError, TypeError):
            return jsonify({"error": "scan_interval_hours must be between 1 and 24"}), 400

    # Validate expire_warn_days if present
    if expire_warn_days is not None:
        try:
            expire_warn_days = int(expire_warn_days)
            if not (1 <= expire_warn_days <= 30):
                raise ValueError
        except (ValueError, TypeError):
            return jsonify({"error": "expire_warn_days must be between 1 and 30"}), 400

    # Validate expire_warn_days_2 if present
    if expire_warn_days_2 is not None:
        try:
            expire_warn_days_2 = int(expire_warn_days_2)
            if not (1 <= expire_warn_days_2 <= 30):
                raise ValueError
        except (ValueError, TypeError):
            return jsonify({"error": "expire_warn_days_2 must be between 1 and 30"}), 400

    # Validate login_max_attempts if present
    if login_max_attempts is not None:
        try:
            login_max_attempts = int(login_max_attempts)
            if not (1 <= login_max_attempts <= 100):
                raise ValueError
        except (ValueError, TypeError):
            return jsonify({"error": "login_max_attempts must be between 1 and 100"}), 400

    # Validate login_ban_seconds if present
    if login_ban_seconds is not None:
        try:
            login_ban_seconds = int(login_ban_seconds)
            if not (30 <= login_ban_seconds <= 86400):
                raise ValueError
        except (ValueError, TypeError):
            return jsonify({"error": "login_ban_seconds must be between 30 and 86400"}), 400

    # Read current values from DB if not in request
    current_warn_days = db.query_one("SELECT value FROM settings WHERE key = 'expire_warn_days'")
    current_warn_days_2 = db.query_one("SELECT value FROM settings WHERE key = 'expire_warn_days_2'")

    final_warn_days = expire_warn_days if expire_warn_days is not None else int(current_warn_days["value"])
    final_warn_days_2 = expire_warn_days_2 if expire_warn_days_2 is not None else int(current_warn_days_2["value"])

    # Validate that warn_days > warn_days_2
    if final_warn_days <= final_warn_days_2:
        return jsonify({"error": "expire_warn_days must be greater than expire_warn_days_2"}), 400

    # Update settings in DB
    updates = {
        "scan_interval_hours": scan_interval_hours,
        "expire_warn_days": expire_warn_days,
        "expire_warn_days_2": expire_warn_days_2,
        "login_max_attempts": login_max_attempts,
        "login_ban_seconds": login_ban_seconds,
    }
    for key, value in updates.items():
        if value is not None:
            db.execute("UPDATE settings SET value = %s WHERE key = %s", (str(value), key))

    # Return full updated config
    rows = db.query("SELECT key, value FROM settings")
    config = {r["key"]: int(r["value"]) for r in rows}
    return jsonify(config)


@app.route("/api/system/test-smtp", methods=["POST"])
@require_auth
def test_smtp():
    admin = db.query_one(
        "SELECT email FROM administrators WHERE id = %s", (g.admin_id,)
    )
    to_email = admin["email"] if admin else None
    if not to_email:
        return jsonify({"error": "No email address configured for your account"}), 400
    try:
        alerts.send_test_email(to_email)
        return jsonify({"status": "sent", "to": to_email})
    except FileNotFoundError:
        return jsonify({"error": "msmtp not found on this system"}), 500
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 502


if __name__ == "__main__":
    if not os.environ.get("FLASK_SECRET_KEY"):
        raise RuntimeError("FLASK_SECRET_KEY environment variable is required")
    app.run(host="127.0.0.1", port=5000)
