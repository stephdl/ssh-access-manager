"""
web.py — API REST Flask JSON.
Toutes les routes retournent JSON. Prefixe /api/.
Importe actions.py pour la logique metier — jamais de duplication.
"""
import logging
import os
from datetime import datetime, timezone
from functools import wraps

from flask import Flask, g, jsonify, request, session
from werkzeug.security import check_password_hash

import actions
import collect as collect_mod
import db

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
        admin = db.query_one(
            "SELECT id, username FROM administrators WHERE id = %s AND is_active = true",
            (admin_id,),
        )
        if not admin:
            return jsonify({"error": "Unauthorized"}), 401
        g.admin_id = admin["id"]
        g.admin_username = admin["username"]
        return f(*args, **kwargs)
    return decorated


# ---------------------------------------------------------------------------
# Auth : login / logout / me
# ---------------------------------------------------------------------------

@app.route("/api/auth/login", methods=["POST"])
def auth_login():
    data = request.get_json(force=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")
    if not username or not password:
        return jsonify({"error": "username et password requis"}), 400
    admin = db.query_one(
        "SELECT id, username, password_hash FROM administrators WHERE username = %s AND is_active = true",
        (username,),
    )
    if not admin or not admin["password_hash"]:
        return jsonify({"error": "Identifiants invalides"}), 401
    if not check_password_hash(admin["password_hash"], password):
        return jsonify({"error": "Identifiants invalides"}), 401
    session.clear()
    session["admin_id"] = str(admin["id"])
    session["admin_username"] = admin["username"]
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


@app.route("/api/servers/<hostname>/disable", methods=["PUT"])
@require_auth
def disable_server(hostname):
    try:
        actions.disable_server(hostname, g.admin_id)
        return jsonify({"status": "disabled"})
    except ValueError as e:
        logging.warning("%s", str(e).replace("\n", "\\n").replace("\r", "\\r"))
        return jsonify({"error": str(e)}), 404


@app.route("/api/servers/<hostname>/enable", methods=["PUT"])
@require_auth
def enable_server(hostname):
    try:
        actions.enable_server(hostname, g.admin_id)
        return jsonify({"status": "enabled"})
    except ValueError as e:
        logging.warning("%s", str(e).replace("\n", "\\n").replace("\r", "\\r"))
        return jsonify({"error": str(e)}), 404


@app.route("/api/servers/<hostname>", methods=["DELETE"])
@require_auth
def delete_server(hostname):
    try:
        actions.delete_server(hostname, g.admin_id)
        return jsonify({"status": "deleted"})
    except ValueError as e:
        logging.warning("%s", str(e).replace("\n", "\\n").replace("\r", "\\r"))
        return jsonify({"error": str(e)}), 404


@app.route("/api/servers/<hostname>/scan", methods=["POST"])
@require_auth
def scan_server(hostname):
    results = collect_mod.run_scan(hostname=hostname)
    return jsonify(results)


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
def revoke_key(fingerprint):
    data = request.get_json(force=True) or {}
    reason = data.get("reason", "Manual revocation via API")
    hostname = (data.get("hostname") or "").strip() or None
    unix_user = (data.get("unix_user") or "").strip() or None
    if not actions._FP_RE.match(fingerprint):
        return jsonify({"error": f"Format de fingerprint invalide : {fingerprint}"}), 400
    try:
        actions.revoke_key(fingerprint, g.admin_id, reason, hostname=hostname, unix_user=unix_user)
        return jsonify({"status": "revoked"})
    except ValueError as e:
        logging.warning("%s", str(e).replace("\n", "\\n").replace("\r", "\\r"))
        return jsonify({"error": str(e)}), 404


@app.route("/api/keys/assign/<path:fingerprint>", methods=["POST"])
@require_auth
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
def api_deploy_key():
    from datetime import timedelta
    data = request.json or {}
    public_key = (data.get("public_key") or "").strip()
    unix_user = (data.get("unix_user") or "").strip()
    hostname = (data.get("hostname") or "").strip()
    justification = (data.get("justification") or "").strip()

    if not all([public_key, unix_user, hostname, justification]):
        return jsonify({"error": "public_key, unix_user, hostname, justification requis"}), 400

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
        WHERE ka.unix_user != '' AND ka.status = 'ACTIVE'
        ORDER BY ka.unix_user, s.hostname
        """
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
def approve_request(request_id):
    try:
        actions.approve_request(request_id, g.admin_id)
        return jsonify({"status": "approved"})
    except ValueError as e:
        logging.warning("%s", str(e).replace("\n", "\\n").replace("\r", "\\r"))
        return jsonify({"error": str(e)}), 404


@app.route("/api/access/<request_id>/reject", methods=["POST"])
@require_auth
def reject_request(request_id):
    try:
        actions.reject_request(request_id, g.admin_id)
        return jsonify({"status": "rejected"})
    except ValueError as e:
        logging.warning("%s", str(e).replace("\n", "\\n").replace("\r", "\\r"))
        return jsonify({"error": str(e)}), 404


@app.route("/api/access/<request_id>/revoke", methods=["POST"])
@require_auth
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
        "SELECT id, username, email, role, is_active, created_at FROM administrators ORDER BY username"
    ))


@app.route("/api/admins", methods=["POST"])
@require_auth
def add_admin():
    data = request.get_json(force=True) or {}
    try:
        admin = actions.add_admin(data["username"], data.get("email", ""), data["password"], g.admin_id)
        return jsonify(admin), 201
    except (KeyError, Exception) as e:
        logging.exception("%s", str(e).replace("\n", "\\n").replace("\r", "\\r"))
        return jsonify({"error": str(e)}), 400


@app.route("/api/admins/<username>/password", methods=["PUT"])
@require_auth
def change_admin_password(username):
    data = request.get_json(force=True) or {}
    password = data.get("password", "").strip()
    if not password:
        return jsonify({"error": "password requis"}), 400
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
def delete_admin(username):
    if username == g.admin_username:
        return jsonify({"error": "Cannot delete your own account"}), 403
    try:
        actions.delete_admin(username, g.admin_id)
        return jsonify({"status": "deleted"})
    except ValueError as e:
        logging.warning("%s", str(e).replace("\n", "\\n").replace("\r", "\\r"))
        return jsonify({"error": str(e)}), 400


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
            return jsonify({"public_key": f.read().strip()})
    except FileNotFoundError:
        return jsonify({"error": "Clé collecteur introuvable"}), 404


@app.route("/api/system/config", methods=["GET"])
@require_auth
def get_config():
    rows = db.query("SELECT key, value FROM settings")
    return jsonify({r["key"]: r["value"] for r in rows})


@app.route("/api/system/config", methods=["PUT"])
@require_auth
def update_config():
    data = request.get_json(force=True) or {}
    hours = data.get("scan_interval_hours")
    if hours is None:
        return jsonify({"error": "scan_interval_hours required"}), 400
    try:
        hours = int(hours)
        if not (1 <= hours <= 24):
            raise ValueError
    except (ValueError, TypeError):
        return jsonify({"error": "scan_interval_hours must be between 1 and 24"}), 400
    db.execute(
        "UPDATE settings SET value = %s WHERE key = 'scan_interval_hours'",
        (str(hours),)
    )
    return jsonify({"scan_interval_hours": hours})


if __name__ == "__main__":
    if not os.environ.get("FLASK_SECRET_KEY"):
        raise RuntimeError("FLASK_SECRET_KEY environment variable is required")
    app.run(host="127.0.0.1", port=5000)
