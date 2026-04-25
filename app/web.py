"""
web.py — API REST Flask JSON.
Toutes les routes retournent JSON. Prefixe /api/.
Importe actions.py pour la logique metier — jamais de duplication.
"""
import base64
import os
from datetime import datetime, timezone
from functools import wraps

from flask import Flask, g, jsonify, request

import actions
import collect as collect_mod
import db

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "changeme")


# ---------------------------------------------------------------------------
# Authentification Basic — validee contre la table administrators
# ---------------------------------------------------------------------------

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Basic "):
            return jsonify({"error": "Unauthorized"}), 401
        try:
            decoded = base64.b64decode(auth[6:]).decode()
            username, _ = decoded.split(":", 1)
        except Exception:
            return jsonify({"error": "Unauthorized"}), 401
        admin = db.query_one(
            "SELECT id, username FROM administrators WHERE username = %s AND is_active = true",
            (username,),
        )
        if not admin:
            return jsonify({"error": "Unauthorized"}), 401
        g.admin_id = admin["id"]
        g.admin_username = admin["username"]
        return f(*args, **kwargs)
    return decorated


def _parse_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
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
        return jsonify({"error": str(e)}), 400


@app.route("/api/servers/<hostname>/disable", methods=["PUT"])
@require_auth
def disable_server(hostname):
    try:
        actions.disable_server(hostname, g.admin_id)
        return jsonify({"status": "disabled"})
    except ValueError as e:
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
        SELECT sk.*, ka.status AS auth_status, ka.server_id, ka.expires_at
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


@app.route("/api/keys/<fingerprint>", methods=["GET"])
@require_auth
def get_key(fingerprint):
    row = db.query_one("SELECT * FROM ssh_keys WHERE fingerprint = %s", (fingerprint,))
    if not row:
        return jsonify({"error": "Not found"}), 404
    return jsonify(row)


@app.route("/api/keys/<fingerprint>/validate", methods=["POST"])
@require_auth
def validate_key(fingerprint):
    try:
        actions.validate_key(fingerprint, g.admin_id)
        return jsonify({"status": "validated"})
    except ValueError as e:
        return jsonify({"error": str(e)}), 404


@app.route("/api/keys/<fingerprint>/revoke", methods=["POST"])
@require_auth
def revoke_key(fingerprint):
    data = request.get_json(force=True) or {}
    reason = data.get("reason", "Manual revocation via API")
    try:
        actions.revoke_key(fingerprint, g.admin_id, reason)
        return jsonify({"status": "revoked"})
    except ValueError as e:
        return jsonify({"error": str(e)}), 404


@app.route("/api/keys/<fingerprint>/assign", methods=["POST"])
@require_auth
def assign_key(fingerprint):
    data = request.get_json(force=True) or {}
    try:
        actions.assign_key(fingerprint, data["owner_username"])
        return jsonify({"status": "assigned"})
    except (KeyError, ValueError) as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/keys/<fingerprint>/set-expiry", methods=["POST"])
@require_auth
def set_key_expiry(fingerprint):
    data = request.get_json(force=True) or {}
    expires_at = _parse_datetime(data.get("expires_at"))
    if not expires_at:
        return jsonify({"error": "expires_at required (ISO format)"}), 400
    try:
        actions.set_key_expiry(fingerprint, expires_at)
        return jsonify({"status": "expiry set", "expires_at": expires_at.isoformat()})
    except ValueError as e:
        return jsonify({"error": str(e)}), 404


@app.route("/api/keys/<fingerprint>/remove-expiry", methods=["POST"])
@require_auth
def remove_key_expiry(fingerprint):
    try:
        actions.remove_key_expiry(fingerprint)
        return jsonify({"status": "expiry removed"})
    except ValueError as e:
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
        return jsonify({"error": str(e)}), 400


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
        return jsonify({"error": str(e)}), 400


@app.route("/api/access/<request_id>/approve", methods=["POST"])
@require_auth
def approve_request(request_id):
    try:
        actions.approve_request(request_id, g.admin_id)
        return jsonify({"status": "approved"})
    except ValueError as e:
        return jsonify({"error": str(e)}), 404


@app.route("/api/access/<request_id>/reject", methods=["POST"])
@require_auth
def reject_request(request_id):
    try:
        actions.reject_request(request_id, g.admin_id)
        return jsonify({"status": "rejected"})
    except ValueError as e:
        return jsonify({"error": str(e)}), 404


@app.route("/api/access/<request_id>/revoke", methods=["POST"])
@require_auth
def revoke_request(request_id):
    try:
        actions.revoke_request(request_id, g.admin_id)
        return jsonify({"status": "revoked"})
    except ValueError as e:
        return jsonify({"error": str(e)}), 404


# ---------------------------------------------------------------------------
# Administrateurs
# ---------------------------------------------------------------------------

@app.route("/api/admins", methods=["GET"])
@require_auth
def list_admins():
    return jsonify(db.query("SELECT * FROM administrators ORDER BY username"))


@app.route("/api/admins", methods=["POST"])
@require_auth
def add_admin():
    data = request.get_json(force=True) or {}
    try:
        admin = actions.add_admin(data["username"], data.get("email", ""), data["password"], g.admin_id)
        return jsonify(admin), 201
    except (KeyError, Exception) as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/admins/<username>/disable", methods=["PUT"])
@require_auth
def disable_admin(username):
    try:
        actions.disable_admin(username, g.admin_id)
        return jsonify({"status": "disabled"})
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
def system_scan():
    results = collect_mod.run_scan()
    return jsonify(results)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
