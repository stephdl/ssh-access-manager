"""
manage.py — CLI Click for ssh-access-manager.
Imports `actions.py` for business logic — no duplication between CLI and API.
"""
from datetime import datetime, timedelta, timezone

import click

import actions
import collect as collect_mod
import db


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------

def _table(rows: list[dict], columns: list[str]) -> None:
    if not rows:
        click.echo("(no results)")
        return
    widths = {c: len(c) for c in columns}
    for row in rows:
        for c in columns:
            widths[c] = max(widths[c], len(str(row.get(c, "") or "")))
    header = "  ".join(c.upper().ljust(widths[c]) for c in columns)
    click.echo(header)
    click.echo("-" * len(header))
    for row in rows:
        click.echo("  ".join(str(row.get(c, "") or "").ljust(widths[c]) for c in columns))


def _parse_dt(value: str) -> datetime:
    for fmt in ("%Y-%m-%d %H:%M", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    raise click.BadParameter(f"Invalid format: {value!r} (expected YYYY-MM-DD HH:MM)")


def _require_admin() -> str:
    import os
    username = os.environ.get("ADMIN_USERNAME", "admin")
    admin = db.query_one(
        "SELECT id FROM administrators WHERE username = %s AND is_active = true",
        (username,),
    )
    if not admin:
        raise click.ClickException(f"Administrator '{username}' not found.")
    return admin["id"]


# ---------------------------------------------------------------------------
# Main CLI
# ---------------------------------------------------------------------------

@click.group()
def cli():
    """ssh-access-manager — SSH access management."""


# ---------------------------------------------------------------------------
# servers
# ---------------------------------------------------------------------------

@cli.group()
def servers():
    """SSH server management."""


@servers.command("list")
def servers_list():
    """List all servers."""
    rows = db.query("SELECT hostname, ip_address, environment, os_family, is_active, added_at FROM servers ORDER BY hostname")
    _table(rows, ["hostname", "ip_address", "environment", "is_active"])


@servers.command("show")
@click.argument("hostname")
def servers_show(hostname):
    """Display server details."""
    row = db.query_one("SELECT * FROM servers WHERE hostname = %s", (hostname,))
    if not row:
        raise click.ClickException(f"Server not found: {hostname}")
    for k, v in row.items():
        click.echo(f"{k:20}: {v}")


@servers.command("add")
@click.option("--hostname", required=True, help="Hostname")
@click.option("--ip", required=True, help="IP address")
@click.option("--ssh-user", default="root", show_default=True, help="SSH user for provisioning")
@click.option("--ssh-password", default=None, help="SSH password for provisioning")
@click.option("--env", default=None, type=click.Choice(["production", "staging", "lab"]), help="Environment (optional)")
@click.option("--os", "os_family", default=None, help="OS family")
@click.option("--port", "ssh_port", default=22, show_default=True, type=int, help="SSH port")
def servers_add(hostname, ip, ssh_user, ssh_password, env, os_family, ssh_port):
    """Add and provision a server via SSH. Only created in DB on success."""
    admin_id = _require_admin()
    if ssh_password is None:
        ssh_password = click.prompt("SSH password (leave empty to use collector key)", hide_input=True, default="")
    try:
        actions.add_server(hostname, ip, ssh_user, ssh_password, env, os_family, ssh_port, admin_id)
        click.echo(f"Server {hostname} added and provisioned successfully.")
    except (ValueError, RuntimeError) as e:
        raise click.ClickException(str(e))


@servers.command("update")
@click.argument("hostname")
@click.option("--ip", default=None, help="New IP address")
@click.option("--env", default=None, type=click.Choice(["production", "staging", "lab"]), help="New environment")
@click.option("--os", "os_family", default=None, help="New OS family")
def servers_update(hostname, ip, env, os_family):
    """Update a server."""
    if not any([ip, env, os_family]):
        raise click.UsageError("At least one parameter required: --ip, --env or --os")
    admin_id = _require_admin()
    try:
        current = db.query_one("SELECT ip_address, environment, os_family FROM servers WHERE hostname = %s", (hostname,))
        if not current:
            raise click.ClickException(f"Server not found: {hostname}")
        actions.update_server(
            hostname,
            ip or current["ip_address"],
            env or current["environment"],
            os_family if os_family is not None else current["os_family"],
            admin_id,
        )
        click.echo(f"Server {hostname} updated.")
    except ValueError as e:
        raise click.ClickException(str(e))


@servers.command("disable")
@click.argument("hostname")
def servers_disable(hostname):
    """Disable a server."""
    admin_id = _require_admin()
    try:
        actions.disable_server(hostname, admin_id)
        click.echo(f"Server {hostname} disabled.")
    except ValueError as e:
        raise click.ClickException(str(e))


@servers.command("scan")
@click.option("--server", default=None, help="Scan only this server")
def servers_scan(server):
    """Run an SSH scan."""
    results = collect_mod.run_scan(hostname=server)
    for r in results:
        if r["error"]:
            click.echo(f"FAILED  {r['hostname']}: {r['error']}")
        else:
            click.echo(
                f"OK      {r['hostname']}: "
                f"{r['new']} new, {r['disappeared']} disappeared, {r['known']} known"
            )


# ---------------------------------------------------------------------------
# keys
# ---------------------------------------------------------------------------

@cli.group()
def keys():
    """SSH key management."""


@keys.command("list")
@click.option("--status", default=None, help="Filter by status")
@click.option("--server", default=None, help="Filter by server")
def keys_list(status, server):
    """List SSH keys."""
    sql = """
        SELECT sk.fingerprint, sk.key_type, sk.is_compliant, sk.comment,
               ka.status AS auth_status, s.hostname
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
    rows = db.query(sql, tuple(params))
    _table(rows, ["fingerprint", "key_type", "auth_status", "hostname", "is_compliant"])


@keys.command("show")
@click.argument("fingerprint")
def keys_show(fingerprint):
    """Display key details."""
    row = db.query_one("SELECT * FROM ssh_keys WHERE fingerprint = %s", (fingerprint,))
    if not row:
        raise click.ClickException(f"Key not found: {fingerprint}")
    for k, v in row.items():
        click.echo(f"{k:20}: {v}")


@keys.command("validate")
@click.argument("fingerprint")
def keys_validate(fingerprint):
    """Validate a key (PENDING_REVIEW → ACTIVE)."""
    admin_id = _require_admin()
    try:
        actions.validate_key(fingerprint, admin_id)
        click.echo(f"Key {fingerprint} validated.")
    except ValueError as e:
        raise click.ClickException(str(e))


@keys.command("revoke")
@click.argument("fingerprint")
@click.option("--reason", required=True, help="Revocation reason")
def keys_revoke(fingerprint, reason):
    """Revoke an SSH key."""
    admin_id = _require_admin()
    try:
        actions.revoke_key(fingerprint, admin_id, reason)
        click.echo(f"Key {fingerprint} revoked.")
    except ValueError as e:
        raise click.ClickException(str(e))


@keys.command("assign")
@click.argument("fingerprint")
@click.option("--owner", required=True, help="Owner username")
def keys_assign(fingerprint, owner):
    """Assign a key to an administrator."""
    try:
        actions.assign_key(fingerprint, owner)
        click.echo(f"Key {fingerprint} assigned to {owner}.")
    except ValueError as e:
        raise click.ClickException(str(e))


@keys.command("set-expiry")
@click.argument("fingerprint")
@click.option("--hours", default=None, type=int, help="Duration in hours")
@click.option("--date", "date_str", default=None, help="Date YYYY-MM-DD HH:MM")
def keys_set_expiry(fingerprint, hours, date_str):
    """Set key expiration."""
    if hours and date_str:
        raise click.UsageError("Use --hours OR --date, not both.")
    if hours:
        expires_at = datetime.now(tz=timezone.utc) + timedelta(hours=hours)
    elif date_str:
        expires_at = _parse_dt(date_str)
    else:
        raise click.UsageError("--hours or --date required.")
    try:
        actions.set_key_expiry(fingerprint, expires_at)
        click.echo(f"Expiration set: {expires_at.isoformat()}")
    except ValueError as e:
        raise click.ClickException(str(e))


@keys.command("remove-expiry")
@click.argument("fingerprint")
def keys_remove_expiry(fingerprint):
    """Remove key expiration."""
    try:
        actions.remove_key_expiry(fingerprint)
        click.echo(f"Expiration removed for {fingerprint}.")
    except ValueError as e:
        raise click.ClickException(str(e))


@keys.command("search")
@click.argument("query")
def keys_search(query):
    """Search keys by fingerprint or comment."""
    rows = db.query(
        "SELECT fingerprint, key_type, comment FROM ssh_keys WHERE fingerprint ILIKE %s OR comment ILIKE %s",
        (f"%{query}%", f"%{query}%"),
    )
    _table(rows, ["fingerprint", "key_type", "comment"])


# ---------------------------------------------------------------------------
# access
# ---------------------------------------------------------------------------

@cli.group()
def access():
    """Temporary access management."""


@access.command("list")
@click.option("--status", default=None, help="Filter by status")
def access_list(status):
    """List temporary accesses."""
    sql = "SELECT id, status, justification, requested_at, expires_at FROM access_requests WHERE 1=1"
    params = []
    if status:
        sql += " AND status = %s"
        params.append(status)
    sql += " ORDER BY requested_at DESC"
    rows = db.query(sql, tuple(params))
    _table(rows, ["id", "status", "justification", "expires_at"])


@access.command("show")
@click.argument("request_id")
def access_show(request_id):
    """Display request details."""
    row = db.query_one("SELECT * FROM access_requests WHERE id = %s", (request_id,))
    if not row:
        raise click.ClickException(f"Request not found: {request_id}")
    for k, v in row.items():
        click.echo(f"{k:20}: {v}")


@access.command("grant")
@click.option("--key", "key_fp", required=True, help="Key fingerprint")
@click.option("--server", "hostname", required=True, help="Target server")
@click.option("--hours", default=None, type=int, help="Duration in hours")
@click.option("--date", "date_str", default=None, help="Expiration date YYYY-MM-DD HH:MM")
@click.option("--reason", required=True, help="Justification")
def access_grant(key_fp, hostname, hours, date_str, reason):
    """Grant temporary access."""
    if hours and date_str:
        raise click.UsageError("Use --hours OR --date, not both.")
    if hours:
        expires_at = datetime.now(tz=timezone.utc) + timedelta(hours=hours)
    elif date_str:
        expires_at = _parse_dt(date_str)
    else:
        raise click.UsageError("--hours or --date required.")
    admin_id = _require_admin()
    try:
        actions.grant_access(key_fp, hostname, expires_at, reason, admin_id)
        click.echo(f"Access granted until {expires_at.isoformat()}.")
    except ValueError as e:
        raise click.ClickException(str(e))


@access.command("request")
@click.option("--key", "key_fp", required=True, help="Key fingerprint")
@click.option("--server", "hostname", required=True, help="Target server")
@click.option("--hours", required=True, type=int, help="Duration in hours")
@click.option("--reason", required=True, help="Justification")
def access_request(key_fp, hostname, hours, reason):
    """Submit a temporary access request."""
    admin_id = _require_admin()
    expires_at = datetime.now(tz=timezone.utc) + timedelta(hours=hours)
    db.execute(
        """
        INSERT INTO access_requests
            (requested_by, key_id, server_id, duration_hours, justification)
        VALUES (
            %s,
            (SELECT id FROM ssh_keys WHERE fingerprint = %s),
            (SELECT id FROM servers WHERE hostname = %s),
            %s, %s
        )
        """,
        (admin_id, key_fp, hostname, hours, reason),
    )
    click.echo("Request submitted.")


@access.command("approve")
@click.argument("request_id")
def access_approve(request_id):
    """Approve an access request."""
    admin_id = _require_admin()
    try:
        actions.approve_request(request_id, admin_id)
        click.echo(f"Request {request_id} approved.")
    except ValueError as e:
        raise click.ClickException(str(e))


@access.command("reject")
@click.argument("request_id")
def access_reject(request_id):
    """Reject an access request."""
    admin_id = _require_admin()
    try:
        actions.reject_request(request_id, admin_id)
        click.echo(f"Request {request_id} rejected.")
    except ValueError as e:
        raise click.ClickException(str(e))


@access.command("revoke")
@click.argument("request_id")
def access_revoke(request_id):
    """Revoke a granted access."""
    admin_id = _require_admin()
    try:
        actions.revoke_request(request_id, admin_id)
        click.echo(f"Access {request_id} revoked.")
    except ValueError as e:
        raise click.ClickException(str(e))


@access.command("lock-user")
@click.option("--user", required=True, help="Unix username")
@click.option("--server", required=True, help="Server hostname")
def access_lock_user(user, server):
    """Lock a Unix user account on a remote server."""
    admin_id = _require_admin()
    try:
        result = actions.lock_user(user, server, admin_id)
        click.echo(f"User '{result['unix_user']}' locked on {result['hostname']}")
    except ValueError as e:
        raise click.ClickException(str(e))


@access.command("unlock-user")
@click.option("--user", required=True, help="Unix username")
@click.option("--server", required=True, help="Server hostname")
def access_unlock_user(user, server):
    """Unlock a Unix user account on a remote server."""
    admin_id = _require_admin()
    try:
        result = actions.unlock_user(user, server, admin_id)
        click.echo(f"User '{result['unix_user']}' unlocked on {result['hostname']}")
    except ValueError as e:
        raise click.ClickException(str(e))


# ---------------------------------------------------------------------------
# admin
# ---------------------------------------------------------------------------

@cli.group()
def admin():
    """Administrator management."""


@admin.command("list")
def admin_list():
    """List administrators."""
    rows = db.query("SELECT username, email, role, is_active, created_at FROM administrators ORDER BY username")
    _table(rows, ["username", "email", "role", "is_active"])


@admin.command("add")
@click.option("--username", required=True, help="Login")
@click.option("--email", required=True, help="Email")
@click.option("--password", required=True, help="Password")
def admin_add(username, email, password):
    """Add an administrator."""
    performer_id = _require_admin()
    try:
        actions.add_admin(username, email, password, performer_id)
        click.echo(f"Administrator {username} created.")
    except Exception as e:
        raise click.ClickException(str(e))


@admin.command("disable")
@click.argument("username")
def admin_disable(username):
    """Disable an administrator."""
    performer_id = _require_admin()
    try:
        actions.disable_admin(username, performer_id)
        click.echo(f"Administrator {username} disabled.")
    except ValueError as e:
        raise click.ClickException(str(e))


@admin.command("enable")
@click.argument("username")
def admin_enable(username):
    """Re-enable a disabled administrator."""
    performer_id = _require_admin()
    try:
        actions.enable_admin(username, performer_id)
        click.echo(f"Administrator {username} re-enabled.")
    except ValueError as e:
        raise click.ClickException(str(e))


@admin.command("update")
@click.argument("username")
@click.option("--email", default=None, help="New email address")
@click.option("--role", default=None, help="New role")
def admin_update(username, email, role):
    """Update an administrator (email and/or role)."""
    if not email and not role:
        raise click.UsageError("At least --email or --role required.")
    performer_id = _require_admin()
    try:
        current = db.query_one(
            "SELECT email, role FROM administrators WHERE username = %s", (username,)
        )
        if not current:
            raise click.ClickException(f"Administrator not found: {username}")
        actions.update_admin(
            username,
            email if email is not None else current["email"],
            role if role is not None else current["role"],
            performer_id,
        )
        click.echo(f"Administrator {username} updated.")
    except ValueError as e:
        raise click.ClickException(str(e))


@admin.command("reset-password")
@click.argument("username")
@click.option("--password", required=True, help="New password")
def admin_reset_password(username, password):
    """Reset an administrator's password (emergency use, no login required)."""
    try:
        actions.reset_password(username, password)
        click.echo(f"Password for {username} has been reset.")
    except ValueError as e:
        raise click.ClickException(str(e))


@admin.command("delete")
@click.argument("username")
@click.confirmation_option(prompt="Permanently delete this administrator?")
def admin_delete(username):
    """Permanently delete an administrator (must be disabled, without references)."""
    performer_id = _require_admin()
    try:
        actions.delete_admin(username, performer_id)
        click.echo(f"Administrator {username} deleted.")
    except ValueError as e:
        raise click.ClickException(str(e))


# ---------------------------------------------------------------------------
# audit
# ---------------------------------------------------------------------------

@cli.group()
def audit():
    """Audit log consultation."""


@audit.command("list")
@click.option("--server", default=None, help="Filter by server")
@click.option("--action", default=None, help="Filter by action")
@click.option("--since", default=None, help="Since date YYYY-MM-DD")
def audit_list(server, action, since):
    """Display audit log."""
    sql = """
        SELECT al.action, al.performed_at, s.hostname, sk.fingerprint
        FROM audit_log al
        LEFT JOIN servers s ON s.id = al.target_server
        LEFT JOIN ssh_keys sk ON sk.id = al.target_key
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
        dt = _parse_dt(since)
        sql += " AND al.performed_at >= %s"
        params.append(dt)
    sql += " ORDER BY al.performed_at DESC LIMIT 200"
    rows = db.query(sql, tuple(params))
    _table(rows, ["action", "performed_at", "hostname", "fingerprint"])


# ---------------------------------------------------------------------------
# system
# ---------------------------------------------------------------------------

@cli.group()
def system():
    """System status."""


@system.command("status")
def system_status():
    """Display global status."""
    servers_n = db.query_one("SELECT COUNT(*) AS n FROM servers WHERE is_active = true")
    pending_n = db.query_one("SELECT COUNT(*) AS n FROM key_authorizations WHERE status = 'PENDING_REVIEW'")
    active_n = db.query_one("SELECT COUNT(*) AS n FROM key_authorizations WHERE status = 'ACTIVE'")
    last_scan = db.query_one(
        "SELECT performed_at FROM audit_log WHERE action = 'SCAN_COMPLETED' ORDER BY performed_at DESC LIMIT 1"
    )
    click.echo(f"Active servers     : {servers_n['n'] if servers_n else 0}")
    click.echo(f"ACTIVE keys        : {active_n['n'] if active_n else 0}")
    click.echo(f"PENDING_REVIEW keys: {pending_n['n'] if pending_n else 0}")
    click.echo(f"Last scan          : {last_scan['performed_at'] if last_scan else 'never'}")


@system.command("report")
def system_report():
    """Display security report."""
    non_compliant = db.query(
        """
        SELECT sk.fingerprint, sk.key_type, sk.key_size_bits, s.hostname
        FROM ssh_keys sk
        JOIN key_authorizations ka ON ka.key_id = sk.id
        JOIN servers s ON s.id = ka.server_id
        WHERE sk.is_compliant = false AND ka.status = 'ACTIVE'
        ORDER BY s.hostname
        """
    )
    click.echo(f"\n=== Non-compliant ACTIVE keys ({len(non_compliant)}) ===")
    _table(non_compliant, ["fingerprint", "key_type", "key_size_bits", "hostname"])

    anomalies = db.query(
        """
        SELECT al.action, al.performed_at, s.hostname
        FROM audit_log al
        LEFT JOIN servers s ON s.id = al.target_server
        WHERE al.action = 'ANOMALY_DETECTED'
          AND al.performed_at > now() - INTERVAL '30 days'
        ORDER BY al.performed_at DESC
        """
    )
    click.echo(f"\n=== Anomalies last 30 days ({len(anomalies)}) ===")
    _table(anomalies, ["action", "performed_at", "hostname"])


if __name__ == "__main__":
    cli()
