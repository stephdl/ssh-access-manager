"""
manage.py — CLI click pour ssh-access-manager.
Importe actions.py pour la logique metier — jamais de duplication.
"""
from datetime import datetime, timedelta, timezone

import click

import actions
import collect as collect_mod
import db


# ---------------------------------------------------------------------------
# Helpers de formatage
# ---------------------------------------------------------------------------

def _table(rows: list[dict], columns: list[str]) -> None:
    if not rows:
        click.echo("(aucun resultat)")
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
    raise click.BadParameter(f"Format invalide : {value!r} (attendu YYYY-MM-DD HH:MM)")


def _require_admin() -> str:
    import os
    username = os.environ.get("ADMIN_USERNAME", "admin")
    admin = db.query_one(
        "SELECT id FROM administrators WHERE username = %s AND is_active = true",
        (username,),
    )
    if not admin:
        raise click.ClickException(f"Administrateur '{username}' introuvable.")
    return admin["id"]


# ---------------------------------------------------------------------------
# CLI principal
# ---------------------------------------------------------------------------

@click.group()
def cli():
    """ssh-access-manager — gestion des acces SSH."""


# ---------------------------------------------------------------------------
# servers
# ---------------------------------------------------------------------------

@cli.group()
def servers():
    """Gestion des serveurs SSH."""


@servers.command("list")
def servers_list():
    """Lister tous les serveurs."""
    rows = db.query("SELECT hostname, ip_address, environment, os_family, is_active, added_at FROM servers ORDER BY hostname")
    _table(rows, ["hostname", "ip_address", "environment", "is_active"])


@servers.command("show")
@click.argument("hostname")
def servers_show(hostname):
    """Afficher le detail d'un serveur."""
    row = db.query_one("SELECT * FROM servers WHERE hostname = %s", (hostname,))
    if not row:
        raise click.ClickException(f"Serveur introuvable : {hostname}")
    for k, v in row.items():
        click.echo(f"{k:20}: {v}")


@servers.command("add")
@click.option("--hostname", required=True, help="Nom d'hote")
@click.option("--ip", required=True, help="Adresse IP")
@click.option("--env", required=True, type=click.Choice(["production", "staging", "lab"]), help="Environnement")
@click.option("--os", "os_family", default=None, help="Famille OS")
def servers_add(hostname, ip, env, os_family):
    """Ajouter un serveur."""
    admin_id = _require_admin()
    actions.add_server(hostname, ip, env, os_family, admin_id)
    click.echo(f"Serveur {hostname} ajoute.")


@servers.command("update")
@click.argument("hostname")
@click.option("--ip", default=None, help="Nouvelle adresse IP")
@click.option("--env", default=None, type=click.Choice(["production", "staging", "lab"]), help="Nouvel environnement")
@click.option("--os", "os_family", default=None, help="Nouvelle famille OS")
def servers_update(hostname, ip, env, os_family):
    """Mettre a jour un serveur."""
    if not any([ip, env, os_family]):
        raise click.UsageError("Au moins un parametre requis : --ip, --env ou --os")
    admin_id = _require_admin()
    try:
        current = db.query_one("SELECT ip_address, environment, os_family FROM servers WHERE hostname = %s", (hostname,))
        if not current:
            raise click.ClickException(f"Serveur introuvable : {hostname}")
        actions.update_server(
            hostname,
            ip or current["ip_address"],
            env or current["environment"],
            os_family if os_family is not None else current["os_family"],
            admin_id,
        )
        click.echo(f"Serveur {hostname} mis a jour.")
    except ValueError as e:
        raise click.ClickException(str(e))


@servers.command("disable")
@click.argument("hostname")
def servers_disable(hostname):
    """Desactiver un serveur."""
    admin_id = _require_admin()
    try:
        actions.disable_server(hostname, admin_id)
        click.echo(f"Serveur {hostname} desactive.")
    except ValueError as e:
        raise click.ClickException(str(e))


@servers.command("scan")
@click.option("--server", default=None, help="Scanner uniquement ce serveur")
def servers_scan(server):
    """Lancer un scan SSH."""
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
    """Gestion des cles SSH."""


@keys.command("list")
@click.option("--status", default=None, help="Filtrer par statut")
@click.option("--server", default=None, help="Filtrer par serveur")
def keys_list(status, server):
    """Lister les cles SSH."""
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
    """Afficher le detail d'une cle."""
    row = db.query_one("SELECT * FROM ssh_keys WHERE fingerprint = %s", (fingerprint,))
    if not row:
        raise click.ClickException(f"Cle introuvable : {fingerprint}")
    for k, v in row.items():
        click.echo(f"{k:20}: {v}")


@keys.command("validate")
@click.argument("fingerprint")
def keys_validate(fingerprint):
    """Valider une cle (PENDING_REVIEW → ACTIVE)."""
    admin_id = _require_admin()
    try:
        actions.validate_key(fingerprint, admin_id)
        click.echo(f"Cle {fingerprint} validee.")
    except ValueError as e:
        raise click.ClickException(str(e))


@keys.command("revoke")
@click.argument("fingerprint")
@click.option("--reason", required=True, help="Motif de revocation")
def keys_revoke(fingerprint, reason):
    """Revoquer une cle SSH."""
    admin_id = _require_admin()
    try:
        actions.revoke_key(fingerprint, admin_id, reason)
        click.echo(f"Cle {fingerprint} revoquee.")
    except ValueError as e:
        raise click.ClickException(str(e))


@keys.command("assign")
@click.argument("fingerprint")
@click.option("--owner", required=True, help="Username du proprietaire")
def keys_assign(fingerprint, owner):
    """Assigner une cle a un administrateur."""
    try:
        actions.assign_key(fingerprint, owner)
        click.echo(f"Cle {fingerprint} assignee a {owner}.")
    except ValueError as e:
        raise click.ClickException(str(e))


@keys.command("set-expiry")
@click.argument("fingerprint")
@click.option("--hours", default=None, type=int, help="Duree en heures")
@click.option("--date", "date_str", default=None, help="Date YYYY-MM-DD HH:MM")
def keys_set_expiry(fingerprint, hours, date_str):
    """Definir l'expiration d'une cle."""
    if hours and date_str:
        raise click.UsageError("Utilisez --hours OU --date, pas les deux.")
    if hours:
        expires_at = datetime.now(tz=timezone.utc) + timedelta(hours=hours)
    elif date_str:
        expires_at = _parse_dt(date_str)
    else:
        raise click.UsageError("--hours ou --date requis.")
    try:
        actions.set_key_expiry(fingerprint, expires_at)
        click.echo(f"Expiration definie : {expires_at.isoformat()}")
    except ValueError as e:
        raise click.ClickException(str(e))


@keys.command("remove-expiry")
@click.argument("fingerprint")
def keys_remove_expiry(fingerprint):
    """Supprimer l'expiration d'une cle."""
    try:
        actions.remove_key_expiry(fingerprint)
        click.echo(f"Expiration supprimee pour {fingerprint}.")
    except ValueError as e:
        raise click.ClickException(str(e))


@keys.command("search")
@click.argument("query")
def keys_search(query):
    """Rechercher des cles par fingerprint ou commentaire."""
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
    """Gestion des acces temporaires."""


@access.command("list")
@click.option("--status", default=None, help="Filtrer par statut")
def access_list(status):
    """Lister les acces temporaires."""
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
    """Afficher le detail d'une demande."""
    row = db.query_one("SELECT * FROM access_requests WHERE id = %s", (request_id,))
    if not row:
        raise click.ClickException(f"Demande introuvable : {request_id}")
    for k, v in row.items():
        click.echo(f"{k:20}: {v}")


@access.command("grant")
@click.option("--key", "key_fp", required=True, help="Fingerprint de la cle")
@click.option("--server", "hostname", required=True, help="Serveur cible")
@click.option("--hours", default=None, type=int, help="Duree en heures")
@click.option("--date", "date_str", default=None, help="Date expiration YYYY-MM-DD HH:MM")
@click.option("--reason", required=True, help="Justification")
def access_grant(key_fp, hostname, hours, date_str, reason):
    """Accorder un acces temporaire."""
    if hours and date_str:
        raise click.UsageError("Utilisez --hours OU --date, pas les deux.")
    if hours:
        expires_at = datetime.now(tz=timezone.utc) + timedelta(hours=hours)
    elif date_str:
        expires_at = _parse_dt(date_str)
    else:
        raise click.UsageError("--hours ou --date requis.")
    admin_id = _require_admin()
    try:
        actions.grant_access(key_fp, hostname, expires_at, reason, admin_id)
        click.echo(f"Acces accorde jusqu'au {expires_at.isoformat()}.")
    except ValueError as e:
        raise click.ClickException(str(e))


@access.command("request")
@click.option("--key", "key_fp", required=True, help="Fingerprint de la cle")
@click.option("--server", "hostname", required=True, help="Serveur cible")
@click.option("--hours", required=True, type=int, help="Duree en heures")
@click.option("--reason", required=True, help="Justification")
def access_request(key_fp, hostname, hours, reason):
    """Soumettre une demande d'acces temporaire."""
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
    click.echo("Demande soumise.")


@access.command("approve")
@click.argument("request_id")
def access_approve(request_id):
    """Approuver une demande d'acces."""
    admin_id = _require_admin()
    try:
        actions.approve_request(request_id, admin_id)
        click.echo(f"Demande {request_id} approuvee.")
    except ValueError as e:
        raise click.ClickException(str(e))


@access.command("reject")
@click.argument("request_id")
def access_reject(request_id):
    """Rejeter une demande d'acces."""
    admin_id = _require_admin()
    try:
        actions.reject_request(request_id, admin_id)
        click.echo(f"Demande {request_id} rejetee.")
    except ValueError as e:
        raise click.ClickException(str(e))


@access.command("revoke")
@click.argument("request_id")
def access_revoke(request_id):
    """Revoquer un acces accorde."""
    admin_id = _require_admin()
    try:
        actions.revoke_request(request_id, admin_id)
        click.echo(f"Acces {request_id} revoque.")
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
    """Gestion des administrateurs."""


@admin.command("list")
def admin_list():
    """Lister les administrateurs."""
    rows = db.query("SELECT username, email, role, is_active, created_at FROM administrators ORDER BY username")
    _table(rows, ["username", "email", "role", "is_active"])


@admin.command("add")
@click.option("--username", required=True, help="Login")
@click.option("--email", required=True, help="Email")
@click.option("--password", required=True, help="Mot de passe")
def admin_add(username, email, password):
    """Ajouter un administrateur."""
    performer_id = _require_admin()
    try:
        actions.add_admin(username, email, password, performer_id)
        click.echo(f"Administrateur {username} cree.")
    except Exception as e:
        raise click.ClickException(str(e))


@admin.command("disable")
@click.argument("username")
def admin_disable(username):
    """Desactiver un administrateur."""
    performer_id = _require_admin()
    try:
        actions.disable_admin(username, performer_id)
        click.echo(f"Administrateur {username} desactive.")
    except ValueError as e:
        raise click.ClickException(str(e))


@admin.command("enable")
@click.argument("username")
def admin_enable(username):
    """Reactiver un administrateur desactive."""
    performer_id = _require_admin()
    try:
        actions.enable_admin(username, performer_id)
        click.echo(f"Administrateur {username} reactive.")
    except ValueError as e:
        raise click.ClickException(str(e))


@admin.command("update")
@click.argument("username")
@click.option("--email", default=None, help="Nouvelle adresse email")
@click.option("--role", default=None, help="Nouveau role")
def admin_update(username, email, role):
    """Mettre a jour un administrateur (email et/ou role)."""
    if not email and not role:
        raise click.UsageError("Au moins --email ou --role requis.")
    performer_id = _require_admin()
    try:
        current = db.query_one(
            "SELECT email, role FROM administrators WHERE username = %s", (username,)
        )
        if not current:
            raise click.ClickException(f"Administrateur introuvable : {username}")
        actions.update_admin(
            username,
            email if email is not None else current["email"],
            role if role is not None else current["role"],
            performer_id,
        )
        click.echo(f"Administrateur {username} mis a jour.")
    except ValueError as e:
        raise click.ClickException(str(e))


@admin.command("delete")
@click.argument("username")
@click.confirmation_option(prompt="Supprimer definitivement cet administrateur ?")
def admin_delete(username):
    """Supprimer definitivement un administrateur (doit etre desactive, sans references)."""
    performer_id = _require_admin()
    try:
        actions.delete_admin(username, performer_id)
        click.echo(f"Administrateur {username} supprime.")
    except ValueError as e:
        raise click.ClickException(str(e))


# ---------------------------------------------------------------------------
# audit
# ---------------------------------------------------------------------------

@cli.group()
def audit():
    """Consultation du journal d'audit."""


@audit.command("list")
@click.option("--server", default=None, help="Filtrer par serveur")
@click.option("--action", default=None, help="Filtrer par action")
@click.option("--since", default=None, help="Depuis date YYYY-MM-DD")
def audit_list(server, action, since):
    """Afficher le journal d'audit."""
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
    """Etat du systeme."""


@system.command("status")
def system_status():
    """Afficher le statut global."""
    servers_n = db.query_one("SELECT COUNT(*) AS n FROM servers WHERE is_active = true")
    pending_n = db.query_one("SELECT COUNT(*) AS n FROM key_authorizations WHERE status = 'PENDING_REVIEW'")
    active_n = db.query_one("SELECT COUNT(*) AS n FROM key_authorizations WHERE status = 'ACTIVE'")
    last_scan = db.query_one(
        "SELECT performed_at FROM audit_log WHERE action = 'SCAN_COMPLETED' ORDER BY performed_at DESC LIMIT 1"
    )
    click.echo(f"Serveurs actifs    : {servers_n['n'] if servers_n else 0}")
    click.echo(f"Cles ACTIVE        : {active_n['n'] if active_n else 0}")
    click.echo(f"Cles PENDING_REVIEW: {pending_n['n'] if pending_n else 0}")
    click.echo(f"Dernier scan       : {last_scan['performed_at'] if last_scan else 'jamais'}")


@system.command("report")
def system_report():
    """Afficher un rapport de securite."""
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
    click.echo(f"\n=== Cles non conformes ACTIVE ({len(non_compliant)}) ===")
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
    click.echo(f"\n=== Anomalies 30 derniers jours ({len(anomalies)}) ===")
    _table(anomalies, ["action", "performed_at", "hostname"])


if __name__ == "__main__":
    cli()
