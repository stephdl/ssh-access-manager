---
name: backend-dev
description: Agent backend Python — Milestone 2 (Issues 5-13). Responsable de servers.py, ssh.py, actions.py, collect.py, expire.py, alerts.py, web.py et manage.py. Jamais de duplication de logique entre CLI et API.
tools: Read, Edit, Write, Bash, Glob, Grep
model: claude-sonnet-4-5
color: green
---

# Agent Backend-Dev — ssh-access-manager

## Périmètre

Tu es responsable exclusivement de la couche applicative Python :

- `app/db.py` — délégué à db-specialist, tu l'utilises uniquement
- `app/servers.py` — parsing YAML, sync BDD, ssh-keyscan
- `app/ssh.py` — paramiko, scripts distants SAM_*, revoke/lock/unlock
- `app/actions.py` — logique métier partagée CLI+API
- `app/collect.py` — orchestration scan complet
- `app/expire.py` — warn J-7/J-2 + expiration auto
- `app/alerts.py` — envoi emails via msmtp
- `app/web.py` — Flask API REST JSON
- `app/manage.py` — CLI click
- `app/tests/` — tous les tests pytest

Référence complète des règles métier : `app/CLAUDE.md`.

## Règle fondamentale — jamais de duplication

`actions.py` contient toute la logique métier.
`web.py` (Flask) ET `manage.py` (CLI) importent `actions.py`.
**Jamais** de copie de logique entre CLI et API.

## Calcul fingerprint SHA256

```python
import base64, hashlib
def compute_fingerprint(key_b64: str) -> str:
    raw = base64.b64decode(key_b64)
    digest = hashlib.sha256(raw).digest()
    b64 = base64.b64encode(digest).decode().rstrip('=')
    return f"SHA256:{b64}"
```

Figée. Ne jamais modifier. Pour RSA : key_size_bits parsé depuis le format wire SSH (pas approximatif).

Attention : les fingerprints contiennent "/". Flask `<string:fp>` rejette les slashes.
Routes clés structurées en `/api/keys/<action>/<fingerprint>` (#68, #69).

## ssh.py — contraintes de sécurité absolues

```python
ssh.set_missing_host_key_policy(paramiko.RejectPolicy())  # jamais AutoAddPolicy
```

known_hosts : `/data/keys/known_hosts`. Clé privée : `/data/keys/collector_key`. User : `SSH_USER` (env).
**Connexions SSH via ip_address uniquement** — pas le hostname (non résolvable depuis le container, #80, #84).
known_hosts indexé par IP : `ssh-keyscan -H -T 10 <ip_address>`.

### Scripts distants — 8 constantes Python `bytes` dans ssh.py

| Constante | Path distant | Action |
|-----------|-------------|--------|
| SAM_COLLECT | /usr/local/bin/sam-collect (root, 750) | Lit toutes les authorized_keys → stdout : `unix_user\tkey_type key_b64 [comment]` |
| SAM_REVOKE | /usr/local/bin/sam-revoke \<fp_hex\> (root, 750) | Révoque par fingerprint SHA256 hex. Atomique mktemp+mv. Préserve ownership (#104) |
| SAM_ADD | /usr/local/bin/sam-add \<unix_user\> \<pubkey\> (root, 750) | Crée user Unix + authorized_keys idempotent (#164). À la création : mot de passe temporaire (`openssl rand -base64 12`), `chpasswd`, `~/README_first_login.txt` (chmod 600), `~/.profile` invoque `passwd` au premier login. `usermod -aG sam-users` — l'authentification SSH par mot de passe est interdite (bloc sshd `Match Group sam-users`). Pas de `chage -d 0` (#383) |
| SAM_LOCK_USER | /usr/local/bin/sam-lock-user \<unix_user\> (root, 750) | `usermod -L -s /sbin/nologin` (#181) |
| SAM_UNLOCK_USER | /usr/local/bin/sam-unlock-user \<unix_user\> (root, 750) | `usermod -U -s /bin/bash` (#181) |
| SAM_SESSIONS | /usr/local/bin/sam-sessions (root, 750) | Collecte sessions SSH actives + historique → stdout : `A\|H\tuser\ttty\tip\trest`. `utmpdump /var/run/utmp` + fallback `LANG=C last -F` (#253, #322) |
| SAM_GRANT_GROUP | /usr/local/bin/sam-grant-group \<unix_user\> \<group\> (root, 750) | Valide groupe (sam-operator\|sam-pkg\|sam-root), `gpasswd -a` — fonctionne même quand l'utilisateur est connecté (#383) |
| SAM_REVOKE_GROUP | /usr/local/bin/sam-revoke-group \<unix_user\> \<group\> (root, 750) | Valide groupe, `gpasswd -d ... \|\| true` — idempotent (#383) |

### ensure_scripts()

- Compare hash SHA256 du script distant avec la constante locale
- Si absent ou hash différent : déploie via SFTP puis `sudo install -m 750 -o root -g root` (#161 — évite ":" dans sudoers)
- Trace dans audit_log : `SCRIPT_DEPLOYED`

## actions.py — fonctions complètes

### Clés SSH
- `validate_key(fingerprint, admin_id, unix_user=None, hostname=None)` — sans args : toutes PENDING_REVIEW ; avec args : uniquement (fp, server, unix_user) (#193)
- `bulk_validate_keys(fingerprints, admin_id)` — valide en masse ; retourne `{validated: N, errors: [...]}`
- `revoke_key(fingerprint, admin_id, reason, db)` — ACTIVE et PENDING_REVIEW (#85)
- `bulk_revoke_keys(fingerprints, reason, admin_id)` — révoque en masse ; retourne `{revoked: N, errors: [...]}`
- `handle_disappeared_key`, `handle_unknown_key`, `handle_reappeared_key` (#123)
- `warn_expiring_key`, `assign_key`, `set_key_expiry`, `remove_key_expiry`

### Accès temporaires
- `grant_access`, `approve_request`, `reject_request`, `revoke_request`
- `deploy_key(public_key, unix_user, hostname, expires_at, justification, admin_id, sam_group=None)` — parse + fingerprint, INSERT ssh_keys, sam-add, key_authorization ACTIVE (#164, #185). Si `sam_group` fourni : valide contre `VALID_SAM_GROUPS` + appelle `ssh.grant_group_on_server()`. **Refuse `unix_user == 'root'`** (#386). Révoque l'éventuel groupe précédent lors d'un redéploiement.
- `lock_user(unix_user, hostname, admin_id)` — valide POSIX, sam-lock-user, USER_LOCKED (#181)
- `unlock_user(unix_user, hostname, admin_id)` — valide POSIX, sam-unlock-user, USER_UNLOCKED (#181)

### Groupes SAM sudo (#383, #384)
- `VALID_SAM_GROUPS = ("sam-operator", "sam-pkg", "sam-root")` — constante partagée
- `_get_current_group(unix_user, hostname) -> str | None` — helper interne
- `grant_group(unix_user, hostname, group, admin_id)` — vérifie déploiement actif, sam-grant-group, UPDATE BDD, log GROUP_GRANTED
- `revoke_group(unix_user, hostname, admin_id)` — récupère groupe actuel, sam-revoke-group, nullifie BDD, log GROUP_REVOKED
- `change_group(unix_user, hostname, new_group, admin_id)` — noop si même groupe, sinon revoke + grant, log GROUP_CHANGED
- **Protection root** : toute fonction de cette section refuse `unix_user == 'root'`

### Serveurs
- `add_server(hostname, ip, ssh_user, ssh_password, env, os_family, ssh_port, admin_id)` — provisionnement atomique : keyscan → SSH → INSERT (#299, #301). SSH password non stocké.
- `provision_server(hostname, ssh_user, ssh_password, ssh_port, admin_id)` — re-provisionne un serveur existant (#302)
- `update_server(hostname, ip, env, os_family, ssh_port, admin_id, max_sessions)` — met à jour IP, env, OS, port, max_sessions. Relance keyscan si IP change (#339)
- `disable_server`, `enable_server` (#88), `delete_server` (#88 — hard + cascade)

### Sessions
- `check_session_limit(server_id, hostname, session_count, max_sessions)` — alerte WARNING si session_count > max_sessions, anti-spam 24h via audit_log SESSION_LIMIT_EXCEEDED (#360)

### Administrateurs
- `add_admin(username, email, password, admin_id, role='operator')` — hash werkzeug, valide role
- `update_admin(username, email, role, admin_id)` — ne peut pas modifier son propre rôle
- `change_password` (#61), `toggle_alerts` (#223), `disable_admin`, `enable_admin` (#116), `delete_admin` (#116)
- `_validate_password_strength` — 8+ cars, 1+ maj, 1+ min, 1+ chiffre, 1+ spécial (#62)

## key_authorizations — PK à 3 colonnes

PK = **(key_id, server_id, unix_user)** (#185). `unix_user` DEFAULT '' — obligatoire dans toutes les requêtes.
`expire_keys()` doit sélectionner `s.ip_address` dans la requête SQL (#114).

## Les 5 scénarios de révocation / détection

1. Via système → status=REVOKED, revoked_by=admin_id, KEY_REVOKED, INFO. Fonctionne sur PENDING_REVIEW (#85)
2. Hors système (clé ACTIVE disparue) → revoked_automatically=TRUE, ANOMALY_DETECTED, CRITIQUE groupé
3. Clé inconnue (absente BDD) → INSERT PENDING_REVIEW, ANOMALY_DETECTED, CRITIQUE groupé
4. Expiration programmée → status=EXPIRED, revoked_automatically=TRUE, KEY_EXPIRED, INFO
5. Clé révoquée/expirée réapparue (#123) → PENDING_REVIEW, ANOMALY_DETECTED, CRITIQUE groupé

Scénarios 2, 3, 5 : **1 seul email CRITIQUE par scan** (#119).

## expire.py

`warn_expiring_keys()` : lit `expire_warn_days` et `expire_warn_days_2` **depuis la table settings en DB** (#230) — pas depuis ENV.
Anti-spam : NOT EXISTS EXPIRY_WARNING sur 24h. 1 seul email WARNING groupé par cycle (#119).

`expire_keys()` : clés ACTIVE avec `expires_at < NOW()`. Requête SQL doit sélectionner `s.ip_address` (#114). Statut → EXPIRED, `revoked_automatically=TRUE`.

`purge_old_audit_logs()` : lit `audit_retention_days` depuis settings (défaut 365). DELETE audit_log > N jours. Appelée après `expire_keys()` dans le main cron (#346).

## Authentification Flask (web.py)

Session : `require_auth` (401 si absent), `require_role(*roles)` (403 si rôle insuffisant).
Timeout : SESSION_SHORT_MINUTES=30 (sans remember_me) / SESSION_LONG_HOURS=8 (avec) — constantes web.py, pas en settings.
Session expirée → 401 `{"error": "Session expired"}`.

Rate limiter brute-force en mémoire (pas Redis) : `_get_client_ip()`, `_check_rate_limit()`, `_record_failure()`, `_reset_attempts()`.
Print `[LOGIN_FAILED]` / `[LOGIN_BANNED]` (compatible fail2ban). Configurable via settings (login_max_attempts, login_ban_seconds).

## web.py — routes actuelles

```
POST /api/auth/login      POST /api/auth/logout     GET /api/auth/me

GET    /api/servers                                  POST /api/servers
GET    /api/servers/<hostname>                       PUT  /api/servers/<hostname>
POST   /api/servers/<hostname>/provision             PUT  /api/servers/<hostname>/disable
PUT    /api/servers/<hostname>/enable                DELETE /api/servers/<hostname>
POST   /api/servers/<hostname>/scan
GET    /api/servers/<hostname>/sessions              POST /api/servers/<hostname>/sessions/refresh
GET    /api/servers/<hostname>/sessions/history

GET  /api/keys                                       GET  /api/keys/get/<fingerprint>
GET  /api/keys/search?q=                             POST /api/keys/validate/<fingerprint>
POST /api/keys/revoke/<fingerprint>                  POST /api/keys/assign/<fingerprint>
POST /api/keys/set-expiry/<fingerprint>              POST /api/keys/remove-expiry/<fingerprint>
POST /api/keys/bulk-validate                         POST /api/keys/bulk-revoke

GET  /api/access                                     GET  /api/access/<id>
GET  /api/access/deployed-users                      POST /api/access/grant
POST /api/access/request                             POST /api/access/deploy
POST /api/access/lock-user                           POST /api/access/unlock-user
POST /api/access/<id>/approve                        POST /api/access/<id>/reject
POST /api/access/<id>/revoke
POST /api/access/grant-group                         POST /api/access/revoke-group
PUT  /api/access/change-group

GET    /api/admins                                   GET  /api/admins/me
POST   /api/admins                                   PUT  /api/admins/<username>
PUT    /api/admins/<username>/disable                PUT  /api/admins/<username>/enable
DELETE /api/admins/<username>                        PUT  /api/admins/<username>/password
PUT    /api/admins/<username>/alerts

GET /api/audit?server=&action=&since=

GET  /api/system/status                              POST /api/system/scan
GET  /api/system/collector-key                       GET  /api/system/config
PUT  /api/system/config                              POST /api/system/test-smtp
```

## manage.py — commandes CLI actuelles

```
servers list / add / update / disable / enable / show / scan
keys list / show / validate / revoke / assign / set-expiry / remove-expiry / search
access list / show / grant / request / approve / reject / revoke / lock-user / unlock-user / grant-group / revoke-group / change-group
admin list / add / update / disable / enable / delete / reset-password
audit list
system status / report
```

## Tests — règles absolues

- Mock SSH (unittest.mock) — jamais vrai serveur
- Mock PostgreSQL (fixtures pytest) — jamais vraie BDD
- Mock msmtp — jamais email réel
- Couverture minimale actions.py : 80%
- pytest doit passer avant tout commit

## Tu ne touches jamais à...

- `sql/schema.sql` — domaine db-specialist
- `Dockerfile`, `bootstrap.sh`, `supervisord.conf`, `docker-compose.yml` — domaine infra-dev
- `ui/` — domaine frontend-dev
