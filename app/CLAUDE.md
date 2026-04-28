# app/CLAUDE.md — Backend Python

## bootstrap.sh — ordre strict obligatoire

Détection premier démarrage : absence de /data/pg/PG_VERSION.

Premier démarrage :
1. mkdir -p /data/keys /data/pg /data/config
2. chown postgres:postgres /data/pg && chmod 700 /data/pg
3. ssh-keygen -t ed25519 -f /data/keys/collector_key -N "" -C "ssh-access-manager@$(hostname)"
4. touch /data/keys/known_hosts && chmod 644 /data/keys/known_hosts
5. chmod 600 /data/keys/collector_key
6. chown nobody /data/keys/collector_key /data/keys/known_hosts
7. Démarrer PostgreSQL temporairement (socket local uniquement)
8. Créer base et utilisateur depuis ENV (deux psql séparés — CREATE DATABASE hors transaction)
9. Appliquer /app/sql/schema.sql
10. Insérer administrateur initial depuis ENV avec werkzeug generate_password_hash
11. Arrêter PostgreSQL temporaire
12. Générer /etc/msmtprc depuis msmtp.conf.template + ENV
13. Générer /etc/nginx/nginx.conf depuis nginx.conf.template + ENV
14. Afficher collector_key.pub dans les logs

Non premier démarrage : régénérer nginx.conf + msmtprc depuis ENV.
Toujours en dernier : `exec /usr/bin/supervisord -c /etc/supervisord.conf`

## servers.yml — format

```yaml
servers:
  - hostname: server-prod-01
    ip: 192.168.1.10
    environment: production   # production | staging | lab
    os_family: rhel
```

## Base de données — contraintes clés

Schéma complet dans sql/schema.sql. Points non-évidents :

- `ssh_keys.is_compliant` : colonne GENERATED ALWAYS AS — `key_type = 'ssh-ed25519' OR (key_type = 'ssh-rsa' AND key_size_bits >= 4096)`
- `key_authorizations` PK = **(key_id, server_id, unix_user)** — même clé déployable pour plusieurs users Unix sur même serveur (#185)
- `key_authorizations.unix_user` DEFAULT '' — champ obligatoire dans toutes les requêtes
- Table `settings` : lire en DB, jamais depuis ENV. Clés : `scan_interval_hours` (4), `expire_warn_days` (7), `expire_warn_days_2` (2), `login_max_attempts` (10), `login_ban_seconds` (300)

## Logique métier — fingerprint SHA256

```python
import base64, hashlib
def compute_fingerprint(key_b64):
    raw = base64.b64decode(key_b64)
    digest = hashlib.sha256(raw).digest()
    b64 = base64.b64encode(digest).decode().rstrip('=')
    return f"SHA256:{b64}"
```

Pour RSA : key_size_bits calculé en parsant le format wire SSH (pas approximatif) pour que is_compliant soit exact.

Attention : les fingerprints contiennent "/" (ex: SHA256:abc/def). Flask `<string:fp>` rejette les slashes.
Les routes clés sont structurées en `/api/keys/<action>/<fingerprint>` pour éviter les 404 (#68, #69).

## Logique métier — scripts distants (ssh.py)

Six constantes Python `bytes` dans ssh.py. Déployées via SFTP si absentes ou hash SHA256 différent.
Tracées dans audit_log (SCRIPT_DEPLOYED).

| Constante | Path distant | Droits | Action |
|-----------|-------------|--------|--------|
| SAM_COLLECT | /usr/local/bin/sam-collect | root, 755 | Lit toutes les authorized_keys → stdout : `unix_user\tkey_type key_b64 [comment]` |
| SAM_REVOKE | /usr/local/bin/sam-revoke \<fp_hex\> | root, 755 | Révoque par fingerprint SHA256 hex. Réécriture atomique mktemp+mv. Préserve ownership (#104) |
| SAM_ADD | /usr/local/bin/sam-add \<unix_user\> \<pubkey\> | root, 755 | Crée user Unix si absent, ajoute clé idempotent (#164) |
| SAM_LOCK_USER | /usr/local/bin/sam-lock-user \<unix_user\> | root, 755 | `usermod -L -s /sbin/nologin` — bloque mdp ET shell (#181) |
| SAM_UNLOCK_USER | /usr/local/bin/sam-unlock-user \<unix_user\> | root, 755 | `usermod -U -s /bin/bash` (#181) |
| SAM_SESSIONS | /usr/local/bin/sam-sessions | root, 755 | Collecte sessions SSH actives (who) + historique (last) → stdout : `A\|H\tuser\ttty\tip\trest` (#253) |

## Logique métier — known_hosts et connexions SSH

**`paramiko.RejectPolicy()` obligatoire — jamais AutoAddPolicy.**

ssh-keyscan si hôte absent de known_hosts :
```python
subprocess.run(['ssh-keyscan', '-H', '-T', '10', ip_address])
# → append dans /data/keys/known_hosts
```

**Les connexions SSH utilisent ip_address (pas hostname)** — le hostname peut ne pas être résolvable DNS depuis le container (#80, #84). known_hosts est indexé par IP.

## Logique métier — expiration (expire.py)

`warn_expiring_keys()` :
- Lit expire_warn_days et expire_warn_days_2 depuis settings en DB (#230)
- Clés ACTIVE avec expires_at dans max(expire_warn_days, expire_warn_days_2)
- Anti-spam : NOT EXISTS audit_log EXPIRY_WARNING sur 24h
- 1 seul email WARNING groupé par cycle (#119) + audit_log EXPIRY_WARNING par clé

`expire_keys()` :
- Clés ACTIVE avec expires_at < NOW()
- **Requête SQL doit sélectionner s.ip_address** (#114)
- sam-revoke sur serveur distant via IP
- status=EXPIRED, revoked_automatically=TRUE, audit_log KEY_EXPIRED, email INFO

## Les 5 scénarios de révocation / détection

| # | Contexte | Résultat BDD | Audit | Email |
|---|----------|-------------|-------|-------|
| 1 | Via système (revoke_key) | status=REVOKED, revoked_by=admin_id | KEY_REVOKED | INFO. Fonctionne sur PENDING_REVIEW (#85) |
| 2 | Hors système (clé ACTIVE disparue au scan) | status=REVOKED, revoked_automatically=TRUE, revoked_by=NULL | ANOMALY_DETECTED | CRITIQUE (groupé) |
| 3 | Clé inconnue (présente serveur, absente BDD) | INSERT status=PENDING_REVIEW | ANOMALY_DETECTED | CRITIQUE (groupé) |
| 4 | Expiration programmée (expires_at < NOW()) | status=EXPIRED, revoked_automatically=TRUE | KEY_EXPIRED | INFO |
| 5 | Clé révoquée/expirée réapparue (#123) | status=PENDING_REVIEW, reason=revoked_key_reappeared | ANOMALY_DETECTED | CRITIQUE (groupé) |

Scénarios 2, 3, 5 : **1 seul email CRITIQUE par scan** regroupant toutes les anomalies (#119).

## Alertes email — niveaux

- **CRITIQUE** (1 seul email par scan) : clé inconnue, révocation hors système, scan échoué
- **WARNING** (1 seul email par cycle, anti-spam 24h) : expiry J-expire_warn_days et J-expire_warn_days_2
- **INFO** (log uniquement) : KEY_EXPIRED, KEY_REVOKED, SCAN_COMPLETED, SCRIPT_DEPLOYED

## Authentification Flask — sessions (#51–54, #239)

```
POST /api/auth/login   → session[admin_id, username, expires_at]
POST /api/auth/logout  → clear session
GET  /api/auth/me      → {id, username, email, role}
```

- Sans remember_me → expire après SESSION_SHORT_MINUTES (30 min, constante dans web.py)
- Avec remember_me=true → expire après SESSION_LONG_HOURS (8h, constante dans web.py)
- Session expirée → clear + 401 `{"error": "Session expired"}`
- `require_auth` : charge g.admin_id, g.admin_username, g.admin_role. 401 si absent.
- `require_role(*roles)` : 403 si g.admin_role ∉ roles (#222)

Rôles :
- **sysadmin** : accès complet (seul à gérer les admins)
- **operator** : actions SSH (valider, révoquer, déployer, lock/unlock)
- **viewer** : lecture seule

Exception password : `PUT /api/admins/<username>/password` — sysadmin toujours autorisé ; operator/viewer autorisé uniquement pour son propre mot de passe.

Validation mot de passe (#62) : 8+ cars, 1+ maj, 1+ min, 1+ chiffre, 1+ spécial. Appliquée dans add_admin() et change_password().

## Protection brute-force (web.py, #236)

Rate limiter en mémoire (pas Redis) sur POST /api/auth/login.
Fonctions : `_get_client_ip()`, `_load_login_settings()`, `_check_rate_limit(ip)`, `_record_failure(ip, username)`, `_reset_attempts(ip)`.

- Chaque échec → print `[LOGIN_FAILED] ip=... username=...` + INSERT audit_log LOGIN_FAILED
- Seuil atteint → print `[LOGIN_BANNED] ip=... ban_seconds=...` + INSERT audit_log LOGIN_BANNED + HTTP 429
- Ban expiré → supprimé automatiquement à la prochaine requête
- Format compatible fail2ban/CrowdSec

Configurable sans redémarrage via PUT /api/system/config : login_max_attempts (1–100), login_ban_seconds (30–86400).

## actions.py — fonctions

### Clés SSH
- `validate_key(fingerprint, admin_id, unix_user=None, hostname=None)` — sans args : valide toutes PENDING_REVIEW du fingerprint ; avec args : valide uniquement (fingerprint, server, unix_user) (#193)
- `revoke_key(fingerprint, admin_id, reason, db)` — ACTIVE et PENDING_REVIEW (#85)
- `handle_disappeared_key`, `handle_unknown_key`, `handle_reappeared_key`
- `warn_expiring_key`, `assign_key`, `set_key_expiry`, `remove_key_expiry`

### Accès temporaires
- `grant_access`, `approve_request`, `reject_request`, `revoke_request`
- `deploy_key(public_key, unix_user, hostname, expires_at, justification, admin_id)` — parse + fingerprint, INSERT ssh_keys, sam-add, key_authorization ACTIVE (#164, #185)
- `lock_user(unix_user, hostname, admin_id)` — valide username POSIX, sam-lock-user, USER_LOCKED (#181)
- `unlock_user(unix_user, hostname, admin_id)` — valide username POSIX, sam-unlock-user, USER_UNLOCKED (#181)

### Serveurs
- `add_server(hostname, ip, env, os_family, db)` — appelle add_to_known_hosts(ip) avant INSERT (#70)
- `disable_server`, `enable_server` (#88), `delete_server` (#88 — hard delete + cascade)

### Administrateurs
- `add_admin(username, email, password, admin_id, role='operator')` — email obligatoire, valide role, hash werkzeug
- `update_admin(username, email, role, admin_id)` — ne peut pas modifier son propre rôle
- `change_password`, `toggle_alerts` (#223), `enable_admin` (#116), `delete_admin` (#116 — vérifie FK)
- `disable_admin` (#116, #259) — vérifie qu'il reste ≥ 1 autre sysadmin actif ; `update_admin` vérifie de même si dégradation de rôle (#259)
- `_validate_password_strength(password)` (#62)

## Matrice RBAC

| Route | sysadmin | operator | viewer |
|-------|----------|----------|--------|
| GET /api/servers, /api/keys, /api/access, /api/admins, /api/audit, /api/system/status, /api/system/config, /api/system/collector-key | ✓ | ✓ | ✓ |
| POST /api/servers | ✓ | 403 | 403 |
| PUT/DELETE /api/servers/\*/disable, enable, DELETE | ✓ | 403 | 403 |
| POST /api/servers/\*/scan, /api/system/scan | ✓ | ✓ | 403 |
| GET /api/servers/\*/sessions, /api/servers/\*/sessions/history | ✓ | ✓ | 403 |
| POST /api/servers/\*/sessions/refresh | ✓ | ✓ | 403 |
| POST /api/keys/validate, revoke, assign, set-expiry, remove-expiry | ✓ | ✓ | 403 |
| POST /api/access/grant, deploy, lock-user, unlock-user, request, approve, reject, revoke | ✓ | ✓ | 403 |
| POST /api/admins | ✓ | 403 | 403 |
| PUT /api/admins/\* (sauf password) | ✓ | 403 | 403 |
| PUT /api/admins/\*/password | ✓ | ✓* | 403* |
| PUT /api/system/config | ✓ | 403 | 403 |
| POST /api/system/test-smtp | ✓ | ✓ | ✓ |

*operator/viewer : autorisé uniquement pour son propre mot de passe.

## Tests Python — règles absolues

- Mock SSH obligatoire (unittest.mock) — jamais de vrai serveur
- Mock PostgreSQL via fixtures pytest — jamais de vraie BDD
- Mock msmtp via unittest.mock — jamais d'email réel
- Un test = un comportement précis
- Nommage : `test_<module>_<scenario>_<expected>`
- Couverture minimale actions.py : 80%
- pytest doit passer avant tout commit

Fichiers : conftest.py, test_db.py (7), test_servers.py (9), test_ssh.py (40), test_actions.py (97), test_collect.py (34), test_expire.py (12), test_alerts.py (19), test_web.py (115), test_manage.py (35).

Fixtures obligatoires dans conftest.py : `mock_db`, `mock_ssh_client`, `mock_smtp`, `sample_server`, `sample_key`.

Scénarios critiques à ne jamais casser :
- test_ssh.py : RejectPolicy présent sur chaque connexion, SAM_* sont de type `bytes`
- test_expire.py : expire_keys requiert ip_address dans la requête SQL (#114)
- test_web.py : session expirée → 401, remember_me=true → expires_at dans ~8h
- test_web.py : deploy retourne 400 si hours hors plage (0, -1, 8761) ou non entier

Non testé unitairement : bootstrap.sh, Dockerfile, nginx.conf.template, provision-host.sh.

## sudoers et provision-host.sh

`/etc/sudoers.d/${COLLECTOR_USER}` (chmod 440) — utilise `install` au lieu de mv+chmod+chown.
Raison : évite ":" dans les args sudoers qui brise visudo sur RHEL/CentOS (#161).
Généré avec printf ligne par ligne — résistant au CRLF introduit par sudo PTY (#159).

```bash
# Invocation provision-host.sh
ssh <user>@<ip> "sudo bash -s '$(podman exec ssh-access-manager cat /data/keys/collector_key.pub)' '${SSH_USER}'" \
    < <(podman exec ssh-access-manager cat /app/provision-host.sh)
```

Actions : crée l'utilisateur collector, déploie la clé publique (append, chown collector — #86), crée sudoers dynamique avec ${COLLECTOR_USER}.
