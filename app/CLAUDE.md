# app/CLAUDE.md — Backend Python

## bootstrap.sh — ordre strict obligatoire

Détection premier démarrage : absence de /data/pg/PG_VERSION.

Premier démarrage :
1. mkdir -p /data/keys /data/keys/per-server /data/pg /data/config
2. chown postgres:postgres /data/pg && chmod 700 /data/pg
3. chown nobody:nobody /data/keys/per-server && chmod 700 /data/keys/per-server
4. touch /data/keys/known_hosts && chmod 644 /data/keys/known_hosts && chown nobody /data/keys/known_hosts
5. Si `/data/keys/collector_key` (legacy global key) présent : `rm -f` au boot avec warning
6. Démarrer PostgreSQL temporairement (socket local uniquement)
7. Créer base et utilisateur depuis ENV (deux psql séparés — CREATE DATABASE hors transaction)
8. Appliquer /app/sql/schema.sql
9. Insérer administrateur initial depuis ENV avec werkzeug generate_password_hash
10. Arrêter PostgreSQL temporaire
11. Générer /etc/msmtprc depuis msmtp.conf.template + ENV
12. Générer /etc/nginx/nginx.conf depuis nginx.conf.http.template ou nginx.conf.https.template + ENV

Aucune clé SSH globale n'est générée. À l'ajout d'un serveur (UI ou CLI), `actions.add_server` / `actions.register_server` génèrent une paire ed25519 anonyme dans `/data/keys/per-server/<uuid>.key{,.pub}` (commentaire SSH vide).

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
- Table `settings` : lire en DB, jamais depuis ENV. Clés : `scan_interval_hours` (4), `expire_warn_days` (7), `expire_warn_days_2` (2), `login_max_attempts` (10), `login_ban_seconds` (300), `audit_retention_days` (365)
- `servers.ip_address` : index unique global (`servers_ip_unique`) — une IP ne peut appartenir qu'à un seul serveur, actif ou désactivé. Désactivation = maintenance temporaire, le serveur peut revenir. Seule la suppression libère l'IP.
- `servers.max_sessions` : INTEGER DEFAULT 2 — seuil alertes SESSION_LIMIT_EXCEEDED (alerte WARNING par serveur avec anti-spam 24h, #360)
- `key_authorizations.sam_group` : VARCHAR(20) nullable, CHECK IN ('sam-operator', 'sam-pkg', 'sam-root') — groupe sudo SAM assigné à l'utilisateur Unix (#383)

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

Neuf constantes Python `bytes` dans ssh.py. Déployées via SFTP si absentes ou hash SHA256 différent.
Tracées dans audit_log (SCRIPT_DEPLOYED).

| Constante | Path distant | Droits | Action |
|-----------|-------------|--------|--------|
| SAM_COLLECT | /usr/local/bin/sam-collect | root, 750 | Lit toutes les authorized_keys → stdout : `unix_user\tkey_type key_b64 [comment]` |
| SAM_REVOKE | /usr/local/bin/sam-revoke \<fp_hex\> | root, 750 | Révoque par fingerprint SHA256 hex. Réécriture atomique mktemp+mv. Préserve ownership (#104) |
| SAM_ADD | /usr/local/bin/sam-add \<unix_user\> \<pubkey\> | root, 750 | Crée user Unix si absent (`useradd -m -s /bin/bash`), ajoute clé idempotent (#164). À la création : mot de passe temporaire (`openssl rand -base64 12`) via `chpasswd`, `~/README_first_login.txt` (chmod 600), hook de premier login. Le hook est écrit dans le fichier que bash sourcera vraiment, détecté dans l'ordre `~/.bash_profile` → `~/.bash_login` → `~/.profile` (le dernier est créé par `touch` s'il manque) — reproduit l'ordre de résolution de bash et couvre RHEL/Rocky (skel fournit `.bash_profile`), Debian/Ubuntu/openSUSE (`.profile`), Arch (skel vide → `.profile` créé). Pas de `chage -d 0`. `usermod -aG sam-users` — SSH par mot de passe impossible (bloc sshd `Match Group sam-users` par provision-host.sh). Login SSH par clé uniquement (#383, hook multi-distro #390) |
| SAM_LOCK_USER | /usr/local/bin/sam-lock-user \<unix_user\> | root, 750 | `usermod -L -s /sbin/nologin` — bloque mdp ET shell (#181) |
| SAM_UNLOCK_USER | /usr/local/bin/sam-unlock-user \<unix_user\> | root, 750 | `usermod -U -s /bin/bash` (#181) |
| SAM_SESSIONS | /usr/local/bin/sam-sessions | root, 750 | Collecte sessions SSH actives + historique → stdout : `A\|H\tuser\ttty\tip\trest`. Utilise `utmpdump /var/run/utmp` (ISO 8601, locale-safe), fallback `LANG=C last -F` (#253, #322) |
| SAM_GRANT_GROUP | /usr/local/bin/sam-grant-group \<unix_user\> \<group\> | root, 750 | Valide groupe (sam-operator\|sam-pkg\|sam-root), `gpasswd -a` — works even when user is logged in (#383) |
| SAM_REVOKE_GROUP | /usr/local/bin/sam-revoke-group \<unix_user\> \<group\> | root, 750 | Valide groupe, `gpasswd -d ... \|\| true` — idempotent (#383) |
| SAM_SELF_UPDATE | /usr/local/bin/sam-self-update [\<version\>] | root, 750 | Applique config dynamique SAM (groupes, sudoers, drop-in sshd) de manière idempotente avec rollback `.bak`. Écrit version dans `/etc/sam-provision-version` (#400) |

### Auto-update des artefacts de provisioning (#400)

Constantes Python supplémentaires dans ssh.py :
- `PROVISION_VERSION` : hash SHA256 16 premiers caractères de `SAM_SELF_UPDATE`
- `PROVISION_VERSION_PATH` : `/etc/sam-provision-version`

Fonctions ssh.py :
- `_read_provision_version(client) -> str | None` : lit `/etc/sam-provision-version` distant, retourne None si fichier absent
- `apply_provision_update(hostname, ip, port) -> str` : exécute `sudo sam-self-update <PROVISION_VERSION>`, raise SSHSudoError en cas d'échec

Orchestration collect.py (dans `scan_server`) :
- Après `ensure_scripts()`, avant `collect_keys()`
- Compare version distante avec `PROVISION_VERSION`
- Si différente : `apply_provision_update()` + UPDATE `servers.provision_version`, `provision_drift=FALSE`, audit PROVISION_UPDATED
- Si échec : UPDATE `provision_drift=TRUE`, audit PROVISION_UPDATE_FAILED, continue scan (rollback `.bak` côté script)
- Si serveur injoignable : skip silencieux, SCAN_FAILED couvrira l'erreur
- Résilient aux mocks tests : bloc `try/except (ssh.SSHError, AttributeError, TypeError)`

## Logique métier — known_hosts et connexions SSH

**`paramiko.RejectPolicy()` obligatoire — jamais AutoAddPolicy.**

Récupération de clé hôte si absent de known_hosts — `_fetch_host_key(ip, port, known_hosts_path)` via `paramiko.Transport` :
- 1 handshake TCP (au lieu de 6+ avec ssh-keyscan subprocess) — évite les bans CrowdSec (#320)
- Écrit la ligne hachée dans `/data/keys/known_hosts`

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
- **Requête SQL exclut `unix_user != 'root'`** — sécurité contre révocation automatique de root
- sam-revoke sur serveur distant via IP
- status=EXPIRED, revoked_automatically=TRUE, audit_log KEY_EXPIRED, email INFO

`purge_old_audit_logs()` :
- Lit `audit_retention_days` depuis settings en DB (défaut 365 jours)
- DELETE FROM audit_log WHERE performed_at < NOW() - INTERVAL N days
- Retourne le nombre d'entrées supprimées
- Appelée par expire.py main() après expire_keys()

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

## Exceptions métier (actions.py)

- `UserError(message)` — exception user-safe exposée directement dans les réponses HTTP (400/404/409). Ne pas l'attraper dans web.py : le décorateur `@require_auth` la transforme automatiquement en `{"error": message}`. Résout l'exposition de stack-traces Python dans les réponses API (#314).

## actions.py — fonctions

### Clés SSH
- `validate_key(fingerprint, admin_id, unix_user=None, hostname=None)` — sans args : valide toutes PENDING_REVIEW du fingerprint ; avec args : valide uniquement (fingerprint, server, unix_user) (#193)
- `bulk_validate_keys(fingerprints, admin_id)` — valide en masse une liste de fingerprints PENDING_REVIEW ; retourne `{validated: N, errors: [...]}`
- `bulk_revoke_keys(fingerprints, reason, admin_id)` — révoque en masse ; retourne `{revoked: N, errors: [...]}` ; les fingerprints liés à root sont automatiquement skippés (UserError catchée → skipped+1)
- `revoke_key(fingerprint, admin_id, reason, hostname=None, unix_user=None)` — ACTIVE et PENDING_REVIEW (#85) ; refuse si `unix_user == 'root'` (targeted) ou si root a ce fingerprint (global) → UserError
- `handle_disappeared_key`, `handle_unknown_key`, `handle_reappeared_key`
- `warn_expiring_key`, `assign_key`
- `set_key_expiry(fingerprint, expires_at, unix_user=None, hostname=None)` — refuse si `unix_user == 'root'` ; global UPDATE exclut `unix_user != 'root'`
- `remove_key_expiry(fingerprint, unix_user=None, hostname=None)` — refuse si `unix_user == 'root'` ; global UPDATE exclut `unix_user != 'root'`

### Accès temporaires
- `grant_access`, `approve_request`, `reject_request`, `revoke_request`
- `deploy_key(public_key, unix_user, hostname, expires_at, justification, admin_id)` — parse + fingerprint, INSERT ssh_keys, sam-add, key_authorization ACTIVE (#164, #185) ; refuse si `unix_user == 'root'` ; `justification` inclus dans le `details` du `audit_log` KEY_ADDED
- `lock_user(unix_user, hostname, admin_id)` — valide username POSIX, sam-lock-user, USER_LOCKED (#181)
- `unlock_user(unix_user, hostname, admin_id)` — valide username POSIX, sam-unlock-user, USER_UNLOCKED (#181)

### Serveurs
- `add_server(hostname, ip, ssh_user, ssh_password, env=None, os_family=None, ssh_port=22, admin_id=None, scan_sync=False)` — provisionnement atomique : génère UUID + per-server keypair (`ssh._generate_keypair`), `_fetch_host_key(ip)` → `ssh.provision_server(..., pubkey=per_server_pubkey)` → INSERT servers (`is_provisioned=TRUE`) → audit SERVER_ADDED + SERVER_PROVISIONED + COLLECTOR_KEY_GENERATED → **scan initial** via `_trigger_initial_scan` (fire-and-forget thread depuis l'API, synchrone depuis la CLI). Si le SSH échoue, le keypair est supprimé du disque et aucune donnée n'est écrite (#299, #301, #402).
- `register_server(hostname, ip, ssh_port=22, env, os_family, admin_id)` — version sans SSH de `add_server` : génère UUID + per-server keypair, INSERT avec `is_provisioned=FALSE`. Pour bulk bootstrap (workflow 3 étapes : register → push pubkey avec sa propre clé root → activate) (#402).
- `activate_server(hostname, admin_id, scan_sync=False)` — `_fetch_host_key` + `_connect` avec la per-server key pour valider la connectivité, `is_provisioned=TRUE`, audit SERVER_PROVISIONED, scan initial via `_trigger_initial_scan` (sync depuis CLI, async depuis API) (#402).
- `rotate_collector_key(hostname, admin_id)` — délègue à `ssh.rotate_per_server_key()` (atomique avec rollback : génère `.key.new`, append pubkey distante, vérifie via re-connect, retire l'ancienne, renomme les fichiers). Audit COLLECTOR_KEY_ROTATED ou COLLECTOR_KEY_ROTATION_FAILED (avec error mais sans hostname/ip). Réservé sysadmin via UI (#402).
- `get_collector_key_for_server(hostname) -> {fingerprint, public_key}` — lecture du `<uuid>.key.pub` per-server (#402).
- `_trigger_initial_scan(server, admin_id, sync=False)` — helper : lance `collect.scan_server(server, admin_id)` en thread daemon (`sync=False`) ou en synchrone (`sync=True`). CLI doit utiliser `sync=True` car le process se termine sinon avant la fin du scan.
- `provision_server(hostname, ip, ssh_user, ssh_password, ssh_port)` — re-provisionne un serveur existant (lit la per-server pubkey depuis disque) (#302). Même garantie : ssh password non stocké.
- `update_server(hostname, ip, env, os_family, ssh_port, admin_id, max_sessions, new_hostname=None)` — met à jour hostname, IP, env, OS, port, max_sessions. Si l'IP change, ssh-keyscan atomique (#339). Si `new_hostname` est différent : validation RFC 1123, check d'unicité, audit `SERVER_RENAMED {old_hostname, new_hostname}`. Les entrées d'audit historiques restent intactes (#403).
- `_validate_hostname(hostname) -> str` — regex RFC 1123, longueur ≤253, raise UserError sinon (#403).
- `disable_server`, `enable_server` (#88), `delete_server` (#88 — hard delete + cascade + cleanup per-server keypair fichiers)

### Sessions
- `check_session_limit(server_id, hostname, session_count, max_sessions)` — envoie alerte WARNING si session_count > max_sessions, avec anti-spam 24h via audit_log (SESSION_LIMIT_EXCEEDED, #360)

### Audit sshd (#392)
- `audit_server_sshd(hostname, admin_id) -> dict` — récupère IP+port depuis DB, exécute `ssh.audit_sshd_config()`, applique `check_sshd_compliance()`. Lecture seule, pas d'audit_log. Raise NotFoundError(404) si serveur inconnu, UserError(409) si désactivé, UserError(502) si SSH échoue.
- `check_sshd_compliance(parsed: dict) -> dict` — pure function, applique `SSHD_HARDENING_POLICY` à un dict de directives sshd. Retourne `{"checks": [...], "summary": {ok, warning, critical, info, missing}, "overall": ...}`
- `SSHD_HARDENING_POLICY` — 14 directives de durcissement sshd : permitrootlogin (critical), passwordauthentication (critical), permitemptypasswords (critical), kbdinteractiveauthentication (warning), challengeresponseauthentication (warning, optional), hostbasedauthentication (critical), ignorerhosts (critical), x11forwarding (warning), allowtcpforwarding (warning), maxauthtries (warning, ≤3), logingracetime (warning, ≤60), clientaliveinterval (info, >0), loglevel (info, INFO/VERBOSE), usepam (warning)

### Groupes SAM sudo (#383)
- `VALID_SAM_GROUPS = ("sam-operator", "sam-pkg", "sam-root")` — constante partagée validation
- `_get_current_group(unix_user, hostname) -> str | None` — helper interne, retourne le sam_group actif
- `deploy_key(...)` — paramètre `sam_group: str = None` — si fourni, valide + appelle `ssh.grant_group_on_server()` après le déploiement
- `grant_group(unix_user, hostname, group, admin_id)` — vérifie déploiement actif existant, appelle sam-grant-group, met à jour BDD, log GROUP_GRANTED
- `revoke_group(unix_user, hostname, admin_id)` — récupère groupe actuel, appelle sam-revoke-group, nullifie BDD, log GROUP_REVOKED
- `change_group(unix_user, hostname, new_group, admin_id)` — noop si même groupe, révoque ancien puis assigne nouveau, log GROUP_CHANGED

### Administrateurs
- `add_admin(username, email, password, admin_id, role='operator')` — email obligatoire, valide role, hash werkzeug
- `update_admin(username, email, role, admin_id)` — ne peut pas modifier son propre rôle
- `change_password`, `toggle_alerts` (#223), `enable_admin` (#116), `delete_admin` (#116 — vérifie FK)
- `disable_admin` (#116, #259) — vérifie qu'il reste ≥ 1 autre sysadmin actif ; `update_admin` vérifie de même si dégradation de rôle (#259)
- `_validate_password_strength(password)` (#62)

## Matrice RBAC

| Route | sysadmin | operator | viewer |
|-------|----------|----------|--------|
| GET /api/servers, /api/keys, /api/access, /api/admins, /api/audit, /api/system/status, /api/system/config | ✓ | ✓ | ✓ |
| GET /api/servers/\*/collector-key | ✓ | ✓ | ✓ |
| POST /api/servers/\*/rotate-key | ✓ | 403 | 403 |
| POST /api/servers | ✓ | 403 | 403 |
| POST /api/servers/\*/provision | ✓ | 403 | 403 |
| POST /api/servers/\*/sync | ✓ | 403 | 403 |
| PUT/DELETE /api/servers/\*/disable, enable, DELETE | ✓ | 403 | 403 |
| POST /api/servers/\*/scan, /api/system/scan | ✓ | ✓ | 403 |
| GET /api/servers/\*/sessions, /api/servers/\*/sessions/history | ✓ | ✓ | 403 |
| POST /api/servers/\*/sessions/refresh | ✓ | ✓ | 403 |
| GET /api/servers/\*/sshd-audit | ✓ | ✓ | ✓ |
| POST /api/keys/validate, revoke, assign, set-expiry, remove-expiry, bulk-validate, bulk-revoke | ✓ | ✓ | 403 |
| POST /api/access/grant, deploy, lock-user, unlock-user, request, approve, reject, revoke | ✓ | ✓ | 403 |
| POST /api/access/grant-group, revoke-group (sam-operator/sam-pkg) | ✓ | ✓ | 403 |
| PUT /api/access/change-group (sam-operator/sam-pkg) | ✓ | ✓ | 403 |
| POST /api/access/grant-group (sam-root) | ✓ | 403 | 403 |
| POST /api/access/revoke-group (sam-root actuel) | ✓ | 403 | 403 |
| PUT /api/access/change-group (sam-root en entrée ou sortie) | ✓ | 403 | 403 |
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
- Couverture minimale agrégée 80% sur les 9 modules backend (`actions, alerts, collect, db, expire, manage, servers, ssh, web`)
- Planchers par module appliqués par `app/tests/check_coverage_floors.py` (raise OK, lower = changement visible)
- Commande de référence locale :
  ```
  python3 -m pytest tests/ \
    --cov=actions --cov=alerts --cov=collect --cov=db --cov=expire \
    --cov=manage --cov=servers --cov=ssh --cov=web \
    --cov-report=term --cov-report=json:coverage.json --cov-fail-under=80
  python3 tests/check_coverage_floors.py coverage.json
  ```
- pytest doit passer avant tout commit

Fichiers : conftest.py, test_db.py (7), test_servers.py (10), test_ssh.py (70), test_actions.py (186), test_collect.py (35), test_expire.py (16), test_alerts.py (23), test_web.py (178), test_manage.py (46), test_rbac.py (3).

Fixtures obligatoires dans conftest.py : `mock_db`, `mock_ssh_client`, `mock_smtp`, `sample_server`, `sample_key`.

Scénarios critiques à ne jamais casser :
- test_ssh.py : RejectPolicy présent sur chaque connexion, SAM_* sont de type `bytes`
- test_expire.py : expire_keys requiert ip_address dans la requête SQL (#114)
- test_web.py : session expirée → 401, remember_me=true → expires_at dans ~8h
- test_web.py : deploy retourne 400 si hours hors plage (0, -1, 8761) ou non entier

Non testé unitairement : bootstrap.sh, Dockerfile, nginx.conf.http.template, nginx.conf.https.template, provision-host.sh.

## sudoers et provision-host.sh

`/etc/sudoers.d/${COLLECTOR_USER}` (chmod 440) — utilise `install` au lieu de mv+chmod+chown.
Raison : évite ":" dans les args sudoers qui brise visudo sur RHEL/CentOS (#161).
Généré avec printf ligne par ligne — résistant au CRLF introduit par sudo PTY (#159).

```bash
# Invocation provision-host.sh — la pubkey vient désormais de la per-server key
PUB=$(podman exec ssh-access-manager python3 /app/app/manage.py servers show <hostname> --pubkey)
ssh <user>@<ip> "sudo bash -s '$PUB' '${SSH_USER}'" \
    < <(podman exec ssh-access-manager cat /app/provision-host.sh)
```

Actions : crée l'utilisateur collector, déploie la clé publique (append, chown collector — #86), crée sudoers dynamique avec ${COLLECTOR_USER}.

Permissions appliquées (#260) :
- `chmod 700 /home/${COLLECTOR_USER}` — home non listable par les autres utilisateurs
- Scripts SAM déployés avec `-m 750` (root:root) — non lisibles/exécutables par les non-root
- Sudoers hardcode `-m 750` : si cette valeur change dans `ssh.py`, il faut re-provisionner les serveurs

## Audit sshd config (#392)

**ssh.py** : `audit_sshd_config(hostname, ip, port) -> dict[str, str]` — exécute `sudo sshd -T` sur le serveur distant et retourne les directives parsées. Raise SSHSudoError si exit ≠ 0, SSHScriptError si stdout vide.

**actions.py** :
- `SSHD_HARDENING_POLICY` — 14 directives de durcissement sshd : permitrootlogin, passwordauthentication, permitemptypasswords, kbdinteractiveauthentication, challengeresponseauthentication (optional), hostbasedauthentication, ignorerhosts, x11forwarding, allowtcpforwarding, maxauthtries, logingracetime, clientaliveinterval, loglevel, usepam
- `check_sshd_compliance(parsed: dict) -> dict` — pure function, applique la policy à un dict de config sshd. Retourne `{"checks": [...], "summary": {ok, warning, critical, info, missing}, "overall": ...}`
- `audit_server_sshd(hostname, admin_id) -> dict` — lecture seule, pas d'audit_log. Récupère IP+port de la DB, appelle ssh.audit_sshd_config(), applique check_sshd_compliance(). Raise NotFoundError si serveur inconnu, UserError(409) si désactivé, UserError(502) si SSH échoue.

**web.py** : `GET /api/servers/<hostname>/sshd-audit` — require_auth (tous rôles), retourne le résultat de audit_server_sshd(). Pas de contrôle d'accès restreint : lecture seule, information publique pour tous les utilisateurs connectés.
