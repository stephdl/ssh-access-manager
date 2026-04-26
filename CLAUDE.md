# CLAUDE.md — ssh-access-manager

## Contexte

Projet "ssh-access-manager" — outil d'audit et gestion des accès
SSH dans un container Alpine Linux unique.
VAE RNCP41330 "Expert en développement logiciel" Niveau 7 — C.1.6.
Développeur : Stéphane de Labrusse.
Stack habituelle : Python/Bash, Podman, PostgreSQL, Nginx, Alpine,
Vue.js 3.

## État du projet — toutes issues fermées (47/47)

Milestone 1 (Issues 1–4) ✅  
Milestone 2 (Issues 5–13) ✅  
Milestone 3 (Issues 14–21) ✅  
Milestone 4 (Issues 22–24) ✅  
Issues supplémentaires (25, 51–54, 61–62, 70–71, 73–74, 80, 82, 86, 88–89, 108, 110, 112, 114, 116, 119, 127, 129, 133, 137, 139–140, 143, 145–148) ✅

## Stack vérifiée et figée

### Image finale — alpine:3.23.4
- PostgreSQL 18 (apk postgresql18)
- Python 3.12 (apk python3)
- Supervisor (apk supervisor)
- Nginx (apk nginx)
- msmtp (apk msmtp — community)
- openssh-client (apk openssh-client)
- busybox crond (apk busybox-extras)
- wget (apk wget)
- tzdata (apk tzdata)
- Flask (pip)
- click (pip)
- paramiko (pip)
- psycopg2-binary (pip)
- pyyaml (pip)
- werkzeug (pip — pour password_hash)

### Stage build UI — node:24-alpine
- Node.js 24 LTS
- Vue.js 3 (^3.4)
- vue-router (^4.3)
- vue-i18n (^9.14 — 5 langues : EN/FR/ES/IT/DE)
- Vite (bundler)
- Produit /ui/dist/ copié dans /app/static/

## Multi-stage Dockerfile

# STAGE 1 — Build Vue.js
FROM node:24-alpine AS ui-builder
WORKDIR /ui
COPY ui/package*.json .
RUN npm ci
COPY ui/ .
RUN npm run build

# STAGE 2 — Image finale
FROM alpine:3.23.4

RUN apk update && apk add --no-cache \
    postgresql18 \
    postgresql18-client \
    python3 \
    py3-pip \
    py3-setuptools \
    supervisor \
    nginx \
    msmtp \
    openssh-client \
    busybox-extras \
    wget \
    tzdata && \
    pip install --no-cache-dir \
        flask \
        click \
        paramiko \
        psycopg2-binary \
        pyyaml \
        werkzeug

COPY --from=ui-builder /ui/dist /app/static
COPY app/ /app/app/
COPY sql/ /app/sql/
COPY supervisord.conf /etc/supervisord.conf
COPY bootstrap.sh /app/bootstrap.sh
COPY nginx.conf.template /app/nginx.conf.template
COPY msmtp.conf.template /app/msmtp.conf.template
COPY crontab /etc/crontabs/root
COPY provision-host.sh /app/provision-host.sh

RUN chmod +x /app/bootstrap.sh

ENTRYPOINT ["/app/bootstrap.sh"]

## Architecture — container unique

Supervisord orchestre :
- PostgreSQL 18 — stockage persistant
- Nginx — sert /app/static/ + proxy /api/ → Flask (sans Basic Auth)
- Flask — API REST JSON sur 127.0.0.1:5000 (auth par session)
- busybox crond — scan + expiration toutes les X heures

## Volume unique /data

/data/
    ├── keys/
    │   ├── collector_key        ← clé privée ED25519 (chmod 600, chown nobody)
    │   ├── collector_key.pub    ← clé publique à déployer
    │   └── known_hosts          ← créé vide au bootstrap (chmod 644, chown nobody)
    ├── pg/                      ← PGDATA (chown postgres:postgres 700)
    └── config/
        └── servers.yml          ← liste déclarative des serveurs

Note : collector_key et known_hosts sont chown nobody pour que Flask
(user=nobody) puisse les lire/écrire sans élévation.

## Variables d'environnement

# PostgreSQL
POSTGRES_DB=ssh_manager
POSTGRES_USER=ssh_manager
POSTGRES_PASSWORD=changeme

# Nginx
NGINX_PORT=8080

# Flask
FLASK_SECRET_KEY=changeme

# Email smarthost
SMTP_HOST=mail.example.com
SMTP_PORT=587
SMTP_USER=alerts@example.com
SMTP_PASSWORD=changeme
SMTP_FROM=ssh-manager@example.com
SMTP_TO=admin@example.com

# Collector
SSH_USER=audit-collector
EXPIRE_WARN_DAYS=7
EXPIRE_WARN_DAYS_2=2
ADMIN_USERNAME=admin
ADMIN_EMAIL=admin@example.com
ADMIN_PASSWORD=changeme
TZ=Europe/Paris

Note : NGINX_USER/NGINX_PASSWORD supprimés (Basic Auth Nginx remplacé
par authentification Flask session — issue #54).
ADMIN_PASSWORD ajouté pour définir le mot de passe du premier admin
au bootstrap (issue #51).

## bootstrap.sh — ordre strict obligatoire

Détection premier démarrage : absence de /data/pg/PG_VERSION.

Si premier démarrage :
1. mkdir -p /data/keys /data/pg /data/config
2. chown postgres:postgres /data/pg && chmod 700 /data/pg
3. ssh-keygen -t ed25519 -f /data/keys/collector_key \
   -N "" -C "ssh-access-manager@$(hostname)"
4. touch /data/keys/known_hosts && chmod 644 /data/keys/known_hosts
5. chmod 600 /data/keys/collector_key
6. chown nobody /data/keys/collector_key /data/keys/known_hosts
7. Démarrer PostgreSQL temporairement (socket local uniquement)
8. Créer base et utilisateur depuis ENV (deux psql séparés — CREATE
   DATABASE ne peut pas tourner dans une transaction)
9. Appliquer /app/sql/schema.sql
10. Appliquer migrations (sql/migrations/*.sql dans l'ordre)
11. Insérer administrateur initial depuis ENV avec password_hash
    (werkzeug generate_password_hash)
12. Arrêter PostgreSQL temporaire
13. Générer /etc/msmtprc depuis msmtp.conf.template + ENV
14. Générer /etc/nginx/nginx.conf depuis nginx.conf.template + ENV
15. Afficher collector_key.pub dans les logs

Si non premier démarrage :
- Régénérer /etc/nginx/nginx.conf depuis ENV
- Régénérer /etc/msmtprc depuis ENV

Toujours en dernier :
exec /usr/bin/supervisord -c /etc/supervisord.conf

## servers.yml — format

servers:
  - hostname: server-prod-01
    ip: 192.168.1.10
    environment: production
    os_family: rhel
  - hostname: server-staging
    ip: 192.168.1.20
    environment: staging
    os_family: debian

## Les 6 tables PostgreSQL 18

CREATE TABLE servers (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    hostname    VARCHAR(255) NOT NULL UNIQUE,
    ip_address  INET NOT NULL,
    os_family   VARCHAR(50),
    os_version  VARCHAR(50),
    environment VARCHAR(20) CHECK (environment IN
                    ('production','staging','lab')),
    is_active   BOOLEAN DEFAULT true,
    added_at    TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE administrators (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username      VARCHAR(100) NOT NULL UNIQUE,
    email         VARCHAR(255),
    role          VARCHAR(50) DEFAULT 'sysadmin',
    password_hash VARCHAR(255),
    is_active     BOOLEAN DEFAULT true,
    created_at    TIMESTAMPTZ DEFAULT now()
);

-- password_hash ajouté via issue #51

CREATE TABLE ssh_keys (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    fingerprint     VARCHAR(64) NOT NULL UNIQUE,
    key_type        VARCHAR(30) NOT NULL CHECK (key_type IN (
                        'ssh-ed25519',
                        'ssh-rsa',
                        'ecdsa-sha2-nistp256'
                    )),
    key_size_bits   SMALLINT,
    public_key      TEXT NOT NULL,
    comment         VARCHAR(255),
    owner           VARCHAR(255),
    is_compliant    BOOLEAN GENERATED ALWAYS AS (
                        key_type = 'ssh-ed25519' OR
                        (key_type = 'ssh-rsa'
                         AND key_size_bits >= 4096)
                    ) STORED,
    first_seen      TIMESTAMPTZ DEFAULT now(),
    last_seen       TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE key_authorizations (
    key_id                   UUID REFERENCES ssh_keys(id),
    server_id                UUID REFERENCES servers(id),
    authorized_by            UUID REFERENCES administrators(id),
    authorized_at            TIMESTAMPTZ DEFAULT now(),
    expires_at               TIMESTAMPTZ,
    status                   VARCHAR(20) DEFAULT 'PENDING_REVIEW'
                                 CHECK (status IN (
                                     'ACTIVE',
                                     'REVOKED',
                                     'PENDING_REVIEW',
                                     'UNAUTHORIZED',
                                     'EXPIRED'
                                 )),
    revoked_at               TIMESTAMPTZ,
    revoked_by               UUID REFERENCES administrators(id),
    revoked_automatically    BOOLEAN DEFAULT false,
    revocation_justification TEXT,
    PRIMARY KEY (key_id, server_id)
);

CREATE TABLE access_requests (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    requested_by    UUID REFERENCES administrators(id),
    approved_by     UUID REFERENCES administrators(id),
    key_id          UUID REFERENCES ssh_keys(id),
    server_id       UUID REFERENCES servers(id),
    duration_hours  SMALLINT,
    expires_at_requested TIMESTAMPTZ,
    justification   TEXT NOT NULL,
    status          VARCHAR(20) DEFAULT 'PENDING'
                        CHECK (status IN (
                            'PENDING',
                            'APPROVED',
                            'REJECTED',
                            'EXPIRED'
                        )),
    requested_at    TIMESTAMPTZ DEFAULT now(),
    approved_at     TIMESTAMPTZ,
    expires_at      TIMESTAMPTZ
);

CREATE TABLE audit_log (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    action          VARCHAR(50) NOT NULL CHECK (action IN (
                        'KEY_ADDED',
                        'KEY_REVOKED',
                        'KEY_EXPIRED',
                        'EXPIRY_WARNING',
                        'REQUEST_APPROVED',
                        'REQUEST_REJECTED',
                        'ANOMALY_DETECTED',
                        'SCAN_COMPLETED',
                        'SCAN_FAILED',
                        'SCRIPT_DEPLOYED',
                        'SERVER_ADDED',
                        'SERVER_DISABLED',
                        'ADMIN_ADDED',
                        'ADMIN_DISABLED',
                        'ADMIN_ENABLED',
                        'ADMIN_DELETED'
                    )),
    performed_by    UUID REFERENCES administrators(id),
    target_key      UUID REFERENCES ssh_keys(id),
    target_server   UUID REFERENCES servers(id),
    performed_at    TIMESTAMPTZ DEFAULT now(),
    details         JSONB
);

-- ADMIN_ENABLED et ADMIN_DELETED ajoutés via migration 003
-- (sql/migrations/003_admin_enable_delete.sql — issue #116)

## Migrations SQL

sql/migrations/
    003_admin_enable_delete.sql  ← étend le CHECK de audit_log.action
                                    pour ADMIN_ENABLED et ADMIN_DELETED

Bootstrap applique les migrations dans l'ordre lexicographique
après schema.sql au premier démarrage.

## Table settings (issue #133)

CREATE TABLE settings (
    key   VARCHAR(100) PRIMARY KEY,
    value TEXT NOT NULL
);

INSERT INTO settings (key, value) VALUES ('scan_interval_hours', '4');

-- Défaut 4h hardcodé. Modifiable via GET/PUT /api/system/config sans redémarrage.

## Index

CREATE INDEX idx_key_auth_status
    ON key_authorizations(status);
CREATE INDEX idx_key_auth_expires
    ON key_authorizations(expires_at)
    WHERE expires_at IS NOT NULL;
CREATE INDEX idx_audit_log_performed_at
    ON audit_log(performed_at DESC);
CREATE INDEX idx_audit_log_action
    ON audit_log(action, performed_at DESC);
CREATE INDEX idx_ssh_keys_compliant
    ON ssh_keys(is_compliant);
CREATE INDEX idx_ssh_keys_fingerprint
    ON ssh_keys(fingerprint);

## Modules Python partagés

La logique métier est dans actions.py.
web.py (Flask) ET manage.py (CLI) importent actions.py.
Jamais de duplication de logique entre CLI et API.

app/
    ├── db.py          ← connexion + helpers PostgreSQL
    ├── servers.py     ← parsing servers.yml + sync BDD
    │                     + ssh-keyscan known_hosts
    ├── ssh.py         ← connexion paramiko + ensure_scripts
    │                     + revoke_on_server
    ├── actions.py     ← logique métier pure (partagée)
    ├── collect.py     ← orchestration scan complet
    ├── expire.py      ← warn J-7/J-2 + révocation auto
    ├── alerts.py      ← envoi emails via msmtp
    ├── web.py         ← Flask API REST JSON
    └── manage.py      ← CLI click

## Logique métier — fingerprint SHA256

import base64, hashlib

def compute_fingerprint(key_b64):
    raw = base64.b64decode(key_b64)
    digest = hashlib.sha256(raw).digest()
    b64 = base64.b64encode(digest).decode().rstrip('=')
    return f"SHA256:{b64}"

Pour RSA, key_size_bits est calculé en parsant le format wire SSH
(pas une formule approximative) pour que is_compliant soit exact.

## Logique métier — scripts distants

Trois scripts maintenus sur chaque hôte distant.
Versionnés comme constantes Python (bytes) dans ssh.py.
Déployés via SFTP si absents ou si hash SHA256 différent.
Tracés dans audit_log avec action SCRIPT_DEPLOYED.

SAM_COLLECT — /usr/local/bin/sam-collect (root, 755)
Lit toutes les authorized_keys (homes + root) et les affiche.
Format de sortie : user\tkey_type key_b64 [comment]

SAM_REVOKE — /usr/local/bin/sam-revoke <fingerprint_hex> (root, 755)
Révoque une clé par fingerprint SHA256 hex.
Réécriture atomique via mktemp + mv.
Préserve l'ownership du fichier authorized_keys après le mv
(issue #104 — le tmp créé par root changeait le owner).

SAM_ADD — /usr/local/bin/sam-add <unix_user> <pubkey> (root, 755)
Crée l'utilisateur Unix s'il n'existe pas (useradd -m -s /bin/bash).
Crée ~/.ssh/ si absent (chmod 700, chown user:user).
Ajoute la clé publique dans authorized_keys si absente (idempotent).
Fixe les permissions (chmod 600, chown user:user).
Utilisé par deploy_key() dans actions.py (issue #164).

## Logique métier — known_hosts

paramiko.RejectPolicy() — sécurisé, jamais AutoAddPolicy.
servers.py appelle ssh-keyscan si hôte absent de known_hosts :

subprocess.run(['ssh-keyscan', '-H', '-T', '10', ip_address])
→ append dans /data/keys/known_hosts

## Logique métier — connexions SSH

Les connexions SSH utilisent l'ip_address directement (pas le hostname).
Depuis le container, le hostname du serveur distant peut ne pas être
résolvable DNS — l'IP est toujours joignable (issues #80, #84).

known_hosts est indexé par IP (ssh-keyscan -H <ip>).

## Logique métier — expiration

expire.py appelé par cron à chaque cycle :

warn_expiring_keys() :
→ clés ACTIVE avec expires_at dans max(EXPIRE_WARN_DAYS, EXPIRE_WARN_DAYS_2)
→ anti-spam NOT EXISTS audit_log EXPIRY_WARNING sur 24h
→ 1 seul email WARNING groupé par cycle (issue #119)
→ audit_log EXPIRY_WARNING par clé

expire_keys() :
→ clés ACTIVE avec expires_at < NOW()
→ requête SQL doit sélectionner s.ip_address (issue #114)
→ sam-revoke sur serveur distant via IP
→ status=EXPIRED, revoked_automatically=TRUE
→ audit_log KEY_EXPIRED, email INFO

## Les 5 scénarios de révocation / détection

1. Via système (actions.py revoke_key)
   → sam-revoke, revoked_by=admin_id
   → status=REVOKED, audit_log KEY_REVOKED, email INFO
   → fonctionne aussi si status=PENDING_REVIEW (issue #85)

2. Hors système (scan détecte clé ACTIVE disparue)
   → revoked_by=NULL, revoked_automatically=TRUE
   → status=REVOKED, audit_log ANOMALY_DETECTED
   → 1 seul email CRITICAL par scan regroupant toutes les anomalies

3. Clé inconnue (présente serveur, absente BDD)
   → INSERT status=PENDING_REVIEW
   → audit_log ANOMALY_DETECTED
   → 1 seul email CRITICAL par scan regroupant toutes les anomalies

4. Expiration programmée (expires_at < NOW())
   → sam-revoke automatique
   → status=EXPIRED, revoked_automatically=TRUE
   → audit_log KEY_EXPIRED, email INFO

5. Clé révoquée/expirée réapparue (présente serveur, status REVOKED ou EXPIRED en BDD)
   → status=PENDING_REVIEW, audit_log ANOMALY_DETECTED
   → reason: revoked_key_reappeared
   → 1 seul email CRITICAL par scan regroupant toutes les anomalies (issue #123)
   Cas typique : ssh-copy-id d'une clé précédemment révoquée

## Alertes email — niveaux

CRITIQUE (1 seul email par scan — issue #119) :
- Clé inconnue détectée
- Révocation hors système
- Scan échoué (serveur injoignable)

WARNING (1 seul email par cycle expire — issue #119, anti-spam 24h) :
- Clé expire dans EXPIRE_WARN_DAYS jours
- Clé expire dans EXPIRE_WARN_DAYS_2 jours

INFO (log uniquement) :
- KEY_EXPIRED, KEY_REVOKED, SCAN_COMPLETED, SCRIPT_DEPLOYED

## Authentification Flask — sessions (issue #51–54)

Plus de Basic Auth Nginx (supprimé — issue #54).
Authentification gérée par Flask sessions.

POST /api/auth/login — vérifie password_hash (werkzeug check_password_hash)
                       → session[admin_id], session[username]
POST /api/auth/logout — clear session
GET  /api/auth/me    — retourne l'admin courant

Décorateur require_auth sur toutes les routes protégées.
Retourne 401 JSON si session manquante.

Validation robustesse mot de passe (issue #62) :
- 8+ caractères, 1+ majuscule, 1+ minuscule, 1+ chiffre, 1+ spécial
- Appliquée dans add_admin() et change_password()

## Logique métier — actions.py (fonctions complètes)

### Clés SSH
- validate_key(fingerprint, admin_id, db)
- revoke_key(fingerprint, admin_id, reason, db)
  ↳ fonctionne sur ACTIVE et PENDING_REVIEW (issue #85)
- handle_disappeared_key(key_id, server_id, db)    ← scénario 2
- handle_unknown_key(key_type, key_b64, comment, server_id, db)  ← scénario 3
- handle_reappeared_key(key_id, server_id, hostname)             ← scénario 5 (issue #123)
- warn_expiring_key(key_id, server_id, expires_at, db)
- assign_key(fingerprint, owner_name, db)
- set_key_expiry(fingerprint, expires_at, db)
- remove_key_expiry(fingerprint, db)

### Accès temporaires
- grant_access(key_fp, hostname, expires_at, justification, admin_id, db)
- approve_request(request_id, admin_id, db)
- reject_request(request_id, admin_id, db)
- revoke_request(request_id, admin_id, db)
- deploy_key(public_key, unix_user, hostname, expires_at, justification, admin_id)
  ↳ parse + fingerprint, INSERT ssh_keys, sam-add sur serveur, key_authorization ACTIVE (issue #164)

### Serveurs
- add_server(hostname, ip, env, os_family, db)
  ↳ appelle add_to_known_hosts(ip) avant INSERT (issue #70)
- disable_server(hostname, db)
- enable_server(hostname, db)    ← issue #88
- delete_server(hostname, db)    ← issue #88 — suppression hard + cascade

### Administrateurs
- add_admin(username, email, password, db)
  ↳ valide robustesse mot de passe, hash avec werkzeug
- change_password(username, new_password, db)   ← issue #61
- disable_admin(username, db)
- enable_admin(username, db)     ← issue #116
- delete_admin(username, db)     ← issue #116 — vérifie FK avant DELETE
- _validate_password_strength(password)         ← issue #62

## Stratégie de tests

### Tests unitaires — pytest

app/tests/
    conftest.py        ← fixtures partagées (DB, SSH mock, msmtp mock)
    test_db.py         ← helpers connexion, transactions (7 tests)
    test_servers.py    ← parsing servers.yml, sync BDD (6 tests)
    test_ssh.py        ← mock paramiko, RejectPolicy, ensure_scripts (11 tests)
    test_actions.py    ← toutes les fonctions actions.py (52 tests)
    test_collect.py    ← mock scan complet, 4 scénarios détection (18 tests)
    test_expire.py     ← warn J-7/J-2, anti-spam 24h, expiration auto (9 tests)
    test_alerts.py     ← mock msmtp, niveaux CRITIQUE/WARNING/INFO (12 tests)
    test_web.py        ← toutes les routes Flask, codes HTTP attendus (42+ tests)
    test_manage.py     ← toutes les commandes CLI click (40+ tests)

Règles absolues :
- Mock SSH obligatoire via unittest.mock — jamais de vrai serveur
- Mock PostgreSQL via fixtures pytest — jamais de vraie BDD en test
- Mock msmtp via unittest.mock — jamais d'email réel en test
- Un test = un comportement précis
- Nommage : test_<module>_<scenario>_<expected>
  ex: test_actions_revoke_key_hors_systeme_sends_critical_alert
- Couverture minimale actions.py : 80%
- pytest doit passer avant tout commit

### conftest.py — fixtures obligatoires

@pytest.fixture
def mock_db():
    """Retourne un mock de connexion psycopg2"""

@pytest.fixture
def mock_ssh_client():
    """Retourne un mock paramiko.SSHClient avec RejectPolicy"""

@pytest.fixture
def mock_smtp():
    """Retourne un mock subprocess pour msmtp"""

@pytest.fixture
def sample_server():
    """Retourne un serveur de test standard"""

@pytest.fixture
def sample_key():
    """Retourne une clé SSH ED25519 de test avec fingerprint calculé"""

### Scénarios critiques couverts

test_actions.py :
- revoke_key : scénario 1 (via système, revoked_by=admin_id)
- revoke_key : fonctionne sur PENDING_REVIEW (issue #85)
- collect : scénario 2 (hors système, revoked_automatically=TRUE)
- collect : scénario 3 (clé inconnue → PENDING_REVIEW)
- Anti-spam EXPIRY_WARNING : second appel dans 24h ne renvoie pas d'email
- enable_server, delete_server, enable_admin, delete_admin
- _validate_password_strength : valide et invalide

test_expire.py :
- expire : scénario 4 (expiration programmée → sam-revoke)
- expire_keys requiert ip_address dans la requête SQL (issue #114)

test_ssh.py :
- RejectPolicy présent sur chaque connexion
- ensure_scripts déploie si hash SHA256 différent
- ensure_scripts ne redéploie pas si hash identique
- revoke_on_server appelle sam-revoke avec bon fingerprint
- SAM_REVOKE et SAM_COLLECT sont de type bytes

test_web.py :
- GET /api/keys retourne 200 + liste JSON
- POST /api/keys/revoke/<fp> retourne 200 si admin authentifié
- POST /api/keys/revoke/<fp> retourne 401 si non authentifié
- POST /api/access/grant retourne 201 avec expires_at calculé
- POST /api/auth/login retourne 200 + session
- PUT /api/servers/<hostname>/enable retourne 200
- DELETE /api/servers/<hostname> retourne 200

### Tests frontend — Vitest

ui/tests/
    KeyActions.spec.js    ← modal confirmation révocation (17 tests)
    ExpiryPicker.spec.js  ← modes exclusifs heures/date (11 tests)
    ServerTable.spec.js   ← filtres hostname/IP/env, badges statut (15 tests)
    KeyTable.spec.js      ← boutons par statut, owner, expires_at (18+ tests)
    Admins.spec.js        ← modals enable/delete, garde-fous (15 tests)
    Settings.spec.js      ← chargement, sauvegarde, validation, erreurs (7 tests)

### Ce qui n'est PAS testé unitairement

- bootstrap.sh → testé manuellement au premier démarrage
- Dockerfile → validé par docker build
- nginx.conf.template → validé par nginx -t
- provision-host.sh → testé manuellement sur VM de lab

### Dépendances de test

requirements-test.txt :
flask
click
paramiko
psycopg2-binary
pyyaml
werkzeug
pytest>=8.0
pytest-cov
pytest-mock
freezegun           ← pour mocker datetime dans expire.py

## CI/CD — GitHub Actions

.github/workflows/
    ci.yml              ← PR : pytest ≥ 80% + vitest + prettier + commitlint
    pr-title.yml        ← PR : validation titre (Conventional Commits, script shell)
    build-pr.yml        ← PR : build + push image pr-{N} + scan Trivy CVE (issue #147)
    build-main.yml      ← merge main : build + push image :main sur GHCR
    publish-release.yml ← tag git : build + push :vX.Y.Z (+ :latest si stable)
    cleanup-pr.yml      ← fermeture PR : suppression image pr-{N} sur GHCR
    codeql.yml          ← PR + main + hebdo lundi : analyse statique sécurité Python (issue #146)

Protection branche main :
    PR obligatoire, 5 checks requis, force push bloqué, enforce_admins=true

## Renovate (issue #148)

renovate.json à la racine du projet.
Renovate GitHub App activé sur le compte.

Périmètre :
- npm (ui/package.json)
- pip (requirements-test.txt)
- Dockerfile (FROM lines)

Comportement :
- Planning : lundi avant 9h, TZ Europe/Paris
- Label automatique : dependencies
- npm patch : automerge si CI vert
- npm minor/major : PR manuelle
- pip + Docker : PR groupées, merge manuel

## Formatage — Prettier (issue #139)

Configuration : `.prettierrc` à la racine du projet.
Règles : semi=false, singleQuote=true, trailingComma=es5, printWidth=100.
Ignorés : ui/dist/, ui/node_modules/, *.lock

Commandes UI :
    npm run format:check   ← vérifie sans modifier (CI)
    npm run format:write   ← formate en place (dev local)

## Convention commits — Conventional Commits (issue #140)

Format obligatoire : `type: description courte`
Types valides : feat, fix, docs, style, refactor, test, ci, chore, perf, build, revert

Deux checks CI indépendants :
- `commitlint` (ci.yml) — chaque message de commit de la PR via wagoid/commitlint-github-action@v6
- `pr-title.yml` — titre de la PR via grep -P shell (sans dépendance Node.js)

## Commandes — inventaire complet

### Serveurs
servers list
servers add --hostname HOST --ip IP --env ENV --os OS
servers disable <hostname>
servers enable <hostname>
servers show <hostname>
servers scan [--server HOSTNAME]

### Clés SSH
keys list [--status STATUS] [--server HOSTNAME]
keys show <fingerprint>
keys validate <fingerprint>
keys revoke <fingerprint> --reason TEXT
keys assign <fingerprint> --owner USERNAME
keys set-expiry <fingerprint> --hours N
keys set-expiry <fingerprint> --date YYYY-MM-DD HH:MM
keys remove-expiry <fingerprint>
keys search <query>

### Accès temporaires
access list [--status STATUS]
access show <id>
access grant --key FP --server HOST --hours N --reason TEXT
access grant --key FP --server HOST --date DATE --reason TEXT
access request --key FP --server HOST --hours N --reason TEXT
access approve <id>
access reject <id>
access revoke <id>

### Administrateurs
admin list
admin add --username USER --email EMAIL --password PASSWORD
admin disable <username>
admin enable <username>
admin delete <username>
admin change-password <username>

### Audit
audit list [--server HOST] [--action ACTION] [--since DATE]

### Système
system status
system report

## API REST Flask — routes

Toutes les routes retournent JSON.
Préfixe /api/ pour toutes les routes.

Note : les fingerprints SHA256 contiennent "/" (ex: SHA256:abc/def).
Flask <string:fp> rejette les slashes. Les routes clés ont été
restructurées en /api/keys/<action>/<fingerprint> pour éviter
les 404 (issues #68, #69).

### Authentification
POST /api/auth/login
POST /api/auth/logout
GET  /api/auth/me

### Serveurs
GET    /api/servers
GET    /api/servers/<hostname>
POST   /api/servers
PUT    /api/servers/<hostname>/disable
PUT    /api/servers/<hostname>/enable
DELETE /api/servers/<hostname>
POST   /api/servers/<hostname>/scan

### Clés SSH
GET  /api/keys
GET  /api/keys/get/<fingerprint>
GET  /api/keys/search?q=<query>
POST /api/keys/validate/<fingerprint>
POST /api/keys/revoke/<fingerprint>
POST /api/keys/assign/<fingerprint>
POST /api/keys/set-expiry/<fingerprint>
POST /api/keys/remove-expiry/<fingerprint>

### Accès temporaires
GET  /api/access
GET  /api/access/<id>
POST /api/access/grant
POST /api/access/request
POST /api/access/deploy
POST /api/access/<id>/approve
POST /api/access/<id>/reject
POST /api/access/<id>/revoke

### Administrateurs
GET    /api/admins
GET    /api/admins/me
POST   /api/admins
PUT    /api/admins/<username>/disable
PUT    /api/admins/<username>/enable
DELETE /api/admins/<username>
PUT    /api/admins/<username>/password

### Audit
GET /api/audit?server=&action=&since=

### Système
GET  /api/system/status
POST /api/system/scan
GET  /api/system/collector-key
GET  /api/system/config
PUT  /api/system/config

## Interface Vue.js 3 — vues

ui/src/views/
    Login.vue           ← page de connexion (issue #53)
    Dashboard.vue       ← tableau serveurs + recherche + compteurs
                          + modal ajout serveur (issue #71)
                          + affichage clé collecteur (issue #74)
    ServerDetail.vue    ← détail serveur + clés + actions
                          + boutons désactiver/réactiver/supprimer (issue #89)
                          + bandeau rouge si serveur désactivé (issue #91)
    Anomalies.vue       ← toutes anomalies actives
    AccessRequests.vue  ← déploiement de clé SSH (formulaire DeployKeyForm uniquement)
    Audit.vue           ← historique filtrable
    Admins.vue          ← gestion administrateurs
                          + modals enable/delete + garde-fou self (issue #116)
                          + modal changement mot de passe (issue #61)
                          + confirmation mot de passe + bouton œil (issues #60, #66)
    Settings.vue        ← configuration système (intervalle de scan)
                          + GET/PUT /api/system/config (issue #133)

ui/src/components/
    ServerTable.vue     ← tableau serveurs avec recherche
                          + ligne grisée + badge rouge si désactivé (issue #91)
    KeyTable.vue        ← tableau clés avec actions + tooltip non-conformité (issue #99)
                          + bouton Illimité (remove-expiry) (issue #93)
    KeyActions.vue      ← boutons valider/révoquer/expiry
    ExpiryPicker.vue    ← datepicker durée ou date précise

ui/src/
    i18n.js             ← configuration vue-i18n v9 (issue #98)
    composables/
        useAuth.js      ← composable authentification session
    locales/
        en.json         ← traductions anglais
        fr.json         ← traductions français
        es.json         ← traductions espagnol
        it.json         ← traductions italien
        de.json         ← traductions allemand

Toute nouvelle feature UI doit avoir ses clés dans les 5 fichiers JSON.
Détection automatique de la langue du navigateur.

## Règles UI transversales

Boutons désactivés (issue #107) :
- Règle CSS globale button:disabled → opacity 45%, cursor not-allowed, grayscale

Indicateurs visuels serveurs désactivés (issue #91) :
- ServerTable : ligne grisée + badge rouge "Désactivé"
- ServerDetail : bandeau rouge en haut de page si is_active = false

Internationalisation (issue #98) :
- Toute clé de traduction ajoutée dans les 5 fichiers locales/
- Détection automatique de la langue du navigateur au démarrage

## sudoers sur chaque hôte distant

# /etc/sudoers.d/audit-collector (chmod 440)
audit-collector ALL=(root) NOPASSWD: /usr/local/bin/sam-collect
audit-collector ALL=(root) NOPASSWD: /usr/local/bin/sam-revoke
audit-collector ALL=(root) NOPASSWD: /usr/local/bin/sam-add
audit-collector ALL=(root) NOPASSWD: /usr/bin/install -m 755 -o root -g root /home/audit-collector/sam-collect /usr/local/bin/sam-collect
audit-collector ALL=(root) NOPASSWD: /usr/bin/install -m 755 -o root -g root /home/audit-collector/sam-revoke /usr/local/bin/sam-revoke
audit-collector ALL=(root) NOPASSWD: /usr/bin/install -m 755 -o root -g root /home/audit-collector/sam-add /usr/local/bin/sam-add

# Note : install remplace mv+chmod+chown (3 appels) — évite le ":" dans
# les restrictions d'arguments sudoers qui cause des erreurs visudo sur
# certaines versions (RHEL/CentOS).
# sam-add sans restriction d'arguments : la pubkey et le username sont variables
# (impossible à restreindre dans sudoers). La sécurité repose sur le contenu
# du script, déployé et vérifié par hash SHA256 par le container SAM.

## provision-host.sh

Invocation depuis la machine hébergeant le container (<user> = root ou admin avec sudo ALL) :
ssh <user>@<ip> "sudo bash -s '$(podman exec ssh-access-manager cat /data/keys/collector_key.pub)'" \
    < <(podman exec ssh-access-manager cat /app/provision-host.sh)

Actions :
1. useradd -r -m -s /bin/bash audit-collector (réutilise si existe déjà)
2. Créer /home/audit-collector/.ssh (chmod 700)
3. Déployer clé publique dans authorized_keys en mode append (>>)
   chown audit-collector:audit-collector (fix issue #86 — pas root:root)
4. Créer /etc/sudoers.d/audit-collector (chmod 440)
   Utilise printf ligne par ligne — résistant au CRLF introduit par sudo PTY (fix issue #159)
   Règles install au lieu de mv+chown+chmod — évite le ":" dans les args sudoers (fix issue #161)

## Nginx

location /api/ → proxy_pass http://127.0.0.1:5000
location /     → root /app/static, try_files $uri /index.html
Pas de Basic Auth (supprimé — issue #54).
L'authentification est entièrement gérée par Flask sessions.

## supervisord.conf

[supervisord]
nodaemon=true
logfile=/dev/stdout
logfile_maxbytes=0
user=root

[program:postgresql]
command=postgres -D /data/pg
user=postgres
autorestart=true
priority=1
stdout_logfile=/dev/stdout
stdout_logfile_maxbytes=0
stderr_logfile=/dev/stderr
stderr_logfile_maxbytes=0

[program:flask]
command=python3 /app/app/web.py
user=nobody
autorestart=true
priority=2
stdout_logfile=/dev/stdout
stdout_logfile_maxbytes=0

[program:nginx]
command=nginx -g "daemon off;"
autorestart=true
priority=3
stdout_logfile=/dev/stdout
stdout_logfile_maxbytes=0

[program:crond]
command=crond -f -l 8
autorestart=true
priority=4

## Structure fichiers complète

ssh-access-manager/
    ├── CLAUDE.md
    ├── DESIGN.md               ← document VAE C.1.6 (931 lignes)
    ├── README.md               ← guide installation et workflows
    ├── Dockerfile
    ├── docker-compose.yml
    ├── .env.example
    ├── requirements-test.txt
    ├── renovate.json           ← config Renovate (npm + pip + Docker)
    ├── supervisord.conf
    ├── bootstrap.sh
    ├── crontab
    ├── nginx.conf.template
    ├── msmtp.conf.template
    ├── provision-host.sh
    ├── .github/
    │   └── workflows/
    │       ├── ci.yml              ← pytest + vitest + prettier + commitlint
    │       ├── pr-title.yml        ← validation titre PR (shell grep -P)
    │       ├── build-pr.yml        ← build + push image Docker GHCR + Trivy
    │       ├── build-main.yml      ← build + push :main sur GHCR
    │       ├── publish-release.yml ← build + push :vX.Y.Z (+ :latest)
    │       ├── cleanup-pr.yml      ← suppression image pr-{N}
    │       └── codeql.yml          ← analyse statique sécurité Python
    ├── docs/
    │   └── erd.md              ← diagramme ERD Mermaid 6 tables
    ├── sql/
    │   ├── schema.sql
    │   └── migrations/
    │       └── 003_admin_enable_delete.sql
    ├── app/
    │   ├── db.py
    │   ├── servers.py
    │   ├── ssh.py
    │   ├── actions.py
    │   ├── collect.py
    │   ├── expire.py
    │   ├── alerts.py
    │   ├── web.py
    │   ├── manage.py
    │   └── tests/
    │       ├── conftest.py
    │       ├── test_db.py
    │       ├── test_servers.py
    │       ├── test_ssh.py
    │       ├── test_actions.py
    │       ├── test_collect.py
    │       ├── test_expire.py
    │       ├── test_alerts.py
    │       ├── test_web.py
    │       └── test_manage.py
    └── ui/
        ├── package.json
        ├── vite.config.js
        ├── index.html
        ├── tests/
        │   ├── KeyActions.spec.js
        │   ├── ExpiryPicker.spec.js
        │   ├── ServerTable.spec.js
        │   ├── KeyTable.spec.js
        │   ├── Admins.spec.js
        │   └── Settings.spec.js
        └── src/
            ├── App.vue
            ├── main.js
            ├── i18n.js
            ├── router/
            │   └── index.js
            ├── composables/
            │   └── useAuth.js
            ├── locales/
            │   ├── en.json
            │   ├── fr.json
            │   ├── es.json
            │   ├── it.json
            │   └── de.json
            ├── views/
            │   ├── Login.vue
            │   ├── Dashboard.vue
            │   ├── ServerDetail.vue
            │   ├── Anomalies.vue
            │   ├── AccessRequests.vue
            │   ├── Audit.vue
            │   ├── Admins.vue
    │   └── Settings.vue
            └── components/
                ├── ServerTable.vue
                ├── KeyTable.vue
                ├── KeyActions.vue
                └── ExpiryPicker.vue
