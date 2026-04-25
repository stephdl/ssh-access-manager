# CLAUDE.md — ssh-access-manager

## Contexte

Projet "ssh-access-manager" — outil d'audit et gestion des accès
SSH dans un container Alpine Linux unique.
VAE RNCP41330 "Expert en développement logiciel" Niveau 7 — C.1.6.
Développeur : Stéphane de Labrusse.
Stack habituelle : Python/Bash, Podman, PostgreSQL, Nginx, Alpine,
Vue.js 3.

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

### Stage build UI — node:22-alpine
- Node.js 22 LTS
- Vue.js 3
- Vite (bundler)
- Produit /ui/dist/ copié dans /app/static/

## Multi-stage Dockerfile

# STAGE 1 — Build Vue.js
FROM node:22-alpine AS ui-builder
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
        pyyaml

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
- Nginx — sert /app/static/ + proxy /api/ → Flask
- Flask — API REST JSON sur 127.0.0.1:5000
- busybox crond — scan + expiration toutes les X heures

## Volume unique /data

/data/
    ├── keys/
    │   ├── collector_key        ← clé privée ED25519 (chmod 600)
    │   ├── collector_key.pub    ← clé publique à déployer
    │   └── known_hosts          ← créé vide au bootstrap (chmod 600)
    ├── pg/                      ← PGDATA (chown postgres:postgres 700)
    └── config/
        └── servers.yml          ← liste déclarative des serveurs

## Variables d'environnement

# PostgreSQL
POSTGRES_DB=ssh_manager
POSTGRES_USER=ssh_manager
POSTGRES_PASSWORD=changeme

# Nginx
NGINX_PORT=8080
NGINX_USER=admin
NGINX_PASSWORD=changeme

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
SCAN_INTERVAL_HOURS=4
EXPIRE_WARN_DAYS=7
EXPIRE_WARN_DAYS_2=2
ADMIN_USERNAME=admin
ADMIN_EMAIL=admin@example.com
TZ=Europe/Paris

## bootstrap.sh — ordre strict obligatoire

Détection premier démarrage : absence de /data/pg/PG_VERSION.

Si premier démarrage :
1. mkdir -p /data/keys /data/pg /data/config
2. chown postgres:postgres /data/pg && chmod 700 /data/pg
3. ssh-keygen -t ed25519 -f /data/keys/collector_key \
   -N "" -C "ssh-access-manager@$(hostname)"
4. touch /data/keys/known_hosts && chmod 600 /data/keys/known_hosts
5. chmod 600 /data/keys/collector_key
6. Démarrer PostgreSQL temporairement (socket local uniquement)
7. Créer base et utilisateur depuis ENV
8. Appliquer /app/sql/schema.sql
9. Insérer administrateur initial depuis ENV
10. Arrêter PostgreSQL temporaire
11. Générer /etc/msmtprc depuis msmtp.conf.template + ENV
12. Générer /etc/nginx/nginx.conf depuis nginx.conf.template + ENV
13. Afficher collector_key.pub dans les logs

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
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username    VARCHAR(100) NOT NULL UNIQUE,
    email       VARCHAR(255),
    role        VARCHAR(50) DEFAULT 'sysadmin',
    is_active   BOOLEAN DEFAULT true,
    created_at  TIMESTAMPTZ DEFAULT now()
);

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
    owner_id        UUID REFERENCES administrators(id),
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
                        'ADMIN_DISABLED'
                    )),
    performed_by    UUID REFERENCES administrators(id),
    target_key      UUID REFERENCES ssh_keys(id),
    target_server   UUID REFERENCES servers(id),
    performed_at    TIMESTAMPTZ DEFAULT now(),
    details         JSONB
);

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

## Logique métier — scripts distants

Deux scripts maintenus sur chaque hôte distant.
Versionnés comme constantes Python dans ssh.py.
Déployés via SFTP si absents ou si hash SHA256 différent.
Tracés dans audit_log avec action SCRIPT_DEPLOYED.

SAM_COLLECT — /usr/local/bin/sam-collect (root, 755)
Lit toutes les authorized_keys (homes + root) et les affiche.

SAM_REVOKE — /usr/local/bin/sam-revoke <fingerprint_hex> (root, 755)
Révoque une clé par fingerprint SHA256 hex.
Réécriture atomique via mktemp + mv.

## Logique métier — known_hosts

paramiko.RejectPolicy() — sécurisé, jamais AutoAddPolicy.
servers.py appelle ssh-keyscan si hôte absent de known_hosts :

subprocess.run(['ssh-keyscan', '-H', '-T', '10', hostname])
→ append dans /data/keys/known_hosts

## Logique métier — expiration

expire.py appelé par cron à chaque cycle :

warn_expiring_keys() :
→ clés ACTIVE avec expires_at dans EXPIRE_WARN_DAYS jours
→ anti-spam NOT EXISTS audit_log EXPIRY_WARNING sur 24h
→ email WARNING + audit_log EXPIRY_WARNING

expire_keys() :
→ clés ACTIVE avec expires_at < NOW()
→ sam-revoke sur serveur distant
→ status=EXPIRED, revoked_automatically=TRUE
→ audit_log KEY_EXPIRED, email INFO

## Les 4 scénarios de révocation

1. Via système (actions.py revoke_key)
   → sam-revoke, revoked_by=admin_id
   → status=REVOKED, audit_log KEY_REVOKED, email INFO

2. Hors système (scan détecte clé ACTIVE disparue)
   → revoked_by=NULL, revoked_automatically=TRUE
   → status=REVOKED, audit_log ANOMALY_DETECTED
   → EMAIL CRITIQUE immédiat

3. Clé inconnue (présente serveur, absente BDD)
   → INSERT status=PENDING_REVIEW
   → audit_log ANOMALY_DETECTED
   → EMAIL CRITIQUE immédiat

4. Expiration programmée (expires_at < NOW())
   → sam-revoke automatique
   → status=EXPIRED, revoked_automatically=TRUE
   → audit_log KEY_EXPIRED, email INFO

## Alertes email — niveaux

CRITIQUE (email immédiat) :
- Clé inconnue détectée
- Révocation hors système
- Scan échoué (serveur injoignable)

WARNING (email immédiat, anti-spam 24h) :
- Clé expire dans EXPIRE_WARN_DAYS jours
- Clé expire dans EXPIRE_WARN_DAYS_2 jours

INFO (log uniquement) :
- KEY_EXPIRED, KEY_REVOKED, SCAN_COMPLETED, SCRIPT_DEPLOYED

## Stratégie de tests

### Tests unitaires — pytest

app/tests/
    conftest.py        ← fixtures partagées (DB, SSH mock, msmtp mock)
    test_db.py         ← helpers connexion, transactions
    test_servers.py    ← parsing servers.yml, sync BDD
    test_ssh.py        ← mock paramiko, RejectPolicy, ensure_scripts
    test_actions.py    ← toutes les fonctions actions.py
    test_collect.py    ← mock scan complet, 4 scénarios détection
    test_expire.py     ← warn J-7/J-2, anti-spam 24h, expiration auto
    test_alerts.py     ← mock msmtp, niveaux CRITIQUE/WARNING/INFO
    test_web.py        ← toutes les routes Flask, codes HTTP attendus
    test_manage.py     ← toutes les commandes CLI click

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

### Scénarios critiques à couvrir obligatoirement

test_actions.py :
- revoke_key : scénario 1 (via système, revoked_by=admin_id)
- collect : scénario 2 (hors système, revoked_automatically=TRUE)
- collect : scénario 3 (clé inconnue → PENDING_REVIEW)
- expire : scénario 4 (expiration programmée → sam-revoke)
- Anti-spam EXPIRY_WARNING : second appel dans 24h ne renvoie pas d'email

test_ssh.py :
- RejectPolicy présent sur chaque connexion
- ensure_scripts déploie si hash SHA256 différent
- ensure_scripts ne redéploie pas si hash identique
- revoke_on_server appelle sam-revoke avec bon fingerprint

test_web.py :
- GET /api/keys retourne 200 + liste JSON
- POST /api/keys/<fp>/revoke retourne 200 si admin authentifié
- POST /api/keys/<fp>/revoke retourne 401 si non authentifié
- POST /api/access/grant retourne 201 avec expires_at calculé

### Tests frontend — Vitest

ui/tests/
    KeyActions.spec.js   ← modal confirmation révocation
    AccessForm.spec.js   ← validation durée OU date, pas les deux
    ExpiryPicker.spec.js ← modes exclusifs heures/date

### Ce qui n'est PAS testé unitairement

- bootstrap.sh → testé manuellement au premier démarrage
- Dockerfile → validé par docker build
- nginx.conf.template → validé par nginx -t
- provision-host.sh → testé manuellement sur VM de lab

### Dépendances de test à ajouter

requirements-test.txt :
pytest>=8.0
pytest-cov
pytest-mock
freezegun           ← pour mocker datetime dans expire.py

## Commandes — inventaire complet

### Serveurs
servers list
servers add --hostname HOST --ip IP --env ENV --os OS
servers disable <hostname>
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
admin add --username USER --email EMAIL
admin disable <username>

### Audit
audit list [--server HOST] [--action ACTION] [--since DATE]

### Système
system status
system report

## API REST Flask — routes

Toutes les routes retournent JSON.
Préfixe /api/ pour toutes les routes.

GET  /api/servers
GET  /api/servers/<hostname>
POST /api/servers
PUT  /api/servers/<hostname>/disable
POST /api/servers/<hostname>/scan

GET  /api/keys
GET  /api/keys/<fingerprint>
POST /api/keys/<fingerprint>/validate
POST /api/keys/<fingerprint>/revoke
POST /api/keys/<fingerprint>/assign
POST /api/keys/<fingerprint>/set-expiry
POST /api/keys/<fingerprint>/remove-expiry
GET  /api/keys/search?q=<query>

GET  /api/access
GET  /api/access/<id>
POST /api/access/grant
POST /api/access/request
POST /api/access/<id>/approve
POST /api/access/<id>/reject
POST /api/access/<id>/revoke

GET  /api/admins
POST /api/admins
PUT  /api/admins/<username>/disable

GET  /api/audit?server=&action=&since=

GET  /api/system/status
POST /api/system/scan

## Interface Vue.js 3 — vues

ui/src/views/
    Dashboard.vue       ← tableau serveurs + recherche + compteurs
    ServerDetail.vue    ← détail serveur + clés + actions
    Anomalies.vue       ← toutes anomalies actives
    AccessRequests.vue  ← accès temporaires + formulaire
    Audit.vue           ← historique filtrable
    Admins.vue          ← gestion administrateurs

ui/src/components/
    ServerTable.vue     ← tableau serveurs avec recherche
    KeyTable.vue        ← tableau clés avec actions
    KeyActions.vue      ← boutons valider/révoquer/expiry
    AccessForm.vue      ← formulaire accès temporaire
    ExpiryPicker.vue    ← datepicker durée ou date précise
    StatusBadge.vue     ← badge coloré statut

## sudoers sur chaque hôte distant

# /etc/sudoers.d/audit-collector (chmod 440)
audit-collector ALL=(root) NOPASSWD: /usr/local/bin/sam-collect
audit-collector ALL=(root) NOPASSWD: /usr/local/bin/sam-revoke
audit-collector ALL=(root) NOPASSWD: /bin/mv /tmp/sam-* /usr/local/bin/
audit-collector ALL=(root) NOPASSWD: /bin/chmod 755 /usr/local/bin/sam-collect
audit-collector ALL=(root) NOPASSWD: /bin/chmod 755 /usr/local/bin/sam-revoke
audit-collector ALL=(root) NOPASSWD: /bin/chown root:root /usr/local/bin/sam-collect
audit-collector ALL=(root) NOPASSWD: /bin/chown root:root /usr/local/bin/sam-revoke

## provision-host.sh

Usage : bash provision-host.sh "<contenu collector_key.pub>"
Actions :
1. useradd -r -m -s /bin/bash audit-collector
2. Créer /home/audit-collector/.ssh (chmod 700)
3. Déployer clé publique dans authorized_keys (chmod 600)
4. Créer /etc/sudoers.d/audit-collector (chmod 440)

## Nginx

location /api/ → proxy_pass http://127.0.0.1:5000
location /     → root /app/static, try_files $uri /index.html
Basic auth sur toutes les routes.

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
    ├── Dockerfile
    ├── docker-compose.yml
    ├── .env.example
    ├── supervisord.conf
    ├── bootstrap.sh
    ├── crontab
    ├── nginx.conf.template
    ├── msmtp.conf.template
    ├── provision-host.sh
    ├── sql/
    │   └── schema.sql
    ├── app/
    │   ├── db.py
    │   ├── servers.py
    │   ├── ssh.py
    │   ├── actions.py
    │   ├── collect.py
    │   ├── expire.py
    │   ├── alerts.py
    │   ├── web.py
    │   └── manage.py
    └── ui/
        ├── package.json
        ├── vite.config.js
        ├── index.html
        └── src/
            ├── App.vue
            ├── main.js
            ├── router/
            │   └── index.js
            ├── views/
            │   ├── Dashboard.vue
            │   ├── ServerDetail.vue
            │   ├── Anomalies.vue
            │   ├── AccessRequests.vue
            │   ├── Audit.vue
            │   └── Admins.vue
            └── components/
                ├── ServerTable.vue
                ├── KeyTable.vue
                ├── KeyActions.vue
                ├── AccessForm.vue
                ├── ExpiryPicker.vue
                └── StatusBadge.vue

## Tâches — GitHub Issues à créer

### MILESTONE 1 — Infrastructure

ISSUE 1 — [INFRA] Schema PostgreSQL
Fichier : sql/schema.sql
- 6 tables avec contraintes et CHECK
- Colonnes GENERATED (is_compliant)
- Index complets
- Commentaires SQL sur chaque table et colonne
Labels : infrastructure, database

ISSUE 2 — [INFRA] Dockerfile multi-stage
Fichier : Dockerfile
- Stage 1 : node:22-alpine → build Vue.js
- Stage 2 : alpine:3.23.4 → image finale
- Copie dist/ depuis stage 1
Labels : infrastructure, docker

ISSUE 3 — [INFRA] supervisord + bootstrap
Fichiers : supervisord.conf, bootstrap.sh
- Ordre strict bootstrap (chown postgres en premier)
- Détection premier démarrage via PG_VERSION
- Génération nginx.conf et msmtprc depuis ENV
- Affichage clé publique dans logs
Labels : infrastructure, docker

ISSUE 4 — [INFRA] docker-compose + configuration
Fichiers : docker-compose.yml, .env.example,
           nginx.conf.template, msmtp.conf.template,
           crontab, provision-host.sh
Labels : infrastructure, docker

### MILESTONE 2 — Backend Python

ISSUE 5 — [BACKEND] db.py — connexion PostgreSQL
Fichier : app/db.py
- Pool de connexions
- Helpers execute / query / query_one
- Gestion des transactions
Labels : backend, database

ISSUE 6 — [BACKEND] servers.py — gestion serveurs
Fichier : app/servers.py
- Parsing servers.yml avec pyyaml
- Sync BDD (INSERT ON CONFLICT DO UPDATE)
- ssh-keyscan → known_hosts si hôte absent
Labels : backend

ISSUE 7 — [BACKEND] ssh.py — opérations SSH
Fichier : app/ssh.py
- Connexion paramiko avec RejectPolicy
- ensure_scripts() : SFTP + hash SHA256 + deploy
- revoke_on_server() : sam-revoke via SSH
- Constantes SAM_COLLECT et SAM_REVOKE
Labels : backend, ssh

ISSUE 8 — [BACKEND] actions.py — logique métier
Fichier : app/actions.py
Toutes les fonctions partagées entre CLI et API :
- validate_key(fingerprint, admin_id, db)
- revoke_key(fingerprint, admin_id, reason, db)
- assign_key(fingerprint, owner_username, db)
- set_key_expiry(fingerprint, expires_at, db)
- remove_key_expiry(fingerprint, db)
- grant_access(key_fp, hostname, expires_at,
               justification, admin_id, db)
- approve_request(request_id, admin_id, db)
- reject_request(request_id, admin_id, db)
- revoke_request(request_id, admin_id, db)
- add_server(hostname, ip, env, os_family, db)
- disable_server(hostname, db)
- add_admin(username, email, db)
- disable_admin(username, db)
Labels : backend, core

ISSUE 9 — [BACKEND] collect.py — scan SSH
Fichier : app/collect.py
- Itère sur serveurs actifs depuis servers.yml
- ensure_scripts() sur chaque serveur
- Collecte via sam-collect
- Parse chaque ligne authorized_keys
- Détecte clés nouvelles → PENDING_REVIEW + alerte
- Détecte clés disparues → REVOKED + alerte si hors système
- audit_log SCAN_COMPLETED ou SCAN_FAILED
Labels : backend, ssh

ISSUE 10 — [BACKEND] expire.py — expiration
Fichier : app/expire.py
- warn_expiring_keys() avec anti-spam 24h
- expire_keys() avec sam-revoke automatique
- Emails WARNING et INFO
Labels : backend

ISSUE 11 — [BACKEND] alerts.py — emails
Fichier : app/alerts.py
- Envoi via msmtp
- Templates CRITIQUE / WARNING / INFO
- Fonction send_alert(level, subject, body)
Labels : backend

ISSUE 12 — [BACKEND] web.py — API Flask
Fichier : app/web.py
- Toutes les routes GET et POST listées dans CLAUDE.md
- Retourne JSON uniquement
- Importe actions.py pour la logique métier
- Authentification basique via session Flask
Labels : backend, api

ISSUE 13 — [BACKEND] manage.py — CLI click
Fichier : app/manage.py
- Toutes les commandes listées dans CLAUDE.md
- Importe actions.py pour la logique métier
- --help automatique sur chaque commande
- Output formaté en tableau terminal
Labels : backend, cli

### MILESTONE 3 — Frontend Vue.js

ISSUE 14 — [FRONTEND] Setup Vue.js 3 + Vite
Fichiers : ui/package.json, ui/vite.config.js,
           ui/index.html, ui/src/main.js,
           ui/src/router/index.js, ui/src/App.vue
- Vue Router pour navigation entre vues
- Proxy Vite → Flask en développement
- Configuration build pour /app/static/
Labels : frontend

ISSUE 15 — [FRONTEND] Dashboard.vue
Fichier : ui/src/views/Dashboard.vue
- Compteurs globaux (serveurs OK / alerte / injoignables)
- Tableau serveurs avec recherche temps réel
- Statut coloré par ligne (🔴 🟡 ✅)
- Lien vers détail serveur
- Bouton scanner maintenant
Labels : frontend

ISSUE 16 — [FRONTEND] ServerDetail.vue
Fichier : ui/src/views/ServerDetail.vue
- Informations serveur (hostname, IP, env, os)
- Tableau des clés avec actions inline
- Boutons : Valider / Révoquer / Assigner / Expiry
- Section accès temporaires actifs
Labels : frontend

ISSUE 17 — [FRONTEND] KeyActions.vue + ExpiryPicker.vue
Fichiers : ui/src/components/KeyActions.vue,
           ui/src/components/ExpiryPicker.vue
- Modal confirmation pour révocation
- Formulaire expiration : durée (heures) OU date précise
- Validation côté client avant envoi API
Labels : frontend, components

ISSUE 18 — [FRONTEND] Anomalies.vue
Fichier : ui/src/views/Anomalies.vue
- Toutes les clés PENDING_REVIEW
- Toutes les révocations hors système (30 derniers jours)
- Actions rapides inline : Valider / Révoquer
Labels : frontend

ISSUE 19 — [FRONTEND] AccessRequests.vue + AccessForm.vue
Fichiers : ui/src/views/AccessRequests.vue,
           ui/src/components/AccessForm.vue
- Liste accès temporaires actifs avec countdown
- Demandes en attente avec Approuver / Rejeter
- Formulaire : coller clé publique + serveur
              + durée OU date + justification
Labels : frontend

ISSUE 20 — [FRONTEND] Audit.vue
Fichier : ui/src/views/Audit.vue
- Historique complet audit_log
- Filtres : serveur / action / depuis date
- Couleur par niveau (CRITIQUE / WARNING / INFO)
Labels : frontend

ISSUE 21 — [FRONTEND] Admins.vue
Fichier : ui/src/views/Admins.vue
- Liste des administrateurs
- Formulaire ajout administrateur
- Bouton désactiver
Labels : frontend

### MILESTONE 4 — Documentation

ISSUE 22 — [DOC] ERD Mermaid
Fichier : docs/erd.md
- Diagramme ERD complet en Mermaid
- Rendu automatique sur GitHub
Labels : documentation, vae

ISSUE 23 — [DOC] DESIGN.md — document VAE C.1.6
Fichier : DESIGN.md
- Justification des choix technologiques
- Normalisation 3NF expliquée
- Alternatives évaluées (Zabbix, scripts distants, etc.)
- Politique sécurité ANSSI
- Architecture multi-stage expliquée
Labels : documentation, vae

ISSUE 24 — [DOC] README.md — mode d'emploi
Fichier : README.md
- Installation et premier démarrage
- Workflow ajout serveur distant
- Workflow premier scan
- Workflow traitement PENDING_REVIEW
- Workflow accès temporaire
- Workflow révocation hors système
Labels : documentation

## Ordre de travail Claude Code

Milestone 1 (Issues 1→4) avant tout le reste.
Milestone 2 dans l'ordre Issues 5→13.
Milestone 3 dans l'ordre Issues 14→21.
Milestone 4 Issues 22→24 en parallèle de Milestone 3.

Validation obligatoire après chaque issue avant de continuer.
Ne jamais travailler sur plusieurs issues simultanément.

## Instruction de démarrage pour Claude Code

Lis ce CLAUDE.md entièrement.
Crée les GitHub Issues dans l'ordre des milestones.
Chaque issue doit avoir : titre, description détaillée,
critères d'acceptation, labels, milestone.
Attends validation avant de commencer le code.
