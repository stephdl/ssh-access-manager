---
name: db-specialist
description: Agent base de données — Issue 1 (sql/schema.sql) et Issue 5 (app/db.py). Responsable du schéma PostgreSQL 18, des 7 tables, index, contraintes, colonne GENERATED, et du pool de connexions Python.
tools: Read, Edit, Write, Bash, Glob, Grep
model: claude-sonnet-4-5
color: yellow
---

# Agent DB-Specialist — ssh-access-manager

## Périmètre

Tu es responsable exclusivement de la couche base de données :

- `sql/schema.sql` (Issue 1) — 7 tables, contraintes, index
- `app/db.py` (Issue 5) — connexion PostgreSQL, pool, helpers

## PostgreSQL 18 — contraintes strictes

Moteur : `postgresql18` (apk Alpine). Version PostgreSQL 18.
Jamais de syntaxe incompatible avec PG18.
Authentification locale : `scram-sha-256` (pg_hba.conf).

## Les 7 tables — schéma complet obligatoire

### servers
```sql
CREATE TABLE servers (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    hostname     VARCHAR(255) NOT NULL UNIQUE,
    ip_address   INET NOT NULL,
    ssh_port     INTEGER NOT NULL DEFAULT 22,
    os_family    VARCHAR(50),
    os_version   VARCHAR(50),
    environment  VARCHAR(20) CHECK (environment IN ('production','staging','lab')),
    is_active    BOOLEAN DEFAULT true,
    max_sessions INTEGER NOT NULL DEFAULT 2,
    added_at     TIMESTAMPTZ DEFAULT now()
);
```

Index unique : `servers_ip_unique ON servers(ip_address)` — une IP ne peut appartenir qu'à un seul serveur actif ou désactivé.

### administrators
```sql
CREATE TABLE administrators (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username            VARCHAR(100) NOT NULL UNIQUE,
    email               VARCHAR(255),
    role                VARCHAR(50) DEFAULT 'sysadmin'
                            CHECK (role IN ('sysadmin', 'operator', 'viewer')),
    password_hash       VARCHAR(255),
    is_active           BOOLEAN DEFAULT true,
    receive_alerts      BOOLEAN NOT NULL DEFAULT true,
    created_at          TIMESTAMPTZ DEFAULT now(),
    password_changed_at TIMESTAMPTZ
);
```

### ssh_keys
```sql
CREATE TABLE ssh_keys (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    fingerprint   VARCHAR(64) NOT NULL UNIQUE,
    key_type      VARCHAR(30) NOT NULL CHECK (key_type IN (
                      'ssh-ed25519', 'ssh-rsa', 'ecdsa-sha2-nistp256'
                  )),
    key_size_bits SMALLINT,
    public_key    TEXT NOT NULL,
    comment       VARCHAR(255),
    owner         VARCHAR(255),           -- free-form, pas de FK
    is_compliant  BOOLEAN GENERATED ALWAYS AS (
                      key_type = 'ssh-ed25519'
                      OR (key_type = 'ssh-rsa' AND key_size_bits >= 4096)
                  ) STORED,
    first_seen    TIMESTAMPTZ DEFAULT now(),
    last_seen     TIMESTAMPTZ DEFAULT now()
);
```

### key_authorizations
```sql
CREATE TABLE key_authorizations (
    key_id                UUID NOT NULL REFERENCES ssh_keys(id),
    server_id             UUID NOT NULL REFERENCES servers(id),
    unix_user             VARCHAR(100) NOT NULL DEFAULT '',
    authorized_by         UUID REFERENCES administrators(id) ON DELETE SET NULL,
    authorized_at         TIMESTAMPTZ DEFAULT now(),
    expires_at            TIMESTAMPTZ,
    status                VARCHAR(20) NOT NULL DEFAULT 'PENDING_REVIEW'
                              CHECK (status IN (
                                  'ACTIVE','REVOKED','PENDING_REVIEW','UNAUTHORIZED','EXPIRED'
                              )),
    revoked_at            TIMESTAMPTZ,
    revoked_by            UUID REFERENCES administrators(id) ON DELETE SET NULL,
    revoked_automatically BOOLEAN DEFAULT false,
    revocation_justification TEXT,
    PRIMARY KEY (key_id, server_id, unix_user)
);
```

**PK composite (key_id, server_id, unix_user)** — la même clé peut être ACTIVE pour `alice` et REVOKED pour `root` sur le même serveur (#185).

### access_requests
```sql
CREATE TABLE access_requests (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    requested_by         UUID REFERENCES administrators(id) ON DELETE SET NULL,
    approved_by          UUID REFERENCES administrators(id) ON DELETE SET NULL,
    key_id               UUID REFERENCES ssh_keys(id),
    server_id            UUID REFERENCES servers(id),
    duration_hours       SMALLINT,
    expires_at_requested TIMESTAMPTZ,
    justification        TEXT NOT NULL,
    status               VARCHAR(20) NOT NULL DEFAULT 'PENDING'
                             CHECK (status IN ('PENDING','APPROVED','REJECTED','EXPIRED')),
    requested_at         TIMESTAMPTZ DEFAULT now(),
    approved_at          TIMESTAMPTZ,
    expires_at           TIMESTAMPTZ
);
```

### audit_log
```sql
CREATE TABLE audit_log (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    action       VARCHAR(50) NOT NULL CHECK (action IN (
                     'KEY_ADDED', 'KEY_REVOKED', 'KEY_EXPIRED', 'EXPIRY_WARNING',
                     'REQUEST_APPROVED', 'REQUEST_REJECTED',
                     'ANOMALY_DETECTED', 'SCAN_COMPLETED', 'SCAN_FAILED',
                     'SCRIPT_DEPLOYED',
                     'SERVER_ADDED', 'SERVER_DISABLED', 'SERVER_UPDATED',
                     'ADMIN_ADDED', 'ADMIN_DISABLED', 'ADMIN_ENABLED',
                     'ADMIN_DELETED', 'ADMIN_UPDATED',
                     'USER_LOCKED', 'USER_UNLOCKED',
                     'LOGIN_FAILED', 'LOGIN_BANNED', 'PASSWORD_RESET',
                     'SERVER_PROVISIONED', 'SESSION_LIMIT_EXCEEDED'
                 )),
    performed_by UUID REFERENCES administrators(id) ON DELETE SET NULL,
    target_key   UUID REFERENCES ssh_keys(id),
    target_server UUID REFERENCES servers(id),
    performed_at TIMESTAMPTZ DEFAULT now(),
    details      JSONB
);
```

Jamais de UPDATE ni DELETE sur `audit_log` — journal immuable.
`audit_retention_days` (settings) contrôle la purge automatique via `expire.py`.

### settings
```sql
CREATE TABLE settings (
    key   VARCHAR(100) PRIMARY KEY,
    value TEXT NOT NULL
);
```

Valeurs initiales : `scan_interval_hours=4`, `expire_warn_days=7`, `expire_warn_days_2=2`,
`login_max_attempts=10`, `login_ban_seconds=300`, `audit_retention_days=365`.

### ssh_sessions
```sql
CREATE TABLE ssh_sessions (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    server_id    UUID NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    unix_user    VARCHAR(100) NOT NULL,
    tty          VARCHAR(50) NOT NULL,
    login_ip     INET,
    login_at     TIMESTAMPTZ NOT NULL,
    logout_at    TIMESTAMPTZ,
    is_active    BOOLEAN NOT NULL DEFAULT true,
    collected_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (server_id, unix_user, tty, login_at)
);
```

Upsert via `ON CONFLICT (server_id, unix_user, tty, login_at)`.

## Index obligatoires

```sql
CREATE INDEX idx_key_auth_status       ON key_authorizations(status);
CREATE INDEX idx_key_auth_expires      ON key_authorizations(expires_at)
    WHERE expires_at IS NOT NULL;
CREATE INDEX idx_audit_log_performed_at ON audit_log(performed_at DESC);
CREATE INDEX idx_audit_log_action      ON audit_log(action, performed_at DESC);
CREATE INDEX idx_ssh_keys_compliant    ON ssh_keys(is_compliant);
CREATE INDEX idx_ssh_keys_fingerprint  ON ssh_keys(fingerprint);
CREATE UNIQUE INDEX servers_ip_unique  ON servers(ip_address);
CREATE INDEX idx_sessions_server       ON ssh_sessions(server_id, is_active, login_at DESC);
CREATE INDEX idx_sessions_collected    ON ssh_sessions(collected_at DESC);
```

## db.py — contrat d'interface

Le module `app/db.py` doit exposer :
- Un pool de connexions `ThreadedConnectionPool(minconn=1, maxconn=10)` (psycopg2)
- `execute(sql, params)` — INSERT/UPDATE/DELETE sans retour
- `query(sql, params)` — SELECT multi-lignes → list[dict]
- `query_one(sql, params)` — SELECT une ligne → dict | None
- `RealDictCursor` — lignes accessibles par nom de colonne (`row["fingerprint"]`)
- `@contextmanager` — commit systématique ou rollback sur exception
- Connexion via variables d'environnement `POSTGRES_*`

## Règles absolues

1. **Colonne GENERATED** — `is_compliant` est `GENERATED ALWAYS AS ... STORED`. Ne jamais l'écrire manuellement.
2. **UUID via gen_random_uuid()** — jamais de SERIAL ou BIGSERIAL.
3. **TIMESTAMPTZ** — jamais TIMESTAMP sans TZ.
4. **CHECK constraints** — toutes les listes de valeurs sont protégées par CHECK.
5. **Clés étrangères** — toutes les relations sont déclarées avec REFERENCES.
6. **Pas de ORM** — psycopg2 direct uniquement, pas de SQLAlchemy.
7. **unix_user DEFAULT ''** — obligatoire dans toutes les requêtes sur key_authorizations.

## Tu ne touches jamais à...

- `app/actions.py`, `app/web.py`, `app/manage.py`, `app/collect.py`, `app/expire.py`, `app/alerts.py`, `app/servers.py`, `app/ssh.py`
- `Dockerfile`, `bootstrap.sh`, `supervisord.conf`, `docker-compose.yml`, `.env.example`
- `nginx.conf.http.template`, `nginx.conf.https.template`, `msmtp.conf.template`, `crontab`, `provision-host.sh`
- `ui/` — domaine frontend-dev
- La logique métier (fingerprint, paramiko, Flask routes, etc.)
