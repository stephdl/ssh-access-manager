-- =============================================================================
-- ssh-access-manager - PostgreSQL 18 schema
-- Creation order respecting FK dependencies:
--   servers -> administrators -> ssh_keys ->
--   key_authorizations -> access_requests -> audit_log
-- =============================================================================

-- ---------------------------------------------------------------------------
-- TABLE : servers
-- Declarative inventory of monitored SSH servers.
-- Populated from /data/config/servers.yml by servers.py.
-- ---------------------------------------------------------------------------
CREATE TABLE servers (
    -- Auto-generated unique identifier
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Unique server hostname (matches servers.yml)
    hostname    VARCHAR(255) NOT NULL UNIQUE,
    -- IP address in INET format (supports IPv4 and IPv6)
    ip_address  INET NOT NULL,
    -- SSH port of the server (default 22)
    ssh_port    INTEGER NOT NULL DEFAULT 22,
    -- OS family: rhel, debian, alpine, etc.
    os_family   VARCHAR(50),
    -- Precise OS version (e.g., 'RHEL 9.3', 'Debian 12')
    os_version  VARCHAR(50),
    -- Server environment - controlled values
    environment VARCHAR(20) CHECK (environment IN (
                    'production',
                    'staging',
                    'lab'
                )),
    -- Server active in the collection scope
    is_active   BOOLEAN DEFAULT true,
    -- Maximum allowed concurrent SSH sessions (alert if exceeded)
    max_sessions INTEGER NOT NULL DEFAULT 2,
    -- SHA256 (or prefix) of the last successful SAM_SELF_UPDATE deployment
    provision_version VARCHAR(64),
    -- TRUE if the last provision update attempt failed (rollback succeeded)
    provision_drift BOOLEAN NOT NULL DEFAULT FALSE,
    -- TRUE if the server has been successfully activated (SSH connectivity confirmed)
    is_provisioned BOOLEAN NOT NULL DEFAULT FALSE,
    -- Timestamp when added to the system
    added_at    TIMESTAMPTZ DEFAULT now()
);

COMMENT ON TABLE servers IS 'Inventory of monitored SSH servers, populated from servers.yml';
COMMENT ON COLUMN servers.id IS 'Auto-generated UUID';
COMMENT ON COLUMN servers.hostname IS 'Unique hostname, reconciliation key with servers.yml';
COMMENT ON COLUMN servers.ip_address IS 'IP address (INET, supports IPv4 and IPv6)';
COMMENT ON COLUMN servers.ssh_port IS 'SSH port of the server (default 22)';
COMMENT ON COLUMN servers.os_family IS 'OS family: rhel, debian, alpine...';
COMMENT ON COLUMN servers.os_version IS 'Precise OS version';
COMMENT ON COLUMN servers.environment IS 'Environment: production, staging or lab';
COMMENT ON COLUMN servers.is_active IS 'False = excluded from SSH collection scope';
COMMENT ON COLUMN servers.max_sessions IS 'Max concurrent SSH sessions threshold - WARNING alert if exceeded (24h anti-spam)';
COMMENT ON COLUMN servers.provision_version IS 'SHA256 (or prefix) of last successful SAM_SELF_UPDATE deployment';
COMMENT ON COLUMN servers.provision_drift IS 'TRUE if the last provision update attempt failed (remote remains functional via rollback)';
COMMENT ON COLUMN servers.is_provisioned IS 'TRUE if activate step has succeeded (SSH connectivity confirmed with per-server key)';
COMMENT ON COLUMN servers.added_at IS 'Record timestamp in the system';

-- ---------------------------------------------------------------------------
-- TABLE : administrators
-- Users authorized to manage the system (validate, revoke, approve).
-- The initial administrator is inserted by bootstrap.sh from ENV.
-- ---------------------------------------------------------------------------
CREATE TABLE administrators (
    -- Auto-generated unique identifier
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Administrator unique login
    username    VARCHAR(100) NOT NULL UNIQUE,
    -- Email address for notifications
    email       VARCHAR(255),
    -- Functional role (extensible)
    role        VARCHAR(50) DEFAULT 'sysadmin' CHECK (role IN ('sysadmin', 'operator', 'viewer')),
    -- Password hash (werkzeug generate_password_hash)
    password_hash VARCHAR(255),
    -- Account active or disabled (never deleted to preserve audit)
    is_active     BOOLEAN DEFAULT true,
    -- Receives CRITICAL/WARNING alert emails
    receive_alerts BOOLEAN DEFAULT true NOT NULL,
    -- Account creation timestamp
    created_at    TIMESTAMPTZ DEFAULT now(),
    -- NULL = password never changed since account creation
    password_changed_at TIMESTAMPTZ
);

COMMENT ON TABLE administrators IS 'Users authorized to manage SSH access';
COMMENT ON COLUMN administrators.id IS 'Auto-generated UUID';
COMMENT ON COLUMN administrators.username IS 'Administrator unique login';
COMMENT ON COLUMN administrators.email IS 'Email for alerts and notifications';
COMMENT ON COLUMN administrators.role IS 'Functional role, default: sysadmin';
COMMENT ON COLUMN administrators.password_hash IS 'Werkzeug hash (pbkdf2:sha256) of the password';
COMMENT ON COLUMN administrators.is_active IS 'False = account disabled (never deleted)';
COMMENT ON COLUMN administrators.receive_alerts IS 'True = receives CRITICAL/WARNING emails';
COMMENT ON COLUMN administrators.created_at IS 'Account creation timestamp';

-- ---------------------------------------------------------------------------
-- TABLE : ssh_keys
-- SSH keys collected from remote servers via sam-collect.
-- The is_compliant column is computed automatically (GENERATED STORED).
-- ---------------------------------------------------------------------------
CREATE TABLE ssh_keys (
    -- Auto-generated unique identifier
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- SHA256 fingerprint in format 'SHA256:<base64>' - unique technical identifier
    fingerprint     VARCHAR(64) NOT NULL UNIQUE,
    -- Key type - values controlled by security policy
    key_type        VARCHAR(30) NOT NULL CHECK (key_type IN (
                        'ssh-ed25519',
                        'ssh-rsa',
                        'ecdsa-sha2-nistp256'
                    )),
    -- Size in bits (relevant for RSA: must be >= 4096 to be compliant)
    key_size_bits   SMALLINT,
    -- Full public key content (type + base64 + comment)
    public_key      TEXT NOT NULL,
    -- Comment field extracted from the public key (free text)
    comment         VARCHAR(255),
    -- Free-form owner of the key (full name or any identifier, nullable)
    owner           VARCHAR(255),
    -- Compliance computed: ED25519 always compliant, RSA compliant if >= 4096 bits
    -- GENERATED ALWAYS AS STORED: never write this column manually
    is_compliant    BOOLEAN GENERATED ALWAYS AS (
                        key_type = 'ssh-ed25519'
                        OR (key_type = 'ssh-rsa' AND key_size_bits >= 4096)
                    ) STORED,
    -- First detection of the key on a server
    first_seen      TIMESTAMPTZ DEFAULT now(),
    -- Last detection during the latest scan
    last_seen       TIMESTAMPTZ DEFAULT now()
);

COMMENT ON TABLE ssh_keys IS 'SSH keys collected from servers via sam-collect';
COMMENT ON COLUMN ssh_keys.id IS 'Auto-generated UUID';
COMMENT ON COLUMN ssh_keys.fingerprint IS 'SHA256:<base64> - computed by compute_fingerprint() in ssh.py';
COMMENT ON COLUMN ssh_keys.key_type IS 'Key type: ssh-ed25519, ssh-rsa or ecdsa-sha2-nistp256';
COMMENT ON COLUMN ssh_keys.key_size_bits IS 'Size in bits, NULL for ED25519, required for RSA';
COMMENT ON COLUMN ssh_keys.public_key IS 'Full public key in authorized_keys format';
COMMENT ON COLUMN ssh_keys.comment IS 'Comment extracted from the key (often user@host)';
COMMENT ON COLUMN ssh_keys.owner IS 'Free-form owner name (may be non-admin), NULL if unknown';
COMMENT ON COLUMN ssh_keys.is_compliant IS 'GENERATED: ED25519=true, RSA>=4096=true, otherwise false';
COMMENT ON COLUMN ssh_keys.first_seen IS 'First timestamp the key was detected';
COMMENT ON COLUMN ssh_keys.last_seen IS 'Last timestamp the key was detected during a scan';

-- ---------------------------------------------------------------------------
-- TABLE : key_authorizations
-- Association between SSH key -> server -> unix user with lifecycle status.
-- Composite primary key (key_id, server_id, unix_user): the same key can
-- be deployed for multiple unix users on the same server.
-- ---------------------------------------------------------------------------
CREATE TABLE key_authorizations (
    -- Reference to the SSH key
    key_id                   UUID NOT NULL REFERENCES ssh_keys(id),
    -- Reference to the related server
    server_id                UUID NOT NULL REFERENCES servers(id),
    -- Unix user owning the key on that server
    unix_user                VARCHAR(100) NOT NULL DEFAULT '',
    -- Administrator who authorized it (NULL if auto-detected)
    authorized_by            UUID REFERENCES administrators(id) ON DELETE SET NULL,
    -- Date of first authorization or detection
    authorized_at            TIMESTAMPTZ DEFAULT now(),
    -- Scheduled expiration date (NULL = no expiration)
    expires_at               TIMESTAMPTZ,
    -- Lifecycle status of the authorization
    status                   VARCHAR(20) NOT NULL DEFAULT 'PENDING_REVIEW'
                                 CHECK (status IN (
                                     'ACTIVE',
                                     'REVOKED',
                                     'PENDING_REVIEW',
                                     'UNAUTHORIZED',
                                     'EXPIRED'
                                 )),
    -- Effective revocation date
    revoked_at               TIMESTAMPTZ,
    -- Administrator who revoked (NULL if automatic/revoked outside system)
    revoked_by               UUID REFERENCES administrators(id) ON DELETE SET NULL,
    -- True if revocation was triggered automatically (expiration or external)
    revoked_automatically    BOOLEAN DEFAULT false,
    -- Justification for revocation or anomaly description
    revocation_justification TEXT,
    -- SAM sudo group assigned to the unix user on this server (NULL = no group)
    sam_group                VARCHAR(20) CHECK (sam_group IN ('sam-operator', 'sam-pkg', 'sam-root')),
    -- Composite primary key: one key per unix user per server
    PRIMARY KEY (key_id, server_id, unix_user)
);

COMMENT ON TABLE key_authorizations IS 'Association key_authorizations: SSH key->server->unix_user with lifecycle status';
COMMENT ON COLUMN key_authorizations.key_id IS 'FK to ssh_keys - part of composite PK';
COMMENT ON COLUMN key_authorizations.server_id IS 'FK to servers - part of composite PK';
COMMENT ON COLUMN key_authorizations.unix_user IS 'Unix user on the server - part of composite PK';
COMMENT ON COLUMN key_authorizations.authorized_by IS 'FK to administrators, NULL if auto-detected';
COMMENT ON COLUMN key_authorizations.authorized_at IS 'Timestamp of first authorization or detection';
COMMENT ON COLUMN key_authorizations.expires_at IS 'Scheduled expiration, NULL if permanent';
COMMENT ON COLUMN key_authorizations.status IS 'ACTIVE|REVOKED|PENDING_REVIEW|UNAUTHORIZED|EXPIRED';
COMMENT ON COLUMN key_authorizations.revoked_at IS 'Actual revocation timestamp';
COMMENT ON COLUMN key_authorizations.revoked_by IS 'FK to administrator who revoked, NULL if automatic';
COMMENT ON COLUMN key_authorizations.revoked_automatically IS 'True = revoked by expiration or external anomaly';
COMMENT ON COLUMN key_authorizations.revocation_justification IS 'Reason for revocation or anomaly description';

-- ---------------------------------------------------------------------------
-- TABLE : access_requests
-- Temporary access requests - approval workflow.
-- An approved request creates or updates a key_authorization.
-- ---------------------------------------------------------------------------
CREATE TABLE access_requests (
    -- Auto-generated unique identifier
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Requesting administrator
    requested_by         UUID REFERENCES administrators(id) ON DELETE SET NULL,
    -- Approving administrator (NULL while pending)
    approved_by          UUID REFERENCES administrators(id) ON DELETE SET NULL,
    -- SSH key for which access is requested
    key_id               UUID REFERENCES ssh_keys(id),
    -- Target server of the request
    server_id            UUID REFERENCES servers(id),
    -- Requested duration in hours (alternative to expires_at_requested)
    duration_hours       SMALLINT,
    -- Explicitly requested expiration date (alternative to duration_hours)
    expires_at_requested TIMESTAMPTZ,
    -- Business justification (required)
    justification        TEXT NOT NULL,
    -- Request status in the workflow
    status               VARCHAR(20) NOT NULL DEFAULT 'PENDING'
                             CHECK (status IN (
                                 'PENDING',
                                 'APPROVED',
                                 'REJECTED',
                                 'EXPIRED'
                             )),
    -- Submission timestamp
    requested_at         TIMESTAMPTZ DEFAULT now(),
    -- Decision timestamp (approval or rejection)
    approved_at          TIMESTAMPTZ,
    -- Expiration date of the granted access (computed at approval)
    expires_at           TIMESTAMPTZ
);

COMMENT ON TABLE access_requests IS 'Temporary access requests with approval workflow';
COMMENT ON COLUMN access_requests.id IS 'Auto-generated UUID';
COMMENT ON COLUMN access_requests.requested_by IS 'FK to administrators - requester';
COMMENT ON COLUMN access_requests.approved_by IS 'FK to administrators - approver, NULL if pending';
COMMENT ON COLUMN access_requests.key_id IS 'FK to ssh_keys - key concerned by the request';
COMMENT ON COLUMN access_requests.server_id IS 'FK to servers - target server';
COMMENT ON COLUMN access_requests.duration_hours IS 'Duration in hours, alternative to expires_at_requested';
COMMENT ON COLUMN access_requests.expires_at_requested IS 'Requested expiration date, alternative to duration_hours';
COMMENT ON COLUMN access_requests.justification IS 'Required business justification for the request';
COMMENT ON COLUMN access_requests.status IS 'PENDING|APPROVED|REJECTED|EXPIRED';
COMMENT ON COLUMN access_requests.requested_at IS 'Submission timestamp';
COMMENT ON COLUMN access_requests.approved_at IS 'Decision timestamp (approval or rejection)';
COMMENT ON COLUMN access_requests.expires_at IS 'Expiration of granted access, computed at approval';

-- ---------------------------------------------------------------------------
-- TABLE : audit_log
-- Immutable journal of all sensitive system actions.
-- No row is ever updated or deleted.
-- ---------------------------------------------------------------------------
CREATE TABLE audit_log (
    -- Auto-generated unique identifier
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Action type - controlled and exhaustive values
    action        VARCHAR(50) NOT NULL CHECK (action IN (
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
                      'SERVER_UPDATED',
                      'ADMIN_ADDED',
                      'ADMIN_DISABLED',
                      'ADMIN_ENABLED',
                      'ADMIN_DELETED',
                      'ADMIN_UPDATED',
                      'USER_LOCKED',
                      'USER_UNLOCKED',
                      'LOGIN_FAILED',
                      'LOGIN_BANNED',
                      'PASSWORD_RESET',
                      'SERVER_PROVISIONED',
                      'SESSION_LIMIT_EXCEEDED',
                      'GROUP_GRANTED',
                      'GROUP_REVOKED',
                      'GROUP_CHANGED',
                      'PROVISION_UPDATED',
                      'PROVISION_UPDATE_FAILED',
                      'COLLECTOR_KEY_GENERATED',
                      'COLLECTOR_KEY_ROTATED',
                      'COLLECTOR_KEY_ROTATION_FAILED',
                      'SERVER_RENAMED'
                  )),
    -- Administrator who triggered the action (NULL if automatic)
    performed_by  UUID REFERENCES administrators(id) ON DELETE SET NULL,
    -- SSH key targeted by the action (NULL if not applicable)
    target_key    UUID REFERENCES ssh_keys(id),
    -- Server targeted by the action (NULL if not applicable)
    target_server UUID REFERENCES servers(id),
    -- Timestamp of the action
    performed_at  TIMESTAMPTZ DEFAULT now(),
    -- Free-form contextual data (fingerprint, hostname, reason, etc.)
    details       JSONB
);

COMMENT ON TABLE audit_log IS 'Immutable journal of all actions - never modified or deleted';
COMMENT ON COLUMN audit_log.id IS 'Auto-generated UUID';
COMMENT ON COLUMN audit_log.action IS 'Action type among controlled values';
COMMENT ON COLUMN audit_log.performed_by IS 'FK to administrator, NULL if automatic (cron, expiry)';
COMMENT ON COLUMN audit_log.target_key IS 'FK to ssh_keys, NULL if action not related to a key';
COMMENT ON COLUMN audit_log.target_server IS 'FK to servers, NULL if action not related to a server';
COMMENT ON COLUMN audit_log.performed_at IS 'Precise timestamp of the action (TIMESTAMPTZ)';
COMMENT ON COLUMN audit_log.details IS 'Free JSON context: fingerprint, hostname, reason, etc.';

-- ---------------------------------------------------------------------------
-- TABLE : settings
-- Dynamic configuration editable via the API without restarting the container.
-- ---------------------------------------------------------------------------
CREATE TABLE settings (
    key   VARCHAR(100) PRIMARY KEY,
    value TEXT NOT NULL
);

COMMENT ON TABLE settings IS 'Dynamic system configuration - key/value';
COMMENT ON COLUMN settings.key IS 'Configuration key (e.g., scan_interval_hours)';
COMMENT ON COLUMN settings.value IS 'Text value';

INSERT INTO settings (key, value) VALUES ('scan_interval_hours', '4');
INSERT INTO settings (key, value) VALUES ('expire_warn_days', '7');
INSERT INTO settings (key, value) VALUES ('expire_warn_days_2', '2');
INSERT INTO settings (key, value) VALUES ('login_max_attempts', '10');
INSERT INTO settings (key, value) VALUES ('login_ban_seconds', '300');
INSERT INTO settings (key, value) VALUES ('audit_retention_days', '365');

-- =============================================================================
-- INDEX
-- Optimize frequent queries: status filters, expiration, recent audit,
-- and fingerprint lookup.
-- =============================================================================

-- Filter by status in key_authorizations (ACTIVE, PENDING_REVIEW, etc.)
CREATE INDEX idx_key_auth_status
    ON key_authorizations(status);

-- Keys with expiration defined - partial index to exclude NULL
CREATE INDEX idx_key_auth_expires
    ON key_authorizations(expires_at)
    WHERE expires_at IS NOT NULL;

-- Audit log sorted by descending date (Audit.vue view, reports)
CREATE INDEX idx_audit_log_performed_at
    ON audit_log(performed_at DESC);

-- Combined filter action + date (anti-spam EXPIRY_WARNING queries)
CREATE INDEX idx_audit_log_action
    ON audit_log(action, performed_at DESC);

-- Filter compliant / non-compliant keys (security report)
CREATE INDEX idx_ssh_keys_compliant
    ON ssh_keys(is_compliant);

-- Lookup by fingerprint (most frequent operation on ssh_keys)
CREATE INDEX idx_ssh_keys_fingerprint
    ON ssh_keys(fingerprint);

-- An IP can belong to only one server (disabled = temporary, not freed)
CREATE UNIQUE INDEX servers_ip_unique
    ON servers (ip_address);

-- ---------------------------------------------------------------------------
-- TABLE : ssh_sessions
-- SSH sessions collected from servers during scans or on demand.
-- Upsert via ON CONFLICT (server_id, unix_user, tty, login_at).
-- ---------------------------------------------------------------------------
CREATE TABLE ssh_sessions (
    -- Auto-generated unique identifier
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

COMMENT ON TABLE ssh_sessions IS 'SSH sessions collected via sam-sessions during scans';

CREATE INDEX idx_sessions_server ON ssh_sessions(server_id, is_active, login_at DESC);
CREATE INDEX idx_sessions_collected ON ssh_sessions(collected_at DESC);
