-- =============================================================================
-- ssh-access-manager — schéma PostgreSQL 18
-- Ordre de création respectant les dépendances FK :
--   servers → administrators → ssh_keys →
--   key_authorizations → access_requests → audit_log
-- =============================================================================

-- ---------------------------------------------------------------------------
-- TABLE : servers
-- Inventaire déclaratif des serveurs SSH surveillés.
-- Alimenté depuis /data/config/servers.yml via servers.py.
-- ---------------------------------------------------------------------------
CREATE TABLE servers (
    -- Identifiant unique généré automatiquement
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Nom d'hôte unique du serveur (correspond à servers.yml)
    hostname    VARCHAR(255) NOT NULL UNIQUE,
    -- Adresse IP au format INET (supporte IPv4 et IPv6)
    ip_address  INET NOT NULL,
    -- Port SSH du serveur (défaut 22)
    ssh_port    INTEGER NOT NULL DEFAULT 22,
    -- Famille d'OS : rhel, debian, alpine, etc.
    os_family   VARCHAR(50),
    -- Version précise de l'OS (ex: "RHEL 9.3", "Debian 12")
    os_version  VARCHAR(50),
    -- Environnement du serveur — valeurs contrôlées
    environment VARCHAR(20) CHECK (environment IN (
                    'production',
                    'staging',
                    'lab'
                )),
    -- Serveur actif dans le périmètre de collecte
    is_active   BOOLEAN DEFAULT true,
    -- Date d'enregistrement dans le système
    added_at    TIMESTAMPTZ DEFAULT now()
);

COMMENT ON TABLE servers IS 'Inventaire des serveurs SSH surveillés, alimenté depuis servers.yml';
COMMENT ON COLUMN servers.id IS 'UUID généré automatiquement';
COMMENT ON COLUMN servers.hostname IS 'Nom d''hôte unique, clé de réconciliation avec servers.yml';
COMMENT ON COLUMN servers.ip_address IS 'Adresse IP (INET, supporte IPv4 et IPv6)';
COMMENT ON COLUMN servers.ssh_port IS 'Port SSH du serveur (défaut 22)';
COMMENT ON COLUMN servers.os_family IS 'Famille d''OS : rhel, debian, alpine...';
COMMENT ON COLUMN servers.os_version IS 'Version précise de l''OS';
COMMENT ON COLUMN servers.environment IS 'Environnement : production, staging ou lab';
COMMENT ON COLUMN servers.is_active IS 'False = exclu du périmètre de collecte SSH';
COMMENT ON COLUMN servers.added_at IS 'Horodatage d''enregistrement dans le système';

-- ---------------------------------------------------------------------------
-- TABLE : administrators
-- Utilisateurs autorisés à gérer le système (valider, révoquer, approuver).
-- L'administrateur initial est inséré par bootstrap.sh depuis ENV.
-- ---------------------------------------------------------------------------
CREATE TABLE administrators (
    -- Identifiant unique généré automatiquement
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Login unique de l'administrateur
    username    VARCHAR(100) NOT NULL UNIQUE,
    -- Adresse email pour les notifications
    email       VARCHAR(255),
    -- Rôle fonctionnel (extensible)
    role          VARCHAR(50) DEFAULT 'sysadmin' CHECK (role IN ('sysadmin', 'operator', 'viewer')),
    -- Hash du mot de passe (werkzeug generate_password_hash)
    password_hash VARCHAR(255),
    -- Compte actif ou désactivé (jamais supprimé pour préserver l'audit)
    is_active     BOOLEAN DEFAULT true,
    -- Reçoit les emails d'alerte CRITICAL/WARNING
    receive_alerts BOOLEAN DEFAULT true NOT NULL,
    -- Date de création du compte
    created_at    TIMESTAMPTZ DEFAULT now(),
    -- NULL = password never changed since account creation
    password_changed_at TIMESTAMPTZ
);

COMMENT ON TABLE administrators IS 'Utilisateurs autorisés à gérer les accès SSH';
COMMENT ON COLUMN administrators.id IS 'UUID généré automatiquement';
COMMENT ON COLUMN administrators.username IS 'Login unique de l''administrateur';
COMMENT ON COLUMN administrators.email IS 'Email pour les alertes et notifications';
COMMENT ON COLUMN administrators.role IS 'Rôle fonctionnel, défaut : sysadmin';
COMMENT ON COLUMN administrators.password_hash IS 'Hash werkzeug (pbkdf2:sha256) du mot de passe';
COMMENT ON COLUMN administrators.is_active IS 'False = compte désactivé (jamais supprimé)';
COMMENT ON COLUMN administrators.receive_alerts IS 'True = reçoit les emails CRITICAL/WARNING';
COMMENT ON COLUMN administrators.created_at IS 'Horodatage de création du compte';

-- ---------------------------------------------------------------------------
-- TABLE : ssh_keys
-- Clés SSH collectées sur les serveurs distants via sam-collect.
-- La colonne is_compliant est calculée automatiquement (GENERATED STORED).
-- ---------------------------------------------------------------------------
CREATE TABLE ssh_keys (
    -- Identifiant unique généré automatiquement
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Fingerprint SHA256 au format "SHA256:<base64>" — identifiant technique unique
    fingerprint     VARCHAR(64) NOT NULL UNIQUE,
    -- Type de clé — valeurs contrôlées par politique de sécurité
    key_type        VARCHAR(30) NOT NULL CHECK (key_type IN (
                        'ssh-ed25519',
                        'ssh-rsa',
                        'ecdsa-sha2-nistp256'
                    )),
    -- Taille en bits (pertinent pour RSA : doit être >= 4096 pour être conforme)
    key_size_bits   SMALLINT,
    -- Contenu complet de la clé publique (type + base64 + commentaire)
    public_key      TEXT NOT NULL,
    -- Commentaire extrait de la clé publique (champ libre)
    comment         VARCHAR(255),
    -- Propriétaire libre de la clé (nom complet ou identifiant quelconque, nullable)
    owner           VARCHAR(255),
    -- Conformité calculée : ED25519 toujours conforme, RSA conforme si >= 4096 bits
    -- GENERATED ALWAYS AS STORED : jamais à écrire manuellement
    is_compliant    BOOLEAN GENERATED ALWAYS AS (
                        key_type = 'ssh-ed25519'
                        OR (key_type = 'ssh-rsa' AND key_size_bits >= 4096)
                    ) STORED,
    -- Première détection de la clé sur un serveur
    first_seen      TIMESTAMPTZ DEFAULT now(),
    -- Dernière détection lors du dernier scan
    last_seen       TIMESTAMPTZ DEFAULT now()
);

COMMENT ON TABLE ssh_keys IS 'Clés SSH collectées sur les serveurs via sam-collect';
COMMENT ON COLUMN ssh_keys.id IS 'UUID généré automatiquement';
COMMENT ON COLUMN ssh_keys.fingerprint IS 'SHA256:<base64> — calculé par compute_fingerprint() dans ssh.py';
COMMENT ON COLUMN ssh_keys.key_type IS 'Type de clé : ssh-ed25519, ssh-rsa ou ecdsa-sha2-nistp256';
COMMENT ON COLUMN ssh_keys.key_size_bits IS 'Taille en bits, NULL pour ED25519, obligatoire pour RSA';
COMMENT ON COLUMN ssh_keys.public_key IS 'Clé publique complète au format authorized_keys';
COMMENT ON COLUMN ssh_keys.comment IS 'Commentaire extrait de la clé (souvent user@host)';
COMMENT ON COLUMN ssh_keys.owner IS 'Nom libre du propriétaire (peut être un non-admin), NULL si inconnu';
COMMENT ON COLUMN ssh_keys.is_compliant IS 'GENERATED: ED25519=true, RSA>=4096=true, sinon false';
COMMENT ON COLUMN ssh_keys.first_seen IS 'Premier horodatage de détection de la clé';
COMMENT ON COLUMN ssh_keys.last_seen IS 'Dernier horodatage de détection lors d''un scan';

-- ---------------------------------------------------------------------------
-- TABLE : key_authorizations
-- Association clé SSH ↔ serveur ↔ utilisateur Unix avec statut du cycle de vie.
-- Clé primaire composite (key_id, server_id, unix_user) : la même clé peut
-- être déployée pour plusieurs utilisateurs Unix sur le même serveur.
-- ---------------------------------------------------------------------------
CREATE TABLE key_authorizations (
    -- Référence vers la clé SSH concernée
    key_id                   UUID NOT NULL REFERENCES ssh_keys(id),
    -- Référence vers le serveur concerné
    server_id                UUID NOT NULL REFERENCES servers(id),
    -- Utilisateur Unix propriétaire de la clé sur ce serveur
    unix_user                VARCHAR(100) NOT NULL DEFAULT '',
    -- Administrateur ayant validé l'autorisation (NULL si détection automatique)
    authorized_by            UUID REFERENCES administrators(id) ON DELETE SET NULL,
    -- Date de première autorisation ou détection
    authorized_at            TIMESTAMPTZ DEFAULT now(),
    -- Date d'expiration programmée (NULL = pas d'expiration)
    expires_at               TIMESTAMPTZ,
    -- Statut du cycle de vie de l'autorisation
    status                   VARCHAR(20) NOT NULL DEFAULT 'PENDING_REVIEW'
                                 CHECK (status IN (
                                     'ACTIVE',           -- clé validée et active
                                     'REVOKED',          -- révoquée manuellement ou hors système
                                     'PENDING_REVIEW',   -- détectée, en attente de validation
                                     'UNAUTHORIZED',     -- non autorisée explicitement
                                     'EXPIRED'           -- expiration programmée atteinte
                                 )),
    -- Date effective de révocation
    revoked_at               TIMESTAMPTZ,
    -- Administrateur ayant révoqué (NULL si révocation automatique hors système)
    revoked_by               UUID REFERENCES administrators(id) ON DELETE SET NULL,
    -- True si révocation déclenchée automatiquement (expiration ou hors système)
    revoked_automatically    BOOLEAN DEFAULT false,
    -- Justification de révocation ou d'anomalie
    revocation_justification TEXT,
    -- Clé primaire composite : une clé par utilisateur Unix par serveur
    PRIMARY KEY (key_id, server_id, unix_user)
);

COMMENT ON TABLE key_authorizations IS 'Association clé SSH↔serveur↔unix_user avec statut du cycle de vie';
COMMENT ON COLUMN key_authorizations.key_id IS 'FK vers ssh_keys — partie de la PK composite';
COMMENT ON COLUMN key_authorizations.server_id IS 'FK vers servers — partie de la PK composite';
COMMENT ON COLUMN key_authorizations.unix_user IS 'Utilisateur Unix sur le serveur — partie de la PK composite';
COMMENT ON COLUMN key_authorizations.authorized_by IS 'FK vers administrators, NULL si détection automatique';
COMMENT ON COLUMN key_authorizations.authorized_at IS 'Date de première autorisation ou détection';
COMMENT ON COLUMN key_authorizations.expires_at IS 'Expiration programmée, NULL si permanente';
COMMENT ON COLUMN key_authorizations.status IS 'ACTIVE|REVOKED|PENDING_REVIEW|UNAUTHORIZED|EXPIRED';
COMMENT ON COLUMN key_authorizations.revoked_at IS 'Horodatage effectif de révocation';
COMMENT ON COLUMN key_authorizations.revoked_by IS 'FK administrateur révocateur, NULL si automatique';
COMMENT ON COLUMN key_authorizations.revoked_automatically IS 'True = révocation par expiration ou anomalie hors système';
COMMENT ON COLUMN key_authorizations.revocation_justification IS 'Motif de révocation ou description de l''anomalie';

-- ---------------------------------------------------------------------------
-- TABLE : access_requests
-- Demandes d'accès temporaire — workflow de validation.
-- Une demande approuvée crée ou met à jour une key_authorization.
-- ---------------------------------------------------------------------------
CREATE TABLE access_requests (
    -- Identifiant unique généré automatiquement
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Administrateur demandeur
    requested_by         UUID REFERENCES administrators(id) ON DELETE SET NULL,
    -- Administrateur approbateur (NULL tant que non traité)
    approved_by          UUID REFERENCES administrators(id) ON DELETE SET NULL,
    -- Clé SSH pour laquelle l'accès est demandé
    key_id               UUID REFERENCES ssh_keys(id),
    -- Serveur cible de la demande
    server_id            UUID REFERENCES servers(id),
    -- Durée demandée en heures (alternatif à expires_at_requested)
    duration_hours       SMALLINT,
    -- Date d'expiration explicitement demandée (alternatif à duration_hours)
    expires_at_requested TIMESTAMPTZ,
    -- Justification métier obligatoire
    justification        TEXT NOT NULL,
    -- Statut de la demande dans le workflow
    status               VARCHAR(20) NOT NULL DEFAULT 'PENDING'
                             CHECK (status IN (
                                 'PENDING',   -- en attente de traitement
                                 'APPROVED',  -- approuvée par un administrateur
                                 'REJECTED',  -- rejetée par un administrateur
                                 'EXPIRED'    -- expirée sans traitement
                             )),
    -- Date de soumission de la demande
    requested_at         TIMESTAMPTZ DEFAULT now(),
    -- Date d'approbation ou de rejet
    approved_at          TIMESTAMPTZ,
    -- Date d'expiration de l'accès accordé (calculée à l'approbation)
    expires_at           TIMESTAMPTZ
);

COMMENT ON TABLE access_requests IS 'Demandes d''accès temporaire avec workflow de validation';
COMMENT ON COLUMN access_requests.id IS 'UUID généré automatiquement';
COMMENT ON COLUMN access_requests.requested_by IS 'FK vers administrators — demandeur';
COMMENT ON COLUMN access_requests.approved_by IS 'FK vers administrators — approbateur, NULL si non traité';
COMMENT ON COLUMN access_requests.key_id IS 'FK vers ssh_keys — clé concernée par la demande';
COMMENT ON COLUMN access_requests.server_id IS 'FK vers servers — serveur cible';
COMMENT ON COLUMN access_requests.duration_hours IS 'Durée en heures, alternatif à expires_at_requested';
COMMENT ON COLUMN access_requests.expires_at_requested IS 'Date d''expiration demandée, alternatif à duration_hours';
COMMENT ON COLUMN access_requests.justification IS 'Motif métier obligatoire de la demande';
COMMENT ON COLUMN access_requests.status IS 'PENDING|APPROVED|REJECTED|EXPIRED';
COMMENT ON COLUMN access_requests.requested_at IS 'Horodatage de soumission';
COMMENT ON COLUMN access_requests.approved_at IS 'Horodatage de décision (approbation ou rejet)';
COMMENT ON COLUMN access_requests.expires_at IS 'Expiration de l''accès accordé, calculée à l''approbation';

-- ---------------------------------------------------------------------------
-- TABLE : audit_log
-- Journal immuable de toutes les actions sensibles du système.
-- Aucune ligne n'est jamais modifiée ou supprimée.
-- ---------------------------------------------------------------------------
CREATE TABLE audit_log (
    -- Identifiant unique généré automatiquement
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Type d'action — valeurs contrôlées et exhaustives
    action        VARCHAR(50) NOT NULL CHECK (action IN (
                      'KEY_ADDED',          -- clé validée (PENDING_REVIEW → ACTIVE)
                      'KEY_REVOKED',        -- révocation manuelle via le système
                      'KEY_EXPIRED',        -- expiration programmée atteinte
                      'EXPIRY_WARNING',     -- alerte d'expiration imminente (anti-spam 24h)
                      'REQUEST_APPROVED',   -- demande d'accès approuvée
                      'REQUEST_REJECTED',   -- demande d'accès rejetée
                      'ANOMALY_DETECTED',   -- clé inconnue ou révocation hors système
                      'SCAN_COMPLETED',     -- scan SSH terminé avec succès
                      'SCAN_FAILED',        -- scan SSH échoué (serveur injoignable)
                      'SCRIPT_DEPLOYED',    -- sam-collect ou sam-revoke redéployé
                      'SERVER_ADDED',       -- nouveau serveur enregistré
                      'SERVER_DISABLED',    -- serveur désactivé du périmètre
                      'SERVER_UPDATED',     -- serveur modifié (IP, env, OS)
                      'ADMIN_ADDED',        -- nouvel administrateur créé
                      'ADMIN_DISABLED',     -- administrateur désactivé
                      'ADMIN_ENABLED',      -- administrateur réactivé
                      'ADMIN_DELETED',      -- administrateur supprimé définitivement
                      'ADMIN_UPDATED',      -- administrateur modifié (email, rôle)
                      'USER_LOCKED',        -- compte Unix verrouillé (SSH bloqué)
                      'USER_UNLOCKED',      -- compte Unix déverrouillé
                      'LOGIN_FAILED',       -- tentative de connexion échouée (mauvais mot de passe)
                      'LOGIN_BANNED',       -- IP bannie après trop de tentatives échouées
                      'PASSWORD_RESET',     -- réinitialisation de mot de passe via CLI
                      'SERVER_PROVISIONED'  -- provisionnement automatique via SSH password
                  )),
    -- Administrateur ayant déclenché l'action (NULL si automatique)
    performed_by  UUID REFERENCES administrators(id) ON DELETE SET NULL,
    -- Clé SSH concernée par l'action (NULL si non applicable)
    target_key    UUID REFERENCES ssh_keys(id),
    -- Serveur concerné par l'action (NULL si non applicable)
    target_server UUID REFERENCES servers(id),
    -- Horodatage de l'action
    performed_at  TIMESTAMPTZ DEFAULT now(),
    -- Données contextuelles libres (fingerprint, hostname, raison, etc.)
    details       JSONB
);

COMMENT ON TABLE audit_log IS 'Journal immuable de toutes les actions — jamais modifié ni supprimé';
COMMENT ON COLUMN audit_log.id IS 'UUID généré automatiquement';
COMMENT ON COLUMN audit_log.action IS 'Type d''action parmi 18 valeurs contrôlées';
COMMENT ON COLUMN audit_log.performed_by IS 'FK administrateur, NULL si action automatique (cron, expiration)';
COMMENT ON COLUMN audit_log.target_key IS 'FK ssh_keys, NULL si action non liée à une clé';
COMMENT ON COLUMN audit_log.target_server IS 'FK servers, NULL si action non liée à un serveur';
COMMENT ON COLUMN audit_log.performed_at IS 'Horodatage précis de l''action (TIMESTAMPTZ)';
COMMENT ON COLUMN audit_log.details IS 'Contexte JSON libre : fingerprint, hostname, raison, etc.';

-- ---------------------------------------------------------------------------
-- TABLE : settings
-- Configuration dynamique modifiable via l'API sans redémarrer le container.
-- ---------------------------------------------------------------------------
CREATE TABLE settings (
    key   VARCHAR(100) PRIMARY KEY,
    value TEXT NOT NULL
);

COMMENT ON TABLE settings IS 'Configuration dynamique du système — clé/valeur';
COMMENT ON COLUMN settings.key IS 'Clé de configuration (ex: scan_interval_hours)';
COMMENT ON COLUMN settings.value IS 'Valeur texte';

INSERT INTO settings (key, value) VALUES ('scan_interval_hours', '4');
INSERT INTO settings (key, value) VALUES ('expire_warn_days', '7');
INSERT INTO settings (key, value) VALUES ('expire_warn_days_2', '2');
INSERT INTO settings (key, value) VALUES ('login_max_attempts', '10');
INSERT INTO settings (key, value) VALUES ('login_ban_seconds', '300');
INSERT INTO settings (key, value) VALUES ('audit_retention_days', '365');

-- =============================================================================
-- INDEX
-- Optimisent les requêtes fréquentes : filtres sur statut, expiration,
-- audit récent, et recherche par fingerprint.
-- =============================================================================

-- Filtrage par statut dans key_authorizations (ACTIVE, PENDING_REVIEW, etc.)
CREATE INDEX idx_key_auth_status
    ON key_authorizations(status);

-- Clés avec expiration définie — index partiel pour exclure les NULL
CREATE INDEX idx_key_auth_expires
    ON key_authorizations(expires_at)
    WHERE expires_at IS NOT NULL;

-- Audit log trié par date décroissante (vue Audit.vue, rapports)
CREATE INDEX idx_audit_log_performed_at
    ON audit_log(performed_at DESC);

-- Filtrage combiné action + date (requêtes anti-spam EXPIRY_WARNING)
CREATE INDEX idx_audit_log_action
    ON audit_log(action, performed_at DESC);

-- Filtrage des clés conformes / non conformes (rapport sécurité)
CREATE INDEX idx_ssh_keys_compliant
    ON ssh_keys(is_compliant);

-- Recherche par fingerprint (opération la plus fréquente sur ssh_keys)
CREATE INDEX idx_ssh_keys_fingerprint
    ON ssh_keys(fingerprint);

-- Une IP ne peut appartenir qu'à un seul serveur (désactivé = temporaire, pas libéré)
CREATE UNIQUE INDEX servers_ip_unique
    ON servers (ip_address);

-- ---------------------------------------------------------------------------
-- TABLE : ssh_sessions
-- Sessions SSH collectées sur les serveurs lors du scan ou à la demande.
-- Upsert via ON CONFLICT (server_id, unix_user, tty, login_at).
-- ---------------------------------------------------------------------------
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

COMMENT ON TABLE ssh_sessions IS 'Sessions SSH collectées via sam-sessions lors des scans';

CREATE INDEX idx_sessions_server ON ssh_sessions(server_id, is_active, login_at DESC);
CREATE INDEX idx_sessions_collected ON ssh_sessions(collected_at DESC);
