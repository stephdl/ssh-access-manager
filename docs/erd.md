# Diagramme ERD — ssh-access-manager

```mermaid
erDiagram
    servers {
        UUID id PK
        VARCHAR hostname UK
        INET ip_address
        VARCHAR os_family
        VARCHAR os_version
        VARCHAR environment
        BOOLEAN is_active
        TIMESTAMPTZ added_at
    }

    administrators {
        UUID id PK
        VARCHAR username UK
        VARCHAR email
        VARCHAR role
        VARCHAR password_hash
        BOOLEAN is_active
        BOOLEAN receive_alerts
        TIMESTAMPTZ created_at
    }

    ssh_keys {
        UUID id PK
        VARCHAR fingerprint UK
        VARCHAR key_type
        SMALLINT key_size_bits
        TEXT public_key
        VARCHAR comment
        VARCHAR owner
        BOOLEAN is_compliant
        TIMESTAMPTZ first_seen
        TIMESTAMPTZ last_seen
    }

    key_authorizations {
        UUID key_id FK
        UUID server_id FK
        VARCHAR unix_user
        UUID authorized_by FK
        TIMESTAMPTZ authorized_at
        TIMESTAMPTZ expires_at
        VARCHAR status
        TIMESTAMPTZ revoked_at
        UUID revoked_by FK
        BOOLEAN revoked_automatically
        TEXT revocation_justification
    }

    access_requests {
        UUID id PK
        UUID requested_by FK
        UUID approved_by FK
        UUID key_id FK
        UUID server_id FK
        SMALLINT duration_hours
        TIMESTAMPTZ expires_at_requested
        TEXT justification
        VARCHAR status
        TIMESTAMPTZ requested_at
        TIMESTAMPTZ approved_at
        TIMESTAMPTZ expires_at
    }

    audit_log {
        UUID id PK
        VARCHAR action
        UUID performed_by FK
        UUID target_key FK
        UUID target_server FK
        TIMESTAMPTZ performed_at
        JSONB details
    }

    settings {
        VARCHAR key PK
        TEXT value
    }

    ssh_keys ||--o{ key_authorizations : "autorisée via"
    servers ||--o{ key_authorizations : "héberge"
    administrators ||--o{ key_authorizations : "autorisée par"
    administrators ||--o{ key_authorizations : "révoquée par (revoked_by)"
    administrators ||--o{ access_requests : "demandée par"
    administrators ||--o{ access_requests : "approuvée par"
    ssh_keys ||--o{ access_requests : "concerne"
    servers ||--o{ access_requests : "cible"
    administrators ||--o{ audit_log : "effectuée par"
    ssh_keys ||--o{ audit_log : "clé cible"
    servers ||--o{ audit_log : "serveur cible"
```

## Description des relations

| Relation | Cardinalité | Description |
|---|---|---|
| `ssh_keys` → `key_authorizations` | 1:N | Une clé peut être autorisée sur plusieurs serveurs/utilisateurs |
| `servers` → `key_authorizations` | 1:N | Un serveur peut héberger plusieurs clés autorisées |
| `administrators` → `key_authorizations` | 1:N | Un admin autorise / révoque des accès |
| `administrators` → `access_requests` | 1:N | Un admin fait ou approuve des demandes |
| `ssh_keys` → `access_requests` | 1:N | Une clé peut faire l'objet de plusieurs demandes |
| `servers` → `access_requests` | 1:N | Un serveur cible plusieurs demandes |
| `administrators` → `audit_log` | 1:N | Un admin génère des entrées d'audit |
| `ssh_keys` → `audit_log` | 1:N | Une clé est référencée dans l'audit |
| `servers` → `audit_log` | 1:N | Un serveur est référencé dans l'audit |

## Clé primaire composite — key_authorizations

`key_authorizations` a une PK composite sur trois colonnes : `(key_id, server_id, unix_user)`.
Cela permet à une même clé SSH d'être déployée pour plusieurs utilisateurs Unix sur le même serveur.

## Colonne générée — ssh_keys.is_compliant

`ssh_keys.is_compliant` est une colonne `GENERATED ALWAYS AS … STORED` :

```sql
is_compliant BOOLEAN GENERATED ALWAYS AS (
    key_type = 'ssh-ed25519' OR
    (key_type = 'ssh-rsa' AND key_size_bits >= 4096)
) STORED
```

Valeur calculée automatiquement par PostgreSQL à chaque INSERT/UPDATE — jamais écrite par l'application.

## Champ owner — texte libre

`ssh_keys.owner` est un `VARCHAR(255)` libre (pas une FK vers `administrators`).
Il peut désigner un non-administrateur (ex : développeur externe) et reste NULL si inconnu.

## Table settings

Stocke la configuration dynamique du système. Modifiable via `PUT /api/system/config`
ou l'UI Settings sans redémarrage du container.

Clés présentes par défaut :

| Clé | Valeur par défaut | Description |
|-----|-------------------|-------------|
| `scan_interval_hours` | `4` | Intervalle entre deux scans SSH |
| `expire_warn_days` | `7` | Premier avertissement avant expiration (jours) |
| `expire_warn_days_2` | `2` | Second avertissement avant expiration (jours) |

## Colonne receive_alerts — administrators

`administrators.receive_alerts` contrôle si un administrateur reçoit les emails d'alerte.
Modifiable par un sysadmin via `PUT /api/admins/<username>/alerts` ou le toggle dans l'UI Admins.
