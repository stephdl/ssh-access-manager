# ssh-access-manager

Outil d'audit et de gestion des accès SSH dans un container Alpine Linux unique.

**Stack** : Python 3.12 · Flask · PostgreSQL 18 · Nginx · Vue.js 3 · Supervisord · Alpine 3.23.4

---

## Installation et premier démarrage

### Prérequis

- Podman ou Docker
- Un smarthost SMTP accessible (pour les alertes email)

### 1. Cloner et configurer

```bash
git clone https://github.com/stephdl/ssh-access-manager.git
cd ssh-access-manager
cp .env.example .env
# Éditer .env avec vos valeurs
```

### 2. Construire l'image

```bash
podman build -t ssh-access-manager .
```

### 3. Premier démarrage

```bash
podman run -d \
  --name ssh-access-manager \
  --env-file .env \
  -v ssh_data:/data \
  -p 8080:8080 \
  ssh-access-manager
```

Au premier démarrage, le container :
1. Initialise PostgreSQL et applique le schéma SQL
2. Génère une paire de clés ED25519 dans `/data/keys/`
3. Insère l'administrateur initial (depuis `ADMIN_USERNAME` et `ADMIN_EMAIL`)
4. Affiche la clé publique `collector_key.pub` dans les logs

```bash
# Récupérer la clé publique du collecteur
podman logs ssh-access-manager | grep -A1 "collector_key.pub"
```

L'interface est accessible sur `http://localhost:8080` (authentification Basic Auth : `NGINX_USER` / `NGINX_PASSWORD`).

---

## Workflow — Ajout d'un serveur distant

### 1. Provisionner l'hôte distant

Sur chaque serveur à auditer, exécuter `provision-host.sh` avec la clé publique du collecteur :

```bash
bash provision-host.sh "ssh-ed25519 AAAA... ssh-access-manager@container"
```

Ce script crée l'utilisateur `audit-collector`, dépose la clé publique et configure `sudoers`.

### 2. Déclarer le serveur dans servers.yml

```bash
# Éditer /data/config/servers.yml dans le volume
podman exec ssh-access-manager vi /data/config/servers.yml
```

Format :
```yaml
servers:
  - hostname: server-prod-01
    ip: 192.168.1.10
    environment: production
    os_family: rhel
```

### 3. Synchroniser en base

```bash
podman exec ssh-access-manager python3 /app/app/manage.py servers list
```

---

## Workflow — Premier scan

```bash
# Scan de tous les serveurs déclarés
podman exec ssh-access-manager python3 /app/app/manage.py servers scan

# Ou via l'interface web : Dashboard > "Scanner maintenant"
```

Lors du premier scan :
- Les scripts `sam-collect` et `sam-revoke` sont déployés sur chaque hôte
- Toutes les clés présentes dans `authorized_keys` sont importées avec le statut `PENDING_REVIEW`
- Une alerte email CRITIQUE est envoyée pour chaque clé inconnue détectée

---

## Workflow — Traitement des clés PENDING_REVIEW

Après le premier scan, toutes les clés détectées sont en attente de validation.

### Via l'interface web

1. Aller dans **Anomalies**
2. Pour chaque clé : cliquer **Valider** (clé légitime) ou **Révoquer** (clé à supprimer)

### Via la CLI

```bash
# Lister les clés en attente
podman exec ssh-access-manager python3 /app/app/manage.py keys list --status PENDING_REVIEW

# Valider une clé
podman exec ssh-access-manager python3 /app/app/manage.py keys validate SHA256:...

# Révoquer une clé
podman exec ssh-access-manager python3 /app/app/manage.py keys revoke SHA256:... --reason "Clé orpheline"
```

---

## Workflow — Accès temporaire

### Demande d'accès

```bash
podman exec ssh-access-manager python3 /app/app/manage.py access request \
  --key SHA256:... \
  --server server-prod-01 \
  --hours 8 \
  --reason "Intervention maintenance planifiée"
```

### Approbation

```bash
# Lister les demandes en attente
podman exec ssh-access-manager python3 /app/app/manage.py access list --status PENDING

# Approuver
podman exec ssh-access-manager python3 /app/app/manage.py access approve <id>
```

Ou via **Accès** dans l'interface web : bouton **Approuver** sur la demande en attente.

À expiration, la clé est automatiquement révoquée par `expire.py` (cron toutes les `SCAN_INTERVAL_HOURS` heures).

---

## Workflow — Révocation hors système

Si un scan détecte qu'une clé `ACTIVE` a disparu de `authorized_keys` sans action dans le système :

1. La clé passe au statut `REVOKED` avec `revoked_automatically = true` et `revoked_by = NULL`
2. Une entrée `ANOMALY_DETECTED` est créée dans l'audit
3. Un **email CRITIQUE** est envoyé immédiatement
4. La clé apparaît dans **Anomalies > Révocations hors système**

Action recommandée : investiguer l'origine de la suppression (accès root direct ? compromission ?).

---

## Variables d'environnement

| Variable | Description | Défaut |
|---|---|---|
| `POSTGRES_DB` | Nom de la base de données | `ssh_manager` |
| `POSTGRES_USER` | Utilisateur PostgreSQL | `ssh_manager` |
| `POSTGRES_PASSWORD` | Mot de passe PostgreSQL | — |
| `NGINX_PORT` | Port d'écoute Nginx | `8080` |
| `NGINX_USER` | Login Basic Auth | `admin` |
| `NGINX_PASSWORD` | Mot de passe Basic Auth | — |
| `FLASK_SECRET_KEY` | Clé secrète Flask (sessions) | — |
| `SMTP_HOST` | Serveur SMTP | — |
| `SMTP_PORT` | Port SMTP | `587` |
| `SMTP_USER` | Utilisateur SMTP | — |
| `SMTP_PASSWORD` | Mot de passe SMTP | — |
| `SMTP_FROM` | Adresse expéditeur | — |
| `SMTP_TO` | Adresse destinataire des alertes | — |
| `SSH_USER` | Utilisateur SSH collecteur | `audit-collector` |
| `SCAN_INTERVAL_HOURS` | Intervalle des scans automatiques (heures) | `4` |
| `EXPIRE_WARN_DAYS` | Alerte J-N avant expiration (premier avertissement) | `7` |
| `EXPIRE_WARN_DAYS_2` | Alerte J-N avant expiration (second avertissement) | `2` |
| `ADMIN_USERNAME` | Username de l'administrateur initial | `admin` |
| `ADMIN_EMAIL` | Email de l'administrateur initial | — |
| `TZ` | Fuseau horaire | `Europe/Paris` |

---

## Commandes CLI — référence rapide

```bash
EXEC="podman exec ssh-access-manager python3 /app/app/manage.py"

# Serveurs
$EXEC servers list
$EXEC servers add --hostname HOST --ip IP --env production --os rhel
$EXEC servers scan --server HOST

# Clés
$EXEC keys list --status PENDING_REVIEW
$EXEC keys revoke SHA256:... --reason "Motif"
$EXEC keys set-expiry SHA256:... --hours 24

# Accès temporaires
$EXEC access list
$EXEC access grant --key SHA256:... --server HOST --hours 8 --reason "Motif"
$EXEC access approve <id>

# Audit
$EXEC audit list --action ANOMALY_DETECTED --since 2025-01-01

# Système
$EXEC system status
```

---

## Tests

```bash
# Tests backend Python
cd app && python3 -m pytest tests/ --cov=actions --cov-fail-under=80

# Tests frontend Vitest
cd ui && npx vitest run
```
