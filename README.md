# ssh-access-manager

Outil d'audit et de gestion des accès SSH dans un container Alpine Linux unique.

**Stack** : Python 3.12 · Flask · PostgreSQL 18 · Nginx · Vue.js 3 · vue-i18n · Supervisord · Alpine 3.23.4

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
# Récupérer la clé publique du collecteur depuis les logs
podman logs ssh-access-manager | grep -A1 "collector_key.pub"
```

La clé publique est également visible directement dans l'interface web : **Dashboard > Clé publique collecteur**.

L'interface est accessible sur `http://localhost:8080`. Authentification par session Flask : utilisez les identifiants définis via `ADMIN_USERNAME` / `ADMIN_PASSWORD` au démarrage.

---

## Interface utilisateur

L'interface Vue.js 3 est disponible en **5 langues** : Français, Anglais, Espagnol, Italien, Allemand.

La langue est détectée automatiquement depuis le navigateur, avec fallback sur l'anglais. Un sélecteur dans la barre de navigation permet de changer la langue manuellement (choix sauvegardé).

---

## Rôles et permissions

Trois rôles sont disponibles pour les administrateurs :

| Rôle | Droits |
|---|---|
| `sysadmin` | Accès complet : gestion des administrateurs, des serveurs, des clés SSH, des accès et de la configuration système |
| `operator` | Actions SSH : valider, révoquer, déployer des clés, verrouiller/déverrouiller des comptes Unix, lancer des scans |
| `viewer` | Lecture seule : consultation de toutes les vues sans possibilité d'action |

Le rôle est vérifié **côté backend** (Flask retourne 403 pour les requêtes non autorisées) **et côté frontend** (boutons et formulaires masqués selon le rôle).

Un `sysadmin` ne peut pas modifier son propre rôle. Un email est obligatoire à la création.

Pour créer un administrateur avec un rôle spécifique (défaut : `operator`) :

```bash
$EXEC admin add --username alice --email alice@example.com --password SECRET --role operator
$EXEC admin update alice --role viewer
```

---

## Workflow — Ajout d'un serveur distant

### 1. Provisionner l'hôte distant

Sur chaque serveur à auditer, depuis la machine hébergeant le container.
`<user>` peut être `root` ou tout utilisateur avec `sudo ALL` — c'est le `sudo bash -s` qui élève les privilèges :

```bash
ssh <user>@<ip-du-serveur> "sudo bash -s '$(podman exec ssh-access-manager cat /data/keys/collector_key.pub)'" \
    < <(podman exec ssh-access-manager cat /app/provision-host.sh)
```

Cette commande est **identique** pour un premier provisionnement ou une mise à jour (ex. après un rebuild ou un changement des règles sudoers). Le script est **idempotent** : il crée l'utilisateur `audit-collector` (réutilise s'il existe), ajoute la clé publique dans `authorized_keys` si elle est absente, et écrase `/etc/sudoers.d/audit-collector` avec les règles courantes.

### 2. Déclarer le serveur

**Via l'interface web (recommandé)** : Dashboard → bouton **+ Ajouter un serveur** → remplir hostname, IP, environnement, OS. La clé publique collecteur est affichée directement après l'ajout pour faciliter le déploiement.

**Via la CLI** :

```bash
podman exec ssh-access-manager python3 /app/app/manage.py servers add \
  --hostname server-prod-01 --ip 192.168.1.10 --env production --os rhel
```

**Via `servers.yml`** (déclaratif, chargé au démarrage) :

```yaml
# /data/config/servers.yml
servers:
  - hostname: server-prod-01
    ip: 192.168.1.10
    environment: production
    os_family: rhel
```

> **Note** : La connexion SSH utilise toujours l'adresse IP déclarée, jamais la résolution DNS, pour éviter les ambiguïtés réseau.

---

## Workflow — Gestion du cycle de vie d'un serveur

Depuis la vue détail d'un serveur (**Dashboard > clic sur hostname**) :

| Action | Effet |
|---|---|
| **Désactiver** | Le serveur n'est plus scanné automatiquement. Indicateur rouge visible dans le dashboard et la vue détail. |
| **Réactiver** | Le serveur reprend le cycle de scan automatique. |
| **Supprimer** | Suppression définitive du serveur et de toutes ses clés, autorisations et logs associés (action irréversible). |

---

## Workflow — Premier scan

```bash
# Scan de tous les serveurs actifs
podman exec ssh-access-manager python3 /app/app/manage.py servers scan

# Ou via l'interface web : Dashboard > "Scanner maintenant"
# Ou via la vue détail d'un serveur : bouton "Scanner"
```

Lors du premier scan :
- Les scripts `sam-collect` et `sam-revoke` sont déployés sur chaque hôte (via SFTP, hash SHA256 vérifié)
- Toutes les clés présentes dans `authorized_keys` sont importées avec le statut `PENDING_REVIEW`
- Une alerte email CRITIQUE est envoyée pour chaque clé inconnue détectée

---

## Workflow — Traitement des clés PENDING_REVIEW

Après le premier scan, toutes les clés détectées sont en attente de validation.

Une clé passe également en `PENDING_REVIEW` si elle était révoquée ou expirée et
réapparaît physiquement sur un serveur (ex. `ssh-copy-id` après révocation). Ce
cas est détecté automatiquement au prochain scan et génère une alerte CRITIQUE.

### Via l'interface web

1. Aller dans **Anomalies**
2. Pour chaque clé : cliquer **Valider** (clé légitime) ou **Révoquer** (clé à supprimer)

La colonne **Conforme** indique la conformité de chaque clé :
- ✅ : clé `ssh-ed25519` ou `ssh-rsa ≥ 4096 bits`
- ⚠️ : clé non conforme — survoler pour voir la raison (ex. *"RSA 2048 bits — minimum 4096 requis"*)

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

## Workflow — Gestion des clés SSH

Depuis la vue détail d'un serveur, les actions disponibles sur chaque clé ACTIVE :

| Action | Effet |
|---|---|
| **Révoquer** | Révocation immédiate avec motif obligatoire — supprime la clé du `authorized_keys` distant |
| **Assigner** | Associe la clé à un administrateur (visible dans la colonne Propriétaire) |
| **Expiration** | Définit une date/heure ou une durée en heures — révocation automatique à échéance |
| **Illimité** | Retire l'expiration d'une clé (visible uniquement si `expires_at` est défini) |

---

## Workflow — Verrouiller / Déverrouiller un compte Unix

Après révocation d'une clé, le compte Unix existe toujours sur le serveur. Pour bloquer **toute** connexion SSH (y compris avec une autre clé valide) :

**Via l'interface web** : Accès → section **Verrouiller / Déverrouiller un compte Unix**.

| Action | Commande distante | Effet |
|---|---|---|
| **Verrouiller** | `usermod -L -s /sbin/nologin <user>` | Bloque le mot de passe et interdit le shell — connexion SSH impossible même avec une clé valide |
| **Déverrouiller** | `usermod -U -s /bin/bash <user>` | Rétablit le compte — connexion SSH de nouveau possible avec une clé valide |

**Via la CLI** :
```bash
$EXEC access lock-user --user alice --server server-prod-01
$EXEC access unlock-user --user alice --server server-prod-01
```

---

## Workflow — Déployer une clé SSH

Pour donner accès à un utilisateur sur un serveur depuis l'interface :

**Via l'interface web** : Accès → section **Déployer une clé SSH**.

Le formulaire demande :
- **Utilisateur Unix** — nom du compte à créer sur le serveur cible (créé s'il n'existe pas)
- **Clé publique** — le contenu de la clé `ssh-ed25519` ou `ssh-rsa` (format authorized_keys)
- **Serveur cible** — dropdown des serveurs actifs
- **Durée** — heures / date précise / illimité
- **Justification** — obligatoire

À la soumission, `sam-add` est exécuté sur le serveur distant via SSH :
1. Crée l'utilisateur Unix s'il n'existe pas
2. Ajoute la clé dans `~/.ssh/authorized_keys`
3. Enregistre la clé dans la base avec statut `ACTIVE` et l'expiration choisie

> **Privilèges sudo du nouvel utilisateur** : `sam-add` crée le compte Unix mais ne lui attribue aucun privilège sudo. C'est à l'administrateur système de décider. Pour donner les droits sudo :
> ```bash
> # Debian/Ubuntu
> usermod -aG sudo alice
> # RHEL/CentOS/Rocky
> usermod -aG wheel alice
> ```

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
| `FLASK_SECRET_KEY` | Clé secrète Flask (sessions) — **obligatoire**, le container refuse de démarrer si absente | — |
| `SMTP_HOST` | Serveur SMTP | — |
| `SMTP_PORT` | Port SMTP | `587` |
| `SMTP_USER` | Utilisateur SMTP | — |
| `SMTP_PASSWORD` | Mot de passe SMTP | — |
| `SMTP_FROM` | Adresse expéditeur | — |
| `SMTP_TO` | Adresse destinataire des alertes | — |
| `SSH_USER` | Utilisateur SSH collecteur | `audit-collector` |
| `EXPIRE_WARN_DAYS` | Alerte J-N avant expiration (premier avertissement) | `7` |
| `EXPIRE_WARN_DAYS_2` | Alerte J-N avant expiration (second avertissement) | `2` |
| `ADMIN_USERNAME` | Username de l'administrateur initial | `admin` |
| `ADMIN_EMAIL` | Email de l'administrateur initial | — |
| `ADMIN_PASSWORD` | Mot de passe de l'administrateur initial | — |
| `TZ` | Fuseau horaire | `Europe/Paris` |

> **Secrets obligatoires avant un déploiement en production** — ne jamais laisser les valeurs d'exemple :
> ```bash
> # Générer FLASK_SECRET_KEY
> python3 -c "import secrets; print(secrets.token_hex(32))"
> ```
> Copier la valeur générée dans `.env` :
> ```
> FLASK_SECRET_KEY=<valeur générée>
> POSTGRES_PASSWORD=<mot de passe fort>
> ADMIN_PASSWORD=<mot de passe fort>
> ```

---

## Commandes CLI — référence rapide

```bash
EXEC="podman exec ssh-access-manager python3 /app/app/manage.py"

# Serveurs
$EXEC servers list
$EXEC servers add --hostname HOST --ip IP --env production --os rhel
$EXEC servers scan
$EXEC servers scan --server HOST
$EXEC servers disable HOST
$EXEC servers enable HOST
$EXEC servers show HOST

# Clés
$EXEC keys list --status PENDING_REVIEW
$EXEC keys show SHA256:...
$EXEC keys search QUERY
$EXEC keys validate SHA256:...
$EXEC keys revoke SHA256:... --reason "Motif"
$EXEC keys assign SHA256:... --owner "Alice Martin"
$EXEC keys set-expiry SHA256:... --hours 24
$EXEC keys set-expiry SHA256:... --date "2026-12-31 23:59"
$EXEC keys remove-expiry SHA256:...

# Accès temporaires
$EXEC access list
$EXEC access grant --key SHA256:... --server HOST --hours 8 --reason "Motif"
$EXEC access approve <id>
$EXEC access reject <id>
$EXEC access revoke <id>
$EXEC access lock-user --user USER --server HOST
$EXEC access unlock-user --user USER --server HOST

# Administrateurs
$EXEC admin list
$EXEC admin add --username USER --email EMAIL --password PASSWORD [--role ROLE]
# ROLE : sysadmin | operator (défaut) | viewer
$EXEC admin update <username> [--email EMAIL] [--role ROLE]
$EXEC admin disable USERNAME
$EXEC admin enable USERNAME
$EXEC admin delete USERNAME

# Audit
$EXEC audit list --action ANOMALY_DETECTED --since 2025-01-01
$EXEC audit list --server HOST

# Système
$EXEC system status
$EXEC system report
```

---

## Internationalisation

L'interface supporte 5 langues via `vue-i18n`. Les fichiers de traduction se trouvent dans `ui/src/locales/` :

| Fichier | Langue |
|---|---|
| `en.json` | Anglais (fallback par défaut) |
| `fr.json` | Français |
| `es.json` | Espagnol |
| `it.json` | Italien |
| `de.json` | Allemand |

Pour ajouter une nouvelle langue :
1. Copier `ui/src/locales/en.json` → `ui/src/locales/xx.json` et traduire
2. Ajouter l'import dans `ui/src/i18n.js`
3. Ajouter `<option value="xx">XX</option>` dans `ui/src/App.vue`

---

## Tests

```bash
# Tests backend Python
cd app && python3 -m pytest tests/ --cov=actions --cov-fail-under=80

# Tests frontend Vitest
cd ui && npx vitest run
```

---

## CI/CD & DevOps

### Workflows GitHub Actions

| Workflow | Déclencheur | Rôle |
|---|---|---|
| `ci.yml` | Chaque PR | Tests Python (pytest ≥ 80%), Tests Vue.js (vitest), Prettier, Commitlint |
| `pr-title.yml` | Ouverture / édition de PR | Validation du titre (Conventional Commits) |
| `build-pr.yml` | Chaque PR | Build + push image `pr-{N}` + scan Trivy CVE (CRITICAL/HIGH) |
| `build-main.yml` | Merge sur `main` | Build + push image `:main` sur GHCR |
| `publish-release.yml` | Push d'un tag git | Build + push image `:vX.Y.Z` (+ `:latest` si stable) |
| `cleanup-pr.yml` | Fermeture de PR | Suppression de l'image `pr-{N}` sur GHCR |
| `codeql.yml` | PR + push main + hebdo | Analyse statique sécurité Python (SAST) |

### Stratégie de tags Docker (GHCR)

| Événement | Tag publié |
|---|---|
| PR ouverte | `pr-{N}` |
| Merge sur `main` | `main` |
| Tag git `1.2.0-dev.1` (avec `-`) | `1.2.0-dev.1` uniquement |
| Tag git `1.2.0` (sans `-`) | `1.2.0` **et** `latest` |

### Convention de commits (Conventional Commits)

Tout commit doit respecter le format `type: description courte`.

Types valides : `feat` `fix` `docs` `style` `refactor` `test` `ci` `chore`

```
feat: formulaire DeployKeyForm dans la vue Accès
fix: correction calcul expiration clé
ci: ajout check Prettier
docs: mise à jour README workflow accès
```

Deux checks CI valident cette convention :
- **Commit messages** (`ci.yml`) — vérifie chaque commit de la PR via `wagoid/commitlint-github-action`
- **PR title** (`pr-title.yml`) — vérifie le titre de la PR via script shell `grep -P`

### Protection de la branche `main`

- Push direct interdit — toute modification passe obligatoirement par une PR
- Les 5 checks CI doivent être verts avant le merge : Tests Python, Tests Vue.js, Prettier, Commit messages, Validate PR title
- Force push bloqué
- Règle appliquée aux administrateurs du dépôt

### Sécurité — Trivy + CodeQL

**Trivy** scanne chaque image Docker de PR à la recherche de CVE CRITICAL et HIGH (Alpine packages, pip, npm). Les résultats sont uploadés dans l'onglet **Security > Code scanning** de GitHub.

**CodeQL** analyse le code Python avec les requêtes `security-extended` à chaque PR, merge sur `main`, et chaque lundi matin. Les alertes apparaissent dans **Security > Code scanning**.

### Mises à jour automatiques — Renovate

Renovate est configuré via `renovate.json` (racine du projet). Il ouvre des PRs chaque lundi avant 9h pour :

- **npm** (`ui/package.json`) — mises à jour groupées ; patch automerge si CI vert
- **pip** (`requirements-test.txt`) — PR groupée, merge manuel
- **Docker** (lignes `FROM` du Dockerfile) — PR groupée, merge manuel

### Formatage du code Vue.js

Prettier est configuré dans `.prettierrc` (racine du projet) :

```json
{ "semi": false, "singleQuote": true, "trailingComma": "es5", "printWidth": 100 }
```

```bash
# Vérifier (CI)
cd ui && npm run format:check

# Formater localement avant de commit
cd ui && npm run format:write
```
