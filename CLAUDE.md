# CLAUDE.md — ssh-access-manager

## Contexte

Projet "ssh-access-manager" — audit et gestion des accès SSH dans un container Alpine Linux unique.
VAE RNCP41330 "Expert en développement logiciel" Niveau 7 — C.1.6.
Développeur : Stéphane de Labrusse.

## État du projet — toutes issues fermées (89/89)

Milestone 1–4 + issues supplémentaires (25, 51–54, 61–62, 70–71, 73–74, 80, 82, 86, 88–89, 108, 110, 112, 114, 116, 119, 127, 129, 133, 137, 139–140, 143, 145–148, 181, 183, 185, 222, 223, 228, 230, 236, 239, 253, 257, 259, 260, 299, 301, 302, 303, 312, 314, 320, 322, 324, 326, 328, 330, 332, 335, 337, 339, 343, 345, 346, 348, 350, 352, 354, 357, 360, 361, 363, 365, 367, 368, 378, 380, 383, 384, 386, 392) ✅

## Stack vérifiée et figée

Image finale : **alpine:3.23.4**
- PostgreSQL 18, Python 3.12, Supervisor, Nginx, msmtp, openssh-client, busybox crond, wget, tzdata
- pip : flask, click, paramiko, psycopg2-binary, pyyaml, werkzeug, waitress

Stage build UI : **node:24-alpine**
- Vue.js 3 (^3.4), vue-router (^4.3), vue-i18n (^9.14 — 5 langues : EN/FR/ES/IT/DE), Vite
- Produit /ui/dist/ copié dans /app/static/

## Architecture — container unique

Supervisord orchestre :
- PostgreSQL 18 (user=postgres, priority=1)
- Flask sur 127.0.0.1:5000 (user=nobody, priority=2)
- Nginx — sert /app/static/ + proxy /api/ → Flask (priority=3)
- busybox crond — scan + expiration toutes les X heures (priority=4)

Volume unique /data/ :
- keys/per-server/ — keypairs ed25519 par serveur (`<uuid>.key{,.pub}`, chmod 600, chown nobody, commentaire SSH vide), répertoire chmod 700 (#402)
- keys/known_hosts — chmod 644, chown nobody
- pg/ — PGDATA (chown postgres:postgres, chmod 700)
- config/servers.yml — liste déclarative des serveurs

Nginx : `/api/` → proxy Flask, `/` → /app/static (SPA). Pas de Basic Auth (supprimé — #54).

## Modèle SAM sudo groups (#383, #384)

Trois groupes Unix dédiés sont créés par `provision-host.sh` sur chaque serveur géré : `sam-operator`, `sam-pkg`, `sam-root`. Les règles sudoers SAM associées (chmod 440, validées avec `visudo -c`) exigent `PASSWD:` (jamais NOPASSWD) et fixent `secure_path` incluant `/usr/local/bin`.

Un quatrième groupe `sam-users` regroupe tous les utilisateurs Unix créés via `sam-add`. Le bloc sshd `Match Group sam-users` interdit l'authentification par mot de passe — ces utilisateurs ne peuvent se connecter qu'avec leur clé SSH publique. À la création, `sam-add` génère un mot de passe temporaire (`openssl rand -base64 12`), le set via `chpasswd`, écrit `~/README_first_login.txt` (chmod 600) et `~/.profile` invoque `passwd` automatiquement au premier login pour forcer le changement.

Le compte `root` est protégé : non-déployable, non-révocable, non-promotable en groupe SAM. La colonne `key_authorizations.sam_group` (VARCHAR(20), CHECK IN sam-operator/sam-pkg/sam-root, audit v4) trace le groupe assigné. Routes : `POST /api/access/grant-group`, `POST /api/access/revoke-group`, `PUT /api/access/change-group`. La promotion en `sam-root` est réservée au rôle `sysadmin`.

## Per-server collector SSH keys (#402)

Plus de clé SSH globale. À l'ajout d'un serveur, SAM génère une paire ed25519 distincte stockée dans `/data/keys/per-server/<uuid>.key{,.pub}` (chmod 600, owner `nobody`, commentaire SSH vide pour anonymiser le fichier). Le mapping serveur ↔ clé est implicite via le nom de fichier (UUID v4 random) — pas de fingerprint stocké en base. Threat model : un vol de la BDD seule ne révèle aucune clé privée ; un vol du filesystem seul donne N fichiers anonymes non corrélables aux hôtes. Une exploitation utile exige donc **deux compromissions distinctes**.

Workflows d'ajout (cf. README) :
- **UI / CLI `servers add`** avec password : SAM provisionne tout, password jamais stocké
- **CLI `servers register/show --pubkey/activate`** : 3 étapes pour pousser la pubkey avec sa propre clé SSH root (cloud-init, bulk)
- Rotation manuelle atomique avec rollback via bouton **Rotate collector key** (sysadmin)
- Audit dédié : `COLLECTOR_KEY_GENERATED`, `COLLECTOR_KEY_ROTATED`, `COLLECTOR_KEY_ROTATION_FAILED`

`servers.is_provisioned BOOLEAN DEFAULT FALSE` distingue « registered, pas encore activé » de « actif ».

## Hostname rename (#403)

`actions.update_server(..., new_hostname=...)` accepte une nouvelle valeur de hostname, valide RFC 1123, refuse les doublons, écrit un audit `SERVER_RENAMED {old_hostname, new_hostname}`. Les entrées d'audit historiques ne sont jamais réécrites — elles préservent le hostname en vigueur au moment de l'événement. L'UI redirige automatiquement vers `/servers/<new>` après save (router-view `:key` force le remount).

## Modules Python — responsabilités

**Règle absolue : la logique métier est dans actions.py. web.py et manage.py importent actions.py. Jamais de duplication entre CLI et API.**

| Fichier | Rôle |
|---------|------|
| db.py | connexion + helpers PostgreSQL |
| servers.py | parsing servers.yml + sync BDD + paramiko.Transport known_hosts |
| ssh.py | connexion paramiko + scripts distants (SAM_*) + revoke/lock/unlock |
| actions.py | logique métier pure (partagée CLI+API) |
| collect.py | orchestration scan complet |
| expire.py | warn J-7/J-2 + révocation auto |
| alerts.py | envoi emails via msmtp |
| web.py | Flask API REST JSON |
| manage.py | CLI click |

Voir `app/CLAUDE.md` pour la logique détaillée (bootstrap, scénarios, RBAC, tests).
Voir `ui/CLAUDE.md` pour le frontend Vue.js (vues, composants, i18n, tests Vitest).

## Variables d'environnement

```
POSTGRES_DB=ssh_manager  POSTGRES_USER=ssh_manager  POSTGRES_PASSWORD=changeme
NGINX_PORT=8080
NGINX_TLS_CERT_PATH=/data/certs/server.crt  NGINX_TLS_KEY_PATH=/data/certs/server.key  (optional — enables HTTPS)
FLASK_SECRET_KEY=changeme
SMTP_HOST  SMTP_PORT=587  SMTP_USERNAME  SMTP_PASSWORD  SMTP_FROM
SMTP_ENCRYPTION=starttls  SMTP_TLSVERIFY=1  SMTP_ENABLED=1
SSH_USER=audit-collector
ADMIN_USERNAME=admin  ADMIN_EMAIL  ADMIN_PASSWORD=admin
```

Notes : pas de NGINX_USER/NGINX_PASSWORD (#54). Pas de TZ (UTC en base, conversion navigateur — #228).
Pas de EXPIRE_WARN_DAYS* (configurables en base via settings — #230).
NGINX_TLS_CERT_PATH / NGINX_TLS_KEY_PATH : optionnel — si les deux sont définis, Nginx passe en HTTPS (TLSv1.2/1.3, chiffrement fort). Un certificat auto-signé est généré automatiquement si les fichiers n'existent pas.
SMTP_ENCRYPTION : `none` / `starttls` / `tls` — contrôle le mode TLS de msmtp.
SMTP_USERNAME : si vide → `auth off` dans msmtp (relay sans authentification).
SMTP_TLSVERIFY : `1` (on) / `` (off) — vérifie les certificats TLS.
SMTP_ENABLED : `1` / `` (off) — désactive l'envoi d'emails si vide.

## Langue du code — English only

**Règle absolue : tout le code est en anglais.**
- Noms de variables, fonctions, classes, constantes : anglais
- Commentaires inline et docstrings : anglais
- Messages CLI (`click.echo`, `ClickException`) : anglais
- Scripts shell (commentaires `#`) : anglais

Seules exceptions autorisées : fichiers de traduction `ui/src/locales/` (FR/ES/IT/DE) et ce fichier CLAUDE.md.

## Convention commits — Conventional Commits

Format : `type: description courte`
Types valides : feat, fix, docs, style, refactor, test, ci, chore, perf, build, revert
Deux checks CI : commitlint (wagoid/commitlint-github-action@v6) + pr-title.yml (grep -P shell).

## Formatage — Prettier

.prettierrc : semi=false, singleQuote=true, trailingComma=es5, printWidth=100.
Ignorés : ui/dist/, ui/node_modules/, *.lock.
`npm run format:check` (CI) / `npm run format:write` (dev local).

## CI/CD

| Workflow | Déclencheur | Action |
|----------|-------------|--------|
| ci.yml | PR | pytest ≥ 80% + vitest + prettier + commitlint |
| pr-title.yml | PR | validation titre Conventional Commits |
| build-pr.yml | PR | build + push image pr-{N} + Trivy |
| build-main.yml | merge main | build + push :main GHCR |
| publish-release.yml | tag git | build + push :vX.Y.Z (+ :latest) |
| cleanup-pr.yml | fermeture PR | suppression image pr-{N} |
| codeql.yml | PR + main + hebdo lundi | analyse statique Python |

Protection main : PR obligatoire, 5 checks requis, force push bloqué, enforce_admins=true.

## Renovate

renovate.json — périmètre : npm, pip, Dockerfile.
Lundi avant 9h (Europe/Paris). Label : dependencies.
npm patch : automerge si CI vert. npm minor/major + pip + Docker : PR manuelle (groupées).
