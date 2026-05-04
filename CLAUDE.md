# CLAUDE.md — ssh-access-manager

## Contexte

Projet "ssh-access-manager" — audit et gestion des accès SSH dans un container Alpine Linux unique.
VAE RNCP41330 "Expert en développement logiciel" Niveau 7 — C.1.6.
Développeur : Stéphane de Labrusse.

## État du projet — toutes issues fermées (69/69)

Milestone 1–4 + issues supplémentaires (25, 51–54, 61–62, 70–71, 73–74, 80, 82, 86, 88–89, 108, 110, 112, 114, 116, 119, 127, 129, 133, 137, 139–140, 143, 145–148, 181, 183, 185, 222, 223, 228, 230, 236, 239, 253, 257, 259, 260, 299, 301, 302, 303, 312, 314, 320, 322, 324, 326, 328, 330, 332, 335, 337, 339) ✅

## Stack vérifiée et figée

Image finale : **alpine:3.23.4**
- PostgreSQL 18, Python 3.12, Supervisor, Nginx, msmtp, openssh-client, busybox crond, wget, tzdata
- pip : flask, click, paramiko, psycopg2-binary, pyyaml, werkzeug

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
- keys/ — collector_key (chmod 600, chown nobody), collector_key.pub, known_hosts (chmod 644, chown nobody)
- pg/ — PGDATA (chown postgres:postgres, chmod 700)
- config/servers.yml — liste déclarative des serveurs

Nginx : `/api/` → proxy Flask, `/` → /app/static (SPA). Pas de Basic Auth (supprimé — #54).

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
FLASK_SECRET_KEY=changeme
SMTP_HOST  SMTP_PORT=587  SMTP_USERNAME  SMTP_PASSWORD  SMTP_FROM
SMTP_ENCRYPTION=starttls  SMTP_TLSVERIFY=1  SMTP_ENABLED=1
SSH_USER=audit-collector
ADMIN_USERNAME=admin  ADMIN_EMAIL  ADMIN_PASSWORD=admin
```

Notes : pas de NGINX_USER/NGINX_PASSWORD (#54). Pas de TZ (UTC en base, conversion navigateur — #228).
Pas de EXPIRE_WARN_DAYS* (configurables en base via settings — #230).
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
