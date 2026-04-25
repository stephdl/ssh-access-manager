---
name: validate-issue
description: Valide qu'une issue ssh-access-manager est complètement implémentée selon les critères d'acceptation de CLAUDE.md avant de la marquer done et de passer à la suivante.
user-invocable: true
disable-model-invocation: true
---

# Skill validate-issue — ssh-access-manager

## Usage

Invoquer via `/validate-issue <N>` où N est le numéro d'issue (1 à 24).

## Critères par issue

### Issue 1 — Schema PostgreSQL (sql/schema.sql)

```bash
# 6 tables présentes
for t in servers administrators ssh_keys key_authorizations access_requests audit_log; do
    grep -q "CREATE TABLE $t" sql/schema.sql && echo "✅ $t" || echo "❌ $t MANQUANT"
done

# Colonne GENERATED
grep -q "GENERATED ALWAYS AS" sql/schema.sql && echo "✅ is_compliant GENERATED" || echo "❌ MANQUANT"

# 6 index présents
for idx in idx_key_auth_status idx_key_auth_expires idx_audit_log_performed_at \
           idx_audit_log_action idx_ssh_keys_compliant idx_ssh_keys_fingerprint; do
    grep -q "$idx" sql/schema.sql && echo "✅ $idx" || echo "❌ $idx MANQUANT"
done

# CHECK constraints sur status
grep -q "PENDING_REVIEW" sql/schema.sql && echo "✅ CHECK status" || echo "❌ CHECK status MANQUANT"
```

### Issue 2 — Dockerfile multi-stage

```bash
grep -q "FROM node:22-alpine AS ui-builder" Dockerfile && echo "✅ Stage 1" || echo "❌ Stage 1"
grep -q "FROM alpine:3.23.4" Dockerfile && echo "✅ Stage 2" || echo "❌ Stage 2"
grep -q "COPY --from=ui-builder" Dockerfile && echo "✅ COPY dist" || echo "❌ COPY dist"
grep -q "postgresql18$" Dockerfile && echo "✅ PG18" || echo "❌ PG18"
grep -q "ENTRYPOINT" Dockerfile && echo "✅ ENTRYPOINT" || echo "❌ ENTRYPOINT"
```

### Issue 3 — supervisord + bootstrap

```bash
# bootstrap.sh
grep -q "PG_VERSION" bootstrap.sh && echo "✅ Détection premier démarrage" || echo "❌"
grep -q "ssh-keygen.*ed25519" bootstrap.sh && echo "✅ Génération clé ED25519" || echo "❌"
grep -q "chmod 600.*collector_key" bootstrap.sh && echo "✅ chmod collector_key" || echo "❌"
grep -q "nginx.conf.template" bootstrap.sh && echo "✅ Génération nginx.conf" || echo "❌"
grep -q "msmtp.conf.template" bootstrap.sh && echo "✅ Génération msmtprc" || echo "❌"
grep -q "collector_key.pub" bootstrap.sh && echo "✅ Affichage clé pub" || echo "❌"
grep -q "exec.*supervisord" bootstrap.sh && echo "✅ exec supervisord" || echo "❌"

# supervisord.conf
grep -q "nodaemon=true" supervisord.conf && echo "✅ nodaemon" || echo "❌"
for prog in postgresql flask nginx crond; do
    grep -q "\[program:$prog\]" supervisord.conf && echo "✅ $prog" || echo "❌ $prog MANQUANT"
done
```

### Issue 4 — docker-compose + configuration

```bash
ls docker-compose.yml .env.example nginx.conf.template msmtp.conf.template \
   crontab provision-host.sh 2>&1
grep -q "audit-collector" provision-host.sh && echo "✅ useradd audit-collector" || echo "❌"
grep -q "sudoers" provision-host.sh && echo "✅ sudoers créé" || echo "❌"
```

### Issue 5 — db.py

```bash
python3 -m py_compile app/db.py && echo "✅ Syntaxe OK" || echo "❌ Erreur syntaxe"
grep -q "def execute" app/db.py && echo "✅ execute()" || echo "❌"
grep -q "def query" app/db.py && echo "✅ query()" || echo "❌"
grep -q "def query_one" app/db.py && echo "✅ query_one()" || echo "❌"
grep -q "POSTGRES_" app/db.py && echo "✅ Connexion via ENV" || echo "❌"
```

### Issue 6 — servers.py

```bash
python3 -m py_compile app/servers.py && echo "✅ Syntaxe OK" || echo "❌"
grep -q "ssh-keyscan" app/servers.py && echo "✅ ssh-keyscan" || echo "❌"
grep -q "ON CONFLICT" app/servers.py && echo "✅ UPSERT" || echo "❌"
grep -q "known_hosts" app/servers.py && echo "✅ known_hosts" || echo "❌"
```

### Issue 7 — ssh.py

```bash
python3 -m py_compile app/ssh.py && echo "✅ Syntaxe OK" || echo "❌"
grep -q "RejectPolicy" app/ssh.py && echo "✅ RejectPolicy" || echo "❌ CRITIQUE"
grep -q "AutoAddPolicy" app/ssh.py && echo "❌ AutoAddPolicy DÉTECTÉ" || echo "✅ Pas d'AutoAddPolicy"
grep -q "SAM_COLLECT" app/ssh.py && echo "✅ SAM_COLLECT" || echo "❌"
grep -q "SAM_REVOKE" app/ssh.py && echo "✅ SAM_REVOKE" || echo "❌"
grep -q "ensure_scripts" app/ssh.py && echo "✅ ensure_scripts()" || echo "❌"
grep -q "revoke_on_server" app/ssh.py && echo "✅ revoke_on_server()" || echo "❌"
grep -q "SCRIPT_DEPLOYED" app/ssh.py && echo "✅ audit SCRIPT_DEPLOYED" || echo "❌"
```

### Issue 8 — actions.py

```bash
python3 -m py_compile app/actions.py && echo "✅ Syntaxe OK" || echo "❌"
for fn in validate_key revoke_key assign_key set_key_expiry remove_key_expiry \
           grant_access approve_request reject_request revoke_request \
           add_server disable_server add_admin disable_admin; do
    grep -q "def $fn" app/actions.py && echo "✅ $fn" || echo "❌ $fn MANQUANT"
done
grep -q "SHA256:" app/actions.py app/ssh.py && echo "✅ fingerprint SHA256" || echo "❌"
```

### Issue 9 — collect.py

```bash
python3 -m py_compile app/collect.py && echo "✅ Syntaxe OK" || echo "❌"
grep -q "ensure_scripts" app/collect.py && echo "✅ ensure_scripts appelé" || echo "❌"
grep -q "ANOMALY_DETECTED" app/collect.py && echo "✅ ANOMALY_DETECTED" || echo "❌"
grep -q "PENDING_REVIEW" app/collect.py && echo "✅ PENDING_REVIEW" || echo "❌"
grep -q "SCAN_COMPLETED\|SCAN_FAILED" app/collect.py && echo "✅ SCAN_COMPLETED/FAILED" || echo "❌"
```

### Issue 10 — expire.py

```bash
python3 -m py_compile app/expire.py && echo "✅ Syntaxe OK" || echo "❌"
grep -q "warn_expiring_keys" app/expire.py && echo "✅ warn_expiring_keys()" || echo "❌"
grep -q "expire_keys" app/expire.py && echo "✅ expire_keys()" || echo "❌"
grep -q "EXPIRY_WARNING" app/expire.py && echo "✅ anti-spam EXPIRY_WARNING" || echo "❌"
grep -q "EXPIRE_WARN_DAYS" app/expire.py && echo "✅ seuil ENV" || echo "❌"
```

### Issue 11 — alerts.py

```bash
python3 -m py_compile app/alerts.py && echo "✅ Syntaxe OK" || echo "❌"
grep -q "def send_alert" app/alerts.py && echo "✅ send_alert()" || echo "❌"
grep -q "msmtp" app/alerts.py && echo "✅ envoi msmtp" || echo "❌"
grep -q "CRITIQUE\|WARNING\|INFO" app/alerts.py && echo "✅ niveaux d'alerte" || echo "❌"
```

### Issue 12 — web.py

```bash
python3 -m py_compile app/web.py && echo "✅ Syntaxe OK" || echo "❌"
# Routes obligatoires
for route in "/api/servers" "/api/keys" "/api/access" "/api/admins" "/api/audit" "/api/system"; do
    grep -q "$route" app/web.py && echo "✅ $route" || echo "❌ $route MANQUANT"
done
grep -q "127.0.0.1" app/web.py && echo "✅ Écoute localhost" || echo "⚠️ Vérifier host Flask"
grep -q "from actions import\|import actions" app/web.py && echo "✅ Import actions" || echo "❌"
```

### Issue 13 — manage.py

```bash
python3 -m py_compile app/manage.py && echo "✅ Syntaxe OK" || echo "❌"
for cmd in "servers" "keys" "access" "admin" "audit" "system"; do
    grep -q "@.*$cmd\|group.*$cmd\|command.*$cmd" app/manage.py && echo "✅ groupe $cmd" || echo "❌ $cmd"
done
grep -q "from actions import\|import actions" app/manage.py && echo "✅ Import actions" || echo "❌"
```

### Issues 14-21 — Frontend Vue.js

```bash
cd ui
# package.json et vite.config.js présents
ls package.json vite.config.js index.html src/main.js src/router/index.js src/App.vue 2>&1

# Vues présentes
for vue in Dashboard ServerDetail Anomalies AccessRequests Audit Admins; do
    ls src/views/${vue}.vue 2>/dev/null && echo "✅ ${vue}.vue" || echo "❌ ${vue}.vue MANQUANT"
done

# Composants présents
for comp in ServerTable KeyTable KeyActions AccessForm ExpiryPicker StatusBadge; do
    ls src/components/${comp}.vue 2>/dev/null && echo "✅ ${comp}.vue" || echo "❌ ${comp}.vue MANQUANT"
done

# Build réussi
npm run build 2>&1 | tail -5
```

## Verdict final

```
Issue N validée ✅ — tous les critères satisfaits. Prêt pour commit.
```
ou
```
Issue N non validée ❌ — [liste des critères manquants]. Corriger avant commit.
```
