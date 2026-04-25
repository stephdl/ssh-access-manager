---
name: pre-commit
description: Vérifications pré-commit pour ssh-access-manager. Contrôle la syntaxe Python, l'absence de secrets, la cohérence des imports, et que seuls les fichiers attendus pour l'issue en cours sont modifiés.
user-invocable: true
disable-model-invocation: true
---

# Skill pre-commit — ssh-access-manager

## Usage

Invoquer via `/pre-commit` avant chaque `git commit`.

## Étapes

### 1. Inventaire des modifications

```bash
git status --short
git diff --staged --name-only
```

Vérifier que les fichiers modifiés correspondent au périmètre de l'issue en cours. Signaler tout fichier hors périmètre.

### 2. Syntaxe Python

```bash
python3 -m py_compile app/db.py app/servers.py app/ssh.py \
    app/actions.py app/collect.py app/expire.py \
    app/alerts.py app/web.py app/manage.py 2>&1
```

Aucune erreur de syntaxe tolérée.

### 3. Imports cohérents

```bash
# Vérifier que web.py et manage.py importent actions.py
grep "import actions\|from actions\|from app.actions\|from .actions" app/web.py app/manage.py

# Vérifier que personne n'importe web.py depuis un autre module
grep -r "import web\|from web " app/ --include="*.py" | grep -v web.py
```

### 4. Détection de secrets hardcodés

```bash
# Mots de passe en dur
grep -rn "password\s*=\s*['\"][a-zA-Z0-9]" app/ --include="*.py"

# Clés privées
grep -rn "BEGIN.*PRIVATE\|ssh-ed25519 AAAA\|ssh-rsa AAAA" app/ --include="*.py"

# IP hardcodées (hors 127.0.0.1 et 0.0.0.0)
grep -rn "\"[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]" app/ --include="*.py" \
    | grep -v "127.0.0.1\|0.0.0.0"
```

### 5. Sécurité SSH obligatoire

```bash
# AutoAddPolicy interdit
if grep -r "AutoAddPolicy" app/; then
    echo "BLOQUANT : AutoAddPolicy détecté dans app/"
    exit 1
fi

# RejectPolicy présent dans ssh.py
if ! grep -q "RejectPolicy" app/ssh.py; then
    echo "BLOQUANT : RejectPolicy absent de ssh.py"
    exit 1
fi
```

### 6. shell=True interdit

```bash
if grep -rn "shell=True" app/; then
    echo "ATTENTION : shell=True détecté — vérifier si justifié"
fi
```

### 7. Requêtes SQL — pas de f-strings

```bash
grep -n "f['\"].*SELECT\|f['\"].*INSERT\|f['\"].*UPDATE\|f['\"].*DELETE\|f['\"].*DROP" \
    app/db.py app/actions.py app/web.py app/manage.py 2>/dev/null
```

Toute occurrence est bloquante.

### 8. Schéma SQL — intégrité

Si `sql/schema.sql` est modifié :

```bash
# Vérifier que les 6 tables sont présentes
for table in servers administrators ssh_keys key_authorizations access_requests audit_log; do
    if ! grep -q "CREATE TABLE $table" sql/schema.sql; then
        echo "MANQUANT : table $table absente de schema.sql"
    fi
done

# Vérifier is_compliant GENERATED
grep -q "GENERATED ALWAYS AS" sql/schema.sql || echo "MANQUANT : colonne GENERATED"
```

### 9. Frontend — build check

Si des fichiers `ui/` sont modifiés :

```bash
cd ui && npm run build 2>&1 | tail -20
```

Le build doit réussir sans erreur.

### 10. Rapport

```
## Pre-commit check — [date]

Fichiers modifiés : [liste]

Syntaxe Python    : ✅ OK / ❌ Erreurs
Secrets           : ✅ Aucun / ❌ [détail]
RejectPolicy      : ✅ Présent / ❌ MANQUANT
AutoAddPolicy     : ✅ Absent / ❌ DÉTECTÉ
Injection SQL     : ✅ Clean / ❌ [détail]
shell=True        : ✅ Absent / ⚠️ [fichier:ligne]
Schéma SQL        : ✅ Complet / ❌ [détail]
Build frontend    : ✅ OK / ❌ Erreurs / N/A

Verdict : ✅ Prêt pour commit / ❌ Corrections requises
```
