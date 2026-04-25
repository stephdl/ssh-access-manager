---
name: review
description: Revue de code complète du projet ssh-access-manager. Vérifie la conformité avec CLAUDE.md, la cohérence entre CLI et API, la sécurité (RejectPolicy, injections, secrets), et les critères d'acceptation de l'issue en cours.
user-invocable: true
disable-model-invocation: false
---

# Skill review — ssh-access-manager

## Déclenchement

Invoqué automatiquement après chaque implémentation d'issue, ou manuellement via `/review`.

## Étapes de revue

### 1. Identifier l'issue en cours

```bash
git log --oneline -5
git diff HEAD~1 --name-only
```

Lister les fichiers modifiés depuis le dernier commit.

### 2. Vérifier la conformité structurelle

Lire les fichiers modifiés et vérifier :

- **db.py** : helpers `execute`, `query`, `query_one` présents ; pas de SQLAlchemy ; psycopg2 avec paramètres `%s`
- **servers.py** : `ssh-keyscan -H -T 10` utilisé ; `INSERT ... ON CONFLICT DO UPDATE` présent
- **ssh.py** : `paramiko.RejectPolicy()` présent ; constantes `SAM_COLLECT` et `SAM_REVOKE` définies ; déploiement via SFTP + sudo mv
- **actions.py** : toutes les fonctions du contrat présentes ; pas de duplication avec web.py ou manage.py
- **collect.py** : les 4 scénarios de révocation implémentés ; `ANOMALY_DETECTED` émis correctement
- **expire.py** : anti-spam 24h présent ; seuils depuis ENV (`EXPIRE_WARN_DAYS`, `EXPIRE_WARN_DAYS_2`)
- **web.py** : toutes les routes `/api/` présentes ; retour JSON uniquement ; écoute sur `127.0.0.1:5000`
- **manage.py** : toutes les commandes présentes ; `--help` disponible ; output tabulaire

### 3. Vérifier la sécurité

```bash
# Détecter AutoAddPolicy (interdit)
grep -r "AutoAddPolicy" app/

# Détecter shell=True (interdit sauf justification)
grep -r "shell=True" app/

# Détecter les f-strings dans les requêtes SQL (injection)
grep -r "f\".*SELECT\|f\".*INSERT\|f\".*UPDATE\|f\".*DELETE" app/

# Détecter les secrets hardcodés
grep -r "password\s*=\s*['\"][^{]" app/
grep -r "secret\s*=\s*['\"][^{]" app/
```

### 4. Vérifier la cohérence CLI/API

Pour chaque fonction dans `actions.py` :
- Vérifier qu'elle est appelée dans `web.py` pour la route correspondante
- Vérifier qu'elle est appelée dans `manage.py` pour la commande correspondante
- Vérifier qu'elle n'est pas réimplémentée inline dans web.py ou manage.py

### 5. Vérifier le fingerprint SHA256

```bash
grep -A5 "compute_fingerprint" app/ssh.py app/actions.py app/collect.py
```

L'implémentation doit correspondre exactement à :
```python
raw = base64.b64decode(key_b64)
digest = hashlib.sha256(raw).digest()
b64 = base64.b64encode(digest).decode().rstrip('=')
return f"SHA256:{b64}"
```

### 6. Vérifier les types de clés acceptés

```bash
grep -r "key_type" app/
```

Seuls ces types sont valides : `ssh-ed25519`, `ssh-rsa`, `ecdsa-sha2-nistp256`.

### 7. Rapport final

Produire un rapport structuré :

```
## Revue Issue N — [titre]

### Fichiers revus
- app/xxx.py

### Conformité CLAUDE.md
✅ Conforme / ❌ Non conforme — [détail]

### Sécurité
✅ Pas d'AutoAddPolicy
✅ Pas de shell=True
✅ Pas d'injection SQL
[ou ❌ avec détail]

### Cohérence CLI/API
✅ Pas de duplication / ❌ [détail]

### Problèmes bloquants
[liste ou "Aucun"]

### Verdict
✅ Issue N validée — prête pour commit
❌ Issue N — corrections requises avant commit
```
