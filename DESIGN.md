# DESIGN.md — Justification des choix techniques

**VAE RNCP41330 — Expert en développement logiciel — Niveau 7 — C.1.6**
**Développeur : Stéphane de Labrusse**

---

## 1. Contexte et problème résolu

Les accès SSH aux serveurs de production reposent le plus souvent sur des fichiers
`authorized_keys` gérés manuellement. Ce modèle produit des dérives concrètes :
clés orphelines après départs de collaborateurs, clés sans date d'expiration, clés
non conformes aux recommandations cryptographiques de l'ANSSI, et surtout **aucune
traçabilité** en cas d'incident.

**ssh-access-manager** automatise quatre fonctions qui n'existaient pas :

1. **Collecte** — scan SSH périodique de l'ensemble de la flotte pour inventorier
   les clés effectivement présentes dans chaque `authorized_keys`.
2. **Détection d'anomalies** — comparaison entre l'état collecté et l'état attendu
   en base de données ; toute divergence déclenche une alerte critique.
3. **Révocation** — suppression automatique ou manuelle de clés sur le serveur
   distant, avec piste d'audit immuable.
4. **Conformité ANSSI** — vérification automatique du type et de la taille des clés,
   visualisation immédiate des non-conformités dans l'interface.

---

## 2. Architecture : conteneur unique supervisé

### Décision

Un seul conteneur Alpine Linux 3.23.4 hébergeant quatre processus orchestrés par
Supervisord : PostgreSQL 18, Flask, Nginx et busybox crond.

```
┌─────────────────────────────────────────────────┐
│  Container Alpine 3.23.4                         │
│                                                  │
│  ┌──────────┐   ┌──────────┐   ┌─────────────┐  │
│  │ Nginx    │──▶│ Flask    │──▶│ PostgreSQL  │  │
│  │ :8080    │   │ :5000    │   │ :5432       │  │
│  └──────────┘   └──────────┘   └─────────────┘  │
│       │              │                           │
│       │         ┌────────────┐                   │
│       │         │  crond     │                   │
│       │         │ (4h cycle) │                   │
│       │         └────────────┘                   │
│       │                                          │
│  /app/static/  (Vue.js compilé par Vite)         │
│                                                  │
│  Volume /data/                                   │
│    ├── pg/          (PGDATA)                     │
│    ├── keys/        (clé collecteur ED25519)     │
│    └── config/      (servers.yml)                │
└─────────────────────────────────────────────────┘
```

**Ordre de démarrage Supervisord** (priorité explicite) :

| Priorité | Processus | Raison |
|---|---|---|
| 1 | PostgreSQL | Prérequis de tous les autres |
| 2 | Flask | API REST ; dépend de la base |
| 3 | Nginx | Proxy vers Flask + assets ; dépend de l'API |
| 4 | crond | Jobs périodiques ; dépend de l'API |

### Alternatives évaluées

| Alternative | Rejet |
|---|---|
| Docker Compose multi-services | Réseau inter-conteneurs à gérer ; déploiement plus lourd pour un outil interne |
| Kubernetes / multi-pods | Complexité opérationnelle disproportionnée ; faible charge (dizaines de serveurs, quelques admins) |
| Zabbix / Nagios | Outils génériques de monitoring sans modélisation des autorisations SSH ni workflow de révocation |
| Scripts Bash + cron seuls | Pas de persistance structurée, pas d'API, pas d'interface web, pas de piste d'audit |

### Justification

Le cas d'usage est un outil d'audit interne à faible charge. La simplicité de
déploiement (`podman run`) prime sur la scalabilité horizontale. Le volume unique
`/data` garantit la persistance sans orchestrateur externe. En cas de besoin de
montée en charge, l'extraction de PostgreSQL dans un service dédié reste triviale
(une variable `DATABASE_URL` suffit dans `db.py`).

---

## 3. Build multi-stage Dockerfile

### Décision

```dockerfile
# Stage 1 : build Vue.js
FROM node:22-alpine AS ui-builder
RUN npm ci && npm run build   # produit /ui/dist/

# Stage 2 : image finale
FROM alpine:3.23.4
COPY --from=ui-builder /ui/dist /app/static
```

### Justification

Node.js avec ses dépendances de build représente plus de 300 Mo. L'image finale ne
contient que les fichiers HTML/CSS/JS compilés. Nginx les sert directement sans
passer par Flask, ce qui décharge l'interpréteur Python de toute gestion d'assets
statiques. La séparation des stages garantit également que les outils de build
(npm, node_modules) n'existent pas dans l'image de production, réduisant la surface
d'attaque.

---

## 4. Base de données : PostgreSQL 18

### Décision

PostgreSQL 18 via `apk postgresql18` dans Alpine 3.23.

### Alternatives évaluées

| Alternative | Rejet |
|---|---|
| SQLite | Concurrence limitée ; pas de type `INET`, pas de colonnes `GENERATED` |
| MySQL / MariaDB | Support `JSONB` absent (JSON sans indexation) ; type `INET` absent ; UUID moins natif |
| Redis | Base clé-valeur inadaptée aux relations complexes et aux transactions ACID |

### Justification

PostgreSQL offre plusieurs types natifs décisifs pour ce projet :

- **`INET`** : validation automatique des adresses IPv4 et IPv6 au niveau du SGBD,
  sans contrainte applicative supplémentaire.
- **`JSONB`** : stockage des détails d'audit extensibles sans migration de schéma.
  Les détails d'une action `KEY_REVOKED` (fingerprint, raison) ne sont pas les
  mêmes que ceux d'une `SCAN_COMPLETED` (new, known, disappeared).
- **`GENERATED ALWAYS AS … STORED`** : la colonne `is_compliant` est calculée par
  le SGBD à chaque INSERT/UPDATE, garantissant une cohérence absolue sans jamais
  dépendre de la logique applicative.
- **`gen_random_uuid()`** : identifiants UUID v4 cryptographiquement sûrs, sans
  exposition de séquences incrémentales.
- **`CHECK` constraints** : les valeurs d'`environment` et de `status` sont
  validées à la source, rendant impossibles les états incohérents quelle que soit
  la voie d'accès (API, CLI, accès direct).

---

## 5. Modèle de données : normalisation 3NF

### Les 6 tables

```
administrators ──┐
                 │
servers ─────────┤
                 │
ssh_keys ────────┼──── key_authorizations (PK composite)
                 │
                 ├──── access_requests
                 │
                 └──── audit_log
```

### Démonstration de la 3NF table par table

**1NF** — Valeurs atomiques, clé primaire sur chaque table :
- Toutes les colonnes contiennent des valeurs scalaires (pas de liste, pas de JSON
  sauf `audit_log.details` qui est intentionnel).
- Chaque table a une PK `UUID DEFAULT gen_random_uuid()`.

**2NF** — Dépendance complète à la clé primaire :
- `key_authorizations` utilise une clé composite `(key_id, server_id)`. Chaque
  attribut (`status`, `expires_at`, `revoked_at`, `authorized_by`) dépend du
  *couple* clé+serveur, pas d'un seul de ses membres. Une clé peut être ACTIVE sur
  `server-prod-01` et REVOKED sur `server-prod-02` simultanément.

**3NF** — Absence de dépendances transitives :
- `is_compliant` dépend fonctionnellement de `key_type` et `key_size_bits`, qui
  sont eux-mêmes dans la même table `ssh_keys`. Il n'y a pas de dépendance via une
  clé non-primaire : `id → key_type → is_compliant` serait une violation, mais
  `is_compliant` étant GENERATED directement depuis les colonnes de la ligne, la
  3NF est respectée.

**Dénormalisation intentionnelle et justifiée** :

`is_compliant` est `STORED` (recalculé et physiquement stocké par le SGBD). Ce
choix viole l'esprit de la 3NF (redondance calculable) mais est délibéré pour deux
raisons :
1. L'indexation `idx_ssh_keys_compliant` permet des rapports de conformité de
   flotte en O(log n) au lieu de recalculer pour chaque ligne.
2. La logique de conformité est centralisée au SGBD, imperméable aux évolutions de
   l'application.

### Index et leur justification

```sql
-- Requêtes de filtrage par statut (ACTIVE, PENDING_REVIEW, REVOKED)
CREATE INDEX idx_key_auth_status ON key_authorizations(status);

-- Expiration : index partiel sur les clés qui ont une date d'expiration
-- Évite de scanner les lignes NULL (clés sans expiration = majorité)
CREATE INDEX idx_key_auth_expires ON key_authorizations(expires_at)
    WHERE expires_at IS NOT NULL;

-- Rapports d'audit triés par date décroissante
CREATE INDEX idx_audit_log_performed_at ON audit_log(performed_at DESC);

-- Requêtes filtrées par action ET triées par date (anti-spam EXPIRY_WARNING)
CREATE INDEX idx_audit_log_action ON audit_log(action, performed_at DESC);

-- Rapports de conformité ANSSI de la flotte
CREATE INDEX idx_ssh_keys_compliant ON ssh_keys(is_compliant);

-- Lookup par fingerprint (critère principal des requêtes de révocation)
CREATE INDEX idx_ssh_keys_fingerprint ON ssh_keys(fingerprint);
```

L'index sur `(action, performed_at DESC)` est particulièrement important pour la
fonction anti-spam des alertes d'expiration : la requête vérifie l'existence d'une
entrée `EXPIRY_WARNING` dans les 24 dernières heures pour une clé donnée. Sans cet
index, la requête scanne toute la table `audit_log` à chaque cycle cron.

---

## 6. Sécurité SSH : architecture défensive

### 6.1 RejectPolicy — jamais AutoAddPolicy

**Principe** : toute connexion SSH via paramiko utilise `paramiko.RejectPolicy()`.
La politique `AutoAddPolicy` n'est jamais utilisée.

```python
# ssh.py — _connect()
client = paramiko.SSHClient()
client.load_host_keys("/data/keys/known_hosts")
client.set_missing_host_key_policy(paramiko.RejectPolicy())
client.connect(hostname=ip, username=SSH_USER, ...)
```

**Justification** : `AutoAddPolicy` accepte silencieusement n'importe quelle clé
d'hôte lors de la première connexion, rendant l'outil vulnérable aux attaques
Man-in-the-Middle (un attaquant interpose un serveur SSH entre le collecteur et la
cible). Avec `RejectPolicy`, chaque serveur doit être enregistré préalablement via
`ssh-keyscan` dans `/data/keys/known_hosts`. Toute clé d'hôte inconnue ou modifiée
lève une exception, ce qui est le comportement attendu pour un outil de sécurité.

L'enregistrement est automatisé dans `servers.py` :

```python
subprocess.run(
    ['ssh-keyscan', '-H', '-T', '10', ip],
    capture_output=True, check=True
)
# append dans /data/keys/known_hosts
```

Le flag `-H` hache le nom d'hôte dans `known_hosts` (recommandation ANSSI) ; `-T 10`
impose un timeout pour ne pas bloquer le cycle de scan.

### 6.2 Connexion par IP, jamais par nom DNS

Toutes les connexions SSH utilisent `ip_address` (colonne `INET` de `servers`),
jamais `hostname`. Cette décision évite les attaques par empoisonnement DNS : même
si le DNS est compromis, la connexion cible l'adresse IP vérifiée lors du
provisionnement.

### 6.3 Calcul du fingerprint SHA256

La fonction de calcul est conforme à l'implémentation OpenSSH :

```python
def _compute_fingerprint(key_b64: str) -> str:
    raw = base64.b64decode(key_b64)
    digest = hashlib.sha256(raw).digest()
    b64 = base64.b64encode(digest).decode().rstrip('=')
    return f"SHA256:{b64}"
```

Ce format (`SHA256:<base64-sans-padding>`) est identique à la sortie de
`ssh-keygen -l -E sha256`. L'identification des clés est ainsi cohérente entre
ce que l'outil calcule et ce qu'un administrateur voit avec les outils standard.

### 6.4 Calcul de la taille des clés RSA via le format wire SSH

La taille des clés RSA n'est pas disponible directement dans la représentation
ASCII. Elle est extraite par décodage du format wire SSH (RFC 4253) :

```python
def _parse_rsa_bits(key_b64: str) -> int | None:
    raw = base64.b64decode(key_b64)
    pos = 0
    for _ in range(3):           # 3 champs : type, exposant, modulus
        length = struct.unpack(">I", raw[pos:pos+4])[0]
        pos += 4
        field = raw[pos:pos+length]
        pos += length
    return int.from_bytes(field, "big").bit_length()  # modulus = dernier champ
```

Le troisième champ length-prefixed du wire format est le modulus dont le
`bit_length()` donne exactement la taille de la clé RSA. Cette approche ne dépend
d'aucune bibliothèque cryptographique externe et est testée unitairement avec des
clés 2048 bits et 4096 bits construites manuellement en wire format.

### 6.5 Scripts distants versionnés et hash-déployés

`SAM_COLLECT` et `SAM_REVOKE` sont des constantes Python `bytes` dans `ssh.py`.
Avant chaque déploiement SFTP, leur hash SHA256 est comparé à celui présent sur le
serveur distant :

```python
def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def ensure_scripts(hostname, server_id, ip):
    for script_path, content in SCRIPTS.items():
        stdout, _ = _exec(client, f"sha256sum {script_path}")
        remote_hash = stdout.split()[0] if stdout else ""
        if remote_hash != _sha256(content):
            _sftp_deploy(client, content, script_path)
            db.execute("INSERT INTO audit_log ... 'SCRIPT_DEPLOYED' ...")
```

**Avantages** :
- Redéploiement uniquement si nécessaire (pas de surcoût réseau constant).
- Chaque déploiement est tracé dans `audit_log` avec l'action `SCRIPT_DEPLOYED`.
- Les scripts étant dans le code source Python, leur version est liée à celle de
  l'image Docker ; un `podman pull` met à jour automatiquement les scripts.

`SAM_REVOKE` utilise une réécriture atomique pour éviter la corruption de
`authorized_keys` en cas d'interruption :

```sh
TMPFILE=$(mktemp)
grep -v "$TARGET_FP_HEX" "$FILE" > "$TMPFILE"
if ! diff -q "$TMPFILE" "$FILE" > /dev/null 2>&1; then
    chown $(stat -c "%U:%G" "$FILE") "$TMPFILE"
    mv "$TMPFILE" "$FILE"
fi
rm -f "$TMPFILE"
```

Le `mktemp` + `mv` est atomique au niveau du système de fichiers. Le `chown`
préserve le propriétaire original du fichier avant le remplacement.

---

## 7. Politique de conformité ANSSI (BP-099)

Référence : guide ANSSI « Recommandations pour un usage sécurisé d'OpenSSH »
(ANSSI-BP-099 — dernière version).

| Type | Taille minimale | Conformité | Justification ANSSI |
|---|---|---|---|
| `ssh-ed25519` | N/A (256 bits fixe) | ✅ Toujours | Algorithme moderne, résistant aux attaques sur courbes elliptiques, taille fixe |
| `ssh-rsa` | ≥ 4096 bits | ✅ Si ≥ 4096 | RSA reste acceptable à 4096 bits selon ANSSI ; déconseillé au profit d'Ed25519 |
| `ssh-rsa` | < 4096 bits | ❌ | Trop court selon critères ANSSI actuels |
| `ecdsa-sha2-nistp256` | 256 bits | ⚠️ Accepté | Courbe NIST P-256 : performances acceptables, mais ANSSI préfère Ed25519 |
| DSA | — | ❌ Refusé | Algorithme obsolète, retiré d'OpenSSH 7.0+ |

La conformité est appliquée à **deux niveaux** :

1. **Base de données** : colonne `is_compliant` GENERATED ALWAYS, indexée, garantit
   la cohérence indépendamment de l'application.
2. **Interface** : badge ⚠️ sur chaque clé non conforme dans `KeyTable.vue`, avec
   tooltip affichant la taille de la clé. Un compteur de non-conformités est visible
   dans le Dashboard.

Cette double application empêche qu'une clé non conforme passe inaperçue, quelle
que soit la voie d'accès.

---

## 8. Les 5 scénarios de révocation / détection

Le modèle de données distingue explicitement cinq scénarios de révocation et détection,
chacun traçable par les colonnes `revoked_by`, `revoked_automatically` et le type
d'entrée dans `audit_log`.

### Scénario 1 — Révocation manuelle via le système

**Déclencheur** : administrateur clique sur « Révoquer » dans l'UI ou exécute
`manage.py keys revoke`.

```
actions.revoke_key(fingerprint, admin_id, reason)
  → ssh.revoke_on_server(hostname, fingerprint, ip=ip)
  → UPDATE key_authorizations SET status='REVOKED', revoked_by=admin_id
  → INSERT audit_log('KEY_REVOKED')
  → alerts.send_alert('INFO', ...)
```

**Colonnes discriminantes** : `revoked_by = <UUID admin>`, `revoked_automatically = false`.

### Scénario 2 — Révocation hors système

**Déclencheur** : le scan détecte qu'une clé ACTIVE a disparu de `authorized_keys`
sans avoir été révoquée par le système.

```
collect.scan_server()
  → clé présente en DB avec status=ACTIVE mais absente du scan
  → actions.handle_disappeared_key(key_id, server_id, hostname, ip)
  → UPDATE key_authorizations SET status='REVOKED', revoked_by=NULL,
           revoked_automatically=TRUE
  → INSERT audit_log('ANOMALY_DETECTED')
  → alerts.send_alert('CRITICAL', ...)  # email immédiat
```

**Colonnes discriminantes** : `revoked_by = NULL`, `revoked_automatically = true`.
L'alerte est de niveau **CRITICAL** car une révocation hors système peut indiquer
un accès non autorisé au serveur ou une modification manuelle non tracée.

### Scénario 3 — Clé inconnue détectée

**Déclencheur** : le scan détecte une clé présente sur le serveur mais absente de la
base de données.

```
collect.scan_server()
  → clé absente de ssh_keys
  → actions.handle_unknown_key(key_type, key_size_bits, public_key,
                                fingerprint, comment, server_id, hostname)
  → INSERT ssh_keys (fingerprint, key_type, ...)
  → INSERT key_authorizations (status='PENDING_REVIEW')
  → INSERT audit_log('ANOMALY_DETECTED')
  → alerts.send_alert('CRITICAL', ...)  # email immédiat
```

La clé est mise en `PENDING_REVIEW` (pas révoquée automatiquement) pour permettre
à un administrateur d'examiner si elle est légitime avant décision. L'alerte
CRITICAL garantit que la situation ne passe pas inaperçue.

### Scénario 4 — Expiration programmée

**Déclencheur** : `expire.py` (cron) détecte que `expires_at < NOW()` pour une
clé ACTIVE.

```
expire.expire_keys()
  → SELECT key_authorizations WHERE expires_at < NOW() AND status = 'ACTIVE'
  → ssh.revoke_on_server(hostname, fingerprint, ip=ip)
  → UPDATE key_authorizations SET status='EXPIRED', revoked_automatically=TRUE
  → INSERT audit_log('KEY_EXPIRED')
  → alerts.send_alert('INFO', ...)
```

**Colonnes discriminantes** : `status = 'EXPIRED'`, `revoked_automatically = true`.
Le niveau d'alerte est INFO car l'expiration était attendue et planifiée.

### Scénario 5 — Clé révoquée/expirée réapparue

**Déclencheur** : le scan détecte une clé présente sur le serveur dont le statut
en base est `REVOKED` ou `EXPIRED` — typiquement un `ssh-copy-id` après révocation.

```
collect.scan_server()
  → clé présente dans ssh_keys avec key_authorizations.status IN ('REVOKED','EXPIRED')
  → actions.handle_reappeared_key(key_id, server_id, hostname)
  → UPDATE key_authorizations SET status='PENDING_REVIEW', revoked_at=NULL, ...
  → INSERT audit_log('ANOMALY_DETECTED', reason='revoked_key_reappeared')
  → alerts.send_alert('CRITICAL', ...)  # inclus dans l'email groupé du scan
```

**Pourquoi PENDING_REVIEW et non ACTIVE** : l'administrateur doit décider si la
réapparition est intentionnelle (re-déploiement légitime) ou malveillante (tentative
de contournement d'une révocation). Le niveau CRITICAL garantit que la situation
est traitée.

**Différence avec scénario 3** : la clé est déjà connue en base (`ssh_keys` existe).
Le scénario 3 concerne les clés totalement inconnues.

### Tableau comparatif

| Scénario | `revoked_by` | `revoked_automatically` | `status` | `audit_log.action` | Alerte |
|---|---|---|---|---|---|
| 1 — Manuelle | `UUID admin` | `false` | `REVOKED` | `KEY_REVOKED` | INFO |
| 2 — Hors système | `NULL` | `true` | `REVOKED` | `ANOMALY_DETECTED` | CRITICAL |
| 3 — Clé inconnue | — | — | `PENDING_REVIEW` | `ANOMALY_DETECTED` | CRITICAL |
| 4 — Expiration | `NULL` | `true` | `EXPIRED` | `KEY_EXPIRED` | INFO |
| 5 — Réapparue | — | — | `PENDING_REVIEW` | `ANOMALY_DETECTED` | CRITICAL |

---

## 9. Architecture backend : séparation des responsabilités

### Principe de source unique (Single Source of Truth)

```
┌─────────────────────────────────┐
│  actions.py  (logique métier)   │
│  552 lignes — source unique     │
└───────────────┬─────────────────┘
                │ importé par
       ┌────────┴────────┐
       │                 │
┌──────▼──────┐   ┌──────▼──────┐
│  web.py     │   │  manage.py  │
│  (API REST) │   │  (CLI)      │
│  516 lignes │   │  508 lignes │
└─────────────┘   └─────────────┘
```

`web.py` et `manage.py` sont des **adaptateurs** : ils traduisent respectivement
des requêtes HTTP et des arguments CLI en appels vers `actions.py`. Ils ne
contiennent aucune logique métier propre.

**Conséquence directe** : les tests unitaires `test_actions.py` couvrent la logique
une seule fois. La couverture de 80 % imposée porte spécifiquement sur `actions.py`.
Un bug de révocation corrigé dans `actions.py` est immédiatement corrigé pour
l'API et pour la CLI.

### Module db.py — pool de connexions

```python
# Pool threadé : 1 à 10 connexions
pool = ThreadedConnectionPool(minconn=1, maxconn=10, dsn=DATABASE_URL)

@contextmanager
def _get_conn():
    conn = pool.getconn()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        pool.putconn(conn)
```

Le `@contextmanager` garantit le commit ou le rollback systématique. Trois
helpers couvrent tous les cas d'usage :
- `execute(sql, params)` — INSERT/UPDATE/DELETE sans retour
- `query(sql, params)` — SELECT multiple → liste de dicts
- `query_one(sql, params)` — SELECT unique → dict ou None

`RealDictCursor` est utilisé pour que chaque ligne soit un dictionnaire Python
(`row["fingerprint"]` plutôt que `row[0]`), rendant le code lisible sans mapping.

### Module servers.py — synchronisation déclarative

```python
def sync_from_yaml(yaml_path: str) -> None:
    with open(yaml_path) as f:
        config = yaml.safe_load(f)
    for server in config.get("servers", []):
        db.execute("""
            INSERT INTO servers (hostname, ip_address, environment, os_family)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (hostname) DO UPDATE
            SET ip_address = EXCLUDED.ip_address,
                environment = EXCLUDED.environment
        """, (server["hostname"], server["ip"], ...))
```

L'`INSERT ON CONFLICT DO UPDATE` (upsert) rend la synchronisation idempotente :
appeler `sync_from_yaml` plusieurs fois produit le même résultat qu'une seule fois.
Ajouter un serveur dans `servers.yml` le provisionne lors du prochain démarrage
ou du prochain `manage.py servers scan`.

### Module alerts.py — niveaux d'alerte

Trois niveaux de criticité avec comportements distincts :

| Niveau | Comportement | Cas d'usage |
|---|---|---|
| `CRITICAL` | Email immédiat via msmtp | Clé inconnue détectée, révocation hors système, scan échoué |
| `WARNING` | Email immédiat avec anti-spam 24h | Clé proche de l'expiration (J-7, J-2) |
| `INFO` | Log uniquement | KEY_EXPIRED, KEY_REVOKED, SCAN_COMPLETED |

L'**anti-spam** sur les alertes WARNING est implémenté via une requête sur
`audit_log` :

```python
def _already_warned(key_id, server_id, hours=24):
    cutoff = datetime.now(tz=timezone.utc) - timedelta(hours=hours)
    row = db.query_one("""
        SELECT id FROM audit_log
        WHERE action = 'EXPIRY_WARNING'
          AND target_key = %s
          AND target_server = %s
          AND performed_at > %s
    """, (key_id, server_id, cutoff))
    return row is not None
```

Ce mécanisme utilise `idx_audit_log_action` pour éviter un full scan à chaque
cycle cron. Il garantit qu'une clé qui expire dans 7 jours n'envoie pas un email
toutes les 4 heures.

---

## 10. Cycle de vie complet d'un accès temporaire

Le workflow d'accès temporaire illustre la coordination entre les modules :

```
1. Utilisateur soumet AccessForm.vue
   → POST /api/access/grant
   → actions.grant_access(key_fp, hostname, expires_at, justification, admin_id)
   → INSERT key_authorizations (status='ACTIVE', expires_at=...)
   → INSERT audit_log('REQUEST_APPROVED')

2. Cron (toutes les 4h) — expire.py
   → expire.expire_keys()
   → expires_at < NOW() → sam-revoke sur le serveur
   → UPDATE status='EXPIRED', revoked_automatically=TRUE
   → INSERT audit_log('KEY_EXPIRED')
   → alerts.send_alert('INFO')

3. Si la clé est révoquée avant expiration :
   → actions.revoke_key() → scénario 1
   → UPDATE status='REVOKED', revoked_by=admin_id
```

Les alertes d'avertissement s'intercalent avant l'expiration :

```
J-7 et J-2 : expire.warn_expiring_keys()
  → Anti-spam 24h : si pas d'alerte aujourd'hui
  → alerts.send_alert('WARNING', "Clé expire dans N jours")
  → INSERT audit_log('EXPIRY_WARNING')
```

---

## 11. Frontend Vue.js 3 — architecture des composants

### Composition API et composables

Vue.js 3 avec `<script setup>` est utilisé systématiquement. Le composable
`useAuth.js` encapsule l'état d'authentification partagé entre toutes les vues :

```javascript
// useAuth.js
const admin = ref(null)

async function fetchMe() {
    const resp = await fetch('/api/auth/me')
    if (resp.ok) admin.value = await resp.json()
}

async function login(username, password) {
    const resp = await fetch('/api/auth/login', {
        method: 'POST',
        body: JSON.stringify({ username, password })
    })
    if (resp.ok) await fetchMe()
}
```

**Avantage** : l'état `admin` est réactif et partagé globalement sans Vuex/Pinia.
Toute vue qui importe `useAuth()` accède au même `ref`. Le guard de routeur vérifie
cet état avant chaque navigation.

### Guard de routeur

```javascript
router.beforeEach(async (to) => {
    if (to.meta.public) return true
    if (!admin.value) await fetchMe()
    if (!admin.value) return { name: 'Login' }
})
```

Ce guard est non-bloquant : si `fetchMe()` échoue (session expirée), la
redirection vers Login est automatique. Aucune vue protégée n'est rendue sans
authentification valide.

### Composant ExpiryPicker — modes exclusifs

`ExpiryPicker.vue` illustre la gestion de modes mutuellement exclusifs :

```vue
<script setup>
const mode = ref('hours')  // 'hours' | 'date'
const hours = ref(null)
const date = ref(null)

watch(mode, () => emit('update:modelValue', null))  // reset à chaque changement

const value = computed(() => {
    if (mode.value === 'hours') {
        return hours.value > 0 ? { hours: hours.value } : null
    }
    return date.value && isValidDate(date.value) ? { date: date.value } : null
})
</script>
```

Le `watch(mode)` émet `null` immédiatement lors d'un changement de mode, forçant
le composant parent à désactiver le bouton de soumission jusqu'à ce qu'une valeur
valide soit saisie dans le nouveau mode. Cela évite les soumissions avec des
données du mode précédent.

### Internationalisation (vue-i18n)

5 langues supportées : français, anglais, espagnol, italien, allemand.

```javascript
// main.js
const i18n = createI18n({
    legacy: false,
    locale: localStorage.getItem('lang')
            || navigator.language.slice(0, 2)
            || 'fr',
    messages: { fr, en, es, it, de }
})
```

La détection de langue suit une cascade de priorités :
1. Préférence sauvegardée en `localStorage`
2. Langue du navigateur (premier code ISO 639-1)
3. Français par défaut

Les clés de traduction sont organisées par domaine fonctionnel :
`key_table.btn_validate`, `dashboard.title`, `common.required`, etc.

---

## 12. Stratégie de tests

### Architecture d'isolation totale

La règle fondamentale est qu'aucun test ne contacte une ressource externe réelle.

```
Test                           Mock
────────────────────────────── ─────────────────────────────
test_actions.py                patch("actions.db")
                               patch("actions.ssh")
                               patch("actions.alerts")

test_web.py                    auth_client (session Flask)
                               patch("web.db")
                               patch("web.actions")

test_ssh.py                    patch("ssh._connect")
                               patch("ssh.paramiko.SSHClient")

test_expire.py                 patch("expire.db")
                               freeze_time("2026-01-15 12:00:00")

test_alerts.py                 patch("subprocess.run")
```

### Fixtures partagées (conftest.py)

```python
@pytest.fixture
def sample_server():
    return {
        "id": str(uuid.uuid4()),
        "hostname": "server-test-01",
        "ip_address": "192.168.1.10",
        "environment": "lab",
        "is_active": True,
    }

@pytest.fixture
def sample_key():
    public_key = "ssh-ed25519 AAAA... user@host"
    b64 = public_key.split()[1]
    return {
        "public_key": public_key,
        "fingerprint": _compute_fingerprint(b64),
        "key_type": "ssh-ed25519",
    }
```

Les fixtures fournissent des données cohérentes à travers tous les modules de
tests. Le fingerprint est calculé dynamiquement (pas codé en dur) pour rester
cohérent avec l'implémentation réelle.

### Authentification dans test_web.py

Flask utilise l'authentification par session (pas Basic Auth). Les tests utilisent
`session_transaction()` pour injecter directement un `admin_id` valide :

```python
@pytest.fixture
def auth_client(client):
    with client.session_transaction() as sess:
        sess["admin_id"] = ADMIN_ID
        sess["admin_username"] = "admin"
    return client
```

`require_auth` vérifie `session.get("admin_id")` — si présent, la requête est
autorisée sans passer par la base de données. Cela isole le test du middleware
d'authentification.

### Tests RSA en wire format

Les tests de parsing de taille de clés RSA construisent des clés syntaxiquement
correctes en format wire SSH sans dépendance à une bibliothèque cryptographique :

```python
def _make_rsa_b64(bits: int) -> str:
    key_type = b"ssh-rsa"
    exponent = b"\x01\x00\x01"  # 65537
    # \x00\x80 + (bits//8 - 1) zéros → bit_length() == bits exactement
    modulus = b"\x00" + b"\x80" + b"\x00" * (bits // 8 - 1)

    def pf(data):
        return struct.pack(">I", len(data)) + data

    return base64.b64encode(pf(key_type) + pf(exponent) + pf(modulus)).decode()
```

Cette approche teste la logique de parsing sans générer de vraies clés RSA (opération
coûteuse en temps).

### Métriques de couverture

| Module | Tests | Couverture |
|---|---|---|
| `actions.py` | 60+ | ≥ 80 % (imposé CI) |
| `test_ssh.py` | 15 | RejectPolicy, ensure_scripts, revoke, SAM_REVOKE content |
| `test_web.py` | 16 | Toutes les routes critiques, auth 401/200 |
| `test_manage.py` | 25 | Toutes les commandes CLI |
| `test_collect.py` | 15 | 4 scénarios détection, RSA parsing |
| `test_expire.py` | 12 | Anti-spam 24h, expiration auto |
| Vue.js specs | 70 | KeyActions, ExpiryPicker, AccessForm, KeyTable, ServerTable |

---

## 13. CI/CD — GitHub Actions

### 5 workflows et leur rôle

```
.github/workflows/
  ci.yml             ← Tests sur chaque PR (pytest + vitest)
  build-pr.yml       ← Image Docker pr-{N} sur GHCR
  build-main.yml     ← Image Docker :main à chaque merge
  publish-release.yml← Image semver stable/beta
  cleanup-pr.yml     ← Suppression de pr-{N} à la fermeture
```

**`ci.yml`** — qualité porte d'entrée :
- `tests-python` : pytest avec `--cov=actions --cov-fail-under=80` ; échec si
  couverture < 80 %
- `tests-vue` : `npx vitest run` ; les deux jobs sont parallèles

**Stratégie de tags Docker** :

| Événement | Tag GHCR |
|---|---|
| Push sur PR | `pr-{N}` |
| Merge sur `main` | `main` |
| Tag git `1.0.0-dev.1` (avec `-`) | `1.0.0-dev.1` uniquement |
| Tag git `1.0.0` (sans `-`) | `1.0.0` **+** `latest` |

La détection stable/beta repose sur la présence d'un tiret dans le tag :

```bash
if [[ "$TAG" == *"-"* ]]; then
    # pre-release : tag seul
    docker build -t "$IMAGE:$TAG" .
else
    # stable : tag + latest
    docker build -t "$IMAGE:$TAG" -t "$IMAGE:latest" .
fi
```

**Nettoyage GHCR** (`cleanup-pr.yml`) : à la fermeture d'une PR, l'image `pr-{N}`
est supprimée via l'API GitHub Packages pour ne pas accumuler d'images orphelines.

### Cache pip avec requirements-test.txt

```yaml
- uses: actions/setup-python@v5
  with:
    python-version: '3.12'
    cache: 'pip'
    cache-dependency-path: requirements-test.txt
```

`requirements-test.txt` contient l'ensemble des dépendances (production + test).
Le cache pip GitHub Actions est invalidé uniquement quand ce fichier change, ce
qui réduit le temps de CI de ~30 s par run en régime stable.

---

## 14. Bootstrap et idempotence

### Détection du premier démarrage

```bash
if [ ! -f /data/pg/PG_VERSION ]; then
    # Premier démarrage — initialisation complète
    mkdir -p /data/keys /data/pg /data/config
    chown postgres:postgres /data/pg && chmod 700 /data/pg  # AVANT initdb
    ssh-keygen -t ed25519 -f /data/keys/collector_key -N ""
    initdb -D /data/pg -E UTF8 --locale=C
    # ... start pg, createdb, apply schema, insert admin, stop pg
fi
# Toujours : régénérer les configs depuis ENV
generate_nginx_conf
generate_msmtprc
exec supervisord
```

Le `chown postgres:postgres /data/pg` **avant** `initdb` est un ordre critique :
`initdb` échoue si le répertoire PGDATA n'appartient pas à l'utilisateur `postgres`.
Sur les volumes Docker/Podman, le répertoire créé par `mkdir` appartient à `root`.

### Régénération des configs à chaque démarrage

`nginx.conf` et `/etc/msmtprc` sont régénérés depuis les templates et les variables
d'environnement **à chaque démarrage**, y compris les redémarrages. Cette approche
permet de modifier `NGINX_PORT` ou `SMTP_HOST` sans reconstruire l'image — un
`podman stop` + `podman start` avec les nouvelles variables suffit.

---

## 15. Tableau de synthèse des décisions techniques

| Décision | Justification | Compromis accepté |
|---|---|---|
| Conteneur unique | Déploiement simplifié (`podman run`) | Non scalable horizontalement |
| PostgreSQL 18 | INET, JSONB, GENERATED, UUID natifs | Plus lourd que SQLite |
| GENERATED `is_compliant` | Conformité garantie par le SGBD | Redondance physique (3NF relaxée) |
| `RejectPolicy` | Prévention MITM | Provisionnement manuel des hôtes |
| Connexion par IP | Immunité aux attaques DNS | Gestion séparée des noms/IPs |
| Wire format RSA | Pas de dépendance cryptographique externe | Complexité du parsing |
| `actions.py` centralisé | Source unique de vérité CLI+API | Import circulaire impossible |
| Multi-stage Dockerfile | Image finale sans Node.js | Build légèrement plus lent |
| Session Flask | Simplicité d'implémentation | Pas de support multi-device/token |
| JSONB audit details | Extensibilité sans migration | Données non structurées en DB |
| Réécriture atomique SAM_REVOKE | `authorized_keys` jamais corrompu | Complexité du script shell |
| Anti-spam audit_log | Pas de flood d'emails expiration | Index supplémentaire requis |
| vue-i18n 5 langues | Accessibilité internationale | 5 fichiers JSON à synchroniser |
| `freeze_time` tests | Déterminisme des tests d'expiration | Dépendance à `freezegun` |
| Tag semver sans `v` | Uniformité git tag = Docker tag | Convention moins répandue |

---

## 16. Bilan

ssh-access-manager démontre l'application cohérente de plusieurs principes
d'ingénierie logicielle niveau 7 :

- **Séparation des préoccupations** : chaque module a une responsabilité unique et
  délimitée (db, ssh, actions, collect, expire, alerts, web, manage).
- **Défense en profondeur** : sécurité SSH (RejectPolicy + keyscan + IP directe),
  conformité ANSSI (DB + UI), audit immuable (INSERT uniquement sur `audit_log`).
- **Idempotence** : sync YAML, keyscan, bootstrap, déploiement de scripts.
- **Traçabilité complète** : les 4 scénarios de révocation sont distingués par des
  colonnes dédiées et des entrées `audit_log` de types différents.
- **Qualité mesurée** : couverture ≥ 80 % imposée par CI, 226 tests (156 Python +
  70 Vue.js), isolation totale.
- **Déploiement continu** : 5 workflows GitHub Actions (tests, build PR, build main,
  publication semver, nettoyage GHCR).
