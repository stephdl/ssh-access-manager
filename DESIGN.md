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
FROM node:24-alpine AS ui-builder
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

L'image finale atteint environ 165–190 Mo, contre 400–500 Mo pour une base Python:3.12
Debian équivalente — une réduction de 60 % de l'empreinte de stockage sur GHCR et de
la bande passante consommée à chaque déploiement. Le choix de `alpine:3.23.4` comme
base de production (~7 Mo vs ~77 Mo pour Ubuntu) et l'utilisation systématique de
`--no-cache` sur `apk` et `--no-cache-dir` sur `pip` participent à cette réduction.
Ces pratiques relèvent de l'écoconception logicielle : à fonctionnalité égale, une
image plus légère consomme moins de ressources réseau, de stockage registre et de
mémoire à l'exécution.

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
- `key_authorizations` utilise une clé composite `(key_id, server_id, unix_user)`.
  Chaque attribut (`status`, `expires_at`, `revoked_at`, `authorized_by`) dépend du
  *triplet* clé+serveur+utilisateur, pas d'un seul de ses membres. La même clé peut
  être ACTIVE pour `alice` et REVOKED pour `root` sur le même serveur (issue #185).

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

`SAM_COLLECT`, `SAM_REVOKE`, `SAM_ADD`, `SAM_LOCK_USER` et `SAM_UNLOCK_USER` sont
des constantes Python `bytes` dans `ssh.py`. Avant chaque déploiement SFTP, leur
hash SHA256 est comparé à celui présent sur le serveur distant :

```python
def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def ensure_scripts(hostname, server_id, ip):
    scripts = (
        (SAM_COLLECT, SAM_COLLECT_PATH),
        (SAM_REVOKE, SAM_REVOKE_PATH),
        (SAM_ADD, SAM_ADD_PATH),
        (SAM_LOCK_USER, SAM_LOCK_USER_PATH),
        (SAM_UNLOCK_USER, SAM_UNLOCK_USER_PATH),
    )
    for content, remote_path in scripts:
        remote_hash = _remote_sha256(client, remote_path)
        if remote_hash != _sha256(content):
            tmp_path = f"/home/{SSH_USER}/{os.path.basename(remote_path)}"
            sftp.putfo(io.BytesIO(content), tmp_path)
            _run(client, f"sudo /usr/bin/install -m 750 -o root -g root {tmp_path} {remote_path}")
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
tmp=$(mktemp /tmp/sam-XXXXXX)
while IFS= read -r line || [ -n "$line" ]; do
    fp=$(printf '%s\n' "$line" | ssh-keygen -l -E sha256 -f /dev/stdin 2>/dev/null | awk '{print $2}')
    [ "$fp" = "$TARGET_FP" ] && changed=1 || printf '%s\n' "$line" >> "$tmp"
done < "$keyfile"
if [ "$changed" -eq 1 ]; then
    chown "$(stat -c '%u:%g' "$(dirname "$keyfile")")" "$tmp"
    mv "$tmp" "$keyfile"
fi
```

Le `mktemp` + `mv` est atomique au niveau du système de fichiers. La comparaison se fait par fingerprint SHA256 via `ssh-keygen -l -E sha256` (pas par regex sur la clé brute). Le `chown` préserve le propriétaire du répertoire parent avant le remplacement.

### 6.6 Modèle SAM sudo groups (issues #383, #384)

Trois groupes Unix prédéfinis sont créés sur chaque serveur par `provision-host.sh` pour structurer les privilèges sudo des utilisateurs déployés via `sam-add` :

| Groupe | Périmètre sudo | Rôle minimal requis |
|---|---|---|
| `sam-operator` | Commandes d'exploitation (systemctl, journalctl, etc.) | operator |
| `sam-pkg` | Gestion paquets (dnf, apt) | operator |
| `sam-root` | Accès root équivalent | sysadmin uniquement |

**Invariants sécurité** :

- Toutes les règles sudoers SAM utilisent `PASSWD:` — **jamais `NOPASSWD:`** (contrairement à `audit-collector` qui reste `NOPASSWD` car SAM authentifie via la clé). L'utilisateur doit saisir son mot de passe personnel (défini au premier login) pour `sudo`.
- `secure_path` est explicitement défini pour inclure `/usr/local/bin` afin que les outils NS8 (`runagent`, `api-cli`) soient résolvables.
- Chaque fichier sudoers est **validé par `visudo -c` avant installation** : une règle invalide est rejetée sans casser la config sudo existante.
- Le compte `root` est **non-promotable** : `actions.deploy_key()`, `grant_group()` et `change_group()` lèvent `UserError` si `unix_user == 'root'` ou si une entrée audit `unix_user='root'` correspond au fingerprint visé.

Le cycle de vie est tracé par la colonne `key_authorizations.sam_group` (VARCHAR(20) nullable, contrainte `CHECK IN ('sam-operator','sam-pkg','sam-root')`, schéma audit v4) et par les événements `audit_log` `GROUP_GRANTED` / `GROUP_REVOKED` / `GROUP_CHANGED`. Les scripts distants `sam-grant-group <user> <group>` (`gpasswd -a`) et `sam-revoke-group <user> <group>` (`gpasswd -d ... || true`, idempotent) appliquent les changements à chaud — fonctionne même quand l'utilisateur est connecté en SSH.

Routes Flask correspondantes :
- `POST /api/access/grant-group` — operator pour sam-operator/sam-pkg, sysadmin pour sam-root
- `POST /api/access/revoke-group` — operator sauf si le groupe actuel est sam-root (sysadmin requis)
- `PUT /api/access/change-group` — sysadmin requis si sam-root est l'ancien **ou** le nouveau groupe

### 6.7 Premier login d'un utilisateur SAM et blocage du mot de passe SSH

Les utilisateurs Unix créés par `sam-add` ne doivent **jamais** pouvoir se connecter en SSH par mot de passe. Deux mécanismes l'empêchent :

1. Tous les comptes créés par `sam-add` sont ajoutés au groupe `sam-users` (via `usermod -aG sam-users`).
2. `provision-host.sh` installe dans `/etc/ssh/sshd_config.d/50-sam-users.conf` un bloc `Match Group sam-users` durci (chmod 600, root:root) :

```
Match Group sam-users
    PasswordAuthentication no
    PermitEmptyPasswords no
    KbdInteractiveAuthentication no
    PubkeyAuthentication yes
    AuthenticationMethods publickey
```

`AuthenticationMethods publickey` est la défense en profondeur : même si une autre méthode (PAM, keyboard-interactive…) est globalement activée, sshd ignore tous les autres mécanismes pour ce groupe et exige une clé publique. Après écriture, `provision-host.sh` exécute `sshd -t` ; si la validation échoue, le fichier précédent (sauvegardé en `.bak`) est restauré et le script sort en erreur sans recharger sshd — aucune config invalide n'est jamais activée.

Conséquence : seule la clé SSH publique déployée permet la connexion. Le mot de passe Unix sert uniquement à `sudo` (règles SAM `PASSWD:`).

Pour activer la saisie d'un mot de passe personnel sans bloquer la première lecture du README, `sam-add` à la création applique cette séquence :

```sh
# Génération d'un mot de passe temporaire 12 caractères base64
temp_pw=$(openssl rand -base64 12)
echo "${unix_user}:${temp_pw}" | chpasswd

# Écriture du README dans le home utilisateur (chmod 600)
cat > "/home/${unix_user}/README_first_login.txt" <<EOF
Temporary password: ${temp_pw}
You will be asked to change it on next login.
EOF
chown ${unix_user}:${unix_user} "/home/${unix_user}/README_first_login.txt"
chmod 600 "/home/${unix_user}/README_first_login.txt"

# ~/.profile affiche le README puis force passwd au premier login interactif
# (pas de chage -d 0 — bloquerait la lecture du README avant le shell)
```

Au premier login interactif (TTY), le fichier d'init du shell affiche le contenu du README, supprime le fichier, puis invoque `passwd` pour que l'utilisateur définisse son propre mot de passe. Ce flux est testé dans `app/tests/test_ssh.py` (vérification du contenu de la constante `SAM_ADD`).

#### Choix du fichier d'init — compatibilité multi-distros

Le snippet n'est pas systématiquement écrit dans `~/.profile`. `sam-add` reproduit fidèlement l'ordre de résolution que **bash** applique lui-même pour décider quel fichier d'init lire en shell de login (voir `man bash`, section INVOCATION — « Bash attempts to read and execute commands from the first of the following files that exists ») :

1. `~/.bash_profile`
2. `~/.bash_login`
3. `~/.profile`

Dès que l'un de ces fichiers existe, bash ignore les suivants. Le script d'init choisi diffère donc d'une distribution à l'autre selon ce que `/etc/skel/` fournit au moment du `useradd -m` :

| Distribution | `/etc/skel/` typique | Fichier choisi par bash | Fichier écrit par `sam-add` |
|---|---|---|---|
| RHEL / Rocky / Alma / CentOS | `.bash_profile`, `.bashrc`, `.bash_logout` | `~/.bash_profile` | `~/.bash_profile` |
| Debian / Ubuntu | `.profile`, `.bashrc`, `.bash_logout` | `~/.profile` | `~/.profile` |
| openSUSE Leap / Tumbleweed | variable : `.profile` toujours, `.bash_profile` parfois | celui qui existe | celui qui existe |
| Arch Linux | skel quasi-vide (souvent rien ou juste `.bashrc`) | aucun par défaut | `~/.profile` (créé par `touch`) |
| Alpine *(avec `bash` installé)* | minimal | `~/.profile` ou `~/.bash_profile` selon skel | celui qui existe ou créé |

La logique dans `SAM_ADD` :

```sh
if [ -f "${home}/.bash_profile" ]; then
    profile="${home}/.bash_profile"     # RHEL family
elif [ -f "${home}/.bash_login" ]; then
    profile="${home}/.bash_login"        # rarissime
else
    profile="${home}/.profile"           # Debian, openSUSE, Arch, sh/dash
    touch "$profile"                     # crée si absent (Arch)
fi
```

**Garantie** : tant que `useradd -m -s /bin/bash` est utilisé (toujours le cas dans SAM_ADD), bash trouvera notre hook au premier login, quel que soit le Linux mainstream géré.

**Limites connues** :
- Un changement manuel du shell après création (`chsh -s /bin/zsh alice`) sort de ce contrat — zsh lit `~/.zprofile`/`~/.zlogin`, pas les fichiers couverts par `sam-add`. Documenté comme comportement attendu ; SAM ne re-déploie pas le hook après coup.
- Sur Alpine sans paquet `bash`, `useradd -m -s /bin/bash` échouerait dès la création de l'utilisateur — l'erreur remonte au scan et le user n'est pas créé. Prérequis hôte : `bash` + `sudo` installés.
- Les shells non interactifs (commande SSH directe `ssh alice@host 'cmd'`) ne sourcent ni `.bash_profile` ni `.profile` : c'est attendu, le hook ne se déclenche que pour les sessions interactives — le premier login interactif réel servira.

Cette logique est testée dans `app/tests/test_ssh.py::test_ssh_sam_add_appends_first_login_hook_to_bash_profile_when_present` qui vérifie que les trois noms de fichiers (`.bash_profile`, `.bash_login`, `.profile`) sont référencés dans le corps de la constante `SAM_ADD`.

### 6.8 Détection d'anomalies au niveau serveur (has_anomalies)

La route `GET /api/servers` expose un champ booléen `has_anomalies` par serveur, utilisé par le Dashboard (compteur Alertes) et par `ServerTable.vue` (badge 🟡). Le champ est calculé en SQL pour éviter de charger toutes les clés côté client.

**Définition** — `has_anomalies` est vrai si **au moins une** des deux conditions est remplie :

1. Au moins une `key_authorizations` du serveur a `status = 'PENDING_REVIEW'` (clé en attente de validation).
2. Au moins une `key_authorizations` du serveur correspond à une **révocation hors système récente** : `status = 'REVOKED' AND revoked_automatically = TRUE AND revoked_by IS NULL AND revoked_at > NOW() - INTERVAL '30 days'`.

La définition reflète strictement ce que la vue **Anomalies** affiche (`Anomalies.vue:143-155`) afin que Dashboard, ServerTable et Anomalies soient toujours cohérents.

**Important** : `has_anomalies` ne consulte **jamais** `audit_log`. Une première version interrogeait les entrées `ANOMALY_DETECTED` sur les 30 derniers jours ; le bug fixé en #396 a remplacé cette logique. `audit_log` est immuable par design (aucun `UPDATE`/`DELETE`), donc une entrée `ANOMALY_DETECTED` reste visible 30 jours même après que l'opérateur ait validé ou révoqué la clé fautive — ce qui maintenait à tort le badge orange. La règle est : `has_anomalies` reflète l'**état courant** des `key_authorizations`, pas l'historique des événements.

### 6.9 Audit de la configuration sshd du serveur géré (issue #392)

La vue détail d'un serveur intègre un panneau lisant la configuration sshd **effective** du serveur audité et la confrontant à une policy de durcissement (inspirée des bonnes pratiques OpenSSH usuelles, sans claim de conformité à une norme spécifique). La feature est purement déclarative : aucune modification de la config du serveur n'est jamais effectuée par SAM.

**Périmètre exact de l'audit** : `sudo sshd -T` (sans `-C user=...`) dump la configuration **globale** du démon, hors blocs `Match`. L'audit décrit donc le comportement de sshd pour les utilisateurs **hors `sam-users`** — typiquement `root`, comptes système et comptes créés manuellement par l'administrateur. Les utilisateurs SAM sont déjà couverts par le bloc `Match Group sam-users` posé par `provision-host.sh` (sous-section 6.7) qui force `AuthenticationMethods publickey` quelle que soit la valeur globale. Un statut `critical` sur `PasswordAuthentication` ici ne met donc pas en danger les comptes SAM, mais il signale que d'autres comptes du serveur (notamment `root`) peuvent se connecter par mot de passe.

**Chaîne de lecture** :

1. Une règle sudoers dédiée installée par `provision-host.sh` autorise `audit-collector` à exécuter **uniquement** `sshd -T` en tant que root (NOPASSWD, argument strict, pas de wildcard) :
   ```
   audit-collector ALL=(root) NOPASSWD: <sshd_path> -T
   ```
2. `ssh.audit_sshd_config(hostname, ip, port)` ouvre une connexion paramiko (RejectPolicy) et exécute `sudo sshd -T`. La sortie — une ligne par directive — est parsée en `dict[str, str]` (clés en lowercase). Source de vérité : sshd lui-même, ce qui couvre les `Include`, les blocs `Match` et les valeurs par défaut implicites.
3. `actions.check_sshd_compliance(parsed)` applique la policy déclarée en code (constante `SSHD_HARDENING_POLICY`, voir tableau ci-dessous). Pure, testable, sans I/O — chaque directive devient un dict `{directive, expected, actual, status, severity}`.
4. `actions.audit_server_sshd(hostname, admin_id)` orchestre 2 et 3, lève `UserError(404)` si serveur inconnu, `UserError(409)` si désactivé, `UserError(502)` si SSH échoue.
5. La route `GET /api/servers/<hostname>/sshd-audit` (require_auth, **tous rôles**, lecture seule) retourne le résultat sans le persister — la feature est stateless.
6. Le composant `SshAuditCard.vue` est inséré inline dans `ServerDetail.vue` après `SessionsCard`, affiche un voyant global (vert / orange / rouge) et un tableau de directives filtrable « Tous / Non conformes » (filtré par défaut).

**Policy de durcissement v1** :

| Directive | Règle | Sévérité |
|---|---|---|
| PermitRootLogin | `no` | critical |
| PasswordAuthentication | `no` | critical |
| PermitEmptyPasswords | `no` | critical |
| HostbasedAuthentication | `no` | critical |
| IgnoreRhosts | `yes` | critical |
| KbdInteractiveAuthentication | `no` | warning |
| ChallengeResponseAuthentication | `no` (optionnel) | warning |
| X11Forwarding | `no` | warning |
| AllowTcpForwarding | `no` ou `local` | warning |
| MaxAuthTries | ≤ 3 | warning |
| LoginGraceTime | ≤ 60 | warning |
| UsePAM | `yes` | warning |
| ClientAliveInterval | > 0 | info |
| LogLevel | `INFO` ou `VERBOSE` | info |

Les seuils sont déclarés une fois pour toutes dans `SSHD_HARDENING_POLICY` et explicitement non rattachés à une référence normative — ils représentent des valeurs de durcissement OpenSSH généralement attendues (CIS, STIG, ANSSI BP-099 ont des recommandations équivalentes pour la majorité de ces directives, mais SAM ne prétend pas à une conformité formelle à l'une d'elles). Mettre à jour les seuils = modifier la constante.

**Statut global** : `critical` s'il existe au moins une directive critical non conforme, `warning` sinon s'il y a au moins une non-conformité ou directive manquante, `ok` sinon.

**Hors périmètre v1** : audit des algos crypto (`Ciphers`, `MACs`, `KexAlgorithms`, `HostKeyAlgorithms`), historique persisté, export PDF/CSV, alertes email sur régression.

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
                                fingerprint, comment, server_id, hostname,
                                unix_user=unix_user)
  → INSERT ssh_keys (fingerprint, key_type, ...)
  → INSERT key_authorizations (unix_user, status='PENDING_REVIEW')
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
│  1185 lignes — source unique    │
└───────────────┬─────────────────┘
                │ importé par
       ┌────────┴────────┐
       │                 │
┌──────▼──────┐   ┌──────▼──────┐
│  web.py     │   │  manage.py  │
│  (API REST) │   │  (CLI)      │
│  1174 lignes│   │  631 lignes │
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
| `WARNING` | Email immédiat avec anti-spam 24h | Clé proche de l'expiration (J-N, seuils configurables) |
| `INFO` | Log uniquement | KEY_EXPIRED, KEY_REVOKED, SCAN_COMPLETED, LOGIN_FAILED, LOGIN_BANNED |

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

Le workflow d'accès temporaire illustre la coordination entre les modules.
Le déploiement de clé SSH est disponible via l'UI (vue Accès → DeployKeyForm) ;
le workflow demande/approbation (`access request` / `access approve`) est accessible
uniquement via la CLI et l'API REST.

```
1. Déploiement via UI (DeployKeyForm) ou CLI (access grant)
   → POST /api/access/deploy  (UI)  ou  POST /api/access/grant  (CLI/API)
   → actions.deploy_key() ou actions.grant_access()
   → INSERT key_authorizations (status='ACTIVE', expires_at=... ou NULL si illimité)
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

Les alertes d'avertissement s'intercalent avant l'expiration. Les seuils
`expire_warn_days` (défaut 7) et `expire_warn_days_2` (défaut 2) sont stockés
dans la table `settings` et modifiables sans redémarrage via Settings UI :

```
J-N et J-M : expire.warn_expiring_keys()
  → Lit expire_warn_days et expire_warn_days_2 depuis la table settings
  → Anti-spam 24h : si pas d'alerte aujourd'hui
  → alerts.send_alert('WARNING', "Clé expire dans N jours")
  → INSERT audit_log('EXPIRY_WARNING')
```

Les alertes email sont envoyées aux administrateurs dont `receive_alerts=true`
(colonne ajoutée à la table `administrators`, toggle par admin via l'UI Admins).

---

## 11. Frontend Vue.js 3 — architecture des composants

### Composition API et composables

Vue.js 3 avec `<script setup>` est utilisé systématiquement. Cinq composables
encapsulent la logique partagée :

- **`useAuth.js`** — état d'authentification partagé entre toutes les vues
- **`useFormatDate.js`** — `formatDate()` et `formatDateOnly()` avec locale du navigateur
  (`toLocaleString(undefined, ...)` — s'adapte automatiquement au fuseau du navigateur)
- **`usePagination.js`** — pagination côté client réutilisable (reset auto sur filtre)
- **`useSort.js`** — tri de colonnes réutilisable (`sortKey`, `toggleSort`, `sorted`, `sortIndicator`) — utilisé dans KeyTable, ServerTable, AuditTable, DeployedUsersTable, AdminsTable, AnomaliesTable
- **`useTheme.js`** — thème sombre/clair avec persistance `localStorage` ; initialise `data-theme` sur `<html>` au chargement ; défaut : dark (#363)

Le composable `useAuth.js` encapsule l'état d'authentification partagé entre toutes les vues :

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

### RBAC — contrôle d'accès par rôle (issue #222)

Trois rôles sont définis par une contrainte CHECK PostgreSQL dans la table
`administrators` : `sysadmin`, `operator`, `viewer`.

#### Backend — décorateur require_role

```python
def require_role(*roles):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if g.admin_role not in roles:
                return jsonify({"error": "Forbidden"}), 403
            return f(*args, **kwargs)
        return wrapped
    return decorator
```

`require_auth` charge `g.admin_role` à chaque requête. `require_role` compose avec
`require_auth` pour protéger les routes par niveau d'accès :

| Niveau | Routes protégées |
|---|---|
| `sysadmin` uniquement | `POST /api/admins`, `PUT /api/admins/<u>`, disable/enable/delete admin, `POST /api/servers`, disable/enable/delete server, `PUT /api/system/config` |
| `sysadmin` ou `operator` | Toutes les routes d'écriture clés, accès, scans |
| Tous (auth seule) | Routes GET, `GET /api/auth/me` |

Exception : `PUT /api/admins/<username>/password` — autorisé si sysadmin OU si l'admin modifie son propre mot de passe.

#### Matrice RBAC complète

| Route | Méthode | sysadmin | operator | viewer |
|-------|---------|----------|----------|--------|
| /api/servers | GET | ✓ | ✓ | ✓ |
| /api/servers | POST | ✓ | 403 | 403 |
| /api/servers/\<hostname\> | GET | ✓ | ✓ | ✓ |
| /api/servers/\<hostname\> | PUT | ✓ | 403 | 403 |
| /api/servers/\<hostname\>/disable | PUT | ✓ | 403 | 403 |
| /api/servers/\<hostname\>/enable | PUT | ✓ | 403 | 403 |
| /api/servers/\<hostname\> | DELETE | ✓ | 403 | 403 |
| /api/servers/\<hostname\>/scan | POST | ✓ | ✓ | 403 |
| /api/keys | GET | ✓ | ✓ | ✓ |
| /api/keys/get/\<fp\> | GET | ✓ | ✓ | ✓ |
| /api/keys/search | GET | ✓ | ✓ | ✓ |
| /api/keys/validate/\<fp\> | POST | ✓ | ✓ | 403 |
| /api/keys/revoke/\<fp\> | POST | ✓ | ✓ | 403 |
| /api/keys/assign/\<fp\> | POST | ✓ | ✓ | 403 |
| /api/keys/set-expiry/\<fp\> | POST | ✓ | ✓ | 403 |
| /api/keys/remove-expiry/\<fp\> | POST | ✓ | ✓ | 403 |
| /api/access | GET | ✓ | ✓ | ✓ |
| /api/access/\<id\> | GET | ✓ | ✓ | ✓ |
| /api/access/deployed-users | GET | ✓ | ✓ | ✓ |
| /api/access/grant | POST | ✓ | ✓ | 403 |
| /api/access/deploy | POST | ✓ | ✓ | 403 |
| /api/access/lock-user | POST | ✓ | ✓ | 403 |
| /api/access/unlock-user | POST | ✓ | ✓ | 403 |
| /api/access/request | POST | ✓ | ✓ | 403 |
| /api/access/\<id\>/approve | POST | ✓ | ✓ | 403 |
| /api/access/\<id\>/reject | POST | ✓ | ✓ | 403 |
| /api/access/\<id\>/revoke | POST | ✓ | ✓ | 403 |
| /api/admins | GET | ✓ | ✓ | ✓ |
| /api/admins/me | GET | ✓ | ✓ | ✓ |
| /api/admins | POST | ✓ | 403 | 403 |
| /api/admins/\<username\> | PUT | ✓ | 403 | 403 |
| /api/admins/\<username\>/disable | PUT | ✓ | 403 | 403 |
| /api/admins/\<username\>/enable | PUT | ✓ | 403 | 403 |
| /api/admins/\<username\> | DELETE | ✓ | 403 | 403 |
| /api/admins/\<username\>/alerts | PUT | ✓ | 403 | 403 |
| /api/admins/\<username\>/password | PUT | ✓ | ✓* | 403* |
| /api/audit | GET | ✓ | ✓ | ✓ |
| /api/system/status | GET | ✓ | ✓ | ✓ |
| /api/system/scan | POST | ✓ | ✓ | 403 |
| /api/system/collector-key | GET | ✓ | ✓ | ✓ |
| /api/system/config | GET | ✓ | ✓ | ✓ |
| /api/system/config | PUT | ✓ | 403 | 403 |
| /api/system/test-smtp | POST | ✓ | ✓ | ✓ |

\* `PUT /api/admins/<username>/password` : sysadmin → toujours autorisé ; operator/viewer → autorisé uniquement pour modifier son propre mot de passe (403 sinon).

#### Frontend — visibilité par rôle

`useAuth.js` expose `admin.value.role` (chargé après login via `fetchMe()`).
Chaque vue calcule `currentRole = computed(() => admin.value?.role || 'viewer')`.
Les éléments sensibles utilisent `v-if` (jamais `v-show`) pour être absents du DOM :

- **Admins.vue** : colonne Actions, formulaire d'ajout, boutons Edit/Disable/Enable/Delete masqués pour operator et viewer ; section "My account" visible pour tous pour changer son propre mot de passe
- **Dashboard, ServerDetail** : boutons d'ajout/désactivation/suppression masqués pour viewer
- **DeployedUsersTable** : colonne Actions + boutons Lock/Unlock masqués pour viewer
- **Settings** : formulaire de configuration masqué pour operator et viewer

### Protection contre les attaques par force brute (issue #236)

Un système de limitation de taux (rate limiting) protège la route
`POST /api/auth/login` contre les tentatives de connexion par force brute.
L'implémentation est entièrement en mémoire — aucune dépendance externe
(Redis, Memcached) n'est requise.

#### Architecture

```python
# web.py — État global thread-safe
from threading import Lock

_login_attempts = {}  # dict[ip] = {"count": int, "first_seen": datetime}
_login_attempts_lock = Lock()
```

Chaque IP est suivie indépendamment. Le dictionnaire global `_login_attempts`
enregistre le nombre d'échecs de connexion et le timestamp de la première
tentative. Le lock garantit la cohérence de l'état face aux requêtes concurrentes.

#### Extraction de l'IP client

La directive `proxy_set_header X-Forwarded-For $remote_addr;` dans Nginx injecte
l'IP réelle du client dans chaque requête. Flask la lit via
`request.headers.get("X-Forwarded-For", request.remote_addr).split(",")[0]`.
En production, Nginx est le seul point d'entrée HTTP — l'IP extraite est fiable.

#### Configuration dynamique

Deux paramètres contrôlent le comportement, stockés dans la table `settings` :

- **`login_max_attempts`** (défaut : 10) — nombre d'échecs tolérés avant blocage
- **`login_ban_seconds`** (défaut : 300 / 5 minutes) — durée du blocage

Ces valeurs sont modifiables sans redémarrage via `PUT /api/system/config`.
À chaque requête `/api/auth/login`, les seuils sont lus depuis la base de données.

#### Comportement

**Login échoué** (mot de passe invalide) :
```
→ Incrément compteur pour l'IP
→ HTTP 401 {"error": "Invalid credentials"}
→ stdout : [LOGIN_FAILED] ip=... username=...
→ INSERT audit_log (action='LOGIN_FAILED', details={"ip": ..., "username": ...})
```

**Seuil dépassé** :
```
→ HTTP 429 {"error": "Too many login attempts. Try again in X seconds."}
→ stdout : [LOGIN_BANNED] ip=... attempts=... ban_seconds=...
→ INSERT audit_log (action='LOGIN_BANNED', details={"ip": ..., "attempts": ...})
```

**Login réussi** :
```
→ Suppression de l'entrée pour cette IP (reset du compteur)
→ HTTP 200 + session établie
```

**Fenêtre glissante** : après `login_ban_seconds`, l'entrée est supprimée
automatiquement lors de la prochaine vérification — l'IP peut retenter.

#### Intégration avec fail2ban / CrowdSec

Les logs stdout structurés permettent le filtrage externe :

```
[LOGIN_FAILED] ip=192.0.2.15 username=admin
[LOGIN_BANNED] ip=192.0.2.15 attempts=10 ban_seconds=300
```

Un regex fail2ban peut détecter `[LOGIN_FAILED]` ou `[LOGIN_BANNED]` et
bannir l'IP au niveau du firewall (iptables/nftables). Le rate limiting
applicatif et le rate limiting réseau (fail2ban) se complètent : le premier
réduit la charge sur PostgreSQL, le second bloque au niveau transport.

#### Pourquoi in-memory plutôt que Redis

1. **Simplicité de déploiement** : conteneur unique sans orchestration de services
2. **Faible charge** : quelques dizaines d'admins, pas de flotte de containers
3. **Cohérence avec l'architecture** : toute la persistance est PostgreSQL + volume
4. **Fail-safe acceptable** : un redémarrage réinitialise les compteurs (tolérable
   pour un outil interne — un attaquant persistant sera de toute façon bloqué
   par fail2ban au niveau réseau)

L'état en mémoire est perdu au redémarrage du conteneur, mais la combinaison
(limitation applicative éphémère + audit_log permanent + fail2ban optionnel)
couvre les trois couches : applicative, traçabilité, réseau.

### Timeout de session (issue #239)

Deux durées de session selon le choix de l'utilisateur au login :
- **30 minutes** (défaut) — session courte, sans "Keep me logged on this device"
- **8 heures** — session longue, avec la checkbox cochée

Implémentation : `session["expires_at"]` (timestamp UTC float) posé dans `auth_login()`, vérifié dans `require_auth` avant chaque requête protégée. Session expirée → `session.clear()` + HTTP 401. Durées hardcodées comme constantes `SESSION_SHORT_MINUTES = 30` et `SESSION_LONG_HOURS = 8` dans `web.py` — pas de dépendance à la table `settings`, pas de redémarrage nécessaire.

### Vue AccessRequests — formulaires DeployKeyForm et UserLockForm

La vue `AccessRequests.vue` expose deux formulaires :

**DeployKeyForm** : déploiement d'une clé SSH sur un serveur distant.
Collecte : utilisateur Unix, clé publique, serveur cible (dropdown des serveurs
actifs via `GET /api/servers`, filtré `is_active === true`), durée (heures / date
précise / illimité) et justification.
À la soumission, `POST /api/access/deploy` appelle `actions.deploy_key()` :
exécution de `sam-add` sur le serveur distant, enregistrement de la clé avec
statut `ACTIVE` et expiration choisie.

**UserLockForm** : verrouillage / déverrouillage d'un compte Unix (issue #181).
Collecte : utilisateur Unix (regex POSIX strict — pas d'espaces, pas de majuscules),
serveur cible. Deux boutons distincts : « Bloquer » (POST /api/access/lock-user)
et « Débloquer » (POST /api/access/unlock-user).
`sam-lock-user` exécute `usermod -L -s /sbin/nologin <user>` — bloque à la fois
le mot de passe et le shell, rendant toute connexion SSH impossible même avec une
clé valide. `sam-unlock-user` rétablit avec `usermod -U -s /bin/bash <user>`.
Chaque action est tracée dans `audit_log` avec action `USER_LOCKED` ou
`USER_UNLOCKED`.

Le workflow demande/approbation (`access request` / `access approve`) reste
disponible via la CLI et l'API REST, mais n'est plus exposé dans l'interface web.

### Vue Anomalies — filtres et colonne unix_user

La vue `Anomalies.vue` affiche deux sections : clés en attente de validation
(`PENDING_REVIEW`) et révocations hors système (30 derniers jours). Elle expose
une barre de filtres combinés :

- **Texte libre** : recherche sur fingerprint, type, serveur, unix_user
- **Dropdown type** : filtre par algorithme de clé (ssh-ed25519, ssh-rsa, …)
- **Dropdown serveur** : filtre par hostname de serveur
- **Dropdown conformité** : filtre Conforme / Non conforme

La colonne **Unix user** est affichée dans les deux tables. Les badges de compteur
(`count-badge`) reflètent le total réel avant filtrage, pas le nombre de lignes
visibles — ce qui permet à l'administrateur de savoir combien d'anomalies existent
même si un filtre est actif.

La fonction `validate()` transmet `unix_user` et `server_hostname` au corps de la
requête POST `/api/keys/validate/<fp>`, garantissant que seule la ligne
`(key_id, server_id, unix_user)` ciblée passe en `ACTIVE` (fix issue #193).

### Validation scopée — validate_key (issue #193)

La clé composite `(key_id, server_id, unix_user)` dans `key_authorizations` implique
qu'une même clé SSH peut être autorisée pour plusieurs utilisateurs Unix sur un même
serveur. La fonction `validate_key()` accepte des paramètres optionnels :

```python
def validate_key(fingerprint, admin_id, unix_user=None, hostname=None):
    # sans params : valide toutes les lignes PENDING_REVIEW du fingerprint
    # avec params  : valide uniquement la ligne (fingerprint, server, unix_user)
```

L'UI transmet toujours `unix_user` et `hostname` dans le corps JSON de la requête,
garantissant que valider une clé pour `alice` ne valide pas automatiquement la même
clé pour `bob` sur le même serveur.

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

### Pagination côté client (issues #248, #250)

Toutes les tables de l'interface sont paginées côté client. Les données sont chargées
en une seule requête API ; la pagination opère sur la liste déjà en mémoire, sans
appel supplémentaire au backend.

**Composable `usePagination.js`** — encapsule la logique réutilisable :

```javascript
export function usePagination(filteredItems) {
  const PAGE_SIZES = [10, 20, 40, 50, 100]
  const currentPage = ref(1)
  const pageSize = ref(10)

  watch(filteredItems, () => { currentPage.value = 1 })  // reset auto sur filtre

  const paginatedItems = computed(() => {
    const start = (currentPage.value - 1) * pageSize.value
    return filteredItems.value.slice(start, start + pageSize.value)
  })
  // …
}
```

Le `watch` sur `filteredItems` garantit le retour en page 1 dès qu'un filtre change —
évitant d'afficher une page vide si le résultat filtré est plus court que la page
courante.

**Composant `PaginationBar.vue`** — réutilisé sous chaque table : sélecteur de taille
(10/20/40/50/100), indicateur traduit "1–10 sur 42", boutons Précédent/Suivant
désactivés en limite. Traduit dans les 5 langues.

### Architecture des composants table

Par cohérence, chaque table est encapsulée dans un composant dédié. Le composant
reçoit les données brutes en prop, gère son filtrage et sa pagination en interne,
et émet des événements pour les actions. La vue parente conserve uniquement le
fetch API et les modals.

| Composant | Vue parente | Données |
|-----------|------------|---------|
| `ServerTable.vue` | `Dashboard.vue` | serveurs |
| `KeyTable.vue` | `ServerDetail.vue` | clés SSH |
| `DeployedUsersTable.vue` | `AccessRequests.vue` | utilisateurs déployés |
| `AdminsTable.vue` | `Admins.vue` | administrateurs |
| `AuditTable.vue` | `Audit.vue` | historique audit |
| `AnomaliesTable.vue` | `Anomalies.vue` | anomalies actives |

Le RBAC est appliqué dans chaque composant via la prop `currentRole` : les colonnes
et boutons d'action sont masqués (`v-if`) selon le rôle. Le défaut `'viewer'`
garantit le comportement le plus restrictif si la prop est absente.

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
| `test_actions.py` | 114 | ≥ 80 % (imposé CI) — provision-first, password non stocké, scénarios révocation |
| `test_ssh.py` | 49 | RejectPolicy, ensure_scripts (6 scripts), revoke, lock/unlock, SAM bytes |
| `test_web.py` | 130 | Toutes les routes critiques, auth 401/200, lock/unlock, provision endpoint, error_code |
| `test_rbac.py` | 54 | Couverture complète de la matrice RBAC (sysadmin/operator/viewer) |
| `test_manage.py` | 38 | Toutes les commandes CLI, lock/unlock, servers add avec SSH creds |
| `test_collect.py` | 35 | 4 scénarios détection, RSA parsing |
| `test_expire.py` | 12 | Anti-spam 24h, expiration auto |
| `test_alerts.py` | 23 | Niveaux CRITICAL/WARNING/INFO, anti-spam |
| Vue.js specs | 325 | 19 fichiers : Dashboard (provisionnement, validation hostname), ServerDetail (re-provision), KeyTable (bulk select), ServerTable, Admins, SessionsCard, useSort, et tous composants |

---

## 13. CI/CD — GitHub Actions

### 9 workflows et leur rôle

```
.github/workflows/
  ci.yml                       ← 4 jobs qualité sur chaque PR
  pr-title.yml                 ← Validation titre PR (Conventional Commits)
  build-pr.yml                 ← Image Docker pr-{N} sur GHCR + scan Trivy CVE
  build-main.yml               ← Image Docker :main à chaque merge
  publish-release.yml          ← Image semver stable/beta sur tag git
  cleanup-pr.yml               ← Suppression image pr-{N} à fermeture PR
  codeql.yml                   ← Analyse statique sécurité Python (SAST)
  integration-provision.yml    ← Tests intégration provision-host.sh (Rocky + Debian)
```

### `integration-provision.yml` — tests d'intégration multi-distros (#398)

`provision-host.sh` pose la configuration SAM côté hôte distant en root (utilisateur `audit-collector`, sudoers, groupes `sam-*`, drop-in sshd `Match Group sam-users` durci). Une régression silencieuse (option `useradd` indisponible, binaire absent du PATH, syntaxe sudoers rejetée) casserait le provisioning sans qu'on s'en aperçoive avant la prod.

Le workflow tourne sur chaque PR touchant `provision-host.sh` ou `tests/integration/**`, et sur push main. Matrice v1 : `rockylinux:9` (skel `.bash_profile`, `dnf`) et `debian:13` (skel `.profile`, `apt`). Chaque job lance le conteneur Docker correspondant et exécute `tests/integration/run.sh`. AlmaLinux/Ubuntu/openSUSE/Alpine/Arch sont différés à une v2.

Le script `run.sh` enchaîne trois phases :

1. **Bootstrap** : exécute `provision-host.sh` et vérifie 20+ assertions (user créé, 4 groupes Unix présents, sudoers `audit-collector`/`sam-operator`/`sam-pkg`/`sam-root` valides via `visudo -c`, permissions 440/600 conformes, drop-in sshd contient les 5 directives durcies, `sshd -t` OK, authorized_keys posée avec mode 600).
2. **Idempotence** : rejoue `provision-host.sh` une seconde fois, vérifie qu'aucun fichier `.bak` ne traîne, que le contenu des sudoers n'a pas changé byte-à-byte, et que la clé collecteur n'est pas dupliquée dans `authorized_keys`.
3. **Rollback négatif** : `tests/integration/fixtures/bad_sshd_config.sh` patche `SAM_SSHD_CONF` à la volée avec une directive invalide (`Port not-a-number`) via `sed -z`, exécute le script patché. Vérifie que le script exit non-zéro, que `sshd -t` détecte l'erreur, que le `.bak` de la version précédente est restauré, et qu'aucun `.bak` orphelin ne reste sur le disque.

**Limites assumées** : pas de `systemd` dans Docker → `systemctl reload sshd` reste best-effort dans `provision-host.sh` (déjà gardé par `|| true`) ; on teste la **syntaxe** via `sshd -t`, pas le reload effectif (validé manuellement sur VM staging). L'orchestration paramiko côté SAM reste couverte par `pytest` avec mocks.

**Reproduction locale** :

```bash
podman run --rm -v "$PWD":/repo:Z -w /repo --tmpfs /tmp rockylinux:9 bash tests/integration/run.sh
podman run --rm -v "$PWD":/repo:Z -w /repo --tmpfs /tmp debian:13      bash tests/integration/run.sh
```

Sur Docker (non-rootless), retirer le `:Z` du volume.

### `ci.yml` — porte d'entrée qualité

Quatre jobs parallèles déclenchés sur chaque PR :

| Job | Outil | Condition d'échec |
|---|---|---|
| `tests-python` | pytest `--cov=actions --cov-fail-under=80` | couverture < 80 % ou test rouge |
| `tests-vue` | `npx vitest run` | tout test échoue |
| `prettier` | `npm run format:check` | fichier Vue/JS/JSON non formaté |
| `commitlint` | `wagoid/commitlint-github-action@v6` | commit ne respecte pas Conventional Commits |

### `pr-title.yml` — titre de PR

Script shell `grep -P` sans dépendance externe. Valide que le titre respecte
`type: description` (types : feat, fix, docs, style, refactor, test, ci, chore,
perf, build, revert). La valeur est passée via `env: PR_TITLE` pour éviter
toute injection shell.

### Convention Conventional Commits

Deux niveaux de validation distincts et complémentaires :

- **Commits** : `commitlint` vérifie chaque message de la branche PR
- **Titre PR** : `pr-title.yml` vérifie le titre au moment du merge

Le titre de la PR devient le message du merge commit sur `main` — les deux
checks garantissent que l'historique de `main` est lisible et outillable
(changelog automatique, semver automatique).

### Stratégie de tags Docker (GHCR)

| Événement | Tag publié |
|---|---|
| PR ouverte | `pr-{N}` |
| Merge sur `main` | `main` |
| Tag git `1.0.0-dev.1` (avec `-`) | `1.0.0-dev.1` uniquement |
| Tag git `1.0.0` (sans `-`) | `1.0.0` **+** `latest` |

La détection stable/pre-release repose sur la présence d'un tiret dans le tag :

```bash
if [[ "$TAG" == *"-"* ]]; then
    docker build -t "$IMAGE:$TAG" . && docker push "$IMAGE:$TAG"
else
    docker build -t "$IMAGE:$TAG" -t "$IMAGE:latest" .
    docker push "$IMAGE:$TAG" && docker push "$IMAGE:latest"
fi
```

Les tags pre-release (`1.0.0-dev.1`, `1.0.0-rc.1`) ne mettent jamais à jour
`:latest`, qui ne pointe que vers la dernière version stable.

### Nettoyage GHCR (`cleanup-pr.yml`)

À la fermeture d'une PR (merge ou abandon), l'image `pr-{N}` est supprimée via
l'API GitHub Packages (`gh api --method DELETE`). Cela évite l'accumulation
d'images orphelines dans le registre. Si l'image n'existe pas (PR sans push),
le workflow se termine silencieusement.

### Trivy — scan CVE image Docker (`build-pr.yml`)

Trivy (Aqua Security) scanne l'image buildée sur chaque PR après le push sur
GHCR. Il analyse trois couches :

- **Packages Alpine** (`apk`) : openssl, musl, libssl, nginx…
- **Packages Python** (`pip`) : paramiko, psycopg2, flask, werkzeug…
- **Packages npm** du stage build node:24-alpine

Seuil de blocage : `CRITICAL` et `HIGH` uniquement — les vulnérabilités `MEDIUM`
et `LOW` sont rapportées sans bloquer la PR. Les résultats sont uploadés en
format SARIF dans **Security → Code scanning** du repo pour traçabilité.

Le step `upload-sarif` est conditionné par `if: always()` pour que les résultats
soient visibles même quand Trivy fait échouer la CI.

### Protection de `main`

Configurée via l'API GitHub Branch Protection Rules :

- Push direct interdit — toute modification passe par une PR
- Les 5 checks suivants sont obligatoires : Tests Python, Tests Vue.js,
  Prettier, Commit messages, Validate PR title
- Force push bloqué
- Règle appliquée aux administrateurs du dépôt (`enforce_admins: true`)

### CodeQL — analyse statique de sécurité (`codeql.yml`)

CodeQL est l'outil SAST (Static Application Security Testing) natif de GitHub.
Il analyse le code Python à la recherche de vulnérabilités connues :

- Injection de commandes (appels `subprocess`, exécution paramiko)
- Injection SQL (requêtes psycopg2 mal paramétrées)
- Path traversal (lecture/écriture de fichiers depuis des entrées utilisateur)
- Utilisation de fonctions ou patterns dangereux

Le workflow se déclenche sur trois événements :
- Chaque PR (détection avant merge)
- Push sur `main` (double filet)
- Tous les lundis à 6h (détection de nouvelles CVE sur du code non modifié)

Les résultats sont visibles dans l'onglet **Security → Code scanning** du dépôt
GitHub. La query suite `security-extended` couvre un périmètre plus large que
la suite par défaut.

### Mises à jour automatiques — Renovate (`renovate.json`)

Renovate ouvre des PRs de mise à jour chaque lundi avant 9h (TZ Europe/Paris) :

| Périmètre | Comportement |
|---|---|
| npm `ui/package.json` — patch | PR automerge si CI vert |
| npm `ui/package.json` — minor/major | PR groupée, merge manuel |
| pip `requirements-test.txt` | PR groupée, merge manuel |
| Docker `FROM` lines | PR groupée, merge manuel |

Les PRs Renovate reçoivent automatiquement le label `dependencies`. Les PRs
automerge (patch npm) attendent que les 5 checks CI soient verts — le même
garde-fou que pour les PRs manuelles.

### Cache pip avec requirements-test.txt

```yaml
- uses: actions/setup-python@v6
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
| Base Alpine 3.23.4 | ~7 Mo vs ~77 Mo Ubuntu — réduction 60 % de l'empreinte stockage et bande passante GHCR | Disponibilité de paquets parfois limitée vs Debian |
| Session Flask | Simplicité d'implémentation | Pas de support multi-device/token |
| Rate limiting in-memory | Pas de dépendance Redis/Memcached | État perdu au redémarrage |
| JSONB audit details | Extensibilité sans migration | Données non structurées en DB |
| Réécriture atomique SAM_REVOKE | `authorized_keys` jamais corrompu | Complexité du script shell |
| Anti-spam audit_log | Pas de flood d'emails expiration | Index supplémentaire requis |
| vue-i18n 5 langues | Accessibilité internationale | 5 fichiers JSON à synchroniser |
| `freeze_time` tests | Déterminisme des tests d'expiration | Dépendance à `freezegun` |
| Tag semver sans `v` | Uniformité git tag = Docker tag | Convention moins répandue |
| Provisionnement atomique (provision-first) | Aucun serveur zombie en DB — INSERT uniquement si SSH réussit | SSH obligatoire à l'ajout (pas de déclaration purement déclarative via UI) |
| SSH password non stocké | Sécurité : credential éphémère, jamais en base ni en audit | Pas de re-connexion automatique — re-provisionnement via bouton UI si nécessaire |
| `error_code` API + traduction frontend | Messages d'erreur SSH dans la langue du navigateur sans hard-coder les traductions côté serveur | 7 codes à maintenir synchronisés entre backend et fichiers i18n |
| Waitress WSGI server | Serveur de production thread-safe ; Flask dev server interdit en production | Dépendance supplémentaire (`waitress` dans pip) |
| Bulk validate/revoke | Réduction du nombre de requêtes HTTP pour les opérations de masse ; transactions atomiques | Limite 200 fingerprints par appel |
| Rétention audit configurable | `audit_retention_days` (défaut 365) évite la croissance illimitée de `audit_log` | Perte des entrées purgées (irréversible) |
| Seuil sessions par serveur (`max_sessions`) | Alerte WARNING si sessions SSH actives > seuil ; anti-spam 24h via `audit_log` | Seuil par serveur à maintenir dans l'UI |
| Thème sombre par défaut | Réduction de la fatigue visuelle pour les opérateurs ; persistance via `localStorage` | CSS variables à synchroniser entre composants |

---

## 16. Bilan

ssh-access-manager démontre l'application cohérente de plusieurs principes
d'ingénierie logicielle niveau 7 :

- **Séparation des préoccupations** : chaque module a une responsabilité unique et
  délimitée (db, ssh, actions, collect, expire, alerts, web, manage).
- **Défense en profondeur** : sécurité SSH (RejectPolicy + keyscan + IP directe),
  conformité ANSSI (DB + UI), audit immuable (INSERT uniquement sur `audit_log`),
  protection brute-force (rate limiting applicatif + logs structurés fail2ban).
- **Idempotence** : sync YAML, keyscan, bootstrap, déploiement de scripts.
- **Traçabilité complète** : les 4 scénarios de révocation sont distingués par des
  colonnes dédiées et des entrées `audit_log` de types différents.
- **Qualité mesurée** : couverture ≥ 80 % imposée par CI, 857 tests (532 Python +
  325 Vue.js), isolation totale.
- **Déploiement continu** : 5 workflows GitHub Actions (tests, build PR, build main,
  publication semver, nettoyage GHCR).
