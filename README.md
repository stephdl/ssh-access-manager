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
podman build -t sam-server .
```

### 3. Premier démarrage

```bash
podman run -d \
  --name sam-server \
  --env-file .env \
  -v ssh_data:/data \
  -p 8080:8080 \
  sam-server
```

Au premier démarrage, le container :
1. Initialise PostgreSQL et applique le schéma SQL
2. Crée le répertoire `/data/keys/per-server/` qui contiendra les paires de clés ED25519 générées **par serveur** (une par hôte ajouté)
3. Insère l'administrateur initial (depuis `ADMIN_USERNAME` et `ADMIN_EMAIL`)

> **Per-server collector keys.** SAM ne génère plus de clé SSH globale. À l'ajout d'un serveur (UI ou CLI), une paire `<uuid>.key{,.pub}` est générée dans `/data/keys/per-server/`. La compromission d'une clé est ainsi cantonnée à un seul hôte. La pubkey d'un serveur est consultable depuis **ServerDetail** ou via `GET /api/servers/<hostname>/collector-key`.

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

### Permissions par catégorie

| Catégorie | sysadmin | operator | viewer |
|-----------|----------|----------|--------|
| Lecture (GET — toutes les ressources) | ✓ | ✓ | ✓ |
| Actions SSH (valider/révoquer clés, scans, déploiement, lock/unlock) | ✓ | ✓ | ✗ |
| Administration système (serveurs, admins, configuration) | ✓ | ✗ | ✗ |
| Changement de son propre mot de passe | ✓ | ✓ | ✓ |

Pour créer un administrateur avec un rôle spécifique (défaut : `operator`) :

```bash
$EXEC admin add --username alice --email alice@example.com --password SECRET --role operator
$EXEC admin update alice --role viewer
```

---

## Sécurité — Protection contre les attaques par force brute

Le système intègre une protection contre les tentatives de connexion répétées. En cas de multiples échecs de connexion depuis la même adresse IP, celle-ci est temporairement bannie.

### Fonctionnement

- **Limite de tentatives** : après N échecs de connexion consécutifs, l'IP est bloquée pour M secondes
- **Réponse HTTP** : `429 Too Many Requests` pendant la durée du bannissement
- **Configuration** : les deux paramètres sont modifiables à chaud via **Settings → Security** (rôle `sysadmin` requis)
  - `login_max_attempts` (défaut : 10) — nombre d'échecs avant bannissement
  - `login_ban_seconds` (défaut : 300) — durée du bannissement en secondes
- **Aucun redémarrage** : les modifications prennent effet immédiatement

### Logs stdout — intégration fail2ban / CrowdSec

Chaque tentative de connexion échouée et chaque bannissement sont tracés dans stdout (visibles via `podman logs`) au format suivant :

```
[LOGIN_FAILED] ip=1.2.3.4 username=admin
[LOGIN_BANNED] ip=1.2.3.4 username=admin ban_seconds=300
```

Ces logs structurés facilitent l'intégration avec des systèmes de détection d'intrusion comme **fail2ban** ou **CrowdSec** pour appliquer des règles de bannissement au niveau du pare-feu système.

---

## Gestion de session

La durée de session est contrôlée par une checkbox sur la page de connexion :

| Mode | Durée |
|------|-------|
| Sans coche | 30 minutes |
| "Keep me logged on this device" | 8 heures |

À l'expiration, les routes protégées retournent HTTP 401 et l'UI redirige vers `/login`.
Les durées sont des constantes dans `web.py` — pas de redémarrage nécessaire pour les modifier en dev.

---

## Workflow — Ajout d'un serveur distant

SAM génère **une paire de clés SSH ed25519 distincte par serveur** (stockée dans `/data/keys/per-server/<uuid>.key{,.pub}`, chmod 600, propriétaire `nobody`, fichier anonyme — pas de commentaire SSH). La compromission d'une clé n'expose qu'un seul hôte, jamais l'ensemble du parc. Le mapping serveur ↔ clé est implicite via le nom de fichier (UUID v4 random) — **pas de fingerprint stocké en base**, pour qu'un vol de la BDD seule ne révèle aucune information cryptographique exploitable.

Cinq workflows d'ajout, du plus simple au plus scriptable :

### A. UI, un serveur, avec mot de passe (le plus simple)

Dashboard → bouton **+ Ajouter un serveur** → remplir :

| Champ | Obligatoire | Description |
|---|---|---|
| Hostname | ✓ | Nom RFC 1123 (`server-01`, `web.prod.example.com`) |
| Adresse IP | ✓ | IPv4 ou IPv6 — doit être unique dans SAM |
| Utilisateur SSH | ✓ | Compte avec sudo (`root` ou tout compte `sudo ALL`) |
| Mot de passe SSH | ✓ | Utilisé **une seule fois** pour le provisionnement — jamais stocké en base |
| Port SSH | — | Défaut : 22 |
| Environnement | — | `production` / `staging` / `lab` — modifiable ultérieurement |
| OS | — | Famille d'OS (`rhel`, `debian`…) — modifiable ultérieurement |

À la soumission, SAM : (1) génère la per-server keypair, (2) ouvre une session SSH avec le password, (3) pousse `provision-host.sh` qui crée l'utilisateur `audit-collector`, déploie la pubkey, configure sudoers + groupes SAM + drop-in sshd, (4) INSERT en base avec `is_provisioned=TRUE`, (5) **lance un scan automatique** en arrière-plan (fire-and-forget) pour collecter immédiatement les `authorized_keys` existants. Si le SSH échoue, **aucune donnée n'est écrite**.

### B. CLI, un serveur, avec mot de passe

```bash
podman exec sam-server python3 /app/app/manage.py servers add \
    --hostname server-prod-01 --ip 192.168.1.10 \
    --ssh-user root --ssh-password 'SECRET' \
    [--env production] [--os rhel] [--port 22]
```

Si `--ssh-password` est absent, il est demandé en interactif (`hide_input=True`). Le scan initial est **synchrone** depuis la CLI (le process meurt sinon avant la fin du thread) — la commande retourne après le scan, typiquement 3–5 sec.

### C. CLI, un serveur, sans mot de passe (votre propre clé SSH root)

Workflow 3 étapes — utile quand SAM ne doit jamais voir vos credentials :

```bash
HOSTNAME=server-prod-01
IP=192.168.1.10

# 1. register — génère la per-server keypair, INSERT avec is_provisioned=FALSE
podman exec sam-server python3 /app/app/manage.py servers register \
    --hostname "$HOSTNAME" --ip "$IP"

# 2. push la per-server pubkey avec VOTRE clé SSH root
PUB=$(podman exec sam-server python3 /app/app/manage.py servers show "$HOSTNAME" --pubkey)
ssh root@"$IP" "sudo bash -s '$PUB' 'audit-collector'" \
    < <(podman exec sam-server cat /app/provision-host.sh)

# 3. activate — vérifie connectivité avec la per-server key, passe is_provisioned=TRUE,
#    déclenche un scan initial synchrone
podman exec sam-server python3 /app/app/manage.py servers activate "$HOSTNAME"
```

### D. CLI, plusieurs serveurs en bulk, avec mot de passe

Si tous les serveurs partagent le **même** mot de passe root (cas image cloud-init / Ansible fresh) :

```bash
PASS='SECRET'
for ip in 192.168.1.{10..15}; do
  podman exec sam-server python3 /app/app/manage.py servers add \
      --hostname "srv-${ip##*.}" --ip "$ip" \
      --ssh-user root --ssh-password "$PASS"
done
```

Pour des mots de passe différents par hôte, scripte une boucle qui lit un fichier `ip:password` ou un coffre (vault, pass, sops…) — le password n'est passé qu'en argument CLI, jamais persisté.

### E. CLI, plusieurs serveurs en bulk, sans mot de passe (cloud-init / clé pré-déployée)

```bash
for ip in 192.168.1.{10..15}; do
  hostname=srv-${ip##*.}
  # register
  podman exec sam-server python3 /app/app/manage.py servers register \
      --hostname "$hostname" --ip "$ip"
  # push avec votre clé root
  PUB=$(podman exec sam-server python3 /app/app/manage.py servers show "$hostname" --pubkey)
  ssh root@"$ip" "sudo bash -s '$PUB' 'audit-collector'" \
      < <(podman exec sam-server cat /app/provision-host.sh)
  # activate (scan initial inclus)
  podman exec sam-server python3 /app/app/manage.py servers activate "$hostname"
done
```

Parallélisable avec GNU `parallel`, Ansible (`ansible -m shell`), ou tout outil de CM.

### F. Déclaratif via `servers.yml` (legacy — manuel)

```yaml
# /data/config/servers.yml
servers:
  - hostname: server-prod-01
    ip: 192.168.1.10
    environment: production   # optionnel
    os_family: rhel           # optionnel
```

Cette méthode crée l'entrée en base sans provisionnement SSH automatique — équivalent d'un `register` manuel. Il faut ensuite déployer la pubkey et activer comme dans le workflow **C** ci-dessus.

---

### Provisioning script — interface

`provision-host.sh` accepte deux arguments positionnels :

```bash
sudo bash provision-host.sh <pubkey> <collector_user>
```

Le script est **idempotent** : il peut être rejoué sans risque (rebuild SAM, rotation de clé, mise à jour des règles sudoers). Le bouton **Re-provision** sur la vue détail d'un serveur (rôle `sysadmin`) l'invoque depuis SAM avec saisie d'un nouveau mot de passe SSH ; le snippet manuel est également affiché dans le bloc dépliable **« Provision with your own SSH credentials »** sur chaque ServerDetail.

> **Note** : Les connexions SSH utilisent toujours l'adresse IP déclarée, jamais la résolution DNS, pour éviter les ambiguïtés réseau et les bans CrowdSec/fail2ban.

---

### Rotation manuelle de la clé per-server

Depuis **ServerDetail** (rôle `sysadmin`), le bouton **Rotate collector key** (teal) déclenche une rotation **atomique avec rollback** :

1. Génère un nouveau keypair `<uuid>.key.new` localement
2. SSH avec l'ancienne clé, append la nouvelle pubkey à `~audit-collector/.ssh/authorized_keys`
3. Re-connecte avec la **nouvelle** clé pour vérifier
4. SSH une dernière fois pour retirer l'ancienne pubkey distante
5. Renomme les fichiers locaux (`.new` → courant, ancien supprimé)

À toute étape, en cas d'échec, l'ancienne clé reste seule active et un audit `COLLECTOR_KEY_ROTATION_FAILED` est écrit (avec le message d'erreur, sans hostname/IP pour minimiser l'info disponible). Le succès écrit `COLLECTOR_KEY_ROTATED` avec le nouveau fingerprint.

---

### Renommage d'un serveur

Depuis **ServerDetail** (rôle `sysadmin`) → bouton **Edit** → champ Hostname éditable. Le formulaire :

- Valide le nouveau nom (RFC 1123)
- Refuse si le nouveau nom est déjà utilisé par un autre serveur
- Affiche un avertissement contextuel : « Renaming changes the URL. A SERVER_RENAMED audit entry records the change. »

Après save, l'UI redirige vers `/servers/<nouveau-hostname>` (le component remount proprement). Un audit `SERVER_RENAMED` enregistre `{old_hostname, new_hostname}` avec l'admin et l'horodatage.

**À propos de l'historique d'audit après renommage**. Trois sources coexistent et chacune répond à une question :

1. La colonne **SERVER** dans la vue Audit affiche toujours le hostname **courant** (JOIN SQL sur l'UUID `target_server`). Un audit qui pointerait vers un nom obsolète serait cassé.
2. Le champ **`details` JSONB** de chaque entrée garde le hostname **figé au moment de l'événement** (ex : `SCAN_COMPLETED → {hostname: "srv-12-119"}`). Le code ne réécrit jamais l'audit.
3. Les entrées **`SERVER_RENAMED`** permettent de reconstruire toute la timeline des renommages.

Croiser le `details` d'une entrée avec la chronologie des `SERVER_RENAMED` reconstruit précisément sous quel nom le serveur était connu à un instant T.

---

## Workflow — Gestion du cycle de vie d'un serveur

Depuis la vue détail d'un serveur (**Dashboard > clic sur hostname**) :

| Action | Effet |
|---|---|
| **Scan** | Lance un scan immédiat (ne pas attendre le cycle cron). |
| **Edit** | Modifie hostname, IP, environnement, OS, port SSH ou `max_sessions` (rôle `sysadmin`). Renommer émet un audit `SERVER_RENAMED` et redirige l'UI. |
| **Disable** | Le serveur n'est plus scanné automatiquement. Indicateur rouge sur Dashboard et bandeau rouge dans ServerDetail. |
| **Re-provision** | Rejoue `provision-host.sh` à distance avec un nouveau mot de passe (rôle `sysadmin`, serveur actif) — utile après rebuild SAM ou changement de contrat sudoers. |
| **Rotate collector key** | Génère une nouvelle per-server keypair, la déploie et retire l'ancienne — opération atomique avec rollback (rôle `sysadmin`, serveur actif et provisioned). |
| **Delete** | Suppression définitive du serveur, de toutes ses clés, autorisations, sessions et de sa per-server keypair (action irréversible). |

---

## Workflow — Premier scan

```bash
# Scan de tous les serveurs actifs
podman exec sam-server python3 /app/app/manage.py servers scan

# Ou via l'interface web : Dashboard > "Scanner maintenant"
# Ou via la vue détail d'un serveur : bouton "Scanner"
```

Lors du premier scan :
- Les scripts `sam-collect` et `sam-revoke` sont déployés sur chaque hôte (via SFTP, hash SHA256 vérifié)
- Toutes les clés présentes dans `authorized_keys` sont importées avec le statut `PENDING_REVIEW`
- Une alerte email CRITIQUE est envoyée pour chaque clé inconnue détectée

Si le scan d'un serveur échoue (SSH injoignable, sudo manquant, timeout…), le serveur passe en statut **Scan Failed** :
- Indicateur 🟠 visible dans le tableau de bord (badge orange)
- Bandeau orange en haut de la vue détail du serveur
- Les boutons **Valider** et **Révoquer** sont désactivés jusqu'au prochain scan réussi
- Une alerte email CRITIQUE est envoyée

---

## Mettre à jour SAM

Quand vous mettez à jour SAM (rebuild de l'image, bump de version), trois cas de figure selon le contenu de la mise à jour.

### 1. Mise à jour transparente (cas le plus fréquent)

La plupart des releases ne modifient que la couche applicative Python ou le frontend Vue. Aucun changement côté hôtes gérés, rien à faire — il suffit de redémarrer le container SAM avec la nouvelle image.

### 2. Mise à jour des scripts SAM_* (sam-collect, sam-revoke, sam-self-update, etc.)

Si la nouvelle version modifie un script `SAM_*` déployé sur les hôtes (constantes `bytes` dans `app/ssh.py`), `ensure_scripts()` s'en rend compte au prochain scan en comparant les hashes SHA256 et redéploie automatiquement le script via SFTP + `sudo install -m 750`. Visible dans la vue Audit comme `SCRIPT_DEPLOYED`. **Aucune action admin requise.**

### 3. Mise à jour du contrat sudoers ou sshd posé par provision-host.sh

Si la nouvelle version étend `provision-host.sh` (nouvelle règle sudoers, nouveau groupe Unix, durcissement du drop-in sshd…), les serveurs déjà provisionnés ne se mettent **pas** à jour automatiquement. Ils sont signalés par le badge **« Reprovisionnement requis »** sur le Dashboard et listent une entrée `PROVISION_UPDATE_FAILED` dans l'audit log.

**Pourquoi** : `audit-collector` n'a pas le droit de réécrire son propre fichier sudoers (par design — sinon une compromission de la clé donnerait root illimité). Une intervention root sur chaque serveur concerné est nécessaire **une seule fois** ; ensuite `sam-self-update` prend le relais automatiquement à chaque scan.

Deux voies pour ce re-provisioning :

**Option A — Via l'interface web (pratique pour ~5 serveurs)**

Dashboard → cliquer sur le hostname → bouton **Re-provisionner** (rôle `sysadmin` requis). Le formulaire demande le mot de passe SSH root, qui sert une fois pour rejouer `provision-host.sh` puis n'est jamais stocké.

**Option B — Scripté avec vos propres credentials (pour 50+ serveurs)**

Si vous avez déjà une clé SSH d'admin déployée sur vos serveurs, vous pouvez rejouer `provision-host.sh` sans passer par l'UI ni saisir aucun mot de passe :

```bash
for ip in 192.168.1.10 192.168.1.11 192.168.1.12; do
  hostname=$(podman exec sam-server psql -At -d ssh_manager \
      -c "SELECT hostname FROM servers WHERE ip_address='$ip';")
  PUB=$(podman exec sam-server python3 /app/app/manage.py servers show $hostname --pubkey)
  ssh root@"$ip" "sudo bash -s '$PUB'" \
    < <(podman exec sam-server cat /app/provision-host.sh)
done
```

Cette commande SSH-e avec **votre** clé / ssh-agent, exécute `provision-host.sh` en root sur la cible, et n'introduit aucun secret côté SAM. Vous pouvez paralléliser avec GNU `parallel`, Ansible (`ansible -m shell -a "..."`), ou tout outil de CM que vous utilisez déjà.

Au prochain scan suivant le re-provisioning, `sam-self-update` réussit, le badge disparaît, audit log écrit `PROVISION_UPDATED`. **Plus aucune action manuelle ne sera nécessaire** pour les mises à jour SAM ultérieures, tant que celles-ci ne changent pas à nouveau le contrat sudoers d'`audit-collector`.

---

## Audit de la configuration sshd du serveur

La vue détail d'un serveur affiche un panneau **SSH config audit** qui lit la configuration `sshd` effective de l'hôte (via `sudo sshd -T`, lecture seule, aucune modification effectuée par SAM) et la confronte à une politique de durcissement déclarative. Le panneau est disponible pour tous les rôles (sysadmin, operator, viewer).

> **Important — périmètre de l'audit** : `sshd -T` retourne la configuration **globale** du démon (hors blocs `Match`). Cet audit décrit donc le comportement de sshd pour les utilisateurs qui ne sont **pas** membres du groupe `sam-users` : `root`, comptes système, comptes créés manuellement par l'administrateur hors SAM. Les utilisateurs SAM, eux, sont déjà couverts par le bloc `Match Group sam-users` posé par `provision-host.sh` (publickey-only, pas de mot de passe, pas de keyboard-interactive — voir section *Authentification SSH — publickey uniquement pour `sam-users`*). En clair : un voyant rouge ici ne met pas en danger les comptes SAM, mais il signale par exemple que `root` ou un compte legacy peut se connecter par mot de passe.

### Bandeau global

Trois états possibles, calculés à chaque ouverture du panneau :

| Bandeau | Couleur | Signification |
|---|---|---|
| ✓ **Compliant** | vert | toutes les directives auditées sont conformes |
| ⚠ **Hardening needed** | orange | au moins un avertissement ou une directive manquante, sans non-conformité critique |
| ✗ **Lax configuration** | rouge | au moins une directive critique non conforme |

### Directives auditées

| Sévérité | Directives | Règle attendue |
|---|---|---|
| **Critical** | PermitRootLogin, PasswordAuthentication, PermitEmptyPasswords, HostbasedAuthentication | `no` |
| **Critical** | IgnoreRhosts | `yes` |
| **Warning** | KbdInteractiveAuthentication, ChallengeResponseAuthentication, X11Forwarding | `no` |
| **Warning** | AllowTcpForwarding | `no` ou `local` |
| **Warning** | MaxAuthTries | ≤ 3 |
| **Warning** | LoginGraceTime | ≤ 60 |
| **Warning** | UsePAM | `yes` |
| **Info** | ClientAliveInterval | > 0 |
| **Info** | LogLevel | `INFO` ou `VERBOSE` |

Survoler la cellule **Expected** affiche un tooltip décrivant la directive.

### Filtrage

La case **Non-compliant only** est cochée par défaut : sur un serveur conforme la table est vide (aucune action requise) ; sur un serveur laxiste seules les lignes problématiques s'affichent. Décocher la case pour voir l'ensemble des directives auditées.

### Note sur la politique

Les seuils ci-dessus représentent des valeurs de durcissement OpenSSH généralement attendues. SAM ne prétend pas à une conformité formelle à une norme spécifique (CIS, STIG, ANSSI BP-099 ont des recommandations équivalentes pour la majorité de ces directives, mais c'est une politique déclarative, modifiable dans `app/actions.py` via la constante `SSHD_HARDENING_POLICY`).

---

## Dépannage — Problèmes de connexion SSH

Si le provisionnement ou le scan d'un serveur distant échoue, les erreurs sont à chercher **dans deux endroits**.

### 1. Logs du container SAM

```bash
podman logs sam-server
# ou en temps réel
podman logs -f sam-server
```

Les erreurs de connexion Paramiko (`AuthenticationException`, `NoValidConnectionsError`, `SSHException`) y sont tracées avec l'adresse IP et le port du serveur concerné.

### 2. Logs SSH sur l'hôte distant

La connexion SSH est journalisée côté serveur. Selon l'OS :

```bash
# systemd (RHEL, Debian, Ubuntu…)
journalctl -u sshd -f

# Fichier (Alpine, certaines configs custom)
tail -f /var/log/auth.log
# ou
tail -f /var/log/secure
```

Ces logs indiquent si la connexion a été refusée (mauvaise clé, utilisateur inexistant, `MaxAuthTries` atteint, etc.).

### 3. Prérequis sudo sur l'hôte distant

**`sudo` est obligatoire** pour l'utilisateur `audit-collector` sur chaque serveur géré. Tous les scripts SAM (`sam-collect`, `sam-revoke`, `sam-add`, `sam-lock-user`, `sam-unlock-user`, `sam-sessions`) sont exécutés avec `sudo` via SSH.

Le script `provision-host.sh` configure automatiquement les règles sudoers lors du provisionnement. Si sudo n'est pas disponible ou si les règles sont absentes, toutes les opérations distantes échoueront avec `Permission denied`.

Pour vérifier la configuration sudoers sur l'hôte distant :

```bash
# Sur le serveur distant
sudo -l -U audit-collector
```

La sortie doit inclure les commandes SAM (`/usr/local/bin/sam-*`) sans demande de mot de passe (`NOPASSWD`).

`provision-host.sh` installe également les règles sudoers dédiées aux groupes SAM (`sam-operator`, `sam-pkg`, `sam-root`) — voir section [SAM sudo groups](#workflow--sam-sudo-groups). Toutes ces règles sont validées par `visudo -c` avant installation et exigent `PASSWD:` (jamais NOPASSWD pour les utilisateurs SAM). Le bloc sshd `Match Group sam-users` est aussi posé pour interdire l'authentification par mot de passe aux utilisateurs créés via `sam-add`.

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
podman exec sam-server python3 /app/app/manage.py keys list --status PENDING_REVIEW

# Valider une clé
podman exec sam-server python3 /app/app/manage.py keys validate SHA256:...

# Révoquer une clé
podman exec sam-server python3 /app/app/manage.py keys revoke SHA256:... --reason "Clé orpheline"
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
- **Utilisateur Unix** — nom du compte à créer sur le serveur cible (créé s'il n'existe pas). Le compte `root` est interdit (#386).
- **Clé publique** — le contenu de la clé `ssh-ed25519` ou `ssh-rsa` (format authorized_keys)
- **Serveur cible** — dropdown des serveurs actifs
- **Groupe SAM** — *optionnel* : `sam-operator`, `sam-pkg` ou `sam-root` (réservé `sysadmin`). Voir section [SAM sudo groups](#workflow--sam-sudo-groups).
- **Durée** — heures / date précise / illimité
- **Justification** — obligatoire

> **Prérequis sur l'hôte distant** : `bash` et `sudo` doivent être installés. Les utilisateurs SAM sont créés avec `useradd -m -s /bin/bash`, et le hook de premier login dépend du shell de login de bash. Les distributions sans `bash` par défaut (Alpine en configuration minimale, par exemple) doivent installer le paquet `bash` avant d'être provisionnées par SAM.

À la soumission, `sam-add` est exécuté sur le serveur distant via SSH :
1. Crée l'utilisateur Unix s'il n'existe pas (avec `usermod -aG sam-users` — interdit l'authentification SSH par mot de passe)
2. Si le compte est créé : génère un mot de passe temporaire, le set via `chpasswd`, écrit `~/README_first_login.txt`, et installe un hook qui invoque `passwd` au premier login interactif
3. Ajoute la clé dans `~/.ssh/authorized_keys`
4. Si un Groupe SAM est sélectionné : `sam-grant-group` ajoute l'utilisateur au groupe choisi
5. Enregistre la clé dans la base avec statut `ACTIVE`, l'expiration choisie, et le `sam_group` éventuel

### Premier login d'un utilisateur SAM

Lors du premier login SSH (par clé), l'utilisateur voit le contenu de `~/README_first_login.txt` (mot de passe temporaire), puis `passwd` est invoqué automatiquement pour le forcer à choisir un mot de passe personnel. Ce mot de passe est requis pour `sudo` (les règles sudoers SAM exigent `PASSWD:`).

Le fichier qui porte ce hook varie selon la distribution. `sam-add` reproduit fidèlement l'ordre que bash utilise lui-même pour choisir son fichier d'init en shell de login : il écrit dans `~/.bash_profile` s'il existe (cas des familles RHEL / Rocky / Alma / CentOS où `/etc/skel/` le fournit), sinon dans `~/.bash_login` (rarissime), sinon dans `~/.profile` (Debian / Ubuntu / openSUSE / Arch — créé si absent). Cette détection garantit que le hook est sourcé sur tous les Linux mainstream sans dépendre de la distribution. Pour qu'elle fonctionne, le shell de l'utilisateur doit rester `bash` ; un changement manuel ultérieur vers `zsh` ou `fish` empêcherait le hook de s'exécuter.

### Authentification SSH — publickey uniquement pour `sam-users`

Un utilisateur du groupe `sam-users` ne peut **jamais** se connecter en SSH autrement qu'avec sa clé publique enregistrée dans SAM — ni par mot de passe, ni par mot de passe vide, ni via un mécanisme interactif (PAM keyboard-interactive). Cette règle est appliquée par `provision-host.sh` sur chaque serveur géré, et reste active même si l'authentification par mot de passe est activée globalement sur l'hôte.

Le mot de passe Unix de l'utilisateur (défini au premier login) sert **uniquement à `sudo`**, jamais à la connexion SSH.

`provision-host.sh` valide la configuration sshd avant de l'appliquer : si la validation échoue, l'ancienne configuration est restaurée et sshd n'est pas rechargé — aucune configuration invalide ne peut être mise en production par mégarde.

---

## Workflow — SAM sudo groups

Trois groupes Unix prédéfinis sont créés par `provision-host.sh` sur chaque serveur géré : `sam-operator`, `sam-pkg`, `sam-root`. Chaque groupe a un jeu de règles sudoers dédié (validé par `visudo -c` avant installation, exigeant `PASSWD:` — jamais `NOPASSWD:`, avec `secure_path` explicite incluant `/usr/local/bin` pour résoudre les binaires NS8 type `runagent` / `api-cli`).

### `sam-operator` — exploitation et diagnostic

Cible : opérateurs qui doivent superviser et redémarrer des services sans pouvoir installer de paquets ni accéder à des données sensibles. Règles sudoers installées dans `/etc/sudoers.d/sam-operator` :

| Catégorie | Commandes autorisées (en tant que `root`, `PASSWD:`) |
|---|---|
| Services systemd | `systemctl restart`, `systemctl reload`, `systemctl status`, `systemctl start` |
| Journaux | `journalctl -u`, `journalctl -f`, `journalctl -n`, `journalctl --since`, `journalctl -b`, `journalctl -e` |
| Réseau / processus | `ss -tlnp`, `lsof`, `lsof -i` |
| Diagnostic noyau | `dmesg` |
| Disque | `du -sh /var/* /opt/* /home/*` |
| Outils NS8 (si présents) | `runagent` |

`api-cli` est **volontairement absent** de `sam-operator` : cet outil de gestion NS8 dépasse le périmètre d'exploitation et reste réservé à `sam-pkg` (#394).

### `sam-pkg` — exploitation + gestion paquets

Cible : utilisateurs qui doivent en plus installer ou mettre à jour des paquets. Hérite **de toutes les commandes `sam-operator`** et ajoute la gestion paquets adaptée à la distribution détectée par `provision-host.sh`. Règles sudoers dans `/etc/sudoers.d/sam-pkg` :

| Catégorie | Commandes autorisées (en plus de sam-operator) |
|---|---|
| Debian / Ubuntu | `apt install`, `apt upgrade` |
| RHEL / Rocky / Alma | `dnf install`, `dnf upgrade` (ou `yum install`, `yum update`) |
| SUSE | `zypper install`, `zypper update` |
| Alpine | `apk add`, `apk upgrade` |
| Arch | `pacman -S`, `pacman -Syu`, `pacman -Sy` |
| Modules NS8 (si présents) | `add-module`, `remove-module` |
| Outils NS8 (si présents) | `api-cli` |

### `sam-root` — équivalent root

Cible : administrateurs ayant besoin d'un accès root complet. Règles sudoers dans `/etc/sudoers.d/sam-root` :

```
%sam-root ALL=(ALL) ALL
```

Le mot de passe personnel reste exigé (`PASSWD:` implicite — il n'y a pas de `NOPASSWD`). L'attribution du groupe `sam-root` est réservée au rôle `sysadmin` côté API SAM (voir matrice RBAC dans `app/CLAUDE.md`).

### Vérifier la configuration sur un serveur

```bash
# Sur le serveur géré
sudo -l -U alice                   # liste les commandes autorisées pour alice
getent group sam-operator sam-pkg sam-root sam-users
cat /etc/sudoers.d/sam-operator
visudo -c                          # valide tous les fichiers /etc/sudoers.d/
```

**Assignation du groupe** :
- À la création de la clé : champ Groupe SAM du formulaire « Déployer une clé SSH »
- Après création : actions **Promouvoir / Changer / Révoquer le groupe** depuis la vue Accès (rôles autorisés : `operator` pour sam-operator/sam-pkg, `sysadmin` uniquement pour sam-root)

**Cycle de vie** :
- Promotion : `POST /api/access/grant-group`
- Changement : `PUT /api/access/change-group` (révoque l'ancien, assigne le nouveau)
- Révocation : `POST /api/access/revoke-group` (l'utilisateur Unix reste actif, seul le groupe SAM est retiré)

Tracé en base dans `key_authorizations.sam_group` (audit v4) et dans `audit_log` (`GROUP_GRANTED`, `GROUP_REVOKED`, `GROUP_CHANGED`).

---

## Workflow — Révocation hors système

Si un scan détecte qu'une clé `ACTIVE` a disparu de `authorized_keys` sans action dans le système :

1. La clé passe au statut `REVOKED` avec `revoked_automatically = true` et `revoked_by = NULL`
2. Une entrée `ANOMALY_DETECTED` est créée dans l'audit
3. Un **email CRITIQUE** est envoyé immédiatement
4. La clé apparaît dans **Anomalies > Révocations hors système**

Action recommandée : investiguer l'origine de la suppression (accès root direct ? compromission ?).

---

## Alerte dépassement de sessions SSH

Chaque serveur possède un seuil configurable **`max_sessions`** (défaut : **2**). À la fin de chaque scan, le nombre de sessions SSH actives est comparé à ce seuil.

### Comportement

- Si le nombre de sessions actives **dépasse** `max_sessions`, une alerte email **WARNING** est envoyée à tous les administrateurs ayant `receive_alerts=true`.
- Un **anti-spam 24 h** est appliqué : si une alerte `SESSION_LIMIT_EXCEEDED` a déjà été envoyée dans les dernières 24 heures pour ce serveur, l'email est supprimé. Cela évite de spammer à chaque cycle cron (toutes les 4 heures).
- L'alerte est tracée dans l'`audit_log` avec l'action `SESSION_LIMIT_EXCEEDED` et les détails `{ hostname, session_count, max_sessions }`.

### Contenu de l'email

```
[WARNING] [ssh-access-manager] Session limit exceeded on <hostname>

Server: <hostname>
Active sessions: <N>
Configured limit: <max_sessions>

Please review active connections on this server.
```

### Configurer le seuil par serveur

**Via l'interface web** : vue détail du serveur → bouton **Modifier** → champ **Sessions max** (min. 1).

**Via l'API REST** :

```bash
curl -s -X PUT https://<host>/api/servers/<hostname> \
  -H "Content-Type: application/json" \
  -b cookies.txt \
  -d '{"ip": "192.168.1.10", "environment": "production", "max_sessions": 5}'
```

La valeur est retournée dans tous les endpoints `GET /api/servers` et `GET /api/servers/<hostname>`.

---

## Variables d'environnement

| Variable | Description | Défaut |
|---|---|---|
| `POSTGRES_DB` | Nom de la base de données | `ssh_manager` |
| `POSTGRES_USER` | Utilisateur PostgreSQL | `ssh_manager` |
| `POSTGRES_PASSWORD` | Mot de passe PostgreSQL | — |
| `NGINX_PORT` | Port d'écoute Nginx | `8080` |
| `NGINX_TLS_CERT_PATH` | Chemin du certificat TLS (active le mode HTTPS si défini avec `NGINX_TLS_KEY_PATH`) | — |
| `NGINX_TLS_KEY_PATH` | Chemin de la clé privée TLS (active le mode HTTPS si défini avec `NGINX_TLS_CERT_PATH`) | — |
| `FLASK_SECRET_KEY` | Clé secrète Flask (sessions) — **obligatoire**, le container refuse de démarrer si absente | — |
| `SMTP_HOST` | Serveur SMTP | — |
| `SMTP_PORT` | Port SMTP | `587` |
| `SMTP_USERNAME` | Utilisateur SMTP — si vide, `auth off` dans msmtp (relay sans authentification) | — |
| `SMTP_PASSWORD` | Mot de passe SMTP | — |
| `SMTP_FROM` | Adresse expéditeur | — |
| `SMTP_ENCRYPTION` | Mode TLS : `none` / `starttls` / `tls` | `starttls` |
| `SMTP_TLSVERIFY` | Vérification certificat TLS : `1` (on) / `` (off) | `1` |
| `SMTP_ENABLED` | Active/désactive l'envoi d'emails : `1` / `` (off) | `1` |
| `SSH_USER` | Utilisateur SSH collecteur | `audit-collector` |
| `ADMIN_USERNAME` | Username de l'administrateur initial | `admin` |
| `ADMIN_EMAIL` | Email de l'administrateur initial | — |
| `ADMIN_PASSWORD` | Mot de passe de l'administrateur initial | — |

> **Destinataires des alertes** : les alertes sont envoyées aux administrateurs ayant `receive_alerts=true` (configurable par admin dans l'UI Admins). `SMTP_TO` n'est plus utilisé.
>
> **Seuils d'alerte expiration** : `expire_warn_days` (défaut 7) et `expire_warn_days_2` (défaut 2) sont configurables sans redémarrage depuis **Settings → Expiry warnings**.
>
> **Fuseau horaire** : les dates sont stockées en UTC dans PostgreSQL. L'interface web affiche automatiquement les dates dans le fuseau du navigateur.
>
> **HTTPS (optionnel)** : si `NGINX_TLS_CERT_PATH` et `NGINX_TLS_KEY_PATH` sont tous deux définis, Nginx utilise `nginx.conf.https.template` (TLSv1.2/1.3, ciphers ECDHE, HSTS) et active une redirection `HTTP -> HTTPS` (`301`), y compris si une requête HTTP arrive par erreur sur le port TLS. Ces chemins sont **des chemins internes au conteneur** : vos certificats doivent donc être présents (ou montés) à cet emplacement dans le conteneur. Si les fichiers n'existent pas encore, un certificat auto-signé est généré automatiquement au démarrage. Sans ces variables, Nginx utilise `nginx.conf.http.template` (HTTP pur, aucune directive SSL).
>
> **Exemple docker-compose (certificats montés)** :
> ```yaml
> services:
>   sam-server:
>     volumes:
>       - ssh_data:/data
>       - ./certs:/data/certs:ro
>     environment:
>       - NGINX_TLS_CERT_PATH=/data/certs/server.crt
>       - NGINX_TLS_KEY_PATH=/data/certs/server.key
> ```
> Dans cet exemple, `server.crt` et `server.key` sont stockés sur l'hôte dans `./certs` puis exposés en lecture seule dans le conteneur.

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
EXEC="podman exec sam-server python3 /app/app/manage.py"

# Serveurs
$EXEC servers list
$EXEC servers add --hostname HOST --ip IP --ssh-user USER --ssh-password PASS [--env production] [--os rhel] [--port 22]
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
$EXEC admin reset-password USERNAME --password NEW_PASSWORD

# Audit
$EXEC audit list --action ANOMALY_DETECTED --since 2025-01-01
$EXEC audit list --server HOST

# Système
$EXEC system status
$EXEC system report
```

---

## Récupération de mot de passe administrateur

Si un administrateur a perdu son mot de passe, un sysadmin ayant accès au container peut le réinitialiser via la CLI sans connexion préalable :

```bash
# Docker
docker exec -it ssh-access-manager python3 /app/app/manage.py admin reset-password <username> --password <new_password>

# Podman
podman exec -it sam-server python3 /app/app/manage.py admin reset-password <username> --password <new_password>
```

Contraintes :
- Le mot de passe doit respecter la politique de sécurité (8+ caractères, majuscule, minuscule, chiffre, caractère spécial)
- Fonctionne même si le compte est désactivé
- L'opération est tracée dans l'audit log (`PASSWORD_RESET`, `performed_by=NULL`)

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
