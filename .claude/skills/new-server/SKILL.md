---
name: new-server
description: Workflow complet d'ajout d'un nouveau serveur distant dans ssh-access-manager — provision de l'hôte, ajout dans servers.yml, sync BDD, premier scan SSH.
user-invocable: true
disable-model-invocation: true
---

# Skill new-server — ssh-access-manager

## Usage

```
/new-server
```

Invoquer quand un nouvel hôte doit être intégré au système de collecte SSH.

## Prérequis

- Le container ssh-access-manager est démarré
- L'hôte distant est joignable depuis le container (port 22 ouvert)
- La clé publique du collecteur est disponible dans les logs ou dans `/data/keys/collector_key.pub`

## Étapes

### 1. Récupérer la clé publique du collecteur

```bash
# Dans les logs du container au premier démarrage, ou :
cat /data/keys/collector_key.pub
```

Copier le contenu complet (commence par `ssh-ed25519 AAAA...`).

### 2. Provisionner l'hôte distant

Sur l'hôte distant (en tant que root ou avec sudo) :

```bash
bash provision-host.sh "<contenu de collector_key.pub>"
```

Vérifier que le script a :
- Créé l'utilisateur `audit-collector`
- Déployé la clé publique dans `/home/audit-collector/.ssh/authorized_keys`
- Créé `/etc/sudoers.d/audit-collector` (chmod 440)

### 3. Tester la connexion SSH manuellement

Depuis le container :

```bash
ssh -i /data/keys/collector_key \
    -o UserKnownHostsFile=/data/keys/known_hosts \
    -o StrictHostKeyChecking=accept-new \
    audit-collector@<IP_HÔTE> \
    sudo /usr/local/bin/sam-collect
```

Si la commande affiche des lignes `authorized_keys`, la connexion est opérationnelle.

**Note** : `StrictHostKeyChecking=accept-new` est utilisé ici pour le test manuel uniquement. Le code Python utilise `RejectPolicy` avec `ssh-keyscan` préalable.

### 4. Ajouter le serveur dans servers.yml

Éditer `/data/config/servers.yml` :

```yaml
servers:
  - hostname: <HOSTNAME>
    ip: <IP>
    environment: <production|staging|lab>
    os_family: <rhel|debian|alpine>
```

### 5. Synchroniser la BDD via CLI

```bash
python3 /app/app/manage.py servers add \
    --hostname <HOSTNAME> \
    --ip <IP> \
    --env <production|staging|lab> \
    --os <rhel|debian|alpine>
```

Vérifier :

```bash
python3 /app/app/manage.py servers show <HOSTNAME>
```

### 6. Lancer le premier scan

```bash
python3 /app/app/manage.py servers scan --server <HOSTNAME>
```

Ce scan va :
1. Appeler `ssh-keyscan` si l'hôte est absent de `known_hosts`
2. Déployer `sam-collect` et `sam-revoke` via SFTP si absents
3. Collecter toutes les clés `authorized_keys` présentes
4. Insérer les clés inconnues en statut `PENDING_REVIEW`
5. Envoyer des alertes CRITIQUE pour chaque clé inconnue

### 7. Traiter les PENDING_REVIEW

```bash
# Lister les clés en attente de revue
python3 /app/app/manage.py keys list --status PENDING_REVIEW
```

Pour chaque clé :
- Si la clé est légitime : `python3 /app/app/manage.py keys validate <fingerprint>`
- Si la clé est inconnue/suspecte : `python3 /app/app/manage.py keys revoke <fingerprint> --reason "Clé non autorisée détectée lors du premier scan"`

### 8. Vérification finale

```bash
python3 /app/app/manage.py servers show <HOSTNAME>
python3 /app/app/manage.py keys list --server <HOSTNAME>
python3 /app/app/manage.py audit list --server <HOSTNAME>
```

## Résultat attendu

```
Serveur <HOSTNAME> ajouté ✅
Premier scan complété ✅
Clés PENDING_REVIEW traitées : N validées, M révoquées
Audit trail créé : SCAN_COMPLETED, SERVER_ADDED, SCRIPT_DEPLOYED
```

## En cas d'erreur

- **SSH refused** : vérifier que provision-host.sh a été exécuté et que le port 22 est ouvert
- **Host key verification failed** : l'hôte n'est pas dans known_hosts — relancer le scan (ssh-keyscan automatique)
- **sudo: command not found** : vérifier /etc/sudoers.d/audit-collector sur l'hôte distant
- **Permission denied** : vérifier les droits sur `/home/audit-collector/.ssh/authorized_keys` (chmod 600)
