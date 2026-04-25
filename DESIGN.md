# DESIGN.md — Justification des choix techniques

**VAE RNCP41330 — Expert en développement logiciel — Niveau 7 — C.1.6**
**Développeur : Stéphane de Labrusse**

---

## 1. Contexte et problème résolu

Les accès SSH aux serveurs de production reposent le plus souvent sur des fichiers `authorized_keys` gérés manuellement. Ce modèle produit des dérives : clés orphelines après départs, clés sans expiration, clés non conformes aux recommandations cryptographiques de l'ANSSI. ssh-access-manager automatise la collecte, la détection d'anomalies et la révocation de ces clés, avec une piste d'audit complète.

---

## 2. Choix d'architecture : container unique

### Décision

Un seul container Alpine Linux hébergeant PostgreSQL, Flask, Nginx et crond via Supervisord.

### Alternatives évaluées

| Alternative | Rejet |
|---|---|
| Kubernetes / multi-pods | Complexité opérationnelle disproportionnée pour un outil interne à faible charge |
| Docker Compose multi-services | Réseau inter-services à gérer, déploiement plus lourd pour l'usage cible |
| Zabbix / Nagios | Outils génériques de monitoring, sans modélisation des autorisations SSH ni workflow de révocation |
| Scripts Bash + cron seuls | Pas de persistance structurée, pas d'API, pas d'interface web |

### Justification

Le cas d'usage est un outil d'audit interne avec une charge faible (dizaines de serveurs, quelques administrateurs). La simplicité de déploiement (`podman run`) prime sur la scalabilité horizontale. Le volume unique `/data` garantit la persistance sans orchestrateur externe.

---

## 3. Base de données : PostgreSQL 18

### Décision

PostgreSQL 18 via `apk postgresql18` dans Alpine 3.23.

### Alternatives évaluées

| Alternative | Rejet |
|---|---|
| SQLite | Concurrence limitée, pas de types INET, pas de colonnes GENERATED |
| MySQL / MariaDB | Moins bon support de JSONB, type INET absent, UUID moins natif |
| Redis | Base clé-valeur inadaptée aux relations complexes |

### Justification

PostgreSQL offre le type `INET` pour les adresses IP (validation native), `JSONB` pour les détails d'audit extensibles sans migration, `GENERATED ALWAYS AS … STORED` pour `is_compliant` (logique de conformité garantie par la base, pas par l'application), et `gen_random_uuid()` natif.

---

## 4. Normalisation 3NF

Le schéma respecte la troisième forme normale (3NF) :

- **1NF** : toutes les valeurs sont atomiques (pas de listes dans les colonnes), chaque table a une clé primaire UUID.
- **2NF** : chaque colonne non-clé dépend de la totalité de la clé primaire. `key_authorizations` utilise une clé composite `(key_id, server_id)` ; chaque attribut (status, expires_at…) dépend du couple clé+serveur.
- **3NF** : aucune dépendance transitive. `is_compliant` aurait pu être calculé en application à partir de `key_type` et `key_size_bits`, mais son stockage en colonne GENERATED évite la duplication de logique tout en restant fonctionnellement dépendant de la clé primaire.

**Dénormalisation intentionnelle** : `is_compliant` est `STORED` (redondant mais calculé par le SGBD). Ce choix permet l'indexation (`idx_ssh_keys_compliant`) pour des requêtes rapides sur la conformité de la flotte.

---

## 5. Sécurité SSH : paramiko + RejectPolicy

### Décision

Connexion SSH via `paramiko` avec `RejectPolicy()` obligatoire. Jamais `AutoAddPolicy`.

### Justification

`AutoAddPolicy` accepte silencieusement n'importe quel hôte, ouvrant la porte aux attaques MITM. `RejectPolicy` force l'enregistrement préalable de chaque hôte via `ssh-keyscan` dans `/data/keys/known_hosts`. Toute nouvelle clé d'hôte inconnue lève une exception, ce qui est le comportement attendu pour un outil de sécurité.

### Scripts distants versionnés

`SAM_COLLECT` et `SAM_REVOKE` sont des constantes Python `bytes` dans `ssh.py`. Leur hash SHA256 est comparé avant chaque déploiement SFTP : redéploiement uniquement si le hash diffère. Cela garantit la cohérence des scripts sur tous les serveurs sans surcoût réseau.

---

## 6. Politique de conformité ANSSI

Référence : Guide ANSSI « Recommandations pour un usage sécurisé d'OpenSSH » (ANSSI-BP-099).

| Type de clé | Taille minimale | Conforme |
|---|---|---|
| `ssh-ed25519` | N/A (taille fixe 256 bits) | ✅ Toujours |
| `ssh-rsa` | 4096 bits | ✅ Si ≥ 4096 bits |
| `ssh-rsa` | < 4096 bits | ❌ |
| `ecdsa-sha2-nistp256` | 256 bits | ⚠️ Accepté, non recommandé ANSSI |
| DSA, RSA < 2048 | — | ❌ Refusé à l'import |

La conformité est vérifiée à deux niveaux :
1. **Base de données** : colonne `is_compliant` GENERATED.
2. **Interface** : indicateur visuel ⚠️ sur chaque clé non conforme.

---

## 7. Architecture backend : actions.py comme source unique de vérité

### Décision

`web.py` (API Flask) et `manage.py` (CLI click) importent tous deux `actions.py`. Aucune logique métier n'est dupliquée.

### Justification

Sans cette séparation, modifier le comportement de la révocation (par exemple ajouter un niveau d'alerte) nécessiterait de mettre à jour deux fichiers. Avec `actions.py`, un seul point de modification suffit. Les tests unitaires `test_actions.py` couvrent la logique une seule fois (couverture ≥ 80 % imposée).

---

## 8. Build multi-stage Docker

### Décision

Stage 1 `node:22-alpine` produit `/ui/dist/`. Stage 2 `alpine:3.23.4` copie ce répertoire dans `/app/static/`.

### Justification

Node.js (> 300 Mo) n'est pas présent dans l'image finale. L'image de production ne contient que les artefacts compilés. Nginx sert les fichiers statiques directement ; Flask ne gère pas les assets.

---

## 9. Stratégie de tests

| Couche | Outil | Approche |
|---|---|---|
| Backend Python | pytest + pytest-mock | Mocks SSH, DB, msmtp — jamais de vrais serveurs |
| Expiration | freezegun | Simulation de `datetime.now()` pour les tests d'expiration |
| Frontend composants | Vitest + Vue Test Utils | Tests unitaires des composants critiques (KeyActions, ExpiryPicker, AccessForm) |
| Intégration système | Manuel | bootstrap.sh, Dockerfile, nginx.conf.template |

La règle absolue est l'isolement : aucun test ne contacte un vrai serveur SSH, une vraie base de données ou un vrai serveur SMTP. Les 4 scénarios de révocation sont couverts obligatoirement.

---

## 10. Choix frontend : Vue.js 3 + Vite

### Décision

Vue.js 3 avec Composition API (`<script setup>`), Vue Router, Vite comme bundler.

### Alternatives évaluées

| Alternative | Rejet |
|---|---|
| React | Courbe d'apprentissage plus élevée pour ce périmètre, écosystème plus fragmenté |
| Angular | Sur-dimensionné pour une SPA de 6 vues |
| Svelte | Moins mature en production au moment du projet |
| Templates Jinja2 | Pas d'interactivité temps réel (countdown, recherche live) sans JavaScript additionnel |

### Justification

Vue.js 3 + `<script setup>` offre une syntaxe concise adaptée à des composants de taille moyenne. Vite produit des builds rapides (< 1 s) et fournit un proxy de développement vers Flask sans configuration CORS. La stack est cohérente avec l'expertise habituelle du développeur.
