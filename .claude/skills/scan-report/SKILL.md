---
name: scan-report
description: Génère un rapport de scan SSH complet depuis audit_log et key_authorizations — état des serveurs, anomalies détectées, clés expirées ou en attente de revue, résumé exécutif.
user-invocable: true
disable-model-invocation: true
---

# Skill scan-report — ssh-access-manager

## Usage

```
/scan-report
```

Génère un rapport de l'état actuel du parc SSH géré par ssh-access-manager.

## Étapes

### 1. Récupérer le statut système

```bash
python3 /app/app/manage.py system status
```

### 2. Requêtes d'état depuis la BDD

Connexion via les helpers db.py ou psql direct :

```bash
export PGPASSWORD="${POSTGRES_PASSWORD:-changeme}"
PSQL="psql -h localhost -U ${POSTGRES_USER:-ssh_manager} -d ${POSTGRES_DB:-ssh_manager} -t -A"
```

#### Serveurs actifs / inactifs
```sql
SELECT
    hostname,
    ip_address,
    environment,
    os_family,
    is_active
FROM servers
ORDER BY environment, hostname;
```

#### Clés par statut
```sql
SELECT
    status,
    COUNT(*) as total
FROM key_authorizations
GROUP BY status
ORDER BY status;
```

#### Clés PENDING_REVIEW (anomalies à traiter)
```sql
SELECT
    sk.fingerprint,
    sk.key_type,
    sk.comment,
    s.hostname,
    ka.authorized_at
FROM key_authorizations ka
JOIN ssh_keys sk ON sk.id = ka.key_id
JOIN servers s ON s.id = ka.server_id
WHERE ka.status = 'PENDING_REVIEW'
ORDER BY ka.authorized_at DESC;
```

#### Clés expirées dans les 7 prochains jours
```sql
SELECT
    sk.fingerprint,
    sk.comment,
    s.hostname,
    ka.expires_at,
    ka.expires_at - now() AS temps_restant
FROM key_authorizations ka
JOIN ssh_keys sk ON sk.id = ka.key_id
JOIN servers s ON s.id = ka.server_id
WHERE ka.status = 'ACTIVE'
  AND ka.expires_at IS NOT NULL
  AND ka.expires_at < now() + interval '7 days'
ORDER BY ka.expires_at;
```

#### Anomalies détectées (30 derniers jours)
```sql
SELECT
    al.performed_at,
    al.action,
    sk.fingerprint,
    s.hostname,
    al.details
FROM audit_log al
LEFT JOIN ssh_keys sk ON sk.id = al.target_key
LEFT JOIN servers s ON s.id = al.target_server
WHERE al.action = 'ANOMALY_DETECTED'
  AND al.performed_at > now() - interval '30 days'
ORDER BY al.performed_at DESC;
```

#### Derniers scans par serveur
```sql
SELECT
    s.hostname,
    MAX(al.performed_at) AS dernier_scan,
    al.action AS resultat
FROM audit_log al
JOIN servers s ON s.id = al.target_server
WHERE al.action IN ('SCAN_COMPLETED', 'SCAN_FAILED')
GROUP BY s.hostname, al.action
ORDER BY s.hostname;
```

#### Clés non conformes actives
```sql
SELECT
    sk.fingerprint,
    sk.key_type,
    sk.key_size_bits,
    sk.comment,
    s.hostname
FROM key_authorizations ka
JOIN ssh_keys sk ON sk.id = ka.key_id
JOIN servers s ON s.id = ka.server_id
WHERE ka.status = 'ACTIVE'
  AND sk.is_compliant = false
ORDER BY s.hostname;
```

### 3. Générer le rapport formaté

```
## Rapport SSH Access Manager — [DATE]

### Résumé exécutif
- Serveurs actifs     : N
- Serveurs inactifs   : N
- Clés ACTIVE         : N
- Clés PENDING_REVIEW : N  ← À traiter
- Clés EXPIRED        : N
- Clés REVOKED        : N
- Clés non conformes  : N  ← RSA < 4096 bits ou ECDSA

### Anomalies (30 derniers jours)
[tableau : date | action | fingerprint | serveur | détails]
[ou "Aucune anomalie détectée"]

### Clés en attente de revue
[tableau : fingerprint | type | commentaire | serveur | vu le]
[ou "Aucune"]

### Expirations à venir (7 jours)
[tableau : fingerprint | commentaire | serveur | expire dans]
[ou "Aucune expiration imminente"]

### Clés non conformes actives
[tableau : fingerprint | type | taille | serveur]
[ou "Toutes les clés actives sont conformes"]

### État des derniers scans
[tableau : serveur | dernier scan | résultat]

### Actions recommandées
1. [si PENDING_REVIEW] Traiter N clés en attente de revue
2. [si expiration < 48h] Renouveler ou révoquer les clés expirant sous 48h
3. [si non conformes] Planifier remplacement des clés RSA < 4096 bits
4. [si SCAN_FAILED] Vérifier la connectivité SSH vers les serveurs en échec
```

### 4. Export optionnel

```bash
python3 /app/app/manage.py audit list --since $(date -d '7 days ago' +%Y-%m-%d) \
    > /tmp/audit-$(date +%Y%m%d).txt
```
