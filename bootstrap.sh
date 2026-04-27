#!/bin/sh
set -e

# ---------------------------------------------------------------------------
# Génération nginx.conf depuis template + ENV
# ---------------------------------------------------------------------------
generate_nginx_conf() {
    sed \
        -e "s|{{NGINX_PORT}}|${NGINX_PORT:-8080}|g" \
        /app/nginx.conf.template > /etc/nginx/nginx.conf
}

# ---------------------------------------------------------------------------
# Génération /etc/crontabs/root depuis ENV (SCAN_INTERVAL_HOURS)
# ---------------------------------------------------------------------------
generate_crontab() {
    cat > /etc/crontabs/root << 'EOF'
# ssh-access-manager — généré par bootstrap.sh
*/5 * * * * python3 /app/app/collect.py >> /dev/stdout 2>&1
*/5 * * * * python3 /app/app/expire.py >> /dev/stdout 2>&1
EOF
}

# ---------------------------------------------------------------------------
# Génération /etc/msmtprc depuis template + ENV
# ---------------------------------------------------------------------------
generate_msmtprc() {
    sed \
        -e "s|{{SMTP_HOST}}|${SMTP_HOST:-mail.example.com}|g" \
        -e "s|{{SMTP_PORT}}|${SMTP_PORT:-587}|g" \
        -e "s|{{SMTP_USER}}|${SMTP_USER:-alerts@example.com}|g" \
        -e "s|{{SMTP_PASSWORD}}|${SMTP_PASSWORD:-changeme}|g" \
        -e "s|{{SMTP_FROM}}|${SMTP_FROM:-ssh-manager@example.com}|g" \
        /app/msmtp.conf.template > /etc/msmtprc
    chmod 640 /etc/msmtprc
    chown root:nobody /etc/msmtprc
}

# ---------------------------------------------------------------------------
# Premier démarrage — détecté par l'absence de /data/pg/PG_VERSION
# ---------------------------------------------------------------------------
if [ ! -f /data/pg/PG_VERSION ]; then
    echo "[bootstrap] Premier démarrage détecté."

    # 1. Créer les répertoires du volume
    mkdir -p /data/keys /data/pg /data/config

    # 2. Chown postgres en premier (obligatoire avant initdb)
    chown postgres:postgres /data/pg
    chmod 700 /data/pg

    # 3. Générer la paire de clés ED25519 du collecteur
    ssh-keygen -t ed25519 \
        -f /data/keys/collector_key \
        -N "" \
        -C "ssh-access-manager@$(hostname)"
    chown nobody:nobody /data/keys/collector_key
    chmod 600 /data/keys/collector_key

    # 4. Créer known_hosts vide
    touch /data/keys/known_hosts
    chown nobody:nobody /data/keys/known_hosts
    chmod 644 /data/keys/known_hosts

    # 5. Initialiser le cluster PostgreSQL
    su -s /bin/sh postgres -c "initdb -D /data/pg --encoding=UTF8 --locale=C"

    # 6. Démarrer PostgreSQL temporairement (socket locale uniquement)
    su -s /bin/sh postgres -c "pg_ctl -D /data/pg -o '-k /tmp' start -w"

    # 7. Créer la base et l'utilisateur depuis ENV
    # CREATE DATABASE ne peut pas s'exécuter dans une transaction : deux appels séparés
    su -s /bin/sh postgres -c "psql -h /tmp -c \"CREATE USER ${POSTGRES_USER:-ssh_manager} WITH PASSWORD '${POSTGRES_PASSWORD:-changeme}';\""
    su -s /bin/sh postgres -c "psql -h /tmp -c \"CREATE DATABASE ${POSTGRES_DB:-ssh_manager} OWNER ${POSTGRES_USER:-ssh_manager};\""

    # 8. Appliquer le schéma SQL
    su -s /bin/sh postgres -c \
        "psql -h /tmp -U ${POSTGRES_USER:-ssh_manager} -d ${POSTGRES_DB:-ssh_manager} \
         -f /app/sql/schema.sql"

    # 9. Insérer l'administrateur initial depuis ENV
    # Utilise Python+psycopg2 pour éviter l'interpolation shell du hash ($...)
    python3 << 'PYEOF'
import os, psycopg2
from werkzeug.security import generate_password_hash

conn = psycopg2.connect(
    host="/tmp",
    dbname=os.environ.get("POSTGRES_DB", "ssh_manager"),
    user=os.environ.get("POSTGRES_USER", "ssh_manager"),
    password=os.environ.get("POSTGRES_PASSWORD", "changeme"),
)
conn.autocommit = True
cur = conn.cursor()
cur.execute(
    """INSERT INTO administrators (username, email, role, password_hash)
       VALUES (%s, %s, 'sysadmin', %s)
       ON CONFLICT (username) DO NOTHING""",
    (
        os.environ.get("ADMIN_USERNAME", "admin"),
        os.environ.get("ADMIN_EMAIL", "admin@example.com"),
        generate_password_hash(os.environ.get("ADMIN_PASSWORD", "changeme")),
    ),
)
conn.close()
print("[bootstrap] Administrateur initial insere.")
PYEOF

    # 10. Arrêter PostgreSQL temporaire
    su -s /bin/sh postgres -c "pg_ctl -D /data/pg -o '-k /tmp' stop -w"

    # 11. Générer msmtprc
    generate_msmtprc

    # 12. Générer nginx.conf
    generate_nginx_conf

    # 13. Générer crontab depuis SCAN_INTERVAL_HOURS
    generate_crontab

    # 14. Afficher la clé publique du collecteur dans les logs
    echo ""
    echo "================================================================"
    echo " CLÉ PUBLIQUE DU COLLECTEUR — à déployer sur chaque hôte distant"
    echo " via : bash provision-host.sh \"<contenu ci-dessous>\""
    echo "================================================================"
    cat /data/keys/collector_key.pub
    echo "================================================================"
    echo ""

else
    echo "[bootstrap] Démarrage normal (données existantes)."

    # Régénérer la configuration depuis ENV à chaque démarrage
    generate_nginx_conf
    generate_msmtprc
    generate_crontab
fi

# ---------------------------------------------------------------------------
# Préparer le répertoire de socket PostgreSQL (requis par Alpine postgresql18)
# ---------------------------------------------------------------------------
mkdir -p /run/postgresql
chown postgres:postgres /run/postgresql

# ---------------------------------------------------------------------------
# Lancer supervisord (toujours en dernier)
# ---------------------------------------------------------------------------
exec /usr/bin/supervisord -c /etc/supervisord.conf
