#!/bin/sh
# Usage : bash provision-host.sh "<contenu collector_key.pub>"
# Prépare un hôte distant pour la collecte SSH par audit-collector.
set -e

COLLECTOR_PUBKEY="${1}"
COLLECTOR_USER="${2:-audit-collector}"
SUDOERS_FILE="/etc/sudoers.d/${COLLECTOR_USER}"

if [ -z "${COLLECTOR_PUBKEY}" ]; then
    echo "Usage : $0 \"<contenu collector_key.pub>\"" >&2
    exit 1
fi

# 1. Créer l'utilisateur système (sans shell interactif)
if ! id "${COLLECTOR_USER}" >/dev/null 2>&1; then
    useradd -r -m -s /bin/bash "${COLLECTOR_USER}"
    echo "[provision] Utilisateur ${COLLECTOR_USER} créé."
else
    echo "[provision] Utilisateur ${COLLECTOR_USER} existe déjà."
fi
chmod 700 "/home/${COLLECTOR_USER}"

# 2. Configurer le répertoire SSH
SSH_DIR="/home/${COLLECTOR_USER}/.ssh"
AUTH_KEYS="${SSH_DIR}/authorized_keys"

mkdir -p "${SSH_DIR}"
chmod 700 "${SSH_DIR}"
chown "${COLLECTOR_USER}:${COLLECTOR_USER}" "${SSH_DIR}"

# 3. Déployer la clé publique (ajout si absente, ne pas écraser les clés existantes)
touch "${AUTH_KEYS}"
if ! grep -qF "${COLLECTOR_PUBKEY}" "${AUTH_KEYS}" 2>/dev/null; then
    echo "${COLLECTOR_PUBKEY}" >> "${AUTH_KEYS}"
fi
chmod 600 "${AUTH_KEYS}"
chown "${COLLECTOR_USER}:${COLLECTOR_USER}" "${AUTH_KEYS}"
echo "[provision] Clé publique déployée dans ${AUTH_KEYS}."

# 4. Créer le fichier sudoers
# printf avec \n explicite : résistant au \r\n introduit par sudo PTY lors d'un pipe
printf "# ssh-access-manager — droits sudo pour ${COLLECTOR_USER}\n" > "${SUDOERS_FILE}"
printf "${COLLECTOR_USER} ALL=(root) NOPASSWD: /usr/local/bin/sam-collect\n" >> "${SUDOERS_FILE}"
printf "${COLLECTOR_USER} ALL=(root) NOPASSWD: /usr/local/bin/sam-revoke\n" >> "${SUDOERS_FILE}"
printf "${COLLECTOR_USER} ALL=(root) NOPASSWD: /usr/local/bin/sam-add\n" >> "${SUDOERS_FILE}"
printf "${COLLECTOR_USER} ALL=(root) NOPASSWD: /usr/local/bin/sam-lock-user\n" >> "${SUDOERS_FILE}"
printf "${COLLECTOR_USER} ALL=(root) NOPASSWD: /usr/local/bin/sam-unlock-user\n" >> "${SUDOERS_FILE}"
printf "${COLLECTOR_USER} ALL=(root) NOPASSWD: /usr/local/bin/sam-sessions\n" >> "${SUDOERS_FILE}"
printf "${COLLECTOR_USER} ALL=(root) NOPASSWD: /usr/bin/install -m 750 -o root -g root /home/${COLLECTOR_USER}/sam-collect /usr/local/bin/sam-collect\n" >> "${SUDOERS_FILE}"
printf "${COLLECTOR_USER} ALL=(root) NOPASSWD: /usr/bin/install -m 750 -o root -g root /home/${COLLECTOR_USER}/sam-revoke /usr/local/bin/sam-revoke\n" >> "${SUDOERS_FILE}"
printf "${COLLECTOR_USER} ALL=(root) NOPASSWD: /usr/bin/install -m 750 -o root -g root /home/${COLLECTOR_USER}/sam-add /usr/local/bin/sam-add\n" >> "${SUDOERS_FILE}"
printf "${COLLECTOR_USER} ALL=(root) NOPASSWD: /usr/bin/install -m 750 -o root -g root /home/${COLLECTOR_USER}/sam-lock-user /usr/local/bin/sam-lock-user\n" >> "${SUDOERS_FILE}"
printf "${COLLECTOR_USER} ALL=(root) NOPASSWD: /usr/bin/install -m 750 -o root -g root /home/${COLLECTOR_USER}/sam-unlock-user /usr/local/bin/sam-unlock-user\n" >> "${SUDOERS_FILE}"
printf "${COLLECTOR_USER} ALL=(root) NOPASSWD: /usr/bin/install -m 750 -o root -g root /home/${COLLECTOR_USER}/sam-sessions /usr/local/bin/sam-sessions\n" >> "${SUDOERS_FILE}"

chmod 440 "${SUDOERS_FILE}"
echo "[provision] Sudoers configuré dans ${SUDOERS_FILE}."

echo "[provision] Hôte prêt pour la collecte SSH par ${COLLECTOR_USER}."
