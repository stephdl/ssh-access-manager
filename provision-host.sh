#!/bin/sh
# Usage: bash provision-host.sh "<collector_key.pub content>"
# Prepares a remote host for SSH collection by audit-collector.
set -e

COLLECTOR_PUBKEY="${1}"
COLLECTOR_USER="${2:-audit-collector}"
SUDOERS_FILE="/etc/sudoers.d/${COLLECTOR_USER}"

if [ -z "${COLLECTOR_PUBKEY}" ]; then
    echo "Usage: $0 \"<collector_key.pub content>\"" >&2
    exit 1
fi

# 1. Create system user (without interactive shell)
if ! id "${COLLECTOR_USER}" >/dev/null 2>&1; then
    useradd -r -m -s /bin/bash "${COLLECTOR_USER}"
    echo "[provision] User ${COLLECTOR_USER} created."
else
    echo "[provision] User ${COLLECTOR_USER} already exists."
fi
chown "${COLLECTOR_USER}:${COLLECTOR_USER}" "/home/${COLLECTOR_USER}"
chmod 700 "/home/${COLLECTOR_USER}"

# 2. Configure SSH directory
SSH_DIR="/home/${COLLECTOR_USER}/.ssh"
AUTH_KEYS="${SSH_DIR}/authorized_keys"

mkdir -p "${SSH_DIR}"
chmod 700 "${SSH_DIR}"
chown "${COLLECTOR_USER}:${COLLECTOR_USER}" "${SSH_DIR}"

# 3. Deploy public key — REPLACE authorized_keys with exactly this line.
# Rationale: the audit-collector Unix account is dedicated to SAM and has
# no legitimate human user, no shell login besides this key. Any pre-
# existing entry is at best a residue of a previous SAM install, at worst
# an unmanaged key with persistent access. Same semantic as the rotation
# flow (ssh._replace_authorized_keys_remote), kept in sync to avoid the
# inconsistency where rotate cleans up but (re)provision does not.
#
# Atomic via tmp+mv so a failed write cannot leave the file empty and
# lock the host out — the pre-existing file stays in place on error.
TMP_AUTH_KEYS="${AUTH_KEYS}.provision.$$"
printf '%s\n' "${COLLECTOR_PUBKEY}" > "${TMP_AUTH_KEYS}"
chmod 600 "${TMP_AUTH_KEYS}"
chown "${COLLECTOR_USER}:${COLLECTOR_USER}" "${TMP_AUTH_KEYS}"
mv -f "${TMP_AUTH_KEYS}" "${AUTH_KEYS}"
echo "[provision] Public key deployed in ${AUTH_KEYS} (file replaced — only the SAM collector key remains)."

# 4. Create sudoers file
# Detect sshd binary path (typically /usr/sbin/sshd on Debian/RHEL/Alpine)
SSHD=$(command -v sshd 2>/dev/null || echo /usr/sbin/sshd)

# printf with explicit \n: resistant to \r\n introduced by sudo PTY during pipe
printf "# ssh-access-manager — sudo rights for ${COLLECTOR_USER}\n" > "${SUDOERS_FILE}"
printf "${COLLECTOR_USER} ALL=(root) NOPASSWD: /usr/local/bin/sam-collect\n" >> "${SUDOERS_FILE}"
printf "${COLLECTOR_USER} ALL=(root) NOPASSWD: /usr/local/bin/sam-revoke\n" >> "${SUDOERS_FILE}"
printf "${COLLECTOR_USER} ALL=(root) NOPASSWD: /usr/local/bin/sam-add\n" >> "${SUDOERS_FILE}"
printf "${COLLECTOR_USER} ALL=(root) NOPASSWD: /usr/local/bin/sam-lock-user\n" >> "${SUDOERS_FILE}"
printf "${COLLECTOR_USER} ALL=(root) NOPASSWD: /usr/local/bin/sam-unlock-user\n" >> "${SUDOERS_FILE}"
printf "${COLLECTOR_USER} ALL=(root) NOPASSWD: /usr/local/bin/sam-sessions\n" >> "${SUDOERS_FILE}"
printf "${COLLECTOR_USER} ALL=(root) NOPASSWD: ${SSHD} -T\n" >> "${SUDOERS_FILE}"
printf "${COLLECTOR_USER} ALL=(root) NOPASSWD: /usr/bin/install -m 750 -o root -g root /home/${COLLECTOR_USER}/sam-collect /usr/local/bin/sam-collect\n" >> "${SUDOERS_FILE}"
printf "${COLLECTOR_USER} ALL=(root) NOPASSWD: /usr/bin/install -m 750 -o root -g root /home/${COLLECTOR_USER}/sam-revoke /usr/local/bin/sam-revoke\n" >> "${SUDOERS_FILE}"
printf "${COLLECTOR_USER} ALL=(root) NOPASSWD: /usr/bin/install -m 750 -o root -g root /home/${COLLECTOR_USER}/sam-add /usr/local/bin/sam-add\n" >> "${SUDOERS_FILE}"
printf "${COLLECTOR_USER} ALL=(root) NOPASSWD: /usr/bin/install -m 750 -o root -g root /home/${COLLECTOR_USER}/sam-lock-user /usr/local/bin/sam-lock-user\n" >> "${SUDOERS_FILE}"
printf "${COLLECTOR_USER} ALL=(root) NOPASSWD: /usr/bin/install -m 750 -o root -g root /home/${COLLECTOR_USER}/sam-unlock-user /usr/local/bin/sam-unlock-user\n" >> "${SUDOERS_FILE}"
printf "${COLLECTOR_USER} ALL=(root) NOPASSWD: /usr/bin/install -m 750 -o root -g root /home/${COLLECTOR_USER}/sam-sessions /usr/local/bin/sam-sessions\n" >> "${SUDOERS_FILE}"
printf "${COLLECTOR_USER} ALL=(root) NOPASSWD: /usr/bin/install -m 750 -o root -g root /home/${COLLECTOR_USER}/sam-grant-group /usr/local/bin/sam-grant-group\n" >> "${SUDOERS_FILE}"
printf "${COLLECTOR_USER} ALL=(root) NOPASSWD: /usr/bin/install -m 750 -o root -g root /home/${COLLECTOR_USER}/sam-revoke-group /usr/local/bin/sam-revoke-group\n" >> "${SUDOERS_FILE}"
printf "${COLLECTOR_USER} ALL=(root) NOPASSWD: /usr/local/bin/sam-grant-group *\n" >> "${SUDOERS_FILE}"
printf "${COLLECTOR_USER} ALL=(root) NOPASSWD: /usr/local/bin/sam-revoke-group *\n" >> "${SUDOERS_FILE}"
printf "${COLLECTOR_USER} ALL=(root) NOPASSWD: /usr/bin/install -m 750 -o root -g root /home/${COLLECTOR_USER}/sam-self-update /usr/local/bin/sam-self-update\n" >> "${SUDOERS_FILE}"
printf "${COLLECTOR_USER} ALL=(root) NOPASSWD: /usr/local/bin/sam-self-update\n" >> "${SUDOERS_FILE}"
printf "${COLLECTOR_USER} ALL=(root) NOPASSWD: /usr/local/bin/sam-self-update *\n" >> "${SUDOERS_FILE}"

chmod 440 "${SUDOERS_FILE}"
echo "[provision] Sudoers configured in ${SUDOERS_FILE}."

echo "[provision] Host ready for SSH collection by ${COLLECTOR_USER}."
