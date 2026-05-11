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

# 3. Deploy public key (append if absent, do not overwrite existing keys)
touch "${AUTH_KEYS}"
if ! grep -qF "${COLLECTOR_PUBKEY}" "${AUTH_KEYS}" 2>/dev/null; then
    echo "${COLLECTOR_PUBKEY}" >> "${AUTH_KEYS}"
fi
chmod 600 "${AUTH_KEYS}"
chown "${COLLECTOR_USER}:${COLLECTOR_USER}" "${AUTH_KEYS}"
echo "[provision] Public key deployed in ${AUTH_KEYS}."

# 4. Create sudoers file
# printf with explicit \n: resistant to \r\n introduced by sudo PTY during pipe
printf "# ssh-access-manager — sudo rights for ${COLLECTOR_USER}\n" > "${SUDOERS_FILE}"
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
printf "${COLLECTOR_USER} ALL=(root) NOPASSWD: /usr/bin/install -m 750 -o root -g root /home/${COLLECTOR_USER}/sam-grant-group /usr/local/bin/sam-grant-group\n" >> "${SUDOERS_FILE}"
printf "${COLLECTOR_USER} ALL=(root) NOPASSWD: /usr/bin/install -m 750 -o root -g root /home/${COLLECTOR_USER}/sam-revoke-group /usr/local/bin/sam-revoke-group\n" >> "${SUDOERS_FILE}"
printf "${COLLECTOR_USER} ALL=(root) NOPASSWD: /usr/local/bin/sam-grant-group *\n" >> "${SUDOERS_FILE}"
printf "${COLLECTOR_USER} ALL=(root) NOPASSWD: /usr/local/bin/sam-revoke-group *\n" >> "${SUDOERS_FILE}"

chmod 440 "${SUDOERS_FILE}"
echo "[provision] Sudoers configured in ${SUDOERS_FILE}."

# 5. Create SAM sudo groups
for grp in sam-operator sam-pkg sam-root; do
    if ! getent group "$grp" >/dev/null 2>&1; then
        groupadd "$grp"
        echo "[provision] Group $grp created."
    else
        echo "[provision] Group $grp already exists."
    fi
done

# 6. Detect binary paths for sudoers rules
_bin() { command -v "$1" 2>/dev/null || echo "/usr/bin/$1"; }
SYSTEMCTL=$(_bin systemctl)
JOURNALCTL=$(_bin journalctl)
SS=$(_bin ss)
DMESG=$(_bin dmesg)
LSOF=$(_bin lsof)
DU=$(_bin du)

# 7. Sudoers for sam-operator
OP_FILE="/etc/sudoers.d/sam-operator"
printf "# ssh-access-manager — sam-operator sudo rights\n" > "${OP_FILE}.tmp"
printf "%%sam-operator ALL=(root) ${SYSTEMCTL} restart *\n" >> "${OP_FILE}.tmp"
printf "%%sam-operator ALL=(root) ${SYSTEMCTL} reload *\n" >> "${OP_FILE}.tmp"
printf "%%sam-operator ALL=(root) ${SYSTEMCTL} status *\n" >> "${OP_FILE}.tmp"
printf "%%sam-operator ALL=(root) ${SYSTEMCTL} start *\n" >> "${OP_FILE}.tmp"
printf "%%sam-operator ALL=(root) ${JOURNALCTL} -u *\n" >> "${OP_FILE}.tmp"
printf "%%sam-operator ALL=(root) ${JOURNALCTL} -f *\n" >> "${OP_FILE}.tmp"
printf "%%sam-operator ALL=(root) ${JOURNALCTL} -n *\n" >> "${OP_FILE}.tmp"
printf "%%sam-operator ALL=(root) ${JOURNALCTL} --since *\n" >> "${OP_FILE}.tmp"
printf "%%sam-operator ALL=(root) ${JOURNALCTL} -b *\n" >> "${OP_FILE}.tmp"
printf "%%sam-operator ALL=(root) ${JOURNALCTL} -e *\n" >> "${OP_FILE}.tmp"
printf "%%sam-operator ALL=(root) ${SS} -tlnp\n" >> "${OP_FILE}.tmp"
printf "%%sam-operator ALL=(root) ${DMESG}\n" >> "${OP_FILE}.tmp"
printf "%%sam-operator ALL=(root) ${LSOF}\n" >> "${OP_FILE}.tmp"
printf "%%sam-operator ALL=(root) ${LSOF} -i\n" >> "${OP_FILE}.tmp"
printf "%%sam-operator ALL=(root) ${DU} -sh /var/* /opt/* /home/*\n" >> "${OP_FILE}.tmp"
for bin in runagent api-cli; do
    bin_path=$(_bin "$bin")
    [ -x "$bin_path" ] && printf "%%sam-operator ALL=(root) ${bin_path} *\n" >> "${OP_FILE}.tmp"
done
install -m 440 "${OP_FILE}.tmp" "${OP_FILE}"
rm -f "${OP_FILE}.tmp"
echo "[provision] Sudoers sam-operator configured in ${OP_FILE}."

# 8. Sudoers for sam-pkg (sam-operator commands + package manager)
PKG_FILE="/etc/sudoers.d/sam-pkg"
printf "# ssh-access-manager — sam-pkg sudo rights\n" > "${PKG_FILE}.tmp"
printf "%%sam-pkg ALL=(root) ${SYSTEMCTL} restart *\n" >> "${PKG_FILE}.tmp"
printf "%%sam-pkg ALL=(root) ${SYSTEMCTL} reload *\n" >> "${PKG_FILE}.tmp"
printf "%%sam-pkg ALL=(root) ${SYSTEMCTL} status *\n" >> "${PKG_FILE}.tmp"
printf "%%sam-pkg ALL=(root) ${SYSTEMCTL} start *\n" >> "${PKG_FILE}.tmp"
printf "%%sam-pkg ALL=(root) ${JOURNALCTL} -u *\n" >> "${PKG_FILE}.tmp"
printf "%%sam-pkg ALL=(root) ${JOURNALCTL} -f *\n" >> "${PKG_FILE}.tmp"
printf "%%sam-pkg ALL=(root) ${JOURNALCTL} -n *\n" >> "${PKG_FILE}.tmp"
printf "%%sam-pkg ALL=(root) ${JOURNALCTL} --since *\n" >> "${PKG_FILE}.tmp"
printf "%%sam-pkg ALL=(root) ${JOURNALCTL} -b *\n" >> "${PKG_FILE}.tmp"
printf "%%sam-pkg ALL=(root) ${JOURNALCTL} -e *\n" >> "${PKG_FILE}.tmp"
printf "%%sam-pkg ALL=(root) ${SS} -tlnp\n" >> "${PKG_FILE}.tmp"
printf "%%sam-pkg ALL=(root) ${DMESG}\n" >> "${PKG_FILE}.tmp"
printf "%%sam-pkg ALL=(root) ${LSOF}\n" >> "${PKG_FILE}.tmp"
printf "%%sam-pkg ALL=(root) ${LSOF} -i\n" >> "${PKG_FILE}.tmp"
printf "%%sam-pkg ALL=(root) ${DU} -sh /var/* /opt/* /home/*\n" >> "${PKG_FILE}.tmp"
for bin in runagent api-cli; do
    bin_path=$(_bin "$bin")
    [ -x "$bin_path" ] && printf "%%sam-pkg ALL=(root) ${bin_path} *\n" >> "${PKG_FILE}.tmp"
done
# Package manager — detect distro
if command -v apt >/dev/null 2>&1; then
    APT=$(_bin apt)
    printf "%%sam-pkg ALL=(root) ${APT} install *\n" >> "${PKG_FILE}.tmp"
    printf "%%sam-pkg ALL=(root) ${APT} upgrade *\n" >> "${PKG_FILE}.tmp"
elif command -v dnf >/dev/null 2>&1; then
    DNF=$(_bin dnf)
    printf "%%sam-pkg ALL=(root) ${DNF} install *\n" >> "${PKG_FILE}.tmp"
    printf "%%sam-pkg ALL=(root) ${DNF} upgrade *\n" >> "${PKG_FILE}.tmp"
elif command -v yum >/dev/null 2>&1; then
    YUM=$(_bin yum)
    printf "%%sam-pkg ALL=(root) ${YUM} install *\n" >> "${PKG_FILE}.tmp"
    printf "%%sam-pkg ALL=(root) ${YUM} update *\n" >> "${PKG_FILE}.tmp"
elif command -v zypper >/dev/null 2>&1; then
    ZYPPER=$(_bin zypper)
    printf "%%sam-pkg ALL=(root) ${ZYPPER} install *\n" >> "${PKG_FILE}.tmp"
    printf "%%sam-pkg ALL=(root) ${ZYPPER} update *\n" >> "${PKG_FILE}.tmp"
elif command -v apk >/dev/null 2>&1; then
    APK=$(_bin apk)
    printf "%%sam-pkg ALL=(root) ${APK} add *\n" >> "${PKG_FILE}.tmp"
    printf "%%sam-pkg ALL=(root) ${APK} upgrade *\n" >> "${PKG_FILE}.tmp"
elif command -v pacman >/dev/null 2>&1; then
    PACMAN=$(_bin pacman)
    printf "%%sam-pkg ALL=(root) ${PACMAN} -S *\n" >> "${PKG_FILE}.tmp"
    printf "%%sam-pkg ALL=(root) ${PACMAN} -Syu *\n" >> "${PKG_FILE}.tmp"
    printf "%%sam-pkg ALL=(root) ${PACMAN} -Sy *\n" >> "${PKG_FILE}.tmp"
fi
for bin in add-module remove-module; do
    bin_path="/usr/local/bin/$bin"
    [ -x "$bin_path" ] && printf "%%sam-pkg ALL=(root) ${bin_path} *\n" >> "${PKG_FILE}.tmp"
done
install -m 440 "${PKG_FILE}.tmp" "${PKG_FILE}"
rm -f "${PKG_FILE}.tmp"
echo "[provision] Sudoers sam-pkg configured in ${PKG_FILE}."

# 9. Sudoers for sam-root
ROOT_FILE="/etc/sudoers.d/sam-root"
printf "# ssh-access-manager — sam-root sudo rights\n" > "${ROOT_FILE}.tmp"
printf "%%sam-root ALL=(ALL) ALL\n" >> "${ROOT_FILE}.tmp"
install -m 440 "${ROOT_FILE}.tmp" "${ROOT_FILE}"
rm -f "${ROOT_FILE}.tmp"
echo "[provision] Sudoers sam-root configured in ${ROOT_FILE}."

echo "[provision] Host ready for SSH collection by ${COLLECTOR_USER}."
