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

# 5. Create SAM groups
for grp in sam-operator sam-pkg sam-root sam-users; do
    if ! getent group "$grp" >/dev/null 2>&1; then
        groupadd "$grp"
        echo "[provision] Group $grp created."
    else
        echo "[provision] Group $grp already exists."
    fi
done

# Force publickey-only authentication for the sam-users group.
# sam-add adds every SAM-managed user to this group so they cannot SSH-login
# with a password, empty password, or PAM keyboard-interactive — even if they
# have a Unix password set (which is still required for sudo PASSWD:).
SAM_SSHD_CONF="Match Group sam-users
    PasswordAuthentication no
    PermitEmptyPasswords no
    KbdInteractiveAuthentication no
    PubkeyAuthentication yes
    AuthenticationMethods publickey"
SSHD_D="/etc/ssh/sshd_config.d"
SSHD_BIN=$(command -v sshd 2>/dev/null || echo /usr/sbin/sshd)
SAM_SSHD_INSTALLED=0

# Install drop-in atomically and validate with `sshd -t`; rollback on failure.
_install_sam_sshd_dropin() {
    local target="${SSHD_D}/50-sam-users.conf"
    local backup="${target}.bak"
    local had_previous=0
    if [ -f "$target" ]; then
        cp -p "$target" "$backup"
        had_previous=1
    fi
    printf '%s\n' "${SAM_SSHD_CONF}" > "$target"
    chown root:root "$target"
    chmod 600 "$target"
    if ! "$SSHD_BIN" -t 2>/dev/null; then
        echo "[provision] ERROR: sshd -t rejected ${target} — rolling back"
        if [ "$had_previous" -eq 1 ]; then
            mv "$backup" "$target"
        else
            rm -f "$target"
        fi
        exit 1
    fi
    rm -f "$backup"
    echo "[provision] ${target} written and validated by sshd -t."
    SAM_SSHD_INSTALLED=1
}

if [ -d "$SSHD_D" ] && grep -qE "^Include.*sshd_config\.d" /etc/ssh/sshd_config 2>/dev/null; then
    _install_sam_sshd_dropin
elif ! grep -q "Match Group sam-users" /etc/ssh/sshd_config 2>/dev/null; then
    cp -p /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
    printf '\n# ssh-access-manager\n%s\n' "${SAM_SSHD_CONF}" >> /etc/ssh/sshd_config
    if ! "$SSHD_BIN" -t 2>/dev/null; then
        echo "[provision] ERROR: sshd -t rejected /etc/ssh/sshd_config — rolling back"
        mv /etc/ssh/sshd_config.bak /etc/ssh/sshd_config
        exit 1
    fi
    rm -f /etc/ssh/sshd_config.bak
    echo "[provision] /etc/ssh/sshd_config updated and validated by sshd -t."
    SAM_SSHD_INSTALLED=1
fi
# Reload sshd only when we just changed the config and it validated.
if [ "$SAM_SSHD_INSTALLED" -eq 1 ] && command -v systemctl >/dev/null 2>&1; then
    systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || true
fi

# 6. Detect binary paths for sudoers rules
# command -v searches PATH; also check /usr/local/bin explicitly (NS8 tools may not be in sudo PATH)
_bin() {
    local p
    p=$(command -v "$1" 2>/dev/null)
    [ -n "$p" ] && echo "$p" && return
    [ -x "/usr/local/bin/$1" ] && echo "/usr/local/bin/$1" && return
    echo "/usr/bin/$1"
}
SYSTEMCTL=$(_bin systemctl)
JOURNALCTL=$(_bin journalctl)
SS=$(_bin ss)
DMESG=$(_bin dmesg)
LSOF=$(_bin lsof)
DU=$(_bin du)

# Write both the bare command and the wildcard variant so users can omit arguments.
# PASSWD: is explicit to override any host-level NOPASSWD defaults.
_rule() {
    local file="$1" group="$2" cmd="$3"
    printf "%%${group} ALL=(root) PASSWD: ${cmd}\n"     >> "${file}"
    printf "%%${group} ALL=(root) PASSWD: ${cmd} *\n"   >> "${file}"
}

# 7. Sudoers for sam-operator
OP_FILE="/etc/sudoers.d/sam-operator"
printf "# ssh-access-manager — sam-operator sudo rights\n" > "${OP_FILE}.tmp"
printf "Defaults:%%sam-operator secure_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n" >> "${OP_FILE}.tmp"
_rule "${OP_FILE}.tmp" "sam-operator" "${SYSTEMCTL} restart"
_rule "${OP_FILE}.tmp" "sam-operator" "${SYSTEMCTL} reload"
_rule "${OP_FILE}.tmp" "sam-operator" "${SYSTEMCTL} status"
_rule "${OP_FILE}.tmp" "sam-operator" "${SYSTEMCTL} start"
_rule "${OP_FILE}.tmp" "sam-operator" "${JOURNALCTL} -u"
_rule "${OP_FILE}.tmp" "sam-operator" "${JOURNALCTL} -f"
_rule "${OP_FILE}.tmp" "sam-operator" "${JOURNALCTL} -n"
_rule "${OP_FILE}.tmp" "sam-operator" "${JOURNALCTL} --since"
_rule "${OP_FILE}.tmp" "sam-operator" "${JOURNALCTL} -b"
_rule "${OP_FILE}.tmp" "sam-operator" "${JOURNALCTL} -e"
printf "%%sam-operator ALL=(root) PASSWD: ${SS} -tlnp\n"                    >> "${OP_FILE}.tmp"
printf "%%sam-operator ALL=(root) PASSWD: ${DMESG}\n"                       >> "${OP_FILE}.tmp"
printf "%%sam-operator ALL=(root) PASSWD: ${LSOF}\n"                        >> "${OP_FILE}.tmp"
printf "%%sam-operator ALL=(root) PASSWD: ${LSOF} -i\n"                     >> "${OP_FILE}.tmp"
printf "%%sam-operator ALL=(root) PASSWD: ${DU} -sh /var/* /opt/* /home/*\n" >> "${OP_FILE}.tmp"
for bin in runagent api-cli; do
    bin_path=$(_bin "$bin")
    [ -x "$bin_path" ] && _rule "${OP_FILE}.tmp" "sam-operator" "${bin_path}"
done
visudo -c -f "${OP_FILE}.tmp" || { echo "[provision] ERROR: invalid sudoers ${OP_FILE} — aborting"; rm -f "${OP_FILE}.tmp"; exit 1; }
install -m 440 "${OP_FILE}.tmp" "${OP_FILE}"
rm -f "${OP_FILE}.tmp"
echo "[provision] Sudoers sam-operator configured in ${OP_FILE}."

# 8. Sudoers for sam-pkg (sam-operator commands + package manager)
PKG_FILE="/etc/sudoers.d/sam-pkg"
printf "# ssh-access-manager — sam-pkg sudo rights\n" > "${PKG_FILE}.tmp"
printf "Defaults:%%sam-pkg secure_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n" >> "${PKG_FILE}.tmp"
_rule "${PKG_FILE}.tmp" "sam-pkg" "${SYSTEMCTL} restart"
_rule "${PKG_FILE}.tmp" "sam-pkg" "${SYSTEMCTL} reload"
_rule "${PKG_FILE}.tmp" "sam-pkg" "${SYSTEMCTL} status"
_rule "${PKG_FILE}.tmp" "sam-pkg" "${SYSTEMCTL} start"
_rule "${PKG_FILE}.tmp" "sam-pkg" "${JOURNALCTL} -u"
_rule "${PKG_FILE}.tmp" "sam-pkg" "${JOURNALCTL} -f"
_rule "${PKG_FILE}.tmp" "sam-pkg" "${JOURNALCTL} -n"
_rule "${PKG_FILE}.tmp" "sam-pkg" "${JOURNALCTL} --since"
_rule "${PKG_FILE}.tmp" "sam-pkg" "${JOURNALCTL} -b"
_rule "${PKG_FILE}.tmp" "sam-pkg" "${JOURNALCTL} -e"
printf "%%sam-pkg ALL=(root) PASSWD: ${SS} -tlnp\n"                    >> "${PKG_FILE}.tmp"
printf "%%sam-pkg ALL=(root) PASSWD: ${DMESG}\n"                       >> "${PKG_FILE}.tmp"
printf "%%sam-pkg ALL=(root) PASSWD: ${LSOF}\n"                        >> "${PKG_FILE}.tmp"
printf "%%sam-pkg ALL=(root) PASSWD: ${LSOF} -i\n"                     >> "${PKG_FILE}.tmp"
printf "%%sam-pkg ALL=(root) PASSWD: ${DU} -sh /var/* /opt/* /home/*\n" >> "${PKG_FILE}.tmp"
for bin in runagent api-cli; do
    bin_path=$(_bin "$bin")
    [ -x "$bin_path" ] && _rule "${PKG_FILE}.tmp" "sam-pkg" "${bin_path}"
done
# Package manager — detect distro
if command -v apt >/dev/null 2>&1; then
    APT=$(_bin apt)
    _rule "${PKG_FILE}.tmp" "sam-pkg" "${APT} install"
    _rule "${PKG_FILE}.tmp" "sam-pkg" "${APT} upgrade"
elif command -v dnf >/dev/null 2>&1; then
    DNF=$(_bin dnf)
    _rule "${PKG_FILE}.tmp" "sam-pkg" "${DNF} install"
    _rule "${PKG_FILE}.tmp" "sam-pkg" "${DNF} upgrade"
elif command -v yum >/dev/null 2>&1; then
    YUM=$(_bin yum)
    _rule "${PKG_FILE}.tmp" "sam-pkg" "${YUM} install"
    _rule "${PKG_FILE}.tmp" "sam-pkg" "${YUM} update"
elif command -v zypper >/dev/null 2>&1; then
    ZYPPER=$(_bin zypper)
    _rule "${PKG_FILE}.tmp" "sam-pkg" "${ZYPPER} install"
    _rule "${PKG_FILE}.tmp" "sam-pkg" "${ZYPPER} update"
elif command -v apk >/dev/null 2>&1; then
    APK=$(_bin apk)
    _rule "${PKG_FILE}.tmp" "sam-pkg" "${APK} add"
    _rule "${PKG_FILE}.tmp" "sam-pkg" "${APK} upgrade"
elif command -v pacman >/dev/null 2>&1; then
    PACMAN=$(_bin pacman)
    _rule "${PKG_FILE}.tmp" "sam-pkg" "${PACMAN} -S"
    _rule "${PKG_FILE}.tmp" "sam-pkg" "${PACMAN} -Syu"
    _rule "${PKG_FILE}.tmp" "sam-pkg" "${PACMAN} -Sy"
fi
for bin in add-module remove-module; do
    bin_path="/usr/local/bin/$bin"
    [ -x "$bin_path" ] && _rule "${PKG_FILE}.tmp" "sam-pkg" "${bin_path}"
done
visudo -c -f "${PKG_FILE}.tmp" || { echo "[provision] ERROR: invalid sudoers ${PKG_FILE} — aborting"; rm -f "${PKG_FILE}.tmp"; exit 1; }
install -m 440 "${PKG_FILE}.tmp" "${PKG_FILE}"
rm -f "${PKG_FILE}.tmp"
echo "[provision] Sudoers sam-pkg configured in ${PKG_FILE}."

# 9. Sudoers for sam-root
ROOT_FILE="/etc/sudoers.d/sam-root"
printf "# ssh-access-manager — sam-root sudo rights\n" > "${ROOT_FILE}.tmp"
printf "%%sam-root ALL=(ALL) ALL\n" >> "${ROOT_FILE}.tmp"
visudo -c -f "${ROOT_FILE}.tmp" || { echo "[provision] ERROR: invalid sudoers ${ROOT_FILE} — aborting"; rm -f "${ROOT_FILE}.tmp"; exit 1; }
install -m 440 "${ROOT_FILE}.tmp" "${ROOT_FILE}"
rm -f "${ROOT_FILE}.tmp"
echo "[provision] Sudoers sam-root configured in ${ROOT_FILE}."

echo "[provision] Host ready for SSH collection by ${COLLECTOR_USER}."
