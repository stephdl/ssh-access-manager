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

# 5. Check sshd AllowGroups/AllowUsers directives
# OpenSSH AllowGroups/AllowUsers are global-only directives (not overridable via Match blocks).
# If present, they restrict which users can authenticate via SSH. Detect and fail early.
SSHD_CONFIG="/etc/ssh/sshd_config"
SSHD_CONFIG_DIR="/etc/ssh/sshd_config.d"

# Parse all sshd config files (main + includes), strip comments and blank lines
SSHD_ALL_LINES=""
if [ -f "${SSHD_CONFIG}" ]; then
    SSHD_ALL_LINES="$(grep -vE '^\s*(#|$)' "${SSHD_CONFIG}" 2>/dev/null || true)"
fi
if [ -d "${SSHD_CONFIG_DIR}" ]; then
    for conf_file in "${SSHD_CONFIG_DIR}"/*.conf; do
        [ -f "${conf_file}" ] || continue
        SSHD_ALL_LINES="${SSHD_ALL_LINES}
$(grep -vE '^\s*(#|$)' "${conf_file}" 2>/dev/null || true)"
    done
fi

# Extract AllowGroups directives (case-insensitive, can appear multiple times)
ALLOW_GROUPS=$(echo "${SSHD_ALL_LINES}" | grep -iE '^\s*AllowGroups\s+' | sed -E 's/^\s*AllowGroups\s+//i' || true)

# Extract AllowUsers directives (case-insensitive, can appear multiple times)
ALLOW_USERS=$(echo "${SSHD_ALL_LINES}" | grep -iE '^\s*AllowUsers\s+' | sed -E 's/^\s*AllowUsers\s+//i' || true)

# Check AllowGroups constraint
if [ -n "${ALLOW_GROUPS}" ]; then
    # Get all groups of the collector user
    COLLECTOR_GROUPS=$(id -Gn "${COLLECTOR_USER}" 2>/dev/null || echo "")

    # Build union of all allowed groups (multiple directives → union)
    ALL_ALLOWED_GROUPS=$(echo "${ALLOW_GROUPS}" | tr '\n' ' ')

    # Check if any collector group is in the allowed list
    MATCH_FOUND=false
    for user_group in ${COLLECTOR_GROUPS}; do
        for allowed_group in ${ALL_ALLOWED_GROUPS}; do
            # Exact match only (wildcards like *admin are not expanded)
            if [ "${user_group}" = "${allowed_group}" ]; then
                MATCH_FOUND=true
                break 2
            fi
        done
    done

    if [ "${MATCH_FOUND}" = "false" ]; then
        printf "ERROR: sshd is configured with 'AllowGroups %s' which restricts SSH access.\n" "${ALL_ALLOWED_GROUPS}" >&2
        printf "%s is in groups: %s\n" "${COLLECTOR_USER}" "${COLLECTOR_GROUPS}" >&2
        printf "Action required: add %s to one of the AllowGroups manually, e.g.:\n" "${COLLECTOR_USER}" >&2
        printf "    usermod -aG <allowed-group> %s\n" "${COLLECTOR_USER}" >&2
        printf "Then re-run SAM provisioning for this server.\n" >&2
        exit 1
    fi
fi

# Check AllowUsers constraint
if [ -n "${ALLOW_USERS}" ]; then
    # Build union of all allowed users
    ALL_ALLOWED_USERS=$(echo "${ALLOW_USERS}" | tr '\n' ' ')

    # Check if collector user is in the allowed list (exact match)
    USER_MATCH_FOUND=false
    for allowed_user in ${ALL_ALLOWED_USERS}; do
        if [ "${COLLECTOR_USER}" = "${allowed_user}" ]; then
            USER_MATCH_FOUND=true
            break
        fi
    done

    if [ "${USER_MATCH_FOUND}" = "false" ]; then
        printf "ERROR: sshd is configured with 'AllowUsers %s' which restricts SSH access.\n" "${ALL_ALLOWED_USERS}" >&2
        printf "Action required: add %s to AllowUsers in %s:\n" "${COLLECTOR_USER}" "${SSHD_CONFIG}" >&2
        printf "    AllowUsers %s %s\n" "${ALL_ALLOWED_USERS}" "${COLLECTOR_USER}" >&2
        printf "Then reload sshd and re-run SAM provisioning.\n" >&2
        exit 1
    fi
fi

echo "[provision] Host ready for SSH collection by ${COLLECTOR_USER}."
