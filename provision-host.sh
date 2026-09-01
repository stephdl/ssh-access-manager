#!/bin/sh
# Usage: bash provision-host.sh "<collector_key.pub content>" [collector_user]
#        bash provision-host.sh --print-sudoers [collector_user]
# Prepares a remote host for SSH collection by audit-collector.
set -e

COLLECTOR_PUBKEY="${1}"
COLLECTOR_USER="${2:-audit-collector}"
SUDOERS_FILE="/etc/sudoers.d/${COLLECTOR_USER}"

# The collector name is interpolated into sudoers rules and into a printf
# format string. A `%` would be consumed as a conversion specifier and a
# space or newline would forge an extra rule, so reject anything that is
# not a plain Unix account name before it reaches either.
case "${COLLECTOR_USER}" in
    ''|*[!a-z0-9_-]*)
        printf "ERROR: invalid collector user '%s' (lowercase letters, digits, _ and - only).\n" "${COLLECTOR_USER}" >&2
        exit 1
        ;;
esac

# Detect sshd binary path (typically /usr/sbin/sshd on Debian/RHEL/Alpine)
SSHD=$(command -v sshd 2>/dev/null || echo /usr/sbin/sshd)

# visudo ships with sudo, which step 0 makes a hard requirement, but it lives
# in /usr/sbin and may sit outside PATH depending on how the script is invoked.
VISUDO=$(command -v visudo 2>/dev/null || echo /usr/sbin/visudo)

# Emit the collector sudoers rules on stdout. Every value is passed as a
# printf argument, never interpolated into the format string.
#
# printf with an explicit \n rather than echo: resistant to the \r\n that
# sudo's PTY introduces when the script is piped in over SSH.
#
# The bare rules carry no argument list on purpose: sudoers grants any
# arguments when a Cmnd is listed without them, which is what sam-add,
# sam-revoke and friends need. Rules that do list an argument are pinned
# to it exactly, hence the separate wildcard variants below.
_sudoers_rules() {
    _user="$1"
    _sshd="$2"

    printf '# ssh-access-manager — sudo rights for %s\n' "${_user}"
    for _helper in sam-collect sam-revoke sam-add sam-lock-user sam-unlock-user sam-sessions; do
        printf '%s ALL=(root) NOPASSWD: /usr/local/bin/%s\n' "${_user}" "${_helper}"
    done
    printf '%s ALL=(root) NOPASSWD: %s -T\n' "${_user}" "${_sshd}"

    # Self-update: SAM uploads each helper to the collector home, then
    # installs it with these pinned `install` invocations.
    for _helper in sam-collect sam-revoke sam-add sam-lock-user sam-unlock-user \
                   sam-sessions sam-grant-group sam-revoke-group sam-self-update; do
        printf '%s ALL=(root) NOPASSWD: /usr/bin/install -m 750 -o root -g root /home/%s/%s /usr/local/bin/%s\n' \
            "${_user}" "${_user}" "${_helper}" "${_helper}"
    done

    printf '%s ALL=(root) NOPASSWD: /usr/local/bin/sam-grant-group *\n' "${_user}"
    printf '%s ALL=(root) NOPASSWD: /usr/local/bin/sam-revoke-group *\n' "${_user}"
    printf '%s ALL=(root) NOPASSWD: /usr/local/bin/sam-self-update\n' "${_user}"
    printf '%s ALL=(root) NOPASSWD: /usr/local/bin/sam-self-update *\n' "${_user}"
}

# Inspection mode: print the rules that would be installed and exit. Lets an
# operator (or a test) pipe them through `visudo -c -f -` without touching
# the host.
if [ "${COLLECTOR_PUBKEY}" = "--print-sudoers" ]; then
    _sudoers_rules "${COLLECTOR_USER}" "${SSHD}"
    exit 0
fi

if [ -z "${COLLECTOR_PUBKEY}" ]; then
    echo "Usage: $0 \"<collector_key.pub content>\" [collector_user]" >&2
    exit 1
fi

# 0. sudo is a hard requirement: every collector operation (sam-collect,
# sam-revoke, sam-add, …) runs through `sudo` from the unprivileged
# COLLECTOR_USER account. Without it the host can be provisioned but never
# scanned, so refuse now with an actionable message instead of failing later.
if ! command -v sudo >/dev/null 2>&1; then
    printf "ERROR: 'sudo' is not installed on this host.\n" >&2
    printf "%s needs sudo to run the sam-* helper scripts as root.\n" "${COLLECTOR_USER}" >&2
    printf "Install it, then re-run SAM provisioning:\n" >&2
    printf "    apt install sudo    # Debian/Ubuntu\n" >&2
    printf "    dnf install sudo    # RHEL/Rocky/Fedora\n" >&2
    printf "    apk add sudo        # Alpine\n" >&2
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

# 4. Install the sudoers file
# Atomic via tmp + visudo + install, same reasoning as authorized_keys above
# but with a sharper failure mode: this file has no dot in its name, so sudo
# parses it on every invocation. A truncated write or a malformed rule breaks
# sudo host-wide, including the sudo needed to repair it. Validate first, and
# never leave the live file in a half-written state.
#
# The `.tmp` staging name does contain a dot, which sudo ignores, so the
# in-progress file is inert even while it sits in /etc/sudoers.d.
SUDOERS_TMP="${SUDOERS_FILE}.tmp"
_sudoers_rules "${COLLECTOR_USER}" "${SSHD}" > "${SUDOERS_TMP}"

if [ -x "${VISUDO}" ]; then
    if ! "${VISUDO}" -c -f "${SUDOERS_TMP}" >/dev/null 2>&1; then
        printf "ERROR: generated sudoers for %s is invalid — aborting.\n" "${COLLECTOR_USER}" >&2
        "${VISUDO}" -c -f "${SUDOERS_TMP}" >&2 || true
        rm -f "${SUDOERS_TMP}"
        exit 1
    fi
else
    # Not fatal: the atomic install below is already safer than appending to
    # the live file, which is what this script used to do.
    printf "WARNING: visudo not found, installing %s without syntax validation.\n" "${SUDOERS_FILE}" >&2
fi

install -m 440 -o root -g root "${SUDOERS_TMP}" "${SUDOERS_FILE}"
rm -f "${SUDOERS_TMP}"
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
