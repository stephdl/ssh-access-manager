#!/bin/sh
# Integration test for provision-host.sh — distro-agnostic orchestrator.
#
# Designed to run inside an ephemeral Docker container of a supported distro
# (rockylinux:9, debian:13 for v1). Spawned by the CI workflow
# .github/workflows/integration-provision.yml, but can also be reproduced
# locally:
#
#   docker run --rm -v "$PWD":/repo -w /repo --tmpfs /tmp \
#       rockylinux:9 bash tests/integration/run.sh
#
# Exits non-zero on any failed assertion.

set -e

REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$REPO_ROOT"

# ---------------------------------------------------------------------------
# Distro detection + setup
# ---------------------------------------------------------------------------
if [ ! -f /etc/os-release ]; then
    echo "FATAL: /etc/os-release missing — unsupported environment" >&2
    exit 2
fi
# shellcheck disable=SC1091
. /etc/os-release

case "$ID" in
    rocky|rhel|almalinux|centos)
        SETUP_SCRIPT="tests/integration/setup/rocky.sh"
        EXPECTED_PROFILE=".bash_profile"
        ;;
    debian|ubuntu)
        SETUP_SCRIPT="tests/integration/setup/debian.sh"
        EXPECTED_PROFILE=".profile"
        ;;
    opensuse-leap|opensuse-tumbleweed|opensuse|sles)
        SETUP_SCRIPT="tests/integration/setup/opensuse.sh"
        EXPECTED_PROFILE=".profile"
        ;;
    arch|archlinux)
        SETUP_SCRIPT="tests/integration/setup/arch.sh"
        EXPECTED_PROFILE=".profile"
        ;;
    *)
        echo "FATAL: unsupported distro '$ID'" >&2
        echo "       Add a tests/integration/setup/<distro>.sh and a case branch in run.sh." >&2
        exit 2
        ;;
esac

echo "Running integration suite on $ID $VERSION_ID"
echo "Installing prerequisites via $SETUP_SCRIPT"

# shellcheck disable=SC1090
. "$SETUP_SCRIPT"

# shellcheck disable=SC1091
. tests/integration/assertions.sh

# ---------------------------------------------------------------------------
# Test data
# ---------------------------------------------------------------------------
mkdir -p /tmp/sam-it
ssh-keygen -t ed25519 -f /tmp/sam-it/test_key -N '' -C 'sam-integration@test' >/dev/null
PUBKEY=$(cat /tmp/sam-it/test_key.pub)
COLLECTOR_USER="audit-collector"

# ---------------------------------------------------------------------------
# Phase 1 — bootstrap
# ---------------------------------------------------------------------------
section "Phase 1 — bootstrap (first provision)"
bash provision-host.sh "$PUBKEY" "$COLLECTOR_USER"

assert_exit_zero id "$COLLECTOR_USER"
COLLECTOR_HOME=$(getent passwd "$COLLECTOR_USER" | cut -d: -f6)

# Groups
for grp in sam-operator sam-pkg sam-root sam-users; do
    assert_exit_zero getent group "$grp"
done

# Sudoers files
assert_file_exists "/etc/sudoers.d/${COLLECTOR_USER}"
assert_file_perms  "/etc/sudoers.d/${COLLECTOR_USER}" 440
assert_visudo_ok   "/etc/sudoers.d/${COLLECTOR_USER}"

for grp in sam-operator sam-pkg sam-root; do
    assert_file_exists "/etc/sudoers.d/${grp}"
    assert_file_perms  "/etc/sudoers.d/${grp}" 440
    assert_file_owner  "/etc/sudoers.d/${grp}" root:root
    assert_visudo_ok   "/etc/sudoers.d/${grp}"
    # NOPASSWD must be absent for all three (otherwise a stolen SAM key would
    # not need the user's personal password to escalate via sudo).
    assert_nogrep "NOPASSWD:" "/etc/sudoers.d/${grp}"
done
# sam-operator / sam-pkg use explicit `PASSWD:` to override host-level
# `Defaults !authenticate` setups. sam-root uses bare `ALL=(ALL) ALL` which
# defaults to PASSWD when no NOPASSWD is set — the assert_nogrep above is
# the load-bearing check for sam-root.
assert_grep "PASSWD:" "/etc/sudoers.d/sam-operator"
assert_grep "PASSWD:" "/etc/sudoers.d/sam-pkg"

# audit-collector sudoers must use NOPASSWD on the sam-* binaries
assert_grep "NOPASSWD: /usr/local/bin/sam-collect" "/etc/sudoers.d/${COLLECTOR_USER}"

# sshd drop-in
assert_file_exists "/etc/ssh/sshd_config.d/50-sam-users.conf"
assert_file_perms  "/etc/ssh/sshd_config.d/50-sam-users.conf" 600
assert_file_owner  "/etc/ssh/sshd_config.d/50-sam-users.conf" root:root
for directive in \
    "PasswordAuthentication no" \
    "PermitEmptyPasswords no" \
    "KbdInteractiveAuthentication no" \
    "PubkeyAuthentication yes" \
    "AuthenticationMethods publickey"; do
    assert_grep "$directive" "/etc/ssh/sshd_config.d/50-sam-users.conf"
done
assert_sshd_ok

# Collector authorized_keys
AUTH_KEYS="${COLLECTOR_HOME}/.ssh/authorized_keys"
assert_file_exists "$AUTH_KEYS"
assert_file_perms  "$AUTH_KEYS" 600
assert_file_owner  "$AUTH_KEYS" "${COLLECTOR_USER}:${COLLECTOR_USER}"
assert_grep "ed25519" "$AUTH_KEYS"

# No leftover .bak after a clean run
assert_no_bak_residue /etc/sudoers.d
assert_no_bak_residue /etc/ssh/sshd_config.d

# api-cli must NOT be in sam-operator (#394), but if api-cli is present must be in sam-pkg
if command -v api-cli >/dev/null 2>&1; then
    assert_nogrep "api-cli" "/etc/sudoers.d/sam-operator"
    assert_grep   "api-cli" "/etc/sudoers.d/sam-pkg"
fi

# ---------------------------------------------------------------------------
# Phase 2 — idempotence
# ---------------------------------------------------------------------------
section "Phase 2 — idempotence (second provision)"
cp /etc/sudoers.d/sam-pkg /tmp/sam-it/sam-pkg.before
cp /etc/ssh/sshd_config.d/50-sam-users.conf /tmp/sam-it/sshd.before

bash provision-host.sh "$PUBKEY" "$COLLECTOR_USER"

assert_visudo_ok "/etc/sudoers.d/sam-operator"
assert_visudo_ok "/etc/sudoers.d/sam-pkg"
assert_visudo_ok "/etc/sudoers.d/sam-root"
assert_sshd_ok
assert_files_equal /tmp/sam-it/sam-pkg.before /etc/sudoers.d/sam-pkg \
    "sam-pkg unchanged across two runs"
assert_files_equal /tmp/sam-it/sshd.before /etc/ssh/sshd_config.d/50-sam-users.conf \
    "sshd drop-in unchanged across two runs"
assert_no_bak_residue /etc/sudoers.d
assert_no_bak_residue /etc/ssh/sshd_config.d

# authorized_keys must not have grown a duplicate line
auth_count=$(grep -cF "$PUBKEY" "$AUTH_KEYS" || true)
assert_eq "1" "$auth_count" "collector key appears exactly once in authorized_keys"

# ---------------------------------------------------------------------------
# Phase 3 — rollback on bad sshd config
# ---------------------------------------------------------------------------
section "Phase 3 — rollback when injected sshd config is invalid"

# Snapshot the current good config so we can prove it survives the failed run.
cp /etc/ssh/sshd_config.d/50-sam-users.conf /tmp/sam-it/sshd.good

set +e
bash tests/integration/fixtures/bad_sshd_config.sh "$PUBKEY" "$COLLECTOR_USER"
rc=$?
set -e
assert_eq "0" "$([ "$rc" -ne 0 ] && echo 0 || echo 1)" \
    "bad_sshd_config.sh exits non-zero (rc=$rc)"

# The drop-in on disk must still be the previous, valid one.
assert_files_equal /tmp/sam-it/sshd.good /etc/ssh/sshd_config.d/50-sam-users.conf \
    "sshd drop-in restored from .bak after rollback"
assert_sshd_ok
assert_no_bak_residue /etc/ssh/sshd_config.d

section "All integration assertions passed on $ID $VERSION_ID"
