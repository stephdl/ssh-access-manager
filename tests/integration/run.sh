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

# Sudoers file for collector
assert_file_exists "/etc/sudoers.d/${COLLECTOR_USER}"
assert_file_perms  "/etc/sudoers.d/${COLLECTOR_USER}" 440
assert_visudo_ok   "/etc/sudoers.d/${COLLECTOR_USER}"

# audit-collector sudoers must use NOPASSWD on the sam-* binaries
assert_grep "NOPASSWD: /usr/local/bin/sam-collect" "/etc/sudoers.d/${COLLECTOR_USER}"
assert_grep "NOPASSWD: /usr/local/bin/sam-self-update" "/etc/sudoers.d/${COLLECTOR_USER}"

# Collector authorized_keys
AUTH_KEYS="${COLLECTOR_HOME}/.ssh/authorized_keys"
assert_file_exists "$AUTH_KEYS"
assert_file_perms  "$AUTH_KEYS" 600
assert_file_owner  "$AUTH_KEYS" "${COLLECTOR_USER}:${COLLECTOR_USER}"
assert_grep "ed25519" "$AUTH_KEYS"

# No leftover .bak after a clean run
assert_no_bak_residue /etc/sudoers.d
assert_no_bak_residue /etc/ssh/sshd_config.d

# ---------------------------------------------------------------------------
# Phase 2 — idempotence
# ---------------------------------------------------------------------------
section "Phase 2 — idempotence (second provision)"
cp /etc/sudoers.d/audit-collector /tmp/sam-it/collector-sudoers.before

bash provision-host.sh "$PUBKEY" "$COLLECTOR_USER"

assert_visudo_ok "/etc/sudoers.d/${COLLECTOR_USER}"
assert_files_equal /tmp/sam-it/collector-sudoers.before /etc/sudoers.d/audit-collector \
    "collector sudoers unchanged across two runs"
assert_no_bak_residue /etc/sudoers.d
assert_no_bak_residue /etc/ssh/sshd_config.d

# authorized_keys must not have grown a duplicate line
auth_count=$(grep -cF "$PUBKEY" "$AUTH_KEYS" || true)
assert_eq "1" "$auth_count" "collector key appears exactly once in authorized_keys"

# ---------------------------------------------------------------------------
# Phase 3 — deploy sam-self-update and run initial provisioning
# ---------------------------------------------------------------------------
section "Phase 3 — deploy sam-self-update and run initial provisioning"

# Extract the current SAM_SELF_UPDATE script content from ssh.py
python3 tests/integration/extract_sam_constant.py SAM_SELF_UPDATE > /tmp/sam-it/sam-self-update.v1
chmod +x /tmp/sam-it/sam-self-update.v1

# Deploy the script
install -m 750 -o root -g root /tmp/sam-it/sam-self-update.v1 /usr/local/bin/sam-self-update

# Run sam-self-update to deploy the dynamic configuration (no version argument)
sudo /usr/local/bin/sam-self-update

# Verify groups created
for grp in sam-operator sam-pkg sam-root sam-users; do
    assert_exit_zero getent group "$grp"
done

# Verify sudoers files created
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

# api-cli must NOT be in sam-operator (#394), but if api-cli is present must be in sam-pkg
if command -v api-cli >/dev/null 2>&1; then
    assert_nogrep "api-cli" "/etc/sudoers.d/sam-operator"
    assert_grep   "api-cli" "/etc/sudoers.d/sam-pkg"
fi

# Verify sshd drop-in created
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

# No leftover .bak after a clean run
assert_no_bak_residue /etc/sudoers.d
assert_no_bak_residue /etc/ssh/sshd_config.d

# ---------------------------------------------------------------------------
# Phase 4 — upgrade simulation via sam-self-update
# ---------------------------------------------------------------------------
section "Phase 4 — upgrade simulation via sam-self-update"

# Extract the current SAM_SELF_UPDATE script content from ssh.py
python3 tests/integration/extract_sam_constant.py SAM_SELF_UPDATE > /tmp/sam-it/sam-self-update.v1
chmod +x /tmp/sam-it/sam-self-update.v1

# sam-self-update must be in sudoers for audit-collector
assert_grep "sam-self-update" "/etc/sudoers.d/${COLLECTOR_USER}"

# Simulate an upgrade by injecting a new version of sam-self-update
# For this test, we add a marker rule to sam-pkg sudoers
cat /tmp/sam-it/sam-self-update.v1 | \
    sed 's|_rule "${PKG_FILE}.tmp" "sam-pkg" "${SYSTEMCTL} restart"|_rule "${PKG_FILE}.tmp" "sam-pkg" "${SYSTEMCTL} restart"\n    _rule "${PKG_FILE}.tmp" "sam-pkg" "/usr/bin/echo upgrade-marker"|' \
    > /tmp/sam-it/sam-self-update.v2

# Deploy the upgraded script
install -m 750 -o root -g root /tmp/sam-it/sam-self-update.v2 /usr/local/bin/sam-self-update

# Run the upgrade
sudo /usr/local/bin/sam-self-update version-v2

# Verify the upgrade succeeded
assert_file_exists "/etc/sam-provision-version"
assert_grep "version-v2" "/etc/sam-provision-version"
assert_grep "upgrade-marker" "/etc/sudoers.d/sam-pkg"
assert_visudo_ok "/etc/sudoers.d/sam-operator"
assert_visudo_ok "/etc/sudoers.d/sam-pkg"
assert_visudo_ok "/etc/sudoers.d/sam-root"
assert_sshd_ok
assert_no_bak_residue /etc/sudoers.d
assert_no_bak_residue /etc/ssh/sshd_config.d

# ---------------------------------------------------------------------------
# Phase 5 — test negative sam-self-update (validation failure)
# ---------------------------------------------------------------------------
section "Phase 5 — test negative sam-self-update (validation failure)"

# Construct a v3 with an intentional sudoers error
# Replace the valid sam-root line with an invalid one (missing colon)
cat /tmp/sam-it/sam-self-update.v2 | \
    sed 's|printf "%%sam-root ALL=(ALL) ALL|printf "%%sam-root INVALID|' \
    > /tmp/sam-it/sam-self-update.v3

# Deploy the broken script
install -m 750 -o root -g root /tmp/sam-it/sam-self-update.v3 /usr/local/bin/sam-self-update

# Run it — must fail
set +e
sudo /usr/local/bin/sam-self-update version-v3
rc=$?
set -e

assert_eq "0" "$([ "$rc" -ne 0 ] && echo 0 || echo 1)" \
    "sam-self-update exits non-zero when sudoers validation fails (rc=$rc)"

# Verify rollback: version unchanged, sam-pkg still has upgrade-marker from v2
assert_grep "version-v2" "/etc/sam-provision-version"
assert_grep "upgrade-marker" "/etc/sudoers.d/sam-pkg"
assert_visudo_ok "/etc/sudoers.d/sam-operator"
assert_visudo_ok "/etc/sudoers.d/sam-pkg"
assert_visudo_ok "/etc/sudoers.d/sam-root"
assert_sshd_ok
assert_no_bak_residue /etc/sudoers.d
assert_no_bak_residue /etc/ssh/sshd_config.d

# ---------------------------------------------------------------------------
# Phase 6 — exercise SAM_ADD / SAM_COLLECT / SAM_REVOKE / SAM_LOCK / SAM_UNLOCK
# for real on the host, both as root (direct script logic) and via
# `su -l audit-collector -c 'sudo …'` (sudoers + NOPASSWD chain).
# ---------------------------------------------------------------------------
section "Phase 6 — SAM scripts end-to-end (root + via audit-collector sudoers)"

# Deploy the five scripts to /usr/local/bin with the same mode/owner used in
# production (mirroring ssh.deploy_script: install -m 750 -o root -g root).
for const in SAM_COLLECT SAM_REVOKE SAM_ADD SAM_LOCK_USER SAM_UNLOCK_USER; do
    # SAM_LOCK_USER → /usr/local/bin/sam-lock-user
    bin_name=$(printf '%s' "$const" | tr '[:upper:]_' '[:lower:]-')
    out="/tmp/sam-it/${bin_name}"
    python3 tests/integration/extract_sam_constant.py "$const" > "$out"
    install -m 750 -o root -g root "$out" "/usr/local/bin/${bin_name}"
    assert_file_perms "/usr/local/bin/${bin_name}" 750
    assert_file_owner "/usr/local/bin/${bin_name}" root:root
done

# Generate a separate keypair for the test target user. We must not reuse the
# collector key — the goal is to verify that sam-add deploys *this* pubkey to
# *this* user, distinct from audit-collector.
ssh-keygen -t ed25519 -f /tmp/sam-it/user_key -N '' -C 'testuser1@sam-it' >/dev/null
USER_PUBKEY=$(cat /tmp/sam-it/user_key.pub)
USER_FP=$(ssh-keygen -l -E sha256 -f /tmp/sam-it/user_key.pub | awk '{print $2}')

# --- 6a. sam-add: direct root invocation ----------------------------------
/usr/local/bin/sam-add testuser1 "$USER_PUBKEY"

assert_exit_zero id testuser1
TESTUSER_HOME=$(getent passwd testuser1 | cut -d: -f6)
assert_file_exists "${TESTUSER_HOME}/.ssh/authorized_keys"
assert_file_perms  "${TESTUSER_HOME}/.ssh/authorized_keys" 600
assert_file_owner  "${TESTUSER_HOME}/.ssh/authorized_keys" testuser1:testuser1
assert_grep_fixed "$(printf '%s' "$USER_PUBKEY" | awk '{print $2}')" "${TESTUSER_HOME}/.ssh/authorized_keys"

# Temporary-password README + first-login hook in the right shell rc file
assert_file_exists "${TESTUSER_HOME}/README_first_login.txt"
assert_file_perms  "${TESTUSER_HOME}/README_first_login.txt" 600
# bash login-shell resolution order: .bash_profile → .bash_login → .profile.
# Distros differ in which file ships in skel (Arch can ship .bash_profile in
# recent base packages despite our setup script not preinstalling bash skel,
# Rocky always ships .bash_profile, Debian/openSUSE ship .profile). Assert
# the hook landed in *exactly one* of the three — whichever bash will read.
hook_files=0
for rc in .bash_profile .bash_login .profile; do
    if [ -f "${TESTUSER_HOME}/${rc}" ] && grep -qF "README_first_login.txt" "${TESTUSER_HOME}/${rc}"; then
        _pass "first-login hook present in ${rc}"
        hook_files=$((hook_files + 1))
    fi
done
assert_eq "1" "$hook_files" "first-login hook is in exactly one rc file"

# Membership in sam-users (created by sam-self-update in phase 3)
assert_exit_zero id -Gn testuser1
if id -Gn testuser1 | tr ' ' '\n' | grep -qx sam-users; then
    _pass "testuser1 is a member of sam-users"
else
    _fail "testuser1 is NOT a member of sam-users"
fi

# --- 6b. sam-add: idempotence ---------------------------------------------
/usr/local/bin/sam-add testuser1 "$USER_PUBKEY"
auth_count=$(grep -cF "$USER_PUBKEY" "${TESTUSER_HOME}/.ssh/authorized_keys" || true)
assert_eq "1" "$auth_count" "sam-add is idempotent (key appears exactly once)"

# --- 6c. sam-collect: direct root invocation ------------------------------
COLLECT_OUT=/tmp/sam-it/collect.out
/usr/local/bin/sam-collect > "$COLLECT_OUT"
# Output format: "<unix_user>\t<key_type> <key_b64> [comment]"
# We assert one line for testuser1 with the expected key body.
USER_KEY_BODY=$(awk '{print $2}' /tmp/sam-it/user_key.pub)
# Two-step assertion to avoid regex meta-characters in the base64 key body
# (the body contains '+' and '/' which ERE would misinterpret).
testuser_line=$(grep -E '^testuser1[[:space:]]' "$COLLECT_OUT" || true)
if [ -z "$testuser_line" ]; then
    _fail "sam-collect produced no line for testuser1 (see $COLLECT_OUT)"
elif printf '%s' "$testuser_line" | grep -qF -- "$USER_KEY_BODY"; then
    _pass "sam-collect reports testuser1 with the expected key body"
else
    _fail "sam-collect line for testuser1 does not contain the expected key body"
fi
# audit-collector's own collector pubkey must also be reported
if grep -qE "^${COLLECTOR_USER}\s+ssh-ed25519\s+" "$COLLECT_OUT"; then
    _pass "sam-collect also reports ${COLLECTOR_USER}'s key"
else
    _fail "sam-collect did not report ${COLLECTOR_USER}"
fi

# --- 6d. sam-collect: via audit-collector sudo chain ----------------------
# Validates that the sudoers rule
#   audit-collector ALL=(root) NOPASSWD: /usr/local/bin/sam-collect
# works without TTY and without password. We use `su -l` to get a real login
# shell for audit-collector; `-c` runs the command in that shell.
COLLECT_OUT_SUDO=/tmp/sam-it/collect.out.sudo
su -l "$COLLECTOR_USER" -c 'sudo -n /usr/local/bin/sam-collect' > "$COLLECT_OUT_SUDO"
if cmp -s "$COLLECT_OUT" "$COLLECT_OUT_SUDO"; then
    _pass "sam-collect via audit-collector sudoers produces identical output"
else
    _fail "sam-collect output differs root vs audit-collector (sudoers chain broken)"
fi

# --- 6e. sam-revoke: targeted (preserve ownership #104) -------------------
# Capture ownership + perms before, expect them preserved after rewrite.
PERMS_BEFORE=$(stat -c '%a %U:%G' "${TESTUSER_HOME}/.ssh/authorized_keys")
/usr/local/bin/sam-revoke "$USER_FP" testuser1
PERMS_AFTER=$(stat -c '%a %U:%G' "${TESTUSER_HOME}/.ssh/authorized_keys")
assert_eq "$PERMS_BEFORE" "$PERMS_AFTER" \
    "sam-revoke preserves perms+owner on authorized_keys (#104)"

if grep -qF "$USER_KEY_BODY" "${TESTUSER_HOME}/.ssh/authorized_keys"; then
    _fail "sam-revoke did not remove the targeted key body"
else
    _pass "sam-revoke removed the targeted key from authorized_keys"
fi

# --- 6f. sam-revoke: via audit-collector sudo chain -----------------------
# Re-add the key first so we can revoke it again through the sudo chain.
/usr/local/bin/sam-add testuser1 "$USER_PUBKEY"
assert_grep_fixed "$USER_KEY_BODY" "${TESTUSER_HOME}/.ssh/authorized_keys"
su -l "$COLLECTOR_USER" -c "sudo -n /usr/local/bin/sam-revoke '${USER_FP}' testuser1"
if grep -qF "$USER_KEY_BODY" "${TESTUSER_HOME}/.ssh/authorized_keys"; then
    _fail "sam-revoke via audit-collector did not remove the key"
else
    _pass "sam-revoke via audit-collector sudoers chain works"
fi

# --- 6g. sam-lock-user / sam-unlock-user (#181) ---------------------------
/usr/local/bin/sam-lock-user testuser1
assert_user_locked testuser1
assert_user_shell  testuser1 /sbin/nologin

# Same via sudo chain — unlock through audit-collector to exercise both
# directions of the sudoers entry.
su -l "$COLLECTOR_USER" -c 'sudo -n /usr/local/bin/sam-unlock-user testuser1'
assert_user_unlocked testuser1
assert_user_shell    testuser1 /bin/bash

# ---------------------------------------------------------------------------
# Phase 7 — bad sshd drop-in rollback (negative integration test)
#
# We extract SAM_SELF_UPDATE, replace the SAM_SSHD_CONF heredoc body with an
# intentionally invalid directive (`Port not-a-number` is rejected by
# sshd -t), install the patched script and run it. Expectation: non-zero
# exit, drop-in restored from .bak, sshd -t still OK, no .bak residue.
# ---------------------------------------------------------------------------
section "Phase 7 — bad sshd drop-in must be rejected and rolled back"

GOOD_SSHD_DROPIN=/etc/ssh/sshd_config.d/50-sam-users.conf
cp "$GOOD_SSHD_DROPIN" /tmp/sam-it/sshd-dropin.before

# sed -z lets the pattern span the multi-line heredoc value.
python3 tests/integration/extract_sam_constant.py SAM_SELF_UPDATE | \
    sed -E -z 's|SAM_SSHD_CONF="[^"]*"|SAM_SSHD_CONF="Match Group sam-users\n    Port not-a-number"|' \
    > /tmp/sam-it/sam-self-update.bad

# Sanity: the substitution must actually inject the bad directive, otherwise
# we would silently be running the unpatched (valid) script.
if ! grep -q "Port not-a-number" /tmp/sam-it/sam-self-update.bad; then
    _fail "sed substitution did not inject 'Port not-a-number' — fixture stale"
fi

install -m 750 -o root -g root /tmp/sam-it/sam-self-update.bad /usr/local/bin/sam-self-update

set +e
sudo /usr/local/bin/sam-self-update version-bad-sshd
bad_rc=$?
set -e

if [ "$bad_rc" -ne 0 ]; then
    _pass "sam-self-update with bad sshd directive exits non-zero (rc=$bad_rc)"
else
    _fail "sam-self-update unexpectedly exited 0 — rollback path not exercised"
fi

# After rollback, sshd -t must still pass and the drop-in must be unchanged.
assert_sshd_ok
assert_files_equal /tmp/sam-it/sshd-dropin.before "$GOOD_SSHD_DROPIN" \
    "sshd drop-in restored to its pre-failure state after rollback"
assert_no_bak_residue /etc/ssh/sshd_config.d
assert_no_bak_residue /etc/sudoers.d

# Version file must NOT have been updated to the failing version.
if grep -q "version-bad-sshd" /etc/sam-provision-version 2>/dev/null; then
    _fail "/etc/sam-provision-version updated despite rollback"
else
    _pass "/etc/sam-provision-version not updated (rollback respected)"
fi

section "All integration assertions passed on $ID $VERSION_ID"
