#!/bin/sh
# Negative-test wrapper for provision-host.sh.
#
# Patches provision-host.sh on the fly so the `SAM_SSHD_CONF` variable
# contains a directive that `sshd -t` will reject (a non-numeric value for
# `Port`). The expected behaviour is that provision-host.sh writes the bad
# drop-in, sshd -t fails, the script restores the `.bak`, and exits non-zero
# — proving the rollback works end-to-end.
#
# Invocation: bash bad_sshd_config.sh <collector_pubkey> [collector_user]

set -e

COLLECTOR_PUBKEY="${1:?usage: bad_sshd_config.sh <pubkey> [user]}"
COLLECTOR_USER="${2:-audit-collector}"

SCRIPT_PATH="$(cd "$(dirname "$0")/../../.." && pwd)/provision-host.sh"
PATCHED=$(mktemp /tmp/provision-host-bad-XXXXXX.sh)

# Replace the entire multi-line SAM_SSHD_CONF heredoc-style assignment.
# GNU sed -z treats the file as a single record so the multi-line regex spans
# all lines of the original variable definition.
sed -E -z 's|SAM_SSHD_CONF="[^"]*"|SAM_SSHD_CONF="Match Group sam-users\n    Port not-a-number"|' \
    "$SCRIPT_PATH" > "$PATCHED"

# Sanity check: the patched script must actually contain our marker, otherwise
# the substitution silently failed and we would be testing the real script.
if ! grep -q "Port not-a-number" "$PATCHED"; then
    echo "FATAL: sed substitution failed — fixture must inject the bad directive" >&2
    rm -f "$PATCHED"
    exit 2
fi

# Run the patched script. provision-host.sh is expected to:
#   1. write the bad drop-in to /etc/ssh/sshd_config.d/50-sam-users.conf
#   2. run `sshd -t`, which rejects the `Port not-a-number` directive
#   3. restore the `.bak` (or remove the freshly-created file)
#   4. exit non-zero
bash "$PATCHED" "$COLLECTOR_PUBKEY" "$COLLECTOR_USER"
status=$?
rm -f "$PATCHED"
exit "$status"
