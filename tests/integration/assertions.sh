# shellcheck shell=bash
# Tiny assertion helpers for the provision-host.sh integration suite.
# Each helper prints a colored result line and `exit 1` on failure so the
# enclosing test exits immediately and the CI marks the job red.

# Color helpers — fall back to no-color when stdout is not a TTY (GHA case).
if [ -t 1 ]; then
    _C_OK="$(printf '\033[32m')"   # green
    _C_FAIL="$(printf '\033[31m')" # red
    _C_RST="$(printf '\033[0m')"
else
    _C_OK=""; _C_FAIL=""; _C_RST=""
fi

_pass() { printf '  %sOK%s   %s\n' "$_C_OK" "$_C_RST" "$1"; }
_fail() { printf '  %sFAIL%s %s\n' "$_C_FAIL" "$_C_RST" "$1"; exit 1; }

assert_eq() {
    # assert_eq <expected> <actual> <message>
    if [ "$1" = "$2" ]; then
        _pass "$3 ($1)"
    else
        _fail "$3 — expected '$1', got '$2'"
    fi
}

assert_file_exists() {
    if [ -e "$1" ]; then
        _pass "file exists: $1"
    else
        _fail "missing file: $1"
    fi
}

assert_file_perms() {
    # assert_file_perms <path> <expected-octal>
    local actual
    actual=$(stat -c %a "$1" 2>/dev/null) || _fail "cannot stat $1"
    if [ "$actual" = "$2" ]; then
        _pass "$1 perms = $2"
    else
        _fail "$1 perms — expected $2, got $actual"
    fi
}

assert_file_owner() {
    # assert_file_owner <path> <owner>:<group>
    local actual
    actual=$(stat -c '%U:%G' "$1" 2>/dev/null) || _fail "cannot stat $1"
    if [ "$actual" = "$2" ]; then
        _pass "$1 owner = $2"
    else
        _fail "$1 owner — expected $2, got $actual"
    fi
}

assert_grep() {
    # assert_grep <pattern> <file>
    if grep -qE -- "$1" "$2" 2>/dev/null; then
        _pass "grep '$1' in $2"
    else
        _fail "pattern '$1' not found in $2"
    fi
}

assert_grep_fixed() {
    # assert_grep_fixed <literal-substring> <file>
    # Use this when the needle contains regex meta-characters (e.g. an SSH
    # key body, which is base64 with '+' and '/' that ERE would interpret).
    if grep -qF -- "$1" "$2" 2>/dev/null; then
        _pass "literal '$1' present in $2"
    else
        _fail "literal '$1' not found in $2"
    fi
}

assert_nogrep() {
    # assert_nogrep <pattern> <file>
    if grep -qE -- "$1" "$2" 2>/dev/null; then
        _fail "unexpected pattern '$1' found in $2"
    else
        _pass "absent: '$1' in $2"
    fi
}

assert_visudo_ok() {
    # assert_visudo_ok <path>
    if visudo -cf "$1" >/dev/null 2>&1; then
        _pass "visudo -c OK on $1"
    else
        _fail "visudo -c rejected $1"
    fi
}

assert_sshd_ok() {
    local sshd_bin
    sshd_bin=$(command -v sshd 2>/dev/null || echo /usr/sbin/sshd)
    if "$sshd_bin" -t >/dev/null 2>&1; then
        _pass "sshd -t OK"
    else
        _fail "sshd -t rejected the current configuration"
    fi
}

assert_exit_zero() {
    # assert_exit_zero <command...>
    if "$@" >/dev/null 2>&1; then
        _pass "exit 0: $*"
    else
        _fail "expected exit 0 but got $? for: $*"
    fi
}

assert_exit_nonzero() {
    # assert_exit_nonzero <command...>
    if "$@" >/dev/null 2>&1; then
        _fail "expected non-zero exit but got 0 for: $*"
    else
        _pass "exit != 0 (as expected): $*"
    fi
}

assert_files_equal() {
    # assert_files_equal <a> <b> <message>
    if cmp -s "$1" "$2"; then
        _pass "$3"
    else
        _fail "$3 — files differ ($1 vs $2)"
    fi
}

assert_no_bak_residue() {
    # assert_no_bak_residue <dir>
    local found
    found=$(find "$1" -maxdepth 2 -name '*.bak' 2>/dev/null | head -n 1)
    if [ -z "$found" ]; then
        _pass "no .bak residue in $1"
    else
        _fail ".bak residue found: $found"
    fi
}

assert_user_locked() {
    # assert_user_locked <username>
    # Reads /etc/shadow directly: a leading '!' in the password field means
    # `usermod -L` was applied. Works on every shadow-utils-based distro
    # (RHEL/Debian/openSUSE/Arch) without depending on `passwd -S` (which
    # differs in output format and exit semantics across distros).
    local user="$1"
    local field
    field=$(awk -F: -v u="$user" '$1==u {print $2; exit}' /etc/shadow 2>/dev/null)
    case "$field" in
        '!'*) _pass "$user is locked (shadow starts with '!')" ;;
        '')   _fail "$user not found in /etc/shadow" ;;
        *)    _fail "$user shadow does not start with '!' (got: ${field:0:8}…)" ;;
    esac
}

assert_user_unlocked() {
    # assert_user_unlocked <username>
    local user="$1"
    local field
    field=$(awk -F: -v u="$user" '$1==u {print $2; exit}' /etc/shadow 2>/dev/null)
    case "$field" in
        '!'*) _fail "$user is still locked (shadow starts with '!')" ;;
        '')   _fail "$user not found in /etc/shadow" ;;
        *)    _pass "$user is unlocked" ;;
    esac
}

assert_user_shell() {
    # assert_user_shell <username> <expected-shell-path>
    local user="$1" expected="$2" actual
    actual=$(getent passwd "$user" | cut -d: -f7)
    if [ "$actual" = "$expected" ]; then
        _pass "$user shell = $expected"
    else
        _fail "$user shell — expected $expected, got '$actual'"
    fi
}

assert_grep_stdin() {
    # assert_grep_stdin <pattern> <label>  — reads from stdin
    local pattern="$1" label="$2"
    if grep -qE -- "$pattern" -; then
        _pass "$label matches '$pattern'"
    else
        _fail "$label does not match '$pattern'"
    fi
}

section() {
    printf '\n%s== %s ==%s\n' "$_C_OK" "$1" "$_C_RST"
}
