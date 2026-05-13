#!/usr/bin/env bash
# Smoke test — assert the SAM container is bootable end-to-end.
#
# Invoked by .github/workflows/smoke-container.yml after `docker compose up -d`
# against a freshly-built image. The workflow handles container lifecycle
# (supervisorctl, restart, persistence) while this script focuses on what
# can be observed from outside via HTTP.
#
# Assertions performed:
#   1. Flask is alive behind Nginx and require_auth wired (GET /api/auth/me → 401)
#   2. Postgres init + schema + werkzeug hash + session cookie all work
#      (POST /api/auth/login → 200)
#   3. /api/auth/me with cookie returns the seeded admin profile
#   4. /api/servers (authenticated) returns an empty JSON array — proves
#      Flask ↔ Postgres roundtrip on a clean schema
#   5. SPA fallback in nginx: GET / and GET /servers/xyz both return the
#      same HTML (vue-router history mode)
#   6. Route sweep: every documented /api/ route returns <500 when hit
#      with the admin cookie. 4xx are expected for routes that need real
#      data; only 5xx fails the suite (catches SQL typos, serializer
#      crashes, KeyError in handlers — none of which pytest mocks see)
#   7. Logout flow: POST /api/auth/logout → 200, then GET /api/auth/me → 401
#
# Usage:  bash tests/smoke/run.sh [BASE_URL] [ADMIN_USER] [ADMIN_PASSWORD]
#
# Exits non-zero on the first failed assertion. On failure the workflow
# dumps `docker compose logs` so the CI log is self-contained.

set -eu

BASE_URL="${1:-http://127.0.0.1:8080}"
ADMIN_USER="${2:-admin}"
ADMIN_PASSWORD="${3:-admin}"
COOKIE_JAR="$(mktemp /tmp/sam-smoke-cookies.XXXXXX)"
RESP_BODY=/tmp/sam-smoke-resp.json
trap 'rm -f "$COOKIE_JAR" "$RESP_BODY"' EXIT

if [ -t 1 ]; then
    GREEN=$'\033[32m'; RED=$'\033[31m'; RST=$'\033[0m'
else
    GREEN=""; RED=""; RST=""
fi
pass() { printf '  %sOK%s   %s\n' "$GREEN" "$RST" "$1"; }
fail() { printf '  %sFAIL%s %s\n' "$RED" "$RST" "$1" >&2; exit 1; }
section() { printf '\n%s== %s ==%s\n' "$GREEN" "$1" "$RST"; }

# ---------------------------------------------------------------------------
section "Step 1 — wait for the container to accept HTTP traffic"
# ---------------------------------------------------------------------------
echo "Polling ${BASE_URL}/api/auth/me (up to 120 s)…"
for i in $(seq 1 60); do
    code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 "${BASE_URL}/api/auth/me" || true)
    case "$code" in
        401|200) pass "container responds with HTTP $code after ${i} attempt(s)"; break ;;
    esac
    if [ "$i" -eq 60 ]; then
        fail "container never produced a 200/401 response (last code: '$code')"
    fi
    sleep 2
done

# ---------------------------------------------------------------------------
section "Step 2 — auth wiring (unauthenticated /me, login, authenticated /me)"
# ---------------------------------------------------------------------------
code=$(curl -s -o /dev/null -w '%{http_code}' "${BASE_URL}/api/auth/me")
[ "$code" = "401" ] || fail "GET /api/auth/me unauthenticated — expected 401, got $code"
pass "GET /api/auth/me without session → 401"

login_body=$(printf '{"username":"%s","password":"%s"}' "$ADMIN_USER" "$ADMIN_PASSWORD")
code=$(curl -s -o "$RESP_BODY" -w '%{http_code}' \
    -c "$COOKIE_JAR" \
    -H 'Content-Type: application/json' \
    -X POST -d "$login_body" \
    "${BASE_URL}/api/auth/login")
if [ "$code" != "200" ]; then
    echo "Response body:"; cat "$RESP_BODY" || true; echo
    fail "POST /api/auth/login — expected 200, got $code"
fi
pass "POST /api/auth/login → 200"

body=$(curl -s -b "$COOKIE_JAR" "${BASE_URL}/api/auth/me")
echo "  /api/auth/me payload: $body"
case "$body" in
    *"\"username\""*"\"$ADMIN_USER\""*"\"role\""*"\"sysadmin\""*|*"\"role\""*"\"sysadmin\""*"\"username\""*"\"$ADMIN_USER\""*)
        pass "GET /api/auth/me with cookie returns username=$ADMIN_USER + role=sysadmin" ;;
    *) fail "GET /api/auth/me payload missing username=$ADMIN_USER and/or role=sysadmin" ;;
esac

# ---------------------------------------------------------------------------
section "Step 3 — Flask ↔ Postgres roundtrip (GET /api/servers → [])"
# ---------------------------------------------------------------------------
# Proves: schema applied, FK resolvable, JSON serializer compatible with
# Postgres types, no extension missing (gen_random_uuid…). A 500 here
# means the DB is unreachable from Flask or the query refers to a column
# that does not exist.
code=$(curl -s -o "$RESP_BODY" -w '%{http_code}' -b "$COOKIE_JAR" "${BASE_URL}/api/servers")
[ "$code" = "200" ] || { cat "$RESP_BODY"; echo; fail "GET /api/servers — expected 200, got $code"; }
body=$(cat "$RESP_BODY")
case "$body" in
    "[]"|"[ ]") pass "GET /api/servers → 200 [] (DB is reachable, schema applied, serializer OK)" ;;
    *) fail "GET /api/servers — expected empty array, got: $body" ;;
esac

# ---------------------------------------------------------------------------
section "Step 4 — nginx SPA fallback (/, /servers/xyz both return index.html)"
# ---------------------------------------------------------------------------
# Vue-router runs in history mode. Without `try_files $uri $uri/ /index.html`
# in nginx, a hard-refresh on /servers/server-01 returns 404. This check
# catches that.
root_html=$(curl -s "${BASE_URL}/")
[ -n "$root_html" ] || fail "GET / returned empty body"
case "$root_html" in
    *"<html"*|*"<!DOCTYPE"*|*"<!doctype"*) pass "GET / returns HTML (SPA entry point served)" ;;
    *) fail "GET / does not look like HTML: $(printf '%s' "$root_html" | head -c 100)" ;;
esac

deep_html=$(curl -s "${BASE_URL}/servers/some-future-host")
if [ "$root_html" = "$deep_html" ]; then
    pass "GET /servers/some-future-host returns the same HTML (nginx try_files OK)"
else
    fail "GET /servers/some-future-host differs from / — vue-router history mode will 404 on hard refresh"
fi

# ---------------------------------------------------------------------------
section "Step 5 — route sweep (no /api/ endpoint may return 5xx)"
# ---------------------------------------------------------------------------
# Strategy: as sysadmin, hit every documented route. Sentinel values for
# path parameters (does-not-exist / SHA256:nonexistent / nil UUID) so the
# server has nothing to act on — 4xx is the right answer, 5xx is a bug.
#
# This catches what mocked pytest cannot:
#   - SQL typos that mocks don't see (substring assertions accept them)
#   - JSON serializer crashes on Postgres types (UUID, INET, TIMESTAMPTZ)
#   - KeyError / TypeError in handlers when input is incomplete
#   - Missing pg_extension (gen_random_uuid, etc.)
#
# Route inventory mirrors app/web.py at HEAD. Keep alphabetical by path
# inside each group.

NIL_UUID="00000000-0000-0000-0000-000000000000"
NIL_HOST="does-not-exist"
NIL_FP="SHA256:nonexistent"

sweep() {
    local method="$1" path="$2" body="${3:-}"
    local code
    if [ -n "$body" ]; then
        code=$(curl -s -o "$RESP_BODY" -w '%{http_code}' -b "$COOKIE_JAR" \
            -H 'Content-Type: application/json' -X "$method" -d "$body" \
            "${BASE_URL}${path}")
    else
        code=$(curl -s -o "$RESP_BODY" -w '%{http_code}' -b "$COOKIE_JAR" \
            -X "$method" "${BASE_URL}${path}")
    fi
    if [ "$code" -ge 500 ]; then
        echo "  Response body (first 500 bytes):"
        head -c 500 "$RESP_BODY"; echo
        fail "$method $path → ${code} (server-side crash)"
    fi
    # The sweep runs with the sysadmin cookie. By definition, sysadmin has
    # access to every documented route — a 403 here would mean the role
    # gate erroneously rejects the highest-privileged role, which is a
    # silent regression: pytest mocks the session and would not catch it.
    if [ "$code" = "403" ]; then
        echo "  Response body (first 500 bytes):"
        head -c 500 "$RESP_BODY"; echo
        fail "$method $path → 403 (sysadmin rejected — role-gate regression)"
    fi
    pass "$method $path → $code"
}

# Auth/me variant
sweep GET    /api/admins/me

# Servers
sweep GET    /api/servers
sweep GET    "/api/servers/${NIL_HOST}"
sweep GET    "/api/servers/${NIL_HOST}/collector-key"
sweep GET    "/api/servers/${NIL_HOST}/sessions"
sweep GET    "/api/servers/${NIL_HOST}/sessions/history"
sweep GET    "/api/servers/${NIL_HOST}/sshd-audit"
sweep POST   /api/servers '{}'
sweep POST   "/api/servers/${NIL_HOST}/provision" '{"ssh_user":"root"}'
sweep PUT    "/api/servers/${NIL_HOST}" '{}'
sweep PUT    "/api/servers/${NIL_HOST}/disable"
sweep PUT    "/api/servers/${NIL_HOST}/enable"
sweep DELETE "/api/servers/${NIL_HOST}"
sweep POST   "/api/servers/${NIL_HOST}/scan"
sweep POST   "/api/servers/${NIL_HOST}/rotate-key"
sweep POST   "/api/servers/${NIL_HOST}/sync"
sweep POST   "/api/servers/${NIL_HOST}/sessions/refresh"

# Keys
sweep GET    /api/keys
sweep GET    "/api/keys/search?q=x"
sweep GET    "/api/keys/get/${NIL_FP}"
sweep POST   "/api/keys/validate/${NIL_FP}" '{}'
sweep POST   "/api/keys/revoke/${NIL_FP}"   '{"reason":"smoke"}'
sweep POST   "/api/keys/assign/${NIL_FP}"   '{"owner":"smoke"}'
sweep POST   "/api/keys/set-expiry/${NIL_FP}"   '{"hours":24}'
sweep POST   "/api/keys/remove-expiry/${NIL_FP}" '{}'
sweep POST   /api/keys/bulk-validate '{"fingerprints":[]}'
sweep POST   /api/keys/bulk-revoke   '{"fingerprints":[],"reason":"smoke"}'

# Access
sweep GET    /api/access
sweep GET    "/api/access/${NIL_UUID}"
sweep GET    /api/access/deployed-users
sweep POST   /api/access/grant         '{}'
sweep POST   /api/access/deploy        '{}'
sweep POST   /api/access/grant-group   '{}'
sweep POST   /api/access/revoke-group  '{}'
sweep PUT    /api/access/change-group  '{}'
sweep POST   /api/access/lock-user     '{}'
sweep POST   /api/access/unlock-user   '{}'
sweep POST   /api/access/request       '{}'
sweep POST   "/api/access/${NIL_UUID}/approve" '{}'
sweep POST   "/api/access/${NIL_UUID}/reject"  '{}'
sweep POST   "/api/access/${NIL_UUID}/revoke"  '{}'

# Admins
sweep GET    /api/admins
sweep POST   /api/admins '{}'
sweep PUT    "/api/admins/${NIL_HOST}"          '{}'
sweep PUT    "/api/admins/${NIL_HOST}/password" '{"password":"x"}'
sweep PUT    "/api/admins/${NIL_HOST}/disable"
sweep PUT    "/api/admins/${NIL_HOST}/enable"
sweep DELETE "/api/admins/${NIL_HOST}"
sweep PUT    "/api/admins/${NIL_HOST}/alerts"   '{"alerts_enabled":true}'

# Audit + system
sweep GET    /api/audit
sweep GET    /api/system/status
sweep GET    /api/system/config
sweep POST   /api/system/scan
sweep PUT    /api/system/config '{}'
sweep POST   /api/system/test-smtp '{}'

# ---------------------------------------------------------------------------
section "Step 6 — RBAC roundtrip (sysadmin / operator / viewer enforced at runtime)"
# ---------------------------------------------------------------------------
# Pytest covers `require_role` with mocks. This step proves the wiring
# survives in runtime: real session cookie → real DB lookup of the admin
# row → real role enforcement on real routes. A change that breaks the
# operator/viewer matrix without touching the unit-tested decorator (e.g.
# regression on session-load that returns None for role) lands silently
# in pytest but fails here.
#
# Password policy (#62) requires: 8+ chars, 1 upper, 1 lower, 1 digit,
# 1 special. The two passwords below satisfy it.

COOKIE_OP="$(mktemp /tmp/sam-smoke-cookies-op.XXXXXX)"
COOKIE_VW="$(mktemp /tmp/sam-smoke-cookies-vw.XXXXXX)"
trap 'rm -f "$COOKIE_JAR" "$COOKIE_OP" "$COOKIE_VW" "$RESP_BODY"' EXIT

OP_USER="op-smoke"
OP_PW="Op3rat0rPw!"
VW_USER="vw-smoke"
VW_PW="V13werPw!"

# Create operator + viewer via the admin session. The workflow re-runs the
# full smoke after a container restart on the same volume — by then the
# rows already exist, so accept either 201 (first run) or 409 (replay).
for tuple in "${OP_USER}|operator|${OP_PW}|op@x" "${VW_USER}|viewer|${VW_PW}|vw@x"; do
    user="${tuple%%|*}"; rest="${tuple#*|}"
    role="${rest%%|*}"; rest="${rest#*|}"
    pw="${rest%%|*}"; email="${rest#*|}"
    code=$(curl -s -o "$RESP_BODY" -w '%{http_code}' -b "$COOKIE_JAR" \
        -H 'Content-Type: application/json' -X POST \
        -d "{\"username\":\"${user}\",\"email\":\"${email}\",\"password\":\"${pw}\",\"role\":\"${role}\"}" \
        "${BASE_URL}/api/admins")
    case "$code" in
        201) pass "POST /api/admins (${role} ${user}) → 201 (created)" ;;
        409) pass "POST /api/admins (${role} ${user}) → 409 (already exists from prior run — OK)" ;;
        *)   cat "$RESP_BODY"; echo; fail "create ${role} ${user} — expected 201 or 409, got $code" ;;
    esac
done

# Login as operator + viewer (separate cookie jars).
code=$(curl -s -o /dev/null -w '%{http_code}' -c "$COOKIE_OP" \
    -H 'Content-Type: application/json' -X POST \
    -d "{\"username\":\"${OP_USER}\",\"password\":\"${OP_PW}\"}" \
    "${BASE_URL}/api/auth/login")
[ "$code" = "200" ] || fail "operator login — expected 200, got $code"
pass "operator can log in"

code=$(curl -s -o /dev/null -w '%{http_code}' -c "$COOKIE_VW" \
    -H 'Content-Type: application/json' -X POST \
    -d "{\"username\":\"${VW_USER}\",\"password\":\"${VW_PW}\"}" \
    "${BASE_URL}/api/auth/login")
[ "$code" = "200" ] || fail "viewer login — expected 200, got $code"
pass "viewer can log in"

# Assert a single (role, method, path, expected-code-class) tuple.
#  - "<500" accepts anything 2xx/3xx/4xx other than 403 — for routes
#    where the body is intentionally incomplete (smoke doesn't care
#    about 200 vs 400, it cares that the *role* gate didn't reject)
#  - exact codes (200, 403) tested directly otherwise
rbac_check() {
    local jar="$1" method="$2" path="$3" body="$4" expected="$5" label="$6"
    local code
    if [ -n "$body" ]; then
        code=$(curl -s -o /dev/null -w '%{http_code}' -b "$jar" \
            -H 'Content-Type: application/json' -X "$method" -d "$body" \
            "${BASE_URL}${path}")
    else
        code=$(curl -s -o /dev/null -w '%{http_code}' -b "$jar" \
            -X "$method" "${BASE_URL}${path}")
    fi
    case "$expected" in
        "not403")
            if [ "$code" = "403" ]; then
                fail "$label — expected non-403, got 403 (role gate rejected legitimate access)"
            elif [ "$code" -ge 500 ]; then
                fail "$label — expected non-5xx, got $code"
            else
                pass "$label → $code (not 403)"
            fi
            ;;
        *)
            [ "$code" = "$expected" ] || fail "$label — expected $expected, got $code"
            pass "$label → $code"
            ;;
    esac
}

# RBAC matrix below mirrors app/CLAUDE.md.
# Each role is exercised on the routes that distinguish it from its
# neighbours: an operator must be denied the sysadmin-only writes; a viewer
# must be denied every mutating endpoint regardless of category. Reads that
# are allowed for every role (GET /api/servers, /api/keys, /api/access,
# /api/admins, /api/audit, /api/system/status, /api/system/config) are
# spot-checked here to prove the runtime role-load yields a usable session.

# --- Operator -------------------------------------------------------------
# Allowed reads (must not 403).
for path in /api/servers /api/keys /api/access /api/admins /api/audit \
            /api/system/status /api/system/config /api/access/deployed-users; do
    rbac_check "$COOKIE_OP" GET "$path" "" not403 "operator GET $path"
done
# Allowed writes (operator can scan, validate, deploy, lock/unlock, group-grant
# for sam-operator/sam-pkg, change a non-root group). Not-403, body may 400.
rbac_check "$COOKIE_OP" POST /api/system/scan               ""                         not403 "operator POST /api/system/scan"
rbac_check "$COOKIE_OP" POST /api/keys/bulk-validate        '{"fingerprints":[]}'      not403 "operator POST /api/keys/bulk-validate"
rbac_check "$COOKIE_OP" POST /api/keys/bulk-revoke          '{"fingerprints":[],"reason":"x"}' not403 "operator POST /api/keys/bulk-revoke"
rbac_check "$COOKIE_OP" POST /api/access/deploy             '{}'                       not403 "operator POST /api/access/deploy"
rbac_check "$COOKIE_OP" POST /api/access/lock-user          '{}'                       not403 "operator POST /api/access/lock-user"
rbac_check "$COOKIE_OP" POST /api/access/unlock-user        '{}'                       not403 "operator POST /api/access/unlock-user"
rbac_check "$COOKIE_OP" POST /api/access/grant-group        '{"unix_user":"u","hostname":"h","sam_group":"sam-operator"}' not403 "operator POST /api/access/grant-group (sam-operator)"
rbac_check "$COOKIE_OP" POST /api/system/test-smtp          '{}'                       not403 "operator POST /api/system/test-smtp"
# Sysadmin-only writes (must be 403, never 400 — role-gate runs first).
rbac_check "$COOKIE_OP" POST   /api/admins                          '{"username":"x","password":"Aa1!aaaa"}' 403 "operator POST /api/admins (sysadmin-only)"
rbac_check "$COOKIE_OP" PUT    "/api/admins/${OP_USER}"             '{}'                       403 "operator PUT /api/admins/<user> (sysadmin-only)"
rbac_check "$COOKIE_OP" PUT    /api/system/config                   '{}'                       403 "operator PUT /api/system/config (sysadmin-only)"
rbac_check "$COOKIE_OP" POST   /api/servers                         '{}'                       403 "operator POST /api/servers (sysadmin-only)"
rbac_check "$COOKIE_OP" PUT    "/api/servers/${NIL_HOST}/disable"   ""                         403 "operator PUT /api/servers/<h>/disable (sysadmin-only)"
rbac_check "$COOKIE_OP" PUT    "/api/servers/${NIL_HOST}/enable"    ""                         403 "operator PUT /api/servers/<h>/enable (sysadmin-only)"
rbac_check "$COOKIE_OP" DELETE "/api/servers/${NIL_HOST}"           ""                         403 "operator DELETE /api/servers/<h> (sysadmin-only)"
rbac_check "$COOKIE_OP" POST   "/api/servers/${NIL_HOST}/rotate-key" ""                        403 "operator POST /api/servers/<h>/rotate-key (sysadmin-only)"
rbac_check "$COOKIE_OP" POST   /api/access/grant-group              '{"unix_user":"u","hostname":"h","sam_group":"sam-root"}'     403 "operator POST /api/access/grant-group (sam-root → sysadmin-only)"

# --- Viewer ---------------------------------------------------------------
# Reads — all allowed for viewer per CLAUDE.md matrix.
for path in /api/servers /api/keys /api/access /api/admins /api/audit \
            /api/system/status /api/system/config /api/access/deployed-users; do
    rbac_check "$COOKIE_VW" GET "$path" "" 200 "viewer GET $path"
done
# Mutating endpoints — every one of these must be 403, not 400, not 500.
rbac_check "$COOKIE_VW" POST   /api/keys/bulk-validate              '{"fingerprints":[]}'      403 "viewer POST /api/keys/bulk-validate (forbidden)"
rbac_check "$COOKIE_VW" POST   /api/keys/bulk-revoke                '{"fingerprints":[],"reason":"x"}' 403 "viewer POST /api/keys/bulk-revoke (forbidden)"
rbac_check "$COOKIE_VW" POST   /api/access/deploy                   '{}'                       403 "viewer POST /api/access/deploy (forbidden)"
rbac_check "$COOKIE_VW" POST   /api/access/lock-user                '{}'                       403 "viewer POST /api/access/lock-user (forbidden)"
rbac_check "$COOKIE_VW" POST   /api/access/unlock-user              '{}'                       403 "viewer POST /api/access/unlock-user (forbidden)"
rbac_check "$COOKIE_VW" POST   /api/access/grant-group              '{"unix_user":"u","hostname":"h","sam_group":"sam-operator"}' 403 "viewer POST /api/access/grant-group (forbidden)"
rbac_check "$COOKIE_VW" POST   /api/system/scan                     ""                         403 "viewer POST /api/system/scan (forbidden)"
rbac_check "$COOKIE_VW" POST   /api/admins                          '{"username":"x","password":"Aa1!aaaa"}' 403 "viewer POST /api/admins (forbidden)"
rbac_check "$COOKIE_VW" PUT    /api/system/config                   '{}'                       403 "viewer PUT /api/system/config (forbidden)"
rbac_check "$COOKIE_VW" POST   /api/servers                         '{}'                       403 "viewer POST /api/servers (forbidden)"
rbac_check "$COOKIE_VW" PUT    "/api/servers/${NIL_HOST}/disable"   ""                         403 "viewer PUT /api/servers/<h>/disable (forbidden)"
rbac_check "$COOKIE_VW" DELETE "/api/servers/${NIL_HOST}"           ""                         403 "viewer DELETE /api/servers/<h> (forbidden)"
rbac_check "$COOKIE_VW" POST   "/api/servers/${NIL_HOST}/scan"      ""                         403 "viewer POST /api/servers/<h>/scan (forbidden)"

# ---------------------------------------------------------------------------
section "Step 7 — logout invalidates the session"
# ---------------------------------------------------------------------------
code=$(curl -s -o /dev/null -w '%{http_code}' -b "$COOKIE_JAR" -c "$COOKIE_JAR" \
    -X POST "${BASE_URL}/api/auth/logout")
[ "$code" = "200" ] || fail "POST /api/auth/logout — expected 200, got $code"
pass "POST /api/auth/logout → 200"

code=$(curl -s -o /dev/null -w '%{http_code}' -b "$COOKIE_JAR" "${BASE_URL}/api/auth/me")
[ "$code" = "401" ] || fail "GET /api/auth/me after logout — expected 401, got $code (session not invalidated)"
pass "GET /api/auth/me after logout → 401 (server-side session cleared)"

# ---------------------------------------------------------------------------
section "Step 8 — rate limiter triggers HTTP 429 after threshold (#236)"
# ---------------------------------------------------------------------------
# Default settings.login_max_attempts = 10. The 11th failed attempt from
# the same IP must return 429 (not another 401). This is in-process
# state — pytest single-process with mocked DB cannot exercise it.
#
# IMPORTANT: this step bans the runner's IP for login_ban_seconds (default
# 300 s). Anything that needs to log in after this would fail — that's
# why this step runs last.
ban_seen=""
for i in 1 2 3 4 5 6 7 8 9 10 11 12; do
    code=$(curl -s -o /dev/null -w '%{http_code}' \
        -H 'Content-Type: application/json' -X POST \
        -d '{"username":"ratelimit-probe","password":"wrong-on-purpose"}' \
        "${BASE_URL}/api/auth/login")
    case "$code" in
        429)
            ban_seen="$i"
            break
            ;;
        401|400)
            : # expected pre-ban
            ;;
        *)
            fail "rate limiter probe attempt $i — unexpected code $code (expected 401/400/429)"
            ;;
    esac
done

if [ -z "$ban_seen" ]; then
    fail "rate limiter never triggered HTTP 429 across 12 wrong logins — #236 regressed"
fi
pass "rate limiter triggers 429 at attempt $ban_seen (≤ login_max_attempts+1)"

echo ""
echo "${GREEN}All smoke assertions passed.${RST}"
