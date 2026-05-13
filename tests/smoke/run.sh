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
section "Step 6 — logout invalidates the session"
# ---------------------------------------------------------------------------
code=$(curl -s -o /dev/null -w '%{http_code}' -b "$COOKIE_JAR" -c "$COOKIE_JAR" \
    -X POST "${BASE_URL}/api/auth/logout")
[ "$code" = "200" ] || fail "POST /api/auth/logout — expected 200, got $code"
pass "POST /api/auth/logout → 200"

code=$(curl -s -o /dev/null -w '%{http_code}' -b "$COOKIE_JAR" "${BASE_URL}/api/auth/me")
[ "$code" = "401" ] || fail "GET /api/auth/me after logout — expected 401, got $code (session not invalidated)"
pass "GET /api/auth/me after logout → 401 (server-side session cleared)"

echo ""
echo "${GREEN}All smoke assertions passed.${RST}"
