#!/usr/bin/env bash
# Smoke test — assert the SAM container is bootable end-to-end.
#
# Designed to be invoked by .github/workflows/smoke-container.yml after a
# `docker compose up -d` against a freshly-built image. Validates:
#   - Flask is alive behind Nginx (/api/auth/me returns 401 unauthenticated)
#   - Postgres is initialised, schema applied, admin row inserted from ENV
#   - POST /api/auth/login succeeds with the admin credentials from .env
#   - GET /api/auth/me with the session cookie returns the expected payload
#
# Designed to fail fast and dump compose logs on assertion failure so the
# CI log is self-contained.
#
# Usage:  bash tests/smoke/run.sh [BASE_URL] [ADMIN_USER] [ADMIN_PASSWORD]

set -eu

BASE_URL="${1:-http://127.0.0.1:8080}"
ADMIN_USER="${2:-admin}"
ADMIN_PASSWORD="${3:-admin}"
COOKIE_JAR="$(mktemp /tmp/sam-smoke-cookies.XXXXXX)"
trap 'rm -f "$COOKIE_JAR"' EXIT

if [ -t 1 ]; then
    GREEN=$'\033[32m'; RED=$'\033[31m'; RST=$'\033[0m'
else
    GREEN=""; RED=""; RST=""
fi
pass() { printf '  %sOK%s   %s\n' "$GREEN" "$RST" "$1"; }
fail() { printf '  %sFAIL%s %s\n' "$RED" "$RST" "$1" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Wait for /api/auth/me to respond. We don't care about the status code yet —
# we only need to know the HTTP server is up and proxying to Flask. A 401 is
# the *expected* steady state, but during boot we'll see ConnRefused or 502
# until Nginx has Flask upstream.
# ---------------------------------------------------------------------------
echo "Waiting for ${BASE_URL}/api/auth/me to respond (up to 120 s)…"
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
# Unauthenticated /api/auth/me must be 401 (proves require_auth is wired).
# ---------------------------------------------------------------------------
code=$(curl -s -o /dev/null -w '%{http_code}' "${BASE_URL}/api/auth/me")
[ "$code" = "401" ] || fail "GET /api/auth/me unauthenticated — expected 401, got $code"
pass "GET /api/auth/me without session → 401"

# ---------------------------------------------------------------------------
# Login must succeed with the admin credentials seeded from ENV by
# bootstrap.sh (this exercises Postgres connection, password hash, session
# cookie issuance).
# ---------------------------------------------------------------------------
login_body=$(printf '{"username":"%s","password":"%s"}' "$ADMIN_USER" "$ADMIN_PASSWORD")
code=$(curl -s -o /tmp/sam-smoke-login.json -w '%{http_code}' \
    -c "$COOKIE_JAR" \
    -H 'Content-Type: application/json' \
    -X POST -d "$login_body" \
    "${BASE_URL}/api/auth/login")
if [ "$code" != "200" ]; then
    echo "Response body:"; cat /tmp/sam-smoke-login.json || true
    fail "POST /api/auth/login — expected 200, got $code"
fi
pass "POST /api/auth/login → 200 (admin from ENV is usable)"

# ---------------------------------------------------------------------------
# Authenticated /api/auth/me must echo back the admin profile.
# ---------------------------------------------------------------------------
body=$(curl -s -b "$COOKIE_JAR" "${BASE_URL}/api/auth/me")
echo "  /api/auth/me payload: $body"
case "$body" in
    *"\"username\""*"\"$ADMIN_USER\""*) pass "GET /api/auth/me with cookie returns username=$ADMIN_USER" ;;
    *) fail "GET /api/auth/me payload does not contain username=$ADMIN_USER" ;;
esac
case "$body" in
    *"\"role\""*"\"sysadmin\""*) pass "admin from ENV was seeded with role=sysadmin" ;;
    *) fail "admin role is not sysadmin in /api/auth/me payload" ;;
esac

echo ""
echo "${GREEN}All smoke assertions passed.${RST}"
