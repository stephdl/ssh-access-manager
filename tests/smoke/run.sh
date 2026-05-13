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

# Accept self-signed TLS when BASE_URL is https (HTTPS smoke variant).
case "$BASE_URL" in
    https://*) CURL_FLAGS="-sk" ;;
    *)         CURL_FLAGS="-s"  ;;
esac

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
    code=$(curl $CURL_FLAGS -o /dev/null -w '%{http_code}' --max-time 2 "${BASE_URL}/api/auth/me" || true)
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
code=$(curl $CURL_FLAGS -o /dev/null -w '%{http_code}' "${BASE_URL}/api/auth/me")
[ "$code" = "401" ] || fail "GET /api/auth/me unauthenticated — expected 401, got $code"
pass "GET /api/auth/me without session → 401"

login_body=$(printf '{"username":"%s","password":"%s"}' "$ADMIN_USER" "$ADMIN_PASSWORD")
code=$(curl $CURL_FLAGS -o "$RESP_BODY" -w '%{http_code}' \
    -c "$COOKIE_JAR" \
    -H 'Content-Type: application/json' \
    -X POST -d "$login_body" \
    "${BASE_URL}/api/auth/login")
if [ "$code" != "200" ]; then
    echo "Response body:"; cat "$RESP_BODY" || true; echo
    fail "POST /api/auth/login — expected 200, got $code"
fi
pass "POST /api/auth/login → 200"

body=$(curl $CURL_FLAGS -b "$COOKIE_JAR" "${BASE_URL}/api/auth/me")
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
code=$(curl $CURL_FLAGS -o "$RESP_BODY" -w '%{http_code}' -b "$COOKIE_JAR" "${BASE_URL}/api/servers")
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
root_html=$(curl $CURL_FLAGS "${BASE_URL}/")
[ -n "$root_html" ] || fail "GET / returned empty body"
case "$root_html" in
    *"<html"*|*"<!DOCTYPE"*|*"<!doctype"*) pass "GET / returns HTML (SPA entry point served)" ;;
    *) fail "GET / does not look like HTML: $(printf '%s' "$root_html" | head -c 100)" ;;
esac

deep_html=$(curl $CURL_FLAGS "${BASE_URL}/servers/some-future-host")
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
        code=$(curl $CURL_FLAGS -o "$RESP_BODY" -w '%{http_code}' -b "$COOKIE_JAR" \
            -H 'Content-Type: application/json' -X "$method" -d "$body" \
            "${BASE_URL}${path}")
    else
        code=$(curl $CURL_FLAGS -o "$RESP_BODY" -w '%{http_code}' -b "$COOKIE_JAR" \
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
section "Step 5b — security headers (cookie flags + JSON Content-Type + nginx hardening)"
# ---------------------------------------------------------------------------
# These three sub-checks are inexpensive (one curl each) and cover the most
# dangerous silent regressions a Vue SPA / Flask container can ship with.

# --- Cookie flags on the session cookie ---
# HttpOnly is set unconditionally; SameSite=Lax is always set; Secure is set
# only when the container was started with NGINX_TLS_* (the smoke detects this
# from BASE_URL).
COOKIE_HEADER=$(curl $CURL_FLAGS -D - -o /dev/null \
    -H 'Content-Type: application/json' -X POST \
    -d "$login_body" "${BASE_URL}/api/auth/login" | grep -i '^set-cookie:' || true)
echo "  Set-Cookie line: $(printf '%s' "$COOKIE_HEADER" | head -c 200)"

case "$COOKIE_HEADER" in
    *HttpOnly*) pass "session cookie has HttpOnly" ;;
    *)          fail "session cookie missing HttpOnly — XSS could exfiltrate it" ;;
esac
case "$COOKIE_HEADER" in
    *SameSite=Lax*|*SameSite=Strict*) pass "session cookie has SameSite Lax/Strict" ;;
    *)                                fail "session cookie missing SameSite" ;;
esac
case "$BASE_URL" in
    https://*)
        case "$COOKIE_HEADER" in
            *Secure*) pass "session cookie has Secure (HTTPS mode)" ;;
            *)        fail "session cookie missing Secure under HTTPS — downgrade attack possible" ;;
        esac
        ;;
    *)
        # HTTP mode: Secure must NOT be set (the browser would drop the cookie).
        case "$COOKIE_HEADER" in
            *Secure*) fail "session cookie has Secure under HTTP — browser will drop it" ;;
            *)        pass "session cookie does not have Secure under HTTP (expected)" ;;
        esac
        ;;
esac

# --- Content-Type: application/json on the API surface ---
# A regression where an endpoint returns text/html (debug print, leaked
# traceback page) would be invisible to a JSON-only frontend until the user
# hits a parse error.
for api_path in /api/auth/me /api/servers /api/keys /api/audit /api/system/status; do
    ctype=$(curl $CURL_FLAGS -D - -o /dev/null -b "$COOKIE_JAR" "${BASE_URL}${api_path}" \
        | grep -i '^content-type:' | head -1)
    case "$ctype" in
        *application/json*) pass "Content-Type on ${api_path}: application/json" ;;
        *)                  fail "Content-Type on ${api_path} is not JSON — got: $ctype" ;;
    esac
done

# --- Nginx hardening response headers on / (covers /api too because they're
# declared at server level in both nginx templates) ---
HEADERS=$(curl $CURL_FLAGS -D - -o /dev/null "${BASE_URL}/")
for header in \
    "X-Frame-Options: DENY" \
    "X-Content-Type-Options: nosniff" \
    "Referrer-Policy:" \
    "Content-Security-Policy:"; do
    if printf '%s' "$HEADERS" | grep -qi "^${header}"; then
        pass "nginx serves header '${header}'"
    else
        fail "nginx is NOT serving '${header}' — hardening regression in the template"
    fi
done

# ---------------------------------------------------------------------------
section "Step 5c — settings round-trip (sets a recognisable value; persistence checked by workflow)"
# ---------------------------------------------------------------------------
# Write scan_interval_hours=6 (default is 4). The workflow captures this
# value via a separate curl AFTER the first smoke run completes, then
# verifies it survives a `docker compose down` + `up` cycle. On boot #2
# the PUT is idempotent (value is already 6) so this step is replay-safe.
SETTINGS_BEFORE=$(curl $CURL_FLAGS -b "$COOKIE_JAR" "${BASE_URL}/api/system/config")
echo "  Settings before: $(printf '%s' "$SETTINGS_BEFORE" | head -c 200)"

code=$(curl $CURL_FLAGS -o /dev/null -w '%{http_code}' -b "$COOKIE_JAR" \
    -H 'Content-Type: application/json' -X PUT \
    -d '{"scan_interval_hours":6,"expire_warn_days":7,"expire_warn_days_2":2,"login_max_attempts":10,"login_ban_seconds":300,"audit_retention_days":365}' \
    "${BASE_URL}/api/system/config")
[ "$code" = "200" ] || fail "PUT /api/system/config — expected 200, got $code"
pass "PUT /api/system/config scan_interval_hours=6 → 200"

SETTINGS_AFTER=$(curl $CURL_FLAGS -b "$COOKIE_JAR" "${BASE_URL}/api/system/config")
case "$SETTINGS_AFTER" in
    *'"scan_interval_hours"'*'6'*) pass "GET /api/system/config returns scan_interval_hours=6" ;;
    *) fail "GET /api/system/config does not reflect scan_interval_hours=6 — got: $(printf '%s' "$SETTINGS_AFTER" | head -c 200)" ;;
esac

# ---------------------------------------------------------------------------
section "Step 5d — audit log records LOGIN_FAILED entries (persistence via workflow)"
# ---------------------------------------------------------------------------
# Generate 3 LOGIN_FAILED entries with a username that does NOT exist so the
# rate limiter (threshold 10) is not tripped. Verify the audit_log grew by
# exactly 3 entries with action=LOGIN_FAILED. The workflow then verifies the
# audit count survives a restart.
AUDIT_BEFORE=$(curl $CURL_FLAGS -b "$COOKIE_JAR" "${BASE_URL}/api/audit?action=LOGIN_FAILED&limit=1000" \
    | grep -oE '"id":"[^"]+"' | wc -l)
echo "  LOGIN_FAILED rows before: $AUDIT_BEFORE"

for _ in 1 2 3; do
    curl $CURL_FLAGS -o /dev/null \
        -H 'Content-Type: application/json' -X POST \
        -d '{"username":"audit-probe-not-an-admin","password":"wrong"}' \
        "${BASE_URL}/api/auth/login" >/dev/null
done

AUDIT_AFTER=$(curl $CURL_FLAGS -b "$COOKIE_JAR" "${BASE_URL}/api/audit?action=LOGIN_FAILED&limit=1000" \
    | grep -oE '"id":"[^"]+"' | wc -l)
echo "  LOGIN_FAILED rows after:  $AUDIT_AFTER"

delta=$(( AUDIT_AFTER - AUDIT_BEFORE ))
if [ "$delta" -ge 3 ]; then
    pass "audit log grew by ≥3 LOGIN_FAILED entries (delta=$delta)"
else
    fail "audit log did not grow as expected (delta=$delta, expected ≥3)"
fi

# ---------------------------------------------------------------------------
section "Step 5e — password change flow (first-login state transition)"
# ---------------------------------------------------------------------------
# GET /api/auth/me returns must_change_password=true iff password_changed_at
# IS NULL in the DB. The default admin seeded from ENV starts with NULL.
# After any password change, the flag flips to false permanently.
#
# Two cases:
#   Boot 1: must_change_password=true on entry. Do the full flow and
#           restore the original password (must_change_password stays false
#           because password_changed_at was set).
#   Boot 2 (same volume): must_change_password=false on entry. Skip the
#           mutation (would be no-op) — already validated in boot 1.
ME_BEFORE=$(curl $CURL_FLAGS -b "$COOKIE_JAR" "${BASE_URL}/api/auth/me")
case "$ME_BEFORE" in
    *'"must_change_password":true'*)
        pass "boot 1: /api/auth/me reports must_change_password=true (NULL password_changed_at)"
        NEW_PW="Sm0kePw!New123"
        code=$(curl $CURL_FLAGS -o "$RESP_BODY" -w '%{http_code}' -b "$COOKIE_JAR" \
            -H 'Content-Type: application/json' -X PUT \
            -d "{\"password\":\"${NEW_PW}\"}" \
            "${BASE_URL}/api/admins/${ADMIN_USER}/password")
        [ "$code" = "200" ] || { cat "$RESP_BODY"; echo; fail "PUT password — expected 200, got $code"; }
        pass "PUT /api/admins/${ADMIN_USER}/password → 200"

        # Re-login with the new password — the previous session may still be
        # valid (depends on whether changing password invalidates sessions).
        # Use a fresh cookie jar to be unambiguous.
        TMP_JAR=$(mktemp /tmp/sam-smoke-pwflow.XXXXXX)
        code=$(curl $CURL_FLAGS -o /dev/null -w '%{http_code}' -c "$TMP_JAR" \
            -H 'Content-Type: application/json' -X POST \
            -d "{\"username\":\"${ADMIN_USER}\",\"password\":\"${NEW_PW}\"}" \
            "${BASE_URL}/api/auth/login")
        [ "$code" = "200" ] || { rm -f "$TMP_JAR"; fail "login with new password — expected 200, got $code"; }
        pass "re-login with the new password → 200"

        ME_AFTER=$(curl $CURL_FLAGS -b "$TMP_JAR" "${BASE_URL}/api/auth/me")
        case "$ME_AFTER" in
            *'"must_change_password":false'*)
                pass "/api/auth/me now reports must_change_password=false (flag flipped)" ;;
            *)
                rm -f "$TMP_JAR"
                fail "must_change_password did not flip to false: $ME_AFTER" ;;
        esac

        # Restore the original password so the workflow's second smoke run
        # (and the rate limiter test below) can keep authenticating as the
        # same admin with the same credentials.
        code=$(curl $CURL_FLAGS -o /dev/null -w '%{http_code}' -b "$TMP_JAR" \
            -H 'Content-Type: application/json' -X PUT \
            -d "{\"password\":\"${ADMIN_PASSWORD}\"}" \
            "${BASE_URL}/api/admins/${ADMIN_USER}/password")
        rm -f "$TMP_JAR"
        [ "$code" = "200" ] || fail "restore original password — expected 200, got $code"
        pass "original password restored (must_change_password stays false because password_changed_at is now set)"
        ;;
    *'"must_change_password":false'*)
        pass "boot 2+: must_change_password already false — flow validated on a prior boot (persistence check)" ;;
    *)
        fail "must_change_password field missing from /api/auth/me payload: $ME_BEFORE" ;;
esac

# ---------------------------------------------------------------------------
section "Step 5f — static asset MIME types (Vite-hashed JS + CSS)"
# ---------------------------------------------------------------------------
# Vue/Vite produces hashed bundles in /assets/ and references them from
# index.html via <script type="module" src="/assets/index-XXXXX.js"> and
# <link rel="stylesheet" href="/assets/index-XXXXX.css">. If
# `include /etc/nginx/mime.types;` is missing from nginx.conf, the .js
# file is served with default_type application/octet-stream — modern
# browsers refuse to execute ES modules with the wrong MIME type and the
# SPA never starts.
SPA_HTML=$(curl $CURL_FLAGS "${BASE_URL}/")
JS_URL=$(printf '%s' "$SPA_HTML" | grep -oE '/assets/[A-Za-z0-9._-]+\.js' | head -1)
CSS_URL=$(printf '%s' "$SPA_HTML" | grep -oE '/assets/[A-Za-z0-9._-]+\.css' | head -1)

[ -n "$JS_URL" ] || fail "no /assets/*.js reference found in index.html"
[ -n "$CSS_URL" ] || fail "no /assets/*.css reference found in index.html"

js_ctype=$(curl $CURL_FLAGS -D - -o /dev/null "${BASE_URL}${JS_URL}" | grep -i '^content-type:' | head -1)
case "$js_ctype" in
    *application/javascript*|*text/javascript*) pass "asset ${JS_URL}: $js_ctype" ;;
    *) fail "asset ${JS_URL} has wrong Content-Type: $js_ctype" ;;
esac

css_ctype=$(curl $CURL_FLAGS -D - -o /dev/null "${BASE_URL}${CSS_URL}" | grep -i '^content-type:' | head -1)
case "$css_ctype" in
    *text/css*) pass "asset ${CSS_URL}: $css_ctype" ;;
    *) fail "asset ${CSS_URL} has wrong Content-Type: $css_ctype" ;;
esac

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
    code=$(curl $CURL_FLAGS -o "$RESP_BODY" -w '%{http_code}' -b "$COOKIE_JAR" \
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
code=$(curl $CURL_FLAGS -o /dev/null -w '%{http_code}' -c "$COOKIE_OP" \
    -H 'Content-Type: application/json' -X POST \
    -d "{\"username\":\"${OP_USER}\",\"password\":\"${OP_PW}\"}" \
    "${BASE_URL}/api/auth/login")
[ "$code" = "200" ] || fail "operator login — expected 200, got $code"
pass "operator can log in"

code=$(curl $CURL_FLAGS -o /dev/null -w '%{http_code}' -c "$COOKIE_VW" \
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
        code=$(curl $CURL_FLAGS -o /dev/null -w '%{http_code}' -b "$jar" \
            -H 'Content-Type: application/json' -X "$method" -d "$body" \
            "${BASE_URL}${path}")
    else
        code=$(curl $CURL_FLAGS -o /dev/null -w '%{http_code}' -b "$jar" \
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
# Snapshot for the workflow's persistence check.
# Captured here, with the admin session still active, BEFORE Step 8's rate
# limiter bans the runner's IP — re-authenticating after the ban would
# require waiting login_ban_seconds.
# ---------------------------------------------------------------------------
if [ -n "${SMOKE_STATE_FILE:-}" ]; then
    audit_count=$(curl $CURL_FLAGS -b "$COOKIE_JAR" \
        "${BASE_URL}/api/audit?limit=10000" \
        | grep -oE '"id":"[^"]+"' | wc -l)
    # /api/system/config returns settings values as JSON strings, not
    # numbers — e.g. "scan_interval_hours":"6". Match the surrounding key
    # then strip everything that isn't a digit (tr -dc) to extract the
    # value regardless of whether quotes appear.
    scan_interval=$(curl $CURL_FLAGS -b "$COOKIE_JAR" \
        "${BASE_URL}/api/system/config" \
        | grep -oE '"scan_interval_hours":"?[0-9]+"?' \
        | head -1 \
        | tr -dc 0-9 || true)
    {
        echo "AUDIT_COUNT=${audit_count}"
        echo "SCAN_INTERVAL=${scan_interval}"
    } > "$SMOKE_STATE_FILE"
    pass "smoke state snapshot written to ${SMOKE_STATE_FILE} (audit=${audit_count}, scan=${scan_interval})"
fi

# ---------------------------------------------------------------------------
section "Step 7 — logout invalidates the session"
# ---------------------------------------------------------------------------
code=$(curl $CURL_FLAGS -o /dev/null -w '%{http_code}' -b "$COOKIE_JAR" -c "$COOKIE_JAR" \
    -X POST "${BASE_URL}/api/auth/logout")
[ "$code" = "200" ] || fail "POST /api/auth/logout — expected 200, got $code"
pass "POST /api/auth/logout → 200"

code=$(curl $CURL_FLAGS -o /dev/null -w '%{http_code}' -b "$COOKIE_JAR" "${BASE_URL}/api/auth/me")
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
    code=$(curl $CURL_FLAGS -o /dev/null -w '%{http_code}' \
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
