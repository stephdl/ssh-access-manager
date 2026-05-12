# =============================================================================
# ssh-access-manager — Dockerfile multi-stage
# Stage 1 : node:24-alpine  → build Vue.js 3 / Vite
# Stage 2 : alpine:3.23.4   → image finale container unique
# =============================================================================

# -----------------------------------------------------------------------------
# STAGE 1 — Build de l'interface Vue.js 3
# -----------------------------------------------------------------------------
FROM node:24-alpine AS ui-builder

WORKDIR /ui

COPY ui/package*.json ./
RUN npm ci

COPY ui/ ./
RUN npm run build

# -----------------------------------------------------------------------------
# STAGE 2 — Image finale Alpine 3.23.4
# -----------------------------------------------------------------------------
FROM alpine:3.23.4

# OCI image annotations (org.opencontainers.image.* — see spec v1.1)
LABEL org.opencontainers.image.title="ssh-access-manager" \
      org.opencontainers.image.description="SSH access audit and management — Alpine single-container with PostgreSQL, Flask API, Vue.js UI" \
      org.opencontainers.image.authors="Stéphane de Labrusse <stephdl@de-labrusse.fr>" \
      org.opencontainers.image.source="https://github.com/stephdl/ssh-access-manager" \
      org.opencontainers.image.url="https://github.com/stephdl/ssh-access-manager" \
      org.opencontainers.image.documentation="https://github.com/stephdl/ssh-access-manager/blob/main/README.md" \
      org.opencontainers.image.licenses="GPL-3.0-or-later" \
      org.opencontainers.image.vendor="Stéphane de Labrusse"

RUN apk update && apk add --no-cache \
    postgresql18 \
    postgresql18-client \
    python3 \
    py3-pip \
    py3-setuptools \
    supervisor \
    nginx \
    openssl \
    msmtp \
    openssh-client \
    busybox-extras \
    wget \
    tzdata && \
    pip install --no-cache-dir \
        flask \
        click \
        paramiko \
        psycopg2-binary \
        pyyaml \
        waitress \
        --break-system-packages

COPY --from=ui-builder /ui/dist /app/static

COPY app/            /app/app/
COPY sql/            /app/sql/
COPY supervisord.conf          /etc/supervisord.conf
COPY bootstrap.sh              /app/bootstrap.sh
COPY nginx.conf.http.template    /app/nginx.conf.http.template
COPY nginx.conf.https.template   /app/nginx.conf.https.template
COPY crontab                   /etc/crontabs/root
COPY provision-host.sh         /app/provision-host.sh

RUN chmod +x /app/bootstrap.sh

ENTRYPOINT ["/app/bootstrap.sh"]
