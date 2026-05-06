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

RUN apk update && apk add --no-cache \
    postgresql18 \
    postgresql18-client \
    python3 \
    py3-pip \
    py3-setuptools \
    supervisor \
    nginx \
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
COPY nginx.conf.template       /app/nginx.conf.template
COPY crontab                   /etc/crontabs/root
COPY provision-host.sh         /app/provision-host.sh

RUN chmod +x /app/bootstrap.sh

ENTRYPOINT ["/app/bootstrap.sh"]
