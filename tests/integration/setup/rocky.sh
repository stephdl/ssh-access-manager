# shellcheck shell=bash
# Install the prerequisites needed by provision-host.sh on Rocky / RHEL family.
set -e

dnf install -y --setopt=install_weak_deps=False \
    sudo \
    openssh-server \
    openssh-clients \
    shadow-utils \
    openssl \
    util-linux \
    which \
    diffutils \
    findutils \
    grep \
    procps-ng \
    python3 \
    >/dev/null

# `sshd -t` needs the host keys to exist before it will validate the config.
ssh-keygen -A >/dev/null 2>&1 || true
