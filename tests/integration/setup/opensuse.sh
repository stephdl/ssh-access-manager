# shellcheck shell=bash
# Install the prerequisites needed by provision-host.sh on openSUSE
# (Leap and Tumbleweed).
set -e

zypper --non-interactive install --no-recommends \
    sudo \
    openssh \
    shadow \
    openssl \
    util-linux \
    diffutils \
    findutils \
    grep \
    procps \
    python3 \
    >/dev/null

# `sshd -t` needs the host keys to exist before it will validate the config.
ssh-keygen -A >/dev/null 2>&1 || true
