# shellcheck shell=bash
# Install the prerequisites needed by provision-host.sh on Debian / Ubuntu family.
set -e

export DEBIAN_FRONTEND=noninteractive

apt-get update -qq
apt-get install -y --no-install-recommends \
    sudo \
    openssh-server \
    openssh-client \
    passwd \
    openssl \
    util-linux \
    diffutils \
    findutils \
    grep \
    procps \
    python3 \
    >/dev/null

# Debian's openssh-server postinst usually generates host keys; force in case
# the container image stripped them.
ssh-keygen -A >/dev/null 2>&1 || true
