# shellcheck shell=bash
# Install the prerequisites needed by provision-host.sh on Arch Linux.
# The base archlinux image ships with `pacman` and `bash` but most user-space
# tools (sudo, ssh, shadow) are not preinstalled.
set -e

# Refresh package databases without doing a full system upgrade (faster and
# more deterministic in CI).
pacman -Sy --noconfirm --noprogressbar >/dev/null 2>&1

pacman -S --noconfirm --noprogressbar --needed \
    sudo \
    openssh \
    shadow \
    openssl \
    util-linux \
    diffutils \
    findutils \
    grep \
    procps-ng \
    >/dev/null 2>&1

# `sshd -t` needs the host keys to exist before it will validate the config.
ssh-keygen -A >/dev/null 2>&1 || true
