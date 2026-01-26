#!/bin/bash
set -e

echo ">>> Setting up CI Environment for: $(uname -a)"

if [ -f /etc/os-release ]; then
    . /etc/os-release
    ID=$ID
else
    ID=$(uname)
fi

echo ">>> Detected ID: $ID"

case $ID in
    "ubuntu"|"debian")
        export DEBIAN_FRONTEND=noninteractive
        apt-get update
        apt-get install -y build-essential cmake python3 python3-pip python3-dev
        ;;
    "fedora")
        dnf install -y gcc-c++ make cmake python3 python3-pip python3-devel
        ;;
    "alpine")
        apk update
        apk add build-base cmake python3 py3-pip python3-dev
        ;;
    "arch"|"archlinux")
        pacman -Syu --noconfirm base-devel cmake python python-pip
        ;;
    "Darwin")
        # macOS has python3 and clang by default on GHA runners.
        # Just ensure pip is ready.
        echo "macOS detected. Assuming build tools are present."
        ;;
    *)
        echo "Unknown distro: $ID. Trying generic fallback..."
        ;;
esac

echo ">>> Dependencies Installed."
python3 --version
cmake --version
