# Arch Linux Build Environment for DAIS
FROM archlinux:latest

# Install build dependencies + pip + shells for multi-shell testing
RUN pacman -Sy --noconfirm \
    base-devel \
    cmake \
    python \
    python-pip \
    git \
    zsh \
    fish \
    && pacman -Scc --noconfirm

WORKDIR /app
COPY . .
RUN mkdir -p build && cd build && cmake .. && make

CMD ["./tests/test_build.sh"]
