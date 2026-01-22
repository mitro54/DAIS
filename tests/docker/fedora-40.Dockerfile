# Fedora 40 Build Environment for DAIS
FROM fedora:40

# Install build dependencies + shells for multi-shell testing
RUN dnf install -y \
    gcc-c++ \
    cmake \
    make \
    python3-devel \
    python3-pip \
    git \
    zsh \
    fish \
    && dnf clean all

WORKDIR /app
COPY . .
RUN mkdir -p build && cd build && cmake .. && make

CMD ["./tests/test_build.sh"]
