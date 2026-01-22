# Arch Linux Build Environment for DAIS
FROM archlinux:latest

# Update and install build dependencies (matching README instructions) + pip for tests
RUN pacman -Sy --noconfirm \
    base-devel \
    cmake \
    python \
    python-pip \
    git \
    && pacman -Scc --noconfirm

# Set working directory
WORKDIR /app

# Copy project files
COPY . .

# Build DAIS
RUN mkdir -p build && cd build && cmake .. && make

# Default command: run tests
CMD ["./tests/test_build.sh"]
