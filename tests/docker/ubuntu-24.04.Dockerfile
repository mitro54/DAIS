# Ubuntu 24.04 LTS Build Environment for DAIS
FROM ubuntu:24.04

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install build dependencies (matching README instructions) + pip for tests
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    python3-dev \
    python3-pip \
    git \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy project files
COPY . .

# Build DAIS
RUN mkdir -p build && cd build && cmake .. && make

# Default command: run tests
CMD ["./tests/test_build.sh"]
