# Ubuntu 24.04 LTS Build Environment for DAIS
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# Install build dependencies + pip for tests + shells for multi-shell testing
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    python3-dev \
    python3-pip \
    git \
    zsh \
    fish \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .
RUN mkdir -p build && cd build && cmake .. && make

CMD ["./tests/test_build.sh"]
