# Alpine 3.20 Build Environment for DAIS
FROM alpine:3.20

# Install build dependencies (matching README instructions) + pip for tests
RUN apk add --no-cache \
    build-base \
    cmake \
    python3-dev \
    py3-pip \
    git \
    bash

# Set working directory
WORKDIR /app

# Copy project files
COPY . .

# Build DAIS
RUN mkdir -p build && cd build && cmake .. && make

# Default command: run tests
CMD ["./tests/test_build.sh"]
