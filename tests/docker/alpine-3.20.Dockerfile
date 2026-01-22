# Alpine 3.20 Build Environment for DAIS
FROM alpine:3.20

# Install build dependencies + pip + shells for multi-shell testing
RUN apk add --no-cache \
    build-base \
    cmake \
    python3-dev \
    py3-pip \
    git \
    bash \
    zsh \
    fish

WORKDIR /app
COPY . .
RUN mkdir -p build && cd build && cmake .. && make

CMD ["./tests/test_build.sh"]
