#!/bin/bash
set -e

# Directory where scripts and sources are located
SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
SRC_FILE="$SCRIPT_DIR/agent.cpp"
OUT_DIR="$SCRIPT_DIR/../../build/agents"
HEADER_OUT="$SCRIPT_DIR/../../include/core/dais_agents.hpp"

mkdir -p "$OUT_DIR"

echo "[DAIS] Building Remote Agents..."

# 1. Try Docker Build (Preferred for Cross-Compilation)
if command -v docker >/dev/null 2>&1; then
    echo "  [Docker] Building agents via Docker container..."
    
    # Run from project root
    PROJECT_ROOT="$SCRIPT_DIR/../.."
    pushd "$PROJECT_ROOT" >/dev/null

    # Build builder image
    # We suppress output unless it fails
    if docker build --no-cache -f src/remote/Dockerfile.agents -t dais-agents-builder . >/dev/null; then
        # Create temp container to extract binaries
        CONT_ID=$(docker create dais-agents-builder)
        
        # Copy binaries out
        docker cp "$CONT_ID:/build/agent_x86_64" "$OUT_DIR/" 2>/dev/null || echo "    Failed to extract x86_64"
        docker cp "$CONT_ID:/build/agent_aarch64" "$OUT_DIR/" 2>/dev/null || echo "    Failed to extract aarch64"
        docker cp "$CONT_ID:/build/agent_armv7" "$OUT_DIR/" 2>/dev/null || echo "    Failed to extract armv7"
        
        docker rm "$CONT_ID" >/dev/null
        
        echo "  [Docker] Success."
        popd >/dev/null
        goto_generate=true
    else
        echo "  [Docker] Build failed. Falling back to local tools."
        popd >/dev/null
    fi
fi

if [ "$goto_generate" != "true" ]; then
    echo "  [Local] Attempting local compilation..."
    
    # 2. Host Build (x86_64 usually)
    if command -v g++ >/dev/null 2>&1; then
        echo "  [x86_64] Compiling..."
        
        # MacOS (Darwin) does not support -static easily (crt0.o missing)
        # Linux usually supports it if glibc-static is installed
        STATIC_FLAG="-static"
        if [ "$(uname)" = "Darwin" ]; then
            echo "    [Notice] MacOS detected: Disabling -static linking"
            STATIC_FLAG=""
        fi

        g++ -std=c++20 $STATIC_FLAG -O3 -I"$SCRIPT_DIR/../../include" "$SRC_FILE" -o "$OUT_DIR/agent_x86_64"
    else
        echo "  [x86_64] g++ not found! Skipping."
    fi

    # 3. AArch64 (ARM64)
    if command -v aarch64-linux-gnu-g++ >/dev/null 2>&1; then
        echo "  [aarch64] Compiling..."
        aarch64-linux-gnu-g++ -std=c++20 -static -O3 -I"$SCRIPT_DIR/../../include" "$SRC_FILE" -o "$OUT_DIR/agent_aarch64"
    else
        echo "  [aarch64] Cross-compiler not found. Skipping."
    fi

    # 4. ARMv7 (RPi 3/4 32-bit)
    if command -v arm-linux-gnueabihf-g++ >/dev/null 2>&1; then
        echo "  [armv7l] Compiling..."
        arm-linux-gnueabihf-g++ -std=c++20 -static -O3 -I"$SCRIPT_DIR/../../include" "$SRC_FILE" -o "$OUT_DIR/agent_armv7"
    else
        echo "  [armv7l] Cross-compiler not found. Skipping."
    fi
fi

# 4. Generate Header
echo "[DAIS] Generating Header ($HEADER_OUT)..."
python3 "$SCRIPT_DIR/generate_header.py" "$OUT_DIR" "$HEADER_OUT"

echo "[DAIS] Agent build complete."
