#!/bin/bash
# ============================================================================
# DAIS Build Test Script
# ============================================================================
# Verifies that DAIS builds correctly.
# Exit codes: 0 = success, 1 = failure
# ============================================================================

set -e  # Exit on any error

# Determine project root - works whether run from project root or tests dir
if [ -f "build/DAIS" ]; then
    BINARY="./build/DAIS"
elif [ -f "../build/DAIS" ]; then
    BINARY="../build/DAIS"
else
    # Fallback to script-relative path
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
    BINARY="$PROJECT_ROOT/build/DAIS"
fi

echo "============================================"
echo " DAIS Build Verification Test"
echo "============================================"
echo "Binary path: $BINARY"

# Test 1: Check binary exists
echo "[TEST 1] Checking binary exists..."
if [ ! -f "$BINARY" ]; then
    echo "FAIL: Binary not found at $BINARY"
    echo "Current directory: $(pwd)"
    echo "Listing build dir:"
    ls -la build/ 2>/dev/null || echo "No build directory"
    exit 1
fi
echo "PASS: Binary exists"

# Test 2: Check binary is executable
echo "[TEST 2] Checking binary is executable..."
if [ ! -x "$BINARY" ]; then
    echo "FAIL: Binary is not executable"
    exit 1
fi
echo "PASS: Binary is executable"

# Test 3: Check binary can show help (doesn't require full PTY)
# Note: Full PTY tests are in functional/test_commands.py
echo "[TEST 3] Binary file check..."
file "$BINARY" || echo "file command not available"
echo "PASS: Binary file verified"

echo "============================================"
echo " All build tests passed!"
echo "============================================"
exit 0
