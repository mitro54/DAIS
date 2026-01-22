#!/bin/bash
# =============================================================================
# DAIS Code Coverage Report Generator
# =============================================================================
# Generates an HTML coverage report using lcov/gcov.
#
# Prerequisites:
#   - Build DAIS with: cmake -DENABLE_COVERAGE=ON .. && make
#   - Run tests to generate .gcda files
#   - lcov must be installed
#
# Usage:
#   ./scripts/generate_coverage.sh
#
# Output:
#   coverage/           - HTML report directory
#   coverage/index.html - Main report entry point
# =============================================================================

set -e

# Configuration
BUILD_DIR="${1:-build}"
OUTPUT_DIR="coverage"
LCOV_FILE="coverage.info"

echo "============================================"
echo " DAIS Code Coverage Report Generator"
echo "============================================"

# Check prerequisites
if ! command -v lcov &> /dev/null; then
    echo "ERROR: lcov not installed. Install with:"
    echo "  Ubuntu/Debian: sudo apt install lcov"
    echo "  Fedora: sudo dnf install lcov"
    echo "  Arch: sudo pacman -S lcov"
    exit 1
fi

if [ ! -d "$BUILD_DIR" ]; then
    echo "ERROR: Build directory '$BUILD_DIR' not found"
    echo "Build with: cmake -DENABLE_COVERAGE=ON .. && make"
    exit 1
fi

# Check for .gcda files (generated after running tests)
GCDA_COUNT=$(find "$BUILD_DIR" -name "*.gcda" 2>/dev/null | wc -l)
if [ "$GCDA_COUNT" -eq 0 ]; then
    echo "WARNING: No .gcda files found. Run tests first to generate coverage data."
    echo "Proceeding anyway (will show 0% coverage)..."
fi

echo "Step 1: Capturing coverage data..."
# Note on --ignore-errors flags:
#   mismatch: Template-heavy C++ (pybind11) causes line/block mismatches - expected
#   negative: Race conditions in coverage counters (mitigated by -fprofile-update=atomic)
#   gcov: Unexecuted blocks in templated code - cosmetic warning only
lcov --capture \
    --directory "$BUILD_DIR" \
    --output-file "$LCOV_FILE" \
    --ignore-errors mismatch,mismatch \
    --ignore-errors negative,negative \
    --ignore-errors gcov,gcov \
    --rc branch_coverage=1 \
    --rc geninfo_unexecuted_blocks=1

echo "Step 2: Removing external library coverage..."
lcov --remove "$LCOV_FILE" \
    '/usr/*' \
    '*/pybind11/*' \
    '*/build/_deps/*' \
    --output-file "$LCOV_FILE" \
    --ignore-errors unused,unused \
    --ignore-errors mismatch,mismatch \
    --rc branch_coverage=1

echo "Step 3: Generating HTML report..."
rm -rf "$OUTPUT_DIR"
genhtml "$LCOV_FILE" \
    --output-directory "$OUTPUT_DIR" \
    --title "DAIS Code Coverage" \
    --legend \
    --branch-coverage \
    --ignore-errors mismatch,mismatch \
    --rc branch_coverage=1

echo ""
echo "============================================"
echo " Coverage Report Generated!"
echo "============================================"
echo "Report: $OUTPUT_DIR/index.html"
echo ""

# Print summary
lcov --summary "$LCOV_FILE" --rc branch_coverage=1 2>&1 | tail -5

echo ""
echo "Open the report with: open $OUTPUT_DIR/index.html"
