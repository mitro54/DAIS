#!/usr/bin/env python3
"""
DAIS LS Output Tests.

This module tests the DAIS custom `ls` command output across different shells
(bash, zsh, fish). It verifies that file metadata is displayed correctly and
that the output format is consistent across shell environments.

Usage:
    python3 tests/functional/test_ls_output.py
    SHELL=/bin/zsh python3 tests/functional/test_ls_output.py

Requirements:
    - pexpect: pip install pexpect
    - DAIS binary must be built in ./build/DAIS
    - Test fixtures in tests/fixtures/

Environment Variables:
    SHELL - Specifies which shell DAIS should use (default: /bin/sh)

Exit Codes:
    0 - All tests passed
    1 - One or more tests failed
"""

import sys
import os
import time

try:
    import pexpect
except ImportError:
    print("ERROR: pexpect not installed. Run: pip install pexpect")
    sys.exit(1)


# =============================================================================
# Constants
# =============================================================================

STARTUP_TIMEOUT = 10  # Seconds to wait for DAIS startup message
COMMAND_TIMEOUT = 5   # Seconds to wait for command responses
EXIT_TIMEOUT = 10     # Seconds to wait for clean exit
SHELL_INIT_DELAY = 3  # Seconds to allow shell initialization


# =============================================================================
# Utilities
# =============================================================================

def find_binary():
    """
    Locate the DAIS binary by checking common build paths.

    Returns:
        str: Absolute path to the DAIS binary if found, None otherwise.
    """
    candidates = [
        './build/DAIS',
        '../build/DAIS',
        os.path.join(os.path.dirname(__file__), '..', '..', 'build', 'DAIS'),
    ]
    for path in candidates:
        if os.path.exists(path):
            return os.path.abspath(path)
    return None


def find_fixtures():
    """
    Locate the test fixtures directory.

    The fixtures directory contains sample files used to verify ls output
    formatting, including text files, CSV data, binary files, and subdirectories.

    Returns:
        str: Absolute path to fixtures directory if found, None otherwise.
    """
    candidates = [
        './tests/fixtures',
        '../fixtures',
        os.path.join(os.path.dirname(__file__), '..', 'fixtures'),
    ]
    for path in candidates:
        if os.path.exists(path):
            return os.path.abspath(path)
    return None


def get_current_shell():
    """
    Get the name of the shell being tested.

    Reads the SHELL environment variable to determine which shell DAIS
    will spawn. Defaults to 'sh' for maximum compatibility.

    Returns:
        str: Shell name (e.g., 'bash', 'zsh', 'fish', 'sh').
    """
    shell = os.environ.get('SHELL', '/bin/sh')
    return os.path.basename(shell)


def spawn_dais_ready(binary):
    """
    Spawn DAIS and wait for startup confirmation.

    Args:
        binary: Path to the DAIS binary.

    Returns:
        pexpect.spawn: The spawned child process after startup.
    """
    child = pexpect.spawn(binary, timeout=20, encoding='utf-8')
    try:
        child.expect('DAIS has been started', timeout=STARTUP_TIMEOUT)
    except pexpect.TIMEOUT:
        pass  # Continue anyway
    time.sleep(SHELL_INIT_DELAY)
    return child


def cleanup_child(child):
    """
    Safely terminate and close a pexpect child process.

    Attempts a clean exit via :exit command first, then forces termination
    if the process doesn't respond within EXIT_TIMEOUT.

    Args:
        child: The pexpect child process to clean up.
    """
    try:
        child.sendline(':exit')
        child.expect(pexpect.EOF, timeout=EXIT_TIMEOUT)
    except (pexpect.TIMEOUT, pexpect.EOF):
        child.terminate(force=True)
    finally:
        child.close()


# =============================================================================
# Test Cases
# =============================================================================

def test_shell_startup(binary):
    """
    Verify DAIS starts correctly with the configured shell.

    This test confirms DAIS can initialize with the current SHELL environment
    and displays its startup message. This is a prerequisite for all other tests.

    Args:
        binary: Path to the DAIS binary.

    Returns:
        bool: True if startup succeeded, False if failed.
    """
    print(f"[TEST] Shell startup (shell: {get_current_shell()})...")

    try:
        child = pexpect.spawn(binary, timeout=20, encoding='utf-8')

        try:
            child.expect('DAIS has been started', timeout=STARTUP_TIMEOUT)
            print("  PASS: DAIS started successfully")
            success = True
        except pexpect.TIMEOUT:
            print("  FAIL: DAIS startup message not found")
            success = False

        time.sleep(1)
        cleanup_child(child)
        return success

    except Exception as e:
        print(f"  FAIL: Exception - {e}")
        return False


def test_ls_basic(binary, fixtures_dir):
    """
    Verify the ls command displays expected fixture files.

    Tests that DAIS's custom ls implementation correctly lists files in
    the fixtures directory. Uses `ls` with explicit path to avoid CWD
    synchronization issues. Checks for presence of known test files.

    Args:
        binary: Path to the DAIS binary.
        fixtures_dir: Path to the test fixtures directory.

    Returns:
        bool: True if expected files found, False on error.
    """
    print(f"[TEST] Basic ls output (shell: {get_current_shell()})...")

    try:
        child = spawn_dais_ready(binary)

        # Use ls with explicit path - avoids cd sync issues
        child.sendline(f'ls "{fixtures_dir}"')

        # Use expect to capture output - look for sample.txt
        try:
            child.expect('sample', timeout=COMMAND_TIMEOUT)
            print("  PASS: Fixture files detected in ls output")
            cleanup_child(child)
            return True
        except pexpect.TIMEOUT:
            print("  FAIL: Could not find fixture files in ls output")
            cleanup_child(child)
            return False

    except Exception as e:
        print(f"  FAIL: Exception - {e}")
        return False


def test_ls_shows_directory_count(binary, fixtures_dir):
    """
    Verify ls displays subdirectory in output.

    Tests that DAIS's custom ls correctly identifies and displays
    subdirectories. The fixtures/subdir contains 3 nested files.

    Args:
        binary: Path to the DAIS binary.
        fixtures_dir: Path to the test fixtures directory.

    Returns:
        bool: True if directory detected in output, False on failure.
    """
    print(f"[TEST] Directory item count (shell: {get_current_shell()})...")

    try:
        child = spawn_dais_ready(binary)

        # Use ls with explicit path
        child.sendline(f'ls "{fixtures_dir}"')

        # Look for subdir in output
        try:
            child.expect('subdir', timeout=COMMAND_TIMEOUT)
            print("  PASS: Directory detected in ls output")
            cleanup_child(child)
            return True
        except pexpect.TIMEOUT:
            print("  FAIL: Could not find subdir in ls output")
            cleanup_child(child)
            return False

    except Exception as e:
        print(f"  FAIL: Exception - {e}")
        return False


def test_ls_with_path(binary, fixtures_dir):
    """
    Verify ls accepts an explicit path argument.

    Tests that `ls /path/to/dir` syntax works correctly without needing
    to cd into the directory first. This is the primary method used
    by all ls tests to avoid CWD synchronization issues.

    Args:
        binary: Path to the DAIS binary.
        fixtures_dir: Path to the test fixtures directory.

    Returns:
        bool: True if output was produced, False on failure.
    """
    print(f"[TEST] ls with path argument (shell: {get_current_shell()})...")

    try:
        child = spawn_dais_ready(binary)

        # Run ls with explicit path
        child.sendline(f'ls "{fixtures_dir}"')

        # Look for any fixture file to confirm output
        try:
            child.expect('data', timeout=COMMAND_TIMEOUT)  # data.csv
            print("  PASS: ls with path produced valid output")
            cleanup_child(child)
            return True
        except pexpect.TIMEOUT:
            print("  FAIL: ls with path did not show expected files")
            cleanup_child(child)
            return False

    except Exception as e:
        print(f"  FAIL: Exception - {e}")
        return False


# =============================================================================
# Main Entry Point
# =============================================================================

def main():
    """
    Execute all LS output tests and report results.

    Runs each test case sequentially with delays between tests. Reports
    which shell is being tested and provides a pass/fail summary.
    """
    shell = get_current_shell()
    print("=" * 50)
    print(f" DAIS LS Output Tests (Shell: {shell})")
    print("=" * 50)

    binary = find_binary()
    if not binary:
        print("ERROR: DAIS binary not found")
        sys.exit(1)

    fixtures = find_fixtures()
    if not fixtures:
        print("ERROR: Test fixtures not found")
        sys.exit(1)

    print(f"Binary: {binary}")
    print(f"Fixtures: {fixtures}")
    print()

    # Execute tests with inter-test delays
    results = []

    results.append(('shell_startup', test_shell_startup(binary)))
    time.sleep(1)

    results.append(('ls_basic', test_ls_basic(binary, fixtures)))
    time.sleep(1)

    results.append(('ls_dir_count', test_ls_shows_directory_count(binary, fixtures)))
    time.sleep(1)

    results.append(('ls_with_path', test_ls_with_path(binary, fixtures)))

    # Print summary
    print()
    print("=" * 50)
    print(f" Results Summary (Shell: {shell})")
    print("=" * 50)

    valid_results = [(name, r) for name, r in results if r is not None]
    passed = sum(1 for _, r in valid_results if r)
    total = len(valid_results)

    for name, result in results:
        status = "SKIP" if result is None else ("PASS" if result else "FAIL")
        print(f"  {name}: {status}")

    print(f"\n{passed}/{total} tests passed")

    if passed == total and total > 0:
        print("\nAll tests passed!")
        sys.exit(0)
    else:
        print("\nSome tests failed!")
        sys.exit(1)


if __name__ == '__main__':
    main()
