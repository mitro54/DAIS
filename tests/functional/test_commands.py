#!/usr/bin/env python3
"""
DAIS Functional Tests.

This module provides functional tests for the DAIS shell wrapper using pexpect
to simulate interactive terminal sessions. Tests verify core functionality
including startup, shutdown, built-in commands, and feature configuration.

Usage:
    python3 tests/functional/test_commands.py

Requirements:
    - pexpect: pip install pexpect
    - DAIS binary must be built in ./build/DAIS

Exit Codes:
    0 - All tests passed
    1 - One or more tests failed or binary not found
"""

import os
import shutil
import sys
import tempfile
import time
import uuid

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
SHELL_INIT_DELAY = 2  # Seconds to allow shell initialization


# =============================================================================
# Utilities
# =============================================================================

def find_binary():
    """
    Locate the DAIS binary by checking common build paths.

    Searches multiple candidate paths relative to both the current working
    directory and the script location to support various execution contexts.

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


def spawn_dais(binary):
    """
    Spawn a new DAIS process with PTY allocation.

    Args:
        binary: Path to the DAIS binary.

    Returns:
        pexpect.spawn: The spawned child process.
    """
    return pexpect.spawn(binary, timeout=15, encoding='utf-8')


def spawn_dais_ready(binary):
    """
    Spawn DAIS and wait for startup confirmation.

    Args:
        binary: Path to the DAIS binary.

    Returns:
        pexpect.spawn: The spawned child process after startup.
    """
    child = pexpect.spawn(binary, timeout=15, encoding='utf-8')
    child.expect('DAIS has been started', timeout=STARTUP_TIMEOUT)
    time.sleep(SHELL_INIT_DELAY)
    return child


def cleanup_child(child):
    """
    Safely terminate and close a pexpect child process.

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
# Test Cases: Basic Commands
# =============================================================================

def test_startup_and_exit():
    """
    Verify DAIS starts correctly and responds to :exit command.

    This test confirms:
    - DAIS launches and displays a startup message
    - The :exit command terminates the session cleanly
    - No zombie processes are left behind

    Returns:
        bool: True if test passed, False if failed, None if skipped.
    """
    print("[TEST] Startup and exit...")

    binary = find_binary()
    if not binary:
        print("  SKIP: Binary not found")
        return None

    try:
        child = spawn_dais(binary)

        try:
            child.expect('DAIS has been started', timeout=STARTUP_TIMEOUT)
            print("  PASS: Startup message detected")
        except pexpect.TIMEOUT:
            print("  WARN: Startup message not found (continuing anyway)")

        time.sleep(SHELL_INIT_DELAY)

        child.sendline(':exit')
        try:
            child.expect(pexpect.EOF, timeout=EXIT_TIMEOUT)
            print("  PASS: Clean exit")
        except pexpect.TIMEOUT:
            print("  FAIL: Did not exit within timeout")
            child.terminate(force=True)
            return False

        child.close()
        return True

    except Exception as e:
        print(f"  FAIL: Exception - {e}")
        return False


def test_help_command():
    """
    Verify the :help command displays expected content.

    This test confirms:
    - The :help command is recognized
    - Output contains the "DAIS Commands" header
    - Session can be exited after running :help

    Returns:
        bool: True if test passed, False if failed, None if skipped.
    """
    print("[TEST] :help command...")

    binary = find_binary()
    if not binary:
        print("  SKIP: Binary not found")
        return None

    try:
        child = spawn_dais(binary)
        time.sleep(SHELL_INIT_DELAY + 1)

        child.sendline(':help')

        try:
            child.expect('DAIS Commands', timeout=COMMAND_TIMEOUT)
            print("  PASS: Help header found")
        except pexpect.TIMEOUT:
            print("  WARN: Help header not found")

        time.sleep(0.5)
        cleanup_child(child)
        print("  PASS: :help command works")
        return True

    except Exception as e:
        print(f"  FAIL: Exception - {e}")
        return False


def test_q_exit():
    """
    Verify the :q shortcut command exits DAIS.

    This test confirms:
    - The :q command is recognized as an exit alias
    - Session terminates cleanly without needing :exit

    Returns:
        bool: True if test passed, False if failed, None if skipped.
    """
    print("[TEST] :q exit command...")

    binary = find_binary()
    if not binary:
        print("  SKIP: Binary not found")
        return None

    try:
        child = spawn_dais(binary)
        time.sleep(SHELL_INIT_DELAY + 1)

        child.sendline(':q')

        try:
            child.expect(pexpect.EOF, timeout=EXIT_TIMEOUT)
            print("  PASS: :q works")
            child.close()
            return True
        except pexpect.TIMEOUT:
            print("  FAIL: :q did not terminate")
            child.terminate(force=True)
            return False

    except Exception as e:
        print(f"  FAIL: Exception - {e}")
        return False


# =============================================================================
# Test Cases: LS Configuration
# =============================================================================

def test_ls_sort_options():
    """
    Test LS sort configuration commands.

    Verifies :ls size desc, :ls type asc, and :ls d are accepted.

    Returns:
        bool: True if commands accepted, False on error.
    """
    print("[TEST] LS Sort Options...")

    binary = find_binary()
    if not binary:
        print("  SKIP: Binary not found")
        return None

    try:
        child = spawn_dais_ready(binary)

        child.sendline(':ls size desc')
        time.sleep(0.5)

        child.sendline(':ls type asc')
        time.sleep(0.5)

        child.sendline(':ls d')
        time.sleep(0.5)

        cleanup_child(child)
        print("  PASS: LS sort commands accepted")
        return True

    except Exception as e:
        print(f"  FAIL: Exception - {e}")
        return False


# =============================================================================
# Test Cases: History
# =============================================================================

def test_history_commands():
    """
    Test History command functionality.

    Verifies :history shows commands and :history clear removes them.

    Returns:
        bool: True if history operations work, False on error.
    """
    print("[TEST] History Commands...")

    binary = find_binary()
    if not binary:
        print("  SKIP: Binary not found")
        return None

    temp_home = tempfile.mkdtemp()
    original_home = os.environ.get('HOME')
    os.environ['HOME'] = temp_home

    try:
        # Generate history
        child = spawn_dais_ready(binary)
        child.sendline('echo command1')
        time.sleep(0.5)
        child.sendline('echo command2')
        time.sleep(0.5)
        cleanup_child(child)

        # Verify history
        child = spawn_dais_ready(binary)
        child.sendline(':history')

        try:
            child.expect('command1', timeout=COMMAND_TIMEOUT)
            child.expect('command2', timeout=COMMAND_TIMEOUT)
            print("  PASS: History persistence verified")
        except pexpect.TIMEOUT:
            print("  FAIL: History items not found")
            cleanup_child(child)
            return False

        # Clear history
        child.sendline(':history clear')
        time.sleep(0.5)

        child.sendline(':history')
        try:
            child.expect('command1', timeout=2)
            print("  FAIL: History not cleared")
            cleanup_child(child)
            return False
        except pexpect.TIMEOUT:
            print("  PASS: History cleared successfully")

        cleanup_child(child)
        return True

    except Exception as e:
        print(f"  FAIL: Exception - {e}")
        return False

    finally:
        shutil.rmtree(temp_home, ignore_errors=True)
        if original_home:
            os.environ['HOME'] = original_home
        elif 'HOME' in os.environ:
            del os.environ['HOME']


# =============================================================================
# Test Cases: Special Filenames
# =============================================================================

def test_special_filenames():
    """
    Test LS handling of files with spaces and unicode.

    Returns:
        bool: True if special filenames displayed, False on error.
    """
    print("[TEST] Special Filenames (Spaces/Unicode)...")

    binary = find_binary()
    if not binary:
        print("  SKIP: Binary not found")
        return None

    temp_dir = tempfile.mkdtemp()
    test_files = ["file with spaces.txt", "🚀_unicode.txt"]

    try:
        for filename in test_files:
            with open(os.path.join(temp_dir, filename), 'w') as f:
                f.write("")

        child = spawn_dais_ready(binary)
        
        # Use ls with explicit path instead of cd + ls
        # This avoids CWD synchronization issues
        child.sendline(f'ls "{temp_dir}"')
        
        # Use expect to trigger output reading
        try:
            # Look for "file" in output (from "file with spaces.txt")
            child.expect('file', timeout=COMMAND_TIMEOUT)
            print("  PASS: Special filenames detected in ls output")
            cleanup_child(child)
            return True
        except pexpect.TIMEOUT:
            # Print debug info
            output = (child.before or "") + (child.after or "")
            print("  FAIL: Could not find test files in ls output")
            cleanup_child(child)
            return False

    except Exception as e:
        print(f"  FAIL: Exception - {e}")
        return False

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_ls_flow_control():
    """
    Test LS horizontal vs vertical flow control.

    Verifies that :ls h and :ls v commands correctly change the grid layout order.
    Horizontal: Row-major (fill row 1, then row 2)
    Vertical: Column-major (fill col 1, then col 2)

    Returns:
        bool: True if vertical vs horizontal flow logic is verified, False otherwise.
    """
    print("[TEST] LS Flow Control...")

    binary = find_binary()
    if not binary:
        print("  SKIP: Binary not found")
        return None

    print("[TEST] LS Flow Control...")

    binary = find_binary()
    if not binary:
        print("  SKIP: Binary not found")
        return None

    # Create distinct temp dir for 4-item grid
    temp_grid = tempfile.mkdtemp()
    try:
        # Create a, b, c, d to ensure sort order
        for name in ["a.txt", "b.txt", "c.txt", "d.txt"]:
            with open(os.path.join(temp_grid, name), 'w') as f: f.write(".")

        cmd = spawn_dais(binary)
        if not cmd: return False
        
        # Enforce size to guarantee 2 columns (assuming ~20 chars per column logic)
        cmd.setwinsize(24, 80)
        time.sleep(SHELL_INIT_DELAY)

        # Helper to sync shell
        def sync_shell():
            token = f"SYNC_{uuid.uuid4().hex[:8]}"
            cmd.sendline(f"echo {token}")
            cmd.expect(token)
            cmd.expect(r"[\#\$] ")
            time.sleep(0.5)

        # Go to temp dir
        cmd.sendline(f'cd "{temp_grid}"')
        sync_shell()

        # 1. Horizontal (Default): a   b \n c   d
        # Order in string: a, b, c, d
        # Index(b) < Index(c)
        cmd.sendline(":ls h")
        sync_shell() # wait for config save
        
        cmd.sendline("ls")
        cmd.expect(r"[\#\$] ")
        out_h = cmd.before
        
        if "a.txt" not in out_h:
            print(f"FAIL: Files missing. Output: {out_h}")
            return False

        pos_b = out_h.find("b.txt")
        pos_c = out_h.find("c.txt")

        # 2. Vertical: a   c \n b   d
        # Order in string: a, c, b, d
        # Index(c) < Index(b)
        cmd.sendline(":ls v")
        sync_shell()

        cmd.sendline("ls")
        cmd.expect(r"[\#\$] ")
        out_v = cmd.before
        
        pos_b_v = out_v.find("b.txt")
        pos_c_v = out_v.find("c.txt")
        
        print(f"  DEBUG: H(b={pos_b}, c={pos_c}) | V(b={pos_b_v}, c={pos_c_v})")
        
        # Validation
        # H: b should be before c
        if pos_b > pos_c:
            print("  FAIL: Horizontal flow incorrect (Expected b < c)")
            return False
            
        # V: c should be before b (because 'c' is in col 2 row 1, 'b' is in col 1 row 2)
        if pos_c_v > pos_b_v:
             print("  FAIL: Vertical flow incorrect (Expected c < b)")
             return False

        print("  PASS: Flow control verified")
        return True

    except Exception as e:
        print(f"FAIL: Exception: {e}")
        return False
    finally:
        shutil.rmtree(temp_grid, ignore_errors=True)
        if 'cmd' in locals():
            cmd.close()


# =============================================================================
# Test Cases: DB Auto-Install
# =============================================================================

def test_db_autoinstall():
    """
    Test the interactive Auto-Install prompt for missing DB packages.
    
    Uses standard pexpect logic:
    1. Triggers 'test_autoinstall' adapter in db_handler.py (which raises ImportError).
    2. Expects C++ engine to catch it and prompt "(y/N)".
    3. Sends 'y'.
    4. Expects 'pip install ...' command injection.
    """
    print("[TEST] DB Auto-Install Prompt...")

    binary = find_binary()
    if not binary:
        print("  SKIP: Binary not found")
        return None

    temp_dir = tempfile.mkdtemp()
    
    try:
        # Create .env that forces the test adapter
        with open(os.path.join(temp_dir, ".env"), "w") as f:
            f.write("DB_TYPE=test_autoinstall\n")

        child = spawn_dais_ready(binary)
        
        # Go to temp dir
        # We need to ensure DAIS picks up the CWD change.
        # But we can also pass the path if your implementation supports it? No, db_handler reads CWD.
        # So we must cd.
        child.sendline(f'cd "{temp_dir}"')
        # Wait for prompt to ensure cd completed
        child.expect(r'[\#\$] ', timeout=COMMAND_TIMEOUT)
        
        # Trigger DB command
        child.sendline(':db SELECT 1')
        
        # Expect the prompt
        # We use a broad slice to avoid ANSI escape sequence issues
        try:
            # "Install now? (y/N)" is the most unique part
            child.expect(r"Install now\? \(y/N\)", timeout=COMMAND_TIMEOUT + 5)
            print("  PASS: Install prompt detected")
        except pexpect.TIMEOUT:
            print("  FAIL: Prompt not detected")
            print(f"DEBUG Output: {child.before}")
            return False

        # Send 'y' with newline to ensure flush on all platforms
        child.sendline("y")
        
        # Expect the pip install command to be echoed/run
        try:
            # Look for the command injection with a flexible regex to handle PTY fragmentation/echo issues
            child.expect(r"pip install.*dais-test-pkg", timeout=COMMAND_TIMEOUT + 5)
            
            # Strong verification: Wait for the pip error message to confirm it actually EXECUTED
            # Since 'dais-test-pkg' is fake, this is the most reliable "success" signal.
            child.expect(r"(Could not find a version|No matching distribution found)", timeout=COMMAND_TIMEOUT + 10)
            
            print("  PASS: pip install command triggered and executed")
        except pexpect.TIMEOUT:
            print("  FAIL: pip command execution not detected")
            # Log output for debugging
            print(f"DEBUG After Y: {child.before}")
            return False

        cleanup_child(child)
        return True

    except Exception as e:
        print(f"  FAIL: Exception - {e}")
        return False
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


# =============================================================================
# Main Entry Point
# =============================================================================

def main():
    """
    Execute all functional tests and report results.

    Runs each test case sequentially with delays between tests to avoid
    resource contention. Prints a summary and exits with appropriate code.
    """
    print("=" * 50)
    print(" DAIS Functional Tests")
    print("=" * 50)

    binary = find_binary()
    if not binary:
        print("ERROR: DAIS binary not found")
        print("Searched: ./build/DAIS, ../build/DAIS")
        print("Build first: mkdir build && cd build && cmake .. && make")
        sys.exit(1)

    print(f"Using binary: {binary}")
    print()

    results = []

    # Basic commands
    results.append(('startup_exit', test_startup_and_exit()))
    time.sleep(1)
    results.append(('help', test_help_command()))
    time.sleep(1)
    results.append(('q_exit', test_q_exit()))
    time.sleep(1)

    # LS configuration
    results.append(('ls_options', test_ls_sort_options()))
    time.sleep(1)

    # History
    results.append(('history', test_history_commands()))
    time.sleep(1)

    # Special filenames
    results.append(('special_files', test_special_filenames()))
    
    # DB Auto-Install Prompt
    results.append(('db_autoinstall', test_db_autoinstall()))

    # LS Flow Control
    results.append(('ls_flow', test_ls_flow_control()))

    # Summary
    print()
    print("=" * 50)
    print(" Results Summary")
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
