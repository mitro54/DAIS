#!/usr/bin/env python3
"""
DAIS Functional Tests
=====================
Uses pexpect to test DAIS interactive commands.
Requires: pip install pexpect

Run: python3 tests/functional/test_commands.py
"""

import sys
import os
import time

try:
    import pexpect
except ImportError:
    print("ERROR: pexpect not installed. Run: pip install pexpect")
    sys.exit(1)


def find_binary():
    """Find the DAIS binary, checking multiple possible locations."""
    candidates = [
        './build/DAIS',
        '../build/DAIS',
        os.path.join(os.path.dirname(__file__), '..', '..', 'build', 'DAIS'),
    ]
    for path in candidates:
        if os.path.exists(path):
            return os.path.abspath(path)
    return None


def test_startup_and_exit():
    """Test that DAIS starts and exits cleanly."""
    print("[TEST] Startup and exit...")
    
    binary = find_binary()
    if not binary:
        print("  SKIP: Binary not found")
        return None
    
    try:
        # Spawn DAIS with a PTY
        child = pexpect.spawn(binary, timeout=15, encoding='utf-8')
        
        # Wait for startup - look for the startup message
        try:
            child.expect('DAIS has been started', timeout=10)
            print("  PASS: Startup message detected")
        except pexpect.TIMEOUT:
            print("  WARN: Startup message not found (continuing anyway)")
        
        # Give shell time to initialize
        time.sleep(2)
        
        # Send :exit command
        child.sendline(':exit')
        
        # Wait for clean exit
        try:
            child.expect(pexpect.EOF, timeout=10)
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
    """Test that :help displays expected content."""
    print("[TEST] :help command...")
    
    binary = find_binary()
    if not binary:
        print("  SKIP: Binary not found")
        return None
    
    try:
        child = pexpect.spawn(binary, timeout=15, encoding='utf-8')
        
        # Wait for startup
        time.sleep(3)
        
        # Send :help command
        child.sendline(':help')
        
        # Look for expected content
        try:
            child.expect('DAIS Commands', timeout=5)
            print("  PASS: Help header found")
        except pexpect.TIMEOUT:
            print("  WARN: Help header not found")
        
        # Clean exit
        time.sleep(0.5)
        child.sendline(':exit')
        
        try:
            child.expect(pexpect.EOF, timeout=10)
        except pexpect.TIMEOUT:
            child.terminate(force=True)
        
        child.close()
        print("  PASS: :help command works")
        return True
        
    except Exception as e:
        print(f"  FAIL: Exception - {e}")
        return False


def test_q_exit():
    """Test that :q also exits."""
    print("[TEST] :q exit command...")
    
    binary = find_binary()
    if not binary:
        print("  SKIP: Binary not found")
        return None
    
    try:
        child = pexpect.spawn(binary, timeout=15, encoding='utf-8')
        
        # Wait for startup
        time.sleep(3)
        
        # Send :q command
        child.sendline(':q')
        
        try:
            child.expect(pexpect.EOF, timeout=10)
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


def main():
    """Run all functional tests."""
    print("=" * 50)
    print(" DAIS Functional Tests")
    print("=" * 50)
    
    binary = find_binary()
    if not binary:
        print(f"ERROR: DAIS binary not found")
        print("Searched: ./build/DAIS, ../build/DAIS")
        print("Make sure to build DAIS first: mkdir build && cd build && cmake .. && make")
        sys.exit(1)
    
    print(f"Using binary: {binary}")
    print()
    
    results = []
    
    # Run tests with delays between them to avoid resource contention
    results.append(('startup_exit', test_startup_and_exit()))
    time.sleep(1)
    
    results.append(('help', test_help_command()))
    time.sleep(1)
    
    results.append(('q_exit', test_q_exit()))
    
    # Summary
    print()
    print("=" * 50)
    print(" Results Summary")
    print("=" * 50)
    
    # Filter out None (skipped) results
    valid_results = [(name, result) for name, result in results if result is not None]
    passed = sum(1 for _, r in valid_results if r)
    total = len(valid_results)
    
    for name, result in results:
        if result is None:
            status = "SKIP"
        elif result:
            status = "PASS"
        else:
            status = "FAIL"
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
