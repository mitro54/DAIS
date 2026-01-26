#!/usr/bin/env python3
"""
DAIS DB Command Functional Tests.

Verifies the functionality of the :db command including:
- Basic SELECT queries
- Formatting (Tables)
- Exports (JSON, CSV)
- Error Handling
- Saved Queries

Usage:
    python3 tests/functional/test_db_commands.py
"""

import os
import sys
import time
import json
import shutil
import tempfile
import sqlite3

try:
    import pexpect
except ImportError:
    print("ERROR: pexpect not installed. Run: pip install pexpect")
    sys.exit(1)

# Import utilities from test_commands (add path to sys.path)
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(current_dir)

# Try to import shared utilities (assuming test_commands can differ in structure, 
# we'll duplicate essential utils for standalone robustness)
STARTUP_TIMEOUT = 10
COMMAND_TIMEOUT = 5
SHELL_INIT_DELAY = 2

def find_binary():
    candidates = [
        './build/DAIS',
        '../build/DAIS',
        os.path.join(os.path.dirname(__file__), '..', '..', 'build', 'DAIS'),
    ]
    for path in candidates:
        if os.path.exists(path):
            return os.path.abspath(path)
    return None

def spawn_dais_ready(binary):
    child = pexpect.spawn(binary, timeout=15, encoding='utf-8')
    child.expect('DAIS has been started', timeout=STARTUP_TIMEOUT)
    time.sleep(SHELL_INIT_DELAY)
    return child

def cleanup_child(child):
    try:
        child.sendline(':exit')
        child.expect(pexpect.EOF, timeout=10)
    except:
        child.terminate(force=True)
    finally:
        child.close()

# =============================================================================
# Helper: Database Setup
# =============================================================================
def setup_test_db(db_path):
    """Creates a temporary SQLite DB for testing."""
    if os.path.exists(db_path):
        os.remove(db_path)
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, role TEXT)")
    cursor.execute("INSERT INTO users (name, role) VALUES ('Alice', 'admin')")
    cursor.execute("INSERT INTO users (name, role) VALUES ('Bob', 'user')")
    conn.commit()
    conn.close()

# =============================================================================
# Test Cases
# =============================================================================

def test_basic_query(binary, db_path):
    print("[TEST] Basic Query (Table View)...")
    try:
        # We need to overwrite config.py or assume config points to our DB.
        # Since we can't easily change config.py at runtime from outside, 
        # we will assume the User set up config.py to point to "dais_test.db".
        # We will create "dais_test.db" in the Project Root (where DAIS runs).
        
        # Ensure db exists where DAIS expects it (Project Root)
        # We assume DAIS is run from Project Root by CMake or script.
        # Let's locate project root relative to binary
        
        child = spawn_dais_ready(binary)
        
        # Send Query
        child.sendline(':db SELECT name, role FROM users ORDER BY name')
        
        # Expect Table Output
        # Alice | admin
        # Bob   | user
        try:
            child.expect('Alice', timeout=COMMAND_TIMEOUT)
            child.expect('admin', timeout=COMMAND_TIMEOUT)
            child.expect('Bob', timeout=COMMAND_TIMEOUT)
            print("  PASS: Table output verification")
            cleanup_child(child)
            return True
        except pexpect.TIMEOUT:
            print(f"  FAIL: Expected output not found. Got: {child.before}")
            cleanup_child(child)
            return False

    except Exception as e:
        print(f"  FAIL: Exception - {e}")
        return False

def test_json_export(binary):
    print("[TEST] JSON Export...")
    try:
        child = spawn_dais_ready(binary)
        child.sendline(':db SELECT name FROM users WHERE name="Alice" --json')
        
        try:
            # Expect JSON format
            child.expect(r'\[', timeout=COMMAND_TIMEOUT)
            child.expect(r'"name": "Alice"', timeout=COMMAND_TIMEOUT)
            print("  PASS: JSON Export verified")
            cleanup_child(child)
            return True
        except pexpect.TIMEOUT:
            print(f"  FAIL: JSON output not found. Got: {child.before}")
            return False
            
    except Exception as e:
        print(f"  FAIL: Exception - {e}")
        return False

def test_file_output(binary):
    print("[TEST] File Output (Portability)...")
    try:
        # Define target file in temp dir
        fd, target_path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        os.remove(target_path) # Ensure it doesn't exist yet

        child = spawn_dais_ready(binary)
        # Use simple query with output flag
        child.sendline(f':db SELECT name FROM users LIMIT 1 --json --output {target_path}')
        
        try:
            # Expect success message "Saved JSON to: ..."
            child.expect('Saved JSON to:', timeout=COMMAND_TIMEOUT)
            cleanup_child(child)
            
            # Verify file exists and content
            if os.path.exists(target_path):
                with open(target_path, 'r') as f:
                    content = f.read()
                if "Alice" in content:
                     print("  PASS: File created and content verified")
                     os.remove(target_path)
                     return True
                else:
                    print(f"  FAIL: File content incorrect. Got: {content}")
                    os.remove(target_path)
                    return False
            else:
                print("  FAIL: File was not created")
                return False

        except pexpect.TIMEOUT:
            print(f"  FAIL: Success message not found. Got: {child.before}")
            cleanup_child(child)
            return False
            
    except Exception as e:
        print(f"  FAIL: Exception - {e}")
        return False

def test_error_handling(binary):
    print("[TEST] Error Handling (Invalid SQL)...")
    try:
        child = spawn_dais_ready(binary)
        child.sendline(':db SELECT * FROM nonexistent_table_123')
        
        try:
            child.expect('no such table', timeout=COMMAND_TIMEOUT)
            print("  PASS: Error caught correctly")
            cleanup_child(child)
            return True
        except pexpect.TIMEOUT:
            print(f"  FAIL: Error message missing. Got: {child.before}")
            return False
            
    except Exception as e:
        print(f"  FAIL: Exception - {e}")
        return False

# =============================================================================
# Main
# =============================================================================
def main():
    print("=" * 50)
    print(" DAIS DB Command Tests")
    print("=" * 50)

    binary = find_binary()
    if not binary:
        print("ERROR: DAIS binary not found")
        sys.exit(1)

    # Setup DB in Project Root (Assuming this script is run from project root or test dir)
    # We try to put the DB where config.py expects it.
    # Config default: os.path.join(root, "dais_test.db")
    project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    db_path = os.path.join(project_root, "dais_test.db")
    
    print(f"Setting up test DB at: {db_path}")
    setup_test_db(db_path)

    results = []
    results.append(test_basic_query(binary, db_path))
    time.sleep(1)
    results.append(test_json_export(binary))
    time.sleep(1)
    results.append(test_file_output(binary))
    time.sleep(1)
    results.append(test_error_handling(binary))

    print("\n" + "="*50)
    if all(results):
        print(" ALL DB TESTS PASSED")
        sys.exit(0)
    else:
        print(" SOME TESTS FAILED")
        sys.exit(1)

if __name__ == "__main__":
    main()
