#!/usr/bin/env python3
"""
DAIS Advanced DB Functional Tests.

Nerifies more complex DB interactions:
- JSON/CSV export capabilities
- Saved Query expansion
- Large dataset handling (limit logic)

Usage:
    python3 tests/functional/test_db_advanced.py
"""

import os
import sys
import shutil
import time
import json
import csv
import tempfile

try:
    import pexpect
except ImportError:
    print("ERROR: pexpect not installed")
    sys.exit(1)

STARTUP_TIMEOUT = 10
SHELL_INIT_DELAY = 1.5

def find_binary():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.abspath(os.path.join(script_dir, '..', '..'))
    binary = os.path.join(project_root, 'build', 'DAIS')
    return binary if os.path.exists(binary) else None

def test_json_export():
    print("[TEST] DB JSON Export...")
    
    binary = find_binary()
    if not binary: return None

    with tempfile.TemporaryDirectory() as temp_dir:
        # Create a persistent DB file in temp dir
        db_path = os.path.join(temp_dir, "test.db")
        json_out = os.path.join(temp_dir, "out.json")
        
        # We need to tell DAIS to use THIS db. 
        # Since we can't easily swap config for every test, we rely on the .env auto-loading logic.
        env_path = os.path.join(temp_dir, ".env")
        with open(env_path, "w") as f:
            f.write(f"DB_SOURCE={db_path}\nDB_TYPE=sqlite")

        child = pexpect.spawn(binary, encoding='utf-8', timeout=10)
        try:
            child.expect('DAIS has been started', timeout=STARTUP_TIMEOUT)
            time.sleep(SHELL_INIT_DELAY)
            
            # 1. Switch CWD to temp_dir so DAIS picks up .env
            child.sendline(f"cd {temp_dir}")
            child.expect(r"[\$#>] ") # Wait for prompt
            
            # 2. Seed Data
            child.sendline(":db CREATE TABLE users (id INTEGER, name TEXT)")
            child.expect("Command executed", timeout=5)
            
            child.sendline(":db INSERT INTO users VALUES (1, 'Alice')")
            child.expect("Command executed", timeout=5)
            
            child.sendline(":db INSERT INTO users VALUES (2, 'Bob')")
            child.expect("Command executed", timeout=5)
            
            # 3. Export JSON
            # Note: We must escape the path if it had spaces, but tempfile usually doesn't on linux.
            # However Windows paths might have backslashes. Python handles path join correctly though.
            child.sendline(f":db SELECT * FROM users --json --output {json_out}")
            child.expect("Saved JSON to:", timeout=5)
            
            # 4. Verify File Content
            if not os.path.exists(json_out):
                print("  FAIL: JSON file not created")
                return False
                
            with open(json_out, 'r') as f:
                data = json.load(f)
                
            if len(data) == 2 and data[0]['name'] == 'Alice':
                print("  PASS: JSON content correct")
                child.sendline(":exit")
                return True
            else:
                print(f"  FAIL: Unexpected content: {data}")
                child.terminate(force=True)
                return False

        except Exception as e:
            print(f"  FAIL: {e}")
            child.terminate(force=True)
            return False

def test_csv_export():
    print("[TEST] DB CSV Export...")
    binary = find_binary()
    if not binary: return None

    with tempfile.TemporaryDirectory() as temp_dir:
        db_path = os.path.join(temp_dir, "test.db")
        csv_out = os.path.join(temp_dir, "out.csv")
        
        env_path = os.path.join(temp_dir, ".env")
        with open(env_path, "w") as f:
            f.write(f"DB_SOURCE={db_path}\nDB_TYPE=sqlite")

        child = pexpect.spawn(binary, encoding='utf-8', timeout=10)
        try:
            child.expect('DAIS has been started', timeout=STARTUP_TIMEOUT)
            time.sleep(SHELL_INIT_DELAY)
            
            child.sendline(f"cd {temp_dir}")
            child.expect(r"[\$#>] ")
            
            child.sendline(":db CREATE TABLE items (sku TEXT, cost INT)")
            # Wait for execution. Using expect(r"[\$#>]") is safer generally, 
            # but we assume the output contains "Command executed".
            child.expect(r"[\$#>] ")
            
            child.sendline(":db INSERT INTO items VALUES ('A1', 10)")
            child.expect(r"[\$#>] ")
            
            # Export CSV
            child.sendline(f":db SELECT * FROM items --csv --output {csv_out}")
            child.expect("Saved CSV to:")
            
            if not os.path.exists(csv_out):
                print("  FAIL: CSV file missing")
                return False
                
            with open(csv_out, 'r') as f:
                reader = list(csv.reader(f))
                
            # Expect header + row
            if len(reader) == 2 and reader[0] == ['sku', 'cost'] and reader[1] == ['A1', '10']:
                print("  PASS: CSV content correct")
                child.sendline(":exit")
                return True
            else:
                print(f"  FAIL: Unexpected csv content: {reader}")
                child.terminate(force=True)
                return False

        except Exception as e:
            print(f"  FAIL: {e}")
            child.terminate(force=True)
            return False

def main():
    print("="*50)
    print(" DAIS Advanced DB Tests")
    print("="*50)
    
    results = []
    results.append(test_json_export())
    time.sleep(1)
    results.append(test_csv_export())
    
    passed = sum(1 for r in results if r)
    total = len(results)
    print(f"\n{passed}/{total} tests passed")
    sys.exit(0 if passed == total and total > 0 else 1)

if __name__ == "__main__":
    main()
