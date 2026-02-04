#!/usr/bin/env python3
"""
DAIS Config Loader Functional Tests.

This module verifies that the DAIS engine correctly loads configuration
values from `config/config.py` at startup. It uses a swap-and-restore
strategy to temporarily replace the configuration file with test values.

Usage:
    python3 tests/functional/test_config_loader.py

Requirements:
    - pexpect
    - DAIS binary built
"""

import os
import sys
import shutil
import time
import tempfile

try:
    import pexpect
except ImportError:
    print("ERROR: pexpect not installed")
    sys.exit(1)

# Constants
STARTUP_TIMEOUT = 10
SHELL_INIT_DELAY = 2

def find_paths():
    """Locate binary and config directory."""
    # Assumptions based on project structure:
    # root/
    #   build/DAIS
    #   config/config.py
    #   tests/functional/this_script.py
    
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.abspath(os.path.join(script_dir, '..', '..'))
    
    binary = os.path.join(project_root, 'build', 'DAIS')
    config_dir = os.path.join(project_root, 'config')
    config_file = os.path.join(config_dir, 'config.py')
    
    if not os.path.exists(binary):
        return None, None
    return binary, config_file

class ConfigManager:
    """Context manager to safely swap config.py"""
    def __init__(self, config_path, new_content):
        self.config_path = config_path
        self.backup_path = config_path + ".bak"
        self.new_content = new_content
        
    def __enter__(self):
        # Backup
        if os.path.exists(self.config_path):
            shutil.copy2(self.config_path, self.backup_path)
        
        # Write new
        with open(self.config_path, 'w') as f:
            f.write(self.new_content)
            
    def __exit__(self, exc_type, exc_val, exc_tb):
        # Restore
        if os.path.exists(self.backup_path):
            shutil.move(self.backup_path, self.config_path)

def test_custom_ls_padding():
    """Verify LS_PADDING config is applied."""
    print("[TEST] Custom LS_PADDING config...")
    
    binary, config_path = find_paths()
    if not binary:
        print("  SKIP: Binary not found")
        return None

    # Custom Config: Extreme padding (20 spaces)
    custom_conf = """
SHOW_LOGO = True
SHELL_PROMPTS = ["$ ", "> "]
TEXT_EXTENSIONS = [".txt"]
DATA_EXTENSIONS = [".csv"]
DB_KEY_MAPPING = {}
DB_QUERIES = {}

# TEST VALUES
LS_SORT = {"by": "name", "order": "asc", "dirs_first": True, "flow": "h"}
LS_PADDING = 20  # Extreme padding
THEME = {
    "RESET": "", "STRUCTURE": "", "UNIT": "", "VALUE": "", "ESTIMATE": "", 
    "TEXT": "", "SYMLINK": "", "LOGO": "", "SUCCESS": "", "WARNING": "", 
    "ERROR": "", "NOTICE": ""
}
LS_FORMATS = {
    "directory": "{name}/",
    "text_file": "{name}",
    "data_file": "{name}",
    "binary_file": "{name}",
    "error": "{name}"
}
"""
    
    with ConfigManager(config_path, custom_conf):
        # Create temp files to list
        with tempfile.TemporaryDirectory() as temp_dir:
            for n in ["a", "b"]:
                with open(os.path.join(temp_dir, n), 'w') as f: f.write(".")
            
            # Spawn DAIS
            child = pexpect.spawn(binary, encoding='utf-8', timeout=10)
            child.setwinsize(24, 80) # Force standard size to ensure padding calculation works
            try:
                child.expect('DAIS has been started', timeout=STARTUP_TIMEOUT)
                
                # Consume the initial prompt so we don't match it immediately after sending ls
                child.expect(r"[\$#>] ", timeout=5)
                time.sleep(0.5) # Short delay to ensure stable state
                
                # Run LS
                child.sendline(f"ls {temp_dir}")
                
                # Wait for the NEXT prompt. This ensures command finished.
                # output will be in child.before
                child.expect(r"[\$#>] ", timeout=5)
                
                # Check output for large whitespace
                output = child.before
                
                # With padding 20, there should be a huge gap between 'a' and 'b'
                # or they might be on separate lines if terminal is narrow.
                # Let's check for at least 15 consecutive spaces.
                if "               " in output:
                    print("  PASS: High padding detected")
                    child.sendline(":exit")
                    return True
                else:
                    print("  FAIL: High padding NOT detected")
                    print(f"DEBUG: Output captured: {repr(output)}")
                    child.terminate(force=True)
                    return False
                    
            except Exception as e:
                print(f"  FAIL: {e}")
                child.terminate(force=True)
                return False

def test_disable_logo():
    """Verify SHOW_LOGO = False disables the [-] prefix."""
    print("[TEST] Disable SHOW_LOGO...")
    
    binary, config_path = find_paths()
    
    custom_conf = """
SHOW_LOGO = False # DISABLED
SHELL_PROMPTS = ["$ ", "> "]
TEXT_EXTENSIONS = []
DATA_EXTENSIONS = []
DB_KEY_MAPPING = {}
DB_QUERIES = {}
LS_SORT = {"by": "name", "order": "asc", "dirs_first": True, "flow": "h"}
LS_PADDING = 2
THEME = {
    "RESET": "", "STRUCTURE": "", "UNIT": "", "VALUE": "", "ESTIMATE": "", 
    "TEXT": "", "SYMLINK": "", "LOGO": "", "SUCCESS": "", "WARNING": "", 
    "ERROR": "", "NOTICE": ""
}
LS_FORMATS = {}
"""

    with ConfigManager(config_path, custom_conf):
        child = pexpect.spawn(binary, encoding='utf-8', timeout=10)
        try:
            # Startup message might still have it because it's hardcoded in main?
            # No, main uses config.show_logo (defaults to true).
            # But Config is loaded BEFORE run().
            # Let's check a standard log message or command output.
            
            child.expect('DAIS has been started', timeout=STARTUP_TIMEOUT)
            time.sleep(SHELL_INIT_DELAY)
            
            # Trigger a known log message, e.g., :help
            child.sendline(":help")
            child.expect("DAIS Commands")
            
            output = child.before
            
            # The structure for logo is usually: [LOGO-RESET]
            # Since theme is empty strings, we look for brackets []
            # Wait, if show_logo is false, the Engine doesn't print the prefix.
            
            if "[-]" in output:
                print("  FAIL: Logo found despite SHOW_LOGO=False")
                print(f"DEBUG: Output captured: {repr(output)}")
                child.terminate(force=True)
                return False
            else:
                print("  PASS: Logo prefix absent")
                child.sendline(":exit")
                return True

        except Exception as e:
            print(f"  FAIL: {e}")
            child.terminate(force=True)
            return False

def main():
    print("="*50)
    print(" DAIS Config Loader Tests")
    print("="*50)
    
    results = []
    results.append(test_custom_ls_padding())
    time.sleep(1)
    results.append(test_disable_logo())
    
    passed = sum(1 for r in results if r)
    total = len(results)
    
    print(f"\n{passed}/{total} tests passed")
    if passed == total and total > 0:
        sys.exit(0)
    else:
        sys.exit(1)

if __name__ == "__main__":
    main()
