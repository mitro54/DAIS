"""
DAIS Database Handler Module.

This script bridges the C++ Engine with Python's database capabilities.
It is designed to be:
1.  **Robust**: Handles large datasets via streaming to avoid OOM.
2.  **Flexible**: Uses an Adapter pattern for easy database extension.
3.  **Context-Aware**: Reads .env files from the current working directory.
"""

import sys
import os
import json
import csv
import tempfile
import sqlite3
import abc
from typing import Dict, Any, Optional

# =============================================================================
# UTILITIES
# =============================================================================

def load_env_file(cwd: str) -> Dict[str, str]:
    """
    Locates and parses the nearest .env file by traversing up the directory tree.
    Priority: 
    1. Current Directory
    2. Parent Directories (recursive)
    3. Stops at User Home or Filesystem Root
    """
    def parse_env(path: str) -> Dict[str, str]:
        env_vars = {}
        try:
            with open(path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    if '=' in line:
                        key, value = line.split('=', 1)
                        value = value.strip()
                        if (value.startswith('"') and value.endswith('"')) or \
                           (value.startswith("'") and value.endswith("'")):
                            value = value[1:-1]
                        env_vars[key.strip()] = value
        except Exception:
            pass
        return env_vars

    current = os.path.abspath(cwd)
    user_home = os.path.abspath(os.path.expanduser("~"))
    root = os.path.abspath(os.sep)

    while True:
        env_path = os.path.join(current, ".env")
        if os.path.exists(env_path):
            return parse_env(env_path)
            
        # Stop guards
        if current == user_home or current == root:
            break
            
        parent = os.path.dirname(current)
        if parent == current: # Infinite loop guard for OS root
            break
        current = parent
        
    return {}

# =============================================================================
# ADAPTER INTERFACE
# =============================================================================

class DBAdapter(abc.ABC):
    @abc.abstractmethod
    def connect(self, source, **kwargs):
        """Establishes connection to the database."""
        pass

    @abc.abstractmethod
    def execute(self, query):
        """Executes a query and returns cursor."""
        pass
        
    @abc.abstractmethod
    def close(self):
        """Closes the connection."""
        pass

# =============================================================================
# ADAPTER IMPLEMENTATIONS
# =============================================================================

class SqliteAdapter(DBAdapter):
    def __init__(self):
        self.conn = None
        self.cursor = None

    def connect(self, source, **kwargs):
        self.conn = sqlite3.connect(source, isolation_level=None)
        self.cursor = self.conn.cursor()

    def execute(self, query):
        self.cursor.execute(query)
        return self.cursor

    def close(self):
        if self.conn:
            self.conn.close()

class DuckDbAdapter(DBAdapter):
    def __init__(self):
        self.conn = None
    
    def connect(self, source, **kwargs):
        try:
            import duckdb
        except ImportError:
            raise ImportError("MISSING_PKG:duckdb")
            
        self.conn = duckdb.connect(source)

    def execute(self, query):
        # DuckDB's execute returns the connection itself which acts as a cursor
        return self.conn.execute(query)

    def close(self):
        # DuckDB usually auto-closes, but we can be explicit
        if self.conn:
            self.conn.close()

class PostgresAdapter(DBAdapter):
    def __init__(self):
        self.conn = None
        self.cursor = None

    def connect(self, source, **kwargs):
        try:
            import psycopg2
        except ImportError:
            raise ImportError("MISSING_PKG:psycopg2-binary")
        
        # Map env vars DB_HOST -> host, etc.
        # Common libpq args: host, port, user, password, dbname
        connect_args = {}
        if "DB_HOST" in kwargs: connect_args["host"] = kwargs["DB_HOST"]
        if "DB_PORT" in kwargs: connect_args["port"] = kwargs["DB_PORT"]
        if "DB_USER" in kwargs: connect_args["user"] = kwargs["DB_USER"]
        if "DB_PASS" in kwargs: connect_args["password"] = kwargs["DB_PASS"]
        if "DB_NAME" in kwargs: connect_args["dbname"] = kwargs["DB_NAME"]
        
        # Fallback: if 'source' looks like a DSN "postgresql://...", use it
        if source and "://" in source:
             self.conn = psycopg2.connect(source)
        else:
             self.conn = psycopg2.connect(**connect_args)
        self.conn.autocommit = True
        self.cursor = self.conn.cursor()

    def execute(self, query):
        self.cursor.execute(query)
        return self.cursor

    def close(self):
        if self.conn: self.conn.close()

class MySqlAdapter(DBAdapter):
    def __init__(self):
        self.conn = None
        self.cursor = None

    def connect(self, source, **kwargs):
        try:
            import mysql.connector
        except ImportError:
            raise ImportError("MISSING_PKG:mysql-connector-python")

        connect_args = {}
        if "DB_HOST" in kwargs: connect_args["host"] = kwargs["DB_HOST"]
        if "DB_PORT" in kwargs: connect_args["port"] = kwargs["DB_PORT"]
        if "DB_USER" in kwargs: connect_args["user"] = kwargs["DB_USER"]
        if "DB_PASS" in kwargs: connect_args["password"] = kwargs["DB_PASS"]
        if "DB_NAME" in kwargs: connect_args["database"] = kwargs["DB_NAME"]

        self.conn = mysql.connector.connect(**connect_args)
        self.conn.autocommit = True
        self.cursor = self.conn.cursor()

    def execute(self, query):
        self.cursor.execute(query)
        return self.cursor

    def close(self):
        if self.conn: self.conn.close()


# Factory
def get_adapter(db_type):
    if db_type == "sqlite":
        return SqliteAdapter()
    elif db_type == "duckdb":
        return DuckDbAdapter()
    elif db_type == "postgres" or db_type == "postgresql":
        return PostgresAdapter()
    elif db_type == "mysql":
        return MySqlAdapter()
    elif db_type == "test_autoinstall":
        return TestAutoInstallAdapter()
    else:
        raise ValueError(f"Unsupported DB_TYPE: {db_type}")

class TestAutoInstallAdapter(DBAdapter):
    """Dummy adapter to trigger MISSING_PKG flow in C++."""
    def connect(self, source, **kwargs):
        raise ImportError("MISSING_PKG:dais-test-pkg")

    def execute(self, query): pass
    def close(self): pass

# =============================================================================
# CORE LOGIC
# =============================================================================

def run_query(query, db_type, db_source, adapter_kwargs={}):
    """
    Executes the query and formats the result.
    """
    flags = {
        "json": False,
        "csv": False,
        "no_limit": False
    }

    # 1. Parse Flags
    import re
    # Extract --output <filename>
    output_match = re.search(r'--output\s+([^\s]+)', query)
    if output_match:
        flags["output"] = output_match.group(1)
        query = query[:output_match.start()] + query[output_match.end():]
    else:
        flags["output"] = None

    # Parse boolean flags using regex to ensure they are whole words
    def pop_bool_flag(q, flag):
        pattern = r'\s+' + re.escape(flag) + r'(\s+|$)'
        match = re.search(pattern, q)
        if match:
            # Replace with space to avoid joining bits
            return q[:match.start()] + " " + q[match.end():], True
        return q, False

    query, flags["json"] = pop_bool_flag(query, "--json")
    query, flags["csv"] = pop_bool_flag(query, "--csv")
    query, flags["no_limit"] = pop_bool_flag(query, "--no-limit")

    clean_query = query.strip()
    
    # 2. Safety Limit (Only for SELECT)
    if not flags["json"] and not flags["csv"] and not flags["no_limit"]:
        low_query = clean_query.lower()
        if low_query.startswith("select") and "limit" not in low_query:
            # Don't append if it ends with a hanging clause (user likely still typing/editing)
            hanging = ["where", "by", "and", "or", "in", "set", "from"]
            words = clean_query.split()
            last_word = words[-1].lower() if words else ""
            if last_word not in hanging:
                clean_query += " LIMIT 1000"

    # 3. Execution
    adapter = None
    try:
        adapter = get_adapter(db_type)
        adapter.connect(db_source, **adapter_kwargs)
        cursor = adapter.execute(clean_query)
        
        # Extract headers
        headers = [d[0] for d in cursor.description] if cursor.description else []

        # Consolidate results for small queries to avoid temp files
        all_rows = []
        if flags["json"] or flags["csv"] or cursor.description:
            # For JSON/CSV without output, or for the Table view, we need the rows.
            # We'll fetch up to 1001 to see if it's "large"
            all_rows = cursor.fetchmany(1001)
            is_large = len(all_rows) > 1000
        
        # --- EXPORT ACTIONS ---
        if flags["json"]:
            if flags.get("output"):
                target_path = os.path.expanduser(flags["output"])
                # Permission Check
                dir_name = os.path.dirname(os.path.abspath(target_path))
                if not os.access(dir_name, os.W_OK):
                    return json.dumps({
                        "status": "error", 
                        "message": f"Permission denied: Cannot write to '{dir_name}'. Try using a path in /tmp/ or your home directory."
                    })
                
                with open(target_path, 'w', encoding='utf-8') as f:
                    f.write("[\n")
                    # Write already fetched rows
                    for i, row in enumerate(all_rows):
                        if i > 0: f.write(",\n")
                        f.write(json.dumps(dict(zip(headers, row)), default=str))
                    # Write remaining if any
                    first = len(all_rows) == 0
                    while True:
                        batch = cursor.fetchmany(1000)
                        if not batch: break
                        for row in batch:
                            if not first: f.write(",\n")
                            f.write(json.dumps(dict(zip(headers, row)), default=str))
                            first = False
                    f.write("\n]")
                adapter.close()
                return json.dumps({"status": "success", "action": "print", "data": f"Saved JSON to: {target_path}"})
            else:
                if is_large:
                    fd, target_path = tempfile.mkstemp(prefix="dais_db_", suffix=".json", text=True)
                    os.close(fd)
                    with open(target_path, 'w', encoding='utf-8') as f:
                        f.write("[\n")
                        for i, row in enumerate(all_rows):
                            if i > 0: f.write(",\n")
                            f.write(json.dumps(dict(zip(headers, row)), default=str))
                        while True:
                            batch = cursor.fetchmany(1000)
                            if not batch: break
                            for row in batch:
                                f.write(",\n")
                                f.write(json.dumps(dict(zip(headers, row)), default=str))
                        f.write("\n]")
                    adapter.close()
                    return json.dumps({"status": "success", "action": "page", "data": target_path, "pager": "cat"})
                else:
                    # Small result: print directly
                    data = [dict(zip(headers, r)) for r in all_rows]
                    adapter.close()
                    return json.dumps({"status": "success", "action": "print", "data": json.dumps(data, default=str, indent=2)})

        if flags["csv"]:
            import io, csv
            if flags.get("output"):
                target_path = os.path.expanduser(flags["output"])
                with open(target_path, 'w', encoding='utf-8', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(headers)
                    writer.writerows(all_rows)
                    while True:
                        batch = cursor.fetchmany(1000)
                        if not batch: break
                        writer.writerows(batch)
                adapter.close()
                return json.dumps({"status": "success", "action": "print", "data": f"Saved CSV to: {target_path}"})
            else:
                if is_large:
                    fd, target_path = tempfile.mkstemp(prefix="dais_db_", suffix=".csv", text=True)
                    os.close(fd)
                    with open(target_path, 'w', encoding='utf-8', newline='') as f:
                        writer = csv.writer(f)
                        writer.writerow(headers)
                        writer.writerows(all_rows)
                        while True:
                            batch = cursor.fetchmany(1000)
                            if not batch: break
                            writer.writerows(batch)
                    adapter.close()
                    return json.dumps({"status": "success", "action": "page", "data": target_path, "pager": "cat"})
                else:
                    # Small result: print directly
                    output = io.StringIO()
                    writer = csv.writer(output)
                    writer.writerow(headers)
                    writer.writerows(all_rows)
                    adapter.close()
                    return json.dumps({"status": "success", "action": "print", "data": output.getvalue()})

        # --- VIEW ACTION ---
        # If cursor.description is None, this was a DDL/DML statement (INSERT, UPDATE, CREATE)
        # that returns no rows. We should report success instead of trying to fetch.
        if not cursor.description:
            adapter.close()
            return json.dumps({"status": "success", "action": "print", "data": "Command executed successfully."})

        # Use already fetched rows plus any remaining
        rows = all_rows
        if is_large:
            if flags["no_limit"]:
                # User wants ALL rows - fetch the rest
                while True:
                    batch = cursor.fetchmany(1000)
                    if not batch:
                        break
                    rows.extend(batch)
            # else: We already fetched 1001, just use those for the preview
        adapter.close()

        # Calculate widths
        widths = [len(h) for h in headers]
        if not rows:
            if not headers:
                return json.dumps({"status": "success", "action": "print", "data": "Command executed (no results)."})
            
            # Show headers even if no data
            head = " | ".join(f"{h:<{len(h)}}" for h in headers)
            sep = "-+-".join("-" * len(h) for h in headers)
            return json.dumps({"status": "success", "action": "print", "data": f"{head}\n{sep}\n(0 rows returned)"})

        # Calculate widths
        widths = [len(h) for h in headers]
        str_rows = []
        for row in rows:
            s_row = [str(cell) if cell is not None else "NULL" for cell in row]
            str_rows.append(s_row)
            for i, cell in enumerate(s_row):
                widths[i] = max(widths[i], len(cell))

        def format_line(r, w_list):
            return " | ".join(f"{c:<{w}}" for c, w in zip(r, w_list))

        separator = "-+-".join("-" * w for w in widths)
        header_line = format_line(headers, widths)

        output_lines = [header_line, separator]
        for row in str_rows:
            output_lines.append(format_line(row, widths))

        full_output = "\n".join(output_lines)
        
        if len(output_lines) > 50:
            fd, path = tempfile.mkstemp(prefix="dais_db_", suffix=".txt", text=True)
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                f.write(full_output)
                f.write("\n")  # Ensure prompt appears on new line after output
            user_pager = os.environ.get("PAGER", "less -S")
            return json.dumps({"status": "success", "action": "page", "data": path, "pager": user_pager})
        else:
            return json.dumps({"status": "success", "action": "print", "data": full_output})

    except ImportError as e:
        # Catch our custom missing package error or others
        msg = str(e)
        
        # RETRY MECHANISM: 
        # If import failed, it might be because the package is in the shell's python (e.g. Conda/Venv)
        # but not in our embedded python's path.
        if "MISSING_PKG" in msg and not getattr(sys, "_dais_path_synced", False):
            try:
                import subprocess
                # Ask the active shell python for its sys.path
                # We use the current shell's 'python3' command
                output = subprocess.check_output(
                    ["python3", "-c", "import sys; print(chr(10).join(sys.path))"], 
                    text=True, 
                    stderr=subprocess.DEVNULL
                )
                
                added_something = False
                for p in output.splitlines():
                    p = p.strip()
                    if p and os.path.isdir(p) and p not in sys.path:
                        sys.path.append(p)
                        added_something = True
                
                if added_something:
                    import importlib
                    importlib.invalidate_caches()
                
                # Mark as synced to prevent infinite recursion
                sys._dais_path_synced = True
                
                # RECURSIVE RETRY
                return run_query(query, db_type, db_source, adapter_kwargs)
                
            except Exception:
                # If sync fails (e.g. no python3), just proceed to error
                pass

        if "MISSING_PKG" in msg:
            pkg = msg.split(":")[1]
            return json.dumps({"status": "missing_pkg", "package": pkg})
        return json.dumps({"status": "error", "message": msg})
    except Exception as e:
        if adapter: adapter.close()
        return json.dumps({"status": "error", "message": str(e)})


def _resolve_connection_config(env_vars: Dict[str, str], config: Optional[Any] = None) -> Dict[str, str]:
    """
    Helper function to resolve database connection parameters.
    Prioritizes:
    1. .env file value (via mapped keys)
    2. os.environ value (via mapped keys)
    3. config.py default value
    """
    resolved_config: Dict[str, str] = {}

    # Default Mappings (Can be overridden in config.py)
    default_mappings = {
        "DB_TYPE": ["DB_TYPE", "DB_T", "DATABASE_TYPE", "ENGINE"],
        "DB_SOURCE": ["DB_SOURCE", "DB_FILE", "SQLITE_DB", "DB_S"],
        "DB_HOST": ["DB_HOST", "DB_H", "POSTGRES_HOST", "MYSQL_HOST"],
        "DB_PORT": ["DB_PORT", "DB_P", "POSTGRES_PORT", "MYSQL_TCP_PORT"],
        "DB_USER": ["DB_USER", "DB_U", "POSTGRES_USER", "MYSQL_USER"],
        "DB_PASS": ["DB_PASS", "DB_PASSWORD", "POSTGRES_PASSWORD", "MYSQL_PASSWORD", "MYSQL_PWD"],
        "DB_NAME": ["DB_NAME", "DB_N", "POSTGRES_DB", "MYSQL_DATABASE"]
    }
    
    mappings = None
    if config:
        mappings = getattr(config, "DB_KEY_MAPPING", None)
    
    if mappings is None:
        mappings = default_mappings

    def get_config_val(key: str) -> Optional[Any]:
        return getattr(config, key, None) if config else None

    # Iterate over canonical keys we care about
    for canonical, aliases in mappings.items():
        val = None
        
        # A. Search .env (Highest Priority)
        for alias in aliases:
            if alias in env_vars:
                val = env_vars[alias]
                break
        
        # B. Search os.environ (System Env)
        if val is None:
            for alias in aliases:
                if alias in os.environ:
                    val = os.environ[alias]
                    break
        
        # C. Fallback to config.py
        if val is None:
            val = get_config_val(canonical)
        
        if val is not None:
            resolved_config[canonical] = str(val)

    return resolved_config


def handle_command(cmd_input, cwd):
    """
    Main entry point invoked by C++ engine.
    
    Args:
        cmd_input (str): The query string.
        cwd (str): Current working directory of the shell.
    """
    try:
        # Ensure we can see newly installed packages (pip install from shell)
        import importlib
        import sys
        
        # Nuclear option: Clear the importer cache completely
        # This forces Python to re-scan directories for new packages
        sys.path_importer_cache.clear() 
        importlib.invalidate_caches()

        # Load .env from CWD if present
        env_vars = load_env_file(cwd)
        
        # Import config to get defaults / mappings
        try:
            import config
        except ImportError:
            config = None

        # 2. Resolve Connection Details with Key Mappings
        resolved_config = _resolve_connection_config(env_vars, config)

        # Set defaults if still missing
        db_type = resolved_config.get("DB_TYPE", "sqlite")
        
        # Priority for default SQlite source:
        # 1. ~/.dais/dais.db (Created if missing)
        # 2. current directory .dais.db
        # 3. :memory: (absolute fallback)
        default_source = os.path.expanduser("~/.dais/dais.db")
        if not os.path.exists(os.path.dirname(default_source)):
            try: os.makedirs(os.path.dirname(default_source), exist_ok=True)
            except: default_source = ".dais.db"
            
        db_source = resolved_config.get("DB_SOURCE", default_source)
        
        # Extra args for adapters (host/user/pass)
        adapter_kwargs = {}
        for k, v in resolved_config.items():
            if k not in ["DB_TYPE", "DB_SOURCE"]:
                adapter_kwargs[k] = v

        query = cmd_input.strip()

        # 1. Expand Saved Queries
        if config and hasattr(config, "DB_QUERIES") and isinstance(config.DB_QUERIES, dict):
            if query in config.DB_QUERIES:
                query = config.DB_QUERIES[query]

        return run_query(query, db_type, db_source.replace("_PROJECT_ROOT", cwd) if "_PROJECT_ROOT" in db_source else db_source, adapter_kwargs)

    except Exception as e:
         return json.dumps({"status": "error", "message": f"Unexpected Handler Error: {str(e)}"})

# =============================================================================
# CLI ENTRY POINT (For SSH usage)
# =============================================================================
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(json.dumps({"status": "error", "message": "Usage: python3 db_handler.py <query>"}))
        sys.exit(1)
        
    query = sys.argv[1]
    cwd = os.getcwd() # In SSH, we run in the user's directory directly
    print(handle_command(query, cwd))
