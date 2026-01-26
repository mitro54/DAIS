import os
import sys
import shutil
import tempfile
import unittest
from unittest.mock import patch, MagicMock

# Add src/py_scripts to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../src/py_scripts')))

import db_handler

class TestDBHandler(unittest.TestCase):
    def setUp(self):
        # Create a temp directory structure for env testing
        # /tmp/
        #   - parent/
        #       - .env (DB_NAME=ParentDB)
        #       - child/
        #           - (empty)
        self.test_dir = tempfile.mkdtemp()
        self.parent_dir = os.path.join(self.test_dir, "parent")
        self.child_dir = os.path.join(self.parent_dir, "child")
        os.makedirs(self.child_dir)

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_recursive_env_loading(self):
        """Verify we can find .env in a parent directory."""
        env_path = os.path.join(self.parent_dir, ".env")
        with open(env_path, "w") as f:
            f.write("DB_NAME=ParentDB\nTEST_KEY=FoundIt")

        # Run from child
        env = db_handler.load_env_file(self.child_dir)
        self.assertEqual(env.get("TEST_KEY"), "FoundIt")
        self.assertEqual(env.get("DB_NAME"), "ParentDB")

    def test_env_priority(self):
        """Verify CWD .env overrides Parent .env."""
        # Parent
        with open(os.path.join(self.parent_dir, ".env"), "w") as f:
            f.write("VAR=Parent")
        
        # Child
        with open(os.path.join(self.child_dir, ".env"), "w") as f:
            f.write("VAR=Child")

        env = db_handler.load_env_file(self.child_dir)
        self.assertEqual(env.get("VAR"), "Child")

    def test_config_key_mapping(self):
        """Verify DB_N maps to DB_NAME etc."""
        # Mock env vars
        env_vars = {"DB_N": "my_db", "DB_H": "localhost", "DB_T": "postgres"}
        
        # Mock Config 
        mock_config = MagicMock()
        mock_config.DB_KEY_MAPPING = {
            "DB_TYPE": ["DB_T"],
            "DB_HOST": ["DB_H"],
            "DB_NAME": ["DB_N"]
        }

        resolved = db_handler._resolve_connection_config(env_vars, mock_config)
        
        self.assertEqual(resolved["DB_NAME"], "my_db")
        self.assertEqual(resolved["DB_HOST"], "localhost")
        self.assertEqual(resolved["DB_TYPE"], "postgres")

    def test_system_env_fallback(self):
        """Verify we check os.environ if .env is missing."""
        with patch.dict(os.environ, {"DB_TYPE": "mysql", "DB_NAME": "sys_db"}):
            resolved = db_handler._resolve_connection_config({}, None)
            self.assertEqual(resolved["DB_TYPE"], "mysql")
            self.assertEqual(resolved["DB_NAME"], "sys_db")

    def test_adapter_factory(self):
        """Verify get_adapter returns correct classes."""
        self.assertIsInstance(db_handler.get_adapter("sqlite"), db_handler.SqliteAdapter)
    
    
    def _verify_connection(self, db_type, env_prefix):
        """Helper to verify connection for a specific DB type using env vars."""
        host = os.environ.get(f"DB_HOST_{env_prefix}")
        if not host:
            if os.environ.get("CI") == "true":
                self.fail(f"CI Error: DB_HOST_{env_prefix} not set. {db_type} service expected in CI.")
            print(f"Skipping {db_type} test (DB_HOST_{env_prefix} not set)")
            return

        try:
            print(f"Testing {db_type} Connection...")
            env_mock = {
                "DB_TYPE": db_type.lower(),
                "DB_HOST": host,
                "DB_PORT": os.environ.get(f"DB_PORT_{env_prefix}", "5432" if db_type == "Postgres" else "3306"),
                "DB_USER": os.environ.get(f"DB_USER_{env_prefix}", "test_user"), 
                "DB_PASS": os.environ.get(f"DB_PASS_{env_prefix}", "test_password"),
                "DB_NAME": os.environ.get(f"DB_NAME_{env_prefix}", "test_db")
            }
            
            # Mock config and resolve
            mock_config = MagicMock()
            mock_config.DB_KEY_MAPPING = None
            resolved = db_handler._resolve_connection_config(env_mock, mock_config)
            
            adapter = db_handler.get_adapter(db_type.lower())
            adapter.connect(None, **resolved)
            
            # Run Connection & Feature Test (CRUD)
            # 1. Create Table
            adapter.execute("CREATE TABLE IF NOT EXISTS ci_test (id INT, val VARCHAR(20))")
             
            # 2. Insert Data
            # Postgres/MySQL placeholders might differ slightly, but simple string injection 
            # for this test logic is acceptable as we control the input 'test_val'
            adapter.execute("INSERT INTO ci_test (id, val) VALUES (100, 'ci_feature_works')")

            # 3. Query Data
            cursor = adapter.execute("SELECT val FROM ci_test WHERE id = 100")
            result = cursor.fetchone()
            self.assertEqual(result[0], "ci_feature_works")
            
            # 4. Cleanup
            adapter.execute("DROP TABLE ci_test")
            
            adapter.close()
            print(f"  {db_type} PASS (CRUD Verified)")
        except Exception as e:
            self.fail(f"{db_type} Connection Failed: {e}")

    def test_live_connections(self):
        """
        Verify real connections to CI Service Containers if configured.
        We check for DB_HOST_PG and DB_HOST_MY environment variables.
        """
        self._verify_connection("Postgres", "PG")
        self._verify_connection("MySQL", "MY")

    def test_sqlite_live(self):
        """Verify SQLite adapter works with a temp file."""
        db_path = os.path.join(self.test_dir, "test.db")
        adapter = db_handler.get_adapter("sqlite")
        try:
            # Connect
            adapter.connect(db_path)
            # Create Table
            adapter.execute("CREATE TABLE foo (id INTEGER PRIMARY KEY, val TEXT)")
            adapter.execute("INSERT INTO foo (val) VALUES ('bar')")
            # Query
            cursor = adapter.execute("SELECT val FROM foo")
            result = cursor.fetchone()
            self.assertEqual(result[0], "bar")
            print("  SQLite PASS")
        finally:
            adapter.close()

    def test_duckdb_live(self):
        """Verify DuckDB adapter works (in-memory)."""
        try:
            import duckdb
        except ImportError:
            print("Skipping DuckDB test (pkg missing)")
            return

        adapter = db_handler.get_adapter("duckdb")
        try:
            # Connect (In Memory)
            adapter.connect(":memory:")
            # Create Table
            adapter.execute("CREATE TABLE foo (id INTEGER, val TEXT)")
            adapter.execute("INSERT INTO foo VALUES (1, 'quack')")
            # Query
            cursor = adapter.execute("SELECT val FROM foo")
            result = cursor.fetchone()
            self.assertEqual(result[0], "quack")
            print("  DuckDB PASS")
        finally:
            adapter.close()

class TestDBFailures(unittest.TestCase):
    """Negative testing: Ensure we fail gracefully."""
    
    def test_invalid_sql(self):
        """Verify executing bad SQL raises an error (not a crash)."""
        adapter = db_handler.get_adapter("sqlite")
        adapter.connect(":memory:")
        try:
            with self.assertRaises(Exception): # sqlite3.OperationalError
                adapter.execute("SELECT * FROM non_existent_table")
            print("  Negative Test (Invalid SQL): PASS")
        finally:
            adapter.close()

    def test_connection_refused(self):
        """Verify connecting to a closed port hangs/fails properly."""
        # We assume localhost:9999 is closed.
        pg_adapter = db_handler.get_adapter("postgres")
        
        # Manually constructing a bad config
        bad_config = {
            "DB_TYPE": "postgres",
            "DB_HOST": "localhost", 
            "DB_PORT": "9999", # Closed port
            "DB_USER": "user",
            "DB_PASS": "pass",
            "DB_NAME": "db"
        }
        
        # Should raise OperationalError (psycopg2)
        with self.assertRaises(Exception):
            try:
                # We need to resolve it manually or just call connect directly if knowing the signature?
                # accessing private method for test setup or just passing args?
                # db_handler doesn't expose resolve cleanly as static.
                # Let's import psycopg2 directly? No, test the adapter wrapper.
                # The adapter takes kwargs.
                pg_adapter.connect(None, host="localhost", port="9999", user="u", password="p", dbname="d")
            except ImportError:
                 print("Skipping PG Failure test (pkg missing)")
                 pass
        print("  Negative Test (Connection Refused): PASS")

    def test_auto_limit_logic(self):
        """Verify LIMIT 1000 is applied ONLY to SELECT statements."""
        # 1. SELECT without limit -> gets limit
        q1 = "SELECT * FROM t"
        # We need to test the logic in run_query. Since run_query is a function that 
        # calls get_adapter, we can mock get_adapter to intercept the query.
        
        with patch("db_handler.get_adapter") as mock_get:
            mock_adapter = MagicMock()
            mock_get.return_value = mock_adapter
            
            # Case A: SELECT
            db_handler.run_query("select * from t", "sqlite", ":memory:")
            # Verify execute was called with limit
            args, _ = mock_adapter.execute.call_args
            self.assertTrue("LIMIT 1000" in args[0])

            # Case B: INSERT
            db_handler.run_query("INSERT INTO t VALUES(1)", "sqlite", ":memory:")
            args, _ = mock_adapter.execute.call_args
            self.assertFalse("LIMIT 1000" in args[0])
            
        print("  Auto-Limit Logic: PASS")

if __name__ == '__main__':
    unittest.main()

