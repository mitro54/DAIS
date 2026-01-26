#!/bin/bash
set -e

# =============================================================================
# Local CI Simulator
# Runs the full database test suite with Strict Mode (CI=true)
# Requires: Docker
# =============================================================================

echo ">>> [1/4] Cleaning up potential stale containers..."
docker rm -f dais-pg-local dais-my-local 2>/dev/null || true

echo ">>> [2/4] Starting Service Containers..."

# Postgres
docker run --name dais-pg-local \
  -e POSTGRES_PASSWORD=test_password \
  -e POSTGRES_USER=test_user \
  -e POSTGRES_DB=test_db \
  -p 5433:5432 \
  -d postgres:15 > /dev/null
echo "    - Postgres 15 started on port 5433"

# MySQL
docker run --name dais-my-local \
  -e MYSQL_ROOT_PASSWORD=root_password \
  -e MYSQL_DATABASE=test_db \
  -e MYSQL_USER=test_user \
  -e MYSQL_PASSWORD=test_password \
  -p 3307:3306 \
  -d mysql:8.0 > /dev/null
echo "    - MySQL 8.0 started on port 3307"

echo ">>> Waiting 15s for databases to be ready..."
sleep 15

echo ">>> [3/4] Running Tests in Strict Mode (CI=true)..."
export CI=true

echo "    - Installing Python dependencies..."
pip install -r tests/requirements.txt > /dev/null 2>&1 || pip3 install -r tests/requirements.txt > /dev/null 2>&1 || echo "⚠️ Warning: Pip install failed, continuing..."

# Postgres Env
export DB_HOST_PG=localhost
export DB_PORT_PG=5433
export DB_USER_PG=test_user
export DB_PASS_PG=test_password
export DB_NAME_PG=test_db

# MySQL Env
export DB_HOST_MY=127.0.0.1
export DB_PORT_MY=3307
export DB_USER_MY=test_user
export DB_PASS_MY=test_password
export DB_NAME_MY=test_db

echo ">>> Running DB Logic Tests..."
python3 tests/functional/test_db_logic.py
LOGIC_EXIT=$?

echo ">>> Running Interactive CLI Tests..."
python3 tests/functional/test_commands.py
CLI_EXIT=$?

TEST_EXIT_CODE=$((LOGIC_EXIT + CLI_EXIT))

echo ">>> [4/4] Cleaning up..."
docker rm -f dais-pg-local dais-my-local > /dev/null

if [ $TEST_EXIT_CODE -eq 0 ]; then
    echo "✅ ALL LOCAL CI TESTS PASSED"
else
    echo "❌ TESTS FAILED"
fi

exit $TEST_EXIT_CODE
