#!/bin/bash
set -e

# Wait for DB to be ready using python (since psql is not installed in slim image)
echo "Waiting for test database..."
until python3 -c "import psycopg2; psycopg2.connect(host='$POSTGRES_HOST', user='$POSTGRES_USER', password='$POSTGRES_PASSWORD', dbname='$POSTGRES_DB')" > /dev/null 2>&1; do
  >&2 echo "Postgres is unavailable - sleeping"
  sleep 1
done

echo "Database is up - running tests"
# We don't necessarily need alembic for tests if we use Base.metadata.create_all in conftest.py
# but it's good to ensure the environment is correct.

# Run tests
PYTHONPATH=. pytest tests/ -v
