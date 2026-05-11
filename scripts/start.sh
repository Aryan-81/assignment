#!/bin/bash
# Wait for DB to be ready (optional but recommended)
# Run migrations
alembic upgrade head
# Start the app
exec uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
