#!/bin/bash

# Exit on error
set -e

echo "Waiting for database..."
python << END
import sys
import time
import MySQLdb

max_retries = 30
retry_count = 0

while retry_count < max_retries:
    try:
        connection = MySQLdb.connect(
            host="${DB_HOST}",
            user="${DB_USER}",
            password="${DB_PASSWORD}",
            database="${DB_NAME}"
        )
        connection.close()
        print("Database is ready!")
        sys.exit(0)
    except MySQLdb.OperationalError:
        retry_count += 1
        print(f"Database not ready yet... Attempt {retry_count}/{max_retries}")
        time.sleep(2)

print("Could not connect to database after", max_retries, "attempts")
sys.exit(1)
END

echo "Running database migrations..."
python manage.py migrate --noinput

echo "Collecting static files..."
python manage.py collectstatic --noinput

echo "Starting gunicorn..."
exec gunicorn rustbucketregistry.wsgi:application \
    --bind 0.0.0.0:8000 \
    --workers 4 \
    --threads 2 \
    --timeout 60 \
    --access-logfile - \
    --error-logfile - \
    --log-level info
