# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

RustBucketRegistry is a Django-based web application. It's set up to use MySQL as the database backend.

## Environment Setup

The project requires environment variables for database connection and Django's secret key. Create a `.env` file in the root directory with:

```
SECRET_KEY=your_secret_key
DB_NAME=your_db_name
DB_USER=your_db_user
DB_PASSWORD=your_db_password
DB_HOST=your_db_host
DB_PORT=your_db_port
```

## Common Commands

### Development Server

Start the development server:
```bash
python manage.py runserver
```

### Database Operations

Make migrations:
```bash
python manage.py makemigrations
```

Apply migrations:
```bash
python manage.py migrate
```

### Django Shell

Open Django interactive shell:
```bash
python manage.py shell
```

### Creating Admin User

```bash
python manage.py createsuperuser
```

### Testing

Run all tests:
```bash
python manage.py test
```

Run specific test file:
```bash
python manage.py test app_name.tests.test_module
```

Run specific test class:
```bash
python manage.py test app_name.tests.test_module.TestClass
```

### Static Files

Collect static files:
```bash
python manage.py collectstatic
```

### Scheduled Tasks

Run a scheduled task manually:
```bash
# List all available tasks
python manage.py run_task --list

# Run a specific task
python manage.py run_task health_check
python manage.py run_task pull_updates
python manage.py run_task extract_logs
```

## Project Structure

This is a standard Django project with the following structure:

- `manage.py`: Django's command-line utility for administrative tasks
- `rustbucketregistry/`: Main project package
  - `settings.py`: Project configuration (database, installed apps, middleware, etc.)
  - `urls.py`: URL routing configuration
  - `wsgi.py` & `asgi.py`: WSGI/ASGI application entry points
  - `scheduler.py`: APScheduler configuration for background tasks
  - `scheduled_tasks.py`: Automated task implementations
  - `signals.py`: Django signal handlers (auto-creates UserProfile on User creation)
  - `apps.py`: App configuration that starts the scheduler and loads signals
  - `views/register.py`: Registration and log extraction endpoints with S3 support

## Database Configuration

The project is configured to use MySQL. The connection parameters are loaded from environment variables in `settings.py`.

## Automated Background Tasks

The project uses **APScheduler** for automated tasks. The scheduler starts automatically when Django starts (via `apps.py`).

### Scheduled Tasks

- **Pull Rustbucket Updates** (every 5 minutes): Pulls status updates from all active rustbuckets
- **Extract Logs** (every 15 minutes): Extracts and stores logs from rustbuckets to S3
- **Health Check** (every 10 minutes): Monitors rustbucket health and creates alerts for unresponsive buckets

### Configuration

- Task schedules: `rustbucketregistry/scheduler.py`
- Task implementations: `rustbucketregistry/scheduled_tasks.py`
- Disable scheduler: Set environment variable `RUN_SCHEDULER=false`

See `SCHEDULER_SETUP.md` for full documentation.

## S3 Bucket Configuration

Each rustbucket can specify its own S3 bucket where it stores logs. The registry reads logs directly from the rustbucket's S3 bucket using IAM roles (all rustbuckets are in the same AWS account).

### Rustbucket S3 Fields

- **s3_bucket_name**: The name of the S3 bucket where the rustbucket stores logs
- **s3_region**: AWS region for the bucket (default: us-east-1)
- **s3_prefix**: Folder path in the bucket where logs are stored (default: logs/)

### How It Works

1. **During Registration**: Rustbucket provides S3 bucket configuration in the registration payload
2. **During Updates**: Rustbucket can update its S3 configuration via the update endpoint
3. **Log Extraction**: The scheduled task `extract_logs` will:
   - Check if rustbucket has S3 configured (`has_s3_configured()`)
   - If yes: Read logs directly from rustbucket's S3 bucket using `extract_logs_from_s3()`
   - If no: Fall back to HTTP pull method
4. **S3-to-S3 Copy**: Logs are copied from rustbucket's S3 bucket to the registry's S3 bucket

### Configuration in Admin

The S3 fields are visible in Django Admin under the "S3 Configuration" section (collapsed by default).

### Security

Access to S3 buckets uses IAM roles via the default boto3 credential chain. No credentials are stored in the database.

## Style Guidelines
- Use Google's Python Style Guide (https://google.github.io/styleguide/pyguide.html) for Python code.
- Separate test fixtures from business logic wherever possible. 