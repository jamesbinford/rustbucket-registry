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
python manage.py run_task cleanup
python manage.py run_task daily_summary
```

### Notifications

Test notification channels:
```bash
# List all notification channels
python manage.py test_notification --list

# Test a specific channel
python manage.py test_notification --channel "Channel Name"

# Test all active channels
python manage.py test_notification --all
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
  - `notifications.py`: Notification service (email, Slack, webhook)
  - `signals.py`: Django signal handlers (auto-send notifications on alerts)
  - `apps.py`: App configuration that starts the scheduler and loads signals

## Database Configuration

The project is configured to use MySQL. The connection parameters are loaded from environment variables in `settings.py`.

## Automated Background Tasks

The project uses **APScheduler** for automated tasks. The scheduler starts automatically when Django starts (via `apps.py`).

### Scheduled Tasks

- **Pull Rustbucket Updates** (every 5 minutes): Pulls status updates from all active rustbuckets
- **Extract Logs** (every 15 minutes): Extracts and stores logs from rustbuckets to S3
- **Health Check** (every 10 minutes): Monitors rustbucket health and creates alerts for unresponsive buckets
- **Cleanup Old Data** (daily at 2:00 AM): Deletes old resolved alerts and log entries
- **Daily Summary** (daily at 8:00 AM): Generates a summary report of activities

### Configuration

- Task schedules: `rustbucketregistry/scheduler.py`
- Task implementations: `rustbucketregistry/scheduled_tasks.py`
- Disable scheduler: Set environment variable `RUN_SCHEDULER=false`

See `SCHEDULER_SETUP.md` for full documentation.

## Real-time Alert Notifications

The project supports automatic notifications when alerts are created. Notifications can be sent via email, Slack, or webhooks.

### Supported Channels

- **Email**: Send alerts to multiple email addresses
- **Slack**: Post alerts to Slack channels via webhooks
- **Webhook**: Send alerts to custom webhook endpoints (PagerDuty, OpsGenie, etc.)

### Configuration

Notification channels are configured in Django Admin:
1. Go to **Admin → Notification Channels**
2. Create a new channel with appropriate configuration
3. Test the channel to verify it works
4. Notifications are sent automatically when alerts are created

### Filtering

- **Severity filtering**: Only notify on high/medium/low severity alerts
- **Alert type filtering**: Only notify on specific alert types

See `NOTIFICATIONS_SETUP.md` for full documentation and setup instructions.

## Style Guidelines
- Use Google's Python Style Guide (https://google.github.io/styleguide/pyguide.html) for Python code.
- Separate test fixtures from business logic wherever possible. 