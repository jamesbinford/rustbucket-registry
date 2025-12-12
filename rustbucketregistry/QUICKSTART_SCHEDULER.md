# Quick Start: Automated Tasks

Get automated background tasks running in 2 minutes!

## Setup

### 1. Install Dependencies

```bash
cd rustbucketregistry
source ../env/bin/activate
pip install -r requirements.txt
```

### 2. Start Django

```bash
python manage.py runserver
```

**That's it!** The scheduler starts automatically.

## Verify It's Working

You should see these log messages when Django starts:

```
INFO APScheduler started successfully
INFO Scheduled jobs: 5
```

## What's Running?

These tasks now run automatically:

- **Every 5 minutes**: Pull rustbucket updates
- **Every 10 minutes**: Health check all rustbuckets
- **Every 15 minutes**: Extract logs
- **Daily at 2 AM**: Cleanup old data
- **Daily at 8 AM**: Generate daily summary

## Test a Task Manually

```bash
# List available tasks
python manage.py run_task --list

# Run health check
python manage.py run_task health_check
```

## Customize Schedules

Edit `rustbucketregistry/scheduler.py` to change when tasks run.

## Need Help?

See [SCHEDULER_SETUP.md](SCHEDULER_SETUP.md) for full documentation.

## No External Services Needed!

Unlike Celery, this scheduler:
- ✅ Requires no Redis or RabbitMQ
- ✅ No separate worker processes
- ✅ Starts automatically with Django
- ✅ Just works!
