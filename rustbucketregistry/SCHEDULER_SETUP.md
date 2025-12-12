# Automated Task Scheduler Setup

The Rustbucket Registry uses **APScheduler** for running background tasks. This is a simple, lightweight solution that requires no external services like Redis or RabbitMQ.

## Features

✅ No external dependencies (Redis, RabbitMQ, etc.)
✅ Runs in the same process as Django
✅ Simple configuration
✅ Easy to test and debug
✅ Automatic startup with Django

## Installation

### 1. Install Dependencies

```bash
cd rustbucketregistry
source ../env/bin/activate  # or your virtual environment
pip install -r requirements.txt
```

### 2. Start Django

That's it! The scheduler starts automatically when Django starts:

```bash
python manage.py runserver
```

You'll see log messages confirming the scheduler started:

```
INFO APScheduler started successfully
INFO Scheduled jobs: 5
INFO   - Pull Rustbucket Updates (ID: pull_rustbucket_updates): interval[0:05:00]
INFO   - Extract Logs from Rustbuckets (ID: extract_logs): interval[0:15:00]
INFO   - Health Check Rustbuckets (ID: health_check): interval[0:10:00]
INFO   - Cleanup Old Data (ID: cleanup_old_data): cron[hour='2', minute='0']
INFO   - Generate Daily Summary (ID: daily_summary): cron[hour='8', minute='0']
```

## Scheduled Tasks

The following tasks run automatically:

| Task | Schedule | Description |
|------|----------|-------------|
| **Pull Rustbucket Updates** | Every 5 minutes | Pulls status updates from all active rustbuckets |
| **Extract Logs** | Every 15 minutes | Extracts and stores logs from rustbuckets to S3 |
| **Health Check** | Every 10 minutes | Monitors rustbucket health and creates alerts for unresponsive buckets |
| **Cleanup Old Data** | Daily at 2:00 AM | Deletes resolved alerts older than 90 days and log entries older than 30 days |
| **Daily Summary** | Daily at 8:00 AM | Generates a summary report of activities in the last 24 hours |

## Manual Task Execution

### Run a Specific Task

```bash
# List available tasks
python manage.py run_task --list

# Run a specific task
python manage.py run_task health_check
python manage.py run_task pull_updates
python manage.py run_task extract_logs
python manage.py run_task cleanup
python manage.py run_task daily_summary
```

### Run from Django Shell

```bash
python manage.py shell
```

```python
from rustbucketregistry.scheduled_tasks import health_check_rustbuckets

# Run the task
result = health_check_rustbuckets()
print(result)
```

## Customizing Task Schedules

Edit `rustbucketregistry/scheduler.py` to change task schedules:

```python
# Change from every 5 minutes to every 10 minutes
scheduler.add_job(
    pull_rustbucket_updates,
    trigger=IntervalTrigger(minutes=10),  # Changed from 5 to 10
    id='pull_rustbucket_updates',
    name='Pull Rustbucket Updates',
    replace_existing=True,
    max_instances=1,
)

# Change to run at 3:30 AM instead of 2:00 AM
scheduler.add_job(
    cleanup_old_data,
    trigger=CronTrigger(hour=3, minute=30),  # Changed from hour=2, minute=0
    id='cleanup_old_data',
    name='Cleanup Old Data',
    replace_existing=True,
    max_instances=1,
)
```

### Available Trigger Types

**IntervalTrigger** - Run every X time:
```python
trigger=IntervalTrigger(minutes=5)  # Every 5 minutes
trigger=IntervalTrigger(hours=1)    # Every hour
trigger=IntervalTrigger(days=1)     # Every day
```

**CronTrigger** - Run at specific times:
```python
trigger=CronTrigger(hour=8, minute=0)           # Daily at 8:00 AM
trigger=CronTrigger(hour=14, minute=30)         # Daily at 2:30 PM
trigger=CronTrigger(day_of_week='mon', hour=9)  # Every Monday at 9 AM
trigger=CronTrigger(hour='*/2')                 # Every 2 hours
```

## Disabling the Scheduler

If you need to disable the scheduler temporarily:

```bash
# Set environment variable before starting Django
export RUN_SCHEDULER=false
python manage.py runserver
```

Or add to your `.env` file:
```
RUN_SCHEDULER=false
```

## Production Deployment

### Using Gunicorn (Recommended)

The scheduler works seamlessly with Gunicorn:

```bash
gunicorn rustbucketregistry.wsgi:application --bind 0.0.0.0:8000
```

**Note**: If running multiple Gunicorn workers, each worker will start its own scheduler. To avoid duplicate task execution, consider one of these approaches:

1. **Single Worker** (simplest):
   ```bash
   gunicorn rustbucketregistry.wsgi:application --workers 1
   ```

2. **Separate Scheduler Process**:
   - Disable scheduler on web workers: `RUN_SCHEDULER=false`
   - Run a dedicated scheduler worker: `RUN_SCHEDULER=true`

3. **Use process locking** (requires code modification)

### Using Apache + mod_wsgi

The scheduler will start automatically. Ensure only one Apache process runs the scheduler by using:
- Single-process mode for development
- Distributed locking for multi-process production

### Docker

In your Dockerfile:
```dockerfile
FROM python:3.12
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
CMD ["gunicorn", "rustbucketregistry.wsgi:application", "--bind", "0.0.0.0:8000", "--workers", "1"]
```

## Adding New Tasks

### 1. Create Task Function

Add to `rustbucketregistry/scheduled_tasks.py`:

```python
def my_new_task():
    """
    Description of what this task does.
    """
    try:
        logger.info("Starting my new task")

        # Your task logic here
        result = perform_some_operation()

        logger.info("Task completed successfully")
        return result

    except Exception as e:
        logger.error(f"Error in task: {str(e)}", exc_info=True)
```

### 2. Schedule the Task

Add to `rustbucketregistry/scheduler.py` in the `start()` function:

```python
from rustbucketregistry.scheduled_tasks import my_new_task

scheduler.add_job(
    my_new_task,
    trigger=IntervalTrigger(hours=1),  # Run every hour
    id='my_new_task',
    name='My New Task',
    replace_existing=True,
    max_instances=1,
)
```

### 3. Add to Management Command

Add to the `available_tasks` dictionary in `management/commands/run_task.py`:

```python
available_tasks = {
    # ... existing tasks ...
    'my_task': scheduled_tasks.my_new_task,
}
```

### 4. Restart Django

```bash
# Stop Django (Ctrl+C)
# Start again
python manage.py runserver
```

## Troubleshooting

### Scheduler Not Starting

**Check logs**: Look for APScheduler messages in the console output.

**Verify installation**:
```bash
python -c "import apscheduler; print(apscheduler.__version__)"
```

**Check if disabled**:
```bash
echo $RUN_SCHEDULER  # Should be empty or "true"
```

### Tasks Not Running

**Verify scheduler is running**:
- Look for "APScheduler started successfully" in logs
- Check that Django server is running

**Check task logs**:
- Tasks log their execution to the console
- Look for "Starting [task name]" messages

**Run task manually** to test:
```bash
python manage.py run_task health_check
```

### Multiple Task Executions

If you see tasks running multiple times:
- Check if you're running multiple Django processes
- Ensure only one Gunicorn worker if in production
- Set `RUN_SCHEDULER=false` on additional workers

### Task Errors

**View detailed error logs**:
```bash
python manage.py run_task health_check
```

**Check Django logs** for exception tracebacks

**Test in Django shell** for easier debugging:
```python
from rustbucketregistry.scheduled_tasks import health_check_rustbuckets
health_check_rustbuckets()
```

## Monitoring Tasks

### View Scheduled Jobs

From Django shell:
```python
from rustbucketregistry.scheduler import scheduler

# List all jobs
for job in scheduler.get_jobs():
    print(f"{job.name}: {job.next_run_time}")
```

### Task Execution History

Currently, APScheduler doesn't store task history. To track task execution:

1. **Check logs** for task output
2. **Add database logging** to tasks
3. Consider integrating with **Django-Q** or **Celery** if you need detailed history

## Performance Considerations

- **Lightweight**: APScheduler has minimal overhead
- **In-Process**: Runs in the same process as Django (no IPC overhead)
- **Concurrent**: Tasks run in background threads (won't block web requests)
- **Scalability**: For high-scale deployments, consider migrating to Celery

## Migration to Celery (Future)

If you need more advanced features later (distributed tasks, complex workflows, etc.), you can easily migrate:

1. Tasks are already separated in `scheduled_tasks.py`
2. Convert task functions to Celery tasks (add `@shared_task` decorator)
3. Replace APScheduler with Celery Beat
4. Update `scheduler.py` to use Celery

## Resources

- [APScheduler Documentation](https://apscheduler.readthedocs.io/)
- [Django AppConfig](https://docs.djangoproject.com/en/stable/ref/applications/)
- [Python Logging](https://docs.python.org/3/library/logging.html)

## Next Steps

After setting up the scheduler:

1. Monitor tasks for a few hours to ensure they run correctly
2. Check logs for any errors
3. Customize schedules based on your needs
4. Consider adding email notifications for task failures
5. Implement task monitoring dashboard (Future Feature)
