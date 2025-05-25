# Rustbucket Registry Scheduled Tasks

## Overview
The Rustbucket Registry system includes several scheduled tasks that need to run at regular intervals to maintain proper functionality. These tasks include:

1. **Pull-based bucket updates** - Get updated information from all rustbuckets
2. **Pull-based log extraction** - Extract logs from all rustbuckets and store them in S3
3. **Hourly log parsing** - Parse logs from S3 and store them in the database
4. **Four-hourly log analysis** - Analyze logs using Claude and store analysis results

## Scheduling with Cron

These tasks can be scheduled using cron jobs on your server. Below are example cron entries for each task:

### 1. Pull-based Bucket Updates (Every 15 minutes)
```
*/15 * * * * cd /path/to/rustbucketregistry && python manage.py shell -c "from rustbucketregistry.api.views import pull_bucket_updates; pull_bucket_updates()"
```

### 2. Pull-based Log Extraction (Every 30 minutes)
```
*/30 * * * * cd /path/to/rustbucketregistry && python manage.py shell -c "from rustbucketregistry.api.views import extract_logs_from_buckets; extract_logs_from_buckets()"
```

### 3. Hourly Log Parsing
```
0 * * * * cd /path/to/rustbucketregistry && python manage.py parse_logs
```

### 4. Four-hourly Log Analysis with Claude
```
0 */4 * * * cd /path/to/rustbucketregistry && python manage.py analyze_logs
```

## Setting Up Cron Jobs

To set up these cron jobs:

1. Open your crontab for editing:
   ```
   crontab -e
   ```

2. Add the above cron entries, replacing `/path/to/rustbucketregistry` with the actual path to your project.

3. Save and exit the editor.

## Environment Setup

For the cron jobs to work properly, make sure:

1. Your environment variables (AWS credentials, database settings, Claude API key) are properly set up.
2. The user running the cron jobs has appropriate permissions to access the database and S3 bucket.
3. Consider using a virtualenv wrapper for your cron jobs if your project is using a virtual environment.

## Log Files

To capture the output of the cron jobs for debugging purposes, you can redirect the output to a log file:

```
*/15 * * * * cd /path/to/rustbucketregistry && python manage.py shell -c "from rustbucketregistry.api.views import pull_bucket_updates; pull_bucket_updates()" >> /var/log/rustbucketregistry/updates.log 2>&1
```

## Alternative: Celery Tasks

For more advanced scheduling and task management, consider using Celery with Django:

1. Install Celery and configure it with your Django project.
2. Set up periodic tasks using Celery Beat.
3. Implement the scheduled tasks as Celery tasks.

This approach provides better monitoring, error handling, and scalability compared to simple cron jobs.