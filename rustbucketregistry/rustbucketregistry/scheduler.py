"""
APScheduler configuration for RustBucket Registry.

This module sets up and configures the background task scheduler using APScheduler.
The scheduler runs in the same process as Django and requires no external services.
"""
import logging
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from django.conf import settings

logger = logging.getLogger(__name__)

# Global scheduler instance
scheduler = None


def start():
    """
    Start the APScheduler background scheduler.

    This function is called when Django starts up (via AppConfig.ready()).
    It sets up all scheduled tasks with their intervals.
    """
    global scheduler

    # Prevent starting multiple schedulers
    if scheduler is not None and scheduler.running:
        logger.info("Scheduler already running")
        return

    # Create a background scheduler
    scheduler = BackgroundScheduler(timezone=settings.TIME_ZONE)

    # Import task functions
    from rustbucketregistry.scheduled_tasks import (
        pull_rustbucket_updates,
        extract_logs_from_rustbuckets,
        health_check_rustbuckets,
    )

    # Schedule tasks
    # Note: You can adjust these intervals based on your needs

    # Pull rustbucket updates every 5 minutes
    scheduler.add_job(
        pull_rustbucket_updates,
        trigger=IntervalTrigger(minutes=5),
        id='pull_rustbucket_updates',
        name='Pull Rustbucket Updates',
        replace_existing=True,
        max_instances=1,  # Prevent overlapping runs
    )

    # Extract logs every 15 minutes
    scheduler.add_job(
        extract_logs_from_rustbuckets,
        trigger=IntervalTrigger(minutes=15),
        id='extract_logs',
        name='Extract Logs from Rustbuckets',
        replace_existing=True,
        max_instances=1,
    )

    # Health check every 10 minutes
    scheduler.add_job(
        health_check_rustbuckets,
        trigger=IntervalTrigger(minutes=10),
        id='health_check',
        name='Health Check Rustbuckets',
        replace_existing=True,
        max_instances=1,
    )

    # Start the scheduler
    scheduler.start()
    logger.info("APScheduler started successfully")
    logger.info(f"Scheduled jobs: {len(scheduler.get_jobs())}")

    # Log all scheduled jobs
    for job in scheduler.get_jobs():
        logger.info(f"  - {job.name} (ID: {job.id}): {job.trigger}")


def stop():
    """
    Stop the APScheduler background scheduler.

    This is called when Django shuts down.
    """
    if scheduler is not None and scheduler.running:
        scheduler.shutdown(wait=False)
        logger.info("APScheduler stopped")
