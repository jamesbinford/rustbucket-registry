"""
Scheduled tasks for the RustBucket Registry application.

These functions are called by APScheduler to perform automated maintenance,
monitoring, and data collection tasks.
"""
import logging
from datetime import timedelta

from django.conf import settings
from django.utils import timezone

logger = logging.getLogger(__name__)


def pull_rustbucket_updates():
    """
    Pull updates from all active rustbuckets.

    This task calls the existing pull_bucket_updates function.
    """
    try:
        from rustbucketregistry.views.register import pull_bucket_updates

        logger.info("Starting rustbucket updates pull")
        result = pull_bucket_updates()

        logger.info(
            f"Rustbucket updates completed: "
            f"{result['updated']} updated, {result['failed']} failed"
        )

        return result

    except Exception as e:
        logger.error(f"Error pulling rustbucket updates: {str(e)}", exc_info=True)


def extract_logs_from_rustbuckets():
    """
    Extract logs from all active rustbuckets.

    This task calls the existing extract_logs_from_buckets function.
    """
    try:
        from rustbucketregistry.views.register import extract_logs_from_buckets

        logger.info("Starting log extraction from rustbuckets")
        result = extract_logs_from_buckets()

        logger.info(
            f"Log extraction completed: "
            f"{result['extracted']} extracted, {result['failed']} failed"
        )

        return result

    except Exception as e:
        logger.error(f"Error extracting logs: {str(e)}", exc_info=True)


def health_check_rustbuckets():
    """
    Check the health of all rustbuckets and create alerts for unhealthy ones.

    A rustbucket is considered unhealthy if:
    - It hasn't been seen within the configured threshold
    - Its status is 'Active' but not responding
    """
    try:
        from rustbucketregistry.models import Rustbucket, Alert, LogSink

        logger.info("Starting rustbucket health checks")

        unhealthy_count = 0
        threshold = timezone.now() - timedelta(minutes=settings.HEALTH_CHECK_THRESHOLD_MINUTES)

        # Get all rustbuckets that should be active
        rustbuckets = Rustbucket.objects.filter(status='Active')

        for rustbucket in rustbuckets:
            # Check if rustbucket hasn't been seen recently
            if rustbucket.last_seen < threshold:
                # Check if we already have an unresolved alert for this
                existing_alert = Alert.objects.filter(
                    logsink__rustbucket=rustbucket,
                    message__contains='not responding',
                    is_resolved=False
                ).first()

                if not existing_alert:
                    # Find or create a logsink for health check alerts
                    logsink, _ = LogSink.objects.get_or_create(
                        rustbucket=rustbucket,
                        log_type='Warning',
                        defaults={
                            'size': '0 MB',
                            'status': 'Active',
                            'alert_level': 'high'
                        }
                    )

                    # Create a new alert
                    Alert.objects.create(
                        logsink=logsink,
                        type='warning',
                        severity='high',
                        message=f'Rustbucket {rustbucket.name} is not responding (last seen: {rustbucket.last_seen})',
                        is_resolved=False
                    )

                    unhealthy_count += 1
                    logger.warning(f"Rustbucket {rustbucket.id} is unhealthy")

        logger.info(f"Health check completed: {unhealthy_count} unhealthy rustbuckets found")

        return {
            'checked': rustbuckets.count(),
            'unhealthy': unhealthy_count
        }

    except Exception as e:
        logger.error(f"Error checking rustbucket health: {str(e)}", exc_info=True)
