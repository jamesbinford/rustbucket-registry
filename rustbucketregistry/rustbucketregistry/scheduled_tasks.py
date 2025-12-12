"""
Scheduled tasks for the RustBucket Registry application.

These functions are called by APScheduler to perform automated maintenance,
monitoring, and data collection tasks.
"""
import logging
from datetime import timedelta
from django.utils import timezone
from django.db.models import Count

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
    - It hasn't been seen in over 15 minutes
    - Its status is 'Active' but not responding
    """
    try:
        from rustbucketregistry.models import Rustbucket, Alert, LogSink

        logger.info("Starting rustbucket health checks")

        unhealthy_count = 0
        threshold = timezone.now() - timedelta(minutes=15)

        # Get all rustbuckets that should be active
        rustbuckets = Rustbucket.objects.filter(status='Active')

        for rustbucket in rustbuckets:
            # Check if rustbucket hasn't been seen recently
            if rustbucket.last_seen < threshold:
                # Check if we already have an unresolved alert for this
                existing_alert = Alert.objects.filter(
                    rustbucket=rustbucket,
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
                        rustbucket=rustbucket,
                        type='warning',
                        severity='HIGH',
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


def cleanup_old_data():
    """
    Clean up old data to manage database size.

    This task:
    - Deletes resolved alerts older than 90 days
    - Deletes log entries older than 30 days
    """
    try:
        from rustbucketregistry.models import Alert, LogEntry

        logger.info("Starting data cleanup")

        cleanup_results = {}

        # Delete old resolved alerts (90 days)
        alert_threshold = timezone.now() - timedelta(days=90)
        deleted_alerts = Alert.objects.filter(
            is_resolved=True,
            resolved_at__lt=alert_threshold
        ).delete()
        cleanup_results['alerts_deleted'] = deleted_alerts[0]

        # Delete old log entries (30 days)
        log_threshold = timezone.now() - timedelta(days=30)
        deleted_logs = LogEntry.objects.filter(
            timestamp__lt=log_threshold
        ).delete()
        cleanup_results['logs_deleted'] = deleted_logs[0]

        logger.info(
            f"Data cleanup completed: {cleanup_results['alerts_deleted']} alerts, "
            f"{cleanup_results['logs_deleted']} logs deleted"
        )

        return cleanup_results

    except Exception as e:
        logger.error(f"Error during data cleanup: {str(e)}", exc_info=True)


def generate_daily_summary():
    """
    Generate a daily summary report of system activity.

    This creates a summary of:
    - New alerts in the last 24 hours
    - Honeypot activities
    - Rustbucket health status
    - Top attacking IPs
    """
    try:
        from rustbucketregistry.models import (
            Rustbucket, Alert, HoneypotActivity
        )

        logger.info("Generating daily summary report")

        # Get data from the last 24 hours
        since = timezone.now() - timedelta(days=1)

        # Count new alerts
        new_alerts = Alert.objects.filter(created_at__gte=since).count()

        # Count honeypot activities by type
        activities = HoneypotActivity.objects.filter(timestamp__gte=since)
        activity_counts = activities.values('type').annotate(count=Count('type'))

        # Count active rustbuckets
        active_rustbuckets = Rustbucket.objects.filter(status='Active').count()

        # Get top attacking IPs
        top_ips = (
            activities.values('source_ip')
            .annotate(count=Count('source_ip'))
            .order_by('-count')[:10]
        )

        summary = {
            'date': timezone.now().date().isoformat(),
            'new_alerts': new_alerts,
            'activity_counts': list(activity_counts),
            'active_rustbuckets': active_rustbuckets,
            'top_attacking_ips': list(top_ips),
            'total_activities': activities.count()
        }

        logger.info(f"Daily summary: {new_alerts} new alerts, {activities.count()} activities")

        return summary

    except Exception as e:
        logger.error(f"Error generating daily summary: {str(e)}", exc_info=True)
