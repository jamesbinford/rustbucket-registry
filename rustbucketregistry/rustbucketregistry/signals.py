"""
Django signals for Rustbucket Registry.

Handles automatic actions when models are saved/deleted.
"""
import logging
import threading

from django.db import transaction
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib.auth.models import User

from rustbucketregistry.models import Alert, UserProfile

logger = logging.getLogger(__name__)


# =============================================================================
# User Profile Auto-Creation
# =============================================================================

@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    """
    Automatically create a UserProfile when a new User is created.

    Superusers get admin role, others get viewer role by default.
    """
    if created:
        role = 'admin' if instance.is_superuser else 'viewer'
        UserProfile.objects.create(
            user=instance,
            role=role,
            all_rustbuckets_access=instance.is_superuser
        )
        logger.info(f"Created UserProfile for {instance.username} with role '{role}'")


def _send_notifications_async(alert_id):
    """
    Send notifications for an alert in a background thread.

    Args:
        alert_id: The ID of the alert to send notifications for
    """
    try:
        # Import here to avoid circular imports
        from rustbucketregistry.notifications import send_alert_notification
        from rustbucketregistry.models import Alert

        # Re-fetch the alert to ensure we have a fresh database connection
        try:
            alert = Alert.objects.get(id=alert_id)
        except Alert.DoesNotExist:
            logger.error(f"Alert {alert_id} not found for notification")
            return

        results = send_alert_notification(alert)

        logger.info(
            f"Notifications sent for alert {alert_id}: "
            f"{results['sent']} successful, {results['failed']} failed"
        )

    except Exception as e:
        logger.error(
            f"Error sending notifications for alert {alert_id}: {str(e)}",
            exc_info=True
        )


@receiver(post_save, sender=Alert)
def alert_created_handler(sender, instance, created, **kwargs):
    """
    Handle Alert creation by sending notifications asynchronously.

    This signal is triggered after an Alert is saved. If it's a new alert
    (created=True), we schedule notification sending to run after the
    transaction commits. This ensures:
    1. The alert is fully persisted before notifications are sent
    2. Alert creation is not blocked by slow notification channels
    3. Tests work correctly (on_commit runs immediately in non-atomic tests)

    Args:
        sender: The model class (Alert)
        instance: The actual Alert instance
        created: Boolean indicating if this is a new record
        **kwargs: Additional keyword arguments
    """
    # Only send notifications for new alerts
    if created:
        logger.info(f"New alert created (ID: {instance.id}), scheduling notifications")

        # Use transaction.on_commit to ensure the alert is persisted before
        # spawning the notification thread
        def send_after_commit():
            thread = threading.Thread(
                target=_send_notifications_async,
                args=(instance.id,),
                daemon=True
            )
            thread.start()

        transaction.on_commit(send_after_commit)
