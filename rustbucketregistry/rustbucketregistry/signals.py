"""
Django signals for Rustbucket Registry.

Handles automatic actions when models are saved/deleted.
"""
import logging
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


@receiver(post_save, sender=Alert)
def alert_created_handler(sender, instance, created, **kwargs):
    """
    Handle Alert creation by sending notifications.

    This signal is triggered after an Alert is saved. If it's a new alert
    (created=True), we send notifications through all configured channels.

    Args:
        sender: The model class (Alert)
        instance: The actual Alert instance
        created: Boolean indicating if this is a new record
        **kwargs: Additional keyword arguments
    """
    # Only send notifications for new alerts
    if created:
        logger.info(f"New alert created (ID: {instance.id}), sending notifications")

        try:
            from rustbucketregistry.notifications import send_alert_notification

            # Send notifications (runs synchronously for now)
            results = send_alert_notification(instance)

            logger.info(
                f"Notifications sent for alert {instance.id}: "
                f"{results['sent']} successful, {results['failed']} failed"
            )

        except Exception as e:
            # Don't fail the alert creation if notifications fail
            logger.error(
                f"Error sending notifications for alert {instance.id}: {str(e)}",
                exc_info=True
            )
