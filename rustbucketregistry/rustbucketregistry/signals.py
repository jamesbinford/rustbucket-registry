"""
Django signals for Rustbucket Registry.

Handles automatic actions when models are saved/deleted.
"""
import logging

from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib.auth.models import User

from rustbucketregistry.models import UserProfile

logger = logging.getLogger(__name__)


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
