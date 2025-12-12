"""
Django app configuration for RustBucket Registry.
"""
from django.apps import AppConfig
import os


class RustbucketregistryConfig(AppConfig):
    """Configuration for the rustbucketregistry app."""

    default_auto_field = 'django.db.models.BigAutoField'
    name = 'rustbucketregistry'

    def ready(self):
        """
        Called when Django starts.

        This is where we start the APScheduler for background tasks.
        """
        # Only start scheduler if not running migrations or other management commands
        # that don't need the scheduler
        run_scheduler = os.environ.get('RUN_SCHEDULER', 'true').lower() == 'true'

        # Don't start scheduler during migrations or when explicitly disabled
        if run_scheduler:
            # Check if we're running the development server or in production
            # Avoid starting scheduler during migrations
            import sys
            if 'migrate' not in sys.argv and 'makemigrations' not in sys.argv:
                from rustbucketregistry import scheduler
                scheduler.start()
