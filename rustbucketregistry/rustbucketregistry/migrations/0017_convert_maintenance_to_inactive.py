"""Data migration to convert Maintenance status to Inactive.

This migration updates any existing rustbuckets with status='Maintenance'
to status='Inactive' as part of simplifying the status workflow.
"""
from django.db import migrations


def convert_maintenance_to_inactive(apps, schema_editor):
    """Convert all Maintenance status rustbuckets to Inactive."""
    Rustbucket = apps.get_model('rustbucketregistry', 'Rustbucket')
    updated = Rustbucket.objects.filter(status='Maintenance').update(status='Inactive')
    if updated:
        print(f'  Converted {updated} rustbucket(s) from Maintenance to Inactive')


def reverse_migration(apps, schema_editor):
    """Reverse migration is a no-op since we can't know which were originally Maintenance."""
    pass


class Migration(migrations.Migration):

    dependencies = [
        ('rustbucketregistry', '0016_standardize_alert_naming'),
    ]

    operations = [
        migrations.RunPython(convert_maintenance_to_inactive, reverse_migration),
    ]
