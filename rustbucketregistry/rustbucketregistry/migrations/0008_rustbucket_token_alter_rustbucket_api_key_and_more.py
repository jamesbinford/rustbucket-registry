# Generated by Django 5.2.1 on 2025-05-23 21:43

import uuid
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('rustbucketregistry', '0007_alter_rustbucket_status'),
    ]

    operations = [
        migrations.AddField(
            model_name='rustbucket',
            name='token',
            field=models.CharField(blank=True, help_text='Token provided by the Rustbucket for registration', max_length=255, null=True),
        ),
        migrations.AlterField(
            model_name='rustbucket',
            name='api_key',
            field=models.UUIDField(default=uuid.uuid4, editable=False, help_text='API key for rustbucket authentication (for backward compatibility)', unique=True),
        ),
        migrations.AlterField(
            model_name='rustbucket',
            name='connections',
            field=models.CharField(blank=True, help_text='Number of active connections', max_length=20, null=True),
        ),
    ]
