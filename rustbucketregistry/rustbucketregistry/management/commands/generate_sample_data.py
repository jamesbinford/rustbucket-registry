"""
Management command to generate sample/demo data for the RustBucket Registry.

This command creates realistic sample data for testing and demonstration
purposes, including log sinks and alerts.
"""
import random

from django.core.management.base import BaseCommand

from rustbucketregistry.models import Rustbucket, LogSink, Alert


class Command(BaseCommand):
    help = 'Generate sample data for testing and demonstration'

    def add_arguments(self, parser):
        parser.add_argument(
            '--clear',
            action='store_true',
            help='Clear existing sample data before generating new data'
        )
        parser.add_argument(
            '--logsinks',
            type=int,
            default=10,
            help='Number of log sinks to generate per rustbucket (default: 10)'
        )

    def handle(self, *args, **options):
        if options['clear']:
            self.stdout.write('Clearing existing sample data...')
            Alert.objects.all().delete()
            LogSink.objects.all().delete()

        rustbuckets = Rustbucket.objects.all()
        if not rustbuckets.exists():
            self.stderr.write(
                self.style.ERROR('No rustbuckets found. Create rustbuckets first.')
            )
            return

        self.stdout.write(f'Generating sample data for {rustbuckets.count()} rustbuckets...')

        # Generate log sinks and alerts
        for rustbucket in rustbuckets:
            self._generate_logsinks(rustbucket, options['logsinks'])

        self.stdout.write(self.style.SUCCESS('Sample data generated successfully!'))

    def _generate_logsinks(self, rustbucket, count):
        """Generate log sinks with alerts for a rustbucket."""
        log_types = ['Error', 'Warning', 'Info', 'Debug']
        statuses = ['Active', 'Inactive']

        for _ in range(count):
            log_type = random.choice(log_types)

            # Determine alert level based on log type
            if log_type == 'Error':
                alert_level = 'high'
            elif log_type == 'Warning':
                alert_level = 'medium'
            else:
                alert_level = 'low'

            logsink = LogSink.objects.create(
                rustbucket=rustbucket,
                log_type=log_type,
                size=f'{random.randint(10, 500)} MB',
                status=random.choice(statuses),
                alert_level=alert_level
            )

            # Generate alerts for non-debug logs
            if log_type != 'Debug':
                num_alerts = random.randint(0, 3)
                for _ in range(num_alerts):
                    Alert.objects.create(
                        logsink=logsink,
                        type=log_type.lower() if log_type in ['Error', 'Warning'] else 'info',
                        severity=alert_level,
                        message=self._generate_alert_message(log_type)
                    )

        self.stdout.write(f'  Created logsinks for {rustbucket.name}')

    def _generate_alert_message(self, log_type):
        """Generate an alert message based on log type."""
        messages = {
            'Error': ['Disk failure', 'Connection lost', 'Service down', 'Memory leak'],
            'Warning': ['High CPU', 'Low disk space', 'Network latency', 'Memory pressure'],
            'Info': ['Update needed', 'New version', 'Restarted service', 'Config changed']
        }
        return random.choice(messages.get(log_type, messages['Info']))
