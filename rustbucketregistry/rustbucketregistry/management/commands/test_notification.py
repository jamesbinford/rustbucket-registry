"""
Management command to test notification channels.

This is useful for verifying that notification channels are configured correctly.
"""
from django.core.management.base import BaseCommand
import logging

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Test notification channels'

    def add_arguments(self, parser):
        parser.add_argument(
            '--channel',
            type=str,
            help='Test a specific channel by name',
        )
        parser.add_argument(
            '--list',
            action='store_true',
            help='List all notification channels',
        )
        parser.add_argument(
            '--all',
            action='store_true',
            help='Test all active channels',
        )

    def handle(self, *args, **options):
        from rustbucketregistry.models import NotificationChannel
        from rustbucketregistry.notifications import test_notification_channel

        if options['list']:
            self.list_channels()
            return

        if options['all']:
            self.test_all_channels()
            return

        channel_name = options.get('channel')
        if channel_name:
            self.test_specific_channel(channel_name)
        else:
            self.stdout.write(
                self.style.WARNING(
                    'Please specify a channel name with --channel, use --all to test all channels, '
                    'or use --list to see available channels\n'
                    'Example: python manage.py test_notification --channel "Email Alerts"'
                )
            )

    def list_channels(self):
        """List all configured notification channels"""
        from rustbucketregistry.models import NotificationChannel

        channels = NotificationChannel.objects.all()

        if not channels:
            self.stdout.write(self.style.WARNING('No notification channels configured'))
            return

        self.stdout.write(self.style.SUCCESS('Configured Notification Channels:'))
        self.stdout.write('')

        for channel in channels:
            status = '✓ Active' if channel.is_active else '✗ Inactive'
            status_style = self.style.SUCCESS if channel.is_active else self.style.ERROR

            self.stdout.write(f'  {status_style(status)} {channel.name}')
            self.stdout.write(f'    Type: {channel.channel_type}')
            self.stdout.write(f'    Min Severity: {channel.min_severity}')
            if channel.alert_types:
                self.stdout.write(f'    Alert Types: {", ".join(channel.alert_types)}')
            self.stdout.write('')

    def test_specific_channel(self, channel_name):
        """Test a specific notification channel"""
        from rustbucketregistry.models import NotificationChannel
        from rustbucketregistry.notifications import test_notification_channel

        try:
            channel = NotificationChannel.objects.get(name=channel_name)
        except NotificationChannel.DoesNotExist:
            self.stdout.write(
                self.style.ERROR(f'Channel "{channel_name}" not found')
            )
            self.stdout.write('Use --list to see available channels')
            return

        self.stdout.write(f'Testing notification channel: {channel.name}')
        self.stdout.write(f'Type: {channel.channel_type}')
        self.stdout.write('')

        result = test_notification_channel(channel)

        if result['success']:
            self.stdout.write(
                self.style.SUCCESS(f'✓ {result["message"]}')
            )
        else:
            self.stdout.write(
                self.style.ERROR(f'✗ {result["message"]}')
            )

    def test_all_channels(self):
        """Test all active notification channels"""
        from rustbucketregistry.models import NotificationChannel
        from rustbucketregistry.notifications import test_notification_channel

        channels = NotificationChannel.objects.filter(is_active=True)

        if not channels:
            self.stdout.write(self.style.WARNING('No active notification channels found'))
            return

        self.stdout.write(f'Testing {channels.count()} active channel(s)...')
        self.stdout.write('')

        success_count = 0
        fail_count = 0

        for channel in channels:
            self.stdout.write(f'Testing {channel.name} ({channel.channel_type})...')

            result = test_notification_channel(channel)

            if result['success']:
                self.stdout.write(self.style.SUCCESS(f'  ✓ {result["message"]}'))
                success_count += 1
            else:
                self.stdout.write(self.style.ERROR(f'  ✗ {result["message"]}'))
                fail_count += 1

            self.stdout.write('')

        # Summary
        self.stdout.write('─' * 50)
        if success_count > 0:
            self.stdout.write(
                self.style.SUCCESS(f'✓ {success_count} channel(s) tested successfully')
            )
        if fail_count > 0:
            self.stdout.write(
                self.style.ERROR(f'✗ {fail_count} channel(s) failed')
            )
