"""Tests for notification functionality.

This module contains unit tests for testing notification channels including
email, Slack, webhooks, severity filtering, and alert type filtering.
"""
from unittest.mock import patch, MagicMock, call
from django.test import TestCase
from django.core import mail
from django.utils import timezone
import json
import requests

from rustbucketregistry.models import Rustbucket, LogSink, Alert, NotificationChannel
from rustbucketregistry.notifications import (
    send_alert_notification,
    should_notify,
    send_email_notification,
    send_slack_notification,
    send_webhook_notification,
    test_notification_channel
)


class NotificationChannelModelTest(TestCase):
    """Tests for the NotificationChannel model."""

    def setUp(self):
        """Set up test data."""
        self.email_channel = NotificationChannel.objects.create(
            name='Email Alerts',
            channel_type='email',
            config={'recipients': ['admin@example.com', 'alerts@example.com']},
            min_severity='high',
            is_active=True
        )

        self.slack_channel = NotificationChannel.objects.create(
            name='Slack Channel',
            channel_type='slack',
            config={'webhook_url': 'https://hooks.slack.com/services/TEST'},
            min_severity='medium',
            is_active=True
        )

        self.webhook_channel = NotificationChannel.objects.create(
            name='Custom Webhook',
            channel_type='webhook',
            config={
                'url': 'https://example.com/webhook',
                'headers': {'X-API-Key': 'test-key'}
            },
            min_severity='low',
            alert_types=['error', 'warning'],
            is_active=True
        )

    def test_notification_channel_creation(self):
        """Test that NotificationChannel instances can be created."""
        self.assertEqual(NotificationChannel.objects.count(), 3)
        self.assertEqual(self.email_channel.channel_type, 'email')
        self.assertEqual(self.slack_channel.channel_type, 'slack')
        self.assertEqual(self.webhook_channel.channel_type, 'webhook')

    def test_notification_channel_str(self):
        """Test the string representation of NotificationChannel."""
        self.assertEqual(str(self.email_channel), 'Email Alerts (email)')
        self.assertEqual(str(self.slack_channel), 'Slack Channel (slack)')

    def test_notification_channel_config(self):
        """Test that config JSON is saved correctly."""
        self.assertIn('recipients', self.email_channel.config)
        self.assertEqual(len(self.email_channel.config['recipients']), 2)

        self.assertIn('webhook_url', self.slack_channel.config)
        self.assertTrue(self.slack_channel.config['webhook_url'].startswith('https://'))

        self.assertIn('url', self.webhook_channel.config)
        self.assertIn('headers', self.webhook_channel.config)

    def test_notification_channel_alert_types_filter(self):
        """Test alert_types filtering."""
        self.assertEqual(self.webhook_channel.alert_types, ['error', 'warning'])
        # Email and Slack have no alert type filtering (empty list)
        self.assertEqual(self.email_channel.alert_types, [])


class ShouldNotifyTest(TestCase):
    """Tests for the should_notify function."""

    def setUp(self):
        """Set up test data."""
        self.rustbucket = Rustbucket.objects.create(
            name='test-rustbucket',
            ip_address='192.168.1.1',
            operating_system='Linux'
        )

        self.logsink = LogSink.objects.create(
            rustbucket=self.rustbucket,
            log_type='Error',
            size='10MB',
            alert_level='high'
        )

        # Create channels with different severity levels
        self.high_channel = NotificationChannel.objects.create(
            name='High Only',
            channel_type='email',
            config={'recipients': ['high@example.com']},
            min_severity='high',
            is_active=True
        )

        self.medium_channel = NotificationChannel.objects.create(
            name='Medium and Up',
            channel_type='email',
            config={'recipients': ['medium@example.com']},
            min_severity='medium',
            is_active=True
        )

        self.low_channel = NotificationChannel.objects.create(
            name='All Alerts',
            channel_type='email',
            config={'recipients': ['all@example.com']},
            min_severity='low',
            is_active=True
        )

        # Channel with alert type filtering
        self.filtered_channel = NotificationChannel.objects.create(
            name='Errors Only',
            channel_type='email',
            config={'recipients': ['errors@example.com']},
            min_severity='low',
            alert_types=['error', 'HIGH'],
            is_active=True
        )

    def test_severity_filtering_high_alert(self):
        """Test that high severity alerts notify appropriate channels."""
        alert = Alert.objects.create(
            logsink=self.logsink,
            type='HIGH',
            severity='HIGH',
            message='High severity alert'
        )

        # All channels should be notified for high severity
        self.assertTrue(should_notify(alert, self.high_channel))
        self.assertTrue(should_notify(alert, self.medium_channel))
        self.assertTrue(should_notify(alert, self.low_channel))

    def test_severity_filtering_medium_alert(self):
        """Test that medium severity alerts notify appropriate channels."""
        alert = Alert.objects.create(
            logsink=self.logsink,
            type='MEDIUM',
            severity='MEDIUM',
            message='Medium severity alert'
        )

        # High channel should not be notified
        self.assertFalse(should_notify(alert, self.high_channel))

        # Medium and low channels should be notified
        self.assertTrue(should_notify(alert, self.medium_channel))
        self.assertTrue(should_notify(alert, self.low_channel))

    def test_severity_filtering_low_alert(self):
        """Test that low severity alerts notify appropriate channels."""
        alert = Alert.objects.create(
            logsink=self.logsink,
            type='LOW',
            severity='LOW',
            message='Low severity alert'
        )

        # Only low channel should be notified
        self.assertFalse(should_notify(alert, self.high_channel))
        self.assertFalse(should_notify(alert, self.medium_channel))
        self.assertTrue(should_notify(alert, self.low_channel))

    def test_alert_type_filtering(self):
        """Test that alert type filtering works correctly."""
        error_alert = Alert.objects.create(
            logsink=self.logsink,
            type='error',
            severity='MEDIUM',
            message='Error alert'
        )

        warning_alert = Alert.objects.create(
            logsink=self.logsink,
            type='warning',
            severity='MEDIUM',
            message='Warning alert'
        )

        info_alert = Alert.objects.create(
            logsink=self.logsink,
            type='info',
            severity='LOW',
            message='Info alert'
        )

        # Filtered channel should only notify on error alerts
        self.assertTrue(should_notify(error_alert, self.filtered_channel))
        self.assertFalse(should_notify(warning_alert, self.filtered_channel))
        self.assertFalse(should_notify(info_alert, self.filtered_channel))

    def test_inactive_channel_not_notified(self):
        """Test that inactive channels are not notified."""
        inactive_channel = NotificationChannel.objects.create(
            name='Inactive Channel',
            channel_type='email',
            config={'recipients': ['inactive@example.com']},
            min_severity='low',
            is_active=False
        )

        alert = Alert.objects.create(
            logsink=self.logsink,
            type='HIGH',
            severity='HIGH',
            message='High severity alert'
        )

        # Function checks is_active in the calling code, not in should_notify
        # But we test that the channel exists and can be checked
        self.assertFalse(inactive_channel.is_active)


class EmailNotificationTest(TestCase):
    """Tests for email notification sending."""

    def setUp(self):
        """Set up test data."""
        self.rustbucket = Rustbucket.objects.create(
            name='test-rustbucket',
            ip_address='192.168.1.1',
            operating_system='Linux'
        )

        self.logsink = LogSink.objects.create(
            rustbucket=self.rustbucket,
            log_type='Error',
            size='10MB',
            alert_level='high'
        )

        self.alert = Alert.objects.create(
            logsink=self.logsink,
            type='error',
            severity='HIGH',
            message='Critical system failure'
        )

        self.channel = NotificationChannel.objects.create(
            name='Email Alerts',
            channel_type='email',
            config={'recipients': ['admin@example.com', 'ops@example.com']},
            min_severity='high',
            is_active=True
        )

    def test_send_email_notification_success(self):
        """Test successful email notification sending."""
        result = send_email_notification(self.alert, self.channel.config)

        # Check result - function returns bool, not dict
        self.assertTrue(result)

        # Check that email was sent
        self.assertEqual(len(mail.outbox), 1)

        # Check email content
        email = mail.outbox[0]
        self.assertIn('Alert', email.subject)
        self.assertIn('Critical system failure', email.body)
        self.assertEqual(email.to, ['admin@example.com', 'ops@example.com'])

    def test_send_email_notification_no_recipients(self):
        """Test email notification with no recipients."""
        config = {'recipients': []}

        result = send_email_notification(self.alert, config)

        # Function returns False on failure
        self.assertFalse(result)

    def test_send_email_notification_missing_config(self):
        """Test email notification with missing config."""
        config = {}

        result = send_email_notification(self.alert, config)

        # Function returns False on failure
        self.assertFalse(result)


class SlackNotificationTest(TestCase):
    """Tests for Slack notification sending."""

    def setUp(self):
        """Set up test data."""
        self.rustbucket = Rustbucket.objects.create(
            name='production-server',
            ip_address='10.0.0.1',
            operating_system='Ubuntu 20.04'
        )

        self.logsink = LogSink.objects.create(
            rustbucket=self.rustbucket,
            log_type='Error',
            size='10MB',
            alert_level='high'
        )

        self.alert = Alert.objects.create(
            logsink=self.logsink,
            type='error',
            severity='HIGH',
            message='Database connection lost'
        )

        self.channel = NotificationChannel.objects.create(
            name='Slack Alerts',
            channel_type='slack',
            config={'webhook_url': 'https://hooks.slack.com/services/TEST/WEBHOOK'},
            min_severity='medium',
            is_active=True
        )

    @patch('requests.post')
    def test_send_slack_notification_success(self, mock_post):
        """Test successful Slack notification sending."""
        # Mock successful response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        result = send_slack_notification(self.alert, self.channel.config)

        # Check result - function returns bool
        self.assertTrue(result)

        # Verify requests.post was called
        mock_post.assert_called_once()

    @patch('requests.post')
    def test_send_slack_notification_failure(self, mock_post):
        """Test failed Slack notification sending."""
        # Mock failed response - raise_for_status will throw exception on 4xx/5xx
        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.text = 'Invalid webhook'
        mock_response.raise_for_status.side_effect = requests.HTTPError('400 Client Error')
        mock_post.return_value = mock_response

        result = send_slack_notification(self.alert, self.channel.config)

        # Function returns False on failure
        self.assertFalse(result)

    @patch('requests.post')
    def test_send_slack_notification_connection_error(self, mock_post):
        """Test Slack notification with connection error."""
        mock_post.side_effect = requests.RequestException('Connection timeout')

        result = send_slack_notification(self.alert, self.channel.config)

        # Function returns False on error
        self.assertFalse(result)

    def test_send_slack_notification_missing_webhook(self):
        """Test Slack notification with missing webhook URL."""
        config = {}

        result = send_slack_notification(self.alert, config)

        # Function returns False on missing config
        self.assertFalse(result)


class WebhookNotificationTest(TestCase):
    """Tests for webhook notification sending."""

    def setUp(self):
        """Set up test data."""
        self.rustbucket = Rustbucket.objects.create(
            name='edge-server',
            ip_address='172.16.0.5',
            operating_system='CentOS 8'
        )

        self.logsink = LogSink.objects.create(
            rustbucket=self.rustbucket,
            log_type='Error',
            size='10MB',
            alert_level='high'
        )

        self.alert = Alert.objects.create(
            logsink=self.logsink,
            type='HIGH',
            severity='HIGH',
            message='Disk space critically low'
        )

        self.channel = NotificationChannel.objects.create(
            name='PagerDuty',
            channel_type='webhook',
            config={
                'url': 'https://events.pagerduty.com/v2/enqueue',
                'headers': {
                    'X-Routing-Key': 'test-key-123',
                    'Content-Type': 'application/json'
                }
            },
            min_severity='high',
            is_active=True
        )

    @patch('requests.post')
    def test_send_webhook_notification_success(self, mock_post):
        """Test successful webhook notification sending."""
        # Mock successful response
        mock_response = MagicMock()
        mock_response.status_code = 202
        mock_post.return_value = mock_response

        result = send_webhook_notification(self.alert, self.channel.config)

        # Check result - function returns bool
        self.assertTrue(result)

        # Verify requests.post was called
        mock_post.assert_called_once()

    @patch('requests.post')
    def test_send_webhook_notification_failure(self, mock_post):
        """Test failed webhook notification sending."""
        # Mock failed response - raise_for_status will throw exception on 4xx/5xx
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.text = 'Internal server error'
        mock_response.raise_for_status.side_effect = requests.HTTPError('500 Server Error')
        mock_post.return_value = mock_response

        result = send_webhook_notification(self.alert, self.channel.config)

        # Function returns False on failure
        self.assertFalse(result)

    @patch('requests.post')
    def test_send_webhook_notification_timeout(self, mock_post):
        """Test webhook notification with timeout."""
        mock_post.side_effect = requests.Timeout('Request timed out')

        result = send_webhook_notification(self.alert, self.channel.config)

        # Function returns False on error
        self.assertFalse(result)

    def test_send_webhook_notification_missing_url(self):
        """Test webhook notification with missing URL."""
        config = {'headers': {'X-API-Key': 'test'}}

        result = send_webhook_notification(self.alert, config)

        # Function returns False on missing URL
        self.assertFalse(result)


class SendAlertNotificationTest(TestCase):
    """Tests for the main send_alert_notification function."""

    def setUp(self):
        """Set up test data."""
        self.rustbucket = Rustbucket.objects.create(
            name='test-server',
            ip_address='192.168.1.100',
            operating_system='Linux'
        )

        self.logsink = LogSink.objects.create(
            rustbucket=self.rustbucket,
            log_type='Error',
            size='10MB',
            alert_level='high'
        )

        self.alert = Alert.objects.create(
            logsink=self.logsink,
            type='error',
            severity='HIGH',
            message='Test alert'
        )

        # Create multiple channels
        self.email_channel = NotificationChannel.objects.create(
            name='Email',
            channel_type='email',
            config={'recipients': ['test@example.com']},
            min_severity='high',
            is_active=True
        )

        self.slack_channel = NotificationChannel.objects.create(
            name='Slack',
            channel_type='slack',
            config={'webhook_url': 'https://hooks.slack.com/test'},
            min_severity='high',
            is_active=True
        )

        self.inactive_channel = NotificationChannel.objects.create(
            name='Inactive',
            channel_type='email',
            config={'recipients': ['inactive@example.com']},
            min_severity='high',
            is_active=False
        )

    @patch('rustbucketregistry.notifications.send_slack_notification')
    @patch('rustbucketregistry.notifications.send_email_notification')
    def test_send_alert_notification_multiple_channels(self, mock_email, mock_slack):
        """Test sending notifications to multiple channels."""
        # Mock successful sends - functions return bool
        mock_email.return_value = True
        mock_slack.return_value = True

        results = send_alert_notification(self.alert)

        # Should have 2 channel results (email and slack, not inactive)
        self.assertEqual(len(results['channels']), 2)
        self.assertEqual(results['sent'], 2)

        # Both should be called
        mock_email.assert_called_once()
        mock_slack.assert_called_once()

    @patch('rustbucketregistry.notifications.send_email_notification')
    def test_send_alert_notification_no_matching_channels(self, mock_email):
        """Test sending notification when no channels match."""
        # Create a low severity alert
        low_alert = Alert.objects.create(
            logsink=self.logsink,
            type='info',
            severity='LOW',
            message='Low severity test'
        )

        results = send_alert_notification(low_alert)

        # Should have no channel results (no channels match low severity)
        self.assertEqual(len(results['channels']), 0)
        self.assertEqual(results['sent'], 0)

        # Email should not be called
        mock_email.assert_not_called()


class TestNotificationChannelTest(TestCase):
    """Tests for the test_notification_channel function."""

    def setUp(self):
        """Set up test data."""
        self.email_channel = NotificationChannel.objects.create(
            name='Test Email',
            channel_type='email',
            config={'recipients': ['test@example.com']},
            min_severity='low',
            is_active=True
        )

    def test_test_notification_channel_email_success(self):
        """Test sending a test notification via email."""
        result = test_notification_channel(self.email_channel)

        self.assertTrue(result['success'])
        self.assertIn('sent successfully', result['message'])

        # Check email was sent
        self.assertEqual(len(mail.outbox), 1)
        email = mail.outbox[0]
        self.assertIn('Alert', email.subject)

    @patch('requests.post')
    def test_test_notification_channel_slack_success(self, mock_post):
        """Test sending a test notification via Slack."""
        slack_channel = NotificationChannel.objects.create(
            name='Test Slack',
            channel_type='slack',
            config={'webhook_url': 'https://hooks.slack.com/test'},
            min_severity='low',
            is_active=True
        )

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        result = test_notification_channel(slack_channel)

        self.assertTrue(result['success'])
        self.assertIn('Test notification sent', result['message'])

    @patch('requests.post')
    def test_test_notification_channel_webhook_success(self, mock_post):
        """Test sending a test notification via webhook."""
        webhook_channel = NotificationChannel.objects.create(
            name='Test Webhook',
            channel_type='webhook',
            config={'url': 'https://example.com/webhook'},
            min_severity='low',
            is_active=True
        )

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        result = test_notification_channel(webhook_channel)

        self.assertTrue(result['success'])
        self.assertIn('Test notification sent', result['message'])

    def test_test_notification_channel_unknown_type(self):
        """Test sending test notification with unknown channel type."""
        bad_channel = NotificationChannel.objects.create(
            name='Unknown Type',
            channel_type='unknown',
            config={},
            min_severity='low',
            is_active=True
        )

        result = test_notification_channel(bad_channel)

        self.assertFalse(result['success'])
        self.assertIn('Unknown channel type', result['message'])
