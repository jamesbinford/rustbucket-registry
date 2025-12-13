"""Tests for Django signal handlers.

This module contains unit tests for testing Django signal handlers including
automatic alert notifications and other signal-based functionality.
"""
from unittest.mock import patch, MagicMock
from django.test import TestCase
from django.db.models.signals import post_save

from rustbucketregistry.models import Rustbucket, LogSink, Alert, NotificationChannel
from rustbucketregistry.signals import alert_created_handler


class AlertSignalTest(TestCase):
    """Tests for alert creation signal handler."""

    def setUp(self):
        """Set up test data."""
        self.rustbucket = Rustbucket.objects.create(
            name='signal-test-bucket',
            ip_address='192.168.1.50',
            operating_system='Linux'
        )

        self.logsink = LogSink.objects.create(
            rustbucket=self.rustbucket,
            log_type='Error',
            size='10MB',
            alert_level='high'
        )

        # Create notification channels
        self.email_channel = NotificationChannel.objects.create(
            name='Email Alerts',
            channel_type='email',
            config={'recipients': ['admin@example.com']},
            min_severity='high',
            is_active=True
        )

        self.slack_channel = NotificationChannel.objects.create(
            name='Slack Alerts',
            channel_type='slack',
            config={'webhook_url': 'https://hooks.slack.com/test'},
            min_severity='medium',
            is_active=True
        )

    @patch('rustbucketregistry.notifications.send_alert_notification')
    def test_alert_created_triggers_notification(self, mock_send_notification):
        """Test that creating an alert triggers notification signal."""
        # Mock the notification function
        mock_send_notification.return_value = [
            {'success': True, 'message': 'Email sent'},
            {'success': True, 'message': 'Slack sent'}
        ]

        # Create a new alert (this should trigger the signal)
        alert = Alert.objects.create(
            logsink=self.logsink,
            rustbucket=self.rustbucket,
            type='error',
            severity='HIGH',
            message='Signal test alert'
        )

        # Verify that send_alert_notification was called
        mock_send_notification.assert_called_once_with(alert)

    @patch('rustbucketregistry.notifications.send_alert_notification')
    def test_alert_update_does_not_trigger_notification(self, mock_send_notification):
        """Test that updating an alert does not trigger notification signal."""
        # Create an alert first
        alert = Alert.objects.create(
            logsink=self.logsink,
            rustbucket=self.rustbucket,
            type='error',
            severity='HIGH',
            message='Original message'
        )

        # Reset the mock (creation already called it once)
        mock_send_notification.reset_mock()

        # Update the alert
        alert.message = 'Updated message'
        alert.save()

        # Verify that send_alert_notification was NOT called on update
        mock_send_notification.assert_not_called()

    @patch('rustbucketregistry.notifications.send_alert_notification')
    def test_alert_resolution_does_not_trigger_notification(self, mock_send_notification):
        """Test that resolving an alert does not trigger additional notification."""
        # Create an alert
        alert = Alert.objects.create(
            logsink=self.logsink,
            rustbucket=self.rustbucket,
            type='error',
            severity='HIGH',
            message='To be resolved'
        )

        # Reset the mock
        mock_send_notification.reset_mock()

        # Resolve the alert
        alert.is_resolved = True
        alert.save()

        # Verify notification was not sent
        mock_send_notification.assert_not_called()

    @patch('rustbucketregistry.notifications.send_alert_notification')
    def test_multiple_alerts_trigger_multiple_notifications(self, mock_send_notification):
        """Test that creating multiple alerts triggers multiple notifications."""
        # Create first alert
        alert1 = Alert.objects.create(
            logsink=self.logsink,
            rustbucket=self.rustbucket,
            type='error',
            severity='HIGH',
            message='First alert'
        )

        # Create second alert
        alert2 = Alert.objects.create(
            logsink=self.logsink,
            rustbucket=self.rustbucket,
            type='warning',
            severity='MEDIUM',
            message='Second alert'
        )

        # Verify notification was called twice
        self.assertEqual(mock_send_notification.call_count, 2)

    @patch('rustbucketregistry.notifications.send_alert_notification')
    def test_signal_handles_notification_failure_gracefully(self, mock_send_notification):
        """Test that signal handler doesn't crash if notification fails."""
        # Mock notification to raise an exception
        mock_send_notification.side_effect = Exception('Notification service down')

        # Create an alert - should not raise exception
        try:
            alert = Alert.objects.create(
                logsink=self.logsink,
                rustbucket=self.rustbucket,
                type='error',
                severity='HIGH',
                message='Test alert'
            )
            # If we get here, the signal handled the exception gracefully
            self.assertIsNotNone(alert.id)
        except Exception as e:
            self.fail(f'Signal handler did not handle exception gracefully: {e}')


class SignalHandlerDirectTest(TestCase):
    """Tests for calling signal handlers directly."""

    def setUp(self):
        """Set up test data."""
        self.rustbucket = Rustbucket.objects.create(
            name='direct-test-bucket',
            ip_address='192.168.1.60',
            operating_system='Ubuntu'
        )

        self.logsink = LogSink.objects.create(
            rustbucket=self.rustbucket,
            log_type='Error',
            size='5MB',
            alert_level='high'
        )

    @patch('rustbucketregistry.notifications.send_alert_notification')
    def test_alert_created_handler_direct_call_created_true(self, mock_send_notification):
        """Test calling alert_created_handler directly with created=True."""
        alert = Alert.objects.create(
            logsink=self.logsink,
            rustbucket=self.rustbucket,
            type='HIGH',
            severity='HIGH',
            message='Direct test'
        )

        # Reset mock from the automatic signal
        mock_send_notification.reset_mock()

        # Call handler directly with created=True
        alert_created_handler(sender=Alert, instance=alert, created=True)

        # Should call send_alert_notification
        mock_send_notification.assert_called_once_with(alert)

    @patch('rustbucketregistry.notifications.send_alert_notification')
    def test_alert_created_handler_direct_call_created_false(self, mock_send_notification):
        """Test calling alert_created_handler directly with created=False."""
        alert = Alert.objects.create(
            logsink=self.logsink,
            rustbucket=self.rustbucket,
            type='HIGH',
            severity='HIGH',
            message='Direct test'
        )

        # Reset mock
        mock_send_notification.reset_mock()

        # Call handler directly with created=False
        alert_created_handler(sender=Alert, instance=alert, created=False)

        # Should NOT call send_alert_notification
        mock_send_notification.assert_not_called()


class SignalConnectionTest(TestCase):
    """Tests to verify signals are properly connected."""

    def test_alert_post_save_signal_is_connected(self):
        """Test that the alert post_save signal is connected."""
        # Get all receivers for the Alert post_save signal
        receivers = post_save._live_receivers(Alert)

        # Check if our handler is in the receivers
        handler_connected = any(
            'alert_created_handler' in str(receiver)
            for receiver in receivers
        )

        self.assertTrue(
            handler_connected,
            'alert_created_handler is not connected to Alert post_save signal'
        )


class SignalWithNoChannelsTest(TestCase):
    """Tests for signal behavior when no notification channels exist."""

    def setUp(self):
        """Set up test data without notification channels."""
        self.rustbucket = Rustbucket.objects.create(
            name='no-channels-bucket',
            ip_address='192.168.1.70',
            operating_system='Debian'
        )

        self.logsink = LogSink.objects.create(
            rustbucket=self.rustbucket,
            log_type='Info',
            size='2MB',
            alert_level='low'
        )

    @patch('rustbucketregistry.notifications.send_alert_notification')
    def test_alert_creation_with_no_channels(self, mock_send_notification):
        """Test that alert creation works even with no notification channels."""
        # Mock to return empty list (no channels matched)
        mock_send_notification.return_value = []

        # Create alert
        alert = Alert.objects.create(
            logsink=self.logsink,
            rustbucket=self.rustbucket,
            type='info',
            severity='LOW',
            message='No channels test'
        )

        # Should still be called
        mock_send_notification.assert_called_once()

        # Alert should be created successfully
        self.assertIsNotNone(alert.id)


class SignalIntegrationTest(TestCase):
    """Integration tests for signal + notification flow."""

    def setUp(self):
        """Set up test data."""
        self.rustbucket = Rustbucket.objects.create(
            name='integration-bucket',
            ip_address='192.168.1.80',
            operating_system='RHEL'
        )

        self.logsink = LogSink.objects.create(
            rustbucket=self.rustbucket,
            log_type='Error',
            size='15MB',
            alert_level='high'
        )

        # Create email channel only
        self.email_channel = NotificationChannel.objects.create(
            name='Email Only',
            channel_type='email',
            config={'recipients': ['integration@example.com']},
            min_severity='high',
            is_active=True
        )

    def test_full_alert_notification_flow(self):
        """Test the complete flow from alert creation to email notification."""
        # Create a high severity alert
        alert = Alert.objects.create(
            logsink=self.logsink,
            rustbucket=self.rustbucket,
            type='error',
            severity='HIGH',
            message='Integration test alert'
        )

        # In a real scenario, email would be sent here via signal
        # We can verify the alert was created
        self.assertIsNotNone(alert.id)
        self.assertEqual(alert.severity, 'HIGH')

        # Verify it matches our channel's criteria
        from rustbucketregistry.notifications import should_notify
        self.assertTrue(should_notify(self.email_channel, alert))
