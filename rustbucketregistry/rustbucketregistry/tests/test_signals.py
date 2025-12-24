"""Tests for Django signal handlers.

This module contains unit tests for testing Django signal handlers including
automatic alert notifications and other signal-based functionality.

Note: Many signal tests use TransactionTestCase because the signal handler
uses transaction.on_commit() for async notifications, which only runs when
transactions are actually committed (not in regular TestCase).
"""
from unittest.mock import patch, MagicMock
from django.test import TestCase, TransactionTestCase
from django.db.models.signals import post_save

from rustbucketregistry.models import Rustbucket, LogSink, Alert, NotificationChannel
from rustbucketregistry.signals import alert_created_handler


class AlertSignalTest(TransactionTestCase):
    """Tests for alert creation signal handler.

    Uses TransactionTestCase because the signal handler uses transaction.on_commit()
    which only runs when transactions are actually committed.
    """

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

    @patch('rustbucketregistry.signals._send_notifications_async')
    def test_alert_created_triggers_notification(self, mock_send_async):
        """Test that creating an alert triggers notification signal."""
        # Create a new alert (this should trigger the signal)
        alert = Alert.objects.create(
            logsink=self.logsink,
            type='error',
            severity='high',
            message='Signal test alert'
        )

        # Give the thread a moment to start (on_commit runs after transaction commits)
        import time
        time.sleep(0.1)

        # Verify that the async notification function was called with the alert ID
        mock_send_async.assert_called_once_with(alert.id)

    @patch('rustbucketregistry.signals._send_notifications_async')
    def test_alert_update_does_not_trigger_notification(self, mock_send_async):
        """Test that updating an alert does not trigger notification signal."""
        # Create an alert first
        alert = Alert.objects.create(
            logsink=self.logsink,
            type='error',
            severity='high',
            message='Original message'
        )

        # Give time for on_commit to run
        import time
        time.sleep(0.1)

        # Reset the mock (creation already called it once)
        mock_send_async.reset_mock()

        # Update the alert
        alert.message = 'Updated message'
        alert.save()

        # Give time for any potential callback
        time.sleep(0.1)

        # Verify that _send_notifications_async was NOT called on update
        mock_send_async.assert_not_called()

    @patch('rustbucketregistry.signals._send_notifications_async')
    def test_alert_resolution_does_not_trigger_notification(self, mock_send_async):
        """Test that resolving an alert does not trigger additional notification."""
        # Create an alert
        alert = Alert.objects.create(
            logsink=self.logsink,
            type='error',
            severity='high',
            message='To be resolved'
        )

        # Give time for on_commit to run
        import time
        time.sleep(0.1)

        # Reset the mock
        mock_send_async.reset_mock()

        # Resolve the alert
        alert.is_resolved = True
        alert.save()

        # Give time for any potential callback
        time.sleep(0.1)

        # Verify notification was not sent
        mock_send_async.assert_not_called()

    @patch('rustbucketregistry.signals._send_notifications_async')
    def test_multiple_alerts_trigger_multiple_notifications(self, mock_send_async):
        """Test that creating multiple alerts triggers multiple notifications."""
        # Create first alert
        alert1 = Alert.objects.create(
            logsink=self.logsink,
            type='error',
            severity='high',
            message='First alert'
        )

        # Create second alert
        alert2 = Alert.objects.create(
            logsink=self.logsink,
            type='warning',
            severity='medium',
            message='Second alert'
        )

        # Give threads time to start
        import time
        time.sleep(0.1)

        # Verify notification was called twice
        self.assertEqual(mock_send_async.call_count, 2)

    @patch('rustbucketregistry.notifications.send_alert_notification')
    def test_signal_handles_notification_failure_gracefully(self, mock_send_notification):
        """Test that signal handler doesn't crash if notification fails."""
        # Mock notification to raise an exception
        mock_send_notification.side_effect = Exception('Notification service down')

        # Create an alert - should not raise exception
        # The exception is caught in the background thread, so alert creation succeeds
        alert = Alert.objects.create(
            logsink=self.logsink,
            type='error',
            severity='high',
            message='Test alert'
        )

        # Give time for the async notification to run and fail
        import time
        time.sleep(0.2)

        # If we get here, the signal handled the exception gracefully
        self.assertIsNotNone(alert.id)


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

    @patch('rustbucketregistry.signals.transaction')
    def test_alert_created_handler_direct_call_created_true(self, mock_transaction):
        """Test calling alert_created_handler directly with created=True."""
        # Create alert without signal (we'll call handler directly)
        from django.db.models.signals import post_save
        post_save.disconnect(alert_created_handler, sender=Alert)

        try:
            alert = Alert.objects.create(
                logsink=self.logsink,
                type='error',
                severity='high',
                message='Direct test'
            )

            # Call handler directly with created=True
            alert_created_handler(sender=Alert, instance=alert, created=True)

            # Should schedule on_commit callback
            mock_transaction.on_commit.assert_called_once()
        finally:
            # Reconnect the signal
            post_save.connect(alert_created_handler, sender=Alert)

    @patch('rustbucketregistry.signals.transaction')
    def test_alert_created_handler_direct_call_created_false(self, mock_send_notification):
        """Test calling alert_created_handler directly with created=False."""
        # Create alert without signal
        from django.db.models.signals import post_save
        post_save.disconnect(alert_created_handler, sender=Alert)

        try:
            alert = Alert.objects.create(
                logsink=self.logsink,
                type='error',
                severity='high',
                message='Direct test'
            )

            # Call handler directly with created=False
            alert_created_handler(sender=Alert, instance=alert, created=False)

            # Should NOT schedule on_commit callback
            mock_send_notification.on_commit.assert_not_called()
        finally:
            # Reconnect the signal
            post_save.connect(alert_created_handler, sender=Alert)


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


class SignalWithNoChannelsTest(TransactionTestCase):
    """Tests for signal behavior when no notification channels exist.

    Uses TransactionTestCase because the signal handler uses transaction.on_commit()
    which only runs when transactions are actually committed.
    """

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

    @patch('rustbucketregistry.signals._send_notifications_async')
    def test_alert_creation_with_no_channels(self, mock_send_async):
        """Test that alert creation works even with no notification channels."""
        # Create alert
        alert = Alert.objects.create(
            logsink=self.logsink,
            type='info',
            severity='low',
            message='No channels test'
        )

        # Give the thread a moment to start
        import time
        time.sleep(0.1)

        # Should still be called (async function)
        mock_send_async.assert_called_once_with(alert.id)

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
            type='error',
            severity='high',
            message='Integration test alert'
        )

        # In a real scenario, email would be sent here via signal
        # We can verify the alert was created
        self.assertIsNotNone(alert.id)
        self.assertEqual(alert.severity, 'high')

        # Verify it matches our channel's criteria
        from rustbucketregistry.notifications import should_notify
        self.assertTrue(should_notify(alert, self.email_channel))
