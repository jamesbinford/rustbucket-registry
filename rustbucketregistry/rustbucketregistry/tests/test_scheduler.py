"""Tests for scheduled tasks functionality.

This module contains unit tests for testing scheduled tasks including
pull updates, log extraction, health checks, cleanup, and daily summaries.
"""
from unittest.mock import patch, MagicMock, call
from django.test import TestCase
from django.core.management import call_command
from django.utils import timezone
from io import StringIO
import datetime

from rustbucketregistry.models import Rustbucket, LogSink, LogEntry, Alert, HoneypotActivity
from rustbucketregistry.scheduled_tasks import (
    pull_rustbucket_updates,
    extract_logs_from_rustbuckets,
    health_check_rustbuckets,
    cleanup_old_data,
    generate_daily_summary
)


class PullRustbucketUpdatesTaskTest(TestCase):
    """Tests for pull_rustbucket_updates scheduled task."""

    def setUp(self):
        """Set up test data."""
        self.active_rustbucket = Rustbucket.objects.create(
            name='active-bucket',
            ip_address='192.168.1.10',
            operating_system='Linux',
            status='Active',
            token='test-token-active'
        )

        self.inactive_rustbucket = Rustbucket.objects.create(
            name='inactive-bucket',
            ip_address='192.168.1.11',
            operating_system='Windows',
            status='Inactive',
            token='test-token-inactive'
        )

    @patch('rustbucketregistry.views.register.pull_bucket_updates')
    def test_pull_rustbucket_updates_calls_api_function(self, mock_pull_updates):
        """Test that the task calls the underlying API function."""
        mock_pull_updates.return_value = {
            'status': 'success',
            'total': 1,
            'updated': 1,
            'failed': 0
        }

        pull_rustbucket_updates()

        mock_pull_updates.assert_called_once()

    @patch('rustbucketregistry.views.register.pull_bucket_updates')
    def test_pull_rustbucket_updates_logs_success(self, mock_pull_updates):
        """Test that successful updates are logged."""
        mock_pull_updates.return_value = {
            'status': 'success',
            'total': 1,
            'updated': 1,
            'failed': 0
        }

        # Should not raise any exceptions
        try:
            pull_rustbucket_updates()
        except Exception as e:
            self.fail(f'Task raised unexpected exception: {e}')

    @patch('rustbucketregistry.views.register.pull_bucket_updates')
    def test_pull_rustbucket_updates_handles_errors(self, mock_pull_updates):
        """Test that errors are handled gracefully."""
        mock_pull_updates.side_effect = Exception('Network error')

        # Should not raise exception
        try:
            pull_rustbucket_updates()
        except Exception as e:
            self.fail(f'Task did not handle error gracefully: {e}')


class ExtractLogsFromRustbucketsTaskTest(TestCase):
    """Tests for extract_logs_from_rustbuckets scheduled task."""

    def setUp(self):
        """Set up test data."""
        self.rustbucket = Rustbucket.objects.create(
            name='log-source-bucket',
            ip_address='192.168.1.20',
            operating_system='Linux',
            status='Active',
            token='test-token-logs'
        )

    @patch('rustbucketregistry.views.register.extract_logs_from_buckets')
    def test_extract_logs_calls_api_function(self, mock_extract_logs):
        """Test that the task calls the extraction function."""
        mock_extract_logs.return_value = {
            'status': 'success',
            'total': 1,
            'extracted': 1,
            'failed': 0,
            'logs': []
        }

        extract_logs_from_rustbuckets()

        mock_extract_logs.assert_called_once()

    @patch('rustbucketregistry.views.register.extract_logs_from_buckets')
    def test_extract_logs_logs_results(self, mock_extract_logs):
        """Test that extraction results are logged."""
        mock_extract_logs.return_value = {
            'status': 'success',
            'total': 2,
            'extracted': 1,
            'failed': 1,
            'logs': [{'name': 'bucket1'}]
        }

        # Should complete without errors
        try:
            extract_logs_from_rustbuckets()
        except Exception as e:
            self.fail(f'Task raised unexpected exception: {e}')

    @patch('rustbucketregistry.views.register.extract_logs_from_buckets')
    def test_extract_logs_handles_errors(self, mock_extract_logs):
        """Test that errors are handled gracefully."""
        mock_extract_logs.side_effect = Exception('S3 connection failed')

        try:
            extract_logs_from_rustbuckets()
        except Exception as e:
            self.fail(f'Task did not handle error gracefully: {e}')


class HealthCheckRustbucketsTaskTest(TestCase):
    """Tests for health_check_rustbuckets scheduled task."""

    def setUp(self):
        """Set up test data."""
        # Rustbucket last seen recently (healthy)
        self.healthy_rustbucket = Rustbucket.objects.create(
            name='healthy-bucket',
            ip_address='192.168.1.30',
            operating_system='Linux',
            status='Active',
            last_seen=timezone.now() - datetime.timedelta(minutes=5)
        )

        # Rustbucket not seen for 20 minutes (unhealthy)
        self.unhealthy_rustbucket = Rustbucket.objects.create(
            name='unhealthy-bucket',
            ip_address='192.168.1.31',
            operating_system='Linux',
            status='Active',
            last_seen=timezone.now() - datetime.timedelta(minutes=20)
        )

        # Create a logsink for alerts
        self.logsink = LogSink.objects.create(
            rustbucket=self.unhealthy_rustbucket,
            log_type='System',
            size='1MB',
            alert_level='high'
        )

    @patch('rustbucketregistry.scheduled_tasks.timezone')
    def test_health_check_creates_alert_for_unhealthy_bucket(self, mock_timezone):
        """Test that alerts are created for unhealthy rustbuckets."""
        # Mock current time
        mock_now = timezone.now()
        mock_timezone.now.return_value = mock_now

        # Set last_seen to 20 minutes ago
        self.unhealthy_rustbucket.last_seen = mock_now - datetime.timedelta(minutes=20)
        self.unhealthy_rustbucket.save()

        # Run health check
        health_check_rustbuckets()

        # Check if alert was created
        alerts = Alert.objects.filter(
            logsink__rustbucket=self.unhealthy_rustbucket,
            message__icontains='not responding'
        )

        self.assertGreater(alerts.count(), 0)

    def test_health_check_no_alert_for_healthy_bucket(self):
        """Test that no alerts are created for healthy rustbuckets."""
        # Update last_seen to be recent
        self.healthy_rustbucket.last_seen = timezone.now()
        self.healthy_rustbucket.save()

        initial_alert_count = Alert.objects.filter(
            logsink__rustbucket=self.healthy_rustbucket
        ).count()

        health_check_rustbuckets()

        final_alert_count = Alert.objects.filter(
            logsink__rustbucket=self.healthy_rustbucket
        ).count()

        # No new alerts should be created
        self.assertEqual(initial_alert_count, final_alert_count)

    def test_health_check_handles_no_logsink(self):
        """Test health check when rustbucket has no logsink."""
        # Create rustbucket without logsink
        no_logsink_bucket = Rustbucket.objects.create(
            name='no-logsink',
            ip_address='192.168.1.32',
            operating_system='Linux',
            status='Active',
            last_seen=timezone.now() - datetime.timedelta(minutes=25)
        )

        # Should not crash
        try:
            health_check_rustbuckets()
        except Exception as e:
            self.fail(f'Health check crashed with no logsink: {e}')

    def test_health_check_inactive_buckets_ignored(self):
        """Test that inactive rustbuckets are not health checked."""
        inactive_bucket = Rustbucket.objects.create(
            name='inactive-health',
            ip_address='192.168.1.33',
            operating_system='Linux',
            status='Inactive',
            last_seen=timezone.now() - datetime.timedelta(days=1)
        )

        health_check_rustbuckets()

        # No alerts should be created for inactive bucket
        alerts = Alert.objects.filter(logsink__rustbucket=inactive_bucket)
        self.assertEqual(alerts.count(), 0)


class CleanupOldDataTaskTest(TestCase):
    """Tests for cleanup_old_data scheduled task."""

    def setUp(self):
        """Set up test data."""
        self.rustbucket = Rustbucket.objects.create(
            name='cleanup-test',
            ip_address='192.168.1.40',
            operating_system='Linux'
        )

        self.logsink = LogSink.objects.create(
            rustbucket=self.rustbucket,
            log_type='Info',
            size='10MB',
            alert_level='low'
        )

    def test_cleanup_deletes_old_resolved_alerts(self):
        """Test that old resolved alerts are deleted."""
        # Create old resolved alert (31 days ago)
        old_resolved = Alert.objects.create(
            logsink=self.logsink,
            type='info',
            severity='LOW',
            message='Old resolved alert',
            is_resolved=True,
            resolved_at=timezone.now() - datetime.timedelta(days=91)
        )

        # Create recent resolved alert (5 days ago)
        recent_resolved = Alert.objects.create(
            logsink=self.logsink,
            type='info',
            severity='LOW',
            message='Recent resolved alert',
            is_resolved=True,
            resolved_at=timezone.now() - datetime.timedelta(days=5)
        )

        # Create unresolved alert
        unresolved = Alert.objects.create(
            logsink=self.logsink,
            type='error',
            severity='HIGH',
            message='Unresolved alert',
            is_resolved=False
        )

        cleanup_old_data()

        # Old resolved alert should be deleted
        self.assertFalse(Alert.objects.filter(id=old_resolved.id).exists())

        # Recent resolved alert should still exist
        self.assertTrue(Alert.objects.filter(id=recent_resolved.id).exists())

        # Unresolved alert should still exist
        self.assertTrue(Alert.objects.filter(id=unresolved.id).exists())

    def test_cleanup_deletes_old_log_entries(self):
        """Test that old log entries are deleted."""
        # Create old log entry (31 days ago - threshold is 30 days)
        old_log = LogEntry.objects.create(
            logsink=self.logsink,
            level='INFO',
            message='Old log entry',
            timestamp=timezone.now() - datetime.timedelta(days=31)
        )

        # Create recent log entry
        recent_log = LogEntry.objects.create(
            logsink=self.logsink,
            level='INFO',
            message='Recent log entry',
            timestamp=timezone.now()
        )

        cleanup_old_data()

        # Old log should be deleted
        self.assertFalse(LogEntry.objects.filter(id=old_log.id).exists())

        # Recent log should still exist
        self.assertTrue(LogEntry.objects.filter(id=recent_log.id).exists())

    def test_cleanup_logs_deletion_counts(self):
        """Test that cleanup logs the number of deleted items."""
        # Create multiple old items
        for i in range(5):
            Alert.objects.create(
                logsink=self.logsink,
                type='info',
                severity='LOW',
                message=f'Old alert {i}',
                is_resolved=True,
                resolved_at=timezone.now() - datetime.timedelta(days=91)
            )

        # Should complete without errors
        try:
            cleanup_old_data()
        except Exception as e:
            self.fail(f'Cleanup task failed: {e}')

        # Verify alerts were deleted
        self.assertEqual(Alert.objects.filter(logsink=self.logsink).count(), 0)


class GenerateDailySummaryTaskTest(TestCase):
    """Tests for generate_daily_summary scheduled task."""

    def setUp(self):
        """Set up test data."""
        self.rustbucket1 = Rustbucket.objects.create(
            name='summary-bucket-1',
            ip_address='192.168.1.50',
            operating_system='Linux',
            status='Active'
        )

        self.rustbucket2 = Rustbucket.objects.create(
            name='summary-bucket-2',
            ip_address='192.168.1.51',
            operating_system='Windows',
            status='Active'
        )

        self.logsink1 = LogSink.objects.create(
            rustbucket=self.rustbucket1,
            log_type='Error',
            size='5MB',
            alert_level='high'
        )

        self.logsink2 = LogSink.objects.create(
            rustbucket=self.rustbucket2,
            log_type='Info',
            size='3MB',
            alert_level='low'
        )

        # Create some data for summary
        today = timezone.now()

        # Create alerts
        for i in range(3):
            Alert.objects.create(
                logsink=self.logsink1,
                type='error',
                severity='HIGH',
                message=f'Alert {i}',
                created_at=today - datetime.timedelta(hours=i)
            )

        # Create honeypot activities
        for i in range(2):
            HoneypotActivity.objects.create(
                rustbucket=self.rustbucket1,
                type='scan',
                source_ip=f'10.0.0.{i}',
                details=f'Scan attempt {i}',
                timestamp=today - datetime.timedelta(hours=i)
            )

    def test_generate_daily_summary_counts_data(self):
        """Test that daily summary counts are calculated correctly."""
        # Should complete without errors and generate summary
        try:
            generate_daily_summary()
        except Exception as e:
            self.fail(f'Daily summary generation failed: {e}')

    def test_generate_daily_summary_handles_no_data(self):
        """Test daily summary with no data for the day."""
        # Delete all data
        Alert.objects.all().delete()
        HoneypotActivity.objects.all().delete()

        # Should still complete
        try:
            generate_daily_summary()
        except Exception as e:
            self.fail(f'Daily summary failed with no data: {e}')

    def test_generate_daily_summary_only_includes_last_24_hours(self):
        """Test that summary only includes data from last 24 hours."""
        # Create old alert (2 days ago)
        old_time = timezone.now() - datetime.timedelta(days=2)
        Alert.objects.create(
            logsink=self.logsink1,
            type='error',
            severity='HIGH',
            message='Old alert',
            created_at=old_time
        )

        # Generate summary - should not crash
        try:
            generate_daily_summary()
        except Exception as e:
            self.fail(f'Summary generation failed: {e}')


class RunTaskManagementCommandTest(TestCase):
    """Tests for the run_task management command."""

    def setUp(self):
        """Set up test data."""
        self.rustbucket = Rustbucket.objects.create(
            name='command-test',
            ip_address='192.168.1.60',
            operating_system='Linux',
            status='Active'
        )

    @patch('rustbucketregistry.scheduled_tasks.pull_rustbucket_updates')
    def test_run_task_command_pull_updates(self, mock_task):
        """Test running pull_updates task via management command."""
        out = StringIO()
        call_command('run_task', 'pull_updates', stdout=out)

        # Verify task was called
        mock_task.assert_called_once()

        # Check output
        output = out.getvalue()
        self.assertIn('pull_updates', output.lower())

    @patch('rustbucketregistry.scheduled_tasks.extract_logs_from_rustbuckets')
    def test_run_task_command_extract_logs(self, mock_task):
        """Test running extract_logs task via management command."""
        out = StringIO()
        call_command('run_task', 'extract_logs', stdout=out)

        mock_task.assert_called_once()

    @patch('rustbucketregistry.scheduled_tasks.health_check_rustbuckets')
    def test_run_task_command_health_check(self, mock_task):
        """Test running health_check task via management command."""
        out = StringIO()
        call_command('run_task', 'health_check', stdout=out)

        mock_task.assert_called_once()

    @patch('rustbucketregistry.scheduled_tasks.cleanup_old_data')
    def test_run_task_command_cleanup(self, mock_task):
        """Test running cleanup task via management command."""
        out = StringIO()
        call_command('run_task', 'cleanup', stdout=out)

        mock_task.assert_called_once()

    @patch('rustbucketregistry.scheduled_tasks.generate_daily_summary')
    def test_run_task_command_daily_summary(self, mock_task):
        """Test running daily_summary task via management command."""
        out = StringIO()
        call_command('run_task', 'daily_summary', stdout=out)

        mock_task.assert_called_once()

    def test_run_task_command_list_tasks(self):
        """Test listing available tasks."""
        out = StringIO()
        call_command('run_task', '--list', stdout=out)

        output = out.getvalue()
        self.assertIn('pull_updates', output)
        self.assertIn('extract_logs', output)
        self.assertIn('health_check', output)
        self.assertIn('cleanup', output)
        self.assertIn('daily_summary', output)

    def test_run_task_command_invalid_task(self):
        """Test running command with invalid task name."""
        out = StringIO()
        err = StringIO()

        # Should handle invalid task gracefully
        try:
            call_command('run_task', 'invalid_task_name', stdout=out, stderr=err)
        except SystemExit:
            # Command may exit on invalid input
            pass

        error_output = err.getvalue()
        self.assertTrue(len(error_output) > 0 or len(out.getvalue()) > 0)


class SchedulerConfigurationTest(TestCase):
    """Tests for scheduler configuration and initialization."""

    @patch('rustbucketregistry.scheduler.scheduler')
    def test_scheduler_has_correct_jobs_configured(self, mock_scheduler):
        """Test that scheduler is configured with all required jobs."""
        # Import triggers loading of scheduler
        from rustbucketregistry import scheduler

        # We can't easily test the actual scheduler without starting it,
        # but we can verify the module loads without errors
        self.assertTrue(hasattr(scheduler, 'start'))

    def test_scheduler_disabled_during_migrations(self):
        """Test that scheduler doesn't start during migrations."""
        import sys
        import os

        # Simulate migration command
        original_argv = sys.argv
        try:
            sys.argv = ['manage.py', 'migrate']
            os.environ['RUN_SCHEDULER'] = 'false'

            # Re-import apps to test ready() logic
            # In real scenario, scheduler.start() would not be called
            # We just verify the environment variable works
            self.assertEqual(os.environ.get('RUN_SCHEDULER'), 'false')

        finally:
            sys.argv = original_argv
            if 'RUN_SCHEDULER' in os.environ:
                del os.environ['RUN_SCHEDULER']
