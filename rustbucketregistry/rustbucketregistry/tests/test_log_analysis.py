"""Tests for log analysis functionality.

This module contains unit tests for testing log analysis features including
log parsing, threat detection, and analytics processing.
"""
from unittest.mock import patch, MagicMock
from io import StringIO
from django.test import TestCase, TransactionTestCase
from django.core.management import call_command
from django.db import connection, transaction
from django.utils import timezone
import json
import anthropic
from datetime import timedelta

from rustbucketregistry.models import Rustbucket, LogSink, LogEntry
from rustbucketregistry.management.commands.analyze_logs import Command as AnalyzeLogsCommand


class LogAnalysisCommandTest(TransactionTestCase):
    """Tests for the analyze_logs management command."""

    def setUp(self):
        """Set up test data."""
        self.rustbucket = Rustbucket.objects.create(
            id="BKT123456",
            name="test-rustbucket",
            ip_address="192.168.1.1",
            operating_system="Linux",
            status="Active",
            token="test-token-active"
        )
        
        # Create a log sink
        self.log_sink = LogSink.objects.create(
            rustbucket=self.rustbucket,
            log_type="Error",
            size="10MB",
            status="Active",
            alert_level="high"
        )
        
        # Create some log entries
        self.log_entries = []
        for i in range(5):
            log_entry = LogEntry.objects.create(
                logsink=self.log_sink,
                rustbucket=self.rustbucket,
                level="ERROR",
                message=f"Test error message {i}",
                timestamp=timezone.now() - timedelta(hours=1)  # Within the analysis window
            )
            self.log_entries.append(log_entry)
        
        # Create the log_analysis table if it doesn't exist
        with connection.cursor() as cursor:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS log_analysis (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    name VARCHAR(255) NOT NULL,
                    ip_address VARCHAR(255) NOT NULL,
                    log_analysis TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
    
    def tearDown(self):
        """Clean up after tests."""
        # Drop the log_analysis table
        with connection.cursor() as cursor:
            cursor.execute("DROP TABLE IF EXISTS log_analysis")
    
    def test_analyze_logs_command_no_claude_api_key(self):
        """Test the analyze_logs command with no Claude API key."""
        # Capture command output
        out = StringIO()
        
        # Call the command
        with patch('os.getenv', return_value=None):
            call_command('analyze_logs', stdout=out)
        
        # Verify the output contains the warning about missing API key
        self.assertIn('Claude API key not provided', out.getvalue())
    
    @patch('anthropic.Anthropic')
    @patch('os.getenv')
    def test_analyze_logs_command_with_logs(self, mock_getenv, mock_anthropic_client):
        """Test the analyze_logs command with logs to analyze."""
        # Mock the getenv function to return an API key
        mock_getenv.return_value = 'test-api-key'
        
        # Mock the Anthropic client
        mock_client = MagicMock()
        mock_anthropic_client.return_value = mock_client
        
        # Mock the messages.create response
        mock_message = MagicMock()
        mock_content = MagicMock()
        mock_content.text = "This is a test analysis of the logs."
        mock_message.content = [mock_content]
        mock_client.messages.create.return_value = mock_message
        
        # Capture command output
        out = StringIO()
        
        # Call the command
        call_command('analyze_logs', stdout=out)
        
        # Verify the anthropic.Anthropic constructor was called with the correct API key
        mock_anthropic_client.assert_called_once_with(api_key='test-api-key')
        
        # Verify the messages.create method was called
        mock_client.messages.create.assert_called_once()
        
        # Verify the output contains the success message
        self.assertIn('Successfully analyzed logs', out.getvalue())
        
        # Check that an entry was added to the log_analysis table
        with connection.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) FROM log_analysis")
            count = cursor.fetchone()[0]
            self.assertEqual(count, 1)
            
            cursor.execute("SELECT log_analysis FROM log_analysis LIMIT 1")
            analysis_text = cursor.fetchone()[0]
            self.assertEqual(analysis_text, "This is a test analysis of the logs.")
    
    @patch('anthropic.Anthropic')
    @patch('os.getenv')
    def test_analyze_logs_command_with_api_error(self, mock_getenv, mock_anthropic_client):
        """Test the analyze_logs command with an API error."""
        # Mock the getenv function to return an API key
        mock_getenv.return_value = 'test-api-key'
        
        # Mock the Anthropic client
        mock_client = MagicMock()
        mock_anthropic_client.return_value = mock_client
        
        # Mock the messages.create method to raise an exception
        mock_request = MagicMock()
        mock_client.messages.create.side_effect = Exception("API Error")
        
        # Capture command output
        out = StringIO()
        
        # Call the command
        call_command('analyze_logs', stdout=out)
        
        # Verify the output contains the error message
        self.assertIn('Error calling Claude API', out.getvalue())
        
        # Check that no entry was added to the log_analysis table
        with connection.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) FROM log_analysis")
            count = cursor.fetchone()[0]
            self.assertEqual(count, 0)
    
    @patch('anthropic.Anthropic')
    @patch('os.getenv')
    def test_analyze_logs_command_no_recent_logs(self, mock_getenv, mock_anthropic_client):
        """Test the analyze_logs command with no recent logs."""
        # Delete the recent logs and create an old one
        LogEntry.objects.all().delete()
        old_log = LogEntry.objects.create(
            logsink=self.log_sink,
            rustbucket=self.rustbucket,
            level="ERROR",
            message="Old error message",
            timestamp=timezone.now() - timedelta(days=1)  # Outside the analysis window
        )
        
        # Mock the getenv function to return an API key
        mock_getenv.return_value = 'test-api-key'
        
        # Capture command output
        out = StringIO()
        
        # Call the command
        with patch('django.conf.settings.LOG_ANALYSIS_INTERVAL_HOURS', 4):
            call_command('analyze_logs', stdout=out)
        
        # Verify the output contains the warning about no recent logs
        self.assertIn('No recent logs found', out.getvalue())
        
        # Verify the anthropic.Anthropic constructor was not called
        mock_anthropic_client.assert_not_called()