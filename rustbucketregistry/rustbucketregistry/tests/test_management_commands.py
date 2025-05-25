"""Tests for Django management commands.

This module contains unit tests for testing Django management commands including
log analysis, log parsing, and other administrative commands.
"""
from unittest.mock import patch, MagicMock, call
from io import StringIO
from django.test import TestCase
from django.core.management import call_command
from django.utils import timezone
import json
import boto3

from rustbucketregistry.models import Rustbucket, LogSink, LogEntry
from rustbucketregistry.management.commands.parse_logs import Command as ParseLogsCommand


class ParseLogsCommandTest(TestCase):
    """Tests for the parse_logs management command."""

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
    
    @patch('boto3.client')
    def test_parse_logs_command_no_aws_credentials(self, mock_boto3_client):
        """Test the parse_logs command with no AWS credentials."""
        # Capture command output
        out = StringIO()
        
        # Call the command
        with patch('django.conf.settings.AWS_ACCESS_KEY_ID', ''):
            with patch('django.conf.settings.AWS_SECRET_ACCESS_KEY', ''):
                call_command('parse_logs', stdout=out)
        
        # Verify the output contains the warning about missing credentials
        self.assertIn('AWS credentials not provided', out.getvalue())
        
        # Verify boto3.client was not called
        mock_boto3_client.assert_not_called()
    
    @patch('boto3.client')
    def test_parse_logs_command_with_no_logs(self, mock_boto3_client):
        """Test the parse_logs command with no logs in S3."""
        # Mock the S3 client
        mock_s3_client = MagicMock()
        mock_boto3_client.return_value = mock_s3_client
        
        # Mock the list_objects_v2 response
        mock_s3_client.list_objects_v2.return_value = {}
        
        # Capture command output
        out = StringIO()
        
        # Call the command
        with patch('django.conf.settings.AWS_ACCESS_KEY_ID', 'test-access-key'):
            with patch('django.conf.settings.AWS_SECRET_ACCESS_KEY', 'test-secret-key'):
                call_command('parse_logs', stdout=out)
        
        # Verify the output contains the warning about no logs
        self.assertIn('No logs found in S3 bucket', out.getvalue())
    
    @patch('boto3.client')
    def test_parse_logs_command_with_logs(self, mock_boto3_client):
        """Test the parse_logs command with logs in S3."""
        # Mock the S3 client
        mock_s3_client = MagicMock()
        mock_boto3_client.return_value = mock_s3_client
        
        # Mock the list_objects_v2 response
        mock_s3_client.list_objects_v2.return_value = {
            'Contents': [
                {'Key': 'BKT123456_20220101120000_logs.txt'},
                {'Key': 'processed_BKT654321_20220101120000_logs.txt'}  # Already processed
            ]
        }
        
        # Mock the get_object response
        mock_body = MagicMock()
        mock_body.read.return_value = json.dumps({
            'level': 'ERROR',
            'message': 'Test error message',
            'source_ip': '192.168.1.2'
        }).encode('utf-8')
        
        mock_s3_client.get_object.return_value = {
            'Body': mock_body
        }
        
        # Capture command output
        out = StringIO()
        
        # Call the command
        with patch('django.conf.settings.AWS_ACCESS_KEY_ID', 'test-access-key'):
            with patch('django.conf.settings.AWS_SECRET_ACCESS_KEY', 'test-secret-key'):
                call_command('parse_logs', stdout=out)
        
        # Verify the S3 client was called with the correct parameters
        mock_s3_client.get_object.assert_called_once()
        args, kwargs = mock_s3_client.get_object.call_args
        self.assertEqual(kwargs['Key'], 'BKT123456_20220101120000_logs.txt')
        
        # Verify the file was marked as processed
        mock_s3_client.copy_object.assert_called_once()
        mock_s3_client.delete_object.assert_called_once()
        
        # Verify a log entry was created
        log_entry = LogEntry.objects.first()
        self.assertIsNotNone(log_entry)
        self.assertEqual(log_entry.level, 'ERROR')
        self.assertEqual(log_entry.message, 'Test error message')
        self.assertEqual(log_entry.source_ip, '192.168.1.2')
        
        # Verify the output contains the success message
        self.assertIn('Log parsing completed', out.getvalue())
    
    @patch('boto3.client')
    def test_parse_logs_command_with_invalid_filename(self, mock_boto3_client):
        """Test the parse_logs command with an invalid filename."""
        # Mock the S3 client
        mock_s3_client = MagicMock()
        mock_boto3_client.return_value = mock_s3_client
        
        # Mock the list_objects_v2 response
        mock_s3_client.list_objects_v2.return_value = {
            'Contents': [
                {'Key': 'invalid_filename.txt'}
            ]
        }
        
        # Capture command output
        out = StringIO()
        
        # Call the command
        with patch('django.conf.settings.AWS_ACCESS_KEY_ID', 'test-access-key'):
            with patch('django.conf.settings.AWS_SECRET_ACCESS_KEY', 'test-secret-key'):
                call_command('parse_logs', stdout=out)
        
        # Verify the output contains the warning about invalid filename
        self.assertIn('Invalid filename format', out.getvalue())