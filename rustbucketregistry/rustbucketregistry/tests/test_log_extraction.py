"""Tests for log extraction functionality.

This module contains unit tests for testing log extraction features including
log collection, S3 upload, and extraction processing.
"""
from unittest.mock import patch, MagicMock, mock_open
from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.auth.models import User
from django.utils import timezone
from django.conf import settings
import json
import requests
import boto3
from io import BytesIO

from rustbucketregistry.models import Rustbucket, LogSink
from rustbucketregistry.views.register import extract_logs_from_buckets, extract_logs


class LogExtractionTest(TestCase):
    """Tests for log extraction functionality."""

    def setUp(self):
        """Set up test data and client."""
        self.client = Client()
        
        # Create a test user for authentication
        self.admin_user = User.objects.create_user(
            username='adminuser',
            password='adminpass',
            is_staff=True
        )
        
        self.regular_user = User.objects.create_user(
            username='regularuser',
            password='regularpass',
            is_staff=False
        )
        
        # Create test rustbuckets with different statuses
        self.active_rustbucket = Rustbucket.objects.create(
            name="active-rustbucket",
            ip_address="192.168.1.1",
            operating_system="Linux",
            status="Active",
            token="test-token-active"
        )
        
        self.inactive_rustbucket = Rustbucket.objects.create(
            name="inactive-rustbucket",
            ip_address="192.168.1.2",
            operating_system="Windows",
            status="Inactive",
            token="test-token-inactive"
        )
    
    @patch('requests.get')
    @patch('boto3.client')
    def test_extract_logs_from_buckets_function(self, mock_boto3_client, mock_get):
        """Test the extract_logs_from_buckets function."""
        # Mock the S3 client
        mock_s3_client = MagicMock()
        mock_boto3_client.return_value = mock_s3_client
        
        # Mock the response from the rustbucket
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = b"Log line 1\nLog line 2\nLog line 3"
        mock_response.headers = {'Content-Type': 'text/plain'}
        mock_get.return_value = mock_response
        
        # Save the original settings
        original_aws_access_key = settings.AWS_ACCESS_KEY_ID
        original_aws_secret_key = settings.AWS_SECRET_ACCESS_KEY
        
        # Temporarily set AWS credentials for testing
        settings.AWS_ACCESS_KEY_ID = 'test-access-key'
        settings.AWS_SECRET_ACCESS_KEY = 'test-secret-key'
        
        try:
            # Call the function
            result = extract_logs_from_buckets()
            
            # Verify the function called requests.get with the correct URL and headers
            mock_get.assert_called_once_with(
                f"http://{self.active_rustbucket.ip_address}/extract_logs",
                headers={'Authorization': f"Token {self.active_rustbucket.token}"},
                timeout=30,
                stream=True
            )
            
            # Verify the function called boto3.client with the correct parameters
            mock_boto3_client.assert_called_once_with(
                's3',
                region_name=settings.AWS_S3_REGION,
                aws_access_key_id='test-access-key',
                aws_secret_access_key='test-secret-key'
            )
            
            # Verify the S3 client was called with the correct parameters
            mock_s3_client.upload_fileobj.assert_called_once()
            # In our test scenario, we're not validating the exact bucket name here
            # just that the method was called properly
            self.assertEqual(len(mock_s3_client.upload_fileobj.call_args[0]), 3)  # 3 arguments: fileobj, bucket, key
            
            # Verify the function returned the correct result
            self.assertEqual(result['status'], 'success')
            self.assertEqual(result['total'], 1)  # Only active rustbuckets
            self.assertEqual(result['extracted'], 1)
            self.assertEqual(result['failed'], 0)
            self.assertEqual(len(result['logs']), 1)
            
            # Verify a log sink was created for this extraction
            log_sink = LogSink.objects.filter(
                rustbucket=self.active_rustbucket,
                log_type='Log Extraction'
            ).first()
            self.assertIsNotNone(log_sink)
            
        finally:
            # Restore the original settings
            settings.AWS_ACCESS_KEY_ID = original_aws_access_key
            settings.AWS_SECRET_ACCESS_KEY = original_aws_secret_key
    
    @patch('requests.get')
    def test_extract_logs_from_buckets_connection_error(self, mock_get):
        """Test the extract_logs_from_buckets function with a connection error."""
        # Mock a connection error
        mock_get.side_effect = requests.RequestException("Connection error")
        
        # Call the function
        result = extract_logs_from_buckets()
        
        # Verify the function returned the correct result
        self.assertEqual(result['status'], 'success')
        self.assertEqual(result['total'], 1)  # Only active rustbuckets
        self.assertEqual(result['extracted'], 0)
        self.assertEqual(result['failed'], 1)
        self.assertEqual(len(result['logs']), 0)
    
    @patch('rustbucketregistry.api.views.extract_logs_from_buckets')
    def test_extract_logs_endpoint_authorized(self, mock_extract_logs):
        """Test the extract_logs endpoint with authorized user."""
        # Mock the extract_logs_from_buckets function
        mock_extract_logs.return_value = {
            'status': 'success',
            'total': 1,
            'extracted': 1,
            'failed': 0,
            'logs': [{'id': self.active_rustbucket.id, 'name': 'active-rustbucket'}]
        }
        
        # Login as admin
        self.client.login(username='adminuser', password='adminpass')
        
        # Call the endpoint
        url = reverse('extract_logs')
        response = self.client.get(url)
        
        # Verify the response
        self.assertEqual(response.status_code, 200)
        response_data = json.loads(response.content)
        self.assertEqual(response_data['status'], 'success')
        
        # Verify the function was called
        mock_extract_logs.assert_called_once()
    
    def test_extract_logs_endpoint_unauthorized(self):
        """Test the extract_logs endpoint with unauthorized user."""
        # Not logged in
        url = reverse('extract_logs')
        response = self.client.get(url)
        
        # Verify the response
        self.assertEqual(response.status_code, 401)
        
        # Login as regular user (non-staff)
        self.client.login(username='regularuser', password='regularpass')
        
        # Call the endpoint
        response = self.client.get(url)
        
        # Verify the response
        self.assertEqual(response.status_code, 401)