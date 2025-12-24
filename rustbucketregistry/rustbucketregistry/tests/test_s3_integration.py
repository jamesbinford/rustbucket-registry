"""Tests for S3 integration functionality.

This module contains unit tests for testing S3 bucket configuration including
per-rustbucket S3 settings, S3-to-S3 log copying, and fallback to HTTP.
"""
from unittest.mock import patch, MagicMock, call
from datetime import timedelta
from django.test import TestCase, Client
from django.urls import reverse
from django.utils import timezone
import json
import boto3

from rustbucketregistry.models import Rustbucket
from rustbucketregistry.views.register import extract_logs_from_s3, extract_logs_from_buckets


class RustbucketS3ConfigurationTest(TestCase):
    """Tests for Rustbucket S3 configuration fields and methods."""

    def setUp(self):
        """Set up test data."""
        # Rustbucket with full S3 configuration
        self.s3_rustbucket = Rustbucket.objects.create(
            name='s3-enabled-bucket',
            ip_address='192.168.1.100',
            operating_system='Linux',
            s3_bucket_name='rustbucket-logs-prod',
            s3_region='us-west-2',
            s3_prefix='logs/production/'
        )

        # Rustbucket with minimal S3 configuration
        self.iam_rustbucket = Rustbucket.objects.create(
            name='iam-bucket',
            ip_address='192.168.1.101',
            operating_system='Linux',
            s3_bucket_name='rustbucket-logs-staging',
            s3_region='us-east-1',
            s3_prefix='logs/'
        )

        # Rustbucket without S3 configuration
        self.no_s3_rustbucket = Rustbucket.objects.create(
            name='no-s3-bucket',
            ip_address='192.168.1.102',
            operating_system='Windows'
        )

    def test_has_s3_configured_with_full_config(self):
        """Test has_s3_configured returns True when S3 is fully configured."""
        self.assertTrue(self.s3_rustbucket.has_s3_configured())

    def test_has_s3_configured_with_iam_config(self):
        """Test has_s3_configured returns True with bucket name and region only."""
        self.assertTrue(self.iam_rustbucket.has_s3_configured())

    def test_has_s3_configured_without_bucket_name(self):
        """Test has_s3_configured returns False without bucket name."""
        self.assertFalse(self.no_s3_rustbucket.has_s3_configured())

    def test_has_s3_configured_with_only_bucket_name(self):
        """Test has_s3_configured with only bucket name (missing region)."""
        partial_bucket = Rustbucket.objects.create(
            name='partial-config',
            ip_address='192.168.1.103',
            operating_system='Linux',
            s3_bucket_name='test-bucket'
            # No region specified
        )
        # Should still work because region has a default
        self.assertTrue(partial_bucket.has_s3_configured())

    @patch('boto3.client')
    def test_get_s3_client_uses_iam_roles(self, mock_boto3_client):
        """Test get_s3_client uses IAM roles (no credentials stored)."""
        mock_client = MagicMock()
        mock_boto3_client.return_value = mock_client

        client = self.s3_rustbucket.get_s3_client()

        # Verify boto3.client was called with only region (uses IAM roles)
        mock_boto3_client.assert_called_once_with(
            's3',
            region_name='us-west-2'
        )

        self.assertEqual(client, mock_client)

    @patch('boto3.client')
    def test_get_s3_client_different_region(self, mock_boto3_client):
        """Test get_s3_client with different region."""
        mock_client = MagicMock()
        mock_boto3_client.return_value = mock_client

        client = self.iam_rustbucket.get_s3_client()

        # Verify boto3.client was called with correct region
        mock_boto3_client.assert_called_once_with(
            's3',
            region_name='us-east-1'
        )

        self.assertEqual(client, mock_client)

    def test_get_s3_client_without_configuration(self):
        """Test get_s3_client returns None when S3 is not configured."""
        client = self.no_s3_rustbucket.get_s3_client()
        self.assertIsNone(client)

    def test_s3_prefix_default_value(self):
        """Test that s3_prefix has correct default value."""
        # Create rustbucket without specifying prefix
        bucket = Rustbucket.objects.create(
            name='default-prefix-test',
            ip_address='192.168.1.104',
            operating_system='Linux',
            s3_bucket_name='test-bucket',
            s3_region='us-east-1'
        )

        # Check default prefix
        self.assertEqual(bucket.s3_prefix, 'logs/')

    def test_s3_region_default_value(self):
        """Test that s3_region has correct default value."""
        bucket = Rustbucket.objects.create(
            name='default-region-test',
            ip_address='192.168.1.105',
            operating_system='Linux',
            s3_bucket_name='test-bucket'
        )

        # Check default region
        self.assertEqual(bucket.s3_region, 'us-east-1')


class ExtractLogsFromS3Test(TestCase):
    """Tests for extract_logs_from_s3 function."""

    def setUp(self):
        """Set up test data."""
        self.rustbucket = Rustbucket.objects.create(
            name='s3-log-source',
            ip_address='192.168.1.110',
            operating_system='Linux',
            s3_bucket_name='source-logs-bucket',
            s3_region='us-west-2',
            s3_prefix='logs/'
        )

    @patch('boto3.client')
    def test_extract_logs_from_s3_success(self, mock_boto3_client):
        """Test successful S3-to-S3 log extraction."""
        # Mock the rustbucket's S3 client
        mock_rustbucket_s3 = MagicMock()

        # Mock list_objects_v2 response
        mock_rustbucket_s3.list_objects_v2.return_value = {
            'Contents': [
                {
                    'Key': 'logs/2025-12-11.log',
                    'LastModified': timezone.now() - timedelta(days=2),
                    'Size': 1000
                },
                {
                    'Key': 'logs/2025-12-12.log',
                    'LastModified': timezone.now() - timedelta(days=1),
                    'Size': 2000
                },
                {
                    'Key': 'logs/2025-12-13.log',
                    'LastModified': timezone.now(),
                    'Size': 3000
                }
            ]
        }

        # Mock the registry's S3 client
        mock_registry_s3 = MagicMock()
        mock_boto3_client.return_value = mock_rustbucket_s3

        # Mock get_s3_client to return our mock
        with patch.object(self.rustbucket, 'get_s3_client', return_value=mock_rustbucket_s3):
            result = extract_logs_from_s3(self.rustbucket, mock_registry_s3)

        # Verify result
        self.assertIsNotNone(result)
        self.assertEqual(result['name'], 's3-log-source')
        self.assertEqual(result['method'], 's3')
        self.assertIn('file_name', result)

        # Verify list_objects_v2 was called
        mock_rustbucket_s3.list_objects_v2.assert_called_once_with(
            Bucket='source-logs-bucket',
            Prefix='logs/',
            MaxKeys=10
        )

        # Verify copy operation was called
        mock_registry_s3.copy.assert_called_once()

    @patch('boto3.client')
    def test_extract_logs_from_s3_no_files(self, mock_boto3_client):
        """Test S3 extraction when no log files exist."""
        mock_rustbucket_s3 = MagicMock()

        # Mock empty response
        mock_rustbucket_s3.list_objects_v2.return_value = {}

        mock_registry_s3 = MagicMock()

        with patch.object(self.rustbucket, 'get_s3_client', return_value=mock_rustbucket_s3):
            result = extract_logs_from_s3(self.rustbucket, mock_registry_s3)

        # Should return None when no files found
        self.assertIsNone(result)

        # Verify copy was not called
        mock_registry_s3.copy_object.assert_not_called()

    @patch('boto3.client')
    def test_extract_logs_from_s3_connection_error(self, mock_boto3_client):
        """Test S3 extraction with connection error."""
        mock_rustbucket_s3 = MagicMock()

        # Mock exception
        mock_rustbucket_s3.list_objects_v2.side_effect = Exception('Connection timeout')

        mock_registry_s3 = MagicMock()

        with patch.object(self.rustbucket, 'get_s3_client', return_value=mock_rustbucket_s3):
            result = extract_logs_from_s3(self.rustbucket, mock_registry_s3)

        # Should return None on error
        self.assertIsNone(result)

    @patch('boto3.client')
    def test_extract_logs_from_s3_filters_most_recent(self, mock_boto3_client):
        """Test that extract_logs_from_s3 selects the most recent file."""
        mock_rustbucket_s3 = MagicMock()

        # Mock files with different timestamps
        old_time = timezone.now() - timedelta(days=5)
        recent_time = timezone.now() - timedelta(hours=1)
        oldest_time = timezone.now() - timedelta(days=10)

        mock_rustbucket_s3.list_objects_v2.return_value = {
            'Contents': [
                {'Key': 'logs/old.log', 'LastModified': old_time, 'Size': 1000},
                {'Key': 'logs/recent.log', 'LastModified': recent_time, 'Size': 2000},
                {'Key': 'logs/oldest.log', 'LastModified': oldest_time, 'Size': 500}
            ]
        }

        mock_registry_s3 = MagicMock()

        with patch.object(self.rustbucket, 'get_s3_client', return_value=mock_rustbucket_s3):
            result = extract_logs_from_s3(self.rustbucket, mock_registry_s3)

        # Should copy the most recent file
        self.assertIsNotNone(result)
        self.assertIn('recent.log', result['file_name'])


class RegistrationWithS3ConfigTest(TestCase):
    """Tests for rustbucket registration with S3 configuration."""

    def setUp(self):
        """Set up test client."""
        self.client = Client()

    def test_register_rustbucket_with_s3_config(self):
        """Test registering a rustbucket with S3 configuration."""
        url = reverse('register_rustbucket')
        data = {
            'name': 's3-enabled-rustbucket',
            'ip_address': '10.0.0.50',
            'operating_system': 'Ubuntu 22.04',
            'token': 'test-token-s3-123',
            's3_bucket_name': 'my-rustbucket-logs',
            's3_region': 'eu-west-1',
            's3_prefix': 'production/logs/',
            'test_skip_validation': True
        }

        response = self.client.post(
            url,
            data=json.dumps(data),
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 200)

        # Verify rustbucket was created with S3 config
        rustbucket = Rustbucket.objects.get(name='s3-enabled-rustbucket')
        self.assertEqual(rustbucket.s3_bucket_name, 'my-rustbucket-logs')
        self.assertEqual(rustbucket.s3_region, 'eu-west-1')
        self.assertEqual(rustbucket.s3_prefix, 'production/logs/')

    def test_register_rustbucket_with_minimal_s3_config(self):
        """Test registering with only bucket name and region."""
        url = reverse('register_rustbucket')
        data = {
            'name': 'minimal-s3-rustbucket',
            'ip_address': '10.0.0.51',
            'operating_system': 'Amazon Linux 2',
            'token': 'test-token-minimal-456',
            's3_bucket_name': 'minimal-logs-bucket',
            's3_region': 'us-east-1',
            'test_skip_validation': True
        }

        response = self.client.post(
            url,
            data=json.dumps(data),
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 200)

        rustbucket = Rustbucket.objects.get(name='minimal-s3-rustbucket')
        self.assertEqual(rustbucket.s3_bucket_name, 'minimal-logs-bucket')
        self.assertEqual(rustbucket.s3_region, 'us-east-1')

    def test_register_rustbucket_without_s3_config(self):
        """Test registering without S3 configuration (legacy behavior)."""
        url = reverse('register_rustbucket')
        data = {
            'name': 'legacy-rustbucket',
            'ip_address': '10.0.0.52',
            'operating_system': 'Debian',
            'token': 'test-token-legacy-789',
            'test_skip_validation': True
        }

        response = self.client.post(
            url,
            data=json.dumps(data),
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 200)

        rustbucket = Rustbucket.objects.get(name='legacy-rustbucket')
        self.assertIsNone(rustbucket.s3_bucket_name)
        self.assertFalse(rustbucket.has_s3_configured())


class UpdateWithS3ConfigTest(TestCase):
    """Tests for updating rustbucket S3 configuration."""

    def setUp(self):
        """Set up test data."""
        self.client = Client()

        # Create a rustbucket without S3 config
        self.rustbucket = Rustbucket.objects.create(
            name='update-test-bucket',
            ip_address='10.0.0.60',
            operating_system='Linux',
            token='test-token-update',
            status='Active'
        )

    @patch('requests.get')
    def test_update_rustbucket_adds_s3_config(self, mock_get):
        """Test that update endpoint can add S3 configuration."""
        # Mock response with S3 config
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'name': 'update-test-bucket',
            'operating_system': 'Linux',
            'cpu_usage': '30%',
            'memory_usage': '45%',
            's3_bucket_name': 'newly-added-bucket',
            's3_region': 'ap-southeast-1',
            's3_prefix': 'logs/updated/'
        }
        mock_get.return_value = mock_response

        # Import and call pull_bucket_updates
        from rustbucketregistry.views.register import pull_bucket_updates
        result = pull_bucket_updates()

        # Verify update was successful
        self.assertEqual(result['updated'], 1)

        # Reload rustbucket and check S3 config was added
        self.rustbucket.refresh_from_db()
        self.assertEqual(self.rustbucket.s3_bucket_name, 'newly-added-bucket')
        self.assertEqual(self.rustbucket.s3_region, 'ap-southeast-1')
        self.assertEqual(self.rustbucket.s3_prefix, 'logs/updated/')

    @patch('requests.get')
    def test_update_rustbucket_modifies_s3_config(self, mock_get):
        """Test that update endpoint can modify existing S3 configuration."""
        # Add initial S3 config
        self.rustbucket.s3_bucket_name = 'old-bucket'
        self.rustbucket.s3_region = 'us-west-1'
        self.rustbucket.save()

        # Mock response with updated S3 config
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'name': 'update-test-bucket',
            'operating_system': 'Linux',
            's3_bucket_name': 'new-bucket',
            's3_region': 'eu-central-1'
        }
        mock_get.return_value = mock_response

        from rustbucketregistry.views.register import pull_bucket_updates
        result = pull_bucket_updates()

        # Reload and verify changes
        self.rustbucket.refresh_from_db()
        self.assertEqual(self.rustbucket.s3_bucket_name, 'new-bucket')
        self.assertEqual(self.rustbucket.s3_region, 'eu-central-1')


class S3PreferenceInLogExtractionTest(TestCase):
    """Tests for S3 preference logic in log extraction."""

    def setUp(self):
        """Set up test data."""
        # Rustbucket with S3 configured
        self.s3_rustbucket = Rustbucket.objects.create(
            name='s3-preferred',
            ip_address='10.0.0.70',
            operating_system='Linux',
            status='Active',
            token='token-s3',
            s3_bucket_name='logs-bucket',
            s3_region='us-east-1'
        )

        # Rustbucket without S3
        self.http_rustbucket = Rustbucket.objects.create(
            name='http-only',
            ip_address='10.0.0.71',
            operating_system='Linux',
            status='Active',
            token='token-http'
        )

    @patch('rustbucketregistry.views.register.extract_logs_from_s3')
    @patch('requests.get')
    @patch('boto3.client')
    def test_extract_logs_prefers_s3_when_configured(
        self, mock_boto3, mock_http_get, mock_extract_s3
    ):
        """Test that extract_logs_from_buckets prefers S3 over HTTP."""
        # Mock S3 extraction success
        mock_extract_s3.return_value = {
            'name': 's3-preferred',
            'source': 's3',
            'key': 'logs/test.log'
        }

        # Mock registry S3 client
        mock_registry_s3 = MagicMock()
        mock_boto3.return_value = mock_registry_s3

        # Call extract_logs_from_buckets
        result = extract_logs_from_buckets()

        # Verify S3 extraction was called for s3_rustbucket
        mock_extract_s3.assert_called()

        # Verify HTTP was NOT called for s3_rustbucket
        # (HTTP should only be called for http_rustbucket)
        http_calls = [call for call in mock_http_get.call_args_list
                     if '10.0.0.70' in str(call)]
        self.assertEqual(len(http_calls), 0)

    @patch('rustbucketregistry.views.register.extract_logs_from_s3')
    @patch('requests.get')
    @patch('boto3.client')
    def test_extract_logs_falls_back_to_http_when_s3_fails(
        self, mock_boto3, mock_http_get, mock_extract_s3
    ):
        """Test fallback to HTTP when S3 extraction fails."""
        # Mock S3 extraction failure
        mock_extract_s3.return_value = None

        # Mock HTTP success
        mock_http_response = MagicMock()
        mock_http_response.status_code = 200
        mock_http_response.content = b"Log line 1\nLog line 2"
        mock_http_get.return_value = mock_http_response

        # Mock registry S3 client
        mock_registry_s3 = MagicMock()
        mock_boto3.return_value = mock_registry_s3

        result = extract_logs_from_buckets()

        # Verify both S3 and HTTP were attempted for s3_rustbucket
        mock_extract_s3.assert_called()

        # HTTP should be called for both rustbuckets
        self.assertGreaterEqual(mock_http_get.call_count, 1)

    @patch('requests.get')
    @patch('boto3.client')
    def test_extract_logs_uses_http_when_no_s3_config(
        self, mock_boto3, mock_http_get
    ):
        """Test that HTTP is used when rustbucket has no S3 configuration."""
        # Mock HTTP success
        mock_http_response = MagicMock()
        mock_http_response.status_code = 200
        mock_http_response.content = b"HTTP log data"
        mock_http_get.return_value = mock_http_response

        # Mock registry S3 client
        mock_registry_s3 = MagicMock()
        mock_boto3.return_value = mock_registry_s3

        result = extract_logs_from_buckets()

        # Verify HTTP was called for http_rustbucket
        http_calls = [call for call in mock_http_get.call_args_list
                     if '10.0.0.71' in str(call)]
        self.assertGreater(len(http_calls), 0)
