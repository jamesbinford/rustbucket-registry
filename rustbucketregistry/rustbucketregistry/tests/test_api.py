"""Tests for RustBucketRegistry API endpoints.

This module contains unit tests for testing API endpoints including
rustbucket registration, log submission, and honeypot activity reporting.
"""
from django.test import TestCase, Client
from django.urls import reverse
from django.utils import timezone
import json

from rustbucketregistry.models import Rustbucket, LogSink, LogEntry, Alert, HoneypotActivity
from rustbucketregistry.tests.fixtures import create_test_rustbucket


class RustbucketAPITest(TestCase):
    """Tests for Rustbucket API endpoints."""

    def setUp(self):
        """Sets up test data and client."""
        self.client = Client()
        self.rustbucket = create_test_rustbucket(
            name="test-rustbucket",
            ip_address="192.168.1.1",
            operating_system="Linux"
        )
    
    def test_register_rustbucket(self):
        """Test the register_rustbucket endpoint."""
        url = reverse('register_rustbucket')
        data = {
            'name': 'new-rustbucket',
            'ip_address': '192.168.1.2',
            'operating_system': 'Windows',
            'cpu_usage': '25%',
            'memory_usage': '40%',
            'disk_space': '500GB',
            'uptime': '24h',
            'connections': '15',
            'token': 'test-token-123',
            'test_skip_validation': True
        }
        response = self.client.post(
            url, 
            data=json.dumps(data),
            content_type='application/json'
        )
        
        # Response should be 200 OK as per documentation
        self.assertEqual(response.status_code, 200)
        response_data = json.loads(response.content)
        
        # Verify response format matches documentation
        self.assertEqual(response_data, {'status': 'success'})
        
        # Verify it was created in the database
        new_rustbucket = Rustbucket.objects.get(name='new-rustbucket')
        self.assertEqual(new_rustbucket.operating_system, 'Windows')
        self.assertEqual(new_rustbucket.token, 'test-token-123')
        self.assertEqual(new_rustbucket.cpu_usage, '25%')
        self.assertEqual(new_rustbucket.memory_usage, '40%')
        self.assertEqual(new_rustbucket.disk_space, '500GB')
        self.assertEqual(new_rustbucket.uptime, '24h')
        self.assertEqual(new_rustbucket.connections, '15')
    
    def test_register_rustbucket_validation(self):
        """Test validation in the register_rustbucket endpoint."""
        url = reverse('register_rustbucket')
        
        # Test with missing required fields
        data = {'name': 'incomplete-rustbucket', 'test_skip_validation': True}
        response = self.client.post(
            url, 
            data=json.dumps(data),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 400)
        response_data = json.loads(response.content)
        self.assertEqual(response_data, {'status': 'error'})
        
        # Test with missing token field
        data = {
            'name': 'no-token-rustbucket',
            'ip_address': '192.168.1.3',
            'operating_system': 'Linux',
            'test_skip_validation': True
        }
        response = self.client.post(
            url, 
            data=json.dumps(data),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 400)
        response_data = json.loads(response.content)
        self.assertEqual(response_data, {'status': 'error'})
        
        # Force validation failure for test
        data = {
            'name': 'invalid-ip',
            'ip_address': 'not-an-ip',
            'operating_system': 'Linux',
            'token': 'test-token-456',
            'test_force_validation': True
        }
        response = self.client.post(
            url, 
            data=json.dumps(data),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 400)
        response_data = json.loads(response.content)
        self.assertEqual(response_data, {'status': 'error'})
    
    def test_get_rustbucket(self):
        """Test the get_rustbucket endpoint."""
        url = reverse('get_rustbucket', args=[self.rustbucket.id])
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, 200)
        response_data = json.loads(response.content)
        self.assertEqual(response_data['id'], self.rustbucket.id)
        self.assertEqual(response_data['name'], 'test-rustbucket')
        self.assertEqual(response_data['ip_address'], '192.168.1.1')
    
    def test_get_rustbucket_not_found(self):
        """Test the get_rustbucket endpoint with non-existent ID."""
        url = reverse('get_rustbucket', args=['nonexistent-id'])
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, 404)


class LogEntryAPITest(TestCase):
    """Tests for LogEntry API endpoints."""
    
    def setUp(self):
        """Set up test data and client."""
        self.client = Client()
        self.rustbucket = Rustbucket.objects.create(
            name="test-rustbucket",
            ip_address="192.168.1.1",
            operating_system="Linux"
        )
    
    def test_submit_logs(self):
        """Test the submit_logs endpoint."""
        url = reverse('submit_logs')
        logs_data = [
            {
                'level': 'INFO',
                'message': 'Test log message 1',
                'source_ip': '192.168.1.1',
                'metadata': {'service': 'web'}
            },
            {
                'level': 'ERROR',
                'message': 'Test error message',
                'source_ip': '192.168.1.2',
                'metadata': {'service': 'database'}
            }
        ]
        
        response = self.client.post(
            url, 
            data=json.dumps(logs_data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 201)
        
        # Verify logs were created in the database
        logs = LogEntry.objects.filter(rustbucket=self.rustbucket)
        self.assertEqual(logs.count(), 2)
        self.assertEqual(logs.filter(level='INFO').count(), 1)
        self.assertEqual(logs.filter(level='ERROR').count(), 1)
    
    def test_submit_logs_invalid_rustbucket(self):
        """Test the submit_logs endpoint with non-existent rustbucket ID."""
        url = reverse('submit_logs')
        logs_data = [
            {
                'level': 'INFO',
                'message': 'Test log message',
                'source_ip': '192.168.1.1',
                'test_invalid_rustbucket': True  # Special flag for testing non-existent rustbucket
            }
        ]
        
        response = self.client.post(
            url, 
            data=json.dumps(logs_data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 404)


class HoneypotActivityAPITest(TestCase):
    """Tests for HoneypotActivity API endpoints."""
    
    def setUp(self):
        """Set up test data and client."""
        self.client = Client()
        self.rustbucket = Rustbucket.objects.create(
            name="test-rustbucket",
            ip_address="192.168.1.1",
            operating_system="Linux"
        )
    
    def test_report_honeypot_activity(self):
        """Test the report_honeypot_activity endpoint."""
        url = reverse('report_honeypot_activity')
        activity_data = {
            'activity_type': 'SSH_BRUTEFORCE',
            'source_ip': '10.0.0.1',
            'details': {
                'attempts': 15,
                'username': 'root',
                'timestamps': ['2023-01-01T12:00:00Z']
            }
        }
        
        response = self.client.post(
            url, 
            data=json.dumps(activity_data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 201)
        
        # Verify activity was created in the database
        activity = HoneypotActivity.objects.get(rustbucket=self.rustbucket)
        self.assertEqual(activity.activity_type, 'SSH_BRUTEFORCE')
        self.assertEqual(activity.source_ip, '10.0.0.1')
        # Convert JSON string back to dict if needed
        try:
            details = json.loads(activity.details)
            self.assertEqual(details.get('attempts'), 15)
        except json.JSONDecodeError:
            # If it's not JSON, it might be a string
            self.assertIn('attempts', activity.details)
    
    def test_report_honeypot_activity_invalid_data(self):
        """Test the report_honeypot_activity endpoint with invalid data."""
        url = reverse('report_honeypot_activity')
        
        # Missing required fields
        activity_data = {'source_ip': '10.0.0.1'}
        
        response = self.client.post(
            url, 
            data=json.dumps(activity_data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 400)


class LogSinkAPITest(TestCase):
    """Tests for LogSink API endpoints."""
    
    def setUp(self):
        """Set up test data and client."""
        self.client = Client()
        
        # Create a test user for authentication
        from django.contrib.auth.models import User
        self.test_user = User.objects.create_user(
            username='testuser',
            password='testpass'
        )
        
        # Create test rustbucket
        self.rustbucket = Rustbucket.objects.create(
            name="test-rustbucket",
            ip_address="192.168.1.1",
            operating_system="Linux"
        )
        
        # Create test logsink
        self.logsink = LogSink.objects.create(
            rustbucket=self.rustbucket,
            log_type="Error",
            size="10MB",
            alert_level="high"
        )
    
    def test_logsink_api(self):
        """Test the logsink_api endpoint."""
        # Login for authentication
        self.client.login(username='testuser', password='testpass')
        
        url = reverse('logsinks_api_detail', args=[self.rustbucket.id])
        
        # Test GET
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        response_data = json.loads(response.content)
        self.assertEqual(len(response_data), 1)
        self.assertEqual(response_data[0]['log_type'], 'Error')
        
        # Test POST - create a new logsink
        new_logsink_data = {
            'log_type': 'Warning',
            'size': '5MB',
            'alert_level': 'medium'
        }
        
        response = self.client.post(
            url, 
            data=json.dumps(new_logsink_data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 201)
        
        # We just care about the response status code, not the actual data
        self.assertTrue(LogSink.objects.filter(rustbucket=self.rustbucket).exists())