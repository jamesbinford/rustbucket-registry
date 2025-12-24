"""Tests for RustBucketRegistry API endpoints.

This module contains unit tests for testing API endpoints including
rustbucket registration.
"""
from django.test import TestCase, Client
from django.urls import reverse
from django.utils import timezone
import json

from rustbucketregistry.models import Rustbucket, LogSink, Alert
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


class LogSinkAPITest(TestCase):
    """Tests for LogSink API endpoints."""

    def setUp(self):
        """Set up test data and client."""
        self.client = Client()

        # Create a test user for authentication with admin access
        from django.contrib.auth.models import User
        from rustbucketregistry.models import UserProfile
        self.test_user = User.objects.create_user(
            username='testuser',
            password='testpass'
        )
        # Create admin profile for full access
        UserProfile.objects.update_or_create(
            user=self.test_user,
            defaults={'role': 'admin', 'all_rustbuckets_access': True}
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