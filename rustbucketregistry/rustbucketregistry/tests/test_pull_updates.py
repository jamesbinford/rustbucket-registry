"""Tests for pull-based updates functionality.

This module contains unit tests for testing pull-based update features including
rustbucket status updates, health checks, and synchronization.
"""
from unittest.mock import patch, MagicMock
from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.auth.models import User
from django.utils import timezone
import json
import requests

from rustbucketregistry.models import Rustbucket
from rustbucketregistry.api.views import pull_bucket_updates, update_buckets


class PullUpdateTest(TestCase):
    """Tests for pull-based update functionality."""

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
            token="test-token-active",
            cpu_usage="10%",
            memory_usage="20%",
            disk_space="100GB",
            uptime="12h",
            connections="5"
        )
        
        self.inactive_rustbucket = Rustbucket.objects.create(
            name="inactive-rustbucket",
            ip_address="192.168.1.2",
            operating_system="Windows",
            status="Inactive",
            token="test-token-inactive"
        )
    
    @patch('requests.get')
    def test_pull_bucket_updates_function(self, mock_get):
        """Test the pull_bucket_updates function."""
        # Mock the response from the rustbucket
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'name': 'active-rustbucket',
            'operating_system': 'Linux',
            'cpu_usage': '50%',  # Changed value
            'memory_usage': '60%',  # Changed value
            'disk_space': '100GB',  # Same value
            'uptime': '24h',  # Changed value
            'connections': '10'  # Changed value
        }
        mock_get.return_value = mock_response
        
        # Call the function
        result = pull_bucket_updates()
        
        # Verify the function called requests.get with the correct URL and headers
        mock_get.assert_called_once_with(
            f"http://{self.active_rustbucket.ip_address}/update_bucket",
            headers={'Authorization': f"Token {self.active_rustbucket.token}"},
            timeout=10
        )
        
        # Verify the function returned the correct result
        self.assertEqual(result['status'], 'success')
        self.assertEqual(result['total'], 1)  # Only active rustbuckets
        self.assertEqual(result['updated'], 1)
        self.assertEqual(result['failed'], 0)
        self.assertEqual(len(result['updates']), 1)
        
        # Verify the rustbucket was updated in the database
        updated_rustbucket = Rustbucket.objects.get(id=self.active_rustbucket.id)
        self.assertEqual(updated_rustbucket.cpu_usage, '50%')
        self.assertEqual(updated_rustbucket.memory_usage, '60%')
        self.assertEqual(updated_rustbucket.disk_space, '100GB')
        self.assertEqual(updated_rustbucket.uptime, '24h')
        self.assertEqual(updated_rustbucket.connections, '10')
    
    @patch('requests.get')
    def test_pull_bucket_updates_connection_error(self, mock_get):
        """Test the pull_bucket_updates function with a connection error."""
        # Mock a connection error
        mock_get.side_effect = requests.RequestException("Connection error")
        
        # Call the function
        result = pull_bucket_updates()
        
        # Verify the function returned the correct result
        self.assertEqual(result['status'], 'success')
        self.assertEqual(result['total'], 1)  # Only active rustbuckets
        self.assertEqual(result['updated'], 0)
        self.assertEqual(result['failed'], 1)
        self.assertEqual(len(result['updates']), 0)
    
    @patch('rustbucketregistry.api.views.pull_bucket_updates')
    def test_update_buckets_endpoint_authorized(self, mock_pull_updates):
        """Test the update_buckets endpoint with authorized user."""
        # Mock the pull_bucket_updates function
        mock_pull_updates.return_value = {
            'status': 'success',
            'total': 1,
            'updated': 1,
            'failed': 0,
            'updates': [{'id': self.active_rustbucket.id, 'name': 'active-rustbucket'}]
        }
        
        # Login as admin
        self.client.login(username='adminuser', password='adminpass')
        
        # Call the endpoint
        url = reverse('update_buckets')
        response = self.client.get(url)
        
        # Verify the response
        self.assertEqual(response.status_code, 200)
        response_data = json.loads(response.content)
        self.assertEqual(response_data['status'], 'success')
        
        # Verify the function was called
        mock_pull_updates.assert_called_once()
    
    def test_update_buckets_endpoint_unauthorized(self):
        """Test the update_buckets endpoint with unauthorized user."""
        # Not logged in
        url = reverse('update_buckets')
        response = self.client.get(url)
        
        # Verify the response
        self.assertEqual(response.status_code, 401)
        
        # Login as regular user (non-staff)
        self.client.login(username='regularuser', password='regularpass')
        
        # Call the endpoint
        response = self.client.get(url)
        
        # Verify the response
        self.assertEqual(response.status_code, 401)