"""Tests for RustBucketRegistry dashboard views.

This module contains unit tests for the dashboard views and API endpoints.
"""
from django.test import TestCase, Client
from django.urls import reverse
from django.utils import timezone
from datetime import timedelta

from rustbucketregistry.models import Rustbucket, Alert, HoneypotActivity, LogSink
from rustbucketregistry.tests.fixtures import (
    TestDataMixin,
    create_test_user,
    create_test_rustbucket,
    create_test_logsink,
    create_test_alert,
    create_test_honeypot_activity
)


class DashboardViewTest(TestCase, TestDataMixin):
    """Tests for the main dashboard view."""

    def setUp(self):
        """Set up test data and client."""
        self.client = Client()
        self.create_basic_test_data()
        self.client.login(username='testuser', password='testpass')

    def test_dashboard_view_requires_login(self):
        """Test that the dashboard view requires authentication."""
        self.client.logout()
        response = self.client.get(reverse('dashboard'))
        self.assertEqual(response.status_code, 302)
        self.assertIn('/login/', response.url)

    def test_dashboard_view_authenticated(self):
        """Test that authenticated users can access the dashboard."""
        response = self.client.get(reverse('dashboard'))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'dashboard.html')

    def test_dashboard_view_context(self):
        """Test that the dashboard view has correct context."""
        response = self.client.get(reverse('dashboard'))
        self.assertIn('rustbuckets', response.context)


class DashboardOverviewApiTest(TestCase, TestDataMixin):
    """Tests for the dashboard overview API endpoint."""

    def setUp(self):
        """Set up test data and client."""
        self.client = Client()
        self.create_basic_test_data()
        self.client.login(username='testuser', password='testpass')

        # Create some honeypot activities for testing
        create_test_honeypot_activity(self.rustbucket1, 'scan', '10.0.0.1')
        create_test_honeypot_activity(self.rustbucket1, 'exploit', '10.0.0.2')

    def test_overview_api_requires_login(self):
        """Test that the overview API requires authentication."""
        self.client.logout()
        response = self.client.get(reverse('dashboard_overview_api'))
        self.assertEqual(response.status_code, 302)

    def test_overview_api_returns_data(self):
        """Test that the overview API returns expected data structure."""
        response = self.client.get(reverse('dashboard_overview_api'))
        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertIn('total_rustbuckets', data)
        self.assertIn('active_rustbuckets', data)
        self.assertIn('total_attacks', data)
        self.assertIn('unresolved_alerts', data)
        self.assertIn('time_range', data)

    def test_overview_api_time_range_24h(self):
        """Test the overview API with 24h time range."""
        response = self.client.get(reverse('dashboard_overview_api'), {'range': '24h'})
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn('time_range', data)

    def test_overview_api_time_range_30d(self):
        """Test the overview API with 30d time range."""
        response = self.client.get(reverse('dashboard_overview_api'), {'range': '30d'})
        self.assertEqual(response.status_code, 200)


class DashboardAttacksApiTest(TestCase, TestDataMixin):
    """Tests for the dashboard attacks API endpoint."""

    def setUp(self):
        """Set up test data and client."""
        self.client = Client()
        self.create_basic_test_data()
        self.client.login(username='testuser', password='testpass')

        # Create honeypot activities
        for i in range(5):
            create_test_honeypot_activity(
                self.rustbucket1,
                'scan',
                f'10.0.0.{i}'
            )
        for i in range(3):
            create_test_honeypot_activity(
                self.rustbucket1,
                'exploit',
                f'10.0.1.{i}'
            )

    def test_attacks_api_returns_data(self):
        """Test that the attacks API returns expected data structure."""
        response = self.client.get(reverse('dashboard_attacks_api'))
        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertIn('labels', data)
        self.assertIn('datasets', data)
        self.assertIsInstance(data['datasets'], list)

    def test_attacks_api_datasets_structure(self):
        """Test that datasets have correct structure."""
        response = self.client.get(reverse('dashboard_attacks_api'))
        data = response.json()

        for dataset in data['datasets']:
            self.assertIn('label', dataset)
            self.assertIn('data', dataset)
            self.assertIn('borderColor', dataset)


class DashboardTopIpsApiTest(TestCase, TestDataMixin):
    """Tests for the dashboard top IPs API endpoint."""

    def setUp(self):
        """Set up test data and client."""
        self.client = Client()
        self.create_basic_test_data()
        self.client.login(username='testuser', password='testpass')

        # Create activities from specific IPs
        for i in range(10):
            create_test_honeypot_activity(
                self.rustbucket1,
                'scan',
                '192.168.1.100'
            )
        for i in range(5):
            create_test_honeypot_activity(
                self.rustbucket1,
                'exploit',
                '10.0.0.50'
            )

    def test_top_ips_api_returns_data(self):
        """Test that the top IPs API returns expected data structure."""
        response = self.client.get(reverse('dashboard_top_ips_api'))
        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertIn('labels', data)
        self.assertIn('data', data)
        self.assertIn('limit', data)

    def test_top_ips_api_ordered_by_count(self):
        """Test that IPs are ordered by attack count."""
        response = self.client.get(reverse('dashboard_top_ips_api'))
        data = response.json()

        if len(data['data']) > 1:
            # Verify data is sorted in descending order
            for i in range(len(data['data']) - 1):
                self.assertGreaterEqual(data['data'][i], data['data'][i + 1])


class DashboardCountriesApiTest(TestCase, TestDataMixin):
    """Tests for the dashboard countries API endpoint."""

    def setUp(self):
        """Set up test data and client."""
        self.client = Client()
        self.create_basic_test_data()
        self.client.login(username='testuser', password='testpass')

    def test_countries_api_returns_data(self):
        """Test that the countries API returns expected data structure."""
        response = self.client.get(reverse('dashboard_countries_api'))
        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertIn('labels', data)
        self.assertIn('codes', data)
        self.assertIn('data', data)
        self.assertIn('limit', data)


class DashboardAlertsApiTest(TestCase, TestDataMixin):
    """Tests for the dashboard alerts API endpoint."""

    def setUp(self):
        """Set up test data and client."""
        self.client = Client()
        self.create_basic_test_data()
        self.client.login(username='testuser', password='testpass')

        # Create additional alerts
        for i in range(3):
            create_test_alert(
                self.logsink1,
                self.rustbucket1,
                severity='HIGH',
                alert_type='error',
                message=f'Error alert {i}'
            )
        for i in range(5):
            create_test_alert(
                self.logsink1,
                self.rustbucket1,
                severity='MEDIUM',
                alert_type='warning',
                message=f'Warning alert {i}'
            )

    def test_alerts_api_returns_data(self):
        """Test that the alerts API returns expected data structure."""
        response = self.client.get(reverse('dashboard_alerts_api'))
        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertIn('labels', data)
        self.assertIn('data', data)
        self.assertIn('colors', data)

    def test_alerts_api_has_colors(self):
        """Test that alert data includes colors for chart."""
        response = self.client.get(reverse('dashboard_alerts_api'))
        data = response.json()

        self.assertEqual(len(data['colors']), len(data['labels']))


class DashboardResourcesApiTest(TestCase, TestDataMixin):
    """Tests for the dashboard resources API endpoint."""

    def setUp(self):
        """Set up test data and client."""
        self.client = Client()
        self.create_basic_test_data()
        self.client.login(username='testuser', password='testpass')

        # Set resource values on rustbuckets
        self.rustbucket1.cpu_usage = '45%'
        self.rustbucket1.memory_usage = '60%'
        self.rustbucket1.disk_space = '75%'
        self.rustbucket1.connections = '12'
        self.rustbucket1.save()

    def test_resources_api_returns_data(self):
        """Test that the resources API returns expected data structure."""
        response = self.client.get(reverse('dashboard_resources_api'))
        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertIn('rustbuckets', data)
        self.assertIsInstance(data['rustbuckets'], list)

    def test_resources_api_bucket_structure(self):
        """Test that each bucket has expected fields."""
        response = self.client.get(reverse('dashboard_resources_api'))
        data = response.json()

        if data['rustbuckets']:
            bucket = data['rustbuckets'][0]
            self.assertIn('id', bucket)
            self.assertIn('name', bucket)
            self.assertIn('status', bucket)
            self.assertIn('cpu_usage', bucket)
            self.assertIn('memory_usage', bucket)
            self.assertIn('disk_usage', bucket)
            self.assertIn('connections', bucket)

    def test_resources_api_specific_bucket(self):
        """Test getting resources for a specific bucket."""
        url = reverse('dashboard_resources_api_detail', args=[self.rustbucket1.id])
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertEqual(len(data['rustbuckets']), 1)
        self.assertEqual(data['rustbuckets'][0]['id'], self.rustbucket1.id)

    def test_resources_api_nonexistent_bucket(self):
        """Test getting resources for a nonexistent bucket."""
        url = reverse('dashboard_resources_api_detail', args=['nonexistent'])
        response = self.client.get(url)
        self.assertEqual(response.status_code, 404)


class DashboardTargetsApiTest(TestCase, TestDataMixin):
    """Tests for the dashboard targets API endpoint."""

    def setUp(self):
        """Set up test data and client."""
        self.client = Client()
        self.create_basic_test_data()
        self.client.login(username='testuser', password='testpass')

        # Create activities targeting specific buckets
        for i in range(10):
            create_test_honeypot_activity(
                self.rustbucket1,
                'scan',
                f'10.0.{i}.1'
            )
        for i in range(5):
            create_test_honeypot_activity(
                self.rustbucket2,
                'exploit',
                f'10.1.{i}.1'
            )

    def test_targets_api_returns_data(self):
        """Test that the targets API returns expected data structure."""
        response = self.client.get(reverse('dashboard_targets_api'))
        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertIn('labels', data)
        self.assertIn('bucket_ids', data)
        self.assertIn('data', data)

    def test_targets_api_ordered_by_count(self):
        """Test that targets are ordered by attack count."""
        response = self.client.get(reverse('dashboard_targets_api'))
        data = response.json()

        if len(data['data']) > 1:
            # Verify data is sorted in descending order
            for i in range(len(data['data']) - 1):
                self.assertGreaterEqual(data['data'][i], data['data'][i + 1])


class DashboardTimeRangeTest(TestCase, TestDataMixin):
    """Tests for time range filtering across dashboard APIs."""

    def setUp(self):
        """Set up test data and client."""
        self.client = Client()
        self.create_basic_test_data()
        self.client.login(username='testuser', password='testpass')

    def test_custom_time_range(self):
        """Test custom time range parameter."""
        now = timezone.now()
        start = (now - timedelta(days=5)).isoformat()
        end = now.isoformat()

        response = self.client.get(reverse('dashboard_attacks_api'), {
            'range': 'custom',
            'start': start,
            'end': end
        })
        self.assertEqual(response.status_code, 200)

    def test_invalid_custom_range_fallback(self):
        """Test that invalid custom range falls back to default."""
        response = self.client.get(reverse('dashboard_attacks_api'), {
            'range': 'custom',
            'start': 'invalid',
            'end': 'also-invalid'
        })
        # Should still return 200 with fallback to 7d
        self.assertEqual(response.status_code, 200)

    def test_all_time_ranges(self):
        """Test all supported time range values."""
        for range_value in ['24h', '7d', '30d']:
            response = self.client.get(reverse('dashboard_overview_api'), {
                'range': range_value
            })
            self.assertEqual(response.status_code, 200)
