"""Tests for deployment management functionality."""
import json
from datetime import timedelta
from unittest.mock import patch, MagicMock

from django.test import TestCase, Client
from django.urls import reverse
from django.utils import timezone

from rustbucketregistry.models import Deployment, RegistrationKey, UserProfile
from rustbucketregistry.tests.fixtures import create_test_user


class TerminateDeploymentTest(TestCase):
    """Tests for the terminate deployment endpoint."""

    def setUp(self):
        """Set up test data."""
        self.client = Client()
        self.admin_user = create_test_user(username='admin', is_admin=True)
        self.client.login(username='admin', password='testpass')

        # Create a registration key for testing
        self.reg_key = RegistrationKey.objects.create(
            name='Test Key',
            created_by=self.admin_user,
            expires_at=timezone.now() + timedelta(hours=1)
        )

        # Create a test deployment
        self.deployment = Deployment.objects.create(
            name='test-honeypot',
            instance_type='t3.micro',
            region='us-east-1',
            registration_key=self.reg_key,
            created_by=self.admin_user,
            status='running',
            instance_id='i-1234567890abcdef0'
        )

    def test_terminate_deployment_success(self):
        """Test successful termination of a deployment."""
        with patch('rustbucketregistry.views.deployments.terminate_instance') as mock_terminate:
            mock_terminate.return_value = True

            response = self.client.post(
                reverse('terminate_deployment', args=[self.deployment.id]),
                content_type='application/json'
            )

            self.assertEqual(response.status_code, 200)
            data = json.loads(response.content)
            self.assertEqual(data['status'], 'success')
            self.assertIn('termination initiated', data['message'].lower())

            # Verify deployment status updated
            self.deployment.refresh_from_db()
            self.assertEqual(self.deployment.status, 'terminated')

            # Verify EC2 terminate was called
            mock_terminate.assert_called_once_with(
                self.deployment.instance_id,
                self.deployment.region
            )

    def test_terminate_already_terminated(self):
        """Test that terminating an already terminated deployment fails."""
        self.deployment.status = 'terminated'
        self.deployment.save()

        response = self.client.post(
            reverse('terminate_deployment', args=[self.deployment.id]),
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 400)
        data = json.loads(response.content)
        self.assertIn('already terminated', data['error'].lower())

    def test_terminate_pending_deployment(self):
        """Test terminating a pending deployment (no instance launched yet)."""
        self.deployment.status = 'pending'
        self.deployment.instance_id = None
        self.deployment.save()

        response = self.client.post(
            reverse('terminate_deployment', args=[self.deployment.id]),
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertEqual(data['status'], 'success')

        self.deployment.refresh_from_db()
        self.assertEqual(self.deployment.status, 'terminated')
        self.assertIn('before launch', self.deployment.status_message)

    def test_terminate_deployment_not_found(self):
        """Test terminating a non-existent deployment."""
        response = self.client.post(
            reverse('terminate_deployment', args=['DEP999999']),
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 404)
        data = json.loads(response.content)
        self.assertIn('not found', data['error'].lower())

    def test_terminate_deployment_requires_admin(self):
        """Test that terminating deployment requires admin role."""
        # Create a viewer user
        viewer_user = create_test_user(username='viewer', is_admin=False)
        viewer_user.profile.role = 'viewer'
        viewer_user.profile.save()

        self.client.logout()
        self.client.login(username='viewer', password='testpass')

        response = self.client.post(
            reverse('terminate_deployment', args=[self.deployment.id]),
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 403)

    def test_terminate_deployment_requires_login(self):
        """Test that terminating deployment requires authentication."""
        self.client.logout()

        response = self.client.post(
            reverse('terminate_deployment', args=[self.deployment.id]),
            content_type='application/json'
        )

        # Should redirect to login or return 401
        self.assertIn(response.status_code, [302, 401])

    def test_terminate_ec2_error(self):
        """Test handling of EC2 termination errors."""
        with patch('rustbucketregistry.views.deployments.terminate_instance') as mock_terminate:
            mock_terminate.side_effect = Exception('AWS API Error')

            response = self.client.post(
                reverse('terminate_deployment', args=[self.deployment.id]),
                content_type='application/json'
            )

            self.assertEqual(response.status_code, 500)
            data = json.loads(response.content)
            self.assertIn('aws api error', data['error'].lower())

            # Deployment should not be marked as terminated on error
            self.deployment.refresh_from_db()
            self.assertEqual(self.deployment.status, 'running')


class DeploymentListTest(TestCase):
    """Tests for listing deployments."""

    def setUp(self):
        """Set up test data."""
        self.client = Client()
        self.admin_user = create_test_user(username='admin', is_admin=True)
        self.client.login(username='admin', password='testpass')

    def test_list_deployments_includes_terminated(self):
        """Test that list includes terminated deployments."""
        reg_key = RegistrationKey.objects.create(
            name='Test Key',
            created_by=self.admin_user,
            expires_at=timezone.now() + timedelta(hours=1)
        )

        # Create deployments with different statuses
        running = Deployment.objects.create(
            name='running-honeypot',
            instance_type='t3.micro',
            region='us-east-1',
            registration_key=reg_key,
            created_by=self.admin_user,
            status='running'
        )

        terminated = Deployment.objects.create(
            name='terminated-honeypot',
            instance_type='t3.micro',
            region='us-east-1',
            registration_key=RegistrationKey.objects.create(
                name='Test Key 2',
                created_by=self.admin_user,
                expires_at=timezone.now() + timedelta(hours=1)
            ),
            created_by=self.admin_user,
            status='terminated'
        )

        response = self.client.get(reverse('list_deployments'))

        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertEqual(data['count'], 2)

        statuses = [d['status'] for d in data['deployments']]
        self.assertIn('running', statuses)
        self.assertIn('terminated', statuses)
