"""Tests for API Key Management functionality."""
import json
from datetime import timedelta
from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.auth.models import User
from django.utils import timezone

from rustbucketregistry.models import Rustbucket, APIKey, AuditLog, UserProfile
from rustbucketregistry.tests.fixtures import (
    create_test_user,
    create_test_rustbucket,
    create_test_api_key,
)


class APIKeyModelTest(TestCase):
    """Tests for APIKey model."""

    def setUp(self):
        self.user = create_test_user()
        self.rustbucket = create_test_rustbucket()

    def test_api_key_creation(self):
        """Test creating an API key generates a secure token."""
        api_key = APIKey.objects.create(
            name='Test Key',
            rustbucket=self.rustbucket,
            created_by=self.user
        )

        self.assertIsNotNone(api_key.key)
        self.assertEqual(len(api_key.key), 43)  # URL-safe base64 of 32 bytes
        self.assertTrue(api_key.is_active)
        self.assertIsNone(api_key.expires_at)

    def test_api_key_is_valid_active(self):
        """Test that active API key is valid."""
        api_key = create_test_api_key(self.rustbucket)
        self.assertTrue(api_key.is_valid())

    def test_api_key_is_valid_expired(self):
        """Test that expired API key is invalid."""
        api_key = create_test_api_key(
            self.rustbucket,
            expires_at=timezone.now() - timedelta(hours=1)
        )
        self.assertFalse(api_key.is_valid())

    def test_api_key_is_valid_revoked(self):
        """Test that revoked API key is invalid."""
        api_key = create_test_api_key(self.rustbucket)
        api_key.is_active = False
        api_key.save()
        self.assertFalse(api_key.is_valid())

    def test_api_key_record_usage(self):
        """Test recording API key usage."""
        api_key = create_test_api_key(self.rustbucket)

        self.assertEqual(api_key.usage_count, 0)
        self.assertIsNone(api_key.last_used_at)

        api_key.record_usage()
        api_key.refresh_from_db()

        self.assertEqual(api_key.usage_count, 1)
        self.assertIsNotNone(api_key.last_used_at)

    def test_api_key_revoke(self):
        """Test revoking API key."""
        api_key = create_test_api_key(self.rustbucket)
        self.assertTrue(api_key.is_active)

        api_key.revoke()
        api_key.refresh_from_db()

        self.assertFalse(api_key.is_active)

    def test_api_key_regenerate(self):
        """Test regenerating API key."""
        api_key = create_test_api_key(self.rustbucket)
        old_key = api_key.key

        new_key = api_key.regenerate()

        self.assertNotEqual(old_key, new_key)
        self.assertEqual(api_key.key, new_key)

    def test_api_key_str(self):
        """Test API key string representation."""
        api_key = create_test_api_key(self.rustbucket, name='My API Key')
        self.assertIn('My API Key', str(api_key))
        self.assertIn(self.rustbucket.name, str(api_key))


class APIKeyManagementEndpointsTest(TestCase):
    """Tests for API key management endpoints."""

    def setUp(self):
        self.client = Client()
        self.user = create_test_user(is_admin=True)
        self.rustbucket = create_test_rustbucket()
        self.client.login(username='testuser', password='testpass')

    def test_list_api_keys(self):
        """Test listing API keys."""
        # Create some API keys
        create_test_api_key(self.rustbucket, name='Key 1')
        create_test_api_key(self.rustbucket, name='Key 2')

        response = self.client.get(reverse('list_api_keys'))

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data['success'])
        self.assertEqual(len(data['api_keys']), 2)

    def test_list_api_keys_by_rustbucket(self):
        """Test listing API keys filtered by rustbucket."""
        rustbucket2 = create_test_rustbucket(
            name='test-2',
            ip_address='192.168.1.2'
        )
        create_test_api_key(self.rustbucket, name='Key 1')
        create_test_api_key(rustbucket2, name='Key 2')

        response = self.client.get(
            reverse('list_api_keys_by_rustbucket', args=[self.rustbucket.id])
        )

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data['success'])
        self.assertEqual(len(data['api_keys']), 1)
        self.assertEqual(data['api_keys'][0]['name'], 'Key 1')

    def test_create_api_key(self):
        """Test creating an API key via API."""
        response = self.client.post(
            reverse('create_api_key', args=[self.rustbucket.id]),
            data=json.dumps({'name': 'New Key'}),
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 201)
        data = response.json()
        self.assertTrue(data['success'])
        self.assertIn('key', data['api_key'])
        self.assertEqual(data['api_key']['name'], 'New Key')

        # Verify API key was created
        self.assertEqual(APIKey.objects.count(), 1)

    def test_create_api_key_with_expiration(self):
        """Test creating an API key with expiration date."""
        expires = (timezone.now() + timedelta(days=30)).isoformat()
        response = self.client.post(
            reverse('create_api_key', args=[self.rustbucket.id]),
            data=json.dumps({
                'name': 'Expiring Key',
                'expires_at': expires
            }),
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 201)
        data = response.json()
        self.assertIsNotNone(data['api_key']['expires_at'])

    def test_create_api_key_missing_name(self):
        """Test creating an API key without name fails."""
        response = self.client.post(
            reverse('create_api_key', args=[self.rustbucket.id]),
            data=json.dumps({}),
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 400)
        data = response.json()
        self.assertFalse(data['success'])

    def test_revoke_api_key(self):
        """Test revoking an API key."""
        api_key = create_test_api_key(self.rustbucket)

        response = self.client.post(
            reverse('revoke_api_key', args=[api_key.id])
        )

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data['success'])

        # Verify key was revoked
        api_key.refresh_from_db()
        self.assertFalse(api_key.is_active)

    def test_rotate_api_key(self):
        """Test rotating an API key."""
        api_key = create_test_api_key(self.rustbucket)
        old_key = api_key.key

        response = self.client.post(
            reverse('rotate_api_key', args=[api_key.id])
        )

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data['success'])
        self.assertIn('key', data['api_key'])
        self.assertNotEqual(data['api_key']['key'], old_key)


class APIKeyRBACTest(TestCase):
    """Tests for API key RBAC permissions."""

    def setUp(self):
        self.client = Client()
        self.rustbucket = create_test_rustbucket()

    def test_create_api_key_requires_analyst(self):
        """Test that creating API key requires analyst role."""
        # Create viewer user
        viewer = User.objects.create_user(
            username='viewer',
            password='viewerpass'
        )
        # Update existing profile (created by signal) to viewer role
        profile, _ = UserProfile.objects.get_or_create(
            user=viewer,
            defaults={'role': 'viewer'}
        )
        profile.role = 'viewer'
        profile.save()

        self.client.login(username='viewer', password='viewerpass')

        response = self.client.post(
            reverse('create_api_key', args=[self.rustbucket.id]),
            data=json.dumps({'name': 'Test Key'}),
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 403)

    def test_revoke_api_key_requires_analyst(self):
        """Test that revoking API key requires analyst role."""
        api_key = create_test_api_key(self.rustbucket)

        # Create viewer user
        viewer = User.objects.create_user(
            username='viewer',
            password='viewerpass'
        )
        # Update existing profile (created by signal) to viewer role
        profile, _ = UserProfile.objects.get_or_create(
            user=viewer,
            defaults={'role': 'viewer'}
        )
        profile.role = 'viewer'
        profile.save()

        self.client.login(username='viewer', password='viewerpass')

        response = self.client.post(
            reverse('revoke_api_key', args=[api_key.id]),
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 403)

    def test_list_api_keys_requires_login(self):
        """Test that listing API keys requires login."""
        response = self.client.get(reverse('list_api_keys'))
        # Should redirect to login
        self.assertEqual(response.status_code, 302)


class APIKeyAuditLogTest(TestCase):
    """Tests for API key audit logging."""

    def setUp(self):
        self.client = Client()
        self.user = create_test_user()
        self.rustbucket = create_test_rustbucket()
        self.client.login(username='testuser', password='testpass')

    def test_create_api_key_logged(self):
        """Test that API key creation is logged."""
        response = self.client.post(
            reverse('create_api_key', args=[self.rustbucket.id]),
            data=json.dumps({'name': 'Logged Key'}),
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 201)

        # Check audit log
        log = AuditLog.objects.filter(action='create_api_key').first()
        self.assertIsNotNone(log)
        self.assertEqual(log.user, self.user)
        self.assertEqual(log.details['name'], 'Logged Key')

    def test_revoke_api_key_logged(self):
        """Test that API key revocation is logged."""
        api_key = create_test_api_key(self.rustbucket)

        response = self.client.post(
            reverse('revoke_api_key', args=[api_key.id])
        )

        self.assertEqual(response.status_code, 200)

        # Check audit log
        log = AuditLog.objects.filter(action='revoke_api_key').first()
        self.assertIsNotNone(log)
        self.assertEqual(log.user, self.user)

    def test_regenerate_api_key_logged(self):
        """Test that API key regeneration is logged."""
        api_key = create_test_api_key(self.rustbucket)

        response = self.client.post(
            reverse('rotate_api_key', args=[api_key.id])
        )

        self.assertEqual(response.status_code, 200)

        # Check audit log
        log = AuditLog.objects.filter(action='regenerate_api_key').first()
        self.assertIsNotNone(log)
        self.assertEqual(log.user, self.user)
        self.assertIn('old_key_prefix', log.details)
