"""Tests for registration key management.

This module contains tests for the registration key API endpoints
and the registration flow using pre-shared keys.
"""
import json
from datetime import timedelta

from django.contrib.auth.models import User
from django.test import TestCase, Client
from django.urls import reverse
from django.utils import timezone

from rustbucketregistry.models import RegistrationKey, Rustbucket, UserProfile


class RegistrationKeyModelTest(TestCase):
    """Tests for the RegistrationKey model."""

    def setUp(self):
        """Set up test data."""
        self.admin_user = User.objects.create_user(
            username='admin',
            password='adminpass'
        )
        # Profile is auto-created by signal, just update the role
        self.admin_user.profile.role = 'admin'
        self.admin_user.profile.save()

    def test_key_auto_generation(self):
        """Test that key is auto-generated on save."""
        reg_key = RegistrationKey(
            name='Test Key',
            created_by=self.admin_user
        )
        reg_key.save()

        self.assertIsNotNone(reg_key.key)
        self.assertTrue(len(reg_key.key) > 20)

    def test_is_valid_new_key(self):
        """Test that a new key is valid."""
        reg_key = RegistrationKey.objects.create(
            name='Test Key',
            created_by=self.admin_user
        )
        self.assertTrue(reg_key.is_valid())

    def test_is_valid_used_key(self):
        """Test that a used key is not valid."""
        reg_key = RegistrationKey.objects.create(
            name='Test Key',
            created_by=self.admin_user,
            used=True
        )
        self.assertFalse(reg_key.is_valid())

    def test_is_valid_revoked_key(self):
        """Test that a revoked key is not valid."""
        reg_key = RegistrationKey.objects.create(
            name='Test Key',
            created_by=self.admin_user,
            revoked=True
        )
        self.assertFalse(reg_key.is_valid())

    def test_is_valid_expired_key(self):
        """Test that an expired key is not valid."""
        reg_key = RegistrationKey.objects.create(
            name='Test Key',
            created_by=self.admin_user,
            expires_at=timezone.now() - timedelta(days=1)
        )
        self.assertFalse(reg_key.is_valid())

    def test_get_status(self):
        """Test get_status method."""
        # Available key
        available_key = RegistrationKey.objects.create(
            name='Available',
            created_by=self.admin_user
        )
        self.assertEqual(available_key.get_status(), 'available')

        # Used key
        used_key = RegistrationKey.objects.create(
            name='Used',
            created_by=self.admin_user,
            used=True
        )
        self.assertEqual(used_key.get_status(), 'used')

        # Revoked key
        revoked_key = RegistrationKey.objects.create(
            name='Revoked',
            created_by=self.admin_user,
            revoked=True
        )
        self.assertEqual(revoked_key.get_status(), 'revoked')

        # Expired key
        expired_key = RegistrationKey.objects.create(
            name='Expired',
            created_by=self.admin_user,
            expires_at=timezone.now() - timedelta(days=1)
        )
        self.assertEqual(expired_key.get_status(), 'expired')


class RegistrationKeyAPITest(TestCase):
    """Tests for the registration key API endpoints."""

    def setUp(self):
        """Set up test data and client."""
        self.client = Client()

        # Create admin user
        self.admin_user = User.objects.create_user(
            username='admin',
            password='adminpass'
        )
        # Profile is auto-created by signal, just update the role
        self.admin_user.profile.role = 'admin'
        self.admin_user.profile.save()

        # Create non-admin user
        self.viewer_user = User.objects.create_user(
            username='viewer',
            password='viewerpass'
        )
        # Profile is auto-created by signal with default 'viewer' role

    def test_create_registration_key_as_admin(self):
        """Test creating a registration key as admin."""
        self.client.login(username='admin', password='adminpass')

        url = reverse('create_registration_key')
        response = self.client.post(
            url,
            data=json.dumps({'name': 'Production Honeypot 1'}),
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 201)
        data = json.loads(response.content)
        self.assertEqual(data['status'], 'success')
        self.assertIn('key', data)
        self.assertEqual(data['name'], 'Production Honeypot 1')

        # Verify key was created in database
        self.assertTrue(RegistrationKey.objects.filter(name='Production Honeypot 1').exists())

    def test_create_registration_key_with_expiration(self):
        """Test creating a registration key with expiration."""
        self.client.login(username='admin', password='adminpass')

        url = reverse('create_registration_key')
        response = self.client.post(
            url,
            data=json.dumps({
                'name': 'Temp Key',
                'expires_in_days': 7
            }),
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 201)
        data = json.loads(response.content)
        self.assertIn('expires_at', data)
        self.assertIsNotNone(data['expires_at'])

    def test_create_registration_key_without_name(self):
        """Test creating a registration key without name fails."""
        self.client.login(username='admin', password='adminpass')

        url = reverse('create_registration_key')
        response = self.client.post(
            url,
            data=json.dumps({}),
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 400)

    def test_create_registration_key_as_viewer(self):
        """Test that non-admin cannot create keys."""
        self.client.login(username='viewer', password='viewerpass')

        url = reverse('create_registration_key')
        response = self.client.post(
            url,
            data=json.dumps({'name': 'Unauthorized Key'}),
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 403)

    def test_create_registration_key_unauthenticated(self):
        """Test that unauthenticated user cannot create keys."""
        url = reverse('create_registration_key')
        response = self.client.post(
            url,
            data=json.dumps({'name': 'Unauthorized Key'}),
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 401)

    def test_list_registration_keys(self):
        """Test listing registration keys."""
        self.client.login(username='admin', password='adminpass')

        # Create some keys
        RegistrationKey.objects.create(name='Key 1', created_by=self.admin_user)
        RegistrationKey.objects.create(name='Key 2', created_by=self.admin_user, used=True)

        url = reverse('list_registration_keys')
        response = self.client.get(url)

        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertEqual(data['status'], 'success')
        self.assertEqual(data['count'], 2)

        # Verify key value is NOT included
        for key in data['keys']:
            self.assertNotIn('key', key)

    def test_revoke_registration_key(self):
        """Test revoking a registration key."""
        self.client.login(username='admin', password='adminpass')

        reg_key = RegistrationKey.objects.create(
            name='To Revoke',
            created_by=self.admin_user
        )

        url = reverse('revoke_registration_key', args=[reg_key.id])
        response = self.client.post(url)

        self.assertEqual(response.status_code, 200)

        # Verify key is revoked
        reg_key.refresh_from_db()
        self.assertTrue(reg_key.revoked)
        self.assertFalse(reg_key.is_valid())

    def test_revoke_used_key_fails(self):
        """Test that revoking a used key fails."""
        self.client.login(username='admin', password='adminpass')

        reg_key = RegistrationKey.objects.create(
            name='Already Used',
            created_by=self.admin_user,
            used=True
        )

        url = reverse('revoke_registration_key', args=[reg_key.id])
        response = self.client.post(url)

        self.assertEqual(response.status_code, 400)

    def test_revoke_nonexistent_key(self):
        """Test revoking a nonexistent key fails."""
        self.client.login(username='admin', password='adminpass')

        url = reverse('revoke_registration_key', args=[99999])
        response = self.client.post(url)

        self.assertEqual(response.status_code, 404)


class RegistrationWithKeyTest(TestCase):
    """Tests for rustbucket registration using pre-shared keys."""

    def setUp(self):
        """Set up test data and client."""
        self.client = Client()

        # Create admin user and registration key
        self.admin_user = User.objects.create_user(
            username='admin',
            password='adminpass'
        )
        # Profile is auto-created by signal, just update the role
        self.admin_user.profile.role = 'admin'
        self.admin_user.profile.save()

        self.registration_key = RegistrationKey.objects.create(
            name='Test Registration Key',
            created_by=self.admin_user
        )

    def test_register_with_valid_key(self):
        """Test registering a rustbucket with a valid key."""
        url = reverse('register_rustbucket')
        data = {
            'name': 'new-honeypot',
            'ip_address': '192.168.1.100',
            'operating_system': 'Linux',
            'registration_key': self.registration_key.key,
        }

        response = self.client.post(
            url,
            data=json.dumps(data),
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 200)
        response_data = json.loads(response.content)
        self.assertEqual(response_data['status'], 'success')

        # Verify S3 config is returned
        self.assertIn('s3_config', response_data)
        self.assertIn('bucket', response_data['s3_config'])
        self.assertIn('prefix', response_data['s3_config'])

        # Verify instance_id is NOT returned (it's in the prefix)
        self.assertNotIn('instance_id', response_data)

        # Verify key is marked as used
        self.registration_key.refresh_from_db()
        self.assertTrue(self.registration_key.used)
        self.assertIsNotNone(self.registration_key.used_at)

        # Verify rustbucket was created with key as token
        rustbucket = Rustbucket.objects.get(name='new-honeypot')
        self.assertEqual(rustbucket.token, self.registration_key.key)

    def test_register_with_invalid_key(self):
        """Test registering with an invalid key fails."""
        url = reverse('register_rustbucket')
        data = {
            'name': 'bad-honeypot',
            'ip_address': '192.168.1.101',
            'operating_system': 'Linux',
            'registration_key': 'invalid-key-value',
        }

        response = self.client.post(
            url,
            data=json.dumps(data),
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 401)

    def test_register_with_used_key(self):
        """Test registering with an already-used key fails."""
        # Mark key as used
        self.registration_key.used = True
        self.registration_key.save()

        url = reverse('register_rustbucket')
        data = {
            'name': 'another-honeypot',
            'ip_address': '192.168.1.102',
            'operating_system': 'Linux',
            'registration_key': self.registration_key.key,
        }

        response = self.client.post(
            url,
            data=json.dumps(data),
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 401)

    def test_register_with_revoked_key(self):
        """Test registering with a revoked key fails."""
        # Revoke key
        self.registration_key.revoked = True
        self.registration_key.save()

        url = reverse('register_rustbucket')
        data = {
            'name': 'revoked-honeypot',
            'ip_address': '192.168.1.103',
            'operating_system': 'Linux',
            'registration_key': self.registration_key.key,
        }

        response = self.client.post(
            url,
            data=json.dumps(data),
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 401)

    def test_register_with_expired_key(self):
        """Test registering with an expired key fails."""
        # Set key to expired
        self.registration_key.expires_at = timezone.now() - timedelta(days=1)
        self.registration_key.save()

        url = reverse('register_rustbucket')
        data = {
            'name': 'expired-honeypot',
            'ip_address': '192.168.1.104',
            'operating_system': 'Linux',
            'registration_key': self.registration_key.key,
        }

        response = self.client.post(
            url,
            data=json.dumps(data),
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 401)

    def test_register_missing_key(self):
        """Test registering without a key fails."""
        url = reverse('register_rustbucket')
        data = {
            'name': 'no-key-honeypot',
            'ip_address': '192.168.1.105',
            'operating_system': 'Linux',
        }

        response = self.client.post(
            url,
            data=json.dumps(data),
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 400)
