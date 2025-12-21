"""Tests for Role-Based Access Control (RBAC) functionality.

This module contains unit tests for testing the RBAC system including
user profiles, permissions, access controls, and audit logging.
"""
from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.auth.models import User

from rustbucketregistry.models import (
    Rustbucket, UserProfile, RustbucketAccess, AuditLog
)
from rustbucketregistry.permissions import (
    get_user_profile,
    filter_rustbuckets_for_user,
    user_can_access_rustbucket,
)


class UserProfileModelTest(TestCase):
    """Tests for UserProfile model."""

    def setUp(self):
        """Set up test users."""
        self.admin_user = User.objects.create_user(
            username='admin', password='adminpass', is_superuser=True
        )
        self.analyst_user = User.objects.create_user(
            username='analyst', password='analystpass'
        )
        self.viewer_user = User.objects.create_user(
            username='viewer', password='viewerpass'
        )

    def test_profile_auto_created_for_superuser(self):
        """Test that superusers get admin profile automatically."""
        profile = get_user_profile(self.admin_user)
        self.assertEqual(profile.role, 'admin')
        self.assertTrue(profile.all_rustbuckets_access)

    def test_profile_created_with_viewer_role_by_default(self):
        """Test that regular users get viewer role by default."""
        profile = get_user_profile(self.viewer_user)
        self.assertEqual(profile.role, 'viewer')
        self.assertFalse(profile.all_rustbuckets_access)

    def test_is_admin_method(self):
        """Test the is_admin method."""
        admin_profile = get_user_profile(self.admin_user)
        viewer_profile = get_user_profile(self.viewer_user)

        self.assertTrue(admin_profile.is_admin())
        self.assertFalse(viewer_profile.is_admin())

    def test_is_analyst_method(self):
        """Test the is_analyst method (includes admin)."""
        admin_profile = get_user_profile(self.admin_user)

        # Create analyst profile
        analyst_profile, _ = UserProfile.objects.update_or_create(
            user=self.analyst_user,
            defaults={'role': 'analyst'}
        )

        viewer_profile = get_user_profile(self.viewer_user)

        self.assertTrue(admin_profile.is_analyst())  # Admins are also analysts
        self.assertTrue(analyst_profile.is_analyst())
        self.assertFalse(viewer_profile.is_analyst())

    def test_can_manage_alerts(self):
        """Test the can_manage_alerts method."""
        admin_profile = get_user_profile(self.admin_user)
        viewer_profile = get_user_profile(self.viewer_user)

        self.assertTrue(admin_profile.can_manage_alerts())
        self.assertFalse(viewer_profile.can_manage_alerts())


class RustbucketAccessTest(TestCase):
    """Tests for RustbucketAccess model."""

    def setUp(self):
        """Set up test data."""
        self.user = User.objects.create_user(
            username='testuser', password='testpass'
        )
        self.rustbucket = Rustbucket.objects.create(
            name='test-bucket',
            ip_address='192.168.1.1',
            operating_system='Linux'
        )

    def test_grant_view_access(self):
        """Test granting view access."""
        access = RustbucketAccess.objects.create(
            user=self.user,
            rustbucket=self.rustbucket,
            access_level='view'
        )

        self.assertTrue(access.can_view())
        self.assertFalse(access.can_manage())
        self.assertFalse(access.is_admin())

    def test_grant_manage_access(self):
        """Test granting manage access."""
        access = RustbucketAccess.objects.create(
            user=self.user,
            rustbucket=self.rustbucket,
            access_level='manage'
        )

        self.assertTrue(access.can_view())
        self.assertTrue(access.can_manage())
        self.assertFalse(access.is_admin())

    def test_grant_admin_access(self):
        """Test granting admin access."""
        access = RustbucketAccess.objects.create(
            user=self.user,
            rustbucket=self.rustbucket,
            access_level='admin'
        )

        self.assertTrue(access.can_view())
        self.assertTrue(access.can_manage())
        self.assertTrue(access.is_admin())


class PermissionDecoratorTest(TestCase):
    """Tests for permission decorators."""

    def setUp(self):
        """Set up test data and client."""
        self.client = Client()

        # Create users with different roles
        self.admin_user = User.objects.create_user(
            username='admin', password='adminpass', is_superuser=True
        )
        self.viewer_user = User.objects.create_user(
            username='viewer', password='viewerpass'
        )

        # Create rustbucket
        self.rustbucket = Rustbucket.objects.create(
            name='test-bucket',
            ip_address='192.168.1.1',
            operating_system='Linux',
            status='Active'
        )

        # Grant viewer access to specific rustbucket
        UserProfile.objects.update_or_create(
            user=self.viewer_user,
            defaults={'role': 'viewer', 'all_rustbuckets_access': False}
        )
        RustbucketAccess.objects.create(
            user=self.viewer_user,
            rustbucket=self.rustbucket,
            access_level='view'
        )

    def test_admin_can_access_all_views(self):
        """Test that admin can access all protected views."""
        self.client.login(username='admin', password='adminpass')

        # Home page
        response = self.client.get(reverse('home'))
        self.assertEqual(response.status_code, 200)

        # Dashboard
        response = self.client.get(reverse('dashboard'))
        self.assertEqual(response.status_code, 200)

        # Logsinks
        response = self.client.get(reverse('logsinks'))
        self.assertEqual(response.status_code, 200)

    def test_viewer_can_access_granted_rustbucket(self):
        """Test that viewer can access rustbucket they have access to."""
        self.client.login(username='viewer', password='viewerpass')

        response = self.client.get(
            reverse('bucket_detail', args=[self.rustbucket.id])
        )
        self.assertEqual(response.status_code, 200)

    def test_viewer_cannot_access_ungrantted_rustbucket(self):
        """Test that viewer cannot access rustbucket they don't have access to."""
        # Create another rustbucket without granting access
        other_bucket = Rustbucket.objects.create(
            name='other-bucket',
            ip_address='192.168.1.2',
            operating_system='Linux'
        )

        self.client.login(username='viewer', password='viewerpass')

        response = self.client.get(
            reverse('bucket_detail', args=[other_bucket.id])
        )
        # Should redirect to home (access denied)
        self.assertEqual(response.status_code, 302)

    def test_unauthenticated_user_redirected(self):
        """Test that unauthenticated users are redirected to login."""
        response = self.client.get(reverse('home'))
        self.assertEqual(response.status_code, 302)
        self.assertIn('/login/', response.url)


class FilterRustbucketsTest(TestCase):
    """Tests for filter_rustbuckets_for_user function."""

    def setUp(self):
        """Set up test data."""
        self.admin_user = User.objects.create_user(
            username='admin', password='adminpass', is_superuser=True
        )
        self.viewer_user = User.objects.create_user(
            username='viewer', password='viewerpass'
        )

        # Create rustbuckets
        self.bucket1 = Rustbucket.objects.create(
            name='bucket1', ip_address='10.0.0.1', operating_system='Linux'
        )
        self.bucket2 = Rustbucket.objects.create(
            name='bucket2', ip_address='10.0.0.2', operating_system='Linux'
        )
        self.bucket3 = Rustbucket.objects.create(
            name='bucket3', ip_address='10.0.0.3', operating_system='Linux'
        )

        # Grant viewer access to bucket1 only
        UserProfile.objects.update_or_create(
            user=self.viewer_user,
            defaults={'role': 'viewer', 'all_rustbuckets_access': False}
        )
        RustbucketAccess.objects.create(
            user=self.viewer_user,
            rustbucket=self.bucket1,
            access_level='view'
        )

    def test_admin_sees_all_buckets(self):
        """Test that admin users see all rustbuckets."""
        buckets = filter_rustbuckets_for_user(self.admin_user)
        self.assertEqual(buckets.count(), 3)

    def test_viewer_sees_only_granted_buckets(self):
        """Test that viewer only sees granted rustbuckets."""
        buckets = filter_rustbuckets_for_user(self.viewer_user)
        self.assertEqual(buckets.count(), 1)
        self.assertEqual(buckets.first(), self.bucket1)

    def test_unauthenticated_user_sees_nothing(self):
        """Test that unauthenticated user sees no rustbuckets."""
        from django.contrib.auth.models import AnonymousUser
        buckets = filter_rustbuckets_for_user(AnonymousUser())
        self.assertEqual(buckets.count(), 0)


class AuditLogTest(TestCase):
    """Tests for AuditLog model."""

    def setUp(self):
        """Set up test user."""
        self.user = User.objects.create_user(
            username='testuser', password='testpass'
        )

    def test_create_audit_log(self):
        """Test creating an audit log entry."""
        AuditLog.log(
            user=self.user,
            action='login',
            details={'ip': '192.168.1.1'},
            success=True
        )

        log = AuditLog.objects.first()
        self.assertIsNotNone(log)
        self.assertEqual(log.user, self.user)
        self.assertEqual(log.action, 'login')
        self.assertTrue(log.success)

    def test_audit_log_with_resource(self):
        """Test creating an audit log with resource info."""
        AuditLog.log(
            user=self.user,
            action='view',
            resource_type='rustbucket',
            resource_id='BUCKET123',
            success=True
        )

        log = AuditLog.objects.first()
        self.assertEqual(log.resource_type, 'rustbucket')
        self.assertEqual(log.resource_id, 'BUCKET123')

    def test_audit_log_ordering(self):
        """Test that audit logs are ordered by timestamp descending."""
        AuditLog.log(user=self.user, action='login')
        AuditLog.log(user=self.user, action='view')

        logs = AuditLog.objects.all()
        self.assertEqual(logs[0].action, 'view')  # Most recent first
        self.assertEqual(logs[1].action, 'login')


class SignalTest(TestCase):
    """Tests for RBAC-related signals."""

    def test_user_profile_created_on_user_creation(self):
        """Test that UserProfile is created when a User is created."""
        user = User.objects.create_user(
            username='newuser', password='newpass'
        )

        profile = UserProfile.objects.filter(user=user).first()
        self.assertIsNotNone(profile)
        self.assertEqual(profile.role, 'viewer')

    def test_superuser_gets_admin_profile(self):
        """Test that superusers get admin role in their profile."""
        user = User.objects.create_superuser(
            username='superadmin', password='superpass', email='admin@test.com'
        )

        profile = UserProfile.objects.filter(user=user).first()
        self.assertIsNotNone(profile)
        self.assertEqual(profile.role, 'admin')
        self.assertTrue(profile.all_rustbuckets_access)
