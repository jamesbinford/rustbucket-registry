"""Tests for Django signal handlers.

This module contains unit tests for testing Django signal handlers including
automatic UserProfile creation when new users are created.
"""
from django.test import TestCase
from django.contrib.auth.models import User
from django.db.models.signals import post_save

from rustbucketregistry.models import UserProfile
from rustbucketregistry.signals import create_user_profile


class UserProfileSignalTest(TestCase):
    """Tests for UserProfile auto-creation signal handler."""

    def test_user_profile_created_for_new_user(self):
        """Test that a UserProfile is automatically created for new users."""
        user = User.objects.create_user(
            username='newuser',
            email='newuser@example.com',
            password='testpass123'
        )

        # Verify UserProfile was created
        self.assertTrue(UserProfile.objects.filter(user=user).exists())
        profile = user.profile
        self.assertEqual(profile.role, 'viewer')
        self.assertFalse(profile.all_rustbuckets_access)

    def test_superuser_gets_admin_role(self):
        """Test that superusers automatically get the admin role."""
        superuser = User.objects.create_superuser(
            username='superadmin',
            email='super@example.com',
            password='superpass123'
        )

        # Verify UserProfile was created with admin role
        profile = superuser.profile
        self.assertEqual(profile.role, 'admin')
        self.assertTrue(profile.all_rustbuckets_access)

    def test_regular_user_gets_viewer_role(self):
        """Test that regular users get the viewer role."""
        user = User.objects.create_user(
            username='regularuser',
            email='regular@example.com',
            password='testpass123'
        )

        profile = user.profile
        self.assertEqual(profile.role, 'viewer')
        self.assertFalse(profile.all_rustbuckets_access)

    def test_staff_user_without_superuser_gets_viewer_role(self):
        """Test that staff users who are not superusers still get viewer role."""
        staff_user = User.objects.create_user(
            username='staffuser',
            email='staff@example.com',
            password='testpass123',
            is_staff=True
        )

        profile = staff_user.profile
        self.assertEqual(profile.role, 'viewer')
        self.assertFalse(profile.all_rustbuckets_access)


class SignalConnectionTest(TestCase):
    """Tests to verify signals are properly connected."""

    def test_user_post_save_signal_is_connected(self):
        """Test that the user post_save signal is connected."""
        receivers = post_save._live_receivers(User)

        handler_connected = any(
            'create_user_profile' in str(receiver)
            for receiver in receivers
        )

        self.assertTrue(
            handler_connected,
            'create_user_profile is not connected to User post_save signal'
        )
