"""Tests for RustBucketRegistry models.

This module contains unit tests for testing Django model classes including
Rustbucket, LogSink, and Alert models.
"""
import json
from django.test import TestCase
from django.utils import timezone
from django.core.exceptions import ValidationError

from rustbucketregistry.models import Rustbucket, LogSink, Alert


class RustbucketModelTest(TestCase):
    """Tests for the Rustbucket model."""
    
    def setUp(self):
        """Set up test data."""
        self.rustbucket = Rustbucket.objects.create(
            name="test-rustbucket",
            url="https://test-rustbucket.example.com",
            ip_address="192.168.1.1",
            operating_system="Linux"
        )
    
    def test_rustbucket_creation(self):
        """Test that a Rustbucket instance can be created correctly."""
        self.assertTrue(isinstance(self.rustbucket, Rustbucket))
        self.assertEqual(self.rustbucket.__str__(), f"Rustbucket: {self.rustbucket.name}")
    
    def test_rustbucket_id_generation(self):
        """Test that an ID is automatically generated for a new Rustbucket."""
        self.assertIsNotNone(self.rustbucket.id)
        self.assertTrue(len(self.rustbucket.id) > 0)
    
    def test_rustbucket_fields(self):
        """Test that all Rustbucket fields are saved correctly."""
        self.assertEqual(self.rustbucket.name, "test-rustbucket")
        self.assertEqual(self.rustbucket.url, "https://test-rustbucket.example.com")
        self.assertIsNotNone(self.rustbucket.created_at)
        self.assertIsNotNone(self.rustbucket.updated_at)


class LogSinkModelTest(TestCase):
    """Tests for the LogSink model."""
    
    def setUp(self):
        """Set up test data."""
        self.rustbucket = Rustbucket.objects.create(
            name="test-rustbucket",
            url="https://test-rustbucket.example.com",
            ip_address="192.168.1.1",
            operating_system="Linux"
        )
        self.logsink = LogSink.objects.create(
            rustbucket=self.rustbucket,
            log_type="Error",
            size="10MB",
            alert_level="high",
            status="Active"
        )
    
    def test_logsink_creation(self):
        """Test that a LogSink instance can be created correctly."""
        self.assertTrue(isinstance(self.logsink, LogSink))
        self.assertEqual(self.logsink.__str__(), f"{self.rustbucket.name} - {self.logsink.log_type}")
    
    def test_logsink_fields(self):
        """Test that all LogSink fields are saved correctly."""
        self.assertEqual(self.logsink.rustbucket, self.rustbucket)
        self.assertEqual(self.logsink.log_type, "Error")
        self.assertEqual(self.logsink.size, "10MB")
        self.assertEqual(self.logsink.alert_level, "high")
        self.assertEqual(self.logsink.status, "Active")
        self.assertIsNotNone(self.logsink.created_at)
        self.assertIsNotNone(self.logsink.last_update)


class AlertModelTest(TestCase):
    """Tests for the Alert model."""
    
    def setUp(self):
        """Set up test data."""
        self.rustbucket = Rustbucket.objects.create(
            name="test-rustbucket",
            url="https://test-rustbucket.example.com",
            ip_address="192.168.1.1",
            operating_system="Linux"
        )
        # Create a logsink first
        self.logsink = LogSink.objects.create(
            rustbucket=self.rustbucket,
            log_type="Error",
            size="10MB",
            alert_level="high"
        )

        self.alert = Alert.objects.create(
            logsink=self.logsink,
            severity="HIGH",
            type="error",
            message="Test alert message"
        )
    
    def test_alert_creation(self):
        """Test that an Alert instance can be created correctly."""
        self.assertTrue(isinstance(self.alert, Alert))
        self.assertEqual(self.alert.__str__(), f"Alert: {self.alert.severity} - {self.alert.message[:50]}")
    
    def test_alert_fields(self):
        """Test that all Alert fields are saved correctly."""
        self.assertEqual(self.alert.logsink.rustbucket, self.rustbucket)
        self.assertEqual(self.alert.severity, "HIGH")
        self.assertEqual(self.alert.message, "Test alert message")
        self.assertIsNotNone(self.alert.created_at)
        self.assertFalse(self.alert.is_resolved)