"""Tests for utility functions in the RustBucket Registry application.

This module contains unit tests for testing utility functions including
registry name formatting and other helper functions.
"""
from django.test import TestCase
from rustbucketregistry.libs.utils import format_registry_name


class UtilsTest(TestCase):
    """Tests for utility functions."""

    def test_format_registry_name_lowercase(self):
        """Test format_registry_name converts to lowercase."""
        name = "TEST"
        formatted_name = format_registry_name(name)
        self.assertEqual(formatted_name, "test")

    def test_format_registry_name_spaces_to_hyphens(self):
        """Test format_registry_name converts spaces to hyphens."""
        name = "test registry name"
        formatted_name = format_registry_name(name)
        self.assertEqual(formatted_name, "test-registry-name")

    def test_format_registry_name_underscores_to_hyphens(self):
        """Test format_registry_name converts underscores to hyphens."""
        name = "test_registry_name"
        formatted_name = format_registry_name(name)
        self.assertEqual(formatted_name, "test-registry-name")

    def test_format_registry_name_special_chars(self):
        """Test format_registry_name handles special characters."""
        name = "Test@Registry!"
        formatted_name = format_registry_name(name)
        self.assertEqual(formatted_name, "test-registry")

    def test_format_registry_name_multiple_consecutive_hyphens(self):
        """Test format_registry_name removes multiple consecutive hyphens."""
        name = "test---registry"
        formatted_name = format_registry_name(name)
        self.assertEqual(formatted_name, "test-registry")

    def test_format_registry_name_leading_trailing_hyphens(self):
        """Test format_registry_name removes leading and trailing hyphens."""
        name = "-test-registry-"
        formatted_name = format_registry_name(name)
        self.assertEqual(formatted_name, "test-registry")

    def test_format_registry_name_combined_scenarios(self):
        """Test format_registry_name with multiple formatting needs."""
        name = "   Test Registry_Name@123!  "
        formatted_name = format_registry_name(name)
        self.assertEqual(formatted_name, "test-registry-name-123")