"""
Tests for RustBucketRegistry utility functions.
"""
from django.test import TestCase
from django.core.exceptions import ValidationError

from rustbucketregistry.libs.utils import format_registry_name, validate_registry_url


class UtilsTest(TestCase):
    """Tests for utility functions."""
    
    def test_format_registry_name(self):
        """Test the format_registry_name function."""
        # Test basic formatting
        self.assertEqual(format_registry_name("Test Registry"), "test-registry")
        self.assertEqual(format_registry_name("Another_Test"), "another-test")
        
        # Test with special characters
        self.assertEqual(format_registry_name("Test@Registry!"), "test-registry")
        
        # Test with multiple spaces
        self.assertEqual(format_registry_name("  Multiple   Spaces  "), "multiple-spaces")
        
        # Test with leading/trailing spaces
        self.assertEqual(format_registry_name(" Leading Trailing "), "leading-trailing")
        
        # Test with numbers
        self.assertEqual(format_registry_name("Registry123"), "registry123")
        
        # Test with already formatted name
        self.assertEqual(format_registry_name("already-formatted"), "already-formatted")
        
        # Test empty string
        self.assertEqual(format_registry_name(""), "")
        
        # Test with only special characters
        self.assertEqual(format_registry_name("@#$%^&*"), "")
    
    def test_validate_registry_url(self):
        """Test the validate_registry_url function."""
        # Test valid URLs
        self.assertTrue(validate_registry_url("https://example.com"))
        self.assertTrue(validate_registry_url("https://subdomain.example.com"))
        self.assertTrue(validate_registry_url("https://example.com/path"))
        self.assertTrue(validate_registry_url("http://localhost:8000"))
        self.assertTrue(validate_registry_url("http://192.168.1.1"))
        
        # Test invalid URLs
        with self.assertRaises(ValidationError):
            validate_registry_url("not-a-url")
        
        with self.assertRaises(ValidationError):
            validate_registry_url("ftp://example.com")  # Only http/https allowed
        
        with self.assertRaises(ValidationError):
            validate_registry_url("http://")  # Missing domain
        
        # Test empty string
        with self.assertRaises(ValidationError):
            validate_registry_url("")