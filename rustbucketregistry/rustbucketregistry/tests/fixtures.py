"""Test fixtures for the RustBucket Registry application.

This module contains reusable test fixtures and factory functions
for creating test data used across multiple test modules.
"""
from django.contrib.auth.models import User
from django.utils import timezone
from rustbucketregistry.models import Rustbucket, LogSink, LogEntry, Alert, HoneypotActivity


def create_test_user(username='testuser', password='testpass', is_staff=False):
    """Creates a test user.
    
    Args:
        username: Username for the test user.
        password: Password for the test user.
        is_staff: Whether the user should have staff privileges.
        
    Returns:
        User: The created test user.
    """
    return User.objects.create_user(
        username=username,
        password=password,
        is_staff=is_staff
    )


def create_test_rustbucket(name="test-rustbucket", ip_address="192.168.1.1", 
                          operating_system="Linux", **kwargs):
    """Creates a test rustbucket.
    
    Args:
        name: Name of the rustbucket.
        ip_address: IP address of the rustbucket.
        operating_system: Operating system of the rustbucket.
        **kwargs: Additional fields to set on the rustbucket.
        
    Returns:
        Rustbucket: The created test rustbucket.
    """
    defaults = {
        'name': name,
        'ip_address': ip_address,
        'operating_system': operating_system,
        'status': 'Active'
    }
    defaults.update(kwargs)
    return Rustbucket.objects.create(**defaults)


def create_test_logsink(rustbucket, log_type="Info", size="5MB", 
                       alert_level="low", **kwargs):
    """Creates a test log sink.
    
    Args:
        rustbucket: The rustbucket to associate with the log sink.
        log_type: Type of log.
        size: Size of the log.
        alert_level: Alert level for the log sink.
        **kwargs: Additional fields to set on the log sink.
        
    Returns:
        LogSink: The created test log sink.
    """
    defaults = {
        'rustbucket': rustbucket,
        'log_type': log_type,
        'size': size,
        'alert_level': alert_level,
        'status': 'Active'
    }
    defaults.update(kwargs)
    return LogSink.objects.create(**defaults)


def create_test_log_entry(logsink, rustbucket, level="INFO", 
                         message="Test log message", **kwargs):
    """Creates a test log entry.
    
    Args:
        logsink: The log sink to associate with the log entry.
        rustbucket: The rustbucket to associate with the log entry.
        level: Log level.
        message: Log message.
        **kwargs: Additional fields to set on the log entry.
        
    Returns:
        LogEntry: The created test log entry.
    """
    defaults = {
        'logsink': logsink,
        'rustbucket': rustbucket,
        'level': level,
        'message': message
    }
    defaults.update(kwargs)
    return LogEntry.objects.create(**defaults)


def create_test_alert(logsink, rustbucket, severity="MEDIUM", 
                     alert_type="info", message="Test alert", **kwargs):
    """Creates a test alert.
    
    Args:
        logsink: The log sink to associate with the alert.
        rustbucket: The rustbucket to associate with the alert.
        severity: Alert severity.
        alert_type: Type of alert.
        message: Alert message.
        **kwargs: Additional fields to set on the alert.
        
    Returns:
        Alert: The created test alert.
    """
    defaults = {
        'logsink': logsink,
        'rustbucket': rustbucket,
        'severity': severity,
        'type': alert_type,
        'message': message,
        'source': 'Test'
    }
    defaults.update(kwargs)
    return Alert.objects.create(**defaults)


def create_test_honeypot_activity(rustbucket, activity_type="scan", 
                                 source_ip="192.168.1.100", 
                                 details="Test activity", **kwargs):
    """Creates a test honeypot activity.
    
    Args:
        rustbucket: The rustbucket to associate with the activity.
        activity_type: Type of honeypot activity.
        source_ip: Source IP address.
        details: Activity details.
        **kwargs: Additional fields to set on the activity.
        
    Returns:
        HoneypotActivity: The created test honeypot activity.
    """
    defaults = {
        'rustbucket': rustbucket,
        'type': activity_type,
        'source_ip': source_ip,
        'details': details
    }
    defaults.update(kwargs)
    return HoneypotActivity.objects.create(**defaults)


class TestDataMixin:
    """Mixin class providing common test data setup methods.
    
    This mixin can be used by test classes to easily set up common
    test data without duplicating fixture creation logic.
    """
    
    def create_basic_test_data(self):
        """Creates basic test data including user, rustbuckets, and logs.
        
        Sets up:
        - test_user: A test user
        - rustbucket1, rustbucket2: Two test rustbuckets
        - logsink1, logsink2: Two test log sinks
        - Basic log entries and alerts
        """
        self.test_user = create_test_user()
        
        self.rustbucket1 = create_test_rustbucket(
            name="test-rustbucket-1",
            url="https://test1.example.com",
            ip_address="192.168.1.1"
        )

        self.rustbucket2 = create_test_rustbucket(
            name="test-rustbucket-2",
            url="https://test2.example.com",
            ip_address="192.168.1.2"
        )
        
        self.logsink1 = create_test_logsink(
            rustbucket=self.rustbucket1,
            log_type="Info"
        )
        
        self.logsink2 = create_test_logsink(
            rustbucket=self.rustbucket1,
            log_type="Error",
            size="10MB",
            alert_level="high"
        )
        
        create_test_log_entry(
            logsink=self.logsink1,
            rustbucket=self.rustbucket1,
            level="INFO",
            message="Test log message 1",
            source_ip="192.168.1.1"
        )
        
        create_test_log_entry(
            logsink=self.logsink2,
            rustbucket=self.rustbucket1,
            level="ERROR",
            message="Test error message",
            source_ip="192.168.1.2"
        )
        
        create_test_alert(
            logsink=self.logsink2,
            rustbucket=self.rustbucket1,
            severity="HIGH",
            alert_type="error",
            message="Test alert",
            source="Security Scan"
        )