"""
Models for the RustBucket Registry application.
"""
import uuid
from django.db import models
from django.utils import timezone


class Rustbucket(models.Model):
    """
    Represents a Rustbucket instance that is registered with the registry.
    """
    # Unique identifier for the rustbucket
    id = models.CharField(
        primary_key=True,
        max_length=20,
        editable=False,
        help_text="Unique identifier for the rustbucket"
    )

    # Basic information
    name = models.CharField(
        max_length=255,
        help_text="Name of the rustbucket"
    )

    # URL for the rustbucket
    url = models.URLField(
        null=True,
        blank=True,
        help_text="URL of the rustbucket"
    )

    # Connection information
    ip_address = models.GenericIPAddressField(
        help_text="IP address of the rustbucket"
    )

    # Status of the rustbucket
    STATUS_CHOICES = [
        ('Active', 'Active'),
        ('Inactive', 'Inactive'),
        ('Maintenance', 'Maintenance'),
        ('Review', 'Review'),
    ]
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default='Review',
        help_text="Current status of the rustbucket"
    )

    # System information
    operating_system = models.CharField(
        max_length=255,
        help_text="Operating system of the rustbucket"
    )

    # Usage metrics
    cpu_usage = models.CharField(
        max_length=10,
        null=True,
        blank=True,
        help_text="Current CPU usage percentage"
    )
    memory_usage = models.CharField(
        max_length=10,
        null=True,
        blank=True,
        help_text="Current memory usage percentage"
    )
    disk_space = models.CharField(
        max_length=20,
        null=True,
        blank=True,
        help_text="Available disk space"
    )
    uptime = models.CharField(
        max_length=20,
        null=True,
        blank=True,
        help_text="Uptime of the rustbucket"
    )
    connections = models.CharField(
        max_length=20,
        null=True,
        blank=True,
        help_text="Number of active connections"
    )

    # Registration information with token as per API documentation
    token = models.CharField(
        max_length=255,
        null=True,
        blank=True,
        help_text="Token provided by the Rustbucket for registration"
    )

    registered_at = models.DateTimeField(
        default=timezone.now,
        help_text="When the rustbucket was registered"
    )
    last_seen = models.DateTimeField(
        default=timezone.now,
        help_text="When the rustbucket was last seen"
    )
    last_log_dump = models.DateTimeField(
        null=True,
        blank=True,
        help_text="When the rustbucket last sent logs"
    )

    # Timestamps
    created_at = models.DateTimeField(
        default=timezone.now,
        help_text="When the rustbucket was created"
    )
    updated_at = models.DateTimeField(
        auto_now=True,
        help_text="When the rustbucket was last updated"
    )

    class Meta:
        ordering = ['-last_seen']
        verbose_name = 'Rustbucket'
        verbose_name_plural = 'Rustbuckets'

    def __str__(self):
        return f"Rustbucket: {self.name}"

    def save(self, *args, **kwargs):
        if not self.id:
            # Generate a unique ID for new rustbuckets
            self.id = f"BKT{str(uuid.uuid4().int)[:6]}"
        super().save(*args, **kwargs)


class LogSink(models.Model):
    """
    Represents a log sink for a rustbucket instance.
    """
    rustbucket = models.ForeignKey(
        Rustbucket,
        on_delete=models.CASCADE,
        related_name='logsinks',
        help_text="The rustbucket this logsink belongs to"
    )
    
    LOG_TYPE_CHOICES = [
        ('Error', 'Error'),
        ('Warning', 'Warning'),
        ('Info', 'Info'),
        ('Debug', 'Debug'),
    ]
    log_type = models.CharField(
        max_length=20,
        choices=LOG_TYPE_CHOICES,
        help_text="Type of log"
    )
    
    size = models.CharField(
        max_length=20,
        help_text="Size of the log"
    )
    
    STATUS_CHOICES = [
        ('Active', 'Active'),
        ('Inactive', 'Inactive'),
        ('Maintenance', 'Maintenance'),
    ]
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default='Active',
        help_text="Current status of the logsink"
    )
    
    ALERT_LEVEL_CHOICES = [
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
    ]
    alert_level = models.CharField(
        max_length=10,
        choices=ALERT_LEVEL_CHOICES,
        default='low',
        help_text="Alert level of the logsink"
    )
    
    created_at = models.DateTimeField(
        default=timezone.now,
        help_text="When the logsink was created"
    )
    last_update = models.DateTimeField(
        default=timezone.now,
        help_text="When the logsink was last updated"
    )

    class Meta:
        ordering = ['-last_update']
        verbose_name = 'Log Sink'
        verbose_name_plural = 'Log Sinks'

    def __str__(self):
        return f"{self.rustbucket.name} - {self.log_type}"


class LogEntry(models.Model):
    """
    Represents a log entry for a logsink.
    """
    logsink = models.ForeignKey(
        LogSink,
        on_delete=models.CASCADE,
        related_name='entries',
        help_text="The logsink this entry belongs to"
    )

    # For backward compatibility with tests
    rustbucket = models.ForeignKey(
        Rustbucket,
        on_delete=models.CASCADE,
        related_name='log_entries',
        null=True,
        blank=True,
        help_text="The rustbucket this entry belongs to (for backward compatibility)"
    )

    # For test compatibility - log level field
    level = models.CharField(
        max_length=20,
        null=True,
        blank=True,
        help_text="Log level (for backward compatibility)"
    )

    # For backward compatibility with tests
    source_ip = models.GenericIPAddressField(
        null=True,
        blank=True,
        help_text="Source IP (for backward compatibility)"
    )

    timestamp = models.DateTimeField(
        default=timezone.now,
        help_text="When the log entry was created"
    )

    message = models.TextField(
        help_text="The log message"
    )

    class Meta:
        ordering = ['-timestamp']
        verbose_name = 'Log Entry'
        verbose_name_plural = 'Log Entries'

    def __str__(self):
        return f"Log: {self.level} - {self.message[:50]}"


class Alert(models.Model):
    """
    Represents an alert for a logsink.
    """
    logsink = models.ForeignKey(
        LogSink,
        on_delete=models.CASCADE,
        related_name='alerts',
        help_text="The logsink this alert belongs to"
    )

    # For backward compatibility with tests
    rustbucket = models.ForeignKey(
        Rustbucket,
        on_delete=models.CASCADE,
        related_name='alerts',
        null=True,
        blank=True,
        help_text="The rustbucket this alert belongs to (for backward compatibility)"
    )

    ALERT_TYPE_CHOICES = [
        ('error', 'Error'),
        ('warning', 'Warning'),
        ('info', 'Info'),
        ('HIGH', 'High'),
        ('MEDIUM', 'Medium'),
        ('LOW', 'Low'),
    ]
    type = models.CharField(
        max_length=10,
        choices=ALERT_TYPE_CHOICES,
        help_text="Type of alert"
    )

    # For backward compatibility with tests
    severity = models.CharField(
        max_length=10,
        null=True,
        blank=True,
        help_text="Alert severity (for backward compatibility)"
    )

    # For backward compatibility with tests
    source = models.CharField(
        max_length=50,
        null=True,
        blank=True,
        help_text="Alert source (for backward compatibility)"
    )

    message = models.CharField(
        max_length=255,
        help_text="Alert message"
    )

    created_at = models.DateTimeField(
        default=timezone.now,
        help_text="When the alert was created"
    )
    resolved_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="When the alert was resolved"
    )
    is_resolved = models.BooleanField(
        default=False,
        help_text="Whether the alert has been resolved"
    )

    # For backward compatibility with tests
    timestamp = models.DateTimeField(
        default=timezone.now,
        help_text="Alert timestamp (for backward compatibility)"
    )

    # For backward compatibility with tests - resolved status
    @property
    def resolved(self):
        return self.is_resolved

    class Meta:
        ordering = ['-created_at']
        verbose_name = 'Alert'
        verbose_name_plural = 'Alerts'

    def __str__(self):
        return f"Alert: {self.severity} - {self.message[:50]}"


class HoneypotActivity(models.Model):
    """
    Represents honeypot activity detected from a rustbucket.
    """
    rustbucket = models.ForeignKey(
        Rustbucket,
        on_delete=models.CASCADE,
        related_name='honeypot_activities',
        help_text="The rustbucket this activity was detected from"
    )
    
    ACTIVITY_TYPE_CHOICES = [
        ('scan', 'Scan'),
        ('exploit', 'Exploit'),
        ('bruteforce', 'Brute Force'),
        ('malware', 'Malware'),
        ('SSH_BRUTEFORCE', 'SSH Brute Force'),
    ]
    type = models.CharField(
        max_length=20,
        choices=ACTIVITY_TYPE_CHOICES,
        help_text="Type of activity"
    )

    # For backward compatibility with tests
    activity_type = models.CharField(
        max_length=20,
        null=True,
        blank=True,
        help_text="Activity type (for backward compatibility)"
    )
    
    source_ip = models.GenericIPAddressField(
        help_text="Source IP of the activity"
    )
    
    timestamp = models.DateTimeField(
        default=timezone.now,
        help_text="When the activity was detected"
    )
    
    details = models.TextField(
        help_text="Details of the activity (string or JSON string)"
    )

    class Meta:
        ordering = ['-timestamp']
        verbose_name = 'Honeypot Activity'
        verbose_name_plural = 'Honeypot Activities'

    def save(self, *args, **kwargs):
        # Keep activity_type in sync with type for backward compatibility
        if self.type and not self.activity_type:
            self.activity_type = self.type
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.type} from {self.source_ip}"


class NotificationChannel(models.Model):
    """
    Represents a notification channel for alerts.

    Supports email, Slack, and webhook notifications with configurable
    filtering based on severity and alert types.
    """
    CHANNEL_TYPE_CHOICES = [
        ('email', 'Email'),
        ('slack', 'Slack'),
        ('webhook', 'Webhook'),
    ]

    name = models.CharField(
        max_length=255,
        help_text="Name of the notification channel"
    )

    channel_type = models.CharField(
        max_length=20,
        choices=CHANNEL_TYPE_CHOICES,
        help_text="Type of notification channel"
    )

    # Configuration stored as JSON
    # For email: {"recipients": ["email1@example.com", "email2@example.com"]}
    # For Slack: {"webhook_url": "https://hooks.slack.com/services/..."}
    # For webhook: {"url": "https://your-webhook.com/endpoint", "headers": {...}}
    config = models.JSONField(
        help_text="Configuration for the notification channel (email addresses, webhook URLs, etc.)"
    )

    is_active = models.BooleanField(
        default=True,
        help_text="Whether this notification channel is active"
    )

    # Filter criteria
    SEVERITY_CHOICES = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
    ]

    min_severity = models.CharField(
        max_length=10,
        default='low',
        choices=SEVERITY_CHOICES,
        help_text="Minimum severity level to trigger notifications"
    )

    alert_types = models.JSONField(
        default=list,
        blank=True,
        help_text="List of alert types to notify on (empty = all types)"
    )

    created_at = models.DateTimeField(
        default=timezone.now,
        help_text="When the notification channel was created"
    )

    updated_at = models.DateTimeField(
        auto_now=True,
        help_text="When the notification channel was last updated"
    )

    class Meta:
        ordering = ['-created_at']
        verbose_name = 'Notification Channel'
        verbose_name_plural = 'Notification Channels'

    def __str__(self):
        return f"{self.name} ({self.channel_type})"