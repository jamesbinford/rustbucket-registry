"""
Models for the RustBucket Registry application.
"""
import secrets
import uuid

from django.contrib.auth.models import User
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

    # S3 bucket configuration (where rustbucket stores its logs)
    s3_bucket_name = models.CharField(
        max_length=255,
        null=True,
        blank=True,
        help_text="S3 bucket name where this rustbucket stores logs"
    )
    s3_region = models.CharField(
        max_length=50,
        null=True,
        blank=True,
        default='us-east-1',
        help_text="AWS region for the S3 bucket"
    )
    s3_access_key_id = models.CharField(
        max_length=255,
        null=True,
        blank=True,
        help_text="AWS access key ID for accessing the S3 bucket (optional for same-account access)"
    )
    s3_secret_access_key = models.CharField(
        max_length=255,
        null=True,
        blank=True,
        help_text="AWS secret access key (stored encrypted - use IAM roles in production)"
    )
    s3_prefix = models.CharField(
        max_length=255,
        null=True,
        blank=True,
        default='logs/',
        help_text="Prefix/folder path in the S3 bucket where logs are stored"
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

    def has_s3_configured(self):
        """Check if this rustbucket has S3 bucket configuration."""
        return bool(self.s3_bucket_name and self.s3_region)

    def get_s3_client(self):
        """
        Get an S3 client configured for this rustbucket's bucket.

        Returns:
            boto3 S3 client or None if not configured
        """
        if not self.has_s3_configured():
            return None

        import boto3

        # Use rustbucket-specific credentials if provided, otherwise use default
        if self.s3_access_key_id and self.s3_secret_access_key:
            return boto3.client(
                's3',
                region_name=self.s3_region,
                aws_access_key_id=self.s3_access_key_id,
                aws_secret_access_key=self.s3_secret_access_key
            )
        else:
            # Use default credentials (IAM role, environment variables, etc.)
            return boto3.client('s3', region_name=self.s3_region)


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

    ALERT_TYPE_CHOICES = [
        ('error', 'Error'),
        ('warning', 'Warning'),
        ('info', 'Info'),
    ]

    SEVERITY_CHOICES = [
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
    ]

    type = models.CharField(
        max_length=10,
        choices=ALERT_TYPE_CHOICES,
        help_text="Type of alert"
    )

    severity = models.CharField(
        max_length=10,
        choices=SEVERITY_CHOICES,
        default='low',
        help_text="Alert severity level"
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


    class Meta:
        ordering = ['-created_at']
        verbose_name = 'Alert'
        verbose_name_plural = 'Alerts'

    def __str__(self):
        return f"Alert: {self.severity} - {self.message[:50]}"


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


# =============================================================================
# Role-Based Access Control (RBAC) Models
# =============================================================================

class UserProfile(models.Model):
    """
    Extends Django's User model with role-based access control.

    Roles:
    - admin: Full access to all features and rustbuckets
    - analyst: Can view all data, manage alerts, but cannot manage users/settings
    - viewer: Read-only access to assigned rustbuckets only
    """
    ROLE_CHOICES = [
        ('admin', 'Administrator'),
        ('analyst', 'Analyst'),
        ('viewer', 'Viewer'),
    ]

    user = models.OneToOneField(
        User,
        on_delete=models.CASCADE,
        related_name='profile',
        help_text="The Django user this profile belongs to"
    )

    role = models.CharField(
        max_length=20,
        choices=ROLE_CHOICES,
        default='viewer',
        help_text="User's role determining their access level"
    )

    # If True, user can access all rustbuckets (useful for analysts)
    all_rustbuckets_access = models.BooleanField(
        default=False,
        help_text="If True, user can access all rustbuckets regardless of specific assignments"
    )

    created_at = models.DateTimeField(
        default=timezone.now,
        help_text="When the profile was created"
    )

    updated_at = models.DateTimeField(
        auto_now=True,
        help_text="When the profile was last updated"
    )

    class Meta:
        verbose_name = 'User Profile'
        verbose_name_plural = 'User Profiles'

    def __str__(self):
        return f"{self.user.username} ({self.get_role_display()})"

    def is_admin(self):
        """Check if user has admin role."""
        return self.role == 'admin' or self.user.is_superuser

    def is_analyst(self):
        """Check if user has analyst role or higher."""
        return self.role in ('admin', 'analyst') or self.user.is_superuser

    def is_viewer(self):
        """Check if user has viewer role or higher (all authenticated users)."""
        return self.role in ('admin', 'analyst', 'viewer') or self.user.is_superuser

    def can_access_rustbucket(self, rustbucket):
        """
        Check if user can access a specific rustbucket.

        Args:
            rustbucket: Rustbucket instance or rustbucket ID

        Returns:
            bool: True if user has access
        """
        # Admins and users with all_rustbuckets_access can access everything
        if self.is_admin() or self.all_rustbuckets_access:
            return True

        # Check specific rustbucket access
        rustbucket_id = rustbucket.id if hasattr(rustbucket, 'id') else rustbucket
        return RustbucketAccess.objects.filter(
            user=self.user,
            rustbucket_id=rustbucket_id
        ).exists()

    def get_accessible_rustbuckets(self):
        """
        Get queryset of rustbuckets the user can access.

        Returns:
            QuerySet of Rustbucket objects
        """
        if self.is_admin() or self.all_rustbuckets_access:
            return Rustbucket.objects.all()

        accessible_ids = RustbucketAccess.objects.filter(
            user=self.user
        ).values_list('rustbucket_id', flat=True)

        return Rustbucket.objects.filter(id__in=accessible_ids)

    def can_manage_alerts(self):
        """Check if user can manage (acknowledge/resolve) alerts."""
        return self.is_analyst()

    def can_manage_users(self):
        """Check if user can manage other users."""
        return self.is_admin()

    def can_manage_settings(self):
        """Check if user can manage system settings."""
        return self.is_admin()


class RustbucketAccess(models.Model):
    """
    Defines per-rustbucket access permissions for users.

    This model allows fine-grained control over which rustbuckets
    a user can access when they don't have all_rustbuckets_access.
    """
    ACCESS_LEVEL_CHOICES = [
        ('view', 'View Only'),
        ('manage', 'Manage (view + manage alerts)'),
        ('admin', 'Admin (full control)'),
    ]

    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='rustbucket_access',
        help_text="The user granted access"
    )

    rustbucket = models.ForeignKey(
        Rustbucket,
        on_delete=models.CASCADE,
        related_name='user_access',
        help_text="The rustbucket the user has access to"
    )

    access_level = models.CharField(
        max_length=20,
        choices=ACCESS_LEVEL_CHOICES,
        default='view',
        help_text="Level of access the user has to this rustbucket"
    )

    granted_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='access_grants',
        help_text="The user who granted this access"
    )

    granted_at = models.DateTimeField(
        default=timezone.now,
        help_text="When access was granted"
    )

    class Meta:
        verbose_name = 'Rustbucket Access'
        verbose_name_plural = 'Rustbucket Access'
        unique_together = ['user', 'rustbucket']
        ordering = ['user__username', 'rustbucket__name']

    def __str__(self):
        return f"{self.user.username} -> {self.rustbucket.name} ({self.get_access_level_display()})"

    def can_view(self):
        """Check if this access level allows viewing."""
        return self.access_level in ('view', 'manage', 'admin')

    def can_manage(self):
        """Check if this access level allows managing alerts."""
        return self.access_level in ('manage', 'admin')

    def is_admin(self):
        """Check if this access level is admin."""
        return self.access_level == 'admin'


class AuditLog(models.Model):
    """
    Tracks user actions for security auditing.

    Records who did what, when, and on which resource.
    """
    ACTION_CHOICES = [
        ('login', 'User Login'),
        ('logout', 'User Logout'),
        ('view', 'View Resource'),
        ('create', 'Create Resource'),
        ('update', 'Update Resource'),
        ('delete', 'Delete Resource'),
        ('resolve_alert', 'Resolve Alert'),
        ('grant_access', 'Grant Access'),
        ('revoke_access', 'Revoke Access'),
        ('change_role', 'Change User Role'),
        ('export', 'Export Data'),
        ('api_access', 'API Access'),
        ('create_api_key', 'Create API Key'),
        ('revoke_api_key', 'Revoke API Key'),
        ('regenerate_api_key', 'Regenerate API Key'),
        ('change_status', 'Change Status'),
    ]

    user = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='audit_logs',
        help_text="The user who performed the action"
    )

    action = models.CharField(
        max_length=50,
        choices=ACTION_CHOICES,
        help_text="The action performed"
    )

    resource_type = models.CharField(
        max_length=50,
        null=True,
        blank=True,
        help_text="Type of resource affected (e.g., 'rustbucket', 'alert', 'user')"
    )

    resource_id = models.CharField(
        max_length=255,
        null=True,
        blank=True,
        help_text="ID of the resource affected"
    )

    details = models.JSONField(
        default=dict,
        blank=True,
        help_text="Additional details about the action"
    )

    ip_address = models.GenericIPAddressField(
        null=True,
        blank=True,
        help_text="IP address of the user"
    )

    user_agent = models.TextField(
        null=True,
        blank=True,
        help_text="User agent string from the request"
    )

    timestamp = models.DateTimeField(
        default=timezone.now,
        db_index=True,
        help_text="When the action occurred"
    )

    success = models.BooleanField(
        default=True,
        help_text="Whether the action was successful"
    )

    class Meta:
        verbose_name = 'Audit Log'
        verbose_name_plural = 'Audit Logs'
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['user', 'timestamp']),
            models.Index(fields=['action', 'timestamp']),
            models.Index(fields=['resource_type', 'resource_id']),
        ]

    def __str__(self):
        username = self.user.username if self.user else 'Anonymous'
        return f"{username} - {self.action} - {self.timestamp}"

    @classmethod
    def log(cls, user, action, resource_type=None, resource_id=None,
            details=None, request=None, success=True):
        """
        Convenience method to create an audit log entry.

        Args:
            user: User performing the action
            action: Action type (from ACTION_CHOICES)
            resource_type: Type of resource affected
            resource_id: ID of affected resource
            details: Additional details dict
            request: HTTP request object (to extract IP and user agent)
            success: Whether action was successful

        Returns:
            AuditLog instance
        """
        ip_address = None
        user_agent = None

        if request:
            # Get IP address
            x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
            if x_forwarded_for:
                ip_address = x_forwarded_for.split(',')[0].strip()
            else:
                ip_address = request.META.get('REMOTE_ADDR')

            user_agent = request.META.get('HTTP_USER_AGENT', '')[:500]

        return cls.objects.create(
            user=user,
            action=action,
            resource_type=resource_type,
            resource_id=str(resource_id) if resource_id else None,
            details=details or {},
            ip_address=ip_address,
            user_agent=user_agent,
            success=success
        )


# =============================================================================
# API Key Management Models
# =============================================================================

class APIKey(models.Model):
    """
    API key for rustbucket authentication (inbound calls to registry).

    Multiple API keys can be created per rustbucket, each with its own
    name, expiration, and usage tracking.
    """
    # The actual API key value - 32-byte URL-safe token
    key = models.CharField(
        max_length=64,
        unique=True,
        editable=False,
        help_text="The API key value (auto-generated)"
    )

    # Human-readable name/label for the key
    name = models.CharField(
        max_length=255,
        help_text="Name/label for this API key (e.g., 'Production', 'Development')"
    )

    # The rustbucket this key belongs to
    rustbucket = models.ForeignKey(
        Rustbucket,
        on_delete=models.CASCADE,
        related_name='api_keys',
        help_text="The rustbucket this API key authenticates"
    )

    # Who created this key
    created_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='created_api_keys',
        help_text="The user who created this API key"
    )

    # Key status
    is_active = models.BooleanField(
        default=True,
        help_text="Whether this API key is active and can be used"
    )

    # Optional expiration
    expires_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="When this API key expires (null = never expires)"
    )

    # Usage tracking
    last_used_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="When this API key was last used"
    )

    usage_count = models.PositiveIntegerField(
        default=0,
        help_text="Number of times this API key has been used"
    )

    # Timestamps
    created_at = models.DateTimeField(
        default=timezone.now,
        help_text="When this API key was created"
    )

    updated_at = models.DateTimeField(
        auto_now=True,
        help_text="When this API key was last updated"
    )

    class Meta:
        ordering = ['-created_at']
        verbose_name = 'API Key'
        verbose_name_plural = 'API Keys'
        indexes = [
            models.Index(fields=['key']),
            models.Index(fields=['rustbucket', 'is_active']),
        ]

    def __str__(self):
        return f"{self.name} ({self.rustbucket.name})"

    @staticmethod
    def _generate_key():
        """Generate a secure, URL-safe API key token."""
        return secrets.token_urlsafe(32)

    def save(self, *args, **kwargs):
        if not self.key:
            self.key = self._generate_key()
        super().save(*args, **kwargs)

    def is_valid(self):
        """Check if this API key is currently valid (active and not expired)."""
        if not self.is_active:
            return False
        if self.expires_at and self.expires_at < timezone.now():
            return False
        return True

    def record_usage(self):
        """Record that this API key was used."""
        self.last_used_at = timezone.now()
        self.usage_count += 1
        self.save(update_fields=['last_used_at', 'usage_count'])

    def revoke(self):
        """Revoke this API key."""
        self.is_active = False
        self.save(update_fields=['is_active', 'updated_at'])

    def regenerate(self):
        """Generate a new key value (invalidates old key)."""
        self.key = self._generate_key()
        self.save(update_fields=['key', 'updated_at'])
        return self.key