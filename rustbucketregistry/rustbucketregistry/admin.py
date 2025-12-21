"""
Admin configuration for the RustBucket Registry application.
"""
from django.contrib import admin
from django.contrib import messages
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth.models import User
from .models import (
    Rustbucket, LogSink, LogEntry, Alert, HoneypotActivity, NotificationChannel,
    UserProfile, RustbucketAccess, AuditLog
)


class LogSinkInline(admin.TabularInline):
    """Inline admin view for LogSink"""
    model = LogSink
    extra = 0


class AlertInline(admin.TabularInline):
    """Inline admin view for Alert"""
    model = Alert
    extra = 0
    fk_name = 'logsink'


class LogEntryInline(admin.TabularInline):
    """Inline admin view for LogEntry"""
    model = LogEntry
    extra = 0
    fk_name = 'logsink'


class HoneypotActivityInline(admin.TabularInline):
    """Inline admin view for HoneypotActivity"""
    model = HoneypotActivity
    extra = 0


@admin.register(Rustbucket)
class RustbucketAdmin(admin.ModelAdmin):
    """Admin view for Rustbucket"""
    list_display = ('id', 'name', 'ip_address', 'status', 'operating_system', 'last_seen')
    list_filter = ('status', 'operating_system')
    search_fields = ('id', 'name', 'ip_address')
    readonly_fields = ('id', 'registered_at')
    fieldsets = (
        ('Identification', {
            'fields': ('id', 'name', 'token')
        }),
        ('Connection Information', {
            'fields': ('ip_address', 'url', 'status')
        }),
        ('System Information', {
            'fields': ('operating_system', 'cpu_usage', 'memory_usage', 'disk_space', 'uptime', 'connections')
        }),
        ('S3 Configuration', {
            'fields': ('s3_bucket_name', 's3_region', 's3_access_key_id', 's3_secret_access_key', 's3_prefix'),
            'description': 'S3 bucket where this rustbucket stores its logs. The registry will read logs directly from this bucket.',
            'classes': ('collapse',)
        }),
        ('Registration Information', {
            'fields': ('registered_at', 'last_seen', 'last_log_dump')
        }),
    )
    inlines = [LogSinkInline, HoneypotActivityInline]


@admin.register(LogSink)
class LogSinkAdmin(admin.ModelAdmin):
    """Admin view for LogSink"""
    list_display = ('id', 'rustbucket', 'log_type', 'size', 'status', 'alert_level', 'last_update')
    list_filter = ('log_type', 'status', 'alert_level')
    search_fields = ('rustbucket__name', 'rustbucket__id')
    inlines = [AlertInline, LogEntryInline]


@admin.register(LogEntry)
class LogEntryAdmin(admin.ModelAdmin):
    """Admin view for LogEntry"""
    list_display = ('id', 'logsink', 'timestamp', 'message_preview')
    list_filter = ('timestamp', 'logsink__log_type')
    search_fields = ('message', 'logsink__rustbucket__name')
    
    def message_preview(self, obj):
        """Return a preview of the message"""
        if len(obj.message) > 50:
            return f"{obj.message[:50]}..."
        return obj.message
    message_preview.short_description = 'Message'


@admin.register(Alert)
class AlertAdmin(admin.ModelAdmin):
    """Admin view for Alert"""
    list_display = ('id', 'logsink', 'type', 'message', 'is_resolved', 'created_at', 'resolved_at')
    list_filter = ('type', 'is_resolved', 'created_at')
    search_fields = ('message', 'logsink__rustbucket__name')
    actions = ['mark_as_resolved']
    
    def mark_as_resolved(self, request, queryset):
        """Mark selected alerts as resolved"""
        from django.utils import timezone
        queryset.update(is_resolved=True, resolved_at=timezone.now())
    mark_as_resolved.short_description = "Mark selected alerts as resolved"


@admin.register(HoneypotActivity)
class HoneypotActivityAdmin(admin.ModelAdmin):
    """Admin view for HoneypotActivity"""
    list_display = ('id', 'rustbucket', 'type', 'source_ip', 'timestamp')
    list_filter = ('type', 'timestamp')
    search_fields = ('rustbucket__name', 'source_ip', 'details')
    readonly_fields = ('timestamp',)


@admin.register(NotificationChannel)
class NotificationChannelAdmin(admin.ModelAdmin):
    """Admin view for NotificationChannel"""
    list_display = ('name', 'channel_type', 'is_active', 'min_severity', 'created_at')
    list_filter = ('channel_type', 'is_active', 'min_severity')
    search_fields = ('name',)
    readonly_fields = ('created_at', 'updated_at')
    actions = ['test_notification', 'activate_channels', 'deactivate_channels']

    fieldsets = (
        ('Basic Information', {
            'fields': ('name', 'channel_type', 'is_active')
        }),
        ('Configuration', {
            'fields': ('config',),
            'description': 'Configuration JSON. Examples:<br>'
                          '<strong>Email:</strong> {"recipients": ["admin@example.com", "alerts@example.com"]}<br>'
                          '<strong>Slack:</strong> {"webhook_url": "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"}<br>'
                          '<strong>Webhook:</strong> {"url": "https://your-webhook.com/endpoint", "headers": {"X-API-Key": "your-key"}}'
        }),
        ('Filters', {
            'fields': ('min_severity', 'alert_types'),
            'description': 'Control which alerts trigger notifications. Leave alert_types empty to receive all alert types.'
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )

    def test_notification(self, request, queryset):
        """Send a test notification to selected channels"""
        from rustbucketregistry.notifications import test_notification_channel

        success_count = 0
        fail_count = 0

        for channel in queryset:
            result = test_notification_channel(channel)
            if result['success']:
                success_count += 1
                self.message_user(
                    request,
                    f"✓ {channel.name}: {result['message']}",
                    level=messages.SUCCESS
                )
            else:
                fail_count += 1
                self.message_user(
                    request,
                    f"✗ {channel.name}: {result['message']}",
                    level=messages.ERROR
                )

        if success_count > 0:
            self.message_user(
                request,
                f"Successfully sent test to {success_count} channel(s)",
                level=messages.SUCCESS
            )
        if fail_count > 0:
            self.message_user(
                request,
                f"Failed to send test to {fail_count} channel(s)",
                level=messages.WARNING
            )

    test_notification.short_description = "Send test notification to selected channels"

    def activate_channels(self, request, queryset):
        """Activate selected notification channels"""
        updated = queryset.update(is_active=True)
        self.message_user(
            request,
            f"Successfully activated {updated} channel(s)",
            level=messages.SUCCESS
        )

    activate_channels.short_description = "Activate selected channels"

    def deactivate_channels(self, request, queryset):
        """Deactivate selected notification channels"""
        updated = queryset.update(is_active=False)
        self.message_user(
            request,
            f"Successfully deactivated {updated} channel(s)",
            level=messages.SUCCESS
        )

    deactivate_channels.short_description = "Deactivate selected channels"


# =============================================================================
# RBAC Admin Configuration
# =============================================================================

class UserProfileInline(admin.StackedInline):
    """Inline admin for UserProfile on User page"""
    model = UserProfile
    can_delete = False
    verbose_name_plural = 'Profile'
    fk_name = 'user'


class RustbucketAccessInline(admin.TabularInline):
    """Inline admin for RustbucketAccess on User page"""
    model = RustbucketAccess
    extra = 1
    fk_name = 'user'
    autocomplete_fields = ['rustbucket']
    readonly_fields = ('granted_at',)


class UserAdmin(BaseUserAdmin):
    """Extended User admin with profile and access management"""
    inlines = [UserProfileInline, RustbucketAccessInline]
    list_display = ('username', 'email', 'first_name', 'last_name', 'is_staff', 'get_role')
    list_filter = BaseUserAdmin.list_filter + ('profile__role',)

    def get_role(self, obj):
        """Get user's role from profile"""
        try:
            return obj.profile.get_role_display()
        except UserProfile.DoesNotExist:
            return 'No Profile'
    get_role.short_description = 'Role'
    get_role.admin_order_field = 'profile__role'

    def get_inline_instances(self, request, obj=None):
        """Only show inlines when editing existing user"""
        if not obj:
            return []
        return super().get_inline_instances(request, obj)


# Unregister the default User admin and register our custom one
admin.site.unregister(User)
admin.site.register(User, UserAdmin)


@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    """Admin view for UserProfile"""
    list_display = ('user', 'role', 'all_rustbuckets_access', 'created_at')
    list_filter = ('role', 'all_rustbuckets_access')
    search_fields = ('user__username', 'user__email')
    readonly_fields = ('created_at', 'updated_at')
    raw_id_fields = ('user',)

    fieldsets = (
        ('User', {
            'fields': ('user',)
        }),
        ('Role & Access', {
            'fields': ('role', 'all_rustbuckets_access'),
            'description': 'Admin: Full access. Analyst: View all + manage alerts. Viewer: Read-only, limited to assigned rustbuckets.'
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )


@admin.register(RustbucketAccess)
class RustbucketAccessAdmin(admin.ModelAdmin):
    """Admin view for RustbucketAccess"""
    list_display = ('user', 'rustbucket', 'access_level', 'granted_by', 'granted_at')
    list_filter = ('access_level', 'granted_at')
    search_fields = ('user__username', 'rustbucket__name', 'rustbucket__id')
    readonly_fields = ('granted_at',)
    raw_id_fields = ('user', 'granted_by')
    autocomplete_fields = ['rustbucket']

    def save_model(self, request, obj, form, change):
        """Automatically set granted_by to current user"""
        if not change:  # Only on create
            obj.granted_by = request.user
        super().save_model(request, obj, form, change)


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    """Admin view for AuditLog"""
    list_display = ('timestamp', 'user', 'action', 'resource_type', 'resource_id', 'success', 'ip_address')
    list_filter = ('action', 'success', 'resource_type', 'timestamp')
    search_fields = ('user__username', 'resource_id', 'ip_address', 'details')
    readonly_fields = ('user', 'action', 'resource_type', 'resource_id', 'details', 'ip_address', 'user_agent', 'timestamp', 'success')
    date_hierarchy = 'timestamp'

    def has_add_permission(self, request):
        """Prevent manual creation of audit logs"""
        return False

    def has_change_permission(self, request, obj=None):
        """Prevent editing of audit logs"""
        return False

    def has_delete_permission(self, request, obj=None):
        """Only superusers can delete audit logs"""
        return request.user.is_superuser