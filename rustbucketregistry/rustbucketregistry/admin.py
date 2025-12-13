"""
Admin configuration for the RustBucket Registry application.
"""
from django.contrib import admin
from django.contrib import messages
from .models import Rustbucket, LogSink, LogEntry, Alert, HoneypotActivity, NotificationChannel


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