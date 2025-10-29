"""
Admin configuration for the RustBucket Registry application.
"""
from django.contrib import admin
from .models import Rustbucket, LogSink, LogEntry, Alert, HoneypotActivity


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
            'fields': ('id', 'name', 'api_key')
        }),
        ('Connection Information', {
            'fields': ('ip_address', 'status')
        }),
        ('System Information', {
            'fields': ('operating_system', 'cpu_usage', 'memory_usage', 'disk_space', 'uptime', 'connections')
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