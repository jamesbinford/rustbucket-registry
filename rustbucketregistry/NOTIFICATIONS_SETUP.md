# Real-time Alert Notifications Setup

The Rustbucket Registry supports real-time alert notifications through multiple channels: **Email**, **Slack**, and **Webhooks**.

## Features

✅ Automatic notifications when alerts are created
✅ Email, Slack, and webhook support
✅ Severity-based filtering (only notify on high-severity alerts, etc.)
✅ Alert type filtering
✅ Easy configuration via Django Admin
✅ Test notifications before going live
✅ Multiple notification channels supported

## Quick Start

### 1. Run Migration

```bash
cd rustbucketregistry
source ../env/bin/activate
python manage.py migrate
```

###2. Configure Email Settings (for Email Notifications)

Add to your `.env` file:

```bash
# Email Configuration
EMAIL_BACKEND=django.core.mail.backends.smtp.EmailBackend
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USE_TLS=True
EMAIL_HOST_USER=your-email@gmail.com
EMAIL_HOST_PASSWORD=your-app-password
DEFAULT_FROM_EMAIL=rustbucket-registry@example.com
```

**For Gmail**: Use an [App Password](https://support.google.com/accounts/answer/185833) instead of your regular password.

### 3. Create Notification Channels

Go to Django Admin → Notification Channels → Add Notification Channel

## Notification Channel Types

### Email Notifications

**Configuration JSON:**
```json
{
  "recipients": [
    "admin@example.com",
    "security@example.com"
  ]
}
```

**Example Setup:**
- **Name**: Email Alerts
- **Channel Type**: Email
- **Config**: `{"recipients": ["admin@example.com"]}`
- **Min Severity**: high
- **Is Active**: ✓

### Slack Notifications

**1. Create Slack Webhook:**
1. Go to https://api.slack.com/apps
2. Create a new app or select existing
3. Go to "Incoming Webhooks" and activate
4. Click "Add New Webhook to Workspace"
5. Select a channel and authorize
6. Copy the webhook URL

**Configuration JSON:**
```json
{
  "webhook_url": "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
}
```

**Example Setup:**
- **Name**: Slack Security Channel
- **Channel Type**: Slack
- **Config**: `{"webhook_url": "https://hooks.slack.com/services/..."}`
- **Min Severity**: medium
- **Is Active**: ✓

### Webhook Notifications

**Configuration JSON:**
```json
{
  "url": "https://your-webhook.com/endpoint",
  "headers": {
    "X-API-Key": "your-api-key",
    "Authorization": "Bearer your-token"
  }
}
```

**Webhook Payload Format:**
```json
{
  "alert_id": 123,
  "alert_type": "error",
  "severity": "high",
  "message": "Rustbucket node1 is not responding",
  "is_resolved": false,
  "created_at": "2025-12-12T10:30:00Z",
  "rustbucket": {
    "id": "BKT123456",
    "name": "Production Node 1"
  }
}
```

**Example Setup:**
- **Name**: PagerDuty Webhook
- **Channel Type**: Webhook
- **Config**: `{"url": "https://events.pagerduty.com/v2/enqueue", "headers": {"X-Routing-Key": "your-key"}}`
- **Min Severity**: high
- **Is Active**: ✓

## Filtering Alerts

### Severity Filtering

Set **Min Severity** to control which alerts trigger notifications:

- **low**: All alerts (info, warnings, errors)
- **medium**: Only medium and high severity alerts
- **high**: Only critical/high severity alerts

### Alert Type Filtering

Leave **Alert Types** empty to receive all alert types, or specify specific types:

```json
["error", "warning"]
```

This will only send notifications for `error` and `warning` type alerts.

## Testing Notifications

### Test via Django Admin

1. Go to **Notification Channels**
2. Select one or more channels
3. From the Actions dropdown, select **"Send test notification to selected channels"**
4. Click **Go**

You should receive a test notification immediately!

### Test via Command Line

```bash
# List all channels
python manage.py test_notification --list

# Test a specific channel
python manage.py test_notification --channel "Email Alerts"

# Test all active channels
python manage.py test_notification --all
```

## How It Works

1. When an **Alert** is created in the database
2. Django's signal handler (`signals.py`) is triggered
3. The notification service checks all active notification channels
4. For each channel that matches the alert criteria:
   - Severity level meets minimum requirement
   - Alert type matches filter (if specified)
5. Notifications are sent through the appropriate channels
6. Results are logged for troubleshooting

## Managing Channels

### Via Django Admin

**Create:**
1. Admin → Notification Channels → Add
2. Fill in configuration
3. Test it!

**Edit:**
1. Click on a channel
2. Modify settings
3. Save and test again

**Activate/Deactivate:**
1. Select channels
2. Actions → "Activate/Deactivate selected channels"

**Delete:**
1. Select channels
2. Actions → "Delete selected notification channels"

### Via Django Shell

```python
from rustbucketregistry.models import NotificationChannel

# Create email channel
NotificationChannel.objects.create(
    name='Critical Alerts',
    channel_type='email',
    config={'recipients': ['admin@example.com']},
    min_severity='high',
    is_active=True
)

# Create Slack channel
NotificationChannel.objects.create(
    name='Slack Alerts',
    channel_type='slack',
    config={'webhook_url': 'https://hooks.slack.com/services/...'},
    min_severity='medium',
    is_active=True
)

# List all channels
for channel in NotificationChannel.objects.all():
    print(f"{channel.name}: {channel.channel_type} ({'active' if channel.is_active else 'inactive'})")
```

## Troubleshooting

### Notifications Not Sending

**Check 1**: Is the channel active?
- Go to Admin → Notification Channels
- Verify "Is Active" is checked

**Check 2**: Does the alert meet severity requirements?
- Check the alert's severity level
- Compare with channel's "Min Severity"

**Check 3**: Test the channel manually
```bash
python manage.py test_notification --channel "Your Channel Name"
```

**Check 4**: Check Django logs
```bash
# Look for notification-related errors
tail -f /path/to/django/logs
```

### Email Not Sending

**Check email settings in `.env`:**
```bash
echo $EMAIL_HOST
echo $EMAIL_HOST_USER
```

**Test email configuration:**
```python
from django.core.mail import send_mail

send_mail(
    'Test',
    'This is a test email',
    'from@example.com',
    ['to@example.com'],
)
```

**Common issues:**
- Gmail: Use App Password, not regular password
- Check EMAIL_USE_TLS is True for port 587
- Firewall blocking outbound SMTP connections

### Slack Notifications Failing

**Verify webhook URL:**
- Make sure you copied the complete URL
- Test it with curl:
```bash
curl -X POST -H 'Content-Type: application/json' \
  -d '{"text":"Test message"}' \
  https://hooks.slack.com/services/YOUR/WEBHOOK/URL
```

**Check Slack app permissions:**
- Go to api.slack.com/apps
- Verify webhook is still active

### Webhook Failures

**Test your webhook endpoint:**
```bash
curl -X POST -H 'Content-Type: application/json' \
  -d '{"test": "data"}' \
  https://your-webhook.com/endpoint
```

**Check logs for detailed error messages**

**Verify headers are correct** (API keys, tokens, etc.)

## Rate Limiting

Currently, there is no built-in rate limiting for notifications. To prevent notification spam:

1. **Use appropriate severity levels** - Don't set everything to "low"
2. **Filter alert types** - Only notify on important alert types
3. **Review alerts regularly** - Delete or resolve old alerts to prevent re-triggering

## Best Practices

### For Production

1. **Use multiple channels** for redundancy
   - Email for non-critical alerts
   - Slack for team awareness
   - Webhook to PagerDuty/OpsGenie for critical alerts

2. **Set appropriate severity levels**
   - **Email**: medium or low (for awareness)
   - **Slack**: medium (for team discussion)
   - **PagerDuty**: high only (on-call escalation)

3. **Test regularly**
   - Test channels monthly to ensure they still work
   - Update webhook URLs/API keys before they expire

4. **Monitor notification delivery**
   - Check logs for failed notifications
   - Set up alerts for notification failures (meta-alerting!)

### Configuration Examples

**Scenario: Small Team**
```
Channel 1: Email to team@company.com (severity: medium)
Channel 2: Slack #alerts channel (severity: high)
```

**Scenario: Large Operations Team**
```
Channel 1: Email to ops@company.com (severity: low, alert_types: ["info", "warning"])
Channel 2: Slack #ops-alerts (severity: medium)
Channel 3: PagerDuty webhook (severity: high, alert_types: ["error"])
Channel 4: Email to security@company.com (severity: high)
```

## Advanced Configuration

### Custom Alert Types

To notify only on specific alert types:

```json
["honeypot_malware", "rustbucket_offline", "high_cpu"]
```

### Multiple Recipients

Email channels support multiple recipients:

```json
{
  "recipients": [
    "oncall@company.com",
    "backup@company.com",
    "manager@company.com"
  ]
}
```

### Webhook with Custom Headers

For services requiring authentication:

```json
{
  "url": "https://api.service.com/alerts",
  "headers": {
    "Authorization": "Bearer your-token-here",
    "X-API-Key": "your-api-key",
    "X-Custom-Header": "custom-value"
  }
}
```

## Integration Examples

### PagerDuty

```json
{
  "url": "https://events.pagerduty.com/v2/enqueue",
  "headers": {
    "Content-Type": "application/json",
    "X-Routing-Key": "your-pagerduty-routing-key"
  }
}
```

### Opsgenie

```json
{
  "url": "https://api.opsgenie.com/v2/alerts",
  "headers": {
    "Authorization": "GenieKey your-api-key"
  }
}
```

### Microsoft Teams

1. Create an Incoming Webhook connector in Teams
2. Use webhook channel type with the Teams webhook URL

### Discord

```json
{
  "url": "https://discord.com/api/webhooks/YOUR/WEBHOOK/URL"
}
```

Note: Discord webhooks use a slightly different format. You may need to adjust the `send_webhook_notification` function for full compatibility.

## Disabling Notifications

### Temporarily Disable All Notifications

Deactivate all channels in Django Admin, or set via shell:

```python
from rustbucketregistry.models import NotificationChannel
NotificationChannel.objects.all().update(is_active=False)
```

### Disable for Specific Alerts

Add logic to your alert creation code to skip notification:

```python
# This is handled automatically by signals
# To prevent notifications, you'd need to modify signals.py
# or temporarily deactivate channels
```

## Next Steps

After setting up notifications:

1. Create test alerts to verify notifications work
2. Adjust severity levels based on your needs
3. Set up multiple channels for redundancy
4. Document your notification strategy for your team
5. Review notification logs periodically

## Resources

- [Django Email Documentation](https://docs.djangoproject.com/en/stable/topics/email/)
- [Slack Incoming Webhooks](https://api.slack.com/messaging/webhooks)
- [PagerDuty Events API](https://developer.pagerduty.com/docs/events-api-v2/overview/)
- [Django Signals Documentation](https://docs.djangoproject.com/en/stable/topics/signals/)

## Related Features

- **Issue #4**: Enhanced Alert Management (assign, comment, resolve)
- **Issue #8**: Export and Reporting (notification logs, statistics)
- **Issue #5**: Automated Scheduled Tasks (health check alerts)
