"""
Notification service for sending alerts through various channels.

Supports email, Slack, and webhook notifications with configurable
filtering and rate limiting.
"""
import logging
import json
import requests
from django.core.mail import send_mail
from django.conf import settings
from django.utils import timezone

logger = logging.getLogger(__name__)


def send_alert_notification(alert):
    """
    Send notifications for an alert through all configured channels.

    Args:
        alert: Alert model instance

    Returns:
        dict: Summary of notification results
    """
    from rustbucketregistry.models import NotificationChannel

    results = {
        'sent': 0,
        'failed': 0,
        'channels': []
    }

    # Get active notification channels
    channels = NotificationChannel.objects.filter(is_active=True)

    for channel in channels:
        # Check if alert meets the channel's severity criteria
        if not should_notify(alert, channel):
            logger.debug(f"Skipping channel {channel.name} - alert doesn't meet criteria")
            continue

        # Send notification based on channel type
        try:
            if channel.channel_type == 'email':
                success = send_email_notification(alert, channel.config)
            elif channel.channel_type == 'slack':
                success = send_slack_notification(alert, channel.config)
            elif channel.channel_type == 'webhook':
                success = send_webhook_notification(alert, channel.config)
            else:
                logger.warning(f"Unknown channel type: {channel.channel_type}")
                success = False

            if success:
                results['sent'] += 1
                results['channels'].append({
                    'name': channel.name,
                    'type': channel.channel_type,
                    'status': 'success'
                })
                logger.info(f"Successfully sent notification via {channel.name}")
            else:
                results['failed'] += 1
                results['channels'].append({
                    'name': channel.name,
                    'type': channel.channel_type,
                    'status': 'failed'
                })

        except Exception as e:
            logger.error(f"Error sending notification via {channel.name}: {str(e)}", exc_info=True)
            results['failed'] += 1
            results['channels'].append({
                'name': channel.name,
                'type': channel.channel_type,
                'status': 'error',
                'error': str(e)
            })

    logger.info(f"Notification results: {results['sent']} sent, {results['failed']} failed")
    return results


def should_notify(alert, channel):
    """
    Check if an alert meets the notification criteria for a channel.

    Args:
        alert: Alert model instance
        channel: NotificationChannel model instance

    Returns:
        bool: True if notification should be sent
    """
    # Map severity levels to numeric values for comparison
    severity_levels = {'low': 1, 'medium': 2, 'high': 3}

    # Get alert severity (normalize to lowercase)
    alert_severity = getattr(alert, 'severity', 'low')
    if alert_severity:
        alert_severity = alert_severity.lower()
    else:
        alert_severity = 'low'

    # Check severity level
    alert_level = severity_levels.get(alert_severity, 1)
    min_level = severity_levels.get(channel.min_severity, 1)

    if alert_level < min_level:
        return False

    # Check alert type filter (if specified)
    if channel.alert_types:
        alert_type = getattr(alert, 'type', '')
        if alert_type not in channel.alert_types:
            return False

    return True


def send_email_notification(alert, config):
    """
    Send email notification for an alert.

    Args:
        alert: Alert model instance
        config: dict with keys:
            - recipients: list of email addresses

    Returns:
        bool: True if email was sent successfully
    """
    try:
        recipients = config.get('recipients', [])
        if not recipients:
            logger.warning("No recipients configured for email notification")
            return False

        # Handle case where recipients might be a JSON string
        if isinstance(recipients, str):
            recipients = json.loads(recipients)

        # Build email content
        subject = f'Rustbucket Alert: {alert.type.upper() if alert.type else "ALERT"}'

        rustbucket_name = alert.rustbucket.name if alert.rustbucket else 'Unknown'

        message = f"""
Rustbucket Alert Notification

Alert Type: {alert.type or 'N/A'}
Severity: {alert.severity or 'N/A'}
Rustbucket: {rustbucket_name}
Message: {alert.message}
Time: {alert.created_at}
Resolved: {'Yes' if alert.is_resolved else 'No'}

---
This is an automated notification from Rustbucket Registry.
"""

        # Send email
        send_mail(
            subject=subject,
            message=message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=recipients,
            fail_silently=False,
        )

        return True

    except Exception as e:
        logger.error(f"Error sending email notification: {str(e)}", exc_info=True)
        return False


def send_slack_notification(alert, config):
    """
    Send Slack notification for an alert.

    Args:
        alert: Alert model instance
        config: dict with keys:
            - webhook_url: Slack webhook URL

    Returns:
        bool: True if Slack message was sent successfully
    """
    try:
        webhook_url = config.get('webhook_url')
        if not webhook_url:
            logger.warning("No webhook URL configured for Slack notification")
            return False

        # Determine color based on severity
        severity = getattr(alert, 'severity', 'low')
        if severity:
            severity = severity.lower()

        if severity == 'high':
            color = 'danger'  # Red
        elif severity == 'medium':
            color = 'warning'  # Yellow
        else:
            color = 'good'  # Green

        rustbucket_name = alert.rustbucket.name if alert.rustbucket else 'Unknown'
        rustbucket_id = alert.rustbucket.id if alert.rustbucket else 'N/A'

        # Build Slack message payload
        payload = {
            'text': f'*Rustbucket Alert: {alert.type.upper() if alert.type else "ALERT"}*',
            'attachments': [{
                'color': color,
                'fields': [
                    {
                        'title': 'Severity',
                        'value': (alert.severity or 'N/A').upper(),
                        'short': True
                    },
                    {
                        'title': 'Rustbucket',
                        'value': f'{rustbucket_name} ({rustbucket_id})',
                        'short': True
                    },
                    {
                        'title': 'Message',
                        'value': alert.message,
                        'short': False
                    },
                    {
                        'title': 'Time',
                        'value': alert.created_at.strftime('%Y-%m-%d %H:%M:%S UTC'),
                        'short': True
                    },
                    {
                        'title': 'Status',
                        'value': 'Resolved' if alert.is_resolved else 'Active',
                        'short': True
                    }
                ],
                'footer': 'Rustbucket Registry',
                'ts': int(alert.created_at.timestamp())
            }]
        }

        # Send to Slack
        response = requests.post(
            webhook_url,
            json=payload,
            headers={'Content-Type': 'application/json'},
            timeout=10
        )

        response.raise_for_status()

        return True

    except Exception as e:
        logger.error(f"Error sending Slack notification: {str(e)}", exc_info=True)
        return False


def send_webhook_notification(alert, config):
    """
    Send generic webhook notification for an alert.

    Args:
        alert: Alert model instance
        config: dict with keys:
            - url: Webhook URL
            - headers: Optional dict of HTTP headers

    Returns:
        bool: True if webhook was called successfully
    """
    try:
        url = config.get('url')
        if not url:
            logger.warning("No URL configured for webhook notification")
            return False

        # Get optional custom headers
        custom_headers = config.get('headers', {})
        headers = {
            'Content-Type': 'application/json',
            **custom_headers
        }

        # Build payload
        payload = {
            'alert_id': alert.id,
            'alert_type': alert.type,
            'severity': alert.severity,
            'message': alert.message,
            'is_resolved': alert.is_resolved,
            'created_at': alert.created_at.isoformat(),
            'rustbucket': {
                'id': alert.rustbucket.id if alert.rustbucket else None,
                'name': alert.rustbucket.name if alert.rustbucket else None,
            } if alert.rustbucket else None
        }

        # Send webhook
        response = requests.post(
            url,
            json=payload,
            headers=headers,
            timeout=10
        )

        response.raise_for_status()

        return True

    except Exception as e:
        logger.error(f"Error sending webhook notification: {str(e)}", exc_info=True)
        return False


def test_notification_channel(channel):
    """
    Send a test notification to verify channel configuration.

    Args:
        channel: NotificationChannel model instance

    Returns:
        dict: Test results with success status and message
    """
    try:
        # Create a fake test alert
        from rustbucketregistry.models import Alert

        test_alert = Alert(
            id=0,
            type='test',
            severity='medium',
            message='This is a test notification from Rustbucket Registry. If you receive this, your notification channel is configured correctly!',
            created_at=timezone.now(),
            is_resolved=False
        )

        # Add a fake rustbucket reference
        class FakeRustbucket:
            id = 'TEST-000'
            name = 'Test Rustbucket'

        test_alert.rustbucket = FakeRustbucket()

        # Send based on channel type
        if channel.channel_type == 'email':
            success = send_email_notification(test_alert, channel.config)
        elif channel.channel_type == 'slack':
            success = send_slack_notification(test_alert, channel.config)
        elif channel.channel_type == 'webhook':
            success = send_webhook_notification(test_alert, channel.config)
        else:
            return {
                'success': False,
                'message': f'Unknown channel type: {channel.channel_type}'
            }

        if success:
            return {
                'success': True,
                'message': f'Test notification sent successfully via {channel.channel_type}'
            }
        else:
            return {
                'success': False,
                'message': 'Failed to send test notification (check logs for details)'
            }

    except Exception as e:
        logger.error(f"Error testing notification channel: {str(e)}", exc_info=True)
        return {
            'success': False,
            'message': f'Error: {str(e)}'
        }
