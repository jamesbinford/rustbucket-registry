"""API Key management endpoints.

This module provides API endpoints for creating, listing, rotating,
and revoking API keys.
"""
import json

from django.http import JsonResponse
from django.utils import timezone

from rustbucketregistry.models import APIKey, AuditLog, Rustbucket
from rustbucketregistry.permissions import api_endpoint


@api_endpoint(role='analyst', method='GET')
def list_api_keys(request, rustbucket_id=None):
    """List API keys, optionally filtered by rustbucket.

    Args:
        request: HTTP request
        rustbucket_id: Optional rustbucket ID to filter by

    Returns:
        JsonResponse with list of API keys (keys are masked)
    """
    queryset = APIKey.objects.select_related('rustbucket', 'created_by')

    if rustbucket_id:
        queryset = queryset.filter(rustbucket_id=rustbucket_id)

    keys = []
    for key in queryset:
        keys.append({
            'id': key.id,
            'name': key.name,
            'rustbucket_id': key.rustbucket.id,
            'rustbucket_name': key.rustbucket.name,
            'is_active': key.is_active,
            'expires_at': key.expires_at.isoformat() if key.expires_at else None,
            'last_used_at': key.last_used_at.isoformat() if key.last_used_at else None,
            'usage_count': key.usage_count,
            'created_at': key.created_at.isoformat(),
            'created_by': key.created_by.username if key.created_by else None,
            'key_prefix': key.key[:8] + '...' if key.key else None  # Only show prefix
        })

    return JsonResponse({'success': True, 'api_keys': keys})


@api_endpoint(role='analyst', method='POST')
def create_api_key(request, rustbucket_id):
    """Create a new API key for a rustbucket.

    Expected JSON payload:
    {
        "name": "required - key name/label",
        "expires_at": "optional - ISO format datetime"
    }

    Returns:
        JsonResponse with the new API key (full key shown only once!)
    """
    try:
        data = json.loads(request.body)

        # Get rustbucket
        try:
            rustbucket = Rustbucket.objects.get(id=rustbucket_id)
        except Rustbucket.DoesNotExist:
            return JsonResponse({'error': 'Rustbucket not found'}, status=404)

        # Validate name
        name = data.get('name')
        if not name:
            return JsonResponse({'error': 'Missing required field: name'}, status=400)

        # Parse expiration
        expires_at = None
        if 'expires_at' in data and data['expires_at']:
            try:
                expires_at = timezone.datetime.fromisoformat(data['expires_at'])
            except (ValueError, TypeError):
                return JsonResponse(
                    {'error': 'Invalid expires_at format (use ISO format)'}, status=400
                )

        # Create API key
        api_key = APIKey.objects.create(
            name=name,
            rustbucket=rustbucket,
            created_by=request.user,
            expires_at=expires_at
        )

        # Audit log
        AuditLog.log(
            user=request.user,
            action='create_api_key',
            resource_type='api_key',
            resource_id=api_key.id,
            details={'name': name, 'rustbucket': rustbucket_id},
            request=request
        )

        return JsonResponse({
            'success': True,
            'message': 'API key created successfully',
            'api_key': {
                'id': api_key.id,
                'name': api_key.name,
                'key': api_key.key,  # Full key shown only on creation!
                'rustbucket_id': rustbucket.id,
                'expires_at': api_key.expires_at.isoformat() if api_key.expires_at else None,
                'created_at': api_key.created_at.isoformat()
            }
        }, status=201)

    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON payload'}, status=400)


@api_endpoint(role='analyst', method='POST')
def revoke_api_key(request, api_key_id):
    """Revoke an API key.

    Returns:
        JsonResponse with success status
    """
    try:
        api_key = APIKey.objects.get(id=api_key_id)
    except APIKey.DoesNotExist:
        return JsonResponse({'error': 'API key not found'}, status=404)

    api_key.revoke()

    # Audit log
    AuditLog.log(
        user=request.user,
        action='revoke_api_key',
        resource_type='api_key',
        resource_id=api_key.id,
        details={'name': api_key.name, 'rustbucket': api_key.rustbucket.id},
        request=request
    )

    return JsonResponse({
        'success': True,
        'message': 'API key revoked successfully'
    })


@api_endpoint(role='analyst', method='POST')
def rotate_api_key(request, api_key_id):
    """Rotate (regenerate) an API key.

    Returns:
        JsonResponse with the new key value
    """
    try:
        api_key = APIKey.objects.get(id=api_key_id)
    except APIKey.DoesNotExist:
        return JsonResponse({'error': 'API key not found'}, status=404)

    old_prefix = api_key.key[:8] + '...'
    new_key = api_key.regenerate()

    # Audit log
    AuditLog.log(
        user=request.user,
        action='regenerate_api_key',
        resource_type='api_key',
        resource_id=api_key.id,
        details={
            'name': api_key.name,
            'rustbucket': api_key.rustbucket.id,
            'old_key_prefix': old_prefix
        },
        request=request
    )

    return JsonResponse({
        'success': True,
        'message': 'API key rotated successfully',
        'api_key': {
            'id': api_key.id,
            'name': api_key.name,
            'key': new_key,  # New key shown only once!
            'rustbucket_id': api_key.rustbucket.id
        }
    })
