"""Admin API views for registration key management.

This module provides endpoints for creating, listing, and revoking
registration keys that rustbuckets use to register with the registry.
"""
import json
from datetime import timedelta

from django.http import JsonResponse
from django.shortcuts import render
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST, require_GET

from rustbucketregistry.models import RegistrationKey, AuditLog
from rustbucketregistry.permissions import admin_required


@csrf_exempt
@require_POST
@admin_required
def create_registration_key(request):
    """Create a new registration key.

    This is the only time the key value is shown - it must be copied
    and securely provided to the rustbucket operator.

    Expected JSON payload:
    {
        "name": "string",  # Required - label for this key
        "expires_in_days": int  # Optional - days until expiration
    }

    Returns:
        JsonResponse with key value (only time shown)
    """
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        data = {}

    name = data.get('name')
    if not name:
        return JsonResponse({'error': 'Name is required'}, status=400)

    # Calculate expiration if provided
    expires_at = None
    expires_in_days = data.get('expires_in_days')
    if expires_in_days:
        try:
            expires_at = timezone.now() + timedelta(days=int(expires_in_days))
        except (ValueError, TypeError):
            return JsonResponse({'error': 'Invalid expires_in_days value'}, status=400)

    # Create the registration key
    reg_key = RegistrationKey(
        name=name,
        created_by=request.user,
        expires_at=expires_at
    )
    reg_key.save()

    # Log the action
    AuditLog.log(
        user=request.user,
        action='create',
        resource_type='registration_key',
        resource_id=reg_key.id,
        details={'name': name},
        request=request
    )

    return JsonResponse({
        'status': 'success',
        'key': reg_key.key,  # Only time the key is shown
        'id': reg_key.id,
        'name': reg_key.name,
        'expires_at': reg_key.expires_at.isoformat() if reg_key.expires_at else None,
        'message': 'Copy this key now - it will not be shown again'
    }, status=201)


@require_GET
@admin_required
def list_registration_keys(request):
    """List all registration keys with their status.

    Keys are returned with status but NOT with the key value itself
    (for security - the key value is only shown once at creation).

    Returns:
        JsonResponse with list of keys and their metadata
    """
    keys = RegistrationKey.objects.all().select_related('created_by', 'used_by_rustbucket')

    key_list = []
    for key in keys:
        key_data = {
            'id': key.id,
            'name': key.name,
            'status': key.get_status(),
            'created_at': key.created_at.isoformat(),
            'created_by': key.created_by.username if key.created_by else None,
            'expires_at': key.expires_at.isoformat() if key.expires_at else None,
        }

        if key.used:
            key_data['used_at'] = key.used_at.isoformat() if key.used_at else None
            key_data['used_by_rustbucket'] = {
                'id': key.used_by_rustbucket.id,
                'name': key.used_by_rustbucket.name
            } if key.used_by_rustbucket else None

        key_list.append(key_data)

    return JsonResponse({
        'status': 'success',
        'count': len(key_list),
        'keys': key_list
    })


@csrf_exempt
@require_POST
@admin_required
def revoke_registration_key(request, key_id):
    """Revoke an unused registration key.

    Revoked keys cannot be used for registration.
    Already-used keys cannot be revoked (they're already consumed).

    Args:
        key_id: ID of the registration key to revoke

    Returns:
        JsonResponse with success/error status
    """
    try:
        reg_key = RegistrationKey.objects.get(id=key_id)
    except RegistrationKey.DoesNotExist:
        return JsonResponse({'error': 'Registration key not found'}, status=404)

    if reg_key.used:
        return JsonResponse(
            {'error': 'Cannot revoke a key that has already been used'}, status=400
        )

    if reg_key.revoked:
        return JsonResponse({'error': 'Key is already revoked'}, status=400)

    reg_key.revoke()

    # Log the action
    AuditLog.log(
        user=request.user,
        action='revoke_access',
        resource_type='registration_key',
        resource_id=reg_key.id,
        details={'name': reg_key.name},
        request=request
    )

    return JsonResponse({
        'status': 'success',
        'message': f'Registration key "{reg_key.name}" has been revoked'
    })


@admin_required
def registration_keys_view(request):
    """Render the registration keys management page.

    Admin-only page that displays all registration keys and allows
    creating new keys and revoking unused ones.

    Args:
        request: HTTP request object

    Returns:
        Rendered registration_keys.html template
    """
    keys = RegistrationKey.objects.all().select_related(
        'created_by', 'used_by_rustbucket'
    ).order_by('-created_at')

    return render(request, 'registration_keys.html', {'keys': keys})
