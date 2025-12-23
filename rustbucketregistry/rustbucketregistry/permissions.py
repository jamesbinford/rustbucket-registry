"""
Permission decorators and utilities for Role-Based Access Control.

This module provides decorators and helper functions to enforce
role-based permissions on views and API endpoints.
"""
import functools
import logging
from django.http import JsonResponse, HttpResponseForbidden
from django.shortcuts import redirect
from django.contrib import messages
from django.contrib.auth.decorators import login_required

from rustbucketregistry.models import UserProfile, RustbucketAccess, AuditLog

logger = logging.getLogger(__name__)


def get_user_profile(user):
    """
    Get or create a UserProfile for the given user.

    Args:
        user: Django User instance

    Returns:
        UserProfile instance
    """
    if not user or not user.is_authenticated:
        return None

    profile, created = UserProfile.objects.get_or_create(
        user=user,
        defaults={'role': 'admin' if user.is_superuser else 'viewer'}
    )

    # Update role if user became superuser
    if user.is_superuser and profile.role != 'admin':
        profile.role = 'admin'
        profile.save()

    return profile


def _check_permission(request, check_func, error_message, redirect_url='home'):
    """
    Internal helper to check permissions and handle failures.

    Args:
        request: HTTP request
        check_func: Function that takes profile and returns bool
        error_message: Message to show on failure
        redirect_url: URL to redirect to on failure (for HTML requests)

    Returns:
        tuple: (allowed: bool, response: HttpResponse or None)
    """
    if not request.user.is_authenticated:
        if request.headers.get('Content-Type') == 'application/json':
            return False, JsonResponse({'error': 'Authentication required'}, status=401)
        return False, redirect('login')

    profile = get_user_profile(request.user)
    if not profile:
        if request.headers.get('Content-Type') == 'application/json':
            return False, JsonResponse({'error': 'User profile not found'}, status=403)
        return False, redirect('login')

    if not check_func(profile):
        # Log the access attempt
        AuditLog.log(
            user=request.user,
            action='view',
            details={'error': error_message, 'path': request.path},
            request=request,
            success=False
        )

        if request.headers.get('Content-Type') == 'application/json':
            return False, JsonResponse({'error': error_message}, status=403)

        messages.error(request, error_message)
        return False, redirect(redirect_url)

    return True, None


def role_required(*roles):
    """
    Decorator that requires the user to have one of the specified roles.

    Usage:
        @role_required('admin')
        def admin_only_view(request):
            ...

        @role_required('admin', 'analyst')
        def analyst_view(request):
            ...
    """
    def decorator(view_func):
        @functools.wraps(view_func)
        @login_required
        def wrapper(request, *args, **kwargs):
            def check_role(profile):
                if 'admin' in roles and profile.is_admin():
                    return True
                if 'analyst' in roles and profile.is_analyst():
                    return True
                if 'viewer' in roles and profile.is_viewer():
                    return True
                return profile.role in roles

            allowed, response = _check_permission(
                request,
                check_role,
                f"You need one of these roles: {', '.join(roles)}"
            )

            if not allowed:
                return response

            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator


def admin_required(view_func):
    """
    Decorator that requires the user to have admin role.

    Usage:
        @admin_required
        def admin_view(request):
            ...
    """
    @functools.wraps(view_func)
    @login_required
    def wrapper(request, *args, **kwargs):
        allowed, response = _check_permission(
            request,
            lambda profile: profile.is_admin(),
            "Administrator access required"
        )

        if not allowed:
            return response

        return view_func(request, *args, **kwargs)
    return wrapper


def analyst_required(view_func):
    """
    Decorator that requires the user to have analyst role or higher.

    Usage:
        @analyst_required
        def analyst_view(request):
            ...
    """
    @functools.wraps(view_func)
    @login_required
    def wrapper(request, *args, **kwargs):
        allowed, response = _check_permission(
            request,
            lambda profile: profile.is_analyst(),
            "Analyst access required"
        )

        if not allowed:
            return response

        return view_func(request, *args, **kwargs)
    return wrapper


def rustbucket_access_required(access_level='view'):
    """
    Decorator that requires the user to have access to the specified rustbucket.

    The rustbucket ID should be passed as 'bucket_id' or 'rustbucket_id' in kwargs.

    Args:
        access_level: Required access level ('view', 'manage', or 'admin')

    Usage:
        @rustbucket_access_required('view')
        def view_rustbucket(request, bucket_id):
            ...

        @rustbucket_access_required('manage')
        def manage_rustbucket(request, bucket_id):
            ...
    """
    def decorator(view_func):
        @functools.wraps(view_func)
        @login_required
        def wrapper(request, *args, **kwargs):
            # Get rustbucket ID from kwargs
            bucket_id = kwargs.get('bucket_id') or kwargs.get('rustbucket_id')

            if not bucket_id:
                # No specific rustbucket, allow if user has general access
                return view_func(request, *args, **kwargs)

            profile = get_user_profile(request.user)
            if not profile:
                if request.headers.get('Content-Type') == 'application/json':
                    return JsonResponse({'error': 'User profile not found'}, status=403)
                return redirect('login')

            # Admins have full access
            if profile.is_admin():
                return view_func(request, *args, **kwargs)

            # Check if user has all_rustbuckets_access
            if profile.all_rustbuckets_access:
                # Still need to check access level for manage/admin
                if access_level == 'view':
                    return view_func(request, *args, **kwargs)
                elif access_level == 'manage' and profile.is_analyst():
                    return view_func(request, *args, **kwargs)

            # Check specific rustbucket access
            try:
                access = RustbucketAccess.objects.get(
                    user=request.user,
                    rustbucket_id=bucket_id
                )

                if access_level == 'view' and access.can_view():
                    return view_func(request, *args, **kwargs)
                elif access_level == 'manage' and access.can_manage():
                    return view_func(request, *args, **kwargs)
                elif access_level == 'admin' and access.is_admin():
                    return view_func(request, *args, **kwargs)

            except RustbucketAccess.DoesNotExist:
                pass

            # Access denied
            AuditLog.log(
                user=request.user,
                action='view',
                resource_type='rustbucket',
                resource_id=bucket_id,
                details={'error': f'Access denied (required: {access_level})'},
                request=request,
                success=False
            )

            error_message = f"You don't have {access_level} access to this rustbucket"
            if request.headers.get('Content-Type') == 'application/json':
                return JsonResponse({'error': error_message}, status=403)

            messages.error(request, error_message)
            return redirect('home')

        return wrapper
    return decorator


def can_manage_alerts(view_func):
    """
    Decorator that requires the user to be able to manage alerts.

    Usage:
        @can_manage_alerts
        def resolve_alert(request, alert_id):
            ...
    """
    @functools.wraps(view_func)
    @login_required
    def wrapper(request, *args, **kwargs):
        allowed, response = _check_permission(
            request,
            lambda profile: profile.can_manage_alerts(),
            "You don't have permission to manage alerts"
        )

        if not allowed:
            return response

        return view_func(request, *args, **kwargs)
    return wrapper


def filter_rustbuckets_for_user(user, queryset=None):
    """
    Filter a queryset of rustbuckets to only those the user can access.

    Args:
        user: Django User instance
        queryset: Optional Rustbucket queryset (defaults to all)

    Returns:
        Filtered QuerySet
    """
    from rustbucketregistry.models import Rustbucket

    if queryset is None:
        queryset = Rustbucket.objects.all()

    if not user or not user.is_authenticated:
        return queryset.none()

    profile = get_user_profile(user)
    if not profile:
        return queryset.none()

    if profile.is_admin() or profile.all_rustbuckets_access:
        return queryset

    accessible_ids = RustbucketAccess.objects.filter(
        user=user
    ).values_list('rustbucket_id', flat=True)

    return queryset.filter(id__in=accessible_ids)


def user_can_access_rustbucket(user, rustbucket_id):
    """
    Check if a user can access a specific rustbucket.

    Args:
        user: Django User instance
        rustbucket_id: Rustbucket ID

    Returns:
        bool: True if user has access
    """
    if not user or not user.is_authenticated:
        return False

    profile = get_user_profile(user)
    if not profile:
        return False

    return profile.can_access_rustbucket(rustbucket_id)


class PermissionMixin:
    """
    Mixin for class-based views that adds permission checking.

    Usage:
        class MyView(PermissionMixin, View):
            required_role = 'analyst'  # or None for just login

            def get(self, request):
                ...
    """
    required_role = None
    required_rustbucket_access = None  # 'view', 'manage', or 'admin'

    def dispatch(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect('login')

        profile = get_user_profile(request.user)
        if not profile:
            return redirect('login')

        # Check role
        if self.required_role:
            if self.required_role == 'admin' and not profile.is_admin():
                messages.error(request, "Administrator access required")
                return redirect('home')
            elif self.required_role == 'analyst' and not profile.is_analyst():
                messages.error(request, "Analyst access required")
                return redirect('home')

        # Check rustbucket access
        if self.required_rustbucket_access:
            bucket_id = kwargs.get('bucket_id') or kwargs.get('rustbucket_id')
            if bucket_id and not profile.is_admin():
                if not profile.all_rustbuckets_access:
                    try:
                        access = RustbucketAccess.objects.get(
                            user=request.user,
                            rustbucket_id=bucket_id
                        )
                        if self.required_rustbucket_access == 'manage' and not access.can_manage():
                            messages.error(request, "Manage access required for this rustbucket")
                            return redirect('home')
                        elif self.required_rustbucket_access == 'admin' and not access.is_admin():
                            messages.error(request, "Admin access required for this rustbucket")
                            return redirect('home')
                    except RustbucketAccess.DoesNotExist:
                        messages.error(request, "You don't have access to this rustbucket")
                        return redirect('home')

        # Store profile on request for easy access in views
        request.user_profile = profile

        return super().dispatch(request, *args, **kwargs)


# =============================================================================
# API Key Authentication
# =============================================================================

def get_api_key_from_request(request):
    """
    Extract API key from request headers or body.

    Supports:
    - Authorization: Bearer <api_key>
    - Authorization: ApiKey <api_key>
    - X-API-Key: <api_key>
    - api_key in JSON body

    Args:
        request: HTTP request object

    Returns:
        str: The API key or None if not found
    """
    # Check Authorization header
    auth_header = request.META.get('HTTP_AUTHORIZATION', '')
    if auth_header:
        if auth_header.startswith('Bearer '):
            return auth_header[7:]
        elif auth_header.startswith('ApiKey '):
            return auth_header[7:]

    # Check X-API-Key header
    api_key = request.META.get('HTTP_X_API_KEY')
    if api_key:
        return api_key

    # Check JSON body (for POST requests)
    if request.method in ('POST', 'PUT', 'PATCH'):
        try:
            import json
            body = json.loads(request.body)
            if isinstance(body, dict) and 'api_key' in body:
                return body['api_key']
        except (json.JSONDecodeError, TypeError, ValueError):
            pass

    return None


def validate_api_key(api_key_value):
    """
    Validate an API key and return the associated rustbucket.

    Args:
        api_key_value: The API key string

    Returns:
        tuple: (APIKey instance, Rustbucket instance) or (None, None) if invalid
    """
    from rustbucketregistry.models import APIKey

    if not api_key_value:
        return None, None

    try:
        api_key = APIKey.objects.select_related('rustbucket').get(key=api_key_value)
        if api_key.is_valid():
            api_key.record_usage()
            return api_key, api_key.rustbucket
    except APIKey.DoesNotExist:
        pass

    return None, None


def api_key_required(view_func):
    """
    Decorator that requires a valid API key for the request.

    On success, adds 'api_key' and 'rustbucket' to the request object.

    Usage:
        @api_key_required
        def my_api_view(request):
            # request.api_key and request.rustbucket are available
            ...
    """
    @functools.wraps(view_func)
    def wrapper(request, *args, **kwargs):
        api_key_value = get_api_key_from_request(request)

        if not api_key_value:
            return JsonResponse({
                'success': False,
                'message': 'Missing API key'
            }, status=401)

        api_key, rustbucket = validate_api_key(api_key_value)

        if not api_key:
            # Log failed authentication attempt
            AuditLog.log(
                user=None,
                action='api_access',
                details={'error': 'Invalid or expired API key'},
                request=request,
                success=False
            )
            return JsonResponse({
                'success': False,
                'message': 'Invalid or expired API key'
            }, status=401)

        # Attach to request for use in view
        request.api_key = api_key
        request.rustbucket = rustbucket

        return view_func(request, *args, **kwargs)
    return wrapper
