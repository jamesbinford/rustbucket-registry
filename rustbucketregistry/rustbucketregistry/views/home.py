"""Home views for the RustBucket Registry application.

This module contains view functions for handling the main pages of the
RustBucket Registry application, including the home page and detail pages.
"""
from django.http import HttpResponse, Http404
from django.shortcuts import render, get_object_or_404
from django.contrib.auth.decorators import login_required

from rustbucketregistry.libs.utils import format_registry_name
from rustbucketregistry.models import Rustbucket, RustbucketAccess, AuditLog
from rustbucketregistry.permissions import (
    filter_rustbuckets_for_user,
    rustbucket_access_required,
    get_user_profile,
)


def get_bucket_data(user=None):
    """Gets actual bucket data from the database.

    If a user is provided, filters to only buckets they can access.

    Args:
        user: Optional Django User instance to filter by.

    Returns:
        A list of Rustbucket objects.
    """
    queryset = Rustbucket.objects.all()
    if user:
        queryset = filter_rustbuckets_for_user(user, queryset)
    return list(queryset)


@login_required
def index(request):
    """Renders the home page view.

    Shows only rustbuckets the user has access to.

    Args:
        request: The HTTP request object.

    Returns:
        HttpResponse: The rendered home page.
    """
    buckets = get_bucket_data(request.user)
    profile = get_user_profile(request.user)

    context = {
        'buckets': buckets,
        'user_profile': profile,
    }

    return render(request, 'home.html', context)


def _user_can_change_status(user, profile, bucket):
    """Check if user has permission to change rustbucket status.

    Args:
        user: Django User instance.
        profile: UserProfile instance.
        bucket: Rustbucket instance.

    Returns:
        bool: True if user can change status.
    """
    if profile.is_admin() or profile.is_analyst():
        return True

    try:
        access = RustbucketAccess.objects.get(user=user, rustbucket=bucket)
        return access.can_manage()
    except RustbucketAccess.DoesNotExist:
        return False


@login_required
@rustbucket_access_required('view')
def detail(request, bucket_id):
    """Renders the detail view for a specific rustbucket.

    Requires view access to the specific rustbucket.
    Handles POST requests for status changes (requires manage permission).

    Args:
        request: The HTTP request object.
        bucket_id: The ID of the bucket to display.

    Returns:
        HttpResponse: The rendered detail page.
    """
    bucket = get_object_or_404(Rustbucket, id=bucket_id)
    profile = get_user_profile(request.user)

    can_change_status = _user_can_change_status(request.user, profile, bucket)

    if request.method == 'POST' and can_change_status:
        new_status = request.POST.get('status')
        valid_statuses = dict(Rustbucket.STATUS_CHOICES)
        if new_status in valid_statuses and new_status != bucket.status:
            old_status = bucket.status
            bucket.status = new_status
            bucket.save()

            AuditLog.log(
                user=request.user,
                action='change_status',
                resource_type='rustbucket',
                resource_id=str(bucket.id),
                details={'old_status': old_status, 'new_status': new_status},
                request=request
            )

    context = {
        'bucket': bucket,
        'user_profile': profile,
        'can_change_status': can_change_status,
        'status_choices': Rustbucket.STATUS_CHOICES,
    }

    return render(request, 'detail.html', context)