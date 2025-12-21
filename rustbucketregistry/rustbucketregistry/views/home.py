"""Home views for the RustBucket Registry application.

This module contains view functions for handling the main pages of the
RustBucket Registry application, including the home page, detail pages,
and about page.
"""
from django.http import HttpResponse, Http404
from django.shortcuts import render, get_object_or_404
from django.contrib.auth.decorators import login_required

from rustbucketregistry.libs.utils import format_registry_name
from rustbucketregistry.models import Rustbucket
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


@login_required
@rustbucket_access_required('view')
def detail(request, bucket_id):
    """Renders the detail view for a specific rustbucket.

    Requires view access to the specific rustbucket.

    Args:
        request: The HTTP request object.
        bucket_id: The ID of the bucket to display.

    Returns:
        HttpResponse: The rendered detail page.
    """
    bucket = get_object_or_404(Rustbucket, id=bucket_id)
    profile = get_user_profile(request.user)

    context = {
        'bucket': bucket,
        'user_profile': profile,
    }

    return render(request, 'detail.html', context)


def about(request):
    """Renders the about page view.
    
    Args:
        request: The HTTP request object.
        
    Returns:
        HttpResponse: The rendered about page.
    """
    registry_name = format_registry_name("Rust Bucket Registry")
    context = {
        'registry_name': registry_name,
        'description': 'A registry for Rust packages and components.'
    }
    return render(request, 'about.html', context)