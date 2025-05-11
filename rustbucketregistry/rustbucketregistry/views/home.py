"""
Home views for the RustBucket Registry application.
"""
from django.http import HttpResponse, Http404
from django.shortcuts import render, get_object_or_404

from rustbucketregistry.libs.utils import format_registry_name
from rustbucketregistry.models import Rustbucket


def get_bucket_data():
    """
    Get actual bucket data from the database.
    Falls back to empty list if no buckets exist.

    Returns:
        list: A list of Rustbucket objects
    """
    # Get all rustbuckets from the database
    return list(Rustbucket.objects.all())


def index(request):
    """
    Home page view.

    Args:
        request: The HTTP request

    Returns:
        HttpResponse: The HTTP response
    """
    buckets = get_bucket_data()

    context = {
        'buckets': buckets
    }

    return render(request, 'home.html', context)


def detail(request, bucket_id):
    """
    Detail view for a specific rustbucket.

    Args:
        request: The HTTP request
        bucket_id: The ID of the bucket to display

    Returns:
        HttpResponse: The HTTP response
    """
    bucket = get_object_or_404(Rustbucket, id=bucket_id)

    context = {
        'bucket': bucket
    }

    return render(request, 'detail.html', context)


def about(request):
    """
    About page view.

    Args:
        request: The HTTP request

    Returns:
        HttpResponse: The HTTP response
    """
    registry_name = format_registry_name("Rust Bucket Registry")
    context = {
        'registry_name': registry_name,
        'description': 'A registry for Rust packages and components.'
    }
    return render(request, 'about.html', context)