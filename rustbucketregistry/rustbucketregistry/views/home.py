"""Home views for the RustBucket Registry application.

This module contains view functions for handling the main pages of the
RustBucket Registry application, including the home page, detail pages,
and about page.
"""
from django.http import HttpResponse, Http404
from django.shortcuts import render, get_object_or_404

from rustbucketregistry.libs.utils import format_registry_name
from rustbucketregistry.models import Rustbucket


def get_bucket_data():
    """Gets actual bucket data from the database.
    
    Falls back to empty list if no buckets exist.
    
    Returns:
        A list of Rustbucket objects.
    """
    # Get all rustbuckets from the database
    return list(Rustbucket.objects.all())


def index(request):
    """Renders the home page view.
    
    Args:
        request: The HTTP request object.
        
    Returns:
        HttpResponse: The rendered home page.
    """
    buckets = get_bucket_data()

    context = {
        'buckets': buckets
    }

    return render(request, 'home.html', context)


def detail(request, bucket_id):
    """Renders the detail view for a specific rustbucket.
    
    Args:
        request: The HTTP request object.
        bucket_id: The ID of the bucket to display.
        
    Returns:
        HttpResponse: The rendered detail page.
    """
    bucket = get_object_or_404(Rustbucket, id=bucket_id)

    context = {
        'bucket': bucket
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