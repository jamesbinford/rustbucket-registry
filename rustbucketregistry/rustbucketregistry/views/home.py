"""
Home views for the RustBucket Registry application.
"""
from django.http import HttpResponse
from django.shortcuts import render

from rustbucketregistry.libs.utils import format_registry_name


def index(request):
    """
    Home page view.
    
    Args:
        request: The HTTP request
        
    Returns:
        HttpResponse: The HTTP response
    """
    return HttpResponse("Welcome to the RustBucket Registry!")


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
    # In a real application, you would render a template:
    # return render(request, 'about.html', context)
    return HttpResponse(f"About {registry_name}: {context['description']}")