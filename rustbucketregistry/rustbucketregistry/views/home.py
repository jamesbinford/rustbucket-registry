"""
Home views for the RustBucket Registry application.
"""
import random
from datetime import datetime, timedelta
from django.http import HttpResponse, Http404
from django.shortcuts import render

from rustbucketregistry.libs.utils import format_registry_name


def get_bucket_data():
    """
    Generate sample bucket data.

    Returns:
        list: A list of bucket dictionaries
    """
    statuses = ['Active', 'Inactive', 'Maintenance']
    bucket_names = [
        'rust-packages', 'cargo-cache', 'dependency-bin',
        'crate-storage', 'module-archive', 'compiler-tools',
        'rust-docs', 'binary-artifacts', 'build-cache',
        'testing-artifacts', 'release-packages', 'staging-bin'
    ]

    operating_systems = ['Ubuntu 22.04', 'Debian 12', 'CentOS 9', 'Fedora 38',
                         'RHEL 9', 'FreeBSD 14', 'OpenBSD 7.4', 'Alpine Linux 3.19']

    buckets = []
    for i in range(1, 11):  # Generate 10 buckets
        # Generate a random IPv4 address
        ip = f"{random.randint(10, 250)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"

        # Generate a random date in the last 30 days
        days_ago = random.randint(0, 30)
        hours_ago = random.randint(0, 23)
        minutes_ago = random.randint(0, 59)
        log_date = datetime.now() - timedelta(days=days_ago, hours=hours_ago, minutes=minutes_ago)

        buckets.append({
            'id': f"BKT{i:03d}",
            'name': random.choice(bucket_names),
            'status': random.choice(statuses),
            'ip_address': ip,
            'operating_system': random.choice(operating_systems),
            'last_log_dump': log_date.strftime("%Y-%m-%d %H:%M:%S"),
            'cpu_usage': f"{random.randint(5, 95)}%",
            'memory_usage': f"{random.randint(10, 90)}%",
            'disk_space': f"{random.randint(20, 500)} GB",
            'uptime': f"{random.randint(1, 365)} days",
            'connections': random.randint(0, 100)
        })

    return buckets


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
    buckets = get_bucket_data()
    bucket = next((b for b in buckets if b['id'] == bucket_id), None)

    if not bucket:
        raise Http404(f"Bucket with ID {bucket_id} not found")

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
    # In a real application, you would render a template:
    # return render(request, 'about.html', context)
    return HttpResponse(f"About {registry_name}: {context['description']}")