"""Dashboard views for the RustBucket Registry application.

This module contains view functions for the analytics dashboard,
including chart data APIs and summary statistics.
"""
import functools
from datetime import datetime, timedelta

from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.core.cache import cache
from django.db.models import Count
from django.http import JsonResponse
from django.shortcuts import render
from django.utils import timezone

from rustbucketregistry.models import Alert, Rustbucket
from rustbucketregistry.permissions import (
    filter_rustbuckets_for_user,
    get_user_profile,
    rustbucket_access_required,
)


def cached_dashboard_api(cache_key_prefix):
    """Decorator that adds caching to dashboard API endpoints.

    Builds cache key from prefix, range param, user id, and optional bucket_id.
    Returns cached JsonResponse if available, otherwise calls view and caches result.

    Args:
        cache_key_prefix: String prefix for the cache key (e.g., 'dashboard_overview')

    Usage:
        @cached_dashboard_api('dashboard_overview')
        def dashboard_overview_api(request):
            # Return dict, not JsonResponse
            return {'total': 100, ...}
    """
    def decorator(view_func):
        @functools.wraps(view_func)
        def wrapper(request, *args, **kwargs):
            # Build cache key components
            range_param = request.GET.get('range', '7d')
            user_id = request.user.id
            bucket_id = kwargs.get('bucket_id', 'all')
            cache_key = f'{cache_key_prefix}_{range_param}_{bucket_id}_{user_id}'

            # Try cache first
            cached_data = cache.get(cache_key)
            if cached_data:
                return JsonResponse(cached_data)

            # Call view to get data dict
            result = view_func(request, *args, **kwargs)

            # If view returned a JsonResponse directly (e.g., error), return it
            if isinstance(result, JsonResponse):
                return result

            # Cache and return
            cache.set(cache_key, result, timeout=settings.DASHBOARD_CACHE_TIMEOUT)
            return JsonResponse(result)

        return wrapper
    return decorator


def get_time_range(request):
    """Parses time range from request query parameters.

    Args:
        request: The HTTP request object.

    Returns:
        tuple: (start_datetime, end_datetime)
    """
    range_param = request.GET.get('range', '7d')
    now = timezone.now()

    if range_param == '24h':
        start = now - timedelta(hours=24)
    elif range_param == '7d':
        start = now - timedelta(days=7)
    elif range_param == '30d':
        start = now - timedelta(days=30)
    elif range_param == 'custom':
        try:
            start_str = request.GET.get('start', '')
            end_str = request.GET.get('end', '')
            start = datetime.fromisoformat(start_str.replace('Z', '+00:00'))
            end = datetime.fromisoformat(end_str.replace('Z', '+00:00'))
            if timezone.is_naive(start):
                start = timezone.make_aware(start)
            if timezone.is_naive(end):
                end = timezone.make_aware(end)
            return (start, end)
        except (ValueError, TypeError):
            # Fall back to 7 days if parsing fails
            start = now - timedelta(days=7)
    else:
        start = now - timedelta(days=7)

    return (start, now)


def parse_percentage(value):
    """Parses percentage string to float.

    Args:
        value: A percentage string like "45%" or "45".

    Returns:
        Float value or 0.0 if parsing fails.
    """
    if not value:
        return 0.0
    try:
        return float(str(value).replace('%', '').strip())
    except (ValueError, TypeError):
        return 0.0


@login_required
def dashboard_view(request):
    """Main dashboard page view.

    Shows only rustbuckets the user has access to.

    Args:
        request: The HTTP request object.

    Returns:
        HttpResponse: The rendered dashboard template.
    """
    # Get rustbuckets filtered by user access
    rustbuckets = filter_rustbuckets_for_user(request.user)
    profile = get_user_profile(request.user)

    context = {
        'rustbuckets': rustbuckets,
        'user_profile': profile,
    }
    return render(request, 'dashboard.html', context)


@login_required
@cached_dashboard_api('dashboard_overview')
def dashboard_overview_api(request):
    """API endpoint for dashboard summary statistics.

    Returns statistics only for rustbuckets the user has access to.

    Args:
        request: The HTTP request object.

    Returns:
        dict: Summary statistics including rustbucket counts,
            attack totals, and unresolved alerts.
    """
    start, end = get_time_range(request)

    # Get accessible rustbuckets for the user
    accessible_rustbuckets = filter_rustbuckets_for_user(request.user)

    # Get rustbucket statistics (filtered by access)
    total_rustbuckets = accessible_rustbuckets.count()
    active_rustbuckets = accessible_rustbuckets.filter(status='Active').count()

    # Attack statistics now come from log file analysis (not tracked separately)
    total_attacks = 0

    # Get unresolved alerts (filtered by access)
    unresolved_alerts = Alert.objects.filter(
        logsink__rustbucket__in=accessible_rustbuckets,
        is_resolved=False
    ).count()

    return {
        'total_rustbuckets': total_rustbuckets,
        'active_rustbuckets': active_rustbuckets,
        'total_attacks': total_attacks,
        'unresolved_alerts': unresolved_alerts,
        'time_range': {
            'start': start.isoformat(),
            'end': end.isoformat()
        }
    }


@login_required
@cached_dashboard_api('dashboard_attacks')
def dashboard_attacks_api(request):
    """API endpoint for attack trends over time (line chart data).

    Returns only attacks for rustbuckets the user has access to.

    Args:
        request: The HTTP request object.

    Returns:
        dict: Labels and datasets for line chart showing
            attack counts by type over time.
    """
    start, end = get_time_range(request)

    # Attack data is now in log files, not tracked separately
    # Generate empty date range for chart structure
    sorted_dates = []
    current = start.date()
    while current <= end.date():
        sorted_dates.append(current.strftime('%Y-%m-%d'))
        current += timedelta(days=1)

    # Build empty datasets
    attack_types = ['scan', 'exploit', 'bruteforce', 'malware']
    colors = {
        'scan': '#2196F3',
        'exploit': '#c62828',
        'bruteforce': '#ef6c00',
        'malware': '#9c27b0'
    }
    datasets = []
    for attack_type in attack_types:
        datasets.append({
            'label': attack_type,
            'data': [0] * len(sorted_dates),
            'borderColor': colors.get(attack_type, '#333'),
            'fill': False
        })

    return {
        'labels': sorted_dates,
        'datasets': datasets
    }


@login_required
@cached_dashboard_api('dashboard_top_ips')
def dashboard_top_ips_api(request):
    """API endpoint for top attacking IPs (bar chart data).

    Returns only attacks for rustbuckets the user has access to.

    Args:
        request: The HTTP request object.

    Returns:
        dict: Labels (IP addresses) and data (attack counts)
            for bar chart showing top 10 attacking IPs.
    """
    # Attack IP data is now in log files, not tracked separately
    return {
        'labels': [],
        'data': [],
        'limit': 10
    }


@login_required
@cached_dashboard_api('dashboard_countries')
def dashboard_countries_api(request):
    """API endpoint for attacks by country (bar chart data).

    Uses GeoIP2 to lookup country for each attacking IP.
    Returns only attacks for rustbuckets the user has access to.

    Args:
        request: The HTTP request object.

    Returns:
        dict: Labels (country names), codes, and data (attack counts)
            for bar chart showing top 10 attacking countries.
    """
    # Attack country data is now in log files, not tracked separately
    return {
        'labels': [],
        'codes': [],
        'data': [],
        'limit': 10
    }


@login_required
@cached_dashboard_api('dashboard_alerts')
def dashboard_alerts_api(request):
    """API endpoint for alert frequency by type (pie chart data).

    Returns only alerts for rustbuckets the user has access to.

    Args:
        request: The HTTP request object.

    Returns:
        dict: Labels (alert types), data (counts), and colors
            for pie chart showing alert distribution.
    """
    start, end = get_time_range(request)

    # Get accessible rustbuckets for the user
    accessible_rustbuckets = filter_rustbuckets_for_user(request.user)

    # Get alerts grouped by type (filtered by access)
    alerts = Alert.objects.filter(
        logsink__rustbucket__in=accessible_rustbuckets,
        created_at__gte=start,
        created_at__lte=end
    ).values('type').annotate(
        count=Count('id')
    ).order_by('-count')

    labels = [a['type'] for a in alerts]
    counts = [a['count'] for a in alerts]

    # Define colors for each alert type
    color_map = {
        'error': '#c62828',
        'warning': '#ef6c00',
        'info': '#1565c0',
        'high': '#b71c1c',
        'medium': '#f57c00',
        'low': '#2e7d32'
    }
    colors = [color_map.get(label, '#757575') for label in labels]

    return {
        'labels': labels,
        'data': counts,
        'colors': colors
    }


@login_required
@rustbucket_access_required('view')
@cached_dashboard_api('dashboard_resources')
def dashboard_resources_api(request, bucket_id=None):
    """API endpoint for current resource usage (card data).

    Returns only resources for rustbuckets the user has access to.

    Args:
        request: The HTTP request object.
        bucket_id: Optional bucket ID to filter by.

    Returns:
        dict: Current resource values (CPU, memory, disk)
            for rustbuckets, displayed as cards/gauges.
    """
    # Get accessible rustbuckets for the user
    accessible_rustbuckets = filter_rustbuckets_for_user(request.user)

    # Get rustbuckets, optionally filtered by ID
    if bucket_id:
        try:
            rustbuckets = accessible_rustbuckets.filter(id=bucket_id)
            if not rustbuckets.exists():
                return JsonResponse(
                    {'error': f'Bucket with ID {bucket_id} not found'},
                    status=404
                )
        except Exception:
            return JsonResponse(
                {'error': f'Bucket with ID {bucket_id} not found'},
                status=404
            )
    else:
        rustbuckets = accessible_rustbuckets.filter(status='Active')

    # Build resource data
    buckets_data = []
    for bucket in rustbuckets:
        buckets_data.append({
            'id': bucket.id,
            'name': bucket.name,
            'status': bucket.status,
            'cpu_usage': parse_percentage(bucket.cpu_usage),
            'memory_usage': parse_percentage(bucket.memory_usage),
            'disk_usage': parse_percentage(bucket.disk_space),
            'connections': int(bucket.connections) if bucket.connections else 0
        })

    return {'rustbuckets': buckets_data}


@login_required
@cached_dashboard_api('dashboard_targets')
def dashboard_targets_api(request):
    """API endpoint for most targeted rustbuckets (bar chart data).

    Returns only rustbuckets the user has access to.

    Args:
        request: The HTTP request object.

    Returns:
        dict: Labels (bucket names), bucket_ids, and data (attack counts)
            for bar chart showing most targeted rustbuckets.
    """
    # Attack target data is now in log files, not tracked separately
    return {
        'labels': [],
        'bucket_ids': [],
        'data': []
    }
