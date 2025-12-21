"""Dashboard views for the RustBucket Registry application.

This module contains view functions for the analytics dashboard,
including chart data APIs and summary statistics.
"""
from datetime import datetime, timedelta
from collections import defaultdict

from django.shortcuts import render
from django.http import JsonResponse
from django.utils import timezone
from django.db.models import Count, F
from django.db.models.functions import TruncDate
from django.core.cache import cache
from django.conf import settings
from django.contrib.auth.decorators import login_required

from rustbucketregistry.models import Rustbucket, Alert, HoneypotActivity
from rustbucketregistry.permissions import (
    filter_rustbuckets_for_user,
    rustbucket_access_required,
    get_user_profile,
)


# Cache timeout in seconds (1 minute for real-time feel)
CACHE_TIMEOUT = 60


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


def get_country_from_ip(ip_address):
    """Gets country information from an IP address using GeoIP2.

    Args:
        ip_address: The IP address to look up.

    Returns:
        dict: Country code and name, or defaults if lookup fails.
    """
    try:
        import geoip2.database
        geoip_path = getattr(settings, 'GEOIP_PATH', None)
        if geoip_path:
            db_path = geoip_path / 'GeoLite2-Country.mmdb'
            if db_path.exists():
                reader = geoip2.database.Reader(str(db_path))
                response = reader.country(ip_address)
                return {
                    'country_code': response.country.iso_code or 'XX',
                    'country_name': response.country.name or 'Unknown'
                }
    except Exception:
        pass
    return {'country_code': 'XX', 'country_name': 'Unknown'}


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
def dashboard_overview_api(request):
    """API endpoint for dashboard summary statistics.

    Returns statistics only for rustbuckets the user has access to.

    Args:
        request: The HTTP request object.

    Returns:
        JsonResponse: Summary statistics including rustbucket counts,
            attack totals, and unresolved alerts.
    """
    range_param = request.GET.get('range', '7d')
    user_id = request.user.id
    cache_key = f'dashboard_overview_{range_param}_{user_id}'

    # Try cache first
    cached_data = cache.get(cache_key)
    if cached_data:
        return JsonResponse(cached_data)

    start, end = get_time_range(request)

    # Get accessible rustbuckets for the user
    accessible_rustbuckets = filter_rustbuckets_for_user(request.user)

    # Get rustbucket statistics (filtered by access)
    total_rustbuckets = accessible_rustbuckets.count()
    active_rustbuckets = accessible_rustbuckets.filter(status='Active').count()

    # Get attack statistics for the time range (filtered by access)
    total_attacks = HoneypotActivity.objects.filter(
        rustbucket__in=accessible_rustbuckets,
        timestamp__gte=start,
        timestamp__lte=end
    ).count()

    # Get unresolved alerts (filtered by access)
    unresolved_alerts = Alert.objects.filter(
        logsink__rustbucket__in=accessible_rustbuckets,
        is_resolved=False
    ).count()

    data = {
        'total_rustbuckets': total_rustbuckets,
        'active_rustbuckets': active_rustbuckets,
        'total_attacks': total_attacks,
        'unresolved_alerts': unresolved_alerts,
        'time_range': {
            'start': start.isoformat(),
            'end': end.isoformat()
        }
    }

    cache.set(cache_key, data, timeout=CACHE_TIMEOUT)
    return JsonResponse(data)


@login_required
def dashboard_attacks_api(request):
    """API endpoint for attack trends over time (line chart data).

    Returns only attacks for rustbuckets the user has access to.

    Args:
        request: The HTTP request object.

    Returns:
        JsonResponse: Labels and datasets for line chart showing
            attack counts by type over time.
    """
    range_param = request.GET.get('range', '7d')
    user_id = request.user.id
    cache_key = f'dashboard_attacks_{range_param}_{user_id}'

    # Try cache first
    cached_data = cache.get(cache_key)
    if cached_data:
        return JsonResponse(cached_data)

    start, end = get_time_range(request)

    # Get accessible rustbuckets for the user
    accessible_rustbuckets = filter_rustbuckets_for_user(request.user)

    # Get attacks grouped by date and type (filtered by access)
    attacks = HoneypotActivity.objects.filter(
        rustbucket__in=accessible_rustbuckets,
        timestamp__gte=start,
        timestamp__lte=end
    ).annotate(
        date=TruncDate('timestamp')
    ).values('date', 'type').annotate(
        count=Count('id')
    ).order_by('date')

    # Build date range for labels
    date_set = set()
    attack_types = ['scan', 'exploit', 'bruteforce', 'malware']
    data_by_type = {t: defaultdict(int) for t in attack_types}

    for attack in attacks:
        date_str = attack['date'].strftime('%Y-%m-%d')
        date_set.add(date_str)
        attack_type = attack['type']
        if attack_type in data_by_type:
            data_by_type[attack_type][date_str] = attack['count']

    # Sort dates
    sorted_dates = sorted(date_set)

    # If no data, generate empty date range
    if not sorted_dates:
        current = start.date()
        while current <= end.date():
            sorted_dates.append(current.strftime('%Y-%m-%d'))
            current += timedelta(days=1)

    # Build datasets
    datasets = []
    colors = {
        'scan': '#2196F3',
        'exploit': '#c62828',
        'bruteforce': '#ef6c00',
        'malware': '#9c27b0'
    }
    for attack_type in attack_types:
        datasets.append({
            'label': attack_type,
            'data': [data_by_type[attack_type][d] for d in sorted_dates],
            'borderColor': colors.get(attack_type, '#333'),
            'fill': False
        })

    data = {
        'labels': sorted_dates,
        'datasets': datasets
    }

    cache.set(cache_key, data, timeout=CACHE_TIMEOUT)
    return JsonResponse(data)


@login_required
def dashboard_top_ips_api(request):
    """API endpoint for top attacking IPs (bar chart data).

    Returns only attacks for rustbuckets the user has access to.

    Args:
        request: The HTTP request object.

    Returns:
        JsonResponse: Labels (IP addresses) and data (attack counts)
            for bar chart showing top 10 attacking IPs.
    """
    range_param = request.GET.get('range', '7d')
    user_id = request.user.id
    cache_key = f'dashboard_top_ips_{range_param}_{user_id}'

    # Try cache first
    cached_data = cache.get(cache_key)
    if cached_data:
        return JsonResponse(cached_data)

    start, end = get_time_range(request)

    # Get accessible rustbuckets for the user
    accessible_rustbuckets = filter_rustbuckets_for_user(request.user)

    # Get top attacking IPs (filtered by access)
    top_ips = HoneypotActivity.objects.filter(
        rustbucket__in=accessible_rustbuckets,
        timestamp__gte=start,
        timestamp__lte=end
    ).values('source_ip').annotate(
        count=Count('id')
    ).order_by('-count')[:10]

    labels = [ip['source_ip'] for ip in top_ips]
    counts = [ip['count'] for ip in top_ips]

    data = {
        'labels': labels,
        'data': counts,
        'limit': 10
    }

    cache.set(cache_key, data, timeout=CACHE_TIMEOUT)
    return JsonResponse(data)


@login_required
def dashboard_countries_api(request):
    """API endpoint for attacks by country (bar chart data).

    Uses GeoIP2 to lookup country for each attacking IP.
    Returns only attacks for rustbuckets the user has access to.

    Args:
        request: The HTTP request object.

    Returns:
        JsonResponse: Labels (country names), codes, and data (attack counts)
            for bar chart showing top 10 attacking countries.
    """
    range_param = request.GET.get('range', '7d')
    user_id = request.user.id
    cache_key = f'dashboard_countries_{range_param}_{user_id}'

    # Try cache first
    cached_data = cache.get(cache_key)
    if cached_data:
        return JsonResponse(cached_data)

    start, end = get_time_range(request)

    # Get accessible rustbuckets for the user
    accessible_rustbuckets = filter_rustbuckets_for_user(request.user)

    # Get all activities in the time range (filtered by access)
    activities = HoneypotActivity.objects.filter(
        rustbucket__in=accessible_rustbuckets,
        timestamp__gte=start,
        timestamp__lte=end
    ).values_list('source_ip', flat=True)

    # Count attacks by country
    country_counts = defaultdict(int)
    country_names = {}

    for ip in activities:
        geo_info = get_country_from_ip(ip)
        country_code = geo_info['country_code']
        country_counts[country_code] += 1
        country_names[country_code] = geo_info['country_name']

    # Sort by count and take top 10
    sorted_countries = sorted(
        country_counts.items(),
        key=lambda x: x[1],
        reverse=True
    )[:10]

    codes = [c[0] for c in sorted_countries]
    labels = [country_names.get(c, 'Unknown') for c in codes]
    counts = [c[1] for c in sorted_countries]

    data = {
        'labels': labels,
        'codes': codes,
        'data': counts,
        'limit': 10
    }

    cache.set(cache_key, data, timeout=CACHE_TIMEOUT)
    return JsonResponse(data)


@login_required
def dashboard_alerts_api(request):
    """API endpoint for alert frequency by type (pie chart data).

    Returns only alerts for rustbuckets the user has access to.

    Args:
        request: The HTTP request object.

    Returns:
        JsonResponse: Labels (alert types), data (counts), and colors
            for pie chart showing alert distribution.
    """
    range_param = request.GET.get('range', '7d')
    user_id = request.user.id
    cache_key = f'dashboard_alerts_{range_param}_{user_id}'

    # Try cache first
    cached_data = cache.get(cache_key)
    if cached_data:
        return JsonResponse(cached_data)

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
        'HIGH': '#b71c1c',
        'MEDIUM': '#f57c00',
        'LOW': '#2e7d32'
    }
    colors = [color_map.get(label, '#757575') for label in labels]

    data = {
        'labels': labels,
        'data': counts,
        'colors': colors
    }

    cache.set(cache_key, data, timeout=CACHE_TIMEOUT)
    return JsonResponse(data)


@login_required
@rustbucket_access_required('view')
def dashboard_resources_api(request, bucket_id=None):
    """API endpoint for current resource usage (card data).

    Returns only resources for rustbuckets the user has access to.

    Args:
        request: The HTTP request object.
        bucket_id: Optional bucket ID to filter by.

    Returns:
        JsonResponse: Current resource values (CPU, memory, disk)
            for rustbuckets, displayed as cards/gauges.
    """
    user_id = request.user.id
    cache_key = f'dashboard_resources_{bucket_id or "all"}_{user_id}'

    # Try cache first
    cached_data = cache.get(cache_key)
    if cached_data:
        return JsonResponse(cached_data)

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

    data = {
        'rustbuckets': buckets_data
    }

    cache.set(cache_key, data, timeout=CACHE_TIMEOUT)
    return JsonResponse(data)


@login_required
def dashboard_targets_api(request):
    """API endpoint for most targeted rustbuckets (bar chart data).

    Returns only rustbuckets the user has access to.

    Args:
        request: The HTTP request object.

    Returns:
        JsonResponse: Labels (bucket names), bucket_ids, and data (attack counts)
            for bar chart showing most targeted rustbuckets.
    """
    range_param = request.GET.get('range', '7d')
    user_id = request.user.id
    cache_key = f'dashboard_targets_{range_param}_{user_id}'

    # Try cache first
    cached_data = cache.get(cache_key)
    if cached_data:
        return JsonResponse(cached_data)

    start, end = get_time_range(request)

    # Get accessible rustbuckets for the user
    accessible_rustbuckets = filter_rustbuckets_for_user(request.user)

    # Get most targeted rustbuckets (filtered by access)
    targets = HoneypotActivity.objects.filter(
        rustbucket__in=accessible_rustbuckets,
        timestamp__gte=start,
        timestamp__lte=end
    ).values(
        'rustbucket__id',
        'rustbucket__name'
    ).annotate(
        count=Count('id')
    ).order_by('-count')[:10]

    labels = [t['rustbucket__name'] for t in targets]
    bucket_ids = [t['rustbucket__id'] for t in targets]
    counts = [t['count'] for t in targets]

    data = {
        'labels': labels,
        'bucket_ids': bucket_ids,
        'data': counts
    }

    cache.set(cache_key, data, timeout=CACHE_TIMEOUT)
    return JsonResponse(data)
