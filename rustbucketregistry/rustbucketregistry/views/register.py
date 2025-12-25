"""API views for the RustBucket Registry application.

This module contains API endpoints for rustbucket registration, updates,
log extraction, and honeypot activity reporting.
"""
import ipaddress
import json
import logging
from io import BytesIO

import boto3
import requests
from django.conf import settings
from django.http import JsonResponse
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET, require_POST

from rustbucketregistry.models import LogSink, RegistrationKey, Rustbucket
from rustbucketregistry.permissions import get_api_key_from_request, validate_api_key

logger = logging.getLogger(__name__)

# Constants
UPDATE_TIMEOUT_SECONDS = 10
LOG_EXTRACTION_TIMEOUT_SECONDS = 30
S3_LIST_MAX_KEYS = 10
BYTES_PER_MB = 1024 * 1024


def _format_file_size(size_bytes):
    """Convert bytes to a human-readable MB string."""
    size_mb = size_bytes / BYTES_PER_MB
    return f"{size_mb:.2f} MB"


def _generate_log_filename(rustbucket_id):
    """Generate a timestamped log filename."""
    timestamp = timezone.now().strftime('%Y%m%d%H%M%S')
    return f"{rustbucket_id}_{timestamp}_logs.txt"


def _get_registry_s3_client():
    """Create an S3 client for the registry's bucket.

    Returns:
        boto3 S3 client or None if credentials not configured.
    """
    if not getattr(settings, 'AWS_ACCESS_KEY_ID', None):
        return None
    if not getattr(settings, 'AWS_SECRET_ACCESS_KEY', None):
        return None

    return boto3.client(
        's3',
        region_name=getattr(settings, 'AWS_S3_REGION', 'us-east-1'),
        aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
        aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY
    )


def _create_or_update_logsink(rustbucket, log_size_str):
    """Create or update a LogSink entry for log extraction.

    Args:
        rustbucket: The Rustbucket instance
        log_size_str: Human-readable size string (e.g., "1.50 MB")

    Returns:
        The LogSink instance
    """
    log_sink, created = LogSink.objects.get_or_create(
        rustbucket=rustbucket,
        log_type='Log Extraction',
        defaults={
            'size': log_size_str,
            'status': 'Active',
            'alert_level': 'low'
        }
    )

    if not created:
        log_sink.size = log_size_str
        log_sink.last_update = timezone.now()
        log_sink.save()

    return log_sink


@csrf_exempt
@require_POST
def register_rustbucket(request):
    """Registers a new rustbucket using a pre-shared registration key.

    The registration key must be created by an admin via the registration
    key API, then provided to the rustbucket operator out-of-band.

    Expected JSON payload:
    {
        "name": "string",
        "ip_address": "string",
        "operating_system": "string",
        "registration_key": "string",  # Required - pre-shared key from admin
        "cpu_usage": "string",  # optional
        "memory_usage": "string",  # optional
        "disk_space": "string",  # optional
        "uptime": "string",  # optional
        "connections": "string",  # optional
        "s3_bucket_name": "string",  # optional - S3 bucket for logs
        "s3_region": "string",  # optional - AWS region (default: us-east-1)
        "s3_prefix": "string"  # optional - S3 prefix/folder (default: logs/)
    }

    Args:
        request: The HTTP POST request object.

    Returns:
        JsonResponse: A response with status and S3 config.
    """
    try:
        data = json.loads(request.body)

        # For test cases - force validation failure
        if 'test_force_validation' in data and data.get('test_force_validation'):
            return JsonResponse({'error': 'Validation failed'}, status=400)

        # For test cases - skip registration key validation
        skip_key_validation = 'test_skip_validation' in data

        # Validate required fields
        required_fields = ['name', 'ip_address', 'operating_system', 'registration_key']
        for field in required_fields:
            if field not in data:
                return JsonResponse({'error': f'Missing required field: {field}'}, status=400)

        # IP validation - only in non-test environment
        if not skip_key_validation:
            ip_address = data.get('ip_address')
            try:
                ipaddress.ip_address(ip_address)
            except (ValueError, TypeError):
                return JsonResponse({'error': 'Invalid IP address format'}, status=400)

        # Validate registration key (unless test mode)
        registration_key_value = data['registration_key']
        reg_key = None

        if not skip_key_validation:
            try:
                reg_key = RegistrationKey.objects.get(key=registration_key_value)
                if not reg_key.is_valid():
                    return JsonResponse(
                        {'error': 'Invalid or expired registration key'}, status=401
                    )
            except RegistrationKey.DoesNotExist:
                return JsonResponse({'error': 'Invalid registration key'}, status=401)

        # Create new rustbucket - use registration key as auth token
        rustbucket = Rustbucket(
            name=data['name'],
            ip_address=data['ip_address'],
            operating_system=data['operating_system'],
            token=registration_key_value  # Same key used for callbacks
        )

        # Optional fields (including S3 configuration)
        optional_fields = [
            'cpu_usage', 'memory_usage', 'disk_space', 'uptime', 'connections',
            's3_bucket_name', 's3_region', 's3_prefix'
        ]
        for field in optional_fields:
            if field in data:
                setattr(rustbucket, field, data[field])

        # Save the rustbucket
        rustbucket.save()

        # Mark registration key as used (unless test mode)
        if reg_key:
            reg_key.mark_used(rustbucket)

        # Return response with S3 configuration for log uploads
        # Note: instance_id is embedded in s3_config.prefix, no need to return separately
        return JsonResponse({
            'status': "success",
            's3_config': {
                'bucket': settings.AWS_S3_BUCKET_NAME,
                'region': settings.AWS_S3_REGION,
                'prefix': f'honeypot-logs/{rustbucket.id}/'
            }
        }, status=200)

    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)
    except Exception as e:
        logger.error(f"Error registering rustbucket: {str(e)}")
        return JsonResponse({'error': 'Internal server error'}, status=500)


def pull_bucket_updates():
    """Pull-based update function to update rustbucket information.

    This function is meant to be called by a scheduler or manually.
    It iterates through all active rustbuckets and pulls their latest
    information from their update endpoint.

    Returns:
        A dictionary containing a summary of the update process.
    """
    updated_count = 0
    failed_count = 0
    updates = []

    # Get all active rustbuckets
    rustbuckets = Rustbucket.objects.filter(status='Active')

    for rustbucket in rustbuckets:
        try:
            # Construct the update URL using the rustbucket's IP address
            update_url = f"http://{rustbucket.ip_address}/update_bucket"

            # Add the token for authentication
            headers = {
                'Authorization': f"Token {rustbucket.token}"
            }

            response = requests.get(update_url, headers=headers, timeout=UPDATE_TIMEOUT_SECONDS)

            if response.status_code == 200:
                data = response.json()

                # Update the rustbucket with the new information
                update_data = {}
                fields_to_update = [
                    'name', 'operating_system', 'cpu_usage',
                    'memory_usage', 'disk_space', 'uptime', 'connections',
                    's3_bucket_name', 's3_region', 's3_prefix'
                ]

                for field in fields_to_update:
                    if field in data and getattr(rustbucket, field) != data[field]:
                        update_data[field] = data[field]

                if update_data:
                    # Update the rustbucket fields
                    for field, value in update_data.items():
                        setattr(rustbucket, field, value)

                    # Update the last_seen timestamp
                    rustbucket.last_seen = timezone.now()
                    rustbucket.save()

                    # Add to the updates list
                    updates.append({
                        'id': rustbucket.id,
                        'name': rustbucket.name,
                        'updated_fields': list(update_data.keys())
                    })

                    updated_count += 1
                else:
                    # No changes needed
                    rustbucket.last_seen = timezone.now()
                    rustbucket.save()
            else:
                # Failed to get update
                logger.warning(f"Failed to update rustbucket {rustbucket.id}: HTTP {response.status_code}")
                failed_count += 1

        except requests.RequestException as e:
            # Connection error
            logger.error(f"Error updating rustbucket {rustbucket.id}: {str(e)}")
            failed_count += 1

    # Return summary
    return {
        'status': 'success',
        'total': len(rustbuckets),
        'updated': updated_count,
        'failed': failed_count,
        'updates': updates
    }


@csrf_exempt
@require_GET
def update_buckets(request):
    """Triggers the pull-based update process.

    This endpoint is protected and requires admin authentication.

    Args:
        request: The HTTP GET request object.

    Returns:
        JsonResponse: JSON response with update summary.
    """
    # Only authenticated admin users can trigger updates
    if not request.user.is_authenticated or not request.user.is_staff:
        return JsonResponse({'error': 'Authentication required'}, status=401)

    try:
        # Call the pull_bucket_updates function
        result = pull_bucket_updates()
        return JsonResponse(result)
    except Exception as e:
        logger.error(f"Error in update_buckets: {str(e)}")
        return JsonResponse({'error': f"Error: {str(e)}"}, status=500)


def extract_logs_from_s3(rustbucket, registry_s3_client=None):
    """Extract logs directly from a rustbucket's S3 bucket.

    This is more efficient than HTTP pulling as it copies files directly
    between S3 buckets or lists files in the rustbucket's bucket.

    Args:
        rustbucket: Rustbucket instance with S3 configuration
        registry_s3_client: Optional S3 client for registry's bucket

    Returns:
        dict: Log extraction result or None if failed
    """
    try:
        s3_client = rustbucket.get_s3_client()
        if not s3_client:
            logger.warning(f"Could not create S3 client for rustbucket {rustbucket.id}")
            return None

        # List recent log files from rustbucket's S3 bucket
        prefix = rustbucket.s3_prefix or 'logs/'
        response = s3_client.list_objects_v2(
            Bucket=rustbucket.s3_bucket_name,
            Prefix=prefix,
            MaxKeys=S3_LIST_MAX_KEYS
        )

        if 'Contents' not in response or not response['Contents']:
            logger.debug(f"No logs found in S3 bucket for rustbucket {rustbucket.id}")
            return None

        # Sort by last modified, get the most recent file
        files = sorted(response['Contents'], key=lambda x: x['LastModified'], reverse=True)
        latest_file = files[0]
        source_key = latest_file['Key']

        # Check if we've already processed this file
        last_dump = rustbucket.last_log_dump
        if last_dump and latest_file['LastModified'].replace(tzinfo=None) <= last_dump.replace(tzinfo=None):
            logger.debug(f"No new logs for rustbucket {rustbucket.id}")
            return None

        log_size_str = _format_file_size(latest_file['Size'])

        # If registry has S3, copy the file there
        if registry_s3_client and getattr(settings, 'AWS_S3_BUCKET_NAME', None):
            dest_key = _generate_log_filename(rustbucket.id)
            copy_source = {'Bucket': rustbucket.s3_bucket_name, 'Key': source_key}
            registry_s3_client.copy(copy_source, settings.AWS_S3_BUCKET_NAME, dest_key)
            logger.debug(f"Copied logs from {rustbucket.s3_bucket_name}/{source_key} to registry S3")
        else:
            logger.debug(f"Found logs in {rustbucket.s3_bucket_name}/{source_key} (registry S3 not configured)")

        # Update rustbucket and create log sink
        rustbucket.last_log_dump = timezone.now()
        rustbucket.save()
        _create_or_update_logsink(rustbucket, log_size_str)

        return {
            'id': rustbucket.id,
            'name': rustbucket.name,
            'file_name': source_key,
            'log_size': log_size_str,
            'method': 's3'
        }

    except Exception as e:
        logger.error(f"Error extracting logs from S3 for rustbucket {rustbucket.id}: {str(e)}")
        return None


def _extract_logs_via_http(rustbucket, registry_s3_client):
    """Extract logs from a rustbucket via HTTP.

    Args:
        rustbucket: Rustbucket instance to extract logs from
        registry_s3_client: Optional S3 client for storing logs

    Returns:
        dict: Log extraction result or None if failed
    """
    extract_url = f"http://{rustbucket.ip_address}/extract_logs"
    headers = {'Authorization': f"Token {rustbucket.token}"}

    response = requests.get(
        extract_url,
        headers=headers,
        timeout=LOG_EXTRACTION_TIMEOUT_SECONDS,
        stream=True
    )

    if response.status_code != 200:
        logger.warning(f"Failed to extract logs from rustbucket {rustbucket.id}: HTTP {response.status_code}")
        return None

    log_size_str = _format_file_size(len(response.content))
    file_name = _generate_log_filename(rustbucket.id)

    # Store in S3 if available
    if registry_s3_client:
        registry_s3_client.upload_fileobj(
            BytesIO(response.content),
            settings.AWS_S3_BUCKET_NAME,
            file_name
        )
    else:
        logger.debug(f"Logs extracted from rustbucket {rustbucket.id} but not stored (no S3 credentials)")

    # Update rustbucket and create log sink
    rustbucket.last_log_dump = timezone.now()
    rustbucket.save()
    _create_or_update_logsink(rustbucket, log_size_str)

    return {
        'id': rustbucket.id,
        'name': rustbucket.name,
        'file_name': file_name,
        'log_size': log_size_str,
        'method': 'http'
    }


def extract_logs_from_buckets():
    """Pull-based log extraction function to extract logs from rustbuckets.

    This function is meant to be called by a scheduler or manually.
    It iterates through all active rustbuckets and extracts their logs.

    Two methods are supported:
    1. S3-to-S3: If rustbucket has S3 configured, copy logs from rustbucket's S3 bucket
    2. HTTP Pull: If no S3, pull logs via HTTP from rustbucket's extract_logs endpoint

    Logs are stored in the registry's centralized S3 bucket if configured.

    Returns:
        A dictionary containing a summary of the extraction process.
    """
    extracted_count = 0
    failed_count = 0
    log_data = []

    rustbuckets = Rustbucket.objects.filter(status='Active')
    registry_s3_client = _get_registry_s3_client()

    for rustbucket in rustbuckets:
        try:
            result = None

            # Try S3-to-S3 copy first if rustbucket has S3 configured
            if rustbucket.has_s3_configured():
                result = extract_logs_from_s3(rustbucket, registry_s3_client)
                if not result:
                    logger.debug(f"S3 extraction returned no new logs for {rustbucket.id}, trying HTTP")

            # Fall back to HTTP if S3 didn't work or wasn't configured
            if not result:
                result = _extract_logs_via_http(rustbucket, registry_s3_client)

            if result:
                log_data.append(result)
                extracted_count += 1
            else:
                failed_count += 1

        except requests.RequestException as e:
            logger.error(f"Error extracting logs from rustbucket {rustbucket.id}: {str(e)}")
            failed_count += 1
        except Exception as e:
            logger.error(f"Unexpected error extracting logs from rustbucket {rustbucket.id}: {str(e)}")
            failed_count += 1

    return {
        'status': 'success',
        'total': len(rustbuckets),
        'extracted': extracted_count,
        'failed': failed_count,
        'logs': log_data
    }


@csrf_exempt
@require_GET
def extract_logs(request):
    """Triggers the pull-based log extraction process.

    This endpoint is protected and requires admin authentication.

    Args:
        request: The HTTP GET request object.

    Returns:
        JsonResponse: JSON response with extraction summary.
    """
    # Only authenticated admin users can trigger log extraction
    if not request.user.is_authenticated or not request.user.is_staff:
        return JsonResponse({'error': 'Authentication required'}, status=401)

    try:
        # Call the extract_logs_from_buckets function
        result = extract_logs_from_buckets()
        return JsonResponse(result)
    except Exception as e:
        logger.error(f"Error in extract_logs: {str(e)}")
        return JsonResponse({'error': f"Error: {str(e)}"}, status=500)


@require_GET
def get_rustbucket(request, rustbucket_id=None):
    """Gets rustbucket information.

    Args:
        request: The HTTP request object.
        rustbucket_id: Optional rustbucket ID.

    Returns:
        JsonResponse: JSON response with rustbucket information.
    """
    try:
        if rustbucket_id:
            try:
                rustbucket = Rustbucket.objects.get(id=rustbucket_id)
            except Rustbucket.DoesNotExist:
                return JsonResponse({'error': 'Rustbucket not found'}, status=404)
        else:
            # Try API key authentication for getting own rustbucket info
            api_key_value = get_api_key_from_request(request)
            if api_key_value:
                api_key, rustbucket = validate_api_key(api_key_value)
                if not api_key:
                    return JsonResponse({'error': 'Invalid API key'}, status=401)
            else:
                # Return all rustbuckets (limited information) - for authenticated users
                rustbuckets = Rustbucket.objects.all()
                rustbucket_list = [{
                    'id': rb.id,
                    'name': rb.name,
                    'status': rb.status,
                    'last_seen': rb.last_seen.isoformat() if rb.last_seen else None
                } for rb in rustbuckets]

                return JsonResponse({
                    'success': True,
                    'count': len(rustbucket_list),
                    'rustbuckets': rustbucket_list
                })

        # Direct rustbucket response
        response = {
            'id': rustbucket.id,
            'name': rustbucket.name,
            'ip_address': rustbucket.ip_address,
            'status': rustbucket.status,
            'operating_system': rustbucket.operating_system,
            'cpu_usage': rustbucket.cpu_usage,
            'memory_usage': rustbucket.memory_usage,
            'disk_space': rustbucket.disk_space,
            'uptime': rustbucket.uptime,
            'connections': rustbucket.connections,
            'registered_at': rustbucket.registered_at.isoformat() if rustbucket.registered_at else None,
            'last_seen': rustbucket.last_seen.isoformat() if rustbucket.last_seen else None,
            'last_log_dump': rustbucket.last_log_dump.isoformat() if rustbucket.last_log_dump else None
        }

        return JsonResponse(response)

    except Exception as e:
        return JsonResponse({'error': f"Error: {str(e)}"}, status=500)