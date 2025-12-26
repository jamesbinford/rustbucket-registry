"""
Admin views for deployment management.

This module provides endpoints for deploying, listing, and managing
EC2-based rustbucket honeypots.
"""
import json
import logging
from datetime import timedelta

from django.conf import settings
from django.http import JsonResponse
from django.shortcuts import render
from django.utils import timezone

from rustbucketregistry.aws.ec2 import (
    ALLOWED_INSTANCE_TYPES,
    AVAILABLE_REGIONS,
    launch_instance,
)
from rustbucketregistry.models import AuditLog, Deployment, RegistrationKey
from rustbucketregistry.permissions import admin_required, api_endpoint

logger = logging.getLogger(__name__)


@api_endpoint(role='admin', method='POST')
def create_deployment(request):
    """
    Create and launch a new rustbucket deployment.

    Expected JSON payload:
    {
        "name": "string",           # Required - name for the honeypot
        "instance_type": "string",  # Optional - default t3.micro
        "region": "string"          # Optional - default from settings
    }

    Returns:
        JsonResponse with deployment details
    """
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)

    name = data.get('name', '').strip()
    if not name:
        return JsonResponse({'error': 'Name is required'}, status=400)

    instance_type = data.get('instance_type', settings.EC2_DEFAULT_INSTANCE_TYPE)
    if instance_type not in ALLOWED_INSTANCE_TYPES:
        return JsonResponse({
            'error': f"Invalid instance type. Allowed: {', '.join(ALLOWED_INSTANCE_TYPES)}"
        }, status=400)

    region = data.get('region', settings.EC2_DEFAULT_REGION)

    # Validate region
    valid_regions = [r[0] for r in AVAILABLE_REGIONS]
    if region not in valid_regions:
        return JsonResponse({
            'error': f"Invalid region. Allowed: {', '.join(valid_regions)}"
        }, status=400)

    # Check deployment limits
    active_count = Deployment.objects.filter(
        status__in=['pending', 'launching', 'running']
    ).count()
    if active_count >= settings.MAX_CONCURRENT_DEPLOYMENTS:
        return JsonResponse({
            'error': f'Maximum concurrent deployments ({settings.MAX_CONCURRENT_DEPLOYMENTS}) reached'
        }, status=400)

    # Create registration key for this deployment (1-hour expiry)
    reg_key = RegistrationKey(
        name=f"Auto: {name}",
        created_by=request.user,
        expires_at=timezone.now() + timedelta(hours=1)
    )
    reg_key.save()

    # Create deployment record
    deployment = Deployment(
        name=name,
        instance_type=instance_type,
        region=region,
        registration_key=reg_key,
        created_by=request.user,
        status='pending'
    )
    deployment.save()

    # Launch EC2 instance
    try:
        result = launch_instance(deployment)

        deployment.instance_id = result['instance_id']
        deployment.ami_id = result['ami_id']
        deployment.public_ip = result.get('public_ip')
        deployment.status = 'launching'
        deployment.launched_at = timezone.now()
        deployment.save()

        # Log the action
        AuditLog.log(
            user=request.user,
            action='create',
            resource_type='deployment',
            resource_id=deployment.id,
            details={
                'name': name,
                'instance_type': instance_type,
                'region': region,
                'instance_id': result['instance_id']
            },
            request=request
        )

        return JsonResponse({
            'status': 'success',
            'deployment': {
                'id': deployment.id,
                'name': deployment.name,
                'instance_id': deployment.instance_id,
                'status': deployment.status,
                'region': deployment.region,
                'public_ip': deployment.public_ip,
            },
            'message': 'Deployment initiated. Instance is launching.'
        }, status=201)

    except Exception as e:
        deployment.status = 'failed'
        deployment.status_message = str(e)
        deployment.save()

        logger.error(f"Deployment failed: {e}", exc_info=True)

        # Also log the failed attempt
        AuditLog.log(
            user=request.user,
            action='create',
            resource_type='deployment',
            resource_id=deployment.id,
            details={'error': str(e)},
            request=request,
            success=False
        )

        return JsonResponse({
            'error': f'Deployment failed: {str(e)}'
        }, status=500)


@api_endpoint(role='admin', method='GET')
def list_deployments(request):
    """List all deployments with their status."""
    deployments = Deployment.objects.all().select_related(
        'created_by', 'rustbucket', 'registration_key'
    )

    deployment_list = []
    for dep in deployments:
        deployment_list.append({
            'id': dep.id,
            'name': dep.name,
            'status': dep.status,
            'status_display': dep.get_status_display(),
            'status_message': dep.status_message,
            'instance_id': dep.instance_id,
            'instance_type': dep.instance_type,
            'region': dep.region,
            'public_ip': str(dep.public_ip) if dep.public_ip else None,
            'created_by': dep.created_by.username if dep.created_by else None,
            'created_at': dep.created_at.isoformat(),
            'launched_at': dep.launched_at.isoformat() if dep.launched_at else None,
            'registered_at': dep.registered_at.isoformat() if dep.registered_at else None,
            'rustbucket_id': dep.rustbucket.id if dep.rustbucket else None,
        })

    return JsonResponse({
        'status': 'success',
        'count': len(deployment_list),
        'deployments': deployment_list
    })


@api_endpoint(role='admin', method='GET')
def get_deployment(request, deployment_id):
    """Get details of a specific deployment."""
    try:
        deployment = Deployment.objects.select_related(
            'created_by', 'rustbucket', 'registration_key'
        ).get(id=deployment_id)
    except Deployment.DoesNotExist:
        return JsonResponse({'error': 'Deployment not found'}, status=404)

    return JsonResponse({
        'status': 'success',
        'deployment': {
            'id': deployment.id,
            'name': deployment.name,
            'status': deployment.status,
            'status_display': deployment.get_status_display(),
            'status_message': deployment.status_message,
            'instance_id': deployment.instance_id,
            'instance_type': deployment.instance_type,
            'region': deployment.region,
            'ami_id': deployment.ami_id,
            'public_ip': str(deployment.public_ip) if deployment.public_ip else None,
            'created_by': deployment.created_by.username if deployment.created_by else None,
            'created_at': deployment.created_at.isoformat(),
            'launched_at': deployment.launched_at.isoformat() if deployment.launched_at else None,
            'registered_at': deployment.registered_at.isoformat() if deployment.registered_at else None,
            'rustbucket_id': deployment.rustbucket.id if deployment.rustbucket else None,
        }
    })


@admin_required
def deployments_view(request):
    """Render the deployments management page."""
    deployments = Deployment.objects.all().select_related(
        'created_by', 'rustbucket'
    ).order_by('-created_at')

    return render(request, 'deployments.html', {
        'deployments': deployments,
        'allowed_instance_types': ALLOWED_INSTANCE_TYPES,
        'available_regions': AVAILABLE_REGIONS,
        'default_region': settings.EC2_DEFAULT_REGION,
        'default_instance_type': settings.EC2_DEFAULT_INSTANCE_TYPE,
    })
