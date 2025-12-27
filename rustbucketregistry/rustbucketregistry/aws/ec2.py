"""
AWS EC2 service layer for rustbucket deployment.

Handles EC2 instance creation, status checking, and AMI discovery.
"""
import logging

import boto3
from botocore.exceptions import ClientError
from django.conf import settings

logger = logging.getLogger(__name__)

# Allowed instance types for honeypots (cost control)
ALLOWED_INSTANCE_TYPES = ['t3.micro', 't3.small', 't3.medium', 't2.micro', 't2.small']

# Available regions for deployment
AVAILABLE_REGIONS = [
    ('us-east-1', 'US East (N. Virginia)'),
    ('us-east-2', 'US East (Ohio)'),
    ('us-west-1', 'US West (N. California)'),
    ('us-west-2', 'US West (Oregon)'),
    ('eu-west-1', 'EU (Ireland)'),
    ('eu-west-2', 'EU (London)'),
    ('eu-central-1', 'EU (Frankfurt)'),
    ('ap-southeast-1', 'Asia Pacific (Singapore)'),
    ('ap-southeast-2', 'Asia Pacific (Sydney)'),
    ('ap-northeast-1', 'Asia Pacific (Tokyo)'),
]


def get_ec2_client(region=None):
    """Get boto3 EC2 client for the specified region."""
    return boto3.client('ec2', region_name=region or settings.EC2_DEFAULT_REGION)


def get_latest_ubuntu_ami(region=None):
    """
    Find the latest Ubuntu 22.04 LTS AMI in the region.

    Args:
        region: AWS region (defaults to EC2_DEFAULT_REGION)

    Returns:
        str: AMI ID or None if not found
    """
    ec2 = get_ec2_client(region)
    try:
        response = ec2.describe_images(
            Owners=['099720109477'],  # Canonical
            Filters=[
                {
                    'Name': 'name',
                    'Values': ['ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*']
                },
                {'Name': 'virtualization-type', 'Values': ['hvm']},
                {'Name': 'state', 'Values': ['available']},
                {'Name': 'architecture', 'Values': ['x86_64']},
            ]
        )
        images = sorted(
            response['Images'],
            key=lambda x: x['CreationDate'],
            reverse=True
        )
        if images:
            logger.info(f"Found Ubuntu AMI: {images[0]['ImageId']} ({images[0]['Name']})")
            return images[0]['ImageId']
        return None
    except ClientError as e:
        logger.error(f"Error finding Ubuntu AMI: {e}")
        raise


def generate_user_data(deployment_name, registration_key, registry_url,
                       docker_image, openai_api_key='', anthropic_api_key='',
                       google_api_key=''):
    """
    Generate user-data script for honeypot bootstrap.

    The script will:
    1. Update the system
    2. Install Docker
    3. Pull and run the RustBucket honeypot container
    4. The container will auto-register with the registry

    Args:
        deployment_name: Name for the honeypot
        registration_key: Registration key for auto-registration
        registry_url: Base URL of the registry
        docker_image: Docker image for RustBucket (e.g., jamesbinford/rustbucket:latest)
        openai_api_key: OpenAI API key for LLM-powered responses
        anthropic_api_key: Anthropic API key for Claude
        google_api_key: Google API key for Gemini

    Returns:
        str: Bash script for EC2 user-data
    """
    # Build LLM environment variables - only include non-empty keys
    llm_env_vars = []
    if openai_api_key:
        llm_env_vars.append(f'-e OPENAI_API_KEY="{openai_api_key}"')
    if anthropic_api_key:
        llm_env_vars.append(f'-e ANTHROPIC_API_KEY="{anthropic_api_key}"')
    if google_api_key:
        llm_env_vars.append(f'-e GOOGLE_API_KEY="{google_api_key}"')

    llm_env_str = ' \\\n    '.join(llm_env_vars) if llm_env_vars else ''

    return f'''#!/bin/bash
set -e

# Log all output
exec > >(tee /var/log/rustbucket-setup.log) 2>&1
echo "=========================================="
echo "Starting rustbucket setup at $(date)"
echo "=========================================="

# Update system
echo "Updating system packages..."
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get upgrade -y

# Install Docker
echo "Installing Docker..."
DEBIAN_FRONTEND=noninteractive apt-get install -y \\
    ca-certificates \\
    curl \\
    gnupg \\
    jq

# Add Docker's official GPG key
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
chmod a+r /etc/apt/keyrings/docker.gpg

# Add Docker repository
echo \\
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \\
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \\
  tee /etc/apt/sources.list.d/docker.list > /dev/null

# Install Docker packages
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

# Start and enable Docker
systemctl start docker
systemctl enable docker

# Create rustbucket directory
mkdir -p /opt/rustbucket
cd /opt/rustbucket

# Get instance metadata using IMDSv2
echo "Getting instance metadata..."
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" \\
    -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
PUBLIC_IP=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \\
    http://169.254.169.254/latest/meta-data/public-ipv4)
INSTANCE_ID=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \\
    http://169.254.169.254/latest/meta-data/instance-id)

echo "Public IP: $PUBLIC_IP"
echo "Instance ID: $INSTANCE_ID"

# Wait for network to be fully ready
echo "Waiting for network stability..."
sleep 10

# Pull RustBucket Docker image
echo "Pulling RustBucket Docker image..."
docker pull {docker_image}

# Run RustBucket container
# The container will auto-register with the registry using RUSTBUCKET_REGISTRY_URL
echo "Starting RustBucket honeypot container..."
docker run -d \\
    --name rustbucket \\
    --restart unless-stopped \\
    -p 22:2222 \\
    -p 21:2121 \\
    -p 25:2525 \\
    -p 80:8080 \\
    -v /opt/rustbucket/logs:/app/logs \\
    -v /opt/rustbucket/data:/app/data \\
    {llm_env_str} \\
    -e RUSTBUCKET_REGISTRY_URL="{registry_url}/api/register/" \\
    -e RUSTBUCKET_API_KEY="{registration_key}" \\
    -e SSH_PORT=2222 \\
    -e FTP_PORT=2121 \\
    -e SMTP_PORT=2525 \\
    -e HTTP_PORT=8080 \\
    {docker_image}

# Wait for container to start and register
echo "Waiting for RustBucket to start..."
sleep 15

# Check container status
if docker ps | grep -q rustbucket; then
    echo "RustBucket container is running"
    docker logs rustbucket 2>&1 | tail -20
else
    echo "ERROR: RustBucket container failed to start"
    docker logs rustbucket 2>&1
fi

# Save deployment info
cat > /opt/rustbucket/deployment_info.json << EOF
{{
    "deployment_name": "{deployment_name}",
    "instance_id": "$INSTANCE_ID",
    "public_ip": "$PUBLIC_IP",
    "docker_image": "{docker_image}",
    "registry_url": "{registry_url}",
    "deployed_at": "$(date -Iseconds)"
}}
EOF

echo "=========================================="
echo "Rustbucket setup complete at $(date)"
echo "=========================================="
'''


def launch_instance(deployment):
    """
    Launch an EC2 instance for the given deployment.

    Args:
        deployment: Deployment model instance with configuration

    Returns:
        dict with instance_id, ami_id, public_ip (may be None initially)

    Raises:
        ValueError: If configuration is invalid
        ClientError: If AWS API call fails
    """
    # Validate instance type
    if deployment.instance_type not in ALLOWED_INSTANCE_TYPES:
        raise ValueError(
            f"Instance type '{deployment.instance_type}' not allowed. "
            f"Allowed types: {', '.join(ALLOWED_INSTANCE_TYPES)}"
        )

    ec2 = get_ec2_client(deployment.region)

    # Get AMI
    ami_id = deployment.ami_id or get_latest_ubuntu_ami(deployment.region)
    if not ami_id:
        raise ValueError(f"Could not find Ubuntu AMI in region {deployment.region}")

    # Generate user-data script
    user_data = generate_user_data(
        deployment_name=deployment.name,
        registration_key=deployment.registration_key.key,
        registry_url=settings.REGISTRY_BASE_URL,
        docker_image=settings.RUSTBUCKET_DOCKER_IMAGE,
        openai_api_key=settings.RUSTBUCKET_OPENAI_API_KEY,
        anthropic_api_key=settings.RUSTBUCKET_ANTHROPIC_API_KEY,
        google_api_key=settings.RUSTBUCKET_GOOGLE_API_KEY,
    )

    # Build launch parameters
    launch_params = {
        'ImageId': ami_id,
        'InstanceType': deployment.instance_type,
        'MinCount': 1,
        'MaxCount': 1,
        'UserData': user_data,
        'TagSpecifications': [{
            'ResourceType': 'instance',
            'Tags': [
                {'Key': 'Name', 'Value': f'rustbucket-{deployment.name}'},
                {'Key': 'Project', 'Value': 'rustbucket-registry'},
                {'Key': 'DeploymentId', 'Value': deployment.id},
                {'Key': 'ManagedBy', 'Value': 'rustbucket-registry'},
            ]
        }]
    }

    # Add optional network configuration from settings
    if settings.EC2_SUBNET_ID:
        launch_params['SubnetId'] = settings.EC2_SUBNET_ID
        logger.info(f"Using subnet: {settings.EC2_SUBNET_ID}")

    if settings.EC2_SECURITY_GROUP_ID:
        launch_params['SecurityGroupIds'] = [settings.EC2_SECURITY_GROUP_ID]
        logger.info(f"Using security group: {settings.EC2_SECURITY_GROUP_ID}")

    if settings.EC2_KEY_NAME:
        launch_params['KeyName'] = settings.EC2_KEY_NAME
        logger.info(f"Using key pair: {settings.EC2_KEY_NAME}")

    if settings.EC2_IAM_INSTANCE_PROFILE:
        launch_params['IamInstanceProfile'] = {'Name': settings.EC2_IAM_INSTANCE_PROFILE}
        logger.info(f"Using IAM profile: {settings.EC2_IAM_INSTANCE_PROFILE}")

    # Launch instance
    logger.info(f"Launching EC2 instance for deployment {deployment.id}")
    try:
        response = ec2.run_instances(**launch_params)
        instance = response['Instances'][0]

        result = {
            'instance_id': instance['InstanceId'],
            'ami_id': ami_id,
            'public_ip': instance.get('PublicIpAddress'),
        }

        logger.info(f"Launched instance: {result['instance_id']}")
        return result

    except ClientError as e:
        logger.error(f"Failed to launch instance: {e}")
        raise


def get_instance_status(instance_id, region=None):
    """
    Get current status and public IP of an instance.

    Args:
        instance_id: EC2 instance ID
        region: AWS region (defaults to EC2_DEFAULT_REGION)

    Returns:
        dict with 'state' and 'public_ip', or None if not found
    """
    ec2 = get_ec2_client(region)
    try:
        response = ec2.describe_instances(InstanceIds=[instance_id])

        if not response['Reservations']:
            return None

        instance = response['Reservations'][0]['Instances'][0]
        return {
            'state': instance['State']['Name'],
            'public_ip': instance.get('PublicIpAddress'),
        }
    except ClientError as e:
        if 'InvalidInstanceID' in str(e):
            return None
        raise


def terminate_instance(instance_id, region=None):
    """
    Terminate an EC2 instance.

    Args:
        instance_id: EC2 instance ID
        region: AWS region (defaults to EC2_DEFAULT_REGION)

    Returns:
        bool: True if termination initiated successfully
    """
    ec2 = get_ec2_client(region)
    try:
        ec2.terminate_instances(InstanceIds=[instance_id])
        logger.info(f"Terminated instance: {instance_id}")
        return True
    except ClientError as e:
        logger.error(f"Failed to terminate instance {instance_id}: {e}")
        raise
