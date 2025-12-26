#!/bin/bash
set -e

# =============================================================================
# RustBucket Registry - EC2 User Data Script
# =============================================================================

exec > >(tee /var/log/user-data.log|logger -t user-data -s 2>/dev/console) 2>&1
echo "Starting RustBucket Registry deployment..."

# -----------------------------------------------------------------------------
# System Updates and Dependencies
# -----------------------------------------------------------------------------

apt-get update
apt-get upgrade -y

apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    nginx \
    certbot \
    python3-certbot-nginx \
    git \
    pkg-config \
    default-libmysqlclient-dev \
    build-essential \
    libssl-dev \
    libffi-dev \
    python3-dev \
    awscli

# -----------------------------------------------------------------------------
# Create Application Directory
# -----------------------------------------------------------------------------

APP_DIR="/opt/rustbucket-registry"
mkdir -p $APP_DIR
cd $APP_DIR

# -----------------------------------------------------------------------------
# Clone Repository
# -----------------------------------------------------------------------------

git clone https://github.com/jamesbinford/rustbucket-registry.git .

# -----------------------------------------------------------------------------
# Python Virtual Environment
# -----------------------------------------------------------------------------

cd $APP_DIR/rustbucketregistry
python3 -m venv venv
source venv/bin/activate

pip install --upgrade pip
pip install -r requirements.txt

# -----------------------------------------------------------------------------
# Environment Configuration
# -----------------------------------------------------------------------------

# Get the public IP address for ALLOWED_HOSTS
PUBLIC_IP=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4)
echo "Detected public IP: $PUBLIC_IP"

# Build ALLOWED_HOSTS - include domain if provided, always include the public IP
ALLOWED_HOSTS_VALUE="$PUBLIC_IP,localhost,127.0.0.1"
%{ if domain_name != "" }
ALLOWED_HOSTS_VALUE="${domain_name},$ALLOWED_HOSTS_VALUE"
%{ endif }

cat > .env << ENVEOF
# Database Configuration
DB_HOST=${db_host}
DB_PORT=3306
DB_NAME=${db_name}
DB_USER=${db_user}
DB_PASSWORD=${db_password}

# Django Configuration
SECRET_KEY=${django_secret_key}
DEBUG=False
ALLOWED_HOSTS=$ALLOWED_HOSTS_VALUE

# HTTPS Configuration - set to true after SSL certificate is configured
ENABLE_HTTPS=${enable_https}

# AWS S3 Configuration
AWS_S3_BUCKET_NAME=${s3_bucket_name}
AWS_S3_REGION=${aws_region}

# Notification Configuration
SLACK_WEBHOOK_URL=${slack_webhook_url}
ALERT_EMAIL=${alert_email}

# Scheduler
RUN_SCHEDULER=true
ENVEOF

# -----------------------------------------------------------------------------
# Database Setup
# -----------------------------------------------------------------------------

echo "Waiting for database to be ready..."
for i in {1..30}; do
    if python3 -c "import MySQLdb; MySQLdb.connect(host='${db_host}', user='${db_user}', password='${db_password}', database='${db_name}')" 2>/dev/null; then
        echo "Database is ready!"
        break
    fi
    echo "Waiting for database... attempt $i/30"
    sleep 10
done

# Run migrations
python manage.py migrate --noinput

# Create cache table
python manage.py createcachetable

# Collect static files
python manage.py collectstatic --noinput

# -----------------------------------------------------------------------------
# Download GeoIP Database
# -----------------------------------------------------------------------------

mkdir -p $APP_DIR/rustbucketregistry/rustbucketregistry/geoip
cd $APP_DIR/rustbucketregistry/rustbucketregistry/geoip

# Note: You need a MaxMind license key for GeoLite2 databases
# For now, create an empty directory - you can add the database later
echo "GeoIP database directory created. Add GeoLite2-Country.mmdb manually."

cd $APP_DIR/rustbucketregistry

# -----------------------------------------------------------------------------
# Gunicorn Systemd Service
# -----------------------------------------------------------------------------

cat > /etc/systemd/system/rustbucket-registry.service << 'SERVICEEOF'
[Unit]
Description=RustBucket Registry Gunicorn Daemon
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/opt/rustbucket-registry/rustbucketregistry
Environment="PATH=/opt/rustbucket-registry/rustbucketregistry/venv/bin"
EnvironmentFile=/opt/rustbucket-registry/rustbucketregistry/.env
ExecStart=/opt/rustbucket-registry/rustbucketregistry/venv/bin/gunicorn \
    --workers 4 \
    --threads 2 \
    --bind 127.0.0.1:8000 \
    --timeout 60 \
    --access-logfile /var/log/rustbucket-registry/access.log \
    --error-logfile /var/log/rustbucket-registry/error.log \
    rustbucketregistry.wsgi:application
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
SERVICEEOF

# Create log directory
mkdir -p /var/log/rustbucket-registry
chown -R www-data:www-data /var/log/rustbucket-registry
chown -R www-data:www-data $APP_DIR

# -----------------------------------------------------------------------------
# Nginx Configuration
# -----------------------------------------------------------------------------

cat > /etc/nginx/sites-available/rustbucket-registry << 'NGINXEOF'
upstream rustbucket_app {
    server 127.0.0.1:8000;
}

server {
    listen 80;
    server_name ${domain_name} _;

    client_max_body_size 100M;

    access_log /var/log/nginx/rustbucket-access.log;
    error_log /var/log/nginx/rustbucket-error.log;

    location /static/ {
        alias /opt/rustbucket-registry/rustbucketregistry/staticfiles/;
        expires 30d;
        add_header Cache-Control "public, immutable";
    }

    location /media/ {
        alias /opt/rustbucket-registry/rustbucketregistry/media/;
        expires 7d;
    }

    location / {
        proxy_pass http://rustbucket_app;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_connect_timeout 60s;
        proxy_read_timeout 60s;
    }
}
NGINXEOF

# Enable site
ln -sf /etc/nginx/sites-available/rustbucket-registry /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

# Test nginx config
nginx -t

# -----------------------------------------------------------------------------
# Start Services
# -----------------------------------------------------------------------------

systemctl daemon-reload
systemctl enable rustbucket-registry
systemctl start rustbucket-registry
systemctl restart nginx

# -----------------------------------------------------------------------------
# SSL Certificate (Let's Encrypt)
# -----------------------------------------------------------------------------

%{ if enable_https && domain_name != "" }
echo "Setting up SSL certificate..."
sleep 30  # Wait for DNS propagation

certbot --nginx -d ${domain_name} \
    --non-interactive \
    --agree-tos \
    --email ${admin_email} \
    --redirect || echo "Certbot failed - you may need to run it manually after DNS is configured"
%{ endif }

# -----------------------------------------------------------------------------
# CloudWatch Agent (Optional)
# -----------------------------------------------------------------------------

# Install CloudWatch agent
wget https://s3.amazonaws.com/amazoncloudwatch-agent/ubuntu/amd64/latest/amazon-cloudwatch-agent.deb
dpkg -i amazon-cloudwatch-agent.deb
rm amazon-cloudwatch-agent.deb

cat > /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json << 'CWEOF'
{
    "logs": {
        "logs_collected": {
            "files": {
                "collect_list": [
                    {
                        "file_path": "/var/log/rustbucket-registry/access.log",
                        "log_group_name": "/aws/ec2/rustbucket-registry",
                        "log_stream_name": "access-{instance_id}"
                    },
                    {
                        "file_path": "/var/log/rustbucket-registry/error.log",
                        "log_group_name": "/aws/ec2/rustbucket-registry",
                        "log_stream_name": "error-{instance_id}"
                    }
                ]
            }
        }
    }
}
CWEOF

systemctl enable amazon-cloudwatch-agent
systemctl start amazon-cloudwatch-agent

# -----------------------------------------------------------------------------
# Completion
# -----------------------------------------------------------------------------

echo "=============================================="
echo "RustBucket Registry deployment complete!"
echo "=============================================="
echo "Application URL: http://$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4)"
echo ""
echo "To create an admin user:"
echo "  cd /opt/rustbucket-registry/rustbucketregistry"
echo "  source venv/bin/activate"
echo "  python manage.py createsuperuser"
echo "=============================================="
