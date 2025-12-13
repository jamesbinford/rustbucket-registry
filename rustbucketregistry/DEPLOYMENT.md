# Rustbucket Registry - Deployment Guide

This guide covers deploying the Rustbucket Registry in production environments.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Quick Start with Docker](#quick-start-with-docker)
- [Production Deployment with Docker](#production-deployment-with-docker)
- [Manual Deployment](#manual-deployment)
- [Environment Configuration](#environment-configuration)
- [Database Setup](#database-setup)
- [Web Server Configuration](#web-server-configuration)
- [Security Checklist](#security-checklist)
- [Monitoring and Maintenance](#monitoring-and-maintenance)
- [Troubleshooting](#troubleshooting)

---

## Prerequisites

### System Requirements

- **OS**: Ubuntu 20.04/22.04, Debian 11+, RHEL 8+, or Docker
- **Python**: 3.10+ (3.12 recommended)
- **Database**: MySQL 8.0+ or MariaDB 10.5+
- **Memory**: Minimum 2GB RAM (4GB+ recommended)
- **Storage**: Minimum 10GB (depends on log volume)

### Required Software

- Python 3.12
- MySQL/MariaDB
- Nginx (for reverse proxy)
- Git
- pip

### Optional but Recommended

- Docker & Docker Compose (simplest deployment)
- AWS Account (for S3 log storage)
- Email service (Gmail, SendGrid, etc.) for notifications

---

## Quick Start with Docker

The fastest way to get started:

```bash
# Clone the repository
git clone https://github.com/yourusername/rustbucket-registry.git
cd rustbucket-registry/rustbucketregistry

# Copy environment file and configure
cp .env.example .env
nano .env  # Edit with your settings

# Generate a secure SECRET_KEY
python -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())"

# Start services
docker-compose up -d

# Check logs
docker-compose logs -f web

# Access the application
# http://localhost:8000
```

---

## Production Deployment with Docker

### Step 1: Prepare Environment

```bash
# Clone repository
git clone https://github.com/yourusername/rustbucket-registry.git
cd rustbucket-registry/rustbucketregistry

# Copy and configure environment
cp .env.example .env
```

### Step 2: Configure Environment Variables

Edit `.env` with production values:

```bash
# CRITICAL: Change these values!
SECRET_KEY=your-generated-secret-key-here
DEBUG=False
ALLOWED_HOSTS=yourdomain.com,www.yourdomain.com

# Database (use strong passwords!)
DB_NAME=rustbucket_registry
DB_USER=rustbucket_user
DB_PASSWORD=your-strong-database-password
DB_ROOT_PASSWORD=your-strong-root-password
DB_HOST=db
DB_PORT=3306

# AWS S3 (for log storage)
AWS_ACCESS_KEY_ID=your-aws-access-key
AWS_SECRET_ACCESS_KEY=your-aws-secret-key
AWS_S3_REGION=us-east-1
AWS_S3_BUCKET_NAME=rustbucket-registry-logs

# Email (for notifications)
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USE_TLS=True
EMAIL_HOST_USER=your-email@gmail.com
EMAIL_HOST_PASSWORD=your-app-password
DEFAULT_FROM_EMAIL=rustbucket-registry@yourdomain.com

# Scheduler
RUN_SCHEDULER=true
```

### Step 3: Generate SECRET_KEY

```bash
python -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())"
```

### Step 4: Build and Deploy

```bash
# Build images
docker-compose build

# Start services
docker-compose up -d

# Verify services are running
docker-compose ps

# Check logs
docker-compose logs -f
```

### Step 5: Create Admin User

```bash
docker-compose exec web python manage.py createsuperuser
```

### Step 6: Access Application

- Application: `http://your-server-ip:8000`
- Admin: `http://your-server-ip:8000/admin`

---

## Manual Deployment

### Step 1: Install System Dependencies

#### Ubuntu/Debian

```bash
sudo apt update
sudo apt install -y python3.12 python3.12-venv python3-pip
sudo apt install -y mysql-server
sudo apt install -y default-libmysqlclient-dev build-essential pkg-config
sudo apt install -y nginx
```

#### RHEL/CentOS

```bash
sudo dnf install -y python3.12 python3-pip
sudo dnf install -y mysql-server
sudo dnf install -y mysql-devel gcc python3-devel
sudo dnf install -y nginx
```

### Step 2: Setup MySQL Database

```bash
sudo mysql -u root -p
```

```sql
CREATE DATABASE rustbucket_registry CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'rustbucket_user'@'localhost' IDENTIFIED BY 'your-strong-password';
GRANT ALL PRIVILEGES ON rustbucket_registry.* TO 'rustbucket_user'@'localhost';
GRANT CREATE ON test_rustbucket_registry.* TO 'rustbucket_user'@'localhost';
FLUSH PRIVILEGES;
EXIT;
```

### Step 3: Clone and Setup Application

```bash
# Create application directory
sudo mkdir -p /opt/rustbucket-registry
sudo chown $USER:$USER /opt/rustbucket-registry
cd /opt/rustbucket-registry

# Clone repository
git clone https://github.com/yourusername/rustbucket-registry.git .

# Create virtual environment
python3.12 -m venv venv
source venv/bin/activate

# Install dependencies
cd rustbucketregistry
pip install -r requirements.txt
```

### Step 4: Configure Environment

```bash
cp .env.example .env
nano .env
```

Update with your production settings (same as Docker deployment above, but use `DB_HOST=localhost`).

### Step 5: Run Migrations and Collect Static Files

```bash
source venv/bin/activate
cd /opt/rustbucket-registry/rustbucketregistry

# Run migrations
python manage.py migrate

# Collect static files
python manage.py collectstatic --noinput

# Create admin user
python manage.py createsuperuser
```

### Step 6: Setup Systemd Service

See [Web Server Configuration](#web-server-configuration) section below.

---

## Environment Configuration

### Required Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `SECRET_KEY` | Django secret key (generate with command above) | `django-insecure-abc123...` |
| `DEBUG` | Debug mode (MUST be False in production) | `False` |
| `ALLOWED_HOSTS` | Comma-separated allowed hostnames | `yourdomain.com,www.yourdomain.com` |
| `DB_NAME` | Database name | `rustbucket_registry` |
| `DB_USER` | Database username | `rustbucket_user` |
| `DB_PASSWORD` | Database password | `StrongPassword123!` |
| `DB_HOST` | Database host | `localhost` or `db` (Docker) |
| `DB_PORT` | Database port | `3306` |

### Optional Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `AWS_ACCESS_KEY_ID` | AWS access key for S3 | None |
| `AWS_SECRET_ACCESS_KEY` | AWS secret key for S3 | None |
| `AWS_S3_REGION` | AWS S3 region | `us-east-1` |
| `AWS_S3_BUCKET_NAME` | S3 bucket for logs | None |
| `EMAIL_HOST` | SMTP server hostname | `localhost` |
| `EMAIL_PORT` | SMTP server port | `587` |
| `EMAIL_USE_TLS` | Use TLS for email | `True` |
| `EMAIL_HOST_USER` | SMTP username | None |
| `EMAIL_HOST_PASSWORD` | SMTP password | None |
| `DEFAULT_FROM_EMAIL` | Default sender email | `webmaster@localhost` |
| `RUN_SCHEDULER` | Enable background tasks | `true` |

---

## Database Setup

### Backup Configuration

Create a backup script:

```bash
#!/bin/bash
# /opt/rustbucket-registry/backup.sh

BACKUP_DIR="/opt/rustbucket-registry/backups"
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p $BACKUP_DIR

# Backup database
mysqldump -u rustbucket_user -p'your-password' rustbucket_registry \
  | gzip > $BACKUP_DIR/rustbucket_registry_$DATE.sql.gz

# Keep only last 7 days of backups
find $BACKUP_DIR -name "*.sql.gz" -mtime +7 -delete

echo "Backup completed: rustbucket_registry_$DATE.sql.gz"
```

Make it executable and add to crontab:

```bash
chmod +x /opt/rustbucket-registry/backup.sh

# Add to crontab (daily at 2 AM)
crontab -e
0 2 * * * /opt/rustbucket-registry/backup.sh >> /var/log/rustbucket-backup.log 2>&1
```

### Restore from Backup

```bash
# Stop application
sudo systemctl stop rustbucket-registry

# Restore database
gunzip < /path/to/backup.sql.gz | mysql -u rustbucket_user -p rustbucket_registry

# Start application
sudo systemctl start rustbucket-registry
```

---

## Web Server Configuration

### Gunicorn Systemd Service

Create `/etc/systemd/system/rustbucket-registry.service`:

```ini
[Unit]
Description=Rustbucket Registry Gunicorn Service
After=network.target mysql.service

[Service]
Type=notify
User=www-data
Group=www-data
WorkingDirectory=/opt/rustbucket-registry/rustbucketregistry
Environment="PATH=/opt/rustbucket-registry/venv/bin"
EnvironmentFile=/opt/rustbucket-registry/rustbucketregistry/.env
ExecStart=/opt/rustbucket-registry/venv/bin/gunicorn \
    --workers 4 \
    --threads 2 \
    --bind 127.0.0.1:8000 \
    --timeout 60 \
    --access-logfile /var/log/rustbucket-registry/access.log \
    --error-logfile /var/log/rustbucket-registry/error.log \
    --log-level info \
    rustbucketregistry.wsgi:application
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Create log directory:

```bash
sudo mkdir -p /var/log/rustbucket-registry
sudo chown www-data:www-data /var/log/rustbucket-registry
```

Enable and start service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable rustbucket-registry
sudo systemctl start rustbucket-registry
sudo systemctl status rustbucket-registry
```

### Nginx Configuration

Create `/etc/nginx/sites-available/rustbucket-registry`:

```nginx
upstream rustbucket_registry {
    server 127.0.0.1:8000;
}

server {
    listen 80;
    server_name yourdomain.com www.yourdomain.com;

    # Redirect HTTP to HTTPS
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name yourdomain.com www.yourdomain.com;

    # SSL certificates (use certbot for Let's Encrypt)
    ssl_certificate /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;

    # SSL configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;

    # Client body size (for log uploads)
    client_max_body_size 100M;

    # Logging
    access_log /var/log/nginx/rustbucket-registry-access.log;
    error_log /var/log/nginx/rustbucket-registry-error.log;

    # Static files
    location /static/ {
        alias /opt/rustbucket-registry/rustbucketregistry/staticfiles/;
        expires 30d;
        add_header Cache-Control "public, immutable";
    }

    # Media files
    location /media/ {
        alias /opt/rustbucket-registry/rustbucketregistry/media/;
        expires 7d;
    }

    # Proxy to Gunicorn
    location / {
        proxy_pass http://rustbucket_registry;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_connect_timeout 60s;
        proxy_read_timeout 60s;
    }
}
```

Enable the site:

```bash
sudo ln -s /etc/nginx/sites-available/rustbucket-registry /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

### Setup SSL with Let's Encrypt

```bash
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d yourdomain.com -d www.yourdomain.com
```

---

## Security Checklist

Before deploying to production:

- [ ] `DEBUG=False` in `.env`
- [ ] `ALLOWED_HOSTS` configured with your domain
- [ ] Strong `SECRET_KEY` generated and set
- [ ] Strong database passwords (20+ characters)
- [ ] No hardcoded passwords in code or docker-compose.yml
- [ ] `.env` file has proper permissions (600)
- [ ] SSL/HTTPS enabled (certbot configured)
- [ ] Firewall configured (only ports 80, 443, 22 open)
- [ ] Database only accessible from localhost
- [ ] Regular backups configured
- [ ] Security updates automated (`unattended-upgrades`)
- [ ] Application logs monitored
- [ ] S3 bucket access restricted (IAM policies)
- [ ] Email credentials secured (use app passwords)
- [ ] Admin password is strong (20+ characters)

### Firewall Configuration (UFW)

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw allow http
sudo ufw allow https
sudo ufw enable
```

---

## Monitoring and Maintenance

### Health Checks

Check application health:

```bash
# Systemd service status
sudo systemctl status rustbucket-registry

# Check logs
sudo journalctl -u rustbucket-registry -f

# Nginx logs
sudo tail -f /var/log/nginx/rustbucket-registry-error.log

# Application logs
sudo tail -f /var/log/rustbucket-registry/error.log
```

### Database Maintenance

```bash
# Check database size
mysql -u rustbucket_user -p -e "
SELECT table_schema AS 'Database',
       ROUND(SUM(data_length + index_length) / 1024 / 1024, 2) AS 'Size (MB)'
FROM information_schema.tables
WHERE table_schema = 'rustbucket_registry'
GROUP BY table_schema;"

# Optimize tables
mysql -u rustbucket_user -p rustbucket_registry -e "OPTIMIZE TABLE rustbucketregistry_alert, rustbucketregistry_logentry;"
```

### Log Rotation

Create `/etc/logrotate.d/rustbucket-registry`:

```
/var/log/rustbucket-registry/*.log {
    daily
    missingok
    rotate 14
    compress
    delaycompress
    notifempty
    create 0640 www-data www-data
    sharedscripts
    postrotate
        systemctl reload rustbucket-registry
    endscript
}
```

### Updates

```bash
# Pull latest code
cd /opt/rustbucket-registry
git pull origin main

# Activate virtual environment
source venv/bin/activate
cd rustbucketregistry

# Install new dependencies
pip install -r requirements.txt

# Run migrations
python manage.py migrate

# Collect static files
python manage.py collectstatic --noinput

# Restart services
sudo systemctl restart rustbucket-registry
sudo systemctl reload nginx
```

---

## Troubleshooting

### Application Won't Start

```bash
# Check service status
sudo systemctl status rustbucket-registry

# Check logs
sudo journalctl -u rustbucket-registry -n 50

# Check if port is already in use
sudo lsof -i :8000

# Verify database connection
mysql -u rustbucket_user -p rustbucket_registry -e "SELECT 1;"
```

### Database Connection Errors

```bash
# Verify database is running
sudo systemctl status mysql

# Check database credentials in .env
cat /opt/rustbucket-registry/rustbucketregistry/.env | grep DB_

# Test connection
mysql -u rustbucket_user -p -h localhost
```

### Static Files Not Loading

```bash
# Collect static files
python manage.py collectstatic --noinput

# Check permissions
ls -la /opt/rustbucket-registry/rustbucketregistry/staticfiles/

# Verify Nginx configuration
sudo nginx -t
```

### Scheduler Not Running

```bash
# Check if scheduler is enabled
grep RUN_SCHEDULER /opt/rustbucket-registry/rustbucketregistry/.env

# Check application logs
sudo journalctl -u rustbucket-registry | grep -i scheduler

# Manually run a task
python manage.py run_task health_check
```

### High Memory Usage

```bash
# Check process memory
ps aux | grep gunicorn

# Reduce number of workers in systemd service
# Edit /etc/systemd/system/rustbucket-registry.service
# Change --workers 4 to --workers 2

sudo systemctl daemon-reload
sudo systemctl restart rustbucket-registry
```

---

## Additional Resources

- [CLAUDE.md](CLAUDE.md) - Development guide
- [NOTIFICATIONS_SETUP.md](NOTIFICATIONS_SETUP.md) - Notification configuration
- [SCHEDULER_SETUP.md](SCHEDULER_SETUP.md) - Scheduled tasks documentation
- [Django Deployment Checklist](https://docs.djangoproject.com/en/stable/howto/deployment/checklist/)
- [Gunicorn Documentation](https://docs.gunicorn.org/)
- [Nginx Documentation](https://nginx.org/en/docs/)

---

## Support

For issues or questions:
- GitHub Issues: https://github.com/yourusername/rustbucket-registry/issues
- Documentation: See README.md and CLAUDE.md

---

**Last Updated**: 2025-12-12
**Version**: 1.0.0
