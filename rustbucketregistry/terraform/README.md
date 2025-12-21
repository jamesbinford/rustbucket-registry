# RustBucket Registry - Terraform Deployment

This directory contains Terraform configuration for deploying RustBucket Registry to AWS.

## Architecture

```
                    ┌─────────────────────────────────────┐
                    │              AWS VPC                │
                    │                                     │
                    │   ┌─────────────────────────────┐   │
                    │   │      Public Subnet          │   │
                    │   │                             │   │
  Internet ────────────▶│   EC2 (Nginx + Gunicorn)    │   │
                    │   │                             │   │
                    │   └──────────────┬──────────────┘   │
                    │                  │                  │
                    │   ┌──────────────▼──────────────┐   │
                    │   │     Private Subnet          │   │
                    │   │                             │   │
                    │   │      RDS MySQL              │   │
                    │   │                             │   │
                    │   └─────────────────────────────┘   │
                    │                                     │
                    └─────────────────────────────────────┘
                                     │
                    ┌────────────────┼────────────────┐
                    │                │                │
                    ▼                ▼                ▼
                ┌───────┐      ┌──────────┐    ┌───────────┐
                │  S3   │      │CloudWatch│    │  SES/SNS  │
                │ Logs  │      │  Logs    │    │  Alerts   │
                └───────┘      └──────────┘    └───────────┘
```

## Prerequisites

1. [Terraform](https://www.terraform.io/downloads.html) >= 1.0.0
2. [AWS CLI](https://aws.amazon.com/cli/) configured with credentials
3. An SSH key pair created in AWS EC2

## Quick Start

1. **Copy the example variables file:**
   ```bash
   cp terraform.tfvars.example terraform.tfvars
   ```

2. **Edit `terraform.tfvars` with your values:**
   ```bash
   vim terraform.tfvars
   ```

3. **Initialize Terraform:**
   ```bash
   terraform init
   ```

4. **Review the plan:**
   ```bash
   terraform plan
   ```

5. **Apply the configuration:**
   ```bash
   terraform apply
   ```

6. **After deployment, create an admin user:**
   ```bash
   ssh -i ~/.ssh/your-key.pem ubuntu@<EC2_PUBLIC_IP>
   cd /opt/rustbucket-registry/rustbucketregistry
   source venv/bin/activate
   python manage.py createsuperuser
   ```

## Configuration Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `aws_region` | AWS region | `us-east-1` |
| `ec2_instance_type` | EC2 instance type | `t3.medium` |
| `ec2_key_name` | SSH key pair name | Required |
| `db_instance_class` | RDS instance class | `db.t3.small` |
| `db_password` | Database password | Required |
| `django_secret_key` | Django secret key | Required |
| `domain_name` | Domain for the app | Optional |
| `s3_bucket_name` | S3 bucket for logs | Required |

## Outputs

After successful deployment, Terraform will output:

- EC2 public IP address
- RDS endpoint
- S3 bucket name
- SSH command to connect
- Application URL

## SSL/HTTPS

If you provide a `domain_name`, the deployment will attempt to configure Let's Encrypt SSL automatically. Ensure:

1. Your domain's DNS points to the EC2 Elastic IP
2. DNS has propagated before running Terraform

If SSL setup fails during deployment, you can configure it manually:
```bash
sudo certbot --nginx -d yourdomain.com
```

## Estimated Costs

| Resource | Spec | Monthly Cost |
|----------|------|--------------|
| EC2 | t3.medium | ~$30 |
| RDS | db.t3.small | ~$25 |
| S3 | 50GB | ~$1 |
| Data Transfer | 100GB | ~$9 |
| **Total** | | **~$65/mo** |

## Destroy

To tear down all resources:
```bash
terraform destroy
```

**Warning:** This will delete all data including the RDS database. Take backups first!

## Troubleshooting

### Check EC2 user data logs
```bash
ssh ubuntu@<IP> "sudo cat /var/log/user-data.log"
```

### Check application logs
```bash
ssh ubuntu@<IP> "sudo journalctl -u rustbucket-registry -f"
```

### Check nginx logs
```bash
ssh ubuntu@<IP> "sudo tail -f /var/log/nginx/rustbucket-error.log"
```

## Security Notes

1. The `terraform.tfvars` file contains sensitive data - never commit it
2. Use strong passwords for `db_password` and `django_secret_key`
3. Consider restricting SSH access to specific IP ranges in production
4. Enable RDS Multi-AZ for production workloads
5. Review and restrict S3 bucket policies as needed
