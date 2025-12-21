# =============================================================================
# RustBucket Registry - Terraform Outputs
# =============================================================================

# -----------------------------------------------------------------------------
# EC2 Outputs
# -----------------------------------------------------------------------------

output "ec2_instance_id" {
  description = "ID of the EC2 instance"
  value       = aws_instance.app.id
}

output "ec2_public_ip" {
  description = "Public IP address of the EC2 instance"
  value       = aws_eip.app.public_ip
}

output "ec2_public_dns" {
  description = "Public DNS name of the EC2 instance"
  value       = aws_eip.app.public_dns
}

output "application_url" {
  description = "URL to access the application"
  value       = var.domain_name != "" ? "https://${var.domain_name}" : "http://${aws_eip.app.public_ip}"
}

# -----------------------------------------------------------------------------
# RDS Outputs
# -----------------------------------------------------------------------------

output "rds_endpoint" {
  description = "RDS instance endpoint"
  value       = aws_db_instance.main.endpoint
}

output "rds_address" {
  description = "RDS instance address (hostname only)"
  value       = aws_db_instance.main.address
}

output "rds_port" {
  description = "RDS instance port"
  value       = aws_db_instance.main.port
}

output "rds_database_name" {
  description = "Name of the database"
  value       = aws_db_instance.main.db_name
}

# -----------------------------------------------------------------------------
# S3 Outputs
# -----------------------------------------------------------------------------

output "s3_bucket_name" {
  description = "Name of the S3 bucket for log storage"
  value       = aws_s3_bucket.logs.id
}

output "s3_bucket_arn" {
  description = "ARN of the S3 bucket"
  value       = aws_s3_bucket.logs.arn
}

# -----------------------------------------------------------------------------
# Networking Outputs
# -----------------------------------------------------------------------------

output "vpc_id" {
  description = "ID of the VPC"
  value       = aws_vpc.main.id
}

output "public_subnet_ids" {
  description = "IDs of the public subnets"
  value       = aws_subnet.public[*].id
}

output "private_subnet_ids" {
  description = "IDs of the private subnets"
  value       = aws_subnet.private[*].id
}

# -----------------------------------------------------------------------------
# Security Group Outputs
# -----------------------------------------------------------------------------

output "ec2_security_group_id" {
  description = "ID of the EC2 security group"
  value       = aws_security_group.ec2.id
}

output "rds_security_group_id" {
  description = "ID of the RDS security group"
  value       = aws_security_group.rds.id
}

# -----------------------------------------------------------------------------
# SSH Connection
# -----------------------------------------------------------------------------

output "ssh_command" {
  description = "SSH command to connect to the EC2 instance"
  value       = "ssh -i ~/.ssh/${var.ec2_key_name}.pem ubuntu@${aws_eip.app.public_ip}"
}

# -----------------------------------------------------------------------------
# Next Steps
# -----------------------------------------------------------------------------

output "next_steps" {
  description = "Next steps after deployment"
  value       = <<-EOT

    ============================================================
    RustBucket Registry Deployment Complete!
    ============================================================

    Application URL: ${var.domain_name != "" ? "https://${var.domain_name}" : "http://${aws_eip.app.public_ip}"}

    SSH Access:
      ssh -i ~/.ssh/${var.ec2_key_name}.pem ubuntu@${aws_eip.app.public_ip}

    Database:
      Host: ${aws_db_instance.main.address}
      Port: ${aws_db_instance.main.port}
      Database: ${var.db_name}

    S3 Bucket: ${aws_s3_bucket.logs.id}

    Next Steps:
    1. Point your domain DNS to: ${aws_eip.app.public_ip}
    2. Wait for DNS propagation (~5-10 minutes)
    3. SSL certificate will be auto-configured via Let's Encrypt
    4. Access the application and create an admin user:
       ssh ubuntu@${aws_eip.app.public_ip}
       cd /opt/rustbucket-registry/rustbucketregistry
       source venv/bin/activate
       python manage.py createsuperuser

    ============================================================
  EOT
}
