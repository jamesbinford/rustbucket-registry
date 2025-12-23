"""Management command to parse logs from S3 and store them in the database.

This module provides a Django management command for parsing log files
from S3 storage and storing the parsed data in the database.
"""
import boto3
import json
import logging
from django.core.management.base import BaseCommand
from django.conf import settings
from django.utils import timezone
from rustbucketregistry.models import Rustbucket, LogSink, LogEntry, Alert, HoneypotActivity

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    """Django management command for parsing logs from S3."""
    help = 'Parse logs from S3 bucket and store them in the database'
    
    def handle(self, *args, **options):
        """Executes the log parsing process.
        
        Args:
            *args: Variable length argument list.
            **options: Arbitrary keyword arguments.
        """
        self.stdout.write(self.style.SUCCESS('Starting log parsing process...'))
        
        # Initialize S3 client
        s3_client = None
        if settings.AWS_ACCESS_KEY_ID and settings.AWS_SECRET_ACCESS_KEY:
            s3_client = boto3.client(
                's3',
                region_name=settings.AWS_S3_REGION,
                aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
                aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY
            )
        else:
            self.stdout.write(self.style.WARNING('AWS credentials not provided, skipping log parsing'))
            return
        
        try:
            # Get all objects in the S3 bucket
            response = s3_client.list_objects_v2(Bucket=settings.AWS_S3_BUCKET_NAME)
            
            if 'Contents' not in response:
                self.stdout.write(self.style.WARNING('No logs found in S3 bucket'))
                return
            
            # Count for summary
            processed_files = 0
            processed_logs = 0
            
            for obj in response.get('Contents', []):
                file_key = obj['Key']
                
                # Only process files that haven't been processed yet
                # We can determine this by checking if the file starts with "processed_"
                if file_key.startswith('processed_'):
                    continue
                
                try:
                    # Get the file from S3
                    s3_response = s3_client.get_object(Bucket=settings.AWS_S3_BUCKET_NAME, Key=file_key)
                    file_content = s3_response['Body'].read().decode('utf-8')
                    
                    # Parse the rustbucket ID from the filename
                    # Format: BKT123456_20220101120000_logs.txt
                    parts = file_key.split('_')
                    if len(parts) < 3:
                        self.stdout.write(self.style.WARNING(f'Invalid filename format: {file_key}'))
                        continue
                    
                    rustbucket_id = parts[0]
                    
                    # Get the rustbucket
                    try:
                        rustbucket = Rustbucket.objects.get(id=rustbucket_id)
                    except Rustbucket.DoesNotExist:
                        self.stdout.write(self.style.WARNING(f'Rustbucket not found: {rustbucket_id}'))
                        continue
                    
                    # Parse the logs (assuming one log entry per line)
                    log_lines = file_content.split('\n')
                    log_count = 0
                    
                    for line in log_lines:
                        if not line.strip():
                            continue
                        
                        # Try to parse as JSON first
                        try:
                            log_data = json.loads(line)
                            log_level = log_data.get('level', 'INFO')
                            log_message = log_data.get('message', line)
                            
                            # Create or get the appropriate log sink
                            log_sink, created = LogSink.objects.get_or_create(
                                rustbucket=rustbucket,
                                log_type=log_level,
                                defaults={
                                    'size': '0 MB',
                                    'status': 'Active',
                                    'alert_level': 'low' if log_level in ['Info', 'Debug', 'INFO', 'DEBUG'] 
                                                    else 'medium' if log_level in ['Warning', 'WARNING'] 
                                                    else 'high'
                                }
                            )
                            
                            # Create the log entry
                            LogEntry.objects.create(
                                logsink=log_sink,
                                level=log_level,
                                message=log_message,
                                source_ip=log_data.get('source_ip')
                            )
                            
                            log_count += 1
                            
                        except json.JSONDecodeError:
                            # If not JSON, just store as plain text
                            log_sink, created = LogSink.objects.get_or_create(
                                rustbucket=rustbucket,
                                log_type='INFO',
                                defaults={
                                    'size': '0 MB',
                                    'status': 'Active',
                                    'alert_level': 'low'
                                }
                            )
                            
                            LogEntry.objects.create(
                                logsink=log_sink,
                                level='INFO',
                                message=line
                            )
                            
                            log_count += 1
                    
                    self.stdout.write(self.style.SUCCESS(f'Processed {log_count} logs from {file_key}'))
                    processed_logs += log_count
                    
                    # Mark the file as processed by copying it with a new prefix
                    new_key = f'processed_{file_key}'
                    s3_client.copy_object(
                        Bucket=settings.AWS_S3_BUCKET_NAME,
                        CopySource={'Bucket': settings.AWS_S3_BUCKET_NAME, 'Key': file_key},
                        Key=new_key
                    )
                    
                    # Delete the original file
                    s3_client.delete_object(Bucket=settings.AWS_S3_BUCKET_NAME, Key=file_key)
                    
                    processed_files += 1
                    
                except Exception as e:
                    self.stdout.write(self.style.ERROR(f'Error processing file {file_key}: {str(e)}'))
                    continue
            
            self.stdout.write(self.style.SUCCESS(f'Log parsing completed: {processed_files} files processed, {processed_logs} logs stored'))
            
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'Error in log parsing process: {str(e)}'))