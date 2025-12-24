"""Management command to parse logs from S3.

This module provides a Django management command for parsing log files
from S3 storage. Log files are tracked as LogSink records (file metadata).
Individual log entries are no longer parsed into the database.
"""
import boto3
import logging
from django.core.management.base import BaseCommand
from django.conf import settings
from rustbucketregistry.models import Rustbucket, LogSink

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    """Django management command for parsing logs from S3."""
    help = 'Parse logs from S3 bucket and create LogSink records for tracking'

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

            for obj in response.get('Contents', []):
                file_key = obj['Key']

                # Only process files that haven't been processed yet
                if file_key.startswith('processed_'):
                    continue

                try:
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

                    # Get file size
                    file_size = obj.get('Size', 0)
                    size_str = f'{file_size / 1024 / 1024:.1f} MB' if file_size > 0 else '0 MB'

                    # Create or update LogSink to track the log file
                    LogSink.objects.get_or_create(
                        rustbucket=rustbucket,
                        log_type='Info',
                        defaults={
                            'size': size_str,
                            'status': 'Active',
                            'alert_level': 'low'
                        }
                    )

                    self.stdout.write(self.style.SUCCESS(f'Processed log file: {file_key}'))

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

            self.stdout.write(self.style.SUCCESS(f'Log parsing completed: {processed_files} files processed'))

        except Exception as e:
            self.stdout.write(self.style.ERROR(f'Error in log parsing process: {str(e)}'))