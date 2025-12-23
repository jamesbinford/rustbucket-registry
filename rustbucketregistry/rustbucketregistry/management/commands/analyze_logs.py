"""Management command to analyze logs using Claude.

This module provides a Django management command for analyzing logs
using Claude AI and storing the analysis results in the database.
"""
import logging
import json
import anthropic
import os
from datetime import timedelta
from django.core.management.base import BaseCommand
from django.conf import settings
from django.utils import timezone
from django.db import models, connection

from rustbucketregistry.models import Rustbucket, LogSink, LogEntry, Alert, HoneypotActivity

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    """Django management command for analyzing logs using Claude."""
    help = 'Analyze logs using Claude and store analysis results in the database'
    
    def handle(self, *args, **options):
        """Executes the log analysis process.
        
        Args:
            *args: Variable length argument list.
            **options: Arbitrary keyword arguments.
        """
        self.stdout.write(self.style.SUCCESS('Starting log analysis process...'))
        
        # Check if analysis table exists, create it if not
        with connection.cursor() as cursor:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS log_analysis (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    name VARCHAR(255) NOT NULL,
                    ip_address VARCHAR(255) NOT NULL,
                    log_analysis TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
        
        # Get all rustbuckets with logs (via logsink entries)
        rustbuckets = Rustbucket.objects.filter(
            logsinks__entries__isnull=False
        ).distinct()
        
        processed_count = 0
        failed_count = 0
        
        for rustbucket in rustbuckets:
            try:
                # Get logs from the last 4 hours for this rustbucket
                cutoff_time = timezone.now() - timedelta(hours=settings.LOG_ANALYSIS_INTERVAL_HOURS)
                logs = LogEntry.objects.filter(
                    logsink__rustbucket=rustbucket,
                    timestamp__gte=cutoff_time
                ).order_by('timestamp')
                
                if not logs.exists():
                    self.stdout.write(self.style.WARNING(
                        f'No recent logs found for rustbucket {rustbucket.id}, skipping analysis'
                    ))
                    continue
                
                # Prepare logs for analysis
                log_texts = []
                for log in logs:
                    log_text = f"[{log.timestamp.isoformat()}] [{log.level}] {log.message}"
                    log_texts.append(log_text)
                
                all_logs = "\n".join(log_texts)
                
                # Only proceed if we have an API key for Claude
                claude_api_key = os.getenv('CLAUDE_API_KEY')
                if not claude_api_key:
                    self.stdout.write(self.style.WARNING(
                        'Claude API key not provided, skipping log analysis'
                    ))
                    break
                
                # Call Claude API for analysis
                try:
                    client = anthropic.Anthropic(api_key=claude_api_key)
                    
                    message = client.messages.create(
                        model="claude-3-sonnet-20240229",
                        max_tokens=1000,
                        system="You are an expert security analyst. Analyze the following logs from a honeypot and provide a concise analysis. Focus on identifying patterns, potential security issues, and recommendations.",
                        messages=[
                            {
                                "role": "user",
                                "content": f"Please analyze these logs from rustbucket {rustbucket.name}:\n\n{all_logs}\n\nProvide a concise analysis focusing on security patterns and any concerning events."
                            }
                        ]
                    )
                    
                    analysis_text = message.content[0].text
                    
                    # Store analysis in the log_analysis table
                    with connection.cursor() as cursor:
                        cursor.execute("""
                            INSERT INTO log_analysis (name, ip_address, log_analysis, created_at)
                            VALUES (%s, %s, %s, %s)
                        """, [
                            rustbucket.name,
                            rustbucket.ip_address,
                            analysis_text,
                            timezone.now()
                        ])
                    
                    self.stdout.write(self.style.SUCCESS(
                        f'Successfully analyzed logs for rustbucket {rustbucket.id}'
                    ))
                    processed_count += 1
                    
                except Exception as e:
                    self.stdout.write(self.style.ERROR(
                        f'Error calling Claude API for rustbucket {rustbucket.id}: {str(e)}'
                    ))
                    failed_count += 1
                    continue
                
            except Exception as e:
                self.stdout.write(self.style.ERROR(
                    f'Error processing rustbucket {rustbucket.id}: {str(e)}'
                ))
                failed_count += 1
                continue
        
        self.stdout.write(self.style.SUCCESS(
            f'Log analysis completed: {processed_count} rustbuckets analyzed, {failed_count} failed'
        ))