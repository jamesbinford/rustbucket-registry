"""
Management command to generate sample/demo data for the RustBucket Registry.

This command creates realistic sample data for testing and demonstration
purposes, including log entries, alerts, and honeypot activities.
"""
import random
from datetime import datetime, timedelta

from django.core.management.base import BaseCommand

from rustbucketregistry.models import (
    Rustbucket, LogSink, LogEntry, Alert, HoneypotActivity
)


class Command(BaseCommand):
    help = 'Generate sample data for testing and demonstration'

    def add_arguments(self, parser):
        parser.add_argument(
            '--clear',
            action='store_true',
            help='Clear existing sample data before generating new data'
        )
        parser.add_argument(
            '--logsinks',
            type=int,
            default=10,
            help='Number of log sinks to generate per rustbucket (default: 10)'
        )
        parser.add_argument(
            '--activities',
            type=int,
            default=50,
            help='Number of honeypot activities to generate (default: 50)'
        )

    def handle(self, *args, **options):
        if options['clear']:
            self.stdout.write('Clearing existing sample data...')
            LogEntry.objects.all().delete()
            Alert.objects.all().delete()
            HoneypotActivity.objects.all().delete()

        rustbuckets = Rustbucket.objects.all()
        if not rustbuckets.exists():
            self.stderr.write(
                self.style.ERROR('No rustbuckets found. Create rustbuckets first.')
            )
            return

        self.stdout.write(f'Generating sample data for {rustbuckets.count()} rustbuckets...')

        # Generate log sinks and entries
        for rustbucket in rustbuckets:
            self._generate_logsinks(rustbucket, options['logsinks'])

        # Generate honeypot activities
        self._generate_honeypot_activities(list(rustbuckets), options['activities'])

        self.stdout.write(self.style.SUCCESS('Sample data generated successfully!'))

    def _generate_logsinks(self, rustbucket, count):
        """Generate log sinks with entries and alerts for a rustbucket."""
        log_types = ['Error', 'Warning', 'Info', 'Debug']
        statuses = ['Active', 'Inactive', 'Maintenance']

        for _ in range(count):
            log_type = random.choice(log_types)

            # Determine alert level based on log type
            if log_type == 'Error':
                alert_level = 'high'
            elif log_type == 'Warning':
                alert_level = 'medium'
            else:
                alert_level = 'low'

            logsink = LogSink.objects.create(
                rustbucket=rustbucket,
                log_type=log_type,
                size=f'{random.randint(10, 500)} MB',
                status=random.choice(statuses),
                alert_level=alert_level
            )

            # Generate log entries
            for _ in range(random.randint(5, 20)):
                LogEntry.objects.create(
                    logsink=logsink,
                    level=log_type.upper(),
                    message=self._generate_log_message(log_type, rustbucket.id)
                )

            # Generate alerts for non-debug logs
            if log_type != 'Debug':
                num_alerts = random.randint(0, 3)
                for _ in range(num_alerts):
                    Alert.objects.create(
                        logsink=logsink,
                        type=log_type.lower() if log_type in ['Error', 'Warning'] else 'info',
                        severity=alert_level,
                        message=self._generate_alert_message(log_type)
                    )

        self.stdout.write(f'  Created logsinks for {rustbucket.name}')

    def _generate_log_message(self, log_type, bucket_id):
        """Generate a sample log message based on log type."""
        timestamp = datetime.now() - timedelta(minutes=random.randint(1, 60))
        timestamp_str = timestamp.strftime('%Y-%m-%d %H:%M:%S')

        messages = {
            'Error': [
                f'[{timestamp_str}] ERROR: Failed to process request for bucket {bucket_id}: Connection timed out',
                f'[{timestamp_str}] ERROR: Database query failed for {bucket_id}: Syntax error in SQL',
                f'[{timestamp_str}] ERROR: Memory allocation failed on {bucket_id}: Out of memory',
                f'[{timestamp_str}] ERROR: File not found in bucket {bucket_id}: /var/log/system.log',
                f'[{timestamp_str}] ERROR: Permission denied for user on {bucket_id}: Access violation'
            ],
            'Warning': [
                f'[{timestamp_str}] WARNING: High CPU usage detected on {bucket_id}: 92%',
                f'[{timestamp_str}] WARNING: Disk space running low on {bucket_id}: 85% used',
                f'[{timestamp_str}] WARNING: Slow network performance on {bucket_id}: 250ms latency',
                f'[{timestamp_str}] WARNING: Memory usage approaching threshold on {bucket_id}: 78%',
                f'[{timestamp_str}] WARNING: Too many concurrent connections on {bucket_id}: 150/200'
            ],
            'Info': [
                f'[{timestamp_str}] INFO: System update completed successfully on {bucket_id}',
                f'[{timestamp_str}] INFO: New package published to {bucket_id}: rust-analyzer-0.3.1459',
                f'[{timestamp_str}] INFO: Backup completed for {bucket_id}: 1.2GB transferred',
                f'[{timestamp_str}] INFO: User authentication successful on {bucket_id}: admin',
                f'[{timestamp_str}] INFO: Repository synced with remote on {bucket_id}: 128 packages'
            ],
            'Debug': [
                f'[{timestamp_str}] DEBUG: Processing request for {bucket_id}: GET /api/v1/packages',
                f'[{timestamp_str}] DEBUG: Cache hit for query on {bucket_id}: query_id=12345',
                f'[{timestamp_str}] DEBUG: Network packet received on {bucket_id}: size=1024 bytes',
                f'[{timestamp_str}] DEBUG: Thread pool status on {bucket_id}: 4/8 active',
                f'[{timestamp_str}] DEBUG: Configuration reloaded on {bucket_id}: 25 settings updated'
            ]
        }

        return random.choice(messages.get(log_type, messages['Info']))

    def _generate_alert_message(self, log_type):
        """Generate an alert message based on log type."""
        messages = {
            'Error': ['Disk failure', 'Connection lost', 'Service down', 'Memory leak'],
            'Warning': ['High CPU', 'Low disk space', 'Network latency', 'Memory pressure'],
            'Info': ['Update needed', 'New version', 'Restarted service', 'Config changed']
        }
        return random.choice(messages.get(log_type, messages['Info']))

    def _generate_honeypot_activities(self, rustbuckets, count):
        """Generate honeypot activities for rustbuckets."""
        activity_types = ['scan', 'exploit', 'bruteforce', 'malware']

        for _ in range(count):
            rustbucket = random.choice(rustbuckets)
            activity_type = random.choice(activity_types)

            # Generate timestamp in last 24 hours
            hours_ago = random.randint(0, 23)
            minutes_ago = random.randint(0, 59)
            timestamp = datetime.now() - timedelta(hours=hours_ago, minutes=minutes_ago)

            source_ip = self._generate_malicious_ip()
            details = self._generate_activity_details(activity_type, source_ip, rustbucket)

            HoneypotActivity.objects.create(
                rustbucket=rustbucket,
                type=activity_type,
                source_ip=source_ip,
                timestamp=timestamp,
                details=details
            )

        self.stdout.write(f'  Created {count} honeypot activities')

    def _generate_malicious_ip(self):
        """Generate a random IP address that looks suspicious."""
        generators = [
            lambda: f'{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}',
            lambda: f'176.{random.randint(10, 20)}.{random.randint(0, 255)}.{random.randint(0, 255)}',
            lambda: f'45.{random.randint(30, 60)}.{random.randint(0, 255)}.{random.randint(0, 255)}',
            lambda: f'103.{random.randint(20, 50)}.{random.randint(0, 255)}.{random.randint(0, 255)}'
        ]
        return random.choice(generators)()

    def _generate_activity_details(self, activity_type, source_ip, rustbucket):
        """Generate details for a honeypot activity."""
        if activity_type == 'scan':
            ports = [21, 22, 23, 25, 80, 443, 445, 3306, 5432, 8080]
            scanned_ports = sorted(random.sample(ports, random.randint(1, len(ports))))
            return f'Port scan detected from {source_ip}. Ports: {", ".join(map(str, scanned_ports))}'

        elif activity_type == 'exploit':
            exploits = [
                'SQL injection in query parameter: id=1\' OR 1=1--',
                'RCE attempt: ?cmd=cat%20/etc/passwd',
                'XSS attempt: ?q=<script>alert(1)</script>',
                'Path traversal: ?file=../../../etc/passwd',
                'Log4j JNDI exploit attempt'
            ]
            return f'Exploit attempt from {source_ip}: {random.choice(exploits)}'

        elif activity_type == 'bruteforce':
            services = ['SSH', 'FTP', 'Admin Portal', 'API', 'Database']
            users = ['admin', 'root', 'user', 'test', 'guest']
            attempts = random.randint(5, 15)
            return f'Brute force attack against {random.choice(services)} from {source_ip}. {attempts} failed attempts for user \'{random.choice(users)}\''

        else:  # malware
            malware_types = ['Trojan', 'Ransomware', 'Cryptominer', 'Backdoor']
            malware_names = ['Emotet', 'TrickBot', 'Ryuk', 'XMRig', 'Mirai']
            return f'Malware upload detected from {source_ip}. Type: {random.choice(malware_types)}, Identified as: {random.choice(malware_names)}'
