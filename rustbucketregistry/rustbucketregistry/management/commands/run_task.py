"""
Management command to run scheduled tasks manually.

This is useful for:
- Testing tasks during development
- Running tasks on-demand
- Debugging task execution
"""
from django.core.management.base import BaseCommand
import logging

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Run scheduled tasks manually'

    def add_arguments(self, parser):
        parser.add_argument(
            'task',
            type=str,
            nargs='?',
            help='Task to run: pull_updates, extract_logs, health_check, cleanup, or daily_summary',
        )
        parser.add_argument(
            '--list',
            action='store_true',
            help='List all available tasks',
        )

    def handle(self, *args, **options):
        from rustbucketregistry import scheduled_tasks

        # Map of task names to functions
        available_tasks = {
            'pull_updates': scheduled_tasks.pull_rustbucket_updates,
            'extract_logs': scheduled_tasks.extract_logs_from_rustbuckets,
            'health_check': scheduled_tasks.health_check_rustbuckets,
            'cleanup': scheduled_tasks.cleanup_old_data,
            'daily_summary': scheduled_tasks.generate_daily_summary,
        }

        if options['list']:
            self.stdout.write(self.style.SUCCESS('Available tasks:'))
            for name in available_tasks.keys():
                self.stdout.write(f'  - {name}')
            return

        task_name = options.get('task')

        if not task_name:
            self.stdout.write(
                self.style.WARNING(
                    'Please specify a task name or use --list to see available tasks\n'
                    'Example: python manage.py run_task health_check'
                )
            )
            return

        if task_name in available_tasks:
            self.run_task(task_name, available_tasks[task_name])
        else:
            self.stdout.write(
                self.style.ERROR(
                    f'Unknown task: {task_name}\n'
                    f'Available tasks: {", ".join(available_tasks.keys())}'
                )
            )

    def run_task(self, name, task_func):
        """Run a single task and display results."""
        self.stdout.write(f'Running task: {name}...')

        try:
            result = task_func()
            self.stdout.write(self.style.SUCCESS(f'✓ Task completed successfully'))

            if result:
                self.stdout.write(f'Result: {result}')

        except Exception as e:
            self.stdout.write(self.style.ERROR(f'✗ Task failed: {str(e)}'))
            logger.error(f'Task {name} failed: {str(e)}', exc_info=True)
