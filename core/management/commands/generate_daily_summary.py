"""
Simple management command to generate daily summary.
"""

from django.core.management.base import BaseCommand
from django.utils import timezone
from core.services.daily_summary_service import daily_summary_generator


class Command(BaseCommand):
    help = 'Generate simple daily summary'

    def add_arguments(self, parser):
        parser.add_argument(
            '--date',
            type=str,
            help='Date for summary (YYYY-MM-DD format, defaults to today)',
        )

    def handle(self, *args, **options):
        try:
            # Parse date if provided
            target_date = None
            if options['date']:
                from datetime import datetime
                target_date = datetime.strptime(options['date'], '%Y-%m-%d')
                target_date = timezone.make_aware(target_date)

            # Generate summary
            self.stdout.write('Generating daily summary...')
            summary = daily_summary_generator.generate_morning_summary(target_date)
            
            # Display summary
            formatted_summary = daily_summary_generator.format_summary_for_display(summary)
            self.stdout.write(formatted_summary)
            
            self.stdout.write(
                self.style.SUCCESS('Daily summary generated successfully')
            )

        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'Error generating daily summary: {str(e)}')
            )
            raise