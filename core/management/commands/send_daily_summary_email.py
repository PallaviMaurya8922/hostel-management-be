"""
Management command to send daily summary emails to staff members.

This command can be run manually or scheduled via cron to send daily summaries.
"""

from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone
from datetime import datetime, date
from core.services.notification_service import notification_service
import logging

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Send daily summary emails to relevant staff members'

    def add_arguments(self, parser):
        parser.add_argument(
            '--date',
            type=str,
            help='Date for the summary in YYYY-MM-DD format (defaults to today)',
        )
        parser.add_argument(
            '--staff-id',
            type=str,
            help='Send to specific staff member only (optional)',
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be sent without actually sending emails',
        )

    def handle(self, *args, **options):
        try:
            # Parse date
            summary_date = options.get('date')
            if summary_date:
                try:
                    target_date = datetime.strptime(summary_date, '%Y-%m-%d').date()
                except ValueError:
                    raise CommandError(f"Invalid date format: {summary_date}. Use YYYY-MM-DD format.")
            else:
                target_date = timezone.now().date()

            self.stdout.write(f"Generating daily summary for {target_date}")

            # Get specific staff ID if provided
            target_staff = None
            if options.get('staff_id'):
                target_staff = [options['staff_id']]
                self.stdout.write(f"Targeting specific staff member: {options['staff_id']}")

            # Dry run mode
            if options.get('dry_run'):
                self.stdout.write(self.style.WARNING("DRY RUN MODE - No emails will be sent"))
                
                # Generate summary to show what would be sent
                from core.services.daily_summary_service import daily_summary_generator
                summary = daily_summary_generator.generate_daily_summary(target_date)
                formatted_summary = daily_summary_generator.format_summary_for_display(summary)
                
                self.stdout.write("\nSummary content that would be sent:")
                self.stdout.write("-" * 50)
                self.stdout.write(formatted_summary)
                self.stdout.write("-" * 50)
                
                # Show target staff
                if target_staff:
                    self.stdout.write(f"\nWould send to staff: {target_staff}")
                else:
                    # Get staff who would receive the summary
                    staff_with_summaries = [
                        staff_id for staff_id, prefs in notification_service.staff_preferences.items()
                        if prefs.daily_summary
                    ]
                    self.stdout.write(f"\nWould send to {len(staff_with_summaries)} staff members:")
                    for staff_id in staff_with_summaries:
                        self.stdout.write(f"  - {staff_id}")
                
                return

            # Send the daily summary emails
            delivery_results = notification_service.send_daily_summary_email(
                summary_date=target_date.strftime('%Y-%m-%d')
            )

            # Report results
            total_recipients = len(delivery_results)
            successful_deliveries = 0
            failed_deliveries = 0

            for staff_id, results in delivery_results.items():
                staff_success = any(result.success for result in results)
                if staff_success:
                    successful_deliveries += 1
                    self.stdout.write(
                        self.style.SUCCESS(f"✓ Successfully sent to {staff_id}")
                    )
                else:
                    failed_deliveries += 1
                    self.stdout.write(
                        self.style.ERROR(f"✗ Failed to send to {staff_id}")
                    )
                    # Show failure reasons
                    for result in results:
                        if not result.success:
                            self.stdout.write(f"  - {result.method.value}: {result.message}")

            # Summary
            self.stdout.write("\n" + "=" * 50)
            self.stdout.write(f"Daily summary email delivery complete for {target_date}")
            self.stdout.write(f"Total recipients: {total_recipients}")
            self.stdout.write(
                self.style.SUCCESS(f"Successful deliveries: {successful_deliveries}")
            )
            if failed_deliveries > 0:
                self.stdout.write(
                    self.style.ERROR(f"Failed deliveries: {failed_deliveries}")
                )

            # Log the operation
            logger.info(
                f"Daily summary email command completed. "
                f"Date: {target_date}, Recipients: {total_recipients}, "
                f"Successful: {successful_deliveries}, Failed: {failed_deliveries}"
            )

        except Exception as e:
            logger.error(f"Daily summary email command failed: {str(e)}")
            raise CommandError(f"Failed to send daily summary emails: {str(e)}")