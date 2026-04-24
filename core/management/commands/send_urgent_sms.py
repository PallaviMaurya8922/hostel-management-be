"""
Management command to send urgent SMS alerts to staff members.

This command can be used to send immediate SMS notifications for critical situations.
"""

from django.core.management.base import BaseCommand, CommandError
from core.services.notification_service import notification_service
import logging

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Send urgent SMS alerts to relevant staff members'

    def add_arguments(self, parser):
        parser.add_argument(
            'alert_type',
            type=str,
            help='Type of alert (e.g., emergency_maintenance, security_issue, fire_alarm)',
        )
        parser.add_argument(
            'message',
            type=str,
            help='Alert message content',
        )
        parser.add_argument(
            '--roles',
            type=str,
            nargs='+',
            default=['warden', 'security'],
            help='Staff roles to notify (default: warden security)',
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be sent without actually sending SMS',
        )

    def handle(self, *args, **options):
        try:
            alert_type = options['alert_type']
            message = options['message']
            target_roles = options['roles']

            self.stdout.write(f"Preparing urgent SMS alert: {alert_type}")
            self.stdout.write(f"Message: {message}")
            self.stdout.write(f"Target roles: {', '.join(target_roles)}")

            # Dry run mode
            if options.get('dry_run'):
                self.stdout.write(self.style.WARNING("DRY RUN MODE - No SMS will be sent"))
                
                # Show who would receive the SMS
                staff_with_sms = []
                for staff_id, prefs in notification_service.staff_preferences.items():
                    if (prefs.urgent_alerts and 
                        notification_service.NotificationMethod.SMS in prefs.methods):
                        from core.models import Staff
                        staff_member = Staff.objects.filter(staff_id=staff_id, is_active=True).first()
                        if staff_member and staff_member.role in target_roles:
                            staff_with_sms.append(f"{staff_id} ({staff_member.name}) - {staff_member.phone}")
                
                if staff_with_sms:
                    self.stdout.write(f"\nWould send SMS to {len(staff_with_sms)} staff members:")
                    for staff_info in staff_with_sms:
                        self.stdout.write(f"  - {staff_info}")
                else:
                    self.stdout.write(self.style.WARNING("\nNo staff members configured for SMS alerts"))
                
                # Show formatted SMS content
                formatted_message = notification_service._format_sms_content(
                    f"URGENT: {alert_type.replace('_', ' ').title()}", 
                    message
                )
                self.stdout.write(f"\nFormatted SMS content ({len(formatted_message)} chars):")
                self.stdout.write(f"'{formatted_message}'")
                
                return

            # Send the urgent SMS alerts
            delivery_results = notification_service.send_urgent_sms_alert(
                alert_type=alert_type,
                message=message,
                target_roles=target_roles
            )

            # Report results
            total_recipients = len(delivery_results)
            successful_deliveries = 0
            failed_deliveries = 0

            for staff_id, results in delivery_results.items():
                if results and results[0].success:
                    successful_deliveries += 1
                    self.stdout.write(
                        self.style.SUCCESS(f"✓ SMS sent to {staff_id}")
                    )
                else:
                    failed_deliveries += 1
                    self.stdout.write(
                        self.style.ERROR(f"✗ Failed to send SMS to {staff_id}")
                    )
                    if results:
                        self.stdout.write(f"  - Error: {results[0].message}")

            # Summary
            self.stdout.write("\n" + "=" * 50)
            self.stdout.write(f"Urgent SMS alert delivery complete")
            self.stdout.write(f"Alert type: {alert_type}")
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
                f"Urgent SMS alert command completed. "
                f"Type: {alert_type}, Recipients: {total_recipients}, "
                f"Successful: {successful_deliveries}, Failed: {failed_deliveries}"
            )

        except Exception as e:
            logger.error(f"Urgent SMS alert command failed: {str(e)}")
            raise CommandError(f"Failed to send urgent SMS alerts: {str(e)}")