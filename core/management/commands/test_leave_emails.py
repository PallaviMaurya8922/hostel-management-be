"""
Management command to test leave notification emails.

This command can be used to test different types of leave notification emails
with sample data to ensure the email system is working correctly.
"""

from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone
from datetime import datetime, date, timedelta
from core.models import Student, Staff, AbsenceRecord, DigitalPass
from core.services.email_service import email_service
import logging

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Test leave notification emails with sample data'

    def add_arguments(self, parser):
        parser.add_argument(
            '--email-type',
            type=str,
            choices=['auto_approval', 'warden_approval', 'rejection', 'escalation', 'all'],
            default='all',
            help='Type of email to test (default: all)',
        )
        parser.add_argument(
            '--student-email',
            type=str,
            help='Email address to send test emails to (overrides student email)',
        )
        parser.add_argument(
            '--staff-email',
            type=str,
            help='Email address to send escalation emails to (overrides staff email)',
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be sent without actually sending emails',
        )

    def handle(self, *args, **options):
        try:
            email_type = options.get('email_type')
            student_email_override = options.get('student_email')
            staff_email_override = options.get('staff_email')
            dry_run = options.get('dry_run')

            if dry_run:
                self.stdout.write(self.style.WARNING("DRY RUN MODE - No emails will be sent"))

            # Create or get test data
            test_student, test_staff, test_absence_record, test_digital_pass = self._create_test_data()
            
            # Override emails if provided
            if student_email_override:
                test_student.email = student_email_override
                test_student.save()
                self.stdout.write(f"Using student email override: {student_email_override}")
            
            if staff_email_override:
                test_staff.email = staff_email_override
                test_staff.save()
                self.stdout.write(f"Using staff email override: {staff_email_override}")

            # Test emails based on type
            if email_type == 'all':
                self._test_all_emails(test_student, test_staff, test_absence_record, test_digital_pass, dry_run)
            elif email_type == 'auto_approval':
                self._test_auto_approval_email(test_student, test_absence_record, test_digital_pass, dry_run)
            elif email_type == 'warden_approval':
                self._test_warden_approval_email(test_student, test_staff, test_absence_record, test_digital_pass, dry_run)
            elif email_type == 'rejection':
                self._test_rejection_email(test_student, test_staff, test_absence_record, dry_run)
            elif email_type == 'escalation':
                self._test_escalation_email(test_student, test_staff, test_absence_record, dry_run)

            self.stdout.write(self.style.SUCCESS("Email testing completed successfully"))

        except Exception as e:
            logger.error(f"Email testing command failed: {str(e)}")
            raise CommandError(f"Failed to test emails: {str(e)}")

    def _create_test_data(self):
        """Create or get test data for email testing"""
        # Create test student
        test_student, created = Student.objects.get_or_create(
            student_id='TEST001',
            defaults={
                'name': 'Test Student',
                'room_number': '101',
                'block': 'A',
                'phone': '+1234567890',
                'email': 'test.student@example.com'
            }
        )
        
        # Create test staff
        test_staff, created = Staff.objects.get_or_create(
            staff_id='WARDEN001',
            defaults={
                'name': 'Test Warden',
                'role': 'warden',
                'email': 'test.warden@example.com',
                'phone': '+1234567891',
                'is_active': True
            }
        )
        
        # Create test absence record
        start_date = timezone.now() + timedelta(days=1)
        end_date = start_date + timedelta(days=2)
        
        test_absence_record, created = AbsenceRecord.objects.get_or_create(
            student=test_student,
            start_date=start_date,
            end_date=end_date,
            defaults={
                'reason': 'Family emergency - need to visit home',
                'emergency_contact': '+9876543210',
                'status': 'approved',
                'auto_approved': True,
                'approval_reason': 'Auto-approved for testing purposes'
            }
        )
        
        # Create test digital pass
        test_digital_pass, created = DigitalPass.objects.get_or_create(
            student=test_student,
            absence_record=test_absence_record,
            defaults={
                'from_date': start_date.date(),
                'to_date': end_date.date(),
                'total_days': 3,
                'reason': 'Family emergency - need to visit home',
                'approved_by': test_staff,
                'approval_type': 'auto',
                'status': 'active'
            }
        )
        
        return test_student, test_staff, test_absence_record, test_digital_pass

    def _test_all_emails(self, student, staff, absence_record, digital_pass, dry_run):
        """Test all email types"""
        self.stdout.write("\n" + "="*50)
        self.stdout.write("Testing All Email Types")
        self.stdout.write("="*50)
        
        self._test_auto_approval_email(student, absence_record, digital_pass, dry_run)
        self._test_warden_approval_email(student, staff, absence_record, digital_pass, dry_run)
        self._test_rejection_email(student, staff, absence_record, dry_run)
        self._test_escalation_email(student, staff, absence_record, dry_run)

    def _test_auto_approval_email(self, student, absence_record, digital_pass, dry_run):
        """Test auto-approval email"""
        self.stdout.write("\n" + "-"*30)
        self.stdout.write("Testing Auto-Approval Email")
        self.stdout.write("-"*30)
        
        if dry_run:
            self.stdout.write(f"Would send auto-approval email to: {student.email}")
            self.stdout.write(f"Pass Number: {digital_pass.pass_number}")
            self.stdout.write(f"Leave Duration: {digital_pass.total_days} days")
            return
        
        try:
            # Generate sample PDF bytes (in real scenario, this would come from PDF service)
            sample_pdf = b"Sample PDF content for testing"
            
            success, message = email_service.send_auto_approval_email(
                student=student,
                absence_record=absence_record,
                digital_pass=digital_pass,
                pdf_bytes=sample_pdf
            )
            
            if success:
                self.stdout.write(self.style.SUCCESS(f"✓ Auto-approval email sent: {message}"))
            else:
                self.stdout.write(self.style.ERROR(f"✗ Auto-approval email failed: {message}"))
        
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"✗ Auto-approval email error: {str(e)}"))

    def _test_warden_approval_email(self, student, staff, absence_record, digital_pass, dry_run):
        """Test warden approval email"""
        self.stdout.write("\n" + "-"*30)
        self.stdout.write("Testing Warden Approval Email")
        self.stdout.write("-"*30)
        
        if dry_run:
            self.stdout.write(f"Would send warden approval email to: {student.email}")
            self.stdout.write(f"Approved by: {staff.name} ({staff.role})")
            self.stdout.write(f"Pass Number: {digital_pass.pass_number}")
            return
        
        try:
            # Generate sample PDF bytes
            sample_pdf = b"Sample PDF content for testing"
            
            success, message = email_service.send_warden_approval_email(
                student=student,
                absence_record=absence_record,
                digital_pass=digital_pass,
                approved_by=staff,
                pdf_bytes=sample_pdf
            )
            
            if success:
                self.stdout.write(self.style.SUCCESS(f"✓ Warden approval email sent: {message}"))
            else:
                self.stdout.write(self.style.ERROR(f"✗ Warden approval email failed: {message}"))
        
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"✗ Warden approval email error: {str(e)}"))

    def _test_rejection_email(self, student, staff, absence_record, dry_run):
        """Test rejection email"""
        self.stdout.write("\n" + "-"*30)
        self.stdout.write("Testing Rejection Email")
        self.stdout.write("-"*30)
        
        if dry_run:
            self.stdout.write(f"Would send rejection email to: {student.email}")
            self.stdout.write(f"Rejected by: {staff.name} ({staff.role})")
            self.stdout.write("Rejection reason: Duration exceeds policy limits")
            return
        
        try:
            # Temporarily update absence record for rejection test
            original_status = absence_record.status
            original_reason = absence_record.approval_reason
            
            absence_record.status = 'rejected'
            absence_record.approval_reason = 'Duration exceeds policy limits and conflicts with academic schedule'
            absence_record.save()
            
            success, message = email_service.send_rejection_email(
                student=student,
                absence_record=absence_record,
                rejected_by=staff
            )
            
            # Restore original values
            absence_record.status = original_status
            absence_record.approval_reason = original_reason
            absence_record.save()
            
            if success:
                self.stdout.write(self.style.SUCCESS(f"✓ Rejection email sent: {message}"))
            else:
                self.stdout.write(self.style.ERROR(f"✗ Rejection email failed: {message}"))
        
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"✗ Rejection email error: {str(e)}"))

    def _test_escalation_email(self, student, staff, absence_record, dry_run):
        """Test escalation email"""
        self.stdout.write("\n" + "-"*30)
        self.stdout.write("Testing Escalation Email")
        self.stdout.write("-"*30)
        
        if dry_run:
            self.stdout.write(f"Would send escalation email to staff: {staff.email}")
            self.stdout.write(f"Student: {student.name} ({student.student_id})")
            self.stdout.write(f"Leave Duration: {(absence_record.end_date.date() - absence_record.start_date.date()).days + 1} days")
            return
        
        try:
            # Temporarily update absence record for escalation test
            original_status = absence_record.status
            absence_record.status = 'pending'
            absence_record.save()
            
            results = email_service.send_escalation_email(
                student=student,
                absence_record=absence_record,
                target_staff=[staff]
            )
            
            # Restore original status
            absence_record.status = original_status
            absence_record.save()
            
            # Report results
            for email_addr, (success, message) in results.items():
                if success:
                    self.stdout.write(self.style.SUCCESS(f"✓ Escalation email sent to {email_addr}: {message}"))
                else:
                    self.stdout.write(self.style.ERROR(f"✗ Escalation email failed for {email_addr}: {message}"))
        
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"✗ Escalation email error: {str(e)}"))

    def _cleanup_test_data(self):
        """Clean up test data (optional)"""
        try:
            # Remove test data if needed
            DigitalPass.objects.filter(student__student_id='TEST001').delete()
            AbsenceRecord.objects.filter(student__student_id='TEST001').delete()
            Student.objects.filter(student_id='TEST001').delete()
            Staff.objects.filter(staff_id='WARDEN001').delete()
            self.stdout.write("Test data cleaned up")
        except Exception as e:
            self.stdout.write(self.style.WARNING(f"Could not clean up test data: {str(e)}"))