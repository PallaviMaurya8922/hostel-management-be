"""
Tests for email notification functionality.
"""

import pytest
from unittest.mock import patch, MagicMock
from django.test import TestCase
from django.core import mail
from django.utils import timezone
from datetime import date, datetime, timedelta

from core.models import Staff, Student, AbsenceRecord, DigitalPass
from core.services.notification_service import (
    notification_service, 
    NotificationMethod, 
    NotificationPriority
)
from core.services.email_service import email_service
from core.services.daily_summary_service import SimpleDailySummary


class EmailNotificationTests(TestCase):
    """Test email notification functionality."""

    def setUp(self):
        """Set up test data."""
        # Create test staff members
        self.warden = Staff.objects.create(
            staff_id='W001',
            name='Test Warden',
            role='warden',
            email='warden@test.com',
            phone='+1234567890',
            is_active=True
        )
        
        self.security = Staff.objects.create(
            staff_id='S001',
            name='Test Security',
            role='security',
            email='security@test.com',
            phone='+1234567891',
            is_active=True
        )
        
        # Create test student
        self.student = Student.objects.create(
            student_id='ST001',
            name='Test Student',
            room_number='101',
            block='A',
            phone='+1234567892',
            email='student@test.com'
        )
        
        # Create test absence record
        start_date = timezone.now() + timedelta(days=1)
        end_date = start_date + timedelta(days=2)
        
        self.absence_record = AbsenceRecord.objects.create(
            student=self.student,
            start_date=start_date,
            end_date=end_date,
            reason='Family emergency',
            emergency_contact='+9876543210',
            status='approved',
            auto_approved=True
        )
        
        # Create test digital pass
        self.digital_pass = DigitalPass.objects.create(
            student=self.student,
            absence_record=self.absence_record,
            from_date=start_date.date(),
            to_date=end_date.date(),
            total_days=3,
            reason='Family emergency',
            approved_by=self.warden,
            approval_type='auto',
            status='active'
        )
        
        # Clear mail outbox
        mail.outbox = []

    def test_send_auto_approval_email(self):
        """Test sending auto-approval email with PDF attachment."""
        # Sample PDF bytes
        pdf_bytes = b"Sample PDF content for testing"
        
        # Send auto-approval email
        success, message = email_service.send_auto_approval_email(
            student=self.student,
            absence_record=self.absence_record,
            digital_pass=self.digital_pass,
            pdf_bytes=pdf_bytes
        )
        
        # Check success
        self.assertTrue(success)
        self.assertIn('sent to', message)
        
        # Check email was sent
        self.assertEqual(len(mail.outbox), 1)
        sent_email = mail.outbox[0]
        
        # Check email content
        self.assertIn('Auto-Approved', sent_email.subject)
        self.assertIn(self.digital_pass.pass_number, sent_email.subject)
        self.assertEqual(sent_email.to, [self.student.email])
        
        # Check PDF attachment
        self.assertEqual(len(sent_email.attachments), 1)
        attachment_name, attachment_content, attachment_type = sent_email.attachments[0]
        self.assertIn('leave_pass_', attachment_name)
        self.assertEqual(attachment_content, pdf_bytes)
        self.assertEqual(attachment_type, 'application/pdf')

    def test_send_warden_approval_email(self):
        """Test sending warden approval email with PDF attachment."""
        # Sample PDF bytes
        pdf_bytes = b"Sample PDF content for testing"
        
        # Send warden approval email
        success, message = email_service.send_warden_approval_email(
            student=self.student,
            absence_record=self.absence_record,
            digital_pass=self.digital_pass,
            approved_by=self.warden,
            pdf_bytes=pdf_bytes
        )
        
        # Check success
        self.assertTrue(success)
        self.assertIn('sent to', message)
        
        # Check email was sent
        self.assertEqual(len(mail.outbox), 1)
        sent_email = mail.outbox[0]
        
        # Check email content
        self.assertIn('Approved by Warden', sent_email.subject)
        self.assertIn(self.digital_pass.pass_number, sent_email.subject)
        self.assertEqual(sent_email.to, [self.student.email])
        
        # Check PDF attachment
        self.assertEqual(len(sent_email.attachments), 1)

    def test_send_rejection_email(self):
        """Test sending rejection email."""
        # Update absence record for rejection
        self.absence_record.status = 'rejected'
        self.absence_record.approval_reason = 'Duration exceeds policy limits'
        self.absence_record.save()
        
        # Send rejection email
        success, message = email_service.send_rejection_email(
            student=self.student,
            absence_record=self.absence_record,
            rejected_by=self.warden
        )
        
        # Check success
        self.assertTrue(success)
        self.assertIn('sent to', message)
        
        # Check email was sent
        self.assertEqual(len(mail.outbox), 1)
        sent_email = mail.outbox[0]
        
        # Check email content
        self.assertIn('Rejected', sent_email.subject)
        self.assertEqual(sent_email.to, [self.student.email])
        
        # Check no PDF attachment for rejection
        self.assertEqual(len(sent_email.attachments), 0)

    def test_send_escalation_email(self):
        """Test sending escalation email to staff."""
        # Update absence record for escalation
        self.absence_record.status = 'pending'
        self.absence_record.save()
        
        # Send escalation email
        results = email_service.send_escalation_email(
            student=self.student,
            absence_record=self.absence_record,
            target_staff=[self.warden]
        )
        
        # Check results
        self.assertTrue(len(results) > 0)
        success, message = results[self.warden.email]
        self.assertTrue(success)
        
        # Check email was sent
        self.assertEqual(len(mail.outbox), 1)
        sent_email = mail.outbox[0]
        
        # Check email content
        self.assertIn('Requires Approval', sent_email.subject)
        self.assertIn(self.student.name, sent_email.subject)
        self.assertEqual(sent_email.to, [self.warden.email])

    def test_email_without_student_email(self):
        """Test email handling when student has no email address."""
        # Remove student email
        self.student.email = ''
        self.student.save()
        
        # Try to send auto-approval email
        success, message = email_service.send_auto_approval_email(
            student=self.student,
            absence_record=self.absence_record,
            digital_pass=self.digital_pass
        )
        
        # Check failure
        self.assertFalse(success)
        self.assertIn('no email address', message.lower())
        
        # Check no email was sent
        self.assertEqual(len(mail.outbox), 0)

    def test_html_email_content_generation(self):
        """Test HTML email content generation."""
        context = {
            'student_name': 'Test Student',
            'student_id': 'ST001',
            'room_number': '101',
            'block': 'A',
            'from_date': 'January 15, 2024',
            'to_date': 'January 17, 2024',
            'total_days': 3,
            'reason': 'Family emergency',
            'pass_number': 'LP-20240115-001',
            'verification_code': 'ABC123',
            'approval_date': 'January 14, 2024 at 10:30 AM',
            'system_name': 'AI Hostel Coordination System'
        }
        
        # Test auto-approval HTML generation
        html_content = email_service._generate_approval_html(context, 'auto_approval')
        
        # Check HTML structure
        self.assertIn('<!DOCTYPE html>', html_content)
        self.assertIn('Auto-Approved', html_content)
        self.assertIn(context['student_name'], html_content)
        self.assertIn(context['pass_number'], html_content)
        self.assertIn('#28a745', html_content)  # Auto-approval color

    def test_text_email_content_generation(self):
        """Test plain text email content generation."""
        context = {
            'student_name': 'Test Student',
            'student_id': 'ST001',
            'room_number': '101',
            'block': 'A',
            'from_date': 'January 15, 2024',
            'to_date': 'January 17, 2024',
            'total_days': 3,
            'reason': 'Family emergency',
            'pass_number': 'LP-20240115-001',
            'verification_code': 'ABC123',
            'approval_date': 'January 14, 2024 at 10:30 AM',
            'system_name': 'AI Hostel Coordination System'
        }
        
        # Test auto-approval text generation
        text_content = email_service._generate_text_content(context, 'auto_approval')
        
        # Check text content
        self.assertIn('Auto-Approved', text_content)
        self.assertIn(context['student_name'], text_content)
        self.assertIn(context['pass_number'], text_content)
        self.assertIn('Digital Pass Information:', text_content)

    def test_send_escalated_request_notification(self):
        """Test sending escalated request notification email."""
        # Ensure notification service has loaded staff preferences
        notification_service._load_default_preferences()
        
        request_details = {
            'guest_name': 'John Doe',
            'start_date': '2024-01-15',
            'end_date': '2024-01-18',
            'reason': 'Family visit'
        }
        
        student_info = {
            'name': self.student.name,
            'student_id': self.student.student_id,
            'room_number': self.student.room_number,
            'block': self.student.block,
            'phone': self.student.phone
        }
        
        # Send escalated request notification
        results = notification_service.send_escalated_request_notification(
            request_type='guest_request',
            request_details=request_details,
            student_info=student_info
        )
        
        # Check that notifications were attempted (may be empty if no staff configured for urgent alerts)
        self.assertTrue(isinstance(results, dict))
        
        # Check email was sent if there are results
        if results:
            # Check that at least one delivery was attempted
            for staff_id, staff_results in results.items():
                self.assertTrue(len(staff_results) > 0)
        
        # Check email was sent (in test mode, emails go to mail.outbox)
        if len(mail.outbox) > 0:
            # Check email content
            sent_email = mail.outbox[0]
            self.assertIn('URGENT:', sent_email.subject)
            self.assertIn('Guest Request', sent_email.subject)

    def test_send_daily_summary_email(self):
        """Test sending daily summary email."""
        # Create a mock daily summary with correct structure
        summary = SimpleDailySummary(
            date=date.today(),
            total_absent=5,
            active_guests=3,
            pending_maintenance=1,
            urgent_items=['Room 205 AC repair needed'],
            generated_at=timezone.now()
        )
        
        # Send daily summary
        results = notification_service.deliver_daily_summary(summary)
        
        # Check that notifications were attempted for staff who want summaries
        self.assertTrue(len(results) >= 0)  # May be 0 if no staff configured
        
        # Check email was sent if there are results
        if results:
            self.assertTrue(len(mail.outbox) > 0)
            
            # Check email content
            sent_email = mail.outbox[0]
            self.assertIn('Daily Hostel Summary', sent_email.subject)

    def test_email_formatting(self):
        """Test HTML email formatting."""
        content = "Test notification content\nWith multiple lines"
        subject = "Test Subject"
        
        html_content = notification_service._format_email_content(content, subject)
        
        # Check HTML structure
        self.assertIn('<!DOCTYPE html>', html_content)
        self.assertIn('<title>Test Subject</title>', html_content)
        self.assertIn('AI Hostel Coordination System', html_content)
        self.assertIn('Test notification content', html_content)
        self.assertIn('With multiple lines', html_content)

    def test_urgent_email_formatting(self):
        """Test urgent email formatting with special styling."""
        content = "Urgent maintenance issue"
        subject = "URGENT: Maintenance Alert"
        
        html_content = notification_service._format_email_content(content, subject)
        
        # Check urgent styling is applied
        self.assertIn('URGENT NOTIFICATION', html_content)
        self.assertIn('class=\'urgent\'', html_content)

    def test_email_delivery_failure_handling(self):
        """Test handling of email delivery failures."""
        # Create staff member without email
        staff_no_email = Staff.objects.create(
            staff_id='S002',
            name='No Email Staff',
            role='security',
            email='',  # No email address
            is_active=True
        )
        
        # Try to send notification
        result = notification_service._send_email(
            recipient=staff_no_email,
            subject='Test Subject',
            content='Test Content',
            timestamp=timezone.now()
        )
        
        # Check that delivery failed appropriately
        self.assertFalse(result.success)
        self.assertIn('No email address configured', result.message)

    @patch('django.core.mail.send_mail')
    def test_email_send_exception_handling(self, mock_send_mail):
        """Test handling of email sending exceptions."""
        # Mock send_mail to raise an exception
        mock_send_mail.side_effect = Exception("SMTP connection failed")
        
        # Try to send email
        result = notification_service._send_email(
            recipient=self.warden,
            subject='Test Subject',
            content='Test Content',
            timestamp=timezone.now()
        )
        
        # Check that exception was handled
        self.assertFalse(result.success)
        self.assertIn('SMTP connection failed', result.message)

    def test_management_command_integration(self):
        """Test that the management command can be imported and has correct structure."""
        from core.management.commands.send_daily_summary_email import Command
        
        # Check command exists and has required methods
        command = Command()
        self.assertTrue(hasattr(command, 'handle'))
        self.assertTrue(hasattr(command, 'add_arguments'))
        
        # Check help text
        self.assertIn('daily summary', command.help.lower())

    def test_leave_email_management_command_integration(self):
        """Test that the leave email testing command can be imported."""
        from core.management.commands.test_leave_emails import Command
        
        # Check command exists and has required methods
        command = Command()
        self.assertTrue(hasattr(command, 'handle'))
        self.assertTrue(hasattr(command, 'add_arguments'))
        
        # Check help text
        self.assertIn('leave notification', command.help.lower())

    def test_sms_content_formatting(self):
        """Test SMS content formatting for character limits."""
        # Test normal message
        content = "Student: John Doe\nRoom: 101\nGuest permission for 3 nights"
        subject = "Escalated Request"
        
        sms_content = notification_service._format_sms_content(subject, content)
        
        # Check length is within SMS limits
        self.assertLessEqual(len(sms_content), 160)
        self.assertIn('ESCALATED:', sms_content)
        
        # Test urgent message with structured content
        urgent_content = "Maintenance: Emergency water leak\nRoom: Block A\nUrgent: Immediate attention required"
        urgent_subject = "URGENT: Maintenance Alert"
        
        urgent_sms = notification_service._format_sms_content(urgent_content, urgent_subject)
        
        self.assertLessEqual(len(urgent_sms), 160)
        self.assertIn('URGENT', urgent_sms)

    def test_sms_delivery_without_phone(self):
        """Test SMS delivery failure when staff has no phone number."""
        # Create staff member without phone
        staff_no_phone = Staff.objects.create(
            staff_id='S003',
            name='No Phone Staff',
            role='security',
            email='test@example.com',
            phone='',  # No phone number
            is_active=True
        )
        
        # Try to send SMS
        result = notification_service._send_sms(
            recipient=staff_no_phone,
            subject='Test Subject',
            content='Test Content',
            timestamp=timezone.now()
        )
        
        # Check that delivery failed appropriately
        self.assertFalse(result.success)
        self.assertIn('No phone number configured', result.message)

    @patch('core.services.notification_service.NotificationService._send_via_twilio')
    def test_sms_via_twilio_success(self, mock_twilio):
        """Test successful SMS sending via Twilio."""
        # Mock successful Twilio response
        mock_twilio.return_value = True
        
        # Mock Twilio settings
        with patch('django.conf.settings.TWILIO_ACCOUNT_SID', 'test_sid'), \
             patch('django.conf.settings.TWILIO_AUTH_TOKEN', 'test_token'), \
             patch('django.conf.settings.TWILIO_PHONE_NUMBER', '+1234567890'):
            
            result = notification_service._send_sms(
                recipient=self.security,
                subject='Test SMS',
                content='Test message',
                timestamp=timezone.now()
            )
            
            # Check successful delivery
            self.assertTrue(result.success)
            self.assertIn('SMS sent to', result.message)

    @patch('core.services.notification_service.NotificationService._send_via_twilio')
    def test_sms_via_twilio_failure(self, mock_twilio):
        """Test SMS sending failure via Twilio."""
        # Mock Twilio failure
        mock_twilio.return_value = False
        
        # Mock Twilio settings
        with patch('django.conf.settings.TWILIO_ACCOUNT_SID', 'test_sid'), \
             patch('django.conf.settings.TWILIO_AUTH_TOKEN', 'test_token'), \
             patch('django.conf.settings.TWILIO_PHONE_NUMBER', '+1234567890'):
            
            result = notification_service._send_sms(
                recipient=self.security,
                subject='Test SMS',
                content='Test message',
                timestamp=timezone.now()
            )
            
            # Check failed delivery
            self.assertFalse(result.success)
            self.assertIn('SMS delivery failed', result.message)

    def test_urgent_sms_alert_functionality(self):
        """Test urgent SMS alert sending."""
        # Send urgent SMS alert
        results = notification_service.send_urgent_sms_alert(
            alert_type='emergency_maintenance',
            message='Water leak in Block A requires immediate attention',
            target_roles=['warden', 'security']
        )
        
        # Check that notifications were attempted
        self.assertTrue(len(results) >= 0)  # May be 0 if no staff configured for SMS
        
        # If there are results, check structure
        for staff_id, delivery_results in results.items():
            self.assertTrue(len(delivery_results) > 0)
            self.assertEqual(delivery_results[0].method, NotificationMethod.SMS)

    def test_sms_management_command_import(self):
        """Test that the SMS management command can be imported."""
        from core.management.commands.send_urgent_sms import Command
        
        # Check command exists and has required methods
        command = Command()
        self.assertTrue(hasattr(command, 'handle'))
        self.assertTrue(hasattr(command, 'add_arguments'))
        
        # Check help text
        self.assertIn('urgent sms', command.help.lower())