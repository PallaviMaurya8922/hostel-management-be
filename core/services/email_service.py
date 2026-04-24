"""
Enhanced Email Service for AI-Powered Hostel Coordination System

This service handles specialized email notifications for leave requests, 
including auto-approval confirmations, warden approval notifications, 
and rejection notifications with PDF attachments.
"""

import logging
import os
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, date
from django.core.mail import EmailMultiAlternatives
from django.conf import settings
from django.template.loader import render_to_string
from django.utils import timezone
from email.mime.application import MIMEApplication

from ..models import Student, Staff, AbsenceRecord, DigitalPass
from .notification_service import notification_service

logger = logging.getLogger(__name__)


class EmailService:
    """Enhanced email service for leave request notifications"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.from_email = getattr(settings, 'EMAIL_HOST_USER', 'noreply@hostel-coordination.com')
    
    def send_auto_approval_email(
        self, 
        student: Student, 
        absence_record: AbsenceRecord, 
        digital_pass: DigitalPass,
        pdf_bytes: Optional[bytes] = None
    ) -> Tuple[bool, str]:
        """
        Send auto-approval confirmation email with digital pass attachment.
        
        Args:
            student: Student who requested leave
            absence_record: The approved absence record
            digital_pass: Generated digital pass
            pdf_bytes: PDF bytes for attachment
            
        Returns:
            Tuple[bool, str]: Success status and message
        """
        try:
            subject = f"Leave Request Auto-Approved - Pass #{digital_pass.pass_number}"
            
            # Prepare email context
            context = {
                'student_name': student.name,
                'student_id': student.student_id,
                'room_number': student.room_number,
                'block': student.block,
                'from_date': digital_pass.from_date.strftime('%B %d, %Y'),
                'to_date': digital_pass.to_date.strftime('%B %d, %Y'),
                'total_days': digital_pass.total_days,
                'reason': digital_pass.reason,
                'pass_number': digital_pass.pass_number,
                'verification_code': digital_pass.verification_code,
                'approval_type': 'Automatic',
                'approval_date': digital_pass.created_at.strftime('%B %d, %Y at %I:%M %p'),
                'system_name': 'AI Hostel Coordination System'
            }
            
            # Generate email content
            html_content = self._render_leave_approval_template(context, 'auto_approval')
            text_content = self._generate_text_content(context, 'auto_approval')
            
            # Create email message
            email = EmailMultiAlternatives(
                subject=subject,
                body=text_content,
                from_email=self.from_email,
                to=[student.email] if student.email else []
            )
            email.attach_alternative(html_content, "text/html")
            
            # Attach PDF if available
            if pdf_bytes:
                email.attach(
                    f"leave_pass_{digital_pass.pass_number}.pdf",
                    pdf_bytes,
                    'application/pdf'
                )
            
            # Send email if student has email address
            if student.email:
                email.send()
                self.logger.info(f"Auto-approval email sent to {student.email} for pass {digital_pass.pass_number}")
                return True, f"Auto-approval email sent to {student.email}"
            else:
                self.logger.warning(f"No email address for student {student.student_id}")
                return False, "Student has no email address configured"
        
        except Exception as e:
            self.logger.error(f"Failed to send auto-approval email for pass {digital_pass.pass_number}: {e}")
            return False, f"Email sending failed: {str(e)}"
    
    def send_warden_approval_email(
        self, 
        student: Student, 
        absence_record: AbsenceRecord, 
        digital_pass: DigitalPass,
        approved_by: Staff,
        pdf_bytes: Optional[bytes] = None
    ) -> Tuple[bool, str]:
        """
        Send warden approval email with digital pass attachment.
        
        Args:
            student: Student who requested leave
            absence_record: The approved absence record
            digital_pass: Generated digital pass
            approved_by: Staff member who approved the request
            pdf_bytes: PDF bytes for attachment
            
        Returns:
            Tuple[bool, str]: Success status and message
        """
        try:
            subject = f"Leave Request Approved by Warden - Pass #{digital_pass.pass_number}"
            
            # Prepare email context
            context = {
                'student_name': student.name,
                'student_id': student.student_id,
                'room_number': student.room_number,
                'block': student.block,
                'from_date': digital_pass.from_date.strftime('%B %d, %Y'),
                'to_date': digital_pass.to_date.strftime('%B %d, %Y'),
                'total_days': digital_pass.total_days,
                'reason': digital_pass.reason,
                'pass_number': digital_pass.pass_number,
                'verification_code': digital_pass.verification_code,
                'approval_type': 'Manual',
                'approved_by': approved_by.name,
                'approved_by_role': approved_by.role.title(),
                'approval_reason': absence_record.approval_reason,
                'approval_date': digital_pass.created_at.strftime('%B %d, %Y at %I:%M %p'),
                'system_name': 'AI Hostel Coordination System'
            }
            
            # Generate email content
            html_content = self._render_leave_approval_template(context, 'warden_approval')
            text_content = self._generate_text_content(context, 'warden_approval')
            
            # Create email message
            email = EmailMultiAlternatives(
                subject=subject,
                body=text_content,
                from_email=self.from_email,
                to=[student.email] if student.email else []
            )
            email.attach_alternative(html_content, "text/html")
            
            # Attach PDF if available
            if pdf_bytes:
                email.attach(
                    f"leave_pass_{digital_pass.pass_number}.pdf",
                    pdf_bytes,
                    'application/pdf'
                )
            
            # Send email if student has email address
            if student.email:
                email.send()
                self.logger.info(f"Warden approval email sent to {student.email} for pass {digital_pass.pass_number}")
                return True, f"Warden approval email sent to {student.email}"
            else:
                self.logger.warning(f"No email address for student {student.student_id}")
                return False, "Student has no email address configured"
        
        except Exception as e:
            self.logger.error(f"Failed to send warden approval email for pass {digital_pass.pass_number}: {e}")
            return False, f"Email sending failed: {str(e)}"
    
    def send_rejection_email(
        self, 
        student: Student, 
        absence_record: AbsenceRecord,
        rejected_by: Staff
    ) -> Tuple[bool, str]:
        """
        Send leave rejection notification email.
        
        Args:
            student: Student who requested leave
            absence_record: The rejected absence record
            rejected_by: Staff member who rejected the request
            
        Returns:
            Tuple[bool, str]: Success status and message
        """
        try:
            subject = f"Leave Request Rejected - {absence_record.start_date.strftime('%B %d, %Y')}"
            
            # Prepare email context
            context = {
                'student_name': student.name,
                'student_id': student.student_id,
                'room_number': student.room_number,
                'block': student.block,
                'from_date': absence_record.start_date.strftime('%B %d, %Y'),
                'to_date': absence_record.end_date.strftime('%B %d, %Y'),
                'total_days': (absence_record.end_date.date() - absence_record.start_date.date()).days + 1,
                'reason': absence_record.reason,
                'rejected_by': rejected_by.name,
                'rejected_by_role': rejected_by.role.title(),
                'rejection_reason': absence_record.approval_reason,
                'rejection_date': timezone.now().strftime('%B %d, %Y at %I:%M %p'),
                'system_name': 'AI Hostel Coordination System'
            }
            
            # Generate email content
            html_content = self._render_leave_rejection_template(context)
            text_content = self._generate_text_content(context, 'rejection')
            
            # Create email message
            email = EmailMultiAlternatives(
                subject=subject,
                body=text_content,
                from_email=self.from_email,
                to=[student.email] if student.email else []
            )
            email.attach_alternative(html_content, "text/html")
            
            # Send email if student has email address
            if student.email:
                email.send()
                self.logger.info(f"Rejection email sent to {student.email} for absence record {absence_record.absence_id}")
                return True, f"Rejection email sent to {student.email}"
            else:
                self.logger.warning(f"No email address for student {student.student_id}")
                return False, "Student has no email address configured"
        
        except Exception as e:
            self.logger.error(f"Failed to send rejection email for absence record {absence_record.absence_id}: {e}")
            return False, f"Email sending failed: {str(e)}"
    
    def send_escalation_email(
        self, 
        student: Student, 
        absence_record: AbsenceRecord,
        target_staff: Optional[List[Staff]] = None
    ) -> Dict[str, Tuple[bool, str]]:
        """
        Send escalation email to wardens for manual review.
        
        Args:
            student: Student who requested leave
            absence_record: The absence record requiring approval
            target_staff: Optional list of specific staff to notify
            
        Returns:
            Dict[str, Tuple[bool, str]]: Results by staff email
        """
        results = {}
        
        try:
            # Get target staff (wardens and admins by default)
            if target_staff is None:
                target_staff = Staff.objects.filter(
                    role__in=['warden', 'admin'],
                    is_active=True,
                    email__isnull=False
                ).exclude(email='')
            
            subject = f"Leave Request Requires Approval - {student.name} ({student.student_id})"
            
            # Prepare email context
            context = {
                'student_name': student.name,
                'student_id': student.student_id,
                'room_number': student.room_number,
                'block': student.block,
                'phone': student.phone,
                'from_date': absence_record.start_date.strftime('%B %d, %Y'),
                'to_date': absence_record.end_date.strftime('%B %d, %Y'),
                'total_days': (absence_record.end_date.date() - absence_record.start_date.date()).days + 1,
                'reason': absence_record.reason,
                'emergency_contact': absence_record.emergency_contact,
                'request_date': absence_record.created_at.strftime('%B %d, %Y at %I:%M %p'),
                'system_name': 'AI Hostel Coordination System',
                'dashboard_url': f"{getattr(settings, 'SITE_URL', 'http://localhost:8000')}/staff/dashboard/"
            }
            
            # Generate email content
            html_content = self._render_escalation_template(context)
            text_content = self._generate_text_content(context, 'escalation')
            
            # Send to each staff member
            for staff in target_staff:
                try:
                    email = EmailMultiAlternatives(
                        subject=subject,
                        body=text_content,
                        from_email=self.from_email,
                        to=[staff.email]
                    )
                    email.attach_alternative(html_content, "text/html")
                    email.send()
                    
                    results[staff.email] = (True, "Escalation email sent successfully")
                    self.logger.info(f"Escalation email sent to {staff.email} for absence record {absence_record.absence_id}")
                
                except Exception as e:
                    results[staff.email] = (False, f"Failed to send: {str(e)}")
                    self.logger.error(f"Failed to send escalation email to {staff.email}: {e}")
        
        except Exception as e:
            self.logger.error(f"Failed to send escalation emails for absence record {absence_record.absence_id}: {e}")
            results['error'] = (False, f"General error: {str(e)}")
        
        return results
    
    def send_guest_approval_email(
        self,
        student: Student,
        guest_request,
        approved_by: Staff
    ) -> Tuple[bool, str]:
        """
        Send guest approval confirmation email to student.
        
        Args:
            student: Student who requested guest
            guest_request: The approved guest request
            approved_by: Staff member who approved the request
            
        Returns:
            Tuple[bool, str]: Success status and message
        """
        try:
            subject = f"Guest Request Approved - {guest_request.guest_name}"
            
            # Prepare email context
            context = {
                'student_name': student.name,
                'student_id': student.student_id,
                'room_number': student.room_number,
                'block': student.block,
                'guest_name': guest_request.guest_name,
                'guest_phone': guest_request.guest_phone or 'Not provided',
                'start_date': guest_request.start_date.strftime('%B %d, %Y at %I:%M %p'),
                'end_date': guest_request.end_date.strftime('%B %d, %Y at %I:%M %p'),
                'purpose': guest_request.purpose or 'Not specified',
                'approved_by': approved_by.name,
                'approved_by_role': approved_by.role.title(),
                'approval_reason': guest_request.approval_reason or 'Request approved',
                'approval_date': timezone.now().strftime('%B %d, %Y at %I:%M %p'),
                'system_name': 'AI Hostel Coordination System'
            }
            
            # Generate email content
            html_content = self._generate_guest_approval_html(context)
            text_content = self._generate_guest_approval_text(context)
            
            # Create email message
            email = EmailMultiAlternatives(
                subject=subject,
                body=text_content,
                from_email=self.from_email,
                to=[student.email] if student.email else []
            )
            email.attach_alternative(html_content, "text/html")
            
            # Send email if student has email address
            if student.email:
                email.send()
                self.logger.info(f"Guest approval email sent to {student.email} for guest {guest_request.guest_name}")
                return True, f"Guest approval email sent to {student.email}"
            else:
                self.logger.warning(f"No email address for student {student.student_id}")
                return False, "Student has no email address configured"
        
        except Exception as e:
            self.logger.error(f"Failed to send guest approval email: {e}")
            return False, f"Email sending failed: {str(e)}"
    
    def _render_leave_approval_template(self, context: Dict[str, Any], approval_type: str) -> str:
        """Render HTML template for leave approval emails"""
        template_name = f"emails/leave_{approval_type}.html"
        
        # If template doesn't exist, use inline HTML
        try:
            return render_to_string(template_name, context)
        except:
            return self._generate_approval_html(context, approval_type)
    
    def _render_leave_rejection_template(self, context: Dict[str, Any]) -> str:
        """Render HTML template for leave rejection emails"""
        template_name = "emails/leave_rejection.html"
        
        # If template doesn't exist, use inline HTML
        try:
            return render_to_string(template_name, context)
        except:
            return self._generate_rejection_html(context)
    
    def _render_escalation_template(self, context: Dict[str, Any]) -> str:
        """Render HTML template for escalation emails"""
        template_name = "emails/leave_escalation.html"
        
        # If template doesn't exist, use inline HTML
        try:
            return render_to_string(template_name, context)
        except:
            return self._generate_escalation_html(context)
    
    def _generate_approval_html(self, context: Dict[str, Any], approval_type: str) -> str:
        """Generate HTML content for approval emails"""
        approval_title = "Auto-Approved" if approval_type == 'auto_approval' else "Approved by Warden"
        approval_color = "#28a745" if approval_type == 'auto_approval' else "#007bff"
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <title>Leave Request {approval_title}</title>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    line-height: 1.6;
                    color: #333;
                    max-width: 600px;
                    margin: 0 auto;
                    padding: 20px;
                }}
                .header {{
                    background-color: {approval_color};
                    color: white;
                    padding: 20px;
                    text-align: center;
                    border-radius: 5px 5px 0 0;
                }}
                .content {{
                    background-color: #f8f9fa;
                    padding: 20px;
                    border: 1px solid #dee2e6;
                }}
                .success-badge {{
                    background-color: #d4edda;
                    color: #155724;
                    padding: 10px;
                    border-radius: 5px;
                    margin-bottom: 20px;
                    text-align: center;
                    font-weight: bold;
                }}
                .details-section {{
                    background-color: white;
                    padding: 15px;
                    border-left: 4px solid {approval_color};
                    margin-bottom: 15px;
                }}
                .pass-info {{
                    background-color: #e3f2fd;
                    padding: 15px;
                    border-radius: 5px;
                    margin: 15px 0;
                }}
                .footer {{
                    background-color: #e9ecef;
                    padding: 15px;
                    border-radius: 0 0 5px 5px;
                    font-size: 12px;
                    color: #6c757d;
                    text-align: center;
                }}
                .important {{
                    color: #dc3545;
                    font-weight: bold;
                }}
            </style>
        </head>
        <body>
            <div class="header">
                <h2>{context['system_name']}</h2>
                <h3>Leave Request {approval_title}</h3>
            </div>
            <div class="content">
                <div class="success-badge">
                    ✅ Your leave request has been {approval_title.lower()}!
                </div>
                
                <div class="details-section">
                    <h4>Student Information</h4>
                    <p><strong>Name:</strong> {context['student_name']}</p>
                    <p><strong>Student ID:</strong> {context['student_id']}</p>
                    <p><strong>Room:</strong> {context['room_number']} - Block {context['block']}</p>
                </div>
                
                <div class="details-section">
                    <h4>Leave Details</h4>
                    <p><strong>From:</strong> {context['from_date']}</p>
                    <p><strong>To:</strong> {context['to_date']}</p>
                    <p><strong>Duration:</strong> {context['total_days']} day(s)</p>
                    <p><strong>Reason:</strong> {context['reason']}</p>
                </div>
                
                <div class="pass-info">
                    <h4>🎫 Digital Pass Information</h4>
                    <p><strong>Pass Number:</strong> {context['pass_number']}</p>
                    <p><strong>Verification Code:</strong> {context['verification_code']}</p>
                    <p><strong>Approved:</strong> {context['approval_date']}</p>
                    {f"<p><strong>Approved By:</strong> {context.get('approved_by', 'System')} ({context.get('approved_by_role', 'Auto-Approval')})</p>" if approval_type == 'warden_approval' else ""}
                </div>
                
                <div class="details-section">
                    <h4>Important Instructions</h4>
                    <ul>
                        <li>Your digital pass is attached to this email as a PDF</li>
                        <li>Present this pass to security when leaving the hostel</li>
                        <li>Keep the pass number and verification code safe</li>
                        <li class="important">Return to the hostel by {context['to_date']} as specified</li>
                        <li>Contact the warden if you need to extend your leave</li>
                    </ul>
                </div>
            </div>
            <div class="footer">
                <p>This is an automated notification from the {context['system_name']}.</p>
                <p>Generated at: {timezone.now().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
            </div>
        </body>
        </html>
        """
        return html
    
    def _generate_rejection_html(self, context: Dict[str, Any]) -> str:
        """Generate HTML content for rejection emails"""
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <title>Leave Request Rejected</title>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    line-height: 1.6;
                    color: #333;
                    max-width: 600px;
                    margin: 0 auto;
                    padding: 20px;
                }}
                .header {{
                    background-color: #dc3545;
                    color: white;
                    padding: 20px;
                    text-align: center;
                    border-radius: 5px 5px 0 0;
                }}
                .content {{
                    background-color: #f8f9fa;
                    padding: 20px;
                    border: 1px solid #dee2e6;
                }}
                .rejection-badge {{
                    background-color: #f8d7da;
                    color: #721c24;
                    padding: 10px;
                    border-radius: 5px;
                    margin-bottom: 20px;
                    text-align: center;
                    font-weight: bold;
                }}
                .details-section {{
                    background-color: white;
                    padding: 15px;
                    border-left: 4px solid #dc3545;
                    margin-bottom: 15px;
                }}
                .reason-section {{
                    background-color: #fff3cd;
                    padding: 15px;
                    border-radius: 5px;
                    margin: 15px 0;
                    border-left: 4px solid #ffc107;
                }}
                .footer {{
                    background-color: #e9ecef;
                    padding: 15px;
                    border-radius: 0 0 5px 5px;
                    font-size: 12px;
                    color: #6c757d;
                    text-align: center;
                }}
            </style>
        </head>
        <body>
            <div class="header">
                <h2>{context['system_name']}</h2>
                <h3>Leave Request Rejected</h3>
            </div>
            <div class="content">
                <div class="rejection-badge">
                    ❌ Your leave request has been rejected
                </div>
                
                <div class="details-section">
                    <h4>Student Information</h4>
                    <p><strong>Name:</strong> {context['student_name']}</p>
                    <p><strong>Student ID:</strong> {context['student_id']}</p>
                    <p><strong>Room:</strong> {context['room_number']} - Block {context['block']}</p>
                </div>
                
                <div class="details-section">
                    <h4>Rejected Leave Details</h4>
                    <p><strong>From:</strong> {context['from_date']}</p>
                    <p><strong>To:</strong> {context['to_date']}</p>
                    <p><strong>Duration:</strong> {context['total_days']} day(s)</p>
                    <p><strong>Reason:</strong> {context['reason']}</p>
                </div>
                
                <div class="reason-section">
                    <h4>Rejection Details</h4>
                    <p><strong>Rejected By:</strong> {context['rejected_by']} ({context['rejected_by_role']})</p>
                    <p><strong>Rejection Date:</strong> {context['rejection_date']}</p>
                    <p><strong>Reason for Rejection:</strong></p>
                    <p style="font-style: italic; margin-left: 20px;">{context['rejection_reason']}</p>
                </div>
                
                <div class="details-section">
                    <h4>Next Steps</h4>
                    <ul>
                        <li>Review the rejection reason above</li>
                        <li>Address any concerns mentioned in the rejection</li>
                        <li>You may submit a new leave request if needed</li>
                        <li>Contact the warden if you have questions about this decision</li>
                    </ul>
                </div>
            </div>
            <div class="footer">
                <p>This is an automated notification from the {context['system_name']}.</p>
                <p>Generated at: {timezone.now().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
            </div>
        </body>
        </html>
        """
        return html
    
    def _generate_escalation_html(self, context: Dict[str, Any]) -> str:
        """Generate HTML content for escalation emails"""
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <title>Leave Request Requires Approval</title>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    line-height: 1.6;
                    color: #333;
                    max-width: 600px;
                    margin: 0 auto;
                    padding: 20px;
                }}
                .header {{
                    background-color: #ffc107;
                    color: #212529;
                    padding: 20px;
                    text-align: center;
                    border-radius: 5px 5px 0 0;
                }}
                .content {{
                    background-color: #f8f9fa;
                    padding: 20px;
                    border: 1px solid #dee2e6;
                }}
                .alert-badge {{
                    background-color: #fff3cd;
                    color: #856404;
                    padding: 10px;
                    border-radius: 5px;
                    margin-bottom: 20px;
                    text-align: center;
                    font-weight: bold;
                }}
                .details-section {{
                    background-color: white;
                    padding: 15px;
                    border-left: 4px solid #ffc107;
                    margin-bottom: 15px;
                }}
                .action-section {{
                    background-color: #e3f2fd;
                    padding: 15px;
                    border-radius: 5px;
                    margin: 15px 0;
                }}
                .footer {{
                    background-color: #e9ecef;
                    padding: 15px;
                    border-radius: 0 0 5px 5px;
                    font-size: 12px;
                    color: #6c757d;
                    text-align: center;
                }}
                .btn {{
                    display: inline-block;
                    padding: 10px 20px;
                    background-color: #007bff;
                    color: white;
                    text-decoration: none;
                    border-radius: 5px;
                    margin: 5px;
                }}
            </style>
        </head>
        <body>
            <div class="header">
                <h2>{context['system_name']}</h2>
                <h3>Leave Request Requires Manual Approval</h3>
            </div>
            <div class="content">
                <div class="alert-badge">
                    ⚠️ A leave request requires your review and approval
                </div>
                
                <div class="details-section">
                    <h4>Student Information</h4>
                    <p><strong>Name:</strong> {context['student_name']}</p>
                    <p><strong>Student ID:</strong> {context['student_id']}</p>
                    <p><strong>Room:</strong> {context['room_number']} - Block {context['block']}</p>
                    <p><strong>Phone:</strong> {context['phone']}</p>
                </div>
                
                <div class="details-section">
                    <h4>Leave Request Details</h4>
                    <p><strong>From:</strong> {context['from_date']}</p>
                    <p><strong>To:</strong> {context['to_date']}</p>
                    <p><strong>Duration:</strong> {context['total_days']} day(s)</p>
                    <p><strong>Reason:</strong> {context['reason']}</p>
                    {f"<p><strong>Emergency Contact:</strong> {context['emergency_contact']}</p>" if context.get('emergency_contact') else ""}
                    <p><strong>Request Submitted:</strong> {context['request_date']}</p>
                </div>
                
                <div class="action-section">
                    <h4>Action Required</h4>
                    <p>This leave request exceeds the auto-approval criteria and requires manual review.</p>
                    <p>Please log in to the staff dashboard to approve or reject this request:</p>
                    <p style="text-align: center;">
                        <a href="{context['dashboard_url']}" class="btn">Open Staff Dashboard</a>
                    </p>
                </div>
                
                <div class="details-section">
                    <h4>Review Guidelines</h4>
                    <ul>
                        <li>Verify the student's reason for leave</li>
                        <li>Check for any recent violations or issues</li>
                        <li>Consider the duration and timing of the request</li>
                        <li>Approve or reject with appropriate reasoning</li>
                        <li>The student will be automatically notified of your decision</li>
                    </ul>
                </div>
            </div>
            <div class="footer">
                <p>This is an automated notification from the {context['system_name']}.</p>
                <p>Generated at: {timezone.now().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
            </div>
        </body>
        </html>
        """
        return html
    
    def _generate_text_content(self, context: Dict[str, Any], email_type: str) -> str:
        """Generate plain text content for emails"""
        if email_type in ['auto_approval', 'warden_approval']:
            approval_type = "Auto-Approved" if email_type == 'auto_approval' else "Approved by Warden"
            return f"""
{context['system_name']}
Leave Request {approval_type}

Dear {context['student_name']},

Your leave request has been {approval_type.lower()}!

Student Information:
- Name: {context['student_name']}
- Student ID: {context['student_id']}
- Room: {context['room_number']} - Block {context['block']}

Leave Details:
- From: {context['from_date']}
- To: {context['to_date']}
- Duration: {context['total_days']} day(s)
- Reason: {context['reason']}

Digital Pass Information:
- Pass Number: {context['pass_number']}
- Verification Code: {context['verification_code']}
- Approved: {context['approval_date']}
{f"- Approved By: {context.get('approved_by', 'System')} ({context.get('approved_by_role', 'Auto-Approval')})" if email_type == 'warden_approval' else ""}

Important Instructions:
- Your digital pass is attached to this email as a PDF
- Present this pass to security when leaving the hostel
- Keep the pass number and verification code safe
- Return to the hostel by {context['to_date']} as specified
- Contact the warden if you need to extend your leave

This is an automated notification from the {context['system_name']}.
Generated at: {timezone.now().strftime('%Y-%m-%d %H:%M:%S UTC')}
            """
        
        elif email_type == 'rejection':
            return f"""
{context['system_name']}
Leave Request Rejected

Dear {context['student_name']},

Your leave request has been rejected.

Student Information:
- Name: {context['student_name']}
- Student ID: {context['student_id']}
- Room: {context['room_number']} - Block {context['block']}

Rejected Leave Details:
- From: {context['from_date']}
- To: {context['to_date']}
- Duration: {context['total_days']} day(s)
- Reason: {context['reason']}

Rejection Details:
- Rejected By: {context['rejected_by']} ({context['rejected_by_role']})
- Rejection Date: {context['rejection_date']}
- Reason for Rejection: {context['rejection_reason']}

Next Steps:
- Review the rejection reason above
- Address any concerns mentioned in the rejection
- You may submit a new leave request if needed
- Contact the warden if you have questions about this decision

This is an automated notification from the {context['system_name']}.
Generated at: {timezone.now().strftime('%Y-%m-%d %H:%M:%S UTC')}
            """
        
        elif email_type == 'escalation':
            return f"""
{context['system_name']}
Leave Request Requires Manual Approval

A leave request requires your review and approval.

Student Information:
- Name: {context['student_name']}
- Student ID: {context['student_id']}
- Room: {context['room_number']} - Block {context['block']}
- Phone: {context['phone']}

Leave Request Details:
- From: {context['from_date']}
- To: {context['to_date']}
- Duration: {context['total_days']} day(s)
- Reason: {context['reason']}
{f"- Emergency Contact: {context['emergency_contact']}" if context.get('emergency_contact') else ""}
- Request Submitted: {context['request_date']}

Action Required:
This leave request exceeds the auto-approval criteria and requires manual review.
Please log in to the staff dashboard to approve or reject this request:
{context['dashboard_url']}

Review Guidelines:
- Verify the student's reason for leave
- Check for any recent violations or issues
- Consider the duration and timing of the request
- Approve or reject with appropriate reasoning
- The student will be automatically notified of your decision

This is an automated notification from the {context['system_name']}.
Generated at: {timezone.now().strftime('%Y-%m-%d %H:%M:%S UTC')}
            """
        
        return "Email content not available."
    
    def _generate_guest_approval_html(self, context: Dict[str, Any]) -> str:
        """Generate HTML content for guest approval emails"""
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <title>Guest Request Approved</title>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    line-height: 1.6;
                    color: #333;
                    max-width: 600px;
                    margin: 0 auto;
                    padding: 20px;
                }}
                .header {{
                    background-color: #17a2b8;
                    color: white;
                    padding: 20px;
                    text-align: center;
                    border-radius: 5px 5px 0 0;
                }}
                .content {{
                    background-color: #f8f9fa;
                    padding: 20px;
                    border: 1px solid #dee2e6;
                }}
                .success-badge {{
                    background-color: #d4edda;
                    color: #155724;
                    padding: 10px;
                    border-radius: 5px;
                    margin-bottom: 20px;
                    text-align: center;
                    font-weight: bold;
                }}
                .details-section {{
                    background-color: white;
                    padding: 15px;
                    border-left: 4px solid #17a2b8;
                    margin-bottom: 15px;
                }}
                .guest-info {{
                    background-color: #d1ecf1;
                    padding: 15px;
                    border-radius: 5px;
                    margin: 15px 0;
                }}
                .footer {{
                    background-color: #e9ecef;
                    padding: 15px;
                    border-radius: 0 0 5px 5px;
                    font-size: 12px;
                    color: #6c757d;
                    text-align: center;
                }}
                .important {{
                    color: #dc3545;
                    font-weight: bold;
                }}
            </style>
        </head>
        <body>
            <div class="header">
                <h2>{context['system_name']}</h2>
                <h3>Guest Request Approved</h3>
            </div>
            <div class="content">
                <div class="success-badge">
                    ✅ Your guest request has been approved!
                </div>
                
                <div class="details-section">
                    <h4>Student Information</h4>
                    <p><strong>Name:</strong> {context['student_name']}</p>
                    <p><strong>Student ID:</strong> {context['student_id']}</p>
                    <p><strong>Room:</strong> {context['room_number']} - Block {context['block']}</p>
                </div>
                
                <div class="guest-info">
                    <h4>👥 Guest Details</h4>
                    <p><strong>Guest Name:</strong> {context['guest_name']}</p>
                    <p><strong>Guest Phone:</strong> {context['guest_phone']}</p>
                    <p><strong>Purpose:</strong> {context['purpose']}</p>
                </div>
                
                <div class="details-section">
                    <h4>Approval Details</h4>
                    <p><strong>Check-in Date & Time:</strong> {context['start_date']}</p>
                    <p><strong>Check-out Date & Time:</strong> {context['end_date']}</p>
                    <p><strong>Approved By:</strong> {context['approved_by']} ({context['approved_by_role']})</p>
                    <p><strong>Reason:</strong> {context['approval_reason']}</p>
                    <p><strong>Approval Date:</strong> {context['approval_date']}</p>
                </div>
                
                <div class="details-section">
                    <h4>Important Instructions</h4>
                    <ul>
                        <li>Ensure your guest checks in at security with valid ID</li>
                        <li>Your guest must follow hostel rules and regulations</li>
                        <li class="important">Check-out deadline: {context['end_date']}</li>
                        <li>Guest visitors are subject to hostel curfew rules</li>
                        <li>If your guest needs to stay longer, request an extension before the deadline</li>
                        <li>Contact the warden if there are any issues</li>
                    </ul>
                </div>
            </div>
            <div class="footer">
                <p>This is an automated notification from the {context['system_name']}.</p>
                <p>Generated at: {timezone.now().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
            </div>
        </body>
        </html>
        """
        return html
    
    def _generate_guest_approval_text(self, context: Dict[str, Any]) -> str:
        """Generate plain text content for guest approval emails"""
        return f"""
{context['system_name']}
Guest Request Approved

Dear {context['student_name']},

Your guest request has been approved!

Student Information:
- Name: {context['student_name']}
- Student ID: {context['student_id']}
- Room: {context['room_number']} - Block {context['block']}

Guest Details:
- Guest Name: {context['guest_name']}
- Guest Phone: {context['guest_phone']}
- Purpose: {context['purpose']}

Approval Details:
- Check-in Date & Time: {context['start_date']}
- Check-out Date & Time: {context['end_date']}
- Approved By: {context['approved_by']} ({context['approved_by_role']})
- Reason: {context['approval_reason']}
- Approval Date: {context['approval_date']}

Important Instructions:
- Ensure your guest checks in at security with valid ID
- Your guest must follow hostel rules and regulations
- Check-out deadline: {context['end_date']}
- Guest visitors are subject to hostel curfew rules
- If your guest needs to stay longer, request an extension before the deadline
- Contact the warden if there are any issues

This is an automated notification from the {context['system_name']}.
Generated at: {timezone.now().strftime('%Y-%m-%d %H:%M:%S UTC')}
        """


# Global service instance
email_service = EmailService()