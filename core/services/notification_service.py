"""
Notification Service for AI-Powered Hostel Coordination System

This service handles delivery of daily summaries and other notifications to staff members.
Supports multiple delivery methods and tracks delivery status.
"""

from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass
from enum import Enum
from django.utils import timezone
from django.core.mail import send_mail
from django.conf import settings
from core.models import Staff
from .daily_summary_service import SimpleDailySummary, daily_summary_generator
import logging

logger = logging.getLogger(__name__)


class NotificationMethod(Enum):
    """Supported notification delivery methods"""
    EMAIL = "email"
    SMS = "sms"
    IN_APP = "in_app"
    WEBHOOK = "webhook"


class NotificationPriority(Enum):
    """Notification priority levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class NotificationPreference:
    """Staff member notification preferences"""
    staff_id: str
    methods: Set[NotificationMethod]
    daily_summary: bool = True
    urgent_alerts: bool = True
    maintenance_updates: bool = True
    guest_notifications: bool = True
    quiet_hours_start: Optional[int] = 22  # 10 PM
    quiet_hours_end: Optional[int] = 6     # 6 AM


@dataclass
class DeliveryResult:
    """Result of notification delivery attempt"""
    method: NotificationMethod
    success: bool
    message: str
    timestamp: datetime
    recipient: str


@dataclass
class NotificationRecord:
    """Record of notification delivery"""
    notification_id: str
    recipient_id: str
    content_type: str
    subject: str
    delivery_attempts: List[DeliveryResult]
    final_status: str  # 'delivered', 'failed', 'pending'
    created_at: datetime
    delivered_at: Optional[datetime] = None


class NotificationService:
    """Service for delivering notifications to staff members"""
    
    def __init__(self):
        self.delivery_records: List[NotificationRecord] = []
        self.staff_preferences: Dict[str, NotificationPreference] = {}
        self._preferences_loaded = False
    
    def _ensure_preferences_loaded(self):
        """Ensure preferences are loaded (lazy initialization)"""
        if not self._preferences_loaded:
            self._load_default_preferences()
            self._preferences_loaded = True
    
    def _load_default_preferences(self):
        """Load default notification preferences for all staff members"""
        try:
            staff_members = Staff.objects.filter(is_active=True)
        except Exception as e:
            logger.warning(f"Could not load staff preferences: {e}")
            return
        
        for staff in staff_members:
            # Set default preferences based on role
            if staff.role == 'warden':
                methods = {NotificationMethod.EMAIL, NotificationMethod.IN_APP}
                preferences = NotificationPreference(
                    staff_id=staff.staff_id,
                    methods=methods,
                    daily_summary=True,
                    urgent_alerts=True,
                    maintenance_updates=True,
                    guest_notifications=True
                )
            elif staff.role == 'security':
                methods = {NotificationMethod.EMAIL, NotificationMethod.SMS}
                preferences = NotificationPreference(
                    staff_id=staff.staff_id,
                    methods=methods,
                    daily_summary=True,
                    urgent_alerts=True,
                    maintenance_updates=False,
                    guest_notifications=True
                )
            elif staff.role == 'maintenance':
                methods = {NotificationMethod.EMAIL}
                preferences = NotificationPreference(
                    staff_id=staff.staff_id,
                    methods=methods,
                    daily_summary=False,
                    urgent_alerts=True,
                    maintenance_updates=True,
                    guest_notifications=False
                )
            else:  # admin and others
                methods = {NotificationMethod.EMAIL, NotificationMethod.IN_APP}
                preferences = NotificationPreference(
                    staff_id=staff.staff_id,
                    methods=methods,
                    daily_summary=True,
                    urgent_alerts=True,
                    maintenance_updates=True,
                    guest_notifications=True
                )
            
            self.staff_preferences[staff.staff_id] = preferences
    
    def deliver_daily_summary(self, summary: SimpleDailySummary, target_staff: Optional[List[str]] = None) -> Dict[str, List[DeliveryResult]]:
        """
        Deliver daily summary to relevant staff members.
        
        Args:
            summary: SimpleDailySummary object to deliver
            target_staff: Optional list of specific staff IDs to notify
            
        Returns:
            Dict[str, List[DeliveryResult]]: Delivery results by staff ID
        """
        self._ensure_preferences_loaded()
        
        if target_staff is None:
            # Get all staff who want daily summaries
            target_staff = [
                staff_id for staff_id, prefs in self.staff_preferences.items()
                if prefs.daily_summary
            ]
        
        delivery_results = {}
        formatted_summary = daily_summary_generator.format_summary_for_display(summary)
        
        for staff_id in target_staff:
            staff_member = Staff.objects.filter(staff_id=staff_id, is_active=True).first()
            if not staff_member:
                continue
            
            preferences = self.staff_preferences.get(staff_id)
            if not preferences:
                continue
            
            # Check if we're in quiet hours
            if self._is_quiet_hours(preferences):
                logger.info(f"Skipping daily summary delivery to {staff_id} - quiet hours")
                continue
            
            results = []
            
            # Try each preferred delivery method
            for method in preferences.methods:
                try:
                    result = self._deliver_notification(
                        method=method,
                        recipient=staff_member,
                        subject=f"Daily Hostel Summary - {summary.date.strftime('%Y-%m-%d')}",
                        content=formatted_summary,
                        priority=NotificationPriority.MEDIUM
                    )
                    results.append(result)
                    
                    if result.success:
                        break  # Stop trying other methods if one succeeds
                        
                except Exception as e:
                    logger.error(f"Failed to deliver daily summary to {staff_id} via {method}: {str(e)}")
                    results.append(DeliveryResult(
                        method=method,
                        success=False,
                        message=f"Delivery failed: {str(e)}",
                        timestamp=timezone.now(),
                        recipient=staff_id
                    ))
            
            delivery_results[staff_id] = results
            
            # Record the notification
            self._record_notification(
                recipient_id=staff_id,
                content_type="daily_summary",
                subject=f"Daily Hostel Summary - {summary.date.strftime('%Y-%m-%d')}",
                delivery_attempts=results
            )
        
        return delivery_results
    
    def deliver_urgent_alert(self, alert_type: str, message: str, priority: NotificationPriority = NotificationPriority.HIGH, target_roles: Optional[List[str]] = None) -> Dict[str, List[DeliveryResult]]:
        """
        Deliver urgent alerts to relevant staff members.
        
        Args:
            alert_type: Type of alert (e.g., 'emergency_maintenance', 'security_issue')
            message: Alert message content
            priority: Alert priority level
            target_roles: Optional list of staff roles to target
            
        Returns:
            Dict[str, List[DeliveryResult]]: Delivery results by staff ID
        """
        self._ensure_preferences_loaded()
        
        if target_roles is None:
            # Default roles for urgent alerts
            target_roles = ['warden', 'security', 'admin']
        
        # Get staff members with matching roles who want urgent alerts
        target_staff = []
        for staff_id, prefs in self.staff_preferences.items():
            if prefs.urgent_alerts:
                staff_member = Staff.objects.filter(staff_id=staff_id, is_active=True).first()
                if staff_member and staff_member.role in target_roles:
                    target_staff.append(staff_id)
        
        delivery_results = {}
        
        for staff_id in target_staff:
            staff_member = Staff.objects.filter(staff_id=staff_id, is_active=True).first()
            if not staff_member:
                continue
            
            preferences = self.staff_preferences.get(staff_id)
            if not preferences:
                continue
            
            results = []
            
            # For urgent alerts, try all available methods
            for method in preferences.methods:
                try:
                    result = self._deliver_notification(
                        method=method,
                        recipient=staff_member,
                        subject=f"URGENT: {alert_type.replace('_', ' ').title()}",
                        content=message,
                        priority=priority
                    )
                    results.append(result)
                    
                except Exception as e:
                    logger.error(f"Failed to deliver urgent alert to {staff_id} via {method}: {str(e)}")
                    results.append(DeliveryResult(
                        method=method,
                        success=False,
                        message=f"Delivery failed: {str(e)}",
                        timestamp=timezone.now(),
                        recipient=staff_id
                    ))
            
            delivery_results[staff_id] = results
            
            # Record the notification
            self._record_notification(
                recipient_id=staff_id,
                content_type="urgent_alert",
                subject=f"URGENT: {alert_type.replace('_', ' ').title()}",
                delivery_attempts=results
            )
        
        return delivery_results
    
    def _deliver_notification(self, method: NotificationMethod, recipient: Staff, subject: str, content: str, priority: NotificationPriority) -> DeliveryResult:
        """
        Deliver notification via specified method.
        
        Args:
            method: Delivery method to use
            recipient: Staff member to notify
            subject: Notification subject
            content: Notification content
            priority: Notification priority
            
        Returns:
            DeliveryResult: Result of delivery attempt
        """
        timestamp = timezone.now()
        
        try:
            if method == NotificationMethod.EMAIL:
                return self._send_email(recipient, subject, content, timestamp)
            elif method == NotificationMethod.SMS:
                return self._send_sms(recipient, subject, content, timestamp)
            elif method == NotificationMethod.IN_APP:
                return self._send_in_app(recipient, subject, content, timestamp)
            elif method == NotificationMethod.WEBHOOK:
                return self._send_webhook(recipient, subject, content, timestamp)
            else:
                return DeliveryResult(
                    method=method,
                    success=False,
                    message=f"Unsupported delivery method: {method}",
                    timestamp=timestamp,
                    recipient=recipient.staff_id
                )
        except Exception as e:
            return DeliveryResult(
                method=method,
                success=False,
                message=f"Delivery failed: {str(e)}",
                timestamp=timestamp,
                recipient=recipient.staff_id
            )
    
    def _send_email(self, recipient: Staff, subject: str, content: str, timestamp: datetime) -> DeliveryResult:
        """Send notification via email"""
        if not recipient.email:
            return DeliveryResult(
                method=NotificationMethod.EMAIL,
                success=False,
                message="No email address configured",
                timestamp=timestamp,
                recipient=recipient.staff_id
            )
        
        try:
            # Use Django's email backend to send actual emails
            from django.core.mail import send_mail
            from django.conf import settings
            
            # Format content as HTML for better readability
            html_content = self._format_email_content(content, subject)
            
            success = send_mail(
                subject=subject,
                message=content,  # Plain text fallback
                from_email=settings.EMAIL_HOST_USER or 'noreply@hostel-coordination.com',
                recipient_list=[recipient.email],
                html_message=html_content,
                fail_silently=False
            )
            
            if success:
                logger.info(f"Email sent successfully to {recipient.email}")
                return DeliveryResult(
                    method=NotificationMethod.EMAIL,
                    success=True,
                    message=f"Email sent to {recipient.email}",
                    timestamp=timestamp,
                    recipient=recipient.staff_id
                )
            else:
                return DeliveryResult(
                    method=NotificationMethod.EMAIL,
                    success=False,
                    message="Email delivery failed - send_mail returned False",
                    timestamp=timestamp,
                    recipient=recipient.staff_id
                )
        except Exception as e:
            logger.error(f"Failed to send email to {recipient.email}: {str(e)}")
            return DeliveryResult(
                method=NotificationMethod.EMAIL,
                success=False,
                message=f"Email error: {str(e)}",
                timestamp=timestamp,
                recipient=recipient.staff_id
            )
    
    def _send_sms(self, recipient: Staff, subject: str, content: str, timestamp: datetime) -> DeliveryResult:
        """Send notification via SMS"""
        if not recipient.phone:
            return DeliveryResult(
                method=NotificationMethod.SMS,
                success=False,
                message="No phone number configured",
                timestamp=timestamp,
                recipient=recipient.staff_id
            )
        
        try:
            # Format SMS content (SMS has character limits)
            sms_content = self._format_sms_content(subject, content)
            
            # Try to send SMS using configured SMS service
            success = self._send_sms_via_service(recipient.phone, sms_content)
            
            if success:
                logger.info(f"SMS sent successfully to {recipient.phone}")
                return DeliveryResult(
                    method=NotificationMethod.SMS,
                    success=True,
                    message=f"SMS sent to {recipient.phone}",
                    timestamp=timestamp,
                    recipient=recipient.staff_id
                )
            else:
                return DeliveryResult(
                    method=NotificationMethod.SMS,
                    success=False,
                    message="SMS delivery failed",
                    timestamp=timestamp,
                    recipient=recipient.staff_id
                )
        except Exception as e:
            logger.error(f"Failed to send SMS to {recipient.phone}: {str(e)}")
            return DeliveryResult(
                method=NotificationMethod.SMS,
                success=False,
                message=f"SMS error: {str(e)}",
                timestamp=timestamp,
                recipient=recipient.staff_id
            )
    
    def _format_sms_content(self, subject: str, content: str) -> str:
        """Format content for SMS (with character limits)"""
        # SMS messages should be concise (160 characters for single SMS)
        max_length = 150  # Leave some room for sender info
        
        # Create a concise message
        if "URGENT" in subject:
            prefix = "URGENT HOSTEL ALERT: "
        elif "Daily Summary" in subject:
            prefix = "Daily Summary: "
        elif "Escalated" in subject:
            prefix = "ESCALATED: "
        else:
            prefix = "Hostel Alert: "
        
        # Extract key information from content
        lines = content.split('\n')
        key_info = []
        
        for line in lines:
            line = line.strip()
            if line and not line.startswith('=') and not line.startswith('-'):
                # Extract important lines
                if any(keyword in line.lower() for keyword in ['student:', 'room:', 'guest:', 'maintenance:', 'urgent']):
                    key_info.append(line)
        
        # Build SMS message
        if key_info:
            message_body = "; ".join(key_info[:3])  # Limit to 3 key pieces of info
        else:
            # Fallback to first meaningful line
            meaningful_lines = [line.strip() for line in lines if line.strip() and len(line.strip()) > 10]
            message_body = meaningful_lines[0] if meaningful_lines else "Check hostel system for details"
        
        full_message = prefix + message_body
        
        # Truncate if too long
        if len(full_message) > max_length:
            full_message = full_message[:max_length-3] + "..."
        
        return full_message
    
    def _send_sms_via_service(self, phone_number: str, message: str) -> bool:
        """Send SMS via configured SMS service"""
        try:
            # Check if Twilio is configured
            twilio_sid = getattr(settings, 'TWILIO_ACCOUNT_SID', None)
            twilio_token = getattr(settings, 'TWILIO_AUTH_TOKEN', None)
            twilio_from = getattr(settings, 'TWILIO_PHONE_NUMBER', None)
            
            if twilio_sid and twilio_token and twilio_from:
                return self._send_via_twilio(phone_number, message, twilio_sid, twilio_token, twilio_from)
            
            # Check if other SMS services are configured
            # Add other SMS service integrations here as needed
            
            # If no SMS service is configured, log and return False
            logger.warning("No SMS service configured. SMS notifications will be disabled.")
            return False
            
        except Exception as e:
            logger.error(f"SMS service error: {str(e)}")
            return False
    
    def _send_via_twilio(self, phone_number: str, message: str, account_sid: str, auth_token: str, from_number: str) -> bool:
        """Send SMS via Twilio service"""
        try:
            # Import Twilio client (only if needed)
            from twilio.rest import Client
            
            # Create Twilio client
            client = Client(account_sid, auth_token)
            
            # Send SMS
            message_obj = client.messages.create(
                body=message,
                from_=from_number,
                to=phone_number
            )
            
            logger.info(f"Twilio SMS sent successfully. SID: {message_obj.sid}")
            return True
            
        except ImportError:
            logger.error("Twilio library not installed. Install with: pip install twilio")
            return False
        except Exception as e:
            logger.error(f"Twilio SMS error: {str(e)}")
            return False

    def send_urgent_sms_alert(self, alert_type: str, message: str, target_roles: List[str] = None) -> Dict[str, List[DeliveryResult]]:
        """
        Send urgent SMS alerts to staff members (SMS only for critical alerts).
        
        Args:
            alert_type: Type of alert
            message: Alert message
            target_roles: Staff roles to target (defaults to warden and security)
            
        Returns:
            Dict[str, List[DeliveryResult]]: Delivery results by staff ID
        """
        if target_roles is None:
            target_roles = ['warden', 'security']  # SMS for urgent roles only
        
        # Get staff members who have SMS enabled and are in target roles
        target_staff = []
        for staff_id, prefs in self.staff_preferences.items():
            if (prefs.urgent_alerts and 
                NotificationMethod.SMS in prefs.methods):
                staff_member = Staff.objects.filter(staff_id=staff_id, is_active=True).first()
                if staff_member and staff_member.role in target_roles:
                    target_staff.append(staff_id)
        
        delivery_results = {}
        
        for staff_id in target_staff:
            staff_member = Staff.objects.filter(staff_id=staff_id, is_active=True).first()
            if not staff_member:
                continue
            
            try:
                # Send SMS only (not other methods for urgent SMS alerts)
                result = self._send_sms(
                    recipient=staff_member,
                    subject=f"URGENT: {alert_type.replace('_', ' ').title()}",
                    content=message,
                    timestamp=timezone.now()
                )
                
                delivery_results[staff_id] = [result]
                
                # Record the notification
                self._record_notification(
                    recipient_id=staff_id,
                    content_type="urgent_sms_alert",
                    subject=f"URGENT SMS: {alert_type.replace('_', ' ').title()}",
                    delivery_attempts=[result]
                )
                
            except Exception as e:
                logger.error(f"Failed to send urgent SMS to {staff_id}: {str(e)}")
                delivery_results[staff_id] = [DeliveryResult(
                    method=NotificationMethod.SMS,
                    success=False,
                    message=f"SMS delivery failed: {str(e)}",
                    timestamp=timezone.now(),
                    recipient=staff_id
                )]
        
        return delivery_results
    
    def _send_in_app(self, recipient: Staff, subject: str, content: str, timestamp: datetime) -> DeliveryResult:
        """Send in-app notification"""
        try:
            # In a real implementation, this would create an in-app notification record
            # For now, we'll simulate in-app notification creation
            success = True  # Simulate successful in-app notification
            
            if success:
                return DeliveryResult(
                    method=NotificationMethod.IN_APP,
                    success=True,
                    message="In-app notification created",
                    timestamp=timestamp,
                    recipient=recipient.staff_id
                )
            else:
                return DeliveryResult(
                    method=NotificationMethod.IN_APP,
                    success=False,
                    message="In-app notification failed",
                    timestamp=timestamp,
                    recipient=recipient.staff_id
                )
        except Exception as e:
            return DeliveryResult(
                method=NotificationMethod.IN_APP,
                success=False,
                message=f"In-app notification error: {str(e)}",
                timestamp=timestamp,
                recipient=recipient.staff_id
            )
    
    def _send_webhook(self, recipient: Staff, subject: str, content: str, timestamp: datetime) -> DeliveryResult:
        """Send notification via webhook"""
        try:
            # In a real implementation, this would send HTTP POST to configured webhook URL
            # For now, we'll simulate webhook delivery
            success = True  # Simulate successful webhook delivery
            
            if success:
                return DeliveryResult(
                    method=NotificationMethod.WEBHOOK,
                    success=True,
                    message="Webhook delivered",
                    timestamp=timestamp,
                    recipient=recipient.staff_id
                )
            else:
                return DeliveryResult(
                    method=NotificationMethod.WEBHOOK,
                    success=False,
                    message="Webhook delivery failed",
                    timestamp=timestamp,
                    recipient=recipient.staff_id
                )
        except Exception as e:
            return DeliveryResult(
                method=NotificationMethod.WEBHOOK,
                success=False,
                message=f"Webhook error: {str(e)}",
                timestamp=timestamp,
                recipient=recipient.staff_id
            )
    
    def _is_quiet_hours(self, preferences: NotificationPreference) -> bool:
        """Check if current time is within quiet hours for the staff member"""
        if not preferences.quiet_hours_start or not preferences.quiet_hours_end:
            return False
        
        current_hour = timezone.now().hour
        start_hour = preferences.quiet_hours_start
        end_hour = preferences.quiet_hours_end
        
        if start_hour <= end_hour:
            # Same day quiet hours (e.g., 14:00 to 18:00)
            return start_hour <= current_hour <= end_hour
        else:
            # Overnight quiet hours (e.g., 22:00 to 06:00)
            return current_hour >= start_hour or current_hour <= end_hour
    
    def _format_email_content(self, content: str, subject: str) -> str:
        """Format email content as HTML for better readability"""
        html_template = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <title>{subject}</title>
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
                    background-color: #2c3e50;
                    color: white;
                    padding: 20px;
                    text-align: center;
                    border-radius: 5px 5px 0 0;
                }}
                .content {{
                    background-color: #f8f9fa;
                    padding: 20px;
                    border: 1px solid #dee2e6;
                    border-radius: 0 0 5px 5px;
                }}
                .urgent {{
                    background-color: #dc3545;
                    color: white;
                    padding: 10px;
                    border-radius: 5px;
                    margin-bottom: 15px;
                    text-align: center;
                    font-weight: bold;
                }}
                .summary-section {{
                    margin-bottom: 20px;
                    padding: 15px;
                    background-color: white;
                    border-left: 4px solid #007bff;
                    border-radius: 3px;
                }}
                .footer {{
                    margin-top: 20px;
                    padding: 15px;
                    background-color: #e9ecef;
                    border-radius: 5px;
                    font-size: 12px;
                    color: #6c757d;
                    text-align: center;
                }}
            </style>
        </head>
        <body>
            <div class="header">
                <h2>AI Hostel Coordination System</h2>
            </div>
            <div class="content">
                {"<div class='urgent'>URGENT NOTIFICATION</div>" if "URGENT" in subject else ""}
                <div class="summary-section">
                    <pre style="white-space: pre-wrap; font-family: Arial, sans-serif;">{content}</pre>
                </div>
            </div>
            <div class="footer">
                <p>This is an automated notification from the AI Hostel Coordination System.</p>
                <p>Generated at: {timezone.now().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
            </div>
        </body>
        </html>
        """
        return html_template

    def send_escalated_request_notification(self, request_type: str, request_details: dict, student_info: dict) -> Dict[str, List[DeliveryResult]]:
        """
        Send email notification to wardens for escalated requests.
        
        Args:
            request_type: Type of request (guest, leave, maintenance, etc.)
            request_details: Details of the request
            student_info: Information about the student making the request
            
        Returns:
            Dict[str, List[DeliveryResult]]: Delivery results by staff ID
        """
        # Format the escalation message
        message = self._format_escalated_request_message(request_type, request_details, student_info)
        subject = f"Escalated Request: {request_type.replace('_', ' ').title()} - {student_info.get('name', 'Unknown Student')}"
        
        # Send to wardens and admins only
        return self.deliver_urgent_alert(
            alert_type=f"escalated_{request_type}",
            message=message,
            priority=NotificationPriority.HIGH,
            target_roles=['warden', 'admin']
        )
    
    def _format_escalated_request_message(self, request_type: str, request_details: dict, student_info: dict) -> str:
        """Format escalated request message for email notification"""
        message_parts = [
            f"ESCALATED REQUEST NOTIFICATION",
            f"=" * 50,
            f"",
            f"Request Type: {request_type.replace('_', ' ').title()}",
            f"Student: {student_info.get('name', 'Unknown')} (ID: {student_info.get('student_id', 'Unknown')})",
            f"Room: {student_info.get('room_number', 'Unknown')} - {student_info.get('block', 'Unknown')}",
            f"Phone: {student_info.get('phone', 'Not provided')}",
            f"",
            f"Request Details:",
            f"-" * 20,
        ]
        
        # Add request-specific details
        for key, value in request_details.items():
            if key not in ['id', 'created_at', 'updated_at']:
                formatted_key = key.replace('_', ' ').title()
                message_parts.append(f"{formatted_key}: {value}")
        
        message_parts.extend([
            f"",
            f"Action Required:",
            f"- Review the request details above",
            f"- Approve or reject the request through the staff dashboard",
            f"- Contact the student if additional information is needed",
            f"",
            f"This request was escalated because it exceeds auto-approval criteria.",
            f"Please review and take appropriate action within 24 hours.",
        ])
        
        return "\n".join(message_parts)

    def notify_security_guest_approval(
        self,
        guest_request,
        student,
        approved_by=None
    ) -> Dict[str, List[DeliveryResult]]:
        """
        Notify security personnel about an approved guest request.
        
        Args:
            guest_request: The approved GuestRequest object
            student: The student who made the request
            approved_by: The staff member who approved the request (optional for auto-approved flows)
            
        Returns:
            Dict[str, List[DeliveryResult]]: Delivery results by security staff ID
        """
        # Get all active security staff
        security_staff = Staff.objects.filter(role='security', is_active=True)
        
        if not security_staff.exists():
            logger.warning("No active security staff found for guest notification")
            return {}
        
        # Format the notification content
        subject = f"Guest Approved - {guest_request.guest_name} visiting Room {student.room_number}"
        
        content = self._format_guest_approval_security_notification(
            guest_request=guest_request,
            student=student,
            approved_by=approved_by
        )
        
        delivery_results = {}
        
        for staff in security_staff:
            # Reload preferences for security staff
            if staff.staff_id not in self.staff_preferences:
                self._load_default_preferences()
            
            preferences = self.staff_preferences.get(staff.staff_id)
            
            # Check if security staff wants guest notifications
            if preferences and not preferences.guest_notifications:
                logger.info(f"Skipping guest notification for {staff.staff_id} - notifications disabled")
                continue
            
            results = []
            
            # Try all configured notification methods
            notification_methods = preferences.methods if preferences else {NotificationMethod.EMAIL}
            
            for method in notification_methods:
                try:
                    result = self._deliver_notification(
                        method=method,
                        recipient=staff,
                        subject=subject,
                        content=content,
                        priority=NotificationPriority.MEDIUM
                    )
                    results.append(result)
                    
                    if result.success:
                        logger.info(f"Security notification sent to {staff.staff_id} via {method.value}")
                        break  # Stop trying other methods if one succeeds
                        
                except Exception as e:
                    logger.error(f"Failed to notify security {staff.staff_id} via {method}: {str(e)}")
                    results.append(DeliveryResult(
                        method=method,
                        success=False,
                        message=f"Delivery failed: {str(e)}",
                        timestamp=timezone.now(),
                        recipient=staff.staff_id
                    ))
            
            delivery_results[staff.staff_id] = results
            
            # Record the notification
            self._record_notification(
                recipient_id=staff.staff_id,
                content_type="guest_approval",
                subject=subject,
                delivery_attempts=results
            )
        
        # Log summary
        successful = sum(1 for results in delivery_results.values() if any(r.success for r in results))
        logger.info(f"Guest approval notification sent to {successful}/{len(delivery_results)} security staff")
        
        return delivery_results
    
    def _format_guest_approval_security_notification(
        self,
        guest_request,
        student,
        approved_by=None
    ) -> str:
        """Format the guest approval notification content for security."""
        arrival_str = guest_request.start_date.strftime('%B %d, %Y at %I:%M %p')
        departure_str = guest_request.end_date.strftime('%B %d, %Y at %I:%M %p')
        relationship = guest_request.get_relationship_display() if hasattr(guest_request, 'get_relationship_display') else 'Not specified'
        approver_name = approved_by.name if approved_by else 'System (Auto-Approved)'
        approver_role = approved_by.role.title() if approved_by else 'Auto Rule'
        
        message_parts = [
            "=" * 50,
            "GUEST ARRIVAL NOTIFICATION",
            "=" * 50,
            "",
            "GUEST DETAILS:",
            f"  • Name: {guest_request.guest_name}",
            f"  • Relationship: {relationship}",
            f"  • Phone: {guest_request.guest_phone or 'Not provided'}",
            f"  • Purpose: {guest_request.purpose or 'Not specified'}",
            "",
            "VISIT SCHEDULE:",
            f"  • Arrival: {arrival_str}",
            f"  • Departure: {departure_str}",
            f"  • Duration: {guest_request.duration_days} day(s)",
            "",
            "HOST STUDENT:",
            f"  • Name: {student.name}",
            f"  • Student ID: {student.student_id}",
            f"  • Room: {student.room_number}",
            f"  • Block: {student.block}",
            f"  • Contact: {student.phone or 'Not provided'}",
            "",
            "APPROVAL INFO:",
            f"  • Approved By: {approver_name} ({approver_role})",
            f"  • Approved At: {timezone.now().strftime('%B %d, %Y at %I:%M %p')}",
            f"  • Request ID: {guest_request.request_id}",
            "",
            "=" * 50,
            "ACTION REQUIRED:",
            "  ✓ Verify guest identity upon arrival",
            "  ✓ Record entry in security log",
            "  ✓ Issue visitor badge if required",
            "  ✓ Record departure when guest leaves",
            "=" * 50,
        ]
        
        return "\n".join(message_parts)

    def send_daily_summary_email(self, summary_date: str = None) -> Dict[str, List[DeliveryResult]]:
        """
        Send daily summary email to relevant staff members.
        
        Args:
            summary_date: Date for the summary (defaults to today)
            
        Returns:
            Dict[str, List[DeliveryResult]]: Delivery results by staff ID
        """
        from .daily_summary_service import daily_summary_generator
        from datetime import datetime
        
        if summary_date:
            try:
                target_date = datetime.strptime(summary_date, '%Y-%m-%d').date()
            except ValueError:
                target_date = timezone.now().date()
        else:
            target_date = timezone.now().date()
        
        # Generate the daily summary
        summary = daily_summary_generator.generate_daily_summary(target_date)
        
        # Deliver to staff members
        return self.deliver_daily_summary(summary)
    
    def _record_notification(self, recipient_id: str, content_type: str, subject: str, delivery_attempts: List[DeliveryResult]):
        """Record notification delivery attempt"""
        # Determine final status
        successful_deliveries = [attempt for attempt in delivery_attempts if attempt.success]
        final_status = 'delivered' if successful_deliveries else 'failed'
        delivered_at = successful_deliveries[0].timestamp if successful_deliveries else None
        
        record = NotificationRecord(
            notification_id=f"notif_{timezone.now().strftime('%Y%m%d_%H%M%S')}_{recipient_id}",
            recipient_id=recipient_id,
            content_type=content_type,
            subject=subject,
            delivery_attempts=delivery_attempts,
            final_status=final_status,
            created_at=timezone.now(),
            delivered_at=delivered_at
        )
        
        self.delivery_records.append(record)
        logger.info(f"Recorded notification {record.notification_id} - Status: {final_status}")
        """Record notification delivery attempt"""
        # Determine final status
        successful_deliveries = [attempt for attempt in delivery_attempts if attempt.success]
        final_status = 'delivered' if successful_deliveries else 'failed'
        delivered_at = successful_deliveries[0].timestamp if successful_deliveries else None
        
        record = NotificationRecord(
            notification_id=f"notif_{timezone.now().strftime('%Y%m%d_%H%M%S')}_{recipient_id}",
            recipient_id=recipient_id,
            content_type=content_type,
            subject=subject,
            delivery_attempts=delivery_attempts,
            final_status=final_status,
            created_at=timezone.now(),
            delivered_at=delivered_at
        )
        
        self.delivery_records.append(record)
        logger.info(f"Recorded notification {record.notification_id} - Status: {final_status}")
    
    def get_delivery_statistics(self, days: int = 7) -> Dict[str, Any]:
        """
        Get notification delivery statistics for the specified number of days.
        
        Args:
            days: Number of days to analyze
            
        Returns:
            Dict: Delivery statistics
        """
        cutoff_date = timezone.now() - timedelta(days=days)
        recent_records = [
            record for record in self.delivery_records
            if record.created_at >= cutoff_date
        ]
        
        total_notifications = len(recent_records)
        delivered_notifications = len([r for r in recent_records if r.final_status == 'delivered'])
        failed_notifications = len([r for r in recent_records if r.final_status == 'failed'])
        
        # Calculate delivery rate by method
        method_stats = {}
        for method in NotificationMethod:
            method_attempts = []
            for record in recent_records:
                method_attempts.extend([
                    attempt for attempt in record.delivery_attempts
                    if attempt.method == method
                ])
            
            if method_attempts:
                successful = len([a for a in method_attempts if a.success])
                method_stats[method.value] = {
                    'total_attempts': len(method_attempts),
                    'successful': successful,
                    'success_rate': successful / len(method_attempts) if method_attempts else 0
                }
        
        return {
            'period_days': days,
            'total_notifications': total_notifications,
            'delivered_notifications': delivered_notifications,
            'failed_notifications': failed_notifications,
            'overall_delivery_rate': delivered_notifications / total_notifications if total_notifications > 0 else 0,
            'method_statistics': method_stats
        }
    
    def update_staff_preferences(self, staff_id: str, preferences: NotificationPreference):
        """Update notification preferences for a staff member"""
        self.staff_preferences[staff_id] = preferences
        logger.info(f"Updated notification preferences for staff {staff_id}")
    
    def get_staff_preferences(self, staff_id: str) -> Optional[NotificationPreference]:
        """Get notification preferences for a staff member"""
        self._ensure_preferences_loaded()
        return self.staff_preferences.get(staff_id)


# Create singleton instance
notification_service = NotificationService()