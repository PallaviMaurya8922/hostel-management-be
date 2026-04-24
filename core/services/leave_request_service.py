"""
Leave Request Service for the AI-Powered Hostel Coordination System.
Handles enhanced leave request processing, auto-approval logic, and digital pass generation.
"""

import logging
import os
import threading
from datetime import datetime, date, timedelta
from typing import Dict, Any, Optional, Tuple
from django.utils import timezone
from django.db import transaction
from dataclasses import dataclass

from ..models import Student, Staff, AbsenceRecord, DigitalPass, SecurityRecord, AuditLog
from .pdf_generation_service import pdf_generation_service
from .email_service import email_service
from .whatsapp_service import send_leave_request

logger = logging.getLogger(__name__)


@dataclass
class LeaveRequestResult:
    """Result of leave request processing"""
    success: bool
    message: str
    absence_record: Optional[AbsenceRecord] = None
    digital_pass: Optional[DigitalPass] = None
    auto_approved: bool = False
    requires_warden_approval: bool = False
    error: Optional[str] = None


class LeaveRequestService:
    """Service for processing enhanced leave requests with auto-approval and digital pass generation"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def process_leave_request(
        self, 
        student: Student, 
        from_date: date, 
        to_date: date, 
        reason: str,
        emergency_contact: Optional[str] = None
    ) -> LeaveRequestResult:
        """
        Process a leave request with enhanced logic for auto-approval and digital pass generation.
        
        Args:
            student: Student making the request
            from_date: Start date of leave
            to_date: End date of leave
            reason: Reason for leave
            emergency_contact: Optional emergency contact during leave
            
        Returns:
            LeaveRequestResult with processing outcome
        """
        try:
            if not isinstance(student, Student):
                return LeaveRequestResult(
                    success=False,
                    message="Only student accounts can submit leave requests.",
                    error="invalid_user_type",
                )

            # Validate dates
            validation_result = self._validate_leave_dates(from_date, to_date)
            if not validation_result[0]:
                return LeaveRequestResult(
                    success=False,
                    message="Invalid leave dates",
                    error=validation_result[1]
                )
            
            # Calculate total days
            total_days = (to_date - from_date).days + 1
            
            # Check if student has recent violations
            has_violations = self._check_student_violations(student)
            
            # Determine if auto-approval is possible
            can_auto_approve = self._can_auto_approve(total_days, has_violations)
            
            with transaction.atomic():
                # Create absence record
                absence_record = AbsenceRecord.objects.create(
                    student=student,
                    start_date=timezone.make_aware(datetime.combine(from_date, datetime.min.time())),
                    end_date=timezone.make_aware(datetime.combine(to_date, datetime.max.time())),
                    reason=reason,
                    emergency_contact=emergency_contact,
                    status='pending',
                    auto_approved=False,
                    parent_approval=None
                )
                
                if can_auto_approve:
                    # Auto-approve the request
                    absence_record.status = 'approved'
                    absence_record.auto_approved = True
                    absence_record.approval_reason = f"Auto-approved: Leave duration ({total_days} days) meets auto-approval criteria"
                    absence_record.save()
                    
                    # Generate digital pass
                    digital_pass = self._generate_digital_pass(
                        student=student,
                        absence_record=absence_record,
                        from_date=from_date,
                        to_date=to_date,
                        total_days=total_days,
                        reason=reason,
                        approval_type='auto'
                    )
                    
                    # Update security records
                    self._update_security_records(student, digital_pass)
                    
                    # Send auto-approval email ASYNC (non-blocking) to speed up response
                    self._send_email_async(
                        email_type='auto_approval',
                        student=student,
                        absence_record=absence_record,
                        digital_pass=digital_pass
                    )
                    
                    # Log the auto-approval
                    self._log_leave_decision(
                        student=student,
                        absence_record=absence_record,
                        decision='approved',
                        reasoning=f"Auto-approved leave request for {total_days} days",
                        auto_approved=True
                    )
                    
                    return LeaveRequestResult(
                        success=True,
                        message=f"Leave request auto-approved! Digital pass generated: {digital_pass.pass_number}",
                        absence_record=absence_record,
                        digital_pass=digital_pass,
                        auto_approved=True,
                        requires_warden_approval=False
                    )
                
                else:
                    # Requires warden approval - send escalation email ASYNC (non-blocking)
                    self._send_escalation_email_async(
                        student=student,
                        absence_record=absence_record
                    )

                    # Parent decision is optional operationally; request submission should not fail
                    # if WhatsApp delivery has a configuration/network issue.
                    try:
                        send_leave_request(
                            phone=student.parent_phone,
                            leave_id=str(absence_record.absence_id),
                            student_name=student.name
                        )
                    except Exception as whatsapp_error:
                        self.logger.warning(
                            "Failed to send parent WhatsApp request for absence %s: %s",
                            absence_record.absence_id,
                            whatsapp_error,
                        )

                    
                    self._log_leave_decision(
                        student=student,
                        absence_record=absence_record,
                        decision='escalated',
                        reasoning=f"Leave request for {total_days} days requires warden approval",
                        auto_approved=False
                    )
                    
                    return LeaveRequestResult(
                        success=True,
                        message=f"Leave request submitted for warden approval. Duration: {total_days} days",
                        absence_record=absence_record,
                        digital_pass=None,
                        auto_approved=False,
                        requires_warden_approval=True
                    )
        
        except Exception as e:
            uid = getattr(student, "student_id", None) or getattr(student, "staff_id", None) or "unknown"
            self.logger.exception("Error processing leave request for %s: %s", uid, e)
            return LeaveRequestResult(
                success=False,
                message="An error occurred while processing your leave request",
                error=str(e)
            )
    def _send_escalation_email_async(
        self,
        student: Student,
        absence_record: AbsenceRecord
    ):
        """
        Send escalation emails in a background thread (non-blocking).
        This speeds up the API response by not waiting for SMTP.
        """
        def send_escalation_task():
            try:
                escalation_results = email_service.send_escalation_email(
                    student=student,
                    absence_record=absence_record
                )
                
                # Log escalation email results
                successful_escalations = sum(1 for success, _ in escalation_results.values() if success)
                if successful_escalations > 0:
                    self.logger.info(f"Async escalation emails sent to {successful_escalations} staff members for absence {absence_record.absence_id}")
                else:
                    self.logger.warning(f"Failed to send async escalation emails for absence {absence_record.absence_id}")
                    
            except Exception as e:
                self.logger.error(f"Error in async escalation email task: {e}")
        
        # Start email sending in background thread
        email_thread = threading.Thread(target=send_escalation_task, daemon=True)
        email_thread.start()
        self.logger.info(f"Started async escalation email thread for absence {absence_record.absence_id}")
        
    def approve_leave_request(
        self, 
        absence_record: AbsenceRecord, 
        approved_by: Staff, 
        approval_reason: str = "Approved by warden"
    ) -> LeaveRequestResult:
        """
        Approve a pending leave request and generate digital pass.
        
        Args:
            absence_record: The absence record to approve
            approved_by: Staff member approving the request
            approval_reason: Reason for approval
            
        Returns:
            LeaveRequestResult with approval outcome
        """
        try:
            if absence_record.status != 'pending':
                return LeaveRequestResult(
                    success=False,
                    message="Leave request is not in pending status",
                    error="Invalid status for approval"
                )

            if absence_record.parent_approval is not True:
                return LeaveRequestResult(
                    success=False,
                    message="Parent approval required before warden approval",
                    error="Parent approval required"
                )
            
            with transaction.atomic():
                # Update absence record
                absence_record.status = 'approved'
                absence_record.approved_by = approved_by
                absence_record.approval_reason = approval_reason
                absence_record.save()
                
                # Calculate dates and total days
                from_date = absence_record.start_date.date()
                to_date = absence_record.end_date.date()
                total_days = (to_date - from_date).days + 1
                
                # Generate digital pass
                digital_pass = self._generate_digital_pass(
                    student=absence_record.student,
                    absence_record=absence_record,
                    from_date=from_date,
                    to_date=to_date,
                    total_days=total_days,
                    reason=absence_record.reason,
                    approval_type='manual',
                    approved_by=approved_by
                )
                
                # Update security records
                self._update_security_records(absence_record.student, digital_pass)
                
                # Send warden approval email ASYNC (non-blocking) to speed up response
                self._send_email_async(
                    email_type='warden_approval',
                    student=absence_record.student,
                    absence_record=absence_record,
                    digital_pass=digital_pass,
                    approved_by=approved_by
                )
                
                # Log the approval
                self._log_leave_decision(
                    student=absence_record.student,
                    absence_record=absence_record,
                    decision='approved',
                    reasoning=f"Manually approved by {approved_by.name}: {approval_reason}",
                    auto_approved=False,
                    staff_member=approved_by
                )
                
                return LeaveRequestResult(
                    success=True,
                    message=f"Leave request approved! Digital pass generated: {digital_pass.pass_number}",
                    absence_record=absence_record,
                    digital_pass=digital_pass,
                    auto_approved=False,
                    requires_warden_approval=False
                )
        
        except Exception as e:
            self.logger.error(f"Error approving leave request {absence_record.absence_id}: {e}")
            return LeaveRequestResult(
                success=False,
                message="An error occurred while approving the leave request",
                error=str(e)
            )
    
    def reject_leave_request(
        self, 
        absence_record: AbsenceRecord, 
        rejected_by: Staff, 
        rejection_reason: str
    ) -> LeaveRequestResult:
        """
        Reject a pending leave request.
        
        Args:
            absence_record: The absence record to reject
            rejected_by: Staff member rejecting the request
            rejection_reason: Reason for rejection
            
        Returns:
            LeaveRequestResult with rejection outcome
        """
        try:
            if absence_record.status != 'pending':
                return LeaveRequestResult(
                    success=False,
                    message="Leave request is not in pending status",
                    error="Invalid status for rejection"
                )
            
            with transaction.atomic():
                # Update absence record
                absence_record.status = 'rejected'
                absence_record.approved_by = rejected_by
                absence_record.approval_reason = rejection_reason
                absence_record.save()
                
                # Send rejection email
                email_success, email_message = email_service.send_rejection_email(
                    student=absence_record.student,
                    absence_record=absence_record,
                    rejected_by=rejected_by
                )
                
                if email_success:
                    self.logger.info(f"Rejection email sent for absence record {absence_record.absence_id}")
                else:
                    self.logger.warning(f"Failed to send rejection email: {email_message}")
                
                # Log the rejection
                self._log_leave_decision(
                    student=absence_record.student,
                    absence_record=absence_record,
                    decision='rejected',
                    reasoning=f"Rejected by {rejected_by.name}: {rejection_reason}",
                    auto_approved=False,
                    staff_member=rejected_by
                )
                
                return LeaveRequestResult(
                    success=True,
                    message=f"Leave request rejected: {rejection_reason}",
                    absence_record=absence_record,
                    digital_pass=None,
                    auto_approved=False,
                    requires_warden_approval=False
                )
        
        except Exception as e:
            self.logger.error(f"Error rejecting leave request {absence_record.absence_id}: {e}")
            return LeaveRequestResult(
                success=False,
                message="An error occurred while rejecting the leave request",
                error=str(e)
            )
    
    def _validate_leave_dates(self, from_date: date, to_date: date) -> Tuple[bool, Optional[str]]:
        """Validate leave request dates"""
        today = timezone.now().date()
        
        if from_date < today:
            return False, "Leave start date cannot be in the past"
        
        if to_date < from_date:
            return False, "Leave end date must be after start date"
        
        # Check for reasonable duration (max 30 days for auto-processing)
        total_days = (to_date - from_date).days + 1
        if total_days > 30:
            return False, "Leave duration cannot exceed 30 days"
        
        return True, None
    
    def _check_student_violations(self, student: Student) -> bool:
        """Check if student has recent violations that would prevent auto-approval"""
        return student.has_recent_violations
    
    def _can_auto_approve(self, total_days: int, has_violations: bool) -> bool:
        """Determine if leave request can be auto-approved"""
        # Auto-approval is intentionally disabled.
        # All leave requests must go through manual warden approval.
        return False
    
    def _generate_digital_pass(
        self,
        student: Student,
        absence_record: AbsenceRecord,
        from_date: date,
        to_date: date,
        total_days: int,
        reason: str,
        approval_type: str,
        approved_by: Optional[Staff] = None
    ) -> DigitalPass:
        """Generate a digital pass for approved leave"""
        digital_pass = DigitalPass.objects.create(
            student=student,
            absence_record=absence_record,
            from_date=from_date,
            to_date=to_date,
            total_days=total_days,
            reason=reason,
            approved_by=approved_by,
            approval_type=approval_type,
            status='active'
        )
        
        # Generate PDF for the pass
        # Note: pdf_generation_service.generate_pass_pdf will update pdf_generated and pdf_path
        try:
            success, file_path, pdf_bytes = pdf_generation_service.generate_pass_pdf(digital_pass)
            if success:
                self.logger.info(f"PDF generated successfully for pass {digital_pass.pass_number}")
                # Refresh from database to get the updated pdf_generated and pdf_path values set by the pdf service
                digital_pass.refresh_from_db()
            else:
                self.logger.error(f"Failed to generate PDF for pass {digital_pass.pass_number}")
        except Exception as e:
            self.logger.error(f"Error generating PDF for pass {digital_pass.pass_number}: {e}")
        
        self.logger.info(f"Digital pass {digital_pass.pass_number} generated for student {student.student_id}")
        return digital_pass
    
    def _update_security_records(self, student: Student, digital_pass: DigitalPass):
        """Update security records to allow student to leave"""
        security_record = SecurityRecord.objects.create(
            student=student,
            digital_pass=digital_pass,
            status='allowed_to_leave',
            notes=f"Approved leave from {digital_pass.from_date} to {digital_pass.to_date}"
        )
        
        self.logger.info(f"Security record updated for student {student.student_id} - allowed to leave")
        return security_record
    
    def _send_email_async(
        self,
        email_type: str,
        student: Student,
        absence_record: AbsenceRecord,
        digital_pass: DigitalPass,
        approved_by: Optional[Staff] = None
    ):
        """
        Send email notification in a background thread (non-blocking).
        This speeds up the API response by not waiting for SMTP.
        
        Args:
            email_type: 'auto_approval' or 'warden_approval'
            student: Student receiving the email
            absence_record: The absence record
            digital_pass: The generated digital pass
            approved_by: Staff member who approved (for warden_approval)
        """
        def send_email_task():
            try:
                # Get PDF bytes (this might be cached from earlier generation)
                pdf_bytes = self.get_pass_pdf_bytes(digital_pass)
                
                if email_type == 'auto_approval':
                    success, message = email_service.send_auto_approval_email(
                        student=student,
                        absence_record=absence_record,
                        digital_pass=digital_pass,
                        pdf_bytes=pdf_bytes
                    )
                elif email_type == 'warden_approval' and approved_by:
                    success, message = email_service.send_warden_approval_email(
                        student=student,
                        absence_record=absence_record,
                        digital_pass=digital_pass,
                        approved_by=approved_by,
                        pdf_bytes=pdf_bytes
                    )
                else:
                    self.logger.error(f"Unknown email type: {email_type}")
                    return
                
                if success:
                    self.logger.info(f"Async {email_type} email sent for pass {digital_pass.pass_number}")
                else:
                    self.logger.warning(f"Failed to send async {email_type} email: {message}")
                    
            except Exception as e:
                self.logger.error(f"Error in async email task: {e}")
        
        # Start email sending in background thread
        email_thread = threading.Thread(target=send_email_task, daemon=True)
        email_thread.start()
        self.logger.info(f"Started async {email_type} email thread for pass {digital_pass.pass_number}")
    
    def _log_leave_decision(
        self,
        student: Student,
        absence_record: AbsenceRecord,
        decision: str,
        reasoning: str,
        auto_approved: bool,
        staff_member: Optional[Staff] = None
    ):
        """Log leave request decision in audit log"""
        AuditLog.objects.create(
            action_type='absence_approval',
            entity_type='absence_record',
            entity_id=str(absence_record.absence_id),
            decision=decision,
            reasoning=reasoning,
            confidence_score=1.0 if auto_approved else 0.9,
            rules_applied=['leave_duration_check', 'violation_history_check'] if auto_approved else ['manual_review_required'],
            user_id=staff_member.staff_id if staff_member else 'system',
            user_type='staff' if staff_member else 'system',
            metadata={
                'student_id': student.student_id,
                'auto_approved': auto_approved,
                'total_days': (absence_record.end_date.date() - absence_record.start_date.date()).days + 1,
                'has_violations': student.has_recent_violations
            }
        )
    
    def get_student_active_passes(self, student: Student) -> list:
        """Get all active digital passes for a student"""
        return DigitalPass.objects.filter(
            student=student,
            status='active'
        ).order_by('-created_at')
    
    def verify_digital_pass(self, pass_number: str) -> Dict[str, Any]:
        """Verify a digital pass by pass number"""
        try:
            digital_pass = DigitalPass.objects.get(pass_number=pass_number)
            
            return {
                'valid': digital_pass.is_valid,
                'pass_number': digital_pass.pass_number,
                'student_name': digital_pass.student.name,
                'student_id': digital_pass.student.student_id,
                'room_number': digital_pass.student.room_number,
                'block': digital_pass.student.block,
                'from_date': digital_pass.from_date.strftime('%d %b %Y'),
                'to_date': digital_pass.to_date.strftime('%d %b %Y'),
                'total_days': digital_pass.total_days,
                'reason': digital_pass.reason,
                'status': digital_pass.status,
                'verification_code': digital_pass.verification_code,
                'days_remaining': digital_pass.days_remaining,
                'message': 'Pass is valid and active' if digital_pass.is_valid else 'Pass has expired or is invalid'
            }
        
        except DigitalPass.DoesNotExist:
            return {
                'valid': False,
                'message': 'Pass not found',
                'error': 'Pass not found'
            }
    
    def regenerate_pass_pdf(self, digital_pass: DigitalPass) -> Tuple[bool, Optional[str]]:
        """Regenerate PDF for an existing digital pass"""
        try:
            success, file_path, pdf_bytes = pdf_generation_service.generate_pass_pdf(digital_pass)
            if success:
                return True, "PDF regenerated successfully"
            else:
                return False, "Failed to regenerate PDF"
        except Exception as e:
            self.logger.error(f"Error regenerating PDF for pass {digital_pass.pass_number}: {e}")
            return False, f"Error: {str(e)}"
    
    def get_pass_pdf_bytes(self, digital_pass: DigitalPass) -> Optional[bytes]:
        """Get PDF bytes for a digital pass"""
        # Regenerate on access so template updates are reflected for existing passes.
        self.regenerate_pass_pdf(digital_pass)

        if not digital_pass.pdf_generated or not pdf_generation_service.pdf_exists(digital_pass):
            # Try to regenerate PDF
            success, _ = self.regenerate_pass_pdf(digital_pass)
            if not success:
                return None
        
        try:
            file_path = pdf_generation_service.get_pdf_file_path(digital_pass)
            if file_path and os.path.exists(file_path):
                with open(file_path, 'rb') as f:
                    return f.read()
        except Exception as e:
            self.logger.error(f"Error reading PDF file for pass {digital_pass.pass_number}: {e}")
        
        return None


# Global service instance
leave_request_service = LeaveRequestService()