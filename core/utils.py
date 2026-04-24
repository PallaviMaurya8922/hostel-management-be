"""
Utility functions for the AI-Powered Hostel Coordination System.
Contains shared helper functions to avoid code duplication.
"""

import logging
from datetime import datetime
from typing import Tuple, Optional, Any, Dict, List
from django.utils import timezone

logger = logging.getLogger(__name__)


def get_or_create_dev_staff():
    """
    Get or create a default development staff member.
    Used across multiple views during development mode.
    
    Returns:
        Tuple of (staff_member, created) where:
        - staff_member: Staff instance
        - created: Boolean indicating if a new record was created
    """
    from .models import Staff
    
    # Try to get existing dev staff first
    try:
        staff_member = Staff.objects.get(staff_id='STAFF001')
        return (staff_member, False)
    except Staff.DoesNotExist:
        pass
    
    # Create with a unique email to avoid conflicts with test users
    unique_email = 'dev-warden@hostel.edu'
    staff_member = Staff.objects.create(
        staff_id='STAFF001',
        name='Development Warden',
        role='warden',
        email=unique_email,
        phone='9876543210',
        permissions={'approve_requests': True, 'view_all_data': True},
        is_active=True
    )
    return (staff_member, True)


def get_staff_from_request_or_dev(request):
    """
    Get the authenticated staff member from request, or from session, or create dev staff if not found.
    
    Args:
        request: Django request object
        
    Returns:
        Staff instance
    """
    from .models import Staff
    from .authentication import get_authenticated_user
    
    # First check DRF authentication (for API endpoints)
    if hasattr(request.user, 'user_object') and request.user.user_object:
        if isinstance(request.user.user_object, Staff):
            return request.user.user_object
    
    # Check session authentication (for regular Django views)
    user_object, auth_type = get_authenticated_user(request)
    if user_object and isinstance(user_object, Staff):
        return user_object
    
    # Development mode - use default staff
    staff_member, _ = get_or_create_dev_staff()
    return staff_member


def parse_date_safe(date_str: str, format: str = '%Y-%m-%d') -> Optional[datetime]:
    """
    Safely parse a date string, returning None on failure.
    
    Args:
        date_str: Date string to parse
        format: Date format string (default: YYYY-MM-DD)
        
    Returns:
        datetime object or None if parsing fails
    """
    if not date_str:
        return None
    
    try:
        return datetime.strptime(date_str, format)
    except (ValueError, TypeError) as e:
        logger.warning(f"Invalid date format: {date_str}, error: {e}")
        return None


def parse_date_range(start_date_str: str, end_date_str: str, 
                     default_start_days_ago: int = 7) -> Tuple[datetime, datetime]:
    """
    Parse start and end date strings with sensible defaults.
    
    Args:
        start_date_str: Start date string (YYYY-MM-DD format)
        end_date_str: End date string (YYYY-MM-DD format)
        default_start_days_ago: Default number of days ago for start date
        
    Returns:
        Tuple of (start_date, end_date) as datetime objects
    """
    from datetime import date, timedelta
    
    today = date.today()
    
    start_date = parse_date_safe(start_date_str)
    if start_date:
        start_date = start_date.date()
    else:
        start_date = today - timedelta(days=default_start_days_ago)
    
    end_date = parse_date_safe(end_date_str)
    if end_date:
        end_date = end_date.date()
    else:
        end_date = today
    
    return start_date, end_date


def build_pass_history_query(start_date_str: str = None, end_date_str: str = None,
                              student_name: str = None, status_filter: str = None,
                              pass_type: str = None) -> Tuple[Any, Any]:
    """
    Build filtered querysets for digital passes and absence records.
    Shared logic for pass history views and exports.
    
    Args:
        start_date_str: Start date filter (YYYY-MM-DD)
        end_date_str: End date filter (YYYY-MM-DD)
        student_name: Student name filter (case-insensitive contains)
        status_filter: Status filter
        pass_type: 'digital' or 'leave' or None for both
        
    Returns:
        Tuple of (digital_passes_queryset, absence_records_queryset)
    """
    from .models import DigitalPass, AbsenceRecord
    from datetime import datetime
    
    # Start with all records
    digital_passes = DigitalPass.objects.select_related(
        'student', 'approved_by'
    ).all()
    
    absence_records = AbsenceRecord.objects.select_related(
        'student', 'approved_by'
    ).all()
    
    # Apply date filters
    if start_date_str:
        start_date = parse_date_safe(start_date_str)
        if start_date:
            digital_passes = digital_passes.filter(from_date__gte=start_date.date())
            start_datetime = timezone.make_aware(datetime.combine(start_date.date(), datetime.min.time()))
            absence_records = absence_records.filter(start_date__gte=start_datetime)
    
    if end_date_str:
        end_date = parse_date_safe(end_date_str)
        if end_date:
            digital_passes = digital_passes.filter(to_date__lte=end_date.date())
            end_datetime = timezone.make_aware(datetime.combine(end_date.date(), datetime.max.time()))
            absence_records = absence_records.filter(end_date__lte=end_datetime)
    
    # Apply name filter
    if student_name and student_name.strip():
        digital_passes = digital_passes.filter(student__name__icontains=student_name)
        absence_records = absence_records.filter(student__name__icontains=student_name)
    
    # Apply status filter
    if status_filter and status_filter.strip():
        digital_passes = digital_passes.filter(status=status_filter)
        absence_records = absence_records.filter(status=status_filter)
    
    return digital_passes, absence_records


def format_pass_history_records(digital_passes, absence_records, 
                                 pass_type: str = None) -> List[Dict[str, Any]]:
    """
    Format digital passes and absence records into a unified history list.
    
    Args:
        digital_passes: QuerySet of DigitalPass objects
        absence_records: QuerySet of AbsenceRecord objects
        pass_type: 'digital', 'leave', or None for both
        
    Returns:
        List of formatted history records, sorted by created_at descending
    """
    history = []
    
    # Add digital passes
    if not pass_type or pass_type == 'digital':
        for pass_obj in digital_passes:
            try:
                history.append({
                    'type': 'digital_pass',
                    'student_name': pass_obj.student.name,
                    'student_id': pass_obj.student.student_id,
                    'room_number': pass_obj.student.room_number,
                    'pass_number': pass_obj.pass_number,
                    'from_date': pass_obj.from_date.isoformat(),
                    'to_date': pass_obj.to_date.isoformat(),
                    'total_days': pass_obj.total_days,
                    'status': pass_obj.status,
                    'approved_by': pass_obj.approved_by.name if pass_obj.approved_by else 'Auto-Approved',
                    'created_at': pass_obj.created_at.isoformat()
                })
            except Exception as e:
                logger.error(f"Error processing digital pass {pass_obj.pass_number}: {e}")
    
    # Add absence records
    if not pass_type or pass_type == 'leave':
        for absence in absence_records:
            try:
                history.append({
                    'type': 'leave_request',
                    'student_name': absence.student.name,
                    'student_id': absence.student.student_id,
                    'room_number': absence.student.room_number,
                    'pass_number': f"LR-{absence.absence_id}",
                    'from_date': absence.start_date.date().isoformat(),
                    'to_date': absence.end_date.date().isoformat(),
                    'total_days': (absence.end_date.date() - absence.start_date.date()).days + 1,
                    'status': absence.status,
                    'approved_by': absence.approved_by.name if absence.approved_by else 'Pending',
                    'created_at': absence.created_at.isoformat()
                })
            except Exception as e:
                logger.error(f"Error processing absence record {absence.absence_id}: {e}")
    
    # Sort by created_at (newest first)
    history.sort(key=lambda x: x['created_at'], reverse=True)
    
    return history
