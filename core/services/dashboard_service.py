"""
Dashboard Service for staff interface with caching and real-time statistics.
Provides optimized data retrieval for dashboard metrics and analytics.
"""

import logging
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from django.utils import timezone
from django.core.cache import cache
from django.db.models import Q, Count, Case, When, IntegerField
from ..models import Student, GuestRequest, AbsenceRecord, MaintenanceRequest, Message

logger = logging.getLogger(__name__)


class DashboardService:
    """
    Service for dashboard data with intelligent caching and real-time metrics.
    """
    
    # Cache keys
    CACHE_KEY_STATS = 'dashboard_stats'
    CACHE_KEY_PENDING_REQUESTS = 'dashboard_pending_requests'
    CACHE_KEY_RECENT_ACTIVITY = 'dashboard_recent_activity'
    CACHE_KEY_DAILY_SUMMARY = 'dashboard_daily_summary'
    
    # Cache timeouts (in seconds)
    CACHE_TIMEOUT_STATS = 300  # 5 minutes for stats
    CACHE_TIMEOUT_REQUESTS = 60  # 1 minute for pending requests
    CACHE_TIMEOUT_ACTIVITY = 120  # 2 minutes for recent activity
    CACHE_TIMEOUT_SUMMARY = 600  # 10 minutes for daily summary
    
    def __init__(self):
        """Initialize the Dashboard Service."""
        logger.info("Dashboard Service initialized")
    
    def get_dashboard_data(self, force_refresh: bool = False) -> Dict[str, Any]:
        """
        Get complete dashboard data with caching.
        
        Args:
            force_refresh: If True, bypass cache and fetch fresh data
            
        Returns:
            Dictionary containing all dashboard data
        """
        try:
            # Get cached data or fetch fresh
            stats = self.get_statistics(force_refresh)
            pending_requests = self.get_pending_requests(force_refresh)
            recent_activity = self.get_recent_activity(force_refresh)
            daily_summary = self.get_daily_summary(force_refresh)
            
            return {
                'success': True,
                'data': {
                    'stats': stats,
                    'pending_requests': pending_requests,
                    'recent_activity': recent_activity,
                    'daily_summary': daily_summary,
                    'cache_info': {
                        'stats_cached': not force_refresh and cache.get(self.CACHE_KEY_STATS) is not None,
                        'requests_cached': not force_refresh and cache.get(self.CACHE_KEY_PENDING_REQUESTS) is not None,
                        'activity_cached': not force_refresh and cache.get(self.CACHE_KEY_RECENT_ACTIVITY) is not None,
                        'summary_cached': not force_refresh and cache.get(self.CACHE_KEY_DAILY_SUMMARY) is not None,
                        'last_updated': timezone.now().isoformat()
                    }
                }
            }
            
        except Exception as e:
            logger.error(f"Error getting dashboard data: {e}")
            return {
                'success': False,
                'error': str(e),
                'data': self._get_fallback_data()
            }
    
    def get_statistics(self, force_refresh: bool = False) -> Dict[str, Any]:
        """
        Get dashboard statistics with intelligent caching.
        
        Args:
            force_refresh: If True, bypass cache
            
        Returns:
            Dictionary containing current statistics
        """
        cache_key = self.CACHE_KEY_STATS
        
        if not force_refresh:
            cached_stats = cache.get(cache_key)
            if cached_stats:
                logger.debug("Using cached dashboard statistics")
                return cached_stats
        
        try:
            def safe_count(metric_name: str, queryset, fallback: int = 0) -> int:
                try:
                    return queryset.count()
                except Exception as exc:
                    logger.error(f"Failed to calculate {metric_name}: {exc}")
                    return fallback

            # Current time for calculations
            now = timezone.now()
            today = now.date()
            
            # Total students in hostel
            total_students = safe_count('total_students', Student.objects.all())
            
            # Students currently absent (approved absence records that are active)
            absent_students_count = safe_count(
                'absent_students_count',
                AbsenceRecord.objects.filter(
                    status='approved',
                    start_date__lte=now,
                    end_date__gte=now
                )
            )
            
            # Students present = Total - Currently Absent
            present_students_count = max(total_students - absent_students_count, 0)
            
            # Active guests (approved guest requests that are currently active)
            active_guests_count = safe_count(
                'active_guests_count',
                GuestRequest.objects.filter(
                    status='approved',
                    start_date__lte=now,
                    end_date__gte=now
                )
            )
            
            # Pending requests by type
            pending_guest_requests = safe_count(
                'pending_guest_requests',
                GuestRequest.objects.filter(status__iexact='pending')
            )
            pending_absence_requests = safe_count(
                'pending_absence_requests',
                AbsenceRecord.objects.filter(status__iexact='pending')
            )
            pending_maintenance_requests = safe_count(
                'pending_maintenance_requests',
                MaintenanceRequest.objects.filter(status__iexact='pending')
            )
            total_pending_requests = pending_guest_requests + pending_absence_requests + pending_maintenance_requests
            
            # Maintenance requests by priority
            high_priority_maintenance = safe_count(
                'high_priority_maintenance',
                MaintenanceRequest.objects.filter(
                    status__in=['pending', 'assigned', 'in_progress'],
                    priority='high'
                )
            )
            
            # Today's activity
            todays_messages = safe_count(
                'todays_messages',
                Message.objects.filter(created_at__date=today)
            )
            
            todays_requests = (
                safe_count('todays_guest_requests', GuestRequest.objects.filter(created_at__date=today)) +
                safe_count('todays_absence_requests', AbsenceRecord.objects.filter(created_at__date=today)) +
                safe_count('todays_maintenance_requests', MaintenanceRequest.objects.filter(created_at__date=today))
            )
            
            # Occupancy rate based on student presence only.
            occupancy_rate = round(
                present_students_count / max(total_students, 1) * 100,
                1
            )
            
            stats = {
                # Core metrics
                'total_students': total_students,
                'present_students': present_students_count,
                'absent_students': absent_students_count,
                'active_guests': active_guests_count,
                
                # Pending requests
                'total_pending_requests': total_pending_requests,
                'pending_guest_requests': pending_guest_requests,
                'pending_absence_requests': pending_absence_requests,
                'pending_maintenance_requests': pending_maintenance_requests,
                
                # Maintenance priority
                'high_priority_maintenance': high_priority_maintenance,
                
                # Today's activity
                'todays_messages': todays_messages,
                'todays_requests': todays_requests,
                
                # Calculated metrics
                'occupancy_rate': occupancy_rate,
                'availability_rate': round((total_students - present_students_count) / max(total_students, 1) * 100, 1),
                
                # Metadata
                'last_updated': now.isoformat(),
                'calculation_date': today.isoformat()
            }
            
            # Cache the results
            cache.set(cache_key, stats, self.CACHE_TIMEOUT_STATS)
            logger.info(f"Dashboard statistics calculated and cached: {present_students_count}/{total_students} students present")
            
            return stats
            
        except Exception as e:
            logger.error(f"Error calculating dashboard statistics: {e}")
            return self._get_fallback_stats()
    
    def get_pending_requests(self, force_refresh: bool = False) -> Dict[str, List[Dict]]:
        """
        Get pending requests with caching.
        
        Args:
            force_refresh: If True, bypass cache
            
        Returns:
            Dictionary containing pending requests by type
        """
        cache_key = self.CACHE_KEY_PENDING_REQUESTS
        
        # Invalidate cache if force refresh is requested
        if force_refresh:
            cache.delete(cache_key)
            logger.debug("Cache invalidated for pending requests due to force refresh")
        
        if not force_refresh:
            cached_requests = cache.get(cache_key)
            if cached_requests:
                logger.debug("Using cached pending requests")
                return cached_requests
        
        try:
            # Get pending requests with case-insensitive status filter
            pending_guest_requests_qs = GuestRequest.objects.filter(
                status__iexact='pending'
            ).select_related('student').order_by('-created_at')[:10]
            
            # Convert to list with request_id as string
            pending_guest_requests = []
            for req in pending_guest_requests_qs.values(
                'id', 'request_id', 'guest_name', 'start_date', 'end_date', 'created_at',
                'student__name', 'student__room_number', 'student__student_id'
            ):
                req['request_id'] = str(req['request_id'])  # Convert UUID to string
                pending_guest_requests.append(req)
            
            # Get pending absence requests with eager loading and UUID included
            pending_absence_requests_qs = AbsenceRecord.objects.filter(
                status__iexact='pending'
            ).select_related('student', 'approved_by').order_by('-created_at')[:10]
            
            # Convert to list with absence_id as string
            pending_absence_requests = []
            for req in pending_absence_requests_qs.values(
                'id', 'absence_id', 'start_date', 'end_date', 'reason', 'created_at',
                'student__name', 'student__room_number', 'student__student_id', 'student__block'
            ):
                req['absence_id'] = str(req['absence_id'])  # Convert UUID to string
                pending_absence_requests.append(req)
            
            pending_maintenance_requests_qs = MaintenanceRequest.objects.filter(
                status__iexact='pending'
            ).select_related('student').order_by('-created_at')[:10]
            
            # Convert to list with request_id as string
            pending_maintenance_requests = []
            for req in pending_maintenance_requests_qs.values(
                'id', 'request_id', 'description', 'issue_type', 'priority', 'room_number', 'created_at',
                'student__name', 'student__student_id'
            ):
                req['request_id'] = str(req['request_id'])  # Convert UUID to string
                pending_maintenance_requests.append(req)
            
            requests_data = {
                'guest_requests': pending_guest_requests,
                'absence_requests': pending_absence_requests,
                'maintenance_requests': pending_maintenance_requests,
                'total_count': len(pending_guest_requests) + len(pending_absence_requests) + len(pending_maintenance_requests)
            }
            
            # Cache the results
            cache.set(cache_key, requests_data, self.CACHE_TIMEOUT_REQUESTS)
            logger.debug(f"Pending requests cached: {requests_data['total_count']} total")
            
            return requests_data
            
        except Exception as e:
            logger.error(f"Error getting pending requests: {e}")
            return {'guest_requests': [], 'absence_requests': [], 'maintenance_requests': [], 'total_count': 0}
    
    def get_recent_activity(self, force_refresh: bool = False) -> List[Dict[str, Any]]:
        """
        Get recent activity with caching - generates crisp, descriptive activity messages.
        
        Args:
            force_refresh: If True, bypass cache
            
        Returns:
            List of recent activity items with clear descriptions
        """
        cache_key = self.CACHE_KEY_RECENT_ACTIVITY
        
        if not force_refresh:
            cached_activity = cache.get(cache_key)
            if cached_activity:
                logger.debug("Using cached recent activity")
                return cached_activity
        
        try:
            # Get recent messages with intent information
            recent_messages = list(Message.objects.filter(
                status='processed'
            ).select_related('sender').order_by('-created_at')[:8].values(
                'id', 'content', 'created_at', 'extracted_intent',
                'sender__name', 'sender__room_number'
            ))
            
            # Get recent maintenance requests
            recent_maintenance = list(MaintenanceRequest.objects.filter(
                created_at__gte=timezone.now() - timedelta(hours=24)
            ).select_related('student').order_by('-created_at')[:5].values(
                'id', 'description', 'issue_type', 'priority', 'created_at',
                'student__name', 'student__room_number'
            ))
            
            # Get recent guest approvals/rejections
            recent_guest_approvals = list(GuestRequest.objects.filter(
                status__in=['approved', 'rejected'],
                updated_at__gte=timezone.now() - timedelta(hours=24)
            ).select_related('student').order_by('-updated_at')[:3].values(
                'id', 'guest_name', 'status', 'updated_at',
                'student__name', 'student__room_number'
            ))
            
            # Get recent absence approvals/rejections
            recent_absence_approvals = list(AbsenceRecord.objects.filter(
                status__in=['approved', 'rejected'],
                updated_at__gte=timezone.now() - timedelta(hours=24)
            ).select_related('student').order_by('-updated_at')[:3].values(
                'id', 'status', 'start_date', 'end_date', 'updated_at',
                'student__name', 'student__room_number'
            ))
            
            # Combine and format activity
            activity = []
            
            # Helper function to generate crisp message descriptions
            def get_message_description(intent, sender_name):
                """Generate descriptive activity text based on message intent."""
                if not intent:
                    return f"{sender_name} sent a message"
                
                intent_lower = intent.lower()
                
                # Map common intents to crisp descriptions
                intent_map = {
                    'maintenance': f"{sender_name} requested maintenance",
                    'guest': f"{sender_name} requested guest permission",
                    'leave': f"{sender_name} requested leave/absence",
                    'complaint': f"{sender_name} filed a complaint",
                    'help': f"{sender_name} requested help",
                    'complaint_feedback': f"{sender_name} submitted feedback",
                    'inquiry': f"{sender_name} made an inquiry",
                    'permission': f"{sender_name} requested permission",
                    'issue': f"{sender_name} reported an issue",
                    'problem': f"{sender_name} reported a problem"
                }
                
                # Check for partial matches
                for key, value in intent_map.items():
                    if key in intent_lower:
                        return value
                
                # Default fallback
                return f"{sender_name} sent a message"
            
            # Add messages with crisp descriptions
            for msg in recent_messages:
                description = get_message_description(msg['extracted_intent'], msg['sender__name'])
                activity.append({
                    'type': 'message',
                    'description': description,
                    'details': msg['content'][:80] + '...' if len(msg['content']) > 80 else msg['content'],
                    'timestamp': msg['created_at'],
                    'student': msg['sender__name'],
                    'room': msg['sender__room_number']
                })
            
            # Add maintenance requests
            for maintenance in recent_maintenance:
                priority_indicator = f"[{maintenance['priority'].upper()}]" if maintenance['priority'] else ""
                activity.append({
                    'type': 'maintenance',
                    'description': f"{maintenance['student__name']} reported {maintenance['issue_type'].lower()} {priority_indicator}".strip(),
                    'details': maintenance['description'][:80] + '...' if len(maintenance['description']) > 80 else maintenance['description'],
                    'timestamp': maintenance['created_at'],
                    'student': maintenance['student__name'],
                    'room': maintenance['student__room_number']
                })
            
            # Add guest approvals
            for approval in recent_guest_approvals:
                action = "approved guest request" if approval['status'] == 'approved' else "rejected guest request"
                activity.append({
                    'type': 'guest_approval',
                    'description': f"{approval['student__name']} {action}",
                    'details': f"Guest: {approval['guest_name']}",
                    'timestamp': approval['updated_at'],
                    'student': approval['student__name'],
                    'room': approval['student__room_number'],
                    'status': approval['status']
                })
            
            # Add absence approvals
            for approval in recent_absence_approvals:
                action = "approved leave request" if approval['status'] == 'approved' else "rejected leave request"
                activity.append({
                    'type': 'absence_approval',
                    'description': f"{approval['student__name']} {action}",
                    'details': f"Duration: {approval['start_date']} to {approval['end_date']}",
                    'timestamp': approval['updated_at'],
                    'student': approval['student__name'],
                    'room': approval['student__room_number'],
                    'status': approval['status']
                })
            
            # Sort by timestamp and limit to 10 most recent
            activity.sort(key=lambda x: x['timestamp'], reverse=True)
            activity = activity[:10]
            
            # Cache the results
            cache.set(cache_key, activity, self.CACHE_TIMEOUT_ACTIVITY)
            logger.debug(f"Recent activity cached: {len(activity)} items")
            
            return activity
            
        except Exception as e:
            logger.error(f"Error getting recent activity: {e}")
            return []
    
    def get_daily_summary(self, force_refresh: bool = False) -> Dict[str, Any]:
        """
        Get daily summary with caching.
        
        Args:
            force_refresh: If True, bypass cache
            
        Returns:
            Dictionary containing daily summary
        """
        cache_key = self.CACHE_KEY_DAILY_SUMMARY
        
        if not force_refresh:
            cached_summary = cache.get(cache_key)
            if cached_summary:
                logger.debug("Using cached daily summary")
                return cached_summary
        
        try:
            today = timezone.now().date()
            
            # Today's statistics
            todays_guest_requests = GuestRequest.objects.filter(created_at__date=today).count()
            todays_absence_requests = AbsenceRecord.objects.filter(created_at__date=today).count()
            todays_maintenance_requests = MaintenanceRequest.objects.filter(created_at__date=today).count()
            todays_messages = Message.objects.filter(created_at__date=today).count()
            
            # Approvals today
            todays_approvals = (
                GuestRequest.objects.filter(updated_at__date=today, status='approved').count() +
                AbsenceRecord.objects.filter(updated_at__date=today, status='approved').count()
            )
            
            # Current status
            stats = self.get_statistics(force_refresh=True)  # Get fresh stats for summary
            
            summary = {
                'date': today.isoformat(),
                'students_present': stats['present_students'],
                'students_absent': stats['absent_students'],
                'active_guests': stats['active_guests'],
                'occupancy_rate': stats['occupancy_rate'],
                'todays_activity': {
                    'guest_requests': todays_guest_requests,
                    'absence_requests': todays_absence_requests,
                    'maintenance_requests': todays_maintenance_requests,
                    'messages': todays_messages,
                    'approvals': todays_approvals
                },
                'pending_items': {
                    'guest_requests': stats['pending_guest_requests'],
                    'absence_requests': stats['pending_absence_requests'],
                    'maintenance_requests': stats['pending_maintenance_requests'],
                    'high_priority_maintenance': stats['high_priority_maintenance']
                },
                'generated_at': timezone.now().isoformat()
            }
            
            # Cache the results
            cache.set(cache_key, summary, self.CACHE_TIMEOUT_SUMMARY)
            logger.info(f"Daily summary generated and cached for {today}")
            
            return summary
            
        except Exception as e:
            logger.error(f"Error generating daily summary: {e}")
            return {
                'date': timezone.now().date().isoformat(),
                'error': 'Failed to generate summary',
                'generated_at': timezone.now().isoformat()
            }
    
    def invalidate_cache(self, cache_type: Optional[str] = None):
        """
        Invalidate dashboard cache.
        
        Args:
            cache_type: Specific cache to invalidate, or None for all
        """
        if cache_type is None:
            # Invalidate all caches
            cache.delete_many([
                self.CACHE_KEY_STATS,
                self.CACHE_KEY_PENDING_REQUESTS,
                self.CACHE_KEY_RECENT_ACTIVITY,
                self.CACHE_KEY_DAILY_SUMMARY
            ])
            logger.info("All dashboard caches invalidated")
        else:
            cache_keys = {
                'stats': self.CACHE_KEY_STATS,
                'requests': self.CACHE_KEY_PENDING_REQUESTS,
                'activity': self.CACHE_KEY_RECENT_ACTIVITY,
                'summary': self.CACHE_KEY_DAILY_SUMMARY
            }
            
            if cache_type in cache_keys:
                cache.delete(cache_keys[cache_type])
                logger.info(f"Dashboard {cache_type} cache invalidated")
    
    def get_students_present_details(self) -> Dict[str, Any]:
        """
        Get detailed information about students currently present.
        
        Returns:
            Dictionary with present students details
        """
        try:
            now = timezone.now()
            
            # Get all students
            all_students = Student.objects.all()
            
            # Get students who are currently absent
            absent_student_ids = AbsenceRecord.objects.filter(
                status='approved',
                start_date__lte=now,
                end_date__gte=now
            ).values_list('student_id', flat=True)
            
            # Students present = All students - Currently absent
            present_students = all_students.exclude(id__in=absent_student_ids)
            
            # Get guests for present students
            present_students_with_guests = present_students.prefetch_related(
                'guest_requests'
            ).annotate(
                active_guests_count=Count(
                    'guest_requests',
                    filter=Q(
                        guest_requests__status='approved',
                        guest_requests__start_date__lte=now,
                        guest_requests__end_date__gte=now
                    )
                )
            )
            
            present_students_data = []
            for student in present_students_with_guests:
                present_students_data.append({
                    'student_id': student.student_id,
                    'name': student.name,
                    'room_number': student.room_number,
                    'block': student.block,
                    'active_guests': student.active_guests_count,
                    'phone': student.phone,
                    'parent_phone': student.parent_phone
                })
            
            return {
                'total_present': len(present_students_data),
                'students': present_students_data,
                'calculated_at': now.isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error getting present students details: {e}")
            return {
                'total_present': 0,
                'students': [],
                'error': str(e),
                'calculated_at': timezone.now().isoformat()
            }
    
    def get_maintenance_overview(self, force_refresh: bool = False) -> Dict[str, Any]:
        """
        Get comprehensive maintenance overview for warden dashboard.
        
        Args:
            force_refresh: If True, bypass cache
            
        Returns:
            Dictionary containing maintenance overview data
        """
        cache_key = 'dashboard_maintenance_overview'
        
        if not force_refresh:
            cached_data = cache.get(cache_key)
            if cached_data:
                logger.debug("Using cached maintenance overview")
                return cached_data
        
        try:
            now = timezone.now()
            today = now.date()
            
            # Status counts
            pending_count = MaintenanceRequest.objects.filter(status='pending').count()
            assigned_count = MaintenanceRequest.objects.filter(status='assigned').count()
            in_progress_count = MaintenanceRequest.objects.filter(status='in_progress').count()
            
            # Today's completed
            completed_today = MaintenanceRequest.objects.filter(
                status='completed',
                actual_completion__date=today
            ).count()
            
            # Priority breakdown for active requests
            priority_stats = {
                'emergency': MaintenanceRequest.objects.filter(
                    priority='emergency',
                    status__in=['pending', 'assigned', 'in_progress']
                ).count(),
                'high': MaintenanceRequest.objects.filter(
                    priority='high',
                    status__in=['pending', 'assigned', 'in_progress']
                ).count(),
                'medium': MaintenanceRequest.objects.filter(
                    priority='medium',
                    status__in=['pending', 'assigned', 'in_progress']
                ).count(),
                'low': MaintenanceRequest.objects.filter(
                    priority='low',
                    status__in=['pending', 'assigned', 'in_progress']
                ).count()
            }
            
            # Issue type breakdown for active requests
            issue_type_stats = {}
            for issue_type in ['electrical', 'plumbing', 'hvac', 'furniture', 'cleaning', 'other']:
                issue_type_stats[issue_type] = MaintenanceRequest.objects.filter(
                    issue_type=issue_type,
                    status__in=['pending', 'assigned', 'in_progress']
                ).count()
            
            # Recent urgent requests
            urgent_requests = list(MaintenanceRequest.objects.filter(
                priority__in=['emergency', 'high'],
                status__in=['pending', 'assigned', 'in_progress']
            ).select_related('student', 'assigned_to').order_by('-created_at')[:5].values(
                'request_id', 'room_number', 'issue_type', 'priority', 'status', 'description',
                'created_at', 'student__name', 'assigned_to__name'
            ))
            
            # Convert UUIDs to strings
            for req in urgent_requests:
                req['request_id'] = str(req['request_id'])
                req['created_at'] = req['created_at'].isoformat()
            
            overview = {
                'status_counts': {
                    'pending': pending_count,
                    'assigned': assigned_count,
                    'in_progress': in_progress_count,
                    'total_active': pending_count + assigned_count + in_progress_count,
                    'completed_today': completed_today
                },
                'priority_breakdown': priority_stats,
                'issue_type_breakdown': issue_type_stats,
                'urgent_requests': urgent_requests,
                'last_updated': now.isoformat()
            }
            
            # Cache for 2 minutes
            cache.set(cache_key, overview, 120)
            logger.debug("Maintenance overview calculated and cached")
            
            return overview
            
        except Exception as e:
            logger.error(f"Error getting maintenance overview: {e}")
            return {
                'status_counts': {
                    'pending': 0,
                    'assigned': 0,
                    'in_progress': 0,
                    'total_active': 0,
                    'completed_today': 0
                },
                'priority_breakdown': {'emergency': 0, 'high': 0, 'medium': 0, 'low': 0},
                'issue_type_breakdown': {},
                'urgent_requests': [],
                'error': str(e),
                'last_updated': timezone.now().isoformat()
            }
    
    def _get_fallback_stats(self) -> Dict[str, Any]:
        """Get fallback statistics when calculation fails."""
        return {
            'total_students': 0,
            'present_students': 0,
            'absent_students': 0,
            'active_guests': 0,
            'total_pending_requests': 0,
            'pending_guest_requests': 0,
            'pending_absence_requests': 0,
            'pending_maintenance_requests': 0,
            'high_priority_maintenance': 0,
            'todays_messages': 0,
            'todays_requests': 0,
            'occupancy_rate': 0.0,
            'availability_rate': 0.0,
            'last_updated': timezone.now().isoformat(),
            'calculation_date': timezone.now().date().isoformat(),
            'error': 'Failed to calculate statistics'
        }
    
    def _get_fallback_data(self) -> Dict[str, Any]:
        """Get fallback data when dashboard data fails."""
        return {
            'stats': self._get_fallback_stats(),
            'pending_requests': {'guest_requests': [], 'absence_requests': [], 'maintenance_requests': [], 'total_count': 0},
            'recent_activity': [],
            'daily_summary': {
                'date': timezone.now().date().isoformat(),
                'error': 'Failed to generate data',
                'generated_at': timezone.now().isoformat()
            }
        }


# Global instance
dashboard_service = DashboardService()