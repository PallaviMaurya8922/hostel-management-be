"""
Views for the AI-Powered Hostel Coordination System.
REST API endpoints for message processing, request management, and system monitoring.
"""

import logging
import secrets
import threading
from dataclasses import asdict
from datetime import datetime, date
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.utils import timezone
from django.shortcuts import get_object_or_404, render
from django.contrib.auth.decorators import login_required
from django.core.exceptions import ValidationError
from django.http import HttpResponse, Http404
from django.conf import settings
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.viewsets import ModelViewSet, ReadOnlyModelViewSet
from rest_framework.decorators import action
from rest_framework.exceptions import NotAuthenticated, PermissionDenied
from rest_framework.parsers import JSONParser, MultiPartParser, FormParser
from django.db.models import Q

from .models import Student, Staff, Message, GuestRequest, AbsenceRecord, MaintenanceRequest, AuditLog, DigitalPass, SecurityRecord, NoticeBoard, Notification
from .serializers import (
    StudentSerializer, StaffSerializer, MessageSerializer, MessageCreateSerializer,
    GuestRequestSerializer, AbsenceRecordSerializer, MaintenanceRequestSerializer,
    AuditLogSerializer, MessageProcessingResponseSerializer, HealthCheckSerializer,
    SystemInfoSerializer, StaffQuerySerializer, StaffQueryResponseSerializer,
    DailySummarySerializer, RequestApprovalSerializer, ConversationContextSerializer,
    NoticeBoardSerializer, NotificationSerializer
)
from .authentication import (
    IsStudentOrStaff, IsStaffOnly, IsStudentOnly, HasStaffRole, 
    CanApproveRequests, CanAccessOwnDataOnly
)
from .security import (
    InputValidator, DataProtection, SecurityAuditLogger, validate_input
)
from .services.dashboard_service import dashboard_service
from .services.supabase_service import supabase_service
from .services.daily_summary_service import daily_summary_generator as daily_summary_service
from .services.leave_request_service import leave_request_service
from .services.qr_image_service import qr_image_service
from .authentication import get_authenticated_user
from .utils import get_or_create_dev_staff, get_staff_from_request_or_dev, build_pass_history_query, format_pass_history_records

logger = logging.getLogger(__name__)

# Alias for backward compatibility - use get_authenticated_user directly in new code
get_user_from_request = get_authenticated_user


def generate_qr_for_guest(guest_request: GuestRequest) -> str:
    """Generate and persist a QR token + image for approved guest requests."""
    if guest_request.qr_token:
        return guest_request.qr_token

    token = secrets.token_urlsafe(32)
    guest_request.qr_token = token
    guest_request.qr_generated_at = timezone.now()
    
    # Generate QR image
    try:
        qr_result = qr_image_service.generate_qr_image(
            data=token,
            filename_prefix=f"guest_qr_{guest_request.request_id}_"
        )
        if qr_result['success']:
            guest_request.qr_image_path = qr_result['file_path']
            logger.info(f"QR image generated for guest {guest_request.request_id}: {qr_result['file_path']}")
        else:
            logger.warning(f"Failed to generate QR image for guest {guest_request.request_id}: {qr_result['error']}")
    except Exception as e:
        logger.warning(f"Exception during QR image generation for guest {guest_request.request_id}: {str(e)}")
    
    guest_request.save(update_fields=['qr_token', 'qr_generated_at', 'qr_image_path', 'updated_at'])
    return token


def notify_security_guest_approval_async(guest_request_id: str, approved_by_id: str | None = None) -> None:
    """Notify security in the background so approval API remains fast."""

    def _worker() -> None:
        try:
            guest_request = GuestRequest.objects.select_related('student').get(request_id=guest_request_id)
            approved_by = None

            if approved_by_id:
                approved_by = Staff.objects.filter(staff_id=approved_by_id).first()

            from .services.notification_service import notification_service

            results = notification_service.notify_security_guest_approval(
                guest_request=guest_request,
                student=guest_request.student,
                approved_by=approved_by,
            )

            delivered = sum(1 for staff_results in results.values() if any(r.success for r in staff_results))
            logger.info(
                "Security guest notification completed for %s: %s successful deliveries",
                guest_request_id,
                delivered,
            )
        except Exception as exc:
            logger.warning(
                "Security guest notification failed for %s: %s",
                guest_request_id,
                exc,
            )

    threading.Thread(target=_worker, daemon=True).start()


@method_decorator(csrf_exempt, name='dispatch')
class MessageViewSet(ModelViewSet):
    """ViewSet for managing messages and message processing."""
    
    queryset = Message.objects.all().order_by('-created_at')
    serializer_class = MessageSerializer
    permission_classes = [AllowAny]  # Allow unauthenticated access for development
    
    def get_queryset(self):
        """Filter queryset based on user type."""
        if hasattr(self.request.user, 'user_type'):
            if self.request.user.user_type == 'student':
                # Students can only see their own messages
                return self.queryset.filter(sender=self.request.user.user_object)
            elif self.request.user.user_type == 'staff':
                # Staff can see all messages
                return self.queryset
        logger.warning("No authenticated user - returning all (DEV)")
        return self.queryset
    
    def get_serializer_class(self):
        """Return appropriate serializer based on action."""
        if self.action == 'create':
            return MessageCreateSerializer
        return MessageSerializer


class GuestRequestViewSet(ModelViewSet):
    """ViewSet for managing guest requests."""

    queryset = GuestRequest.objects.all().order_by('-created_at')
    serializer_class = GuestRequestSerializer
    permission_classes = [AllowAny]

    def perform_create(self, serializer):
        """Attach the logged-in student; `student` and `status` are read-only on the serializer."""
        user_object, _ = get_authenticated_user(self.request)
        if user_object is None:
            raise NotAuthenticated('Sign in as a student to submit a guest request.')
        if not isinstance(user_object, Student):
            raise PermissionDenied(
                'Only students can create guest requests through this endpoint.'
            )
        guest_request = serializer.save(student=user_object)
        if guest_request.visit_type == 'normal':
            guest_request.status = 'approved'
            guest_request.auto_approved = True
            guest_request.approval_reason = 'Auto-approved: normal day visit'
            guest_request.save(
                update_fields=['status', 'auto_approved', 'approval_reason', 'updated_at']
            )
            generate_qr_for_guest(guest_request)
            notify_security_guest_approval_async(str(guest_request.request_id), None)


class AbsenceRecordViewSet(ModelViewSet):
    """ViewSet for managing absence records."""

    queryset = AbsenceRecord.objects.all().order_by('-created_at')
    serializer_class = AbsenceRecordSerializer
    permission_classes = [AllowAny]


class MaintenanceRequestViewSet(ModelViewSet):
    """ViewSet for managing maintenance requests."""

    queryset = MaintenanceRequest.objects.all().order_by('-created_at')
    serializer_class = MaintenanceRequestSerializer
    permission_classes = [AllowAny]
    parser_classes = [MultiPartParser, FormParser, JSONParser]

    def perform_create(self, serializer):
        """Attach the logged-in student; `student` is read-only on the serializer."""
        user_object, _ = get_authenticated_user(self.request)
        if user_object is None:
            raise NotAuthenticated('Sign in as a student to submit a maintenance request.')
        if not isinstance(user_object, Student):
            raise PermissionDenied(
                'Only students can create maintenance requests through this endpoint.'
            )
        serializer.save(student=user_object)


class StudentViewSet(ReadOnlyModelViewSet):
    """Read-only student information."""

    queryset = Student.objects.all().order_by('student_id')
    serializer_class = StudentSerializer
    permission_classes = [AllowAny]
    lookup_field = 'student_id'
    lookup_url_kwarg = 'pk'


class StaffViewSet(ReadOnlyModelViewSet):
    """Read-only staff information."""

    queryset = Staff.objects.all().order_by('staff_id')
    serializer_class = StaffSerializer
    permission_classes = [AllowAny]


class AuditLogViewSet(ReadOnlyModelViewSet):
    """Read-only audit logs."""

    queryset = AuditLog.objects.all().order_by('-timestamp')
    serializer_class = AuditLogSerializer
    permission_classes = [AllowAny]


class NoticeBoardViewSet(ModelViewSet):
    """ViewSet for notice board management."""

    queryset = NoticeBoard.objects.all().order_by('-created_at')
    serializer_class = NoticeBoardSerializer
    permission_classes = [AllowAny]
    lookup_field = 'notice_id'
    lookup_url_kwarg = 'pk'

    def get_queryset(self):
        user_object, _ = get_authenticated_user(self.request)
        queryset = NoticeBoard.objects.all().order_by('-created_at')

        if isinstance(user_object, Student):
            return queryset.filter(is_active=True, target_audience='student')

        if isinstance(user_object, Staff):
            if user_object.role == 'security':
                return queryset.filter(is_active=True, target_audience='security')
            if user_object.role in ['warden', 'admin']:
                return queryset

        return queryset.none()

    def perform_create(self, serializer):
        user_object, _ = get_authenticated_user(self.request)

        if isinstance(user_object, Staff):
            notice = serializer.save(warden=user_object)

            try:
                metadata = {
                    'notice_id': str(notice.notice_id),
                    'target_audience': notice.target_audience,
                }

                if notice.target_audience == 'security':
                    security_staff = Staff.objects.filter(role='security', is_active=True)
                    for staff_member in security_staff:
                        Notification.objects.create(
                            recipient_staff=staff_member,
                            title=notice.title,
                            message=notice.content,
                            type='notice',
                            priority='high',
                            action_url='/security/notice-board',
                            metadata=metadata,
                        )
                else:
                    students = Student.objects.all()
                    for student in students:
                        Notification.objects.create(
                            recipient_student=student,
                            title=notice.title,
                            message=notice.content,
                            type='notice',
                            priority='medium',
                            action_url='/student/notice-board',
                            metadata=metadata,
                        )
            except Exception as exc:
                logger.warning(
                    'Notice notification delivery failed for notice %s: %s',
                    notice.notice_id,
                    exc,
                )
            return

        serializer.save()


class NotificationViewSet(ModelViewSet):
    """ViewSet for in-app notifications."""

    queryset = Notification.objects.all().order_by('-created_at')
    serializer_class = NotificationSerializer
    permission_classes = [AllowAny]
    lookup_field = 'notification_id'
    lookup_url_kwarg = 'pk'

    def get_queryset(self):
        user_object, _ = get_authenticated_user(self.request)

        if isinstance(user_object, Staff) and user_object.role == 'admin':
            return Notification.objects.none()
        
        # Filter by recipient type
        if isinstance(user_object, Student):
            return Notification.objects.filter(recipient_student=user_object).order_by('-created_at')
        elif isinstance(user_object, Staff):
            return Notification.objects.filter(recipient_staff=user_object).order_by('-created_at')
        
        return Notification.objects.none()
    
    @action(detail=False, methods=['get'])
    def unread_count(self, request):
        """Get count of unread notifications."""
        unread = self.get_queryset().filter(is_read=False).count()
        return Response({'unread_count': unread})
    
    @action(detail=True, methods=['post'])
    def mark_read(self, request, notification_id=None):
        """Mark a single notification as read."""
        notification = self.get_object()
        notification.is_read = True
        notification.read_at = timezone.now()
        notification.save()
        serializer = self.get_serializer(notification)
        return Response(serializer.data)
    
    @action(detail=False, methods=['post'])
    def mark_all_read(self, request):
        """Mark all notifications as read for the current user."""
        queryset = self.get_queryset()
        unread_count = queryset.filter(is_read=False).count()
        queryset.filter(is_read=False).update(is_read=True, read_at=timezone.now())
        return Response({'marked_as_read': unread_count})


@api_view(['POST'])
@permission_classes([AllowAny])  # Allow for development
def staff_query(request):
    """Staff query endpoint has been removed."""
    return Response(
        {
            'success': False,
            'error': 'Staff query processing has been removed',
        },
        status=status.HTTP_410_GONE,
    )


@api_view(['GET'])
@permission_classes([AllowAny])
def daily_summary(request):
    """Get daily summary for a specific date."""
    date_str = request.query_params.get('date')
    if date_str:
        try:
            summary_date = datetime.strptime(date_str, '%Y-%m-%d')
        except ValueError:
            return Response(
                {'error': 'Invalid date format. Use YYYY-MM-DD'},
                status=status.HTTP_400_BAD_REQUEST,
            )
    else:
        summary_date = datetime.now()

    try:
        summary_data = daily_summary_service.generate_morning_summary(summary_date)
        return Response(asdict(summary_data), status=status.HTTP_200_OK)
    except Exception as e:
        logger.error(f"Error generating daily summary: {e}")
        return Response(
            {
                'error': 'Failed to generate daily summary',
                'details': str(e),
            },
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@api_view(['GET'])
@permission_classes([AllowAny])
def conversation_status(request):
    """Get status of active follow-up conversations."""
    # Simplified - return empty conversations since followup bot is simplified
    return Response({
        'total_conversations': 0,
        'conversations': []
    })


@api_view(['GET'])
@permission_classes([AllowAny])
def debug_auth_status(request):
    """Debug endpoint to check authentication status."""
    session_user_id = request.session.get('user_id')
    session_user_type = request.session.get('user_type')
    
    from .authentication import get_authenticated_user
    user_object, auth_type = get_authenticated_user(request)
    
    logger.info(f"DEBUG: session_user_id={session_user_id}, session_user_type={session_user_type}, auth_type={auth_type}, user_object={user_object}")
    
    return Response({
        'session': {
            'user_id': session_user_id,
            'user_type': session_user_type,
            'session_keys': list(request.session.keys())
        },
        'authenticated_user': {
            'user_object': str(user_object) if user_object else None,
            'auth_type': auth_type
        },
        'request_user': {
            'is_authenticated': request.user.is_authenticated,
            'user': str(request.user)
        }
    })


@api_view(['GET'])
@permission_classes([AllowAny])
def health_check(request):
    """
    Health check endpoint to verify system status.
    Returns the status of all major system components.
    """
    try:
        health_status = {
            "status": "healthy",
            "timestamp": timezone.now().isoformat(),
            "services": {
                "django": "healthy",
                "supabase": "healthy" if supabase_service.is_configured() else "not_configured",
                "daily_summary": "healthy"
            },
            "version": "1.0.0"
        }
        
        # Determine overall status
        if not supabase_service.is_configured():
            health_status["status"] = "degraded"
            
        return Response(health_status, status=status.HTTP_200_OK)
        
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return Response({
            "status": "unhealthy",
            "error": str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([AllowAny])  # Allow for development
def approve_request(request):
    """Approve a pending request (guest, absence, or maintenance)."""
    request_type = request.data.get('request_type')
    request_id = request.data.get('request_id')
    reason = request.data.get('reason', 'Approved by staff')
    
    if not request_type or not request_id:
        return Response({'error': 'request_type and request_id required'}, 
                      status=status.HTTP_400_BAD_REQUEST)
    
    try:
        # Get authenticated staff or use default for development
        staff_member = get_staff_from_request_or_dev(request)
        
        if request_type == 'guest':
            guest_request = get_object_or_404(GuestRequest, request_id=request_id)

            if guest_request.visit_type != 'overnight':
                return Response(
                    {'error': 'Normal visits do not require approval'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            if guest_request.status == 'approved':
                return Response({
                    'success': True,
                    'message': f'Guest request for {guest_request.guest_name} is already approved',
                    'request': GuestRequestSerializer(guest_request).data
                })

            if guest_request.status == 'rejected':
                return Response(
                    {'error': 'Rejected guest requests cannot be approved'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            guest_request.status = 'approved'
            guest_request.approved_by = staff_member
            guest_request.approval_reason = reason
            guest_request.save()
            generate_qr_for_guest(guest_request)
            notify_security_guest_approval_async(guest_request.request_id, staff_member.staff_id)
            
            # Invalidate dashboard cache
            dashboard_service.invalidate_cache()
            
            return Response({
                'success': True,
                'message': f'Guest request for {guest_request.guest_name} approved',
                'qr_generated': bool(guest_request.qr_token),
                'request': GuestRequestSerializer(guest_request).data
            })
            
        elif request_type == 'absence':
            absence_request = get_object_or_404(AbsenceRecord, absence_id=request_id)
            absence_request.status = 'approved'
            absence_request.approved_by = staff_member
            absence_request.approval_reason = reason
            absence_request.save()
            
            # Invalidate dashboard cache
            dashboard_service.invalidate_cache()
            
            return Response({
                'success': True,
                'message': f'Absence request for {absence_request.student.name} approved',
                'request': AbsenceRecordSerializer(absence_request).data
            })
            
        elif request_type == 'maintenance':
            maintenance_request = get_object_or_404(MaintenanceRequest, request_id=request_id)
            maintenance_request.status = 'assigned'
            maintenance_request.assigned_to = staff_member
            maintenance_request.save()
            
            # Invalidate dashboard cache
            dashboard_service.invalidate_cache()
            
            return Response({
                'success': True,
                'message': f'Maintenance request assigned',
                'request': MaintenanceRequestSerializer(maintenance_request).data
            })
            
        else:
            return Response({'error': 'Invalid request_type'}, 
                          status=status.HTTP_400_BAD_REQUEST)
            
    except Exception as e:
        logger.error(f"Error approving request: {e}")
        return Response({'error': f'Failed to approve request: {str(e)}'}, 
                      status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([AllowAny])  # Allow for development
def reject_request(request):
    """Reject a pending request (guest, absence, or maintenance)."""
    request_type = request.data.get('request_type')
    request_id = request.data.get('request_id')
    reason = request.data.get('reason', 'Rejected by staff')
    
    if not request_type or not request_id:
        return Response({'error': 'request_type and request_id required'}, 
                      status=status.HTTP_400_BAD_REQUEST)
    
    try:
        # Get or create default staff for development
        staff_member, _ = get_or_create_dev_staff()
        
        if request_type == 'guest':
            guest_request = get_object_or_404(GuestRequest, request_id=request_id)

            if guest_request.visit_type != 'overnight':
                return Response(
                    {'error': 'Normal visits do not require rejection workflow'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            guest_request.status = 'rejected'
            guest_request.approved_by = staff_member
            guest_request.approval_reason = reason
            guest_request.save()
            
            # Invalidate dashboard cache
            dashboard_service.invalidate_cache()
            
            return Response({
                'success': True,
                'message': f'Guest request for {guest_request.guest_name} rejected',
                'request': GuestRequestSerializer(guest_request).data
            })
            
        elif request_type == 'absence':
            absence_request = get_object_or_404(AbsenceRecord, absence_id=request_id)
            absence_request.status = 'rejected'
            absence_request.approved_by = staff_member
            absence_request.approval_reason = reason
            absence_request.save()
            
            # Invalidate dashboard cache
            dashboard_service.invalidate_cache()
            
            return Response({
                'success': True,
                'message': f'Absence request for {absence_request.student.name} rejected',
                'request': AbsenceRecordSerializer(absence_request).data
            })
            
        elif request_type == 'maintenance':
            maintenance_request = get_object_or_404(MaintenanceRequest, request_id=request_id)
            maintenance_request.status = 'cancelled'
            maintenance_request.notes = reason
            maintenance_request.save()
            
            # Invalidate dashboard cache
            dashboard_service.invalidate_cache()
            
            return Response({
                'success': True,
                'message': f'Maintenance request cancelled',
                'request': MaintenanceRequestSerializer(maintenance_request).data
            })
            
        else:
            return Response({'error': 'Invalid request_type'}, 
                          status=status.HTTP_400_BAD_REQUEST)
            
    except Exception as e:
        logger.error(f"Error rejecting request: {e}")
        return Response({'error': f'Failed to reject request: {str(e)}'}, 
                      status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([AllowAny])  # Allow for security staff verification
def verify_guest_qr(request, qr_token):
    """Verify a guest QR token and return guest/host details for security verification.
    
    GET /api/guest/verify/{qr_token}/
    
    Returns:
    {
        "valid": true,
        "guest_name": "John Doe",
        "guest_phone": "+919876543210",
        "host_student": "Rahul Kumar",
        "host_room": "A-101",
        "visit_type": "normal",
        "valid_from": "2026-03-22T15:00:00Z",
        "valid_until": "2026-03-23T03:00:00Z",
        "status": "approved",
        "request_id": "REQ123456"
    }
    """
    try:
        guest_request = GuestRequest.objects.get(qr_token=qr_token)
        
        # Check if request is approved
        if guest_request.status != 'approved':
            return Response({
                'valid': False,
                'reason': f'Request status is {guest_request.status}, expected approved',
                'message': 'Guest request not approved'
            }, status=status.HTTP_403_FORBIDDEN)
        
        # Check if token has expired (24 hours from approval)
        now = timezone.now()
        if guest_request.qr_generated_at:
            age = now - guest_request.qr_generated_at
            max_age = timezone.timedelta(hours=24)
            if age > max_age:
                return Response({
                    'valid': False,
                    'reason': 'QR token has expired',
                    'message': 'Valid for 24 hours from approval',
                    'expired_at': (guest_request.qr_generated_at + max_age).isoformat()
                }, status=status.HTTP_403_FORBIDDEN)
        
        # Return verified guest details
        return Response({
            'valid': True,
            'guest_name': guest_request.guest_name,
            'guest_phone': guest_request.guest_phone,
            'host_student': guest_request.student.name,
            'host_student_id': guest_request.student.student_id,
            'host_room': guest_request.student.room_number,
            'visit_type': guest_request.visit_type,
            'visit_purpose': guest_request.purpose,
            'valid_from': guest_request.start_date.isoformat(),
            'valid_until': guest_request.end_date.isoformat(),
            'status': guest_request.status,
            'request_id': guest_request.request_id,
            'verified_at': now.isoformat()
        }, status=status.HTTP_200_OK)
        
    except GuestRequest.DoesNotExist:
        return Response({
            'valid': False,
            'reason': 'Invalid QR token',
            'message': 'Guest request not found'
        }, status=status.HTTP_404_NOT_FOUND)
    
    except Exception as e:
        logger.error(f"Error verifying guest QR: {e}")
        return Response({
            'valid': False,
            'error': str(e),
            'message': 'Failed to verify QR token'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([AllowAny])  # Allow for development
def dashboard_data(request):
    """Get dashboard data for staff interface with caching."""
    try:
        # Check if force refresh is requested
        force_refresh = request.GET.get('refresh', 'false').lower() == 'true'
        
        # Get dashboard data using the service
        result = dashboard_service.get_dashboard_data(force_refresh=force_refresh)
        
        if result['success']:
            return Response(result)
        else:
            return Response(result, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
    except Exception as e:
        logger.error(f"Error in dashboard_data view: {e}")
        return Response({
            'success': False,
            'error': f'Failed to load dashboard data: {str(e)}'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([AllowAny])
def students_present_details(request):
    """Get detailed information about students currently present."""
    try:
        result = dashboard_service.get_students_present_details()
        return Response({
            'success': True,
            'data': result
        })
        
    except Exception as e:
        logger.error(f"Error getting present students details: {e}")
        return Response({
            'success': False,
            'error': f'Failed to get present students details: {str(e)}'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([AllowAny])
def invalidate_dashboard_cache(request):
    """Invalidate dashboard cache for fresh data."""
    try:
        cache_type = request.data.get('cache_type')  # Optional: 'stats', 'requests', 'activity', 'summary'
        dashboard_service.invalidate_cache(cache_type)
        
        return Response({
            'success': True,
            'message': f'Dashboard cache {"(" + cache_type + ")" if cache_type else ""} invalidated successfully'
        })
        
    except Exception as e:
        logger.error(f"Error invalidating dashboard cache: {e}")
        return Response({
            'success': False,
            'error': f'Failed to invalidate cache: {str(e)}'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([AllowAny])  # Allow for development
def submit_leave_request(request):
    """Submit an enhanced leave request with auto-approval logic."""
    try:
        # Get request data
        from_date_str = request.data.get('from_date')
        to_date_str = request.data.get('to_date')
        reason = request.data.get('reason', '').strip()
        emergency_contact = request.data.get('emergency_contact', '').strip()
        
        # Validate required fields
        if not all([from_date_str, to_date_str, reason]):
            return Response({
                'success': False,
                'error': 'From date, to date, and reason are required'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Parse dates
        try:
            from datetime import datetime
            from_date = datetime.strptime(from_date_str, '%Y-%m-%d').date()
            to_date = datetime.strptime(to_date_str, '%Y-%m-%d').date()
        except ValueError:
            return Response({
                'success': False,
                'error': 'Invalid date format. Use YYYY-MM-DD'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Get authenticated student (supports both JWT and session auth)
        from .authentication import get_authenticated_user
        student, auth_type = get_user_from_request(request)
        
        logger.debug(f"Leave request - auth_type: {auth_type}, session_user_id: {request.session.get('user_id')}")
        
        if not student:
            logger.warning(f"Leave request - unauthenticated from {request.META.get('REMOTE_ADDR')}")
            return Response({
                'success': False,
                'error': 'Please log in to submit a leave request'
            }, status=status.HTTP_401_UNAUTHORIZED)
        
        # Process the leave request
        result = leave_request_service.process_leave_request(
            student=student,
            from_date=from_date,
            to_date=to_date,
            reason=reason,
            emergency_contact=emergency_contact if emergency_contact else None
        )
        
        if result.success:
            response_data = {
                'success': True,
                'message': result.message,
                'auto_approved': result.auto_approved,
                'requires_warden_approval': result.requires_warden_approval,
                'absence_record': {
                    'id': str(result.absence_record.absence_id),
                    'status': result.absence_record.status,
                    'from_date': result.absence_record.start_date.date().isoformat(),
                    'to_date': result.absence_record.end_date.date().isoformat(),
                    'total_days': (result.absence_record.end_date.date() - result.absence_record.start_date.date()).days + 1,
                    'reason': result.absence_record.reason
                }
            }
            
            # Add digital pass info if generated
            if result.digital_pass:
                response_data['digital_pass'] = {
                    'pass_number': result.digital_pass.pass_number,
                    'verification_code': result.digital_pass.verification_code,
                    'status': result.digital_pass.status,
                    'from_date': result.digital_pass.from_date.isoformat(),
                    'to_date': result.digital_pass.to_date.isoformat(),
                    'total_days': result.digital_pass.total_days
                }
            
            return Response(response_data, status=status.HTTP_201_CREATED)
        
        else:
            return Response({
                'success': False,
                'error': result.error or result.message
            }, status=status.HTTP_400_BAD_REQUEST)
    
    except Exception as e:
        logger.error(f"Error in submit_leave_request: {e}")
        return Response({
            'success': False,
            'error': 'An error occurred while processing your leave request'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([AllowAny])  # Allow for development
def get_digital_passes(request):
    """Get digital passes for the current student."""
    try:
        # Get authenticated student (supports both JWT and session auth)
        from .authentication import get_authenticated_user
        student, auth_type = get_user_from_request(request)
        
        # Debug logging
        logger.debug(f"Digital passes request - auth_type: {auth_type}, session_user_id: {request.session.get('user_id')}, student: {student}")
        
        if not student:
            logger.warning(f"Digital passes - unauthenticated request from {request.META.get('REMOTE_ADDR')}")
            # Return empty list for unauthenticated users
            return Response({
                'success': True,
                'passes': []
            })
        
        # Filter passes for this student only
        digital_passes = DigitalPass.objects.filter(
            student=student
        ).order_by('-created_at')
        
        passes_data = []
        for pass_obj in digital_passes:
            passes_data.append({
                'pass_number': pass_obj.pass_number,
                'student_name': pass_obj.student.name,  # From pass record (correct student)
                'student_id': pass_obj.student.student_id,  # From pass record (correct student)
                'room_number': pass_obj.student.room_number,  # From pass record (correct student)
                'verification_code': pass_obj.verification_code,
                'from_date': pass_obj.from_date.isoformat(),
                'to_date': pass_obj.to_date.isoformat(),
                'total_days': pass_obj.total_days,
                'reason': pass_obj.reason,
                'status': pass_obj.status,
                'approval_type': pass_obj.approval_type,
                'is_valid': pass_obj.is_valid,
                'days_remaining': pass_obj.days_remaining,
                'created_at': pass_obj.created_at.isoformat()
            })
        
        return Response({
            'success': True,
            'passes': passes_data
        })
    
    except Exception as e:
        logger.error(f"Error in get_digital_passes: {e}")
        return Response({
            'success': False,
            'error': 'An error occurred while fetching digital passes'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET', 'POST'])
@permission_classes([AllowAny])  # Allow for development
def verify_digital_pass(request):
    """Verify a digital pass by pass number."""
    try:
        if request.method == 'GET':
            pass_number = request.query_params.get('pass_number', '').strip()
            verified_by = request.query_params.get('verified_by', 'Security Personnel')
            token = request.query_params.get('token', '').strip()
        else:
            pass_number = request.data.get('pass_number', '').strip()
            verified_by = request.data.get('verified_by', 'Security Personnel')
            token = request.data.get('token', '').strip()
        
        if not pass_number:
            return Response({
                'success': False,
                'error': 'Pass number is required'
            }, status=status.HTTP_400_BAD_REQUEST)

        if token:
            try:
                pass_obj = DigitalPass.objects.get(pass_number=pass_number)
            except DigitalPass.DoesNotExist:
                return Response({
                    'success': False,
                    'verification_result': {
                        'valid': False,
                        'message': 'Pass not found',
                        'error': 'Pass not found'
                    }
                }, status=status.HTTP_404_NOT_FOUND)

            if token != pass_obj.verification_code:
                return Response({
                    'success': False,
                    'verification_result': {
                        'valid': False,
                        'message': 'Invalid verification token',
                        'error': 'Token mismatch'
                    }
                }, status=status.HTTP_403_FORBIDDEN)
        
        # Verify the pass
        verification_result = leave_request_service.verify_digital_pass(pass_number)
        
        # Record verification event if pass exists
        if verification_result.get('valid'):
            try:
                digital_pass = DigitalPass.objects.get(pass_number=pass_number)
                # Update or create security record with verification details
                security_record, created = SecurityRecord.objects.get_or_create(
                    student=digital_pass.student,
                    digital_pass=digital_pass,
                    defaults={
                        'status': 'allowed_to_leave',
                        'verified_by': verified_by,
                        'verification_time': timezone.now(),
                        'notes': f'Pass verified via security dashboard'
                    }
                )
                if not created:
                    # Update existing record with latest verification
                    security_record.verified_by = verified_by
                    security_record.verification_time = timezone.now()
                    security_record.notes = f'Pass re-verified via security dashboard'
                    security_record.save()
                    
                # Add verification timestamp to result
                verification_result['last_verified'] = timezone.now().isoformat()
                verification_result['verified_by'] = verified_by
                
            except DigitalPass.DoesNotExist:
                pass  # Pass not found, already handled in verification_result
        
        return Response({
            'success': True,
            'verification_result': verification_result
        })
    
    except Exception as e:
        logger.error(f"Error in verify_digital_pass: {e}")
        return Response({
            'success': False,
            'error': 'An error occurred while verifying the pass'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([AllowAny])  # Allow for development
def approve_leave_request(request):
    """Approve a pending leave request and generate digital pass."""
    try:
        absence_id = request.data.get('absence_id')
        approval_reason = request.data.get('reason', 'Approved by warden')
        
        if not absence_id:
            return Response({
                'success': False,
                'error': 'absence_id is required'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Get the absence record with UUID validation
        try:
            absence_record = AbsenceRecord.objects.get(absence_id=absence_id)
        except AbsenceRecord.DoesNotExist:
            return Response({
                'success': False,
                'error': 'Leave request not found'
            }, status=status.HTTP_404_NOT_FOUND)
        except (ValueError, ValidationError) as e:
            # Handle UUID validation errors
            return Response({
                'success': False,
                'error': 'Invalid UUID format. Expected format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Get or create default staff for development
        staff_member = get_staff_from_request_or_dev(request)
        
        # Approve the leave request
        result = leave_request_service.approve_leave_request(
            absence_record=absence_record,
            approved_by=staff_member,
            approval_reason=approval_reason
        )
        
        if result.success:
            response_data = {
                'success': True,
                'message': result.message,
                'absence_record': {
                    'id': str(result.absence_record.absence_id),
                    'status': result.absence_record.status,
                    'student_name': result.absence_record.student.name,
                    'from_date': result.absence_record.start_date.date().isoformat(),
                    'to_date': result.absence_record.end_date.date().isoformat(),
                    'total_days': (result.absence_record.end_date.date() - result.absence_record.start_date.date()).days + 1,
                    'reason': result.absence_record.reason,
                    'approved_by': staff_member.name
                }
            }
            
            # Add digital pass info
            if result.digital_pass:
                response_data['digital_pass'] = {
                    'pass_number': result.digital_pass.pass_number,
                    'verification_code': result.digital_pass.verification_code,
                    'status': result.digital_pass.status,
                    'from_date': result.digital_pass.from_date.isoformat(),
                    'to_date': result.digital_pass.to_date.isoformat(),
                    'total_days': result.digital_pass.total_days
                }
            
            # Invalidate dashboard cache
            dashboard_service.invalidate_cache()
            
            return Response(response_data, status=status.HTTP_200_OK)
        
        else:
            return Response({
                'success': False,
                'error': result.error or result.message
            }, status=status.HTTP_400_BAD_REQUEST)
    
    except Exception as e:
        logger.error(f"Error in approve_leave_request: {e}")
        return Response({
            'success': False,
            'error': 'An error occurred while approving the leave request'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([AllowAny])  # Allow for development
def reject_leave_request(request):
    """Reject a pending leave request."""
    try:
        absence_id = request.data.get('absence_id')
        rejection_reason = request.data.get('reason')
        
        if not absence_id:
            return Response({
                'success': False,
                'error': 'absence_id is required'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Validate reason is required for rejection
        if not rejection_reason or not rejection_reason.strip():
            return Response({
                'success': False,
                'error': 'Rejection reason is required'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Get the absence record with UUID validation
        try:
            absence_record = AbsenceRecord.objects.get(absence_id=absence_id)
        except AbsenceRecord.DoesNotExist:
            return Response({
                'success': False,
                'error': 'Leave request not found'
            }, status=status.HTTP_404_NOT_FOUND)
        except (ValueError, ValidationError) as e:
            # Handle UUID validation errors
            return Response({
                'success': False,
                'error': 'Invalid UUID format. Expected format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Get or create default staff for development
        staff_member = get_staff_from_request_or_dev(request)
        
        # Reject the leave request
        result = leave_request_service.reject_leave_request(
            absence_record=absence_record,
            rejected_by=staff_member,
            rejection_reason=rejection_reason
        )
        
        if result.success:
            response_data = {
                'success': True,
                'message': result.message,
                'absence_record': {
                    'id': str(result.absence_record.absence_id),
                    'status': result.absence_record.status,
                    'student_name': result.absence_record.student.name,
                    'from_date': result.absence_record.start_date.date().isoformat(),
                    'to_date': result.absence_record.end_date.date().isoformat(),
                    'total_days': (result.absence_record.end_date.date() - result.absence_record.start_date.date()).days + 1,
                    'reason': result.absence_record.reason,
                    'rejected_by': staff_member.name,
                    'rejection_reason': rejection_reason
                }
            }
            
            # Invalidate dashboard cache
            dashboard_service.invalidate_cache()
            
            return Response(response_data, status=status.HTTP_200_OK)
        
        else:
            return Response({
                'success': False,
                'error': result.error or result.message
            }, status=status.HTTP_400_BAD_REQUEST)
    
    except Exception as e:
        logger.error(f"Error in reject_leave_request: {e}")
        return Response({
            'success': False,
            'error': 'An error occurred while rejecting the leave request'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def download_digital_pass(request, pass_number):
    """Download PDF for a digital pass - requires authentication."""
    try:
        logger.info(f"Attempting to download pass: {pass_number}")
        
        # Get the digital pass
        try:
            logger.info(f"Looking up DigitalPass with pass_number: {pass_number}")
            digital_pass = DigitalPass.objects.get(pass_number=pass_number)
            logger.info(f"Found digital pass: {digital_pass.pass_number}, pdf_generated: {digital_pass.pdf_generated}, pdf_path: {digital_pass.pdf_path}")
        except DigitalPass.DoesNotExist:
            logger.error(f"Digital pass not found for pass_number: {pass_number}")
            return Response({
                'success': False,
                'error': f'Digital pass not found: {pass_number}'
            }, status=status.HTTP_404_NOT_FOUND)
        
        # Check if user has permission to download this pass
        user_obj = request.user.user_object if hasattr(request.user, 'user_object') else None
        
        if not user_obj:
            logger.warning(f"Download attempt with unauthenticated user")
            return Response({
                'success': False,
                'error': 'Authentication required'
            }, status=status.HTTP_401_UNAUTHORIZED)
        
        # Enforce strict permission checking
        user_can_download = False
        if isinstance(user_obj, Student):
            # Students can only download their own valid passes
            user_can_download = (user_obj.student_id == digital_pass.student.student_id)
        elif isinstance(user_obj, Staff):
            # Staff can download any pass
            user_can_download = True
        
        if not user_can_download:
            logger.warning(f"Permission denied for {user_obj}: attempting to download pass {pass_number}")
            return Response({
                'success': False,
                'error': 'Permission denied'
            }, status=status.HTTP_403_FORBIDDEN)
        
        # Validate pass status
        if digital_pass.status != 'active':
            logger.warning(f"Attempt to download inactive pass {pass_number}")
            return Response({
                'success': False,
                'error': f'Pass is {digital_pass.status} and cannot be accessed'
            }, status=status.HTTP_403_FORBIDDEN)
        
        # Get PDF bytes
        pdf_bytes = leave_request_service.get_pass_pdf_bytes(digital_pass)
        
        if not pdf_bytes:
            return Response({
                'success': False,
                'error': 'PDF not available or could not be generated'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        # Detect content type based on file extension or content
        is_html = (digital_pass.pdf_path and digital_pass.pdf_path.endswith('.html')) or \
                  pdf_bytes.startswith(b'<!DOCTYPE html') or pdf_bytes.startswith(b'<html')
        
        # Create HTTP response with appropriate content type
        if is_html:
            response = HttpResponse(pdf_bytes, content_type='text/html')
            filename = f"leave_pass_{digital_pass.pass_number}_{digital_pass.student.student_id}.html"
        else:
            response = HttpResponse(pdf_bytes, content_type='application/pdf')
            filename = f"leave_pass_{digital_pass.pass_number}_{digital_pass.student.student_id}.pdf"
        
        response['Content-Disposition'] = f'attachment; filename="{filename}"'
        response['Content-Length'] = len(pdf_bytes)
        
        return response
    
    except Exception as e:
        logger.error(f"Error downloading digital pass {pass_number}: {e}")
        return Response({
            'success': False,
            'error': 'An error occurred while downloading the pass'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([AllowAny])  # Allow for development
def security_verification_dashboard(request):
    """Render the security verification dashboard."""
    return render(request, 'security/verification_dashboard.html')


@api_view(['GET'])
@permission_classes([AllowAny])  # Allow for development
def get_security_stats(request):
    """Get security statistics for the verification dashboard."""
    try:
        from django.db.models import Q
        from datetime import date
        
        today = timezone.now().date()
        
        # Count active passes (valid today)
        active_passes = DigitalPass.objects.filter(
            status='active',
            from_date__lte=today,
            to_date__gte=today
        ).count()
        
        # Count students currently away (with active passes)
        students_away = SecurityRecord.objects.filter(
            status='allowed_to_leave',
            digital_pass__status='active',
            digital_pass__from_date__lte=today,
            digital_pass__to_date__gte=today
        ).count()
        
        # Count expired passes
        expired_passes = DigitalPass.objects.filter(
            Q(status='expired') | Q(to_date__lt=today)
        ).count()
        
        return Response({
            'success': True,
            'stats': {
                'active_passes': active_passes,
                'students_away': students_away,
                'expired_passes': expired_passes
            }
        })
    
    except Exception as e:
        logger.error(f"Error getting security stats: {e}")
        return Response({
            'success': False,
            'error': 'Failed to load security statistics'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([AllowAny])  # Allow for development
def get_all_active_passes(request):
    """Get all currently active digital passes for security verification."""
    try:
        from datetime import date
        
        today = timezone.now().date()
        
        # Get all active passes
        active_passes = DigitalPass.objects.filter(
            status='active',
            from_date__lte=today,
            to_date__gte=today
        ).select_related('student').order_by('-created_at')
        
        passes_data = []
        for pass_obj in active_passes:
            passes_data.append({
                'pass_number': pass_obj.pass_number,
                'verification_code': pass_obj.verification_code,
                'student_name': pass_obj.student.name,
                'student_id': pass_obj.student.student_id,
                'room_number': pass_obj.student.room_number,
                'block': pass_obj.student.block,
                'from_date': pass_obj.from_date.isoformat(),
                'to_date': pass_obj.to_date.isoformat(),
                'total_days': pass_obj.total_days,
                'reason': pass_obj.reason,
                'days_remaining': pass_obj.days_remaining,
                'approval_type': pass_obj.approval_type,
                'created_at': pass_obj.created_at.isoformat()
            })
        
        return Response({
            'success': True,
            'active_passes': passes_data
        })
    
    except Exception as e:
        logger.error(f"Error getting all active passes: {e}")
        return Response({
            'success': False,
            'error': 'Failed to load active passes'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET', 'POST'])
@permission_classes([AllowAny])  # Allow for development
def search_student_passes(request):
    """Search for student passes by name or ID."""
    try:
        # Support both GET and POST requests
        if request.method == 'GET':
            student_name = request.query_params.get('q', '').strip()
        else:
            student_name = request.data.get('student_name', '').strip() or request.data.get('q', '').strip()
        
        if not student_name:
            return Response({
                'success': False,
                'error': 'Student name or ID is required'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Search for students by name OR student ID (case-insensitive partial match)
        students = Student.objects.filter(
            Q(name__icontains=student_name) | Q(student_id__icontains=student_name)
        ).prefetch_related('digital_passes')[:20]  # Limit results
        
        today = timezone.now().date()
        results = []
        for student in students:
            # Get active passes for this student (valid today)
            active_passes = student.digital_passes.filter(
                status='active',
                from_date__lte=today,
                to_date__gte=today
            ).order_by('-created_at')
            
            has_active_pass = active_passes.exists()
            
            student_data = {
                'student_id': student.student_id,
                'name': student.name,
                'room_number': student.room_number,
                'block': student.block,
                'email': student.email,
                'has_active_pass': has_active_pass,
                'active_passes': []
            }
            
            for pass_obj in active_passes:
                student_data['active_passes'].append({
                    'pass_number': pass_obj.pass_number,
                    'verification_code': pass_obj.verification_code,
                    'from_date': pass_obj.from_date.isoformat(),
                    'to_date': pass_obj.to_date.isoformat(),
                    'total_days': pass_obj.total_days,
                    'reason': pass_obj.reason,
                    'is_valid': pass_obj.is_valid,
                    'days_remaining': pass_obj.days_remaining
                })
            
            results.append(student_data)
        
        return Response({
            'success': True,
            'students': results
        })
    
    except Exception as e:
        logger.error(f"Error searching student passes: {e}")
        return Response({
            'success': False,
            'error': 'Failed to search student passes'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([AllowAny])  # Allow for development
def get_recent_verifications(request):
    """Get recent pass verification history for security dashboard."""
    try:
        # Get recent verifications from the last 24 hours
        since = timezone.now() - timezone.timedelta(hours=24)
        recent_verifications = SecurityRecord.objects.filter(
            verification_time__gte=since
        ).select_related('student', 'digital_pass').order_by('-verification_time')[:10]
        
        verifications_data = []
        for record in recent_verifications:
            verifications_data.append({
                'student_name': record.student.name,
                'student_id': record.student.student_id,
                'pass_number': record.digital_pass.pass_number if record.digital_pass else 'N/A',
                'verified_by': record.verified_by or 'Unknown',
                'verification_time': record.verification_time.isoformat() if record.verification_time else None,
                'status': record.status,
                'notes': record.notes or ''
            })
        
        return Response({
            'success': True,
            'recent_verifications': verifications_data
        })
    
    except Exception as e:
        logger.error(f"Error getting recent verifications: {e}")
        return Response({
            'success': False,
            'error': 'Failed to load recent verifications'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([AllowAny])  # Allow for development
def clear_messages(request):
    """Clear chat messages for a user."""
    try:
        user_id = request.data.get('user_id')
        
        if not user_id:
            return Response({
                'success': False,
                'error': 'user_id is required'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Find messages for this user
        # For development, we'll clear messages based on user context
        messages_deleted = 0
        
        # Try to find student by user_id or name
        try:
            # First try to find by student_id
            student = Student.objects.filter(student_id=user_id).first()
            if not student:
                # Try to find by name (for development users)
                student = Student.objects.filter(name__icontains=user_id.replace('-', ' ')).first()
            
            if student:
                # Delete messages for this student
                messages_to_delete = Message.objects.filter(sender=student)
                messages_deleted = messages_to_delete.count()
                messages_to_delete.delete()
                
                logger.info(f"Cleared {messages_deleted} messages for user {user_id}")
            
        except Exception as e:
            logger.warning(f"Could not find specific user {user_id}, clearing anyway: {e}")
        
        # Log the clear action
        SecurityAuditLogger.log_data_access_event(
            user_id=user_id,
            resource='messages',
            action='clear_chat',
            request=request,
            details={'messages_deleted': messages_deleted}
        )
        
        return Response({
            'success': True,
            'message': f'Chat cleared successfully ({messages_deleted} messages deleted)',
            'messages_deleted': messages_deleted
        })
        
    except Exception as e:
        logger.error(f"Error clearing messages: {e}")
        return Response({
            'success': False,
            'error': 'Failed to clear messages'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([AllowAny])  # Allow for development
def bulk_verify_passes(request):
    """Bulk verify multiple passes at once."""
    try:
        pass_numbers = request.data.get('pass_numbers', [])
        verified_by = request.data.get('verified_by', 'Security Personnel')
        
        if not pass_numbers or not isinstance(pass_numbers, list):
            return Response({
                'success': False,
                'error': 'pass_numbers array is required'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        results = []
        for pass_number in pass_numbers:
            try:
                # Verify each pass
                verification_result = leave_request_service.verify_digital_pass(pass_number.strip())
                
                # Record verification event if pass exists
                if verification_result.get('valid'):
                    try:
                        digital_pass = DigitalPass.objects.get(pass_number=pass_number.strip())
                        # Update or create security record with verification details
                        security_record, created = SecurityRecord.objects.get_or_create(
                            student=digital_pass.student,
                            digital_pass=digital_pass,
                            defaults={
                                'status': 'allowed_to_leave',
                                'verified_by': verified_by,
                                'verification_time': timezone.now(),
                                'notes': f'Pass verified via bulk verification'
                            }
                        )
                        if not created:
                            # Update existing record with latest verification
                            security_record.verified_by = verified_by
                            security_record.verification_time = timezone.now()
                            security_record.notes = f'Pass re-verified via bulk verification'
                            security_record.save()
                            
                        # Add verification timestamp to result
                        verification_result['last_verified'] = timezone.now().isoformat()
                        verification_result['verified_by'] = verified_by
                        
                    except DigitalPass.DoesNotExist:
                        pass  # Pass not found, already handled in verification_result
                
                results.append({
                    'pass_number': pass_number.strip(),
                    'verification_result': verification_result
                })
                
            except Exception as e:
                results.append({
                    'pass_number': pass_number.strip(),
                    'verification_result': {
                        'valid': False,
                        'error': f'Error verifying pass: {str(e)}'
                    }
                })
        
        return Response({
            'success': True,
            'results': results
        })
    
    except Exception as e:
        logger.error(f"Error in bulk_verify_passes: {e}")
        return Response({
            'success': False,
            'error': 'An error occurred during bulk verification'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([AllowAny])  # Allow for development
def export_security_report(request):
    """Export security report with pass verification data."""
    try:
        from datetime import date
        import csv
        from io import StringIO
        
        # Get date range from query parameters
        start_date_str = request.GET.get('start_date')
        end_date_str = request.GET.get('end_date')
        
        if start_date_str:
            try:
                start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date()
            except ValueError:
                start_date = date.today() - timezone.timedelta(days=7)
        else:
            start_date = date.today() - timezone.timedelta(days=7)
            
        if end_date_str:
            try:
                end_date = datetime.strptime(end_date_str, '%Y-%m-%d').date()
            except ValueError:
                end_date = date.today()
        else:
            end_date = date.today()
        
        # Get verification records within date range
        verification_records = SecurityRecord.objects.filter(
            verification_time__date__gte=start_date,
            verification_time__date__lte=end_date
        ).select_related('student', 'digital_pass').order_by('-verification_time')
        
        # Create CSV content
        output = StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow([
            'Date', 'Time', 'Student Name', 'Student ID', 'Room', 'Block',
            'Pass Number', 'Verification Code', 'Verified By', 'Status', 'Notes'
        ])
        
        # Write data rows
        for record in verification_records:
            verification_time = record.verification_time or timezone.now()
            writer.writerow([
                verification_time.strftime('%Y-%m-%d'),
                verification_time.strftime('%H:%M:%S'),
                record.student.name,
                record.student.student_id,
                record.student.room_number,
                record.student.block,
                record.digital_pass.pass_number if record.digital_pass else 'N/A',
                record.digital_pass.verification_code if record.digital_pass else 'N/A',
                record.verified_by or 'Unknown',
                record.status,
                record.notes or ''
            ])
        
        # Create HTTP response
        csv_content = output.getvalue()
        output.close()
        
        response = HttpResponse(csv_content, content_type='text/csv')
        filename = f'security_report_{start_date}_{end_date}.csv'
        response['Content-Disposition'] = f'attachment; filename="{filename}"'
        
        return response
    
    except Exception as e:
        logger.error(f"Error exporting security report: {e}")
        return Response({
            'success': False,
            'error': 'Failed to export security report'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([AllowAny])  # Allow for development
def get_students_by_date_range(request):
    """Get students with passes valid within a specific date range."""
    try:
        start_date_str = request.GET.get('start_date')
        end_date_str = request.GET.get('end_date')
        
        if not start_date_str or not end_date_str:
            return Response({
                'success': False,
                'error': 'start_date and end_date parameters are required (YYYY-MM-DD format)'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date()
            end_date = datetime.strptime(end_date_str, '%Y-%m-%d').date()
        except ValueError:
            return Response({
                'success': False,
                'error': 'Invalid date format. Use YYYY-MM-DD'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Get passes that overlap with the date range
        passes_in_range = DigitalPass.objects.filter(
            status='active',
            from_date__lte=end_date,
            to_date__gte=start_date
        ).select_related('student').order_by('from_date')
        
        students_data = []
        for pass_obj in passes_in_range:
            students_data.append({
                'student_name': pass_obj.student.name,
                'student_id': pass_obj.student.student_id,
                'room_number': pass_obj.student.room_number,
                'block': pass_obj.student.block,
                'pass_number': pass_obj.pass_number,
                'verification_code': pass_obj.verification_code,
                'from_date': pass_obj.from_date.isoformat(),
                'to_date': pass_obj.to_date.isoformat(),
                'total_days': pass_obj.total_days,
                'reason': pass_obj.reason,
                'approval_type': pass_obj.approval_type,
                'is_valid_today': pass_obj.is_valid,
                'days_remaining': pass_obj.days_remaining
            })
        
        return Response({
            'success': True,
            'date_range': {
                'start_date': start_date.isoformat(),
                'end_date': end_date.isoformat()
            },
            'students_with_passes': students_data,
            'total_count': len(students_data)
        })
    
    except Exception as e:
        logger.error(f"Error getting students by date range: {e}")
        return Response({
            'success': False,
            'error': 'Failed to get students by date range'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def view_digital_pass(request, pass_number):
    """View PDF for a digital pass in browser - requires authentication."""
    try:
        logger.info(f"Attempting to view pass: {pass_number}")
        
        # Get the digital pass
        try:
            logger.info(f"Looking up DigitalPass with pass_number: {pass_number}")
            digital_pass = DigitalPass.objects.get(pass_number=pass_number)
            logger.info(f"Found digital pass: {digital_pass.pass_number}, pdf_generated: {digital_pass.pdf_generated}, pdf_path: {digital_pass.pdf_path}")
        except DigitalPass.DoesNotExist:
            logger.error(f"Digital pass not found for pass_number: {pass_number}")
            raise Http404("Digital pass not found")
        
        # Check if user has permission to view this pass
        user_obj = request.user.user_object if hasattr(request.user, 'user_object') else None
        
        if not user_obj:
            logger.warning(f"View attempt with unauthenticated user")
            raise Http404("Permission denied")
        
        # Enforce strict permission checking
        user_can_view = False
        if isinstance(user_obj, Student):
            # Students can only view their own valid passes
            user_can_view = (user_obj.student_id == digital_pass.student.student_id)
        elif isinstance(user_obj, Staff):
            # Staff can view any pass
            user_can_view = True
        
        if not user_can_view:
            logger.warning(f"Permission denied for {user_obj}: attempting to view pass {pass_number}")
            raise Http404("Permission denied")
        
        # Validate pass status
        if digital_pass.status != 'active':
            logger.warning(f"Attempt to view inactive pass {pass_number}")
            raise Http404(f"Pass is {digital_pass.status} and cannot be accessed")
        
        # Get PDF bytes
        pdf_bytes = leave_request_service.get_pass_pdf_bytes(digital_pass)
        
        if not pdf_bytes:
            raise Http404("PDF not available")
        
        # Detect content type based on file extension or content
        is_html = (digital_pass.pdf_path and digital_pass.pdf_path.endswith('.html')) or \
                  pdf_bytes.startswith(b'<!DOCTYPE html') or pdf_bytes.startswith(b'<html')
        
        # Create HTTP response with appropriate content type for viewing
        if is_html:
            response = HttpResponse(pdf_bytes, content_type='text/html')
            filename = f"leave_pass_{digital_pass.pass_number}_{digital_pass.student.student_id}.html"
        else:
            response = HttpResponse(pdf_bytes, content_type='application/pdf')
            filename = f"leave_pass_{digital_pass.pass_number}_{digital_pass.student.student_id}.pdf"
        
        response['Content-Disposition'] = f'inline; filename="{filename}"'
        response['Content-Length'] = len(pdf_bytes)
        
        return response
    
    except Exception as e:
        logger.error(f"Error viewing digital pass {pass_number}: {e}")
        raise Http404("An error occurred while viewing the pass")


@api_view(['GET'])
@permission_classes([AllowAny])
def system_info(request):
    """
    System information endpoint for debugging and monitoring.
    """
    try:
        info = {
            "project": "AI-Powered Hostel Coordination System",
            "version": "1.0.0",
            "django_version": "4.2.7",
            "features": [
                "Natural Language Processing",
                "Auto-Approval Engine", 
                "Follow-up Bot System",
                "Message Routing",
                "Daily Summaries",
                "Comprehensive Audit Logging",
                "Staff Dashboard",
                "Staff Query Interface"
            ],
            "endpoints": {
                "health": "/api/health/",
                "info": "/api/info/",
                "messages": "/api/messages/",
                "guest-requests": "/api/guest-requests/",
                "absence-records": "/api/absence-records/",
                "maintenance-requests": "/api/maintenance-requests/",
                "students": "/api/students/",
                "staff": "/api/staff/",
                "audit-logs": "/api/audit-logs/",
                "staff-query": "/api/staff-query/",
                "daily-summary": "/api/daily-summary/",
                "conversation-status": "/api/conversation-status/",
                "dashboard-data": "/api/dashboard-data/",
                "approve-request": "/api/approve-request/",
                "reject-request": "/api/reject-request/"
            },
            "environment": "development",
            "database_status": "connected"
        }
        
        return Response(info, status=status.HTTP_200_OK)
        
    except Exception as e:
        logger.error(f"System info request failed: {e}")
        return Response({
            "error": "Unable to retrieve system information"
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


def chat_interface(request):
    """
    Render the chat interface template.
    Provides a WhatsApp-like chat experience for students and staff.
    """
    # Get user context for template
    user_context = {}
    
    # Get user information from session
    user_id = request.session.get('user_id')
    user_type = request.session.get('user_type')
    
    if user_id and user_type:
        if user_type == 'student':
            try:
                student = Student.objects.get(student_id=user_id)
                user_context = {
                    'name': student.name,
                    'room_number': student.room_number,
                    'block': student.block,
                    'email': student.email,
                    'user_type': 'student'
                }
            except Student.DoesNotExist:
                user_context = {
                    'name': 'Student',
                    'room_number': '',
                    'block': '',
                    'email': '',
                    'user_type': 'student'
                }
        elif user_type in ['staff', 'warden']:
            try:
                staff = Staff.objects.get(staff_id=user_id)
                user_context = {
                    'name': staff.name,
                    'designation': staff.role.title(),
                    'email': staff.email,
                    'user_type': user_type
                }
            except Staff.DoesNotExist:
                user_context = {
                    'name': 'Staff Member',
                    'designation': 'Staff',
                    'email': '',
                    'user_type': user_type
                }
    else:
        # For development/testing - try to get from session or create test user
        session_user = request.session.get('test_user')
        if session_user:
            user_context = session_user
        else:
            # Create a test student context for development
            user_context = {
                'name': 'Test Student',
                'room_number': '101',
                'block': 'A',
                'email': 'test@example.com',
                'user_type': 'student'
            }
    
    return render(request, 'chat/index.html', {'user': user_context})


@api_view(['GET'])
@permission_classes([IsStaffOnly])
def get_pass_history(request):
    """Get comprehensive pass history for staff/admin."""
    try:
        logger.info(f"get_pass_history called with params: {dict(request.query_params)}")
        
        # Get filter parameters
        start_date_str = request.query_params.get('start_date')
        end_date_str = request.query_params.get('end_date')
        student_name = request.query_params.get('student_name')
        pass_type = request.query_params.get('pass_type')  # 'digital' or 'leave'
        status_filter = request.query_params.get('status')
        
        logger.info(f"Filters - start: {start_date_str}, end: {end_date_str}, pass_type: {pass_type}, status: {status_filter}")
        
        # Use shared utility function for filtering
        digital_passes, absence_records = build_pass_history_query(
            start_date_str=start_date_str,
            end_date_str=end_date_str,
            student_name=student_name,
            status_filter=status_filter,
            pass_type=pass_type
        )
        
        logger.info(f"After filtering: digital_passes={digital_passes.count()}, absence_records={absence_records.count()}")
        
        # Use shared utility function for formatting
        history = format_pass_history_records(digital_passes, absence_records, pass_type)
        
        logger.info(f"Returning {len(history)} records")
        
        return Response({
            'success': True,
            'total_records': len(history),
            'history': history
        })
    
    except Exception as e:
        logger.error(f"Error in get_pass_history: {e}", exc_info=True)
        return Response({
            'success': False,
            'error': 'Failed to retrieve pass history'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([IsStaffOnly])
def export_pass_history(request):
    """Export pass history as CSV."""
    try:
        import csv
        from io import StringIO
        
        # Get filter parameters
        start_date_str = request.query_params.get('start_date')
        end_date_str = request.query_params.get('end_date')
        student_name = request.query_params.get('student_name')
        pass_type = request.query_params.get('pass_type')
        status_filter = request.query_params.get('status')
        
        # Use shared utility function for filtering
        digital_passes, absence_records = build_pass_history_query(
            start_date_str=start_date_str,
            end_date_str=end_date_str,
            student_name=student_name,
            status_filter=status_filter,
            pass_type=pass_type
        )
        
        # Use shared utility function for formatting
        history = format_pass_history_records(digital_passes, absence_records, pass_type)
        
        # Create CSV content
        output = StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow([
            'Type', 'Student Name', 'Student ID', 'Room Number',
            'Pass Number', 'From Date', 'To Date', 'Total Days',
            'Status', 'Approved By', 'Created At'
        ])
        
        # Write data rows
        for record in history:
            writer.writerow([
                record['type'],
                record['student_name'],
                record['student_id'],
                record['room_number'],
                record['pass_number'],
                record['from_date'],
                record['to_date'],
                record['total_days'],
                record['status'],
                record['approved_by'],
                record['created_at']
            ])
        
        # Create HTTP response
        csv_content = output.getvalue()
        output.close()
        
        response = HttpResponse(csv_content, content_type='text/csv')
        filename = f'pass_history_{timezone.now().strftime("%Y%m%d_%H%M%S")}.csv'
        response['Content-Disposition'] = f'attachment; filename="{filename}"'
        
        return response
    
    except Exception as e:
        logger.error(f"Error exporting pass history: {e}")
        return Response({
            'success': False,
            'error': 'Failed to export pass history'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


def staff_dashboard(request):
    """
    Render the staff dashboard for wardens and administrators.
    Provides overview of pending requests, daily summaries, and management tools.
    """
    # Get staff member from request or use dev staff
    staff_member = get_staff_from_request_or_dev(request)
    
    # Get dashboard data
    try:
        # Pending requests
        pending_guest_requests = GuestRequest.objects.filter(status='pending').order_by('-created_at')[:10]
        pending_absence_requests = AbsenceRecord.objects.filter(status='pending').order_by('-created_at')[:10]
        pending_maintenance_requests = MaintenanceRequest.objects.filter(status='pending').order_by('-created_at')[:10]
        
        # Recent activity
        recent_messages = Message.objects.filter(status='processed').order_by('-created_at')[:5]
        recent_audit_logs = AuditLog.objects.order_by('-timestamp')[:10]
        
        # Statistics
        stats = {
            'total_pending_requests': (
                pending_guest_requests.count() + 
                pending_absence_requests.count() + 
                pending_maintenance_requests.count()
            ),
            'total_students': Student.objects.count(),
            'active_guests': GuestRequest.objects.filter(
                status='approved',
                start_date__lte=timezone.now(),
                end_date__gte=timezone.now()
            ).count(),
            'absent_students': AbsenceRecord.objects.filter(
                status='approved',
                start_date__lte=timezone.now(),
                end_date__gte=timezone.now()
            ).count(),
        }
        
        # Get today's daily summary
        from dataclasses import asdict
        today_summary = daily_summary_service.generate_morning_summary(datetime.now())
        
        context = {
            'staff': staff_member,
            'pending_guest_requests': pending_guest_requests,
            'pending_absence_requests': pending_absence_requests,
            'pending_maintenance_requests': pending_maintenance_requests,
            'recent_messages': recent_messages,
            'recent_audit_logs': recent_audit_logs,
            'stats': stats,
            'daily_summary': asdict(today_summary),
        }
        
        return render(request, 'staff/dashboard.html', context)
        
    except Exception as e:
        logger.error(f"Error loading staff dashboard: {e}")
        # Fallback context for errors
        context = {
            'staff': staff_member,
            'error': 'Unable to load dashboard data',
            'stats': {'total_pending_requests': 0, 'total_students': 0, 'active_guests': 0, 'absent_students': 0}
        }
        return render(request, 'staff/dashboard.html', context)


def pass_history_view(request):
    """
    Render the pass history page for staff.
    """
    return render(request, 'staff/pass_history.html')


def security_dashboard(request):
    """
    Render the security staff dashboard.
    Provides pass verification, student tracking, and gate management tools.
    """
    # Get security staff member from session
    security_staff = None
    if hasattr(request.user, 'user_object') and request.user.user_object:
        security_staff = request.user.user_object
    else:
        # Try to get from session
        user_id = request.session.get('user_id')
        if user_id:
            try:
                security_staff = Staff.objects.get(staff_id=user_id)
            except Staff.DoesNotExist:
                pass
    
    # Get today's statistics
    today = timezone.now().date()
    now = timezone.now()
    
    # Active passes count
    active_passes_count = DigitalPass.objects.filter(
        status='active',
        from_date__lte=today,
        to_date__gte=today
    ).count()
    
    # Students currently away
    students_away_count = SecurityRecord.objects.filter(
        status='allowed_to_leave',
        digital_pass__status='active',
        digital_pass__from_date__lte=today,
        digital_pass__to_date__gte=today
    ).count()
    
    # Recent verifications
    recent_verifications = SecurityRecord.objects.filter(
        verification_time__date=today
    ).select_related('student', 'digital_pass').order_by('-verification_time')[:10]
    
    # Get approved guest requests for today (guests expected or currently visiting)
    approved_guests = GuestRequest.objects.filter(
        status='approved',
        start_date__lte=now,
        end_date__gte=now
    ).select_related('student', 'approved_by').order_by('start_date')
    
    # Get upcoming guests (arriving within next 24 hours)
    tomorrow = now + timezone.timedelta(days=1)
    upcoming_guests = GuestRequest.objects.filter(
        status='approved',
        start_date__gt=now,
        start_date__lte=tomorrow
    ).select_related('student', 'approved_by').order_by('start_date')
    
    # Active guests count
    active_guests_count = approved_guests.count()
    
    context = {
        'staff': security_staff,
        'active_passes_count': active_passes_count,
        'students_away_count': students_away_count,
        'recent_verifications': recent_verifications,
        'today': today,
        'approved_guests': approved_guests,
        'upcoming_guests': upcoming_guests,
        'active_guests_count': active_guests_count,
    }
    
    return render(request, 'security/dashboard.html', context)


def active_passes_view(request):
    """
    Render the active passes page with formatted HTML view.
    Shows all currently active digital passes for security verification.
    """
    today = timezone.now().date()
    
    # Get all active passes
    active_passes = DigitalPass.objects.filter(
        status='active',
        from_date__lte=today,
        to_date__gte=today
    ).select_related('student').order_by('student__name')
    
    # Calculate stats
    expiring_today = sum(1 for p in active_passes if p.to_date == today)
    long_leaves = sum(1 for p in active_passes if p.total_days >= 7)
    
    context = {
        'active_passes': active_passes,
        'today': today,
        'expiring_today': expiring_today,
        'long_leaves': long_leaves,
    }
    
    return render(request, 'security/active_passes.html', context)

def maintenance_dashboard(request):
    """
    Render the maintenance staff dashboard.
    Provides maintenance request management and work order tracking.
    """
    # Get maintenance staff member from session
    maintenance_staff = None
    if hasattr(request.user, 'user_object') and request.user.user_object:
        maintenance_staff = request.user.user_object
    else:
        # Try to get from session
        user_id = request.session.get('user_id')
        if user_id:
            try:
                maintenance_staff = Staff.objects.get(staff_id=user_id)
            except Staff.DoesNotExist:
                pass
    
    # Get maintenance statistics
    pending_requests = MaintenanceRequest.objects.filter(status='pending').count()
    in_progress_requests = MaintenanceRequest.objects.filter(status='in_progress').count()
    completed_today = MaintenanceRequest.objects.filter(
        status='completed',
        actual_completion__date=timezone.now().date()
    ).count()
    
    # Get requests assigned to this staff member (if any)
    assigned_requests = []
    if maintenance_staff:
        assigned_requests = MaintenanceRequest.objects.filter(
            assigned_to=maintenance_staff,
            status__in=['assigned', 'in_progress']
        ).select_related('student').order_by('-created_at')
    
    # Get all pending maintenance requests
    all_pending_requests = MaintenanceRequest.objects.filter(
        status='pending'
    ).select_related('student').order_by('-created_at')[:20]
    
    # Get high priority requests
    high_priority_requests = MaintenanceRequest.objects.filter(
        priority__in=['high', 'emergency'],
        status__in=['pending', 'assigned', 'in_progress']
    ).select_related('student').order_by('-created_at')
    
    context = {
        'staff': maintenance_staff,
        'pending_requests': pending_requests,
        'in_progress_requests': in_progress_requests,
        'completed_today': completed_today,
        'assigned_requests': assigned_requests,
        'all_pending_requests': all_pending_requests,
        'high_priority_requests': high_priority_requests,
    }
    
    return render(request, 'maintenance/dashboard.html', context)


def staff_query_interface(request):
    """
    Render the staff query interface for natural language queries.
    Provides a dedicated interface for staff to ask questions about hostel data.
    """
    # Get staff member from request or use dev staff
    staff_member = get_staff_from_request_or_dev(request)
    
    context = {
        'staff': staff_member,
    }
    
    return render(request, 'staff/query_interface.html', context)


@api_view(['POST'])
@permission_classes([AllowAny])  # In production, require authentication
def activate_emergency_mode(request):
    """
    Activate emergency mode and send alerts to all wardens and security staff.
    Sends SMS (if configured) and email notifications.
    """
    try:
        from .services.notification_service import notification_service, NotificationMethod, NotificationPriority
        from .models import AuditLog
        
        # Get emergency details from request
        emergency_type = request.data.get('emergency_type', 'general_emergency')
        description = request.data.get('description', 'Emergency mode activated from security dashboard')
        activated_by = request.data.get('activated_by', 'Security Personnel')
        
        # Validate emergency type
        valid_types = ['fire', 'security_breach', 'medical', 'natural_disaster', 'lockdown', 'general_emergency']
        if emergency_type not in valid_types:
            emergency_type = 'general_emergency'
        
        # Format emergency message
        emergency_labels = {
            'fire': '🔥 FIRE EMERGENCY',
            'security_breach': ' SECURITY BREACH',
            'medical': ' MEDICAL EMERGENCY',
            'natural_disaster': 'NATURAL DISASTER',
            'lockdown': ' CAMPUS LOCKDOWN',
            'general_emergency': '🚨 EMERGENCY ALERT'
        }
        
        alert_title = emergency_labels.get(emergency_type, '🚨 EMERGENCY ALERT')
        
        message = f"""
{alert_title}

Location: Hostel Campus
Time: {timezone.now().strftime('%d %b %Y, %H:%M')}
Activated By: {activated_by}

Details: {description}

IMMEDIATE ACTION REQUIRED!
Please respond to security desk immediately or call emergency line.

This is an automated alert from the Hostel Security System.
        """.strip()
        
        # Send notifications
        delivery_results = {
            'sms': {'sent': 0, 'failed': 0, 'recipients': []},
            'email': {'sent': 0, 'failed': 0, 'recipients': []}
        }
        
        # Get all wardens and security staff
        target_staff = Staff.objects.filter(
            is_active=True,
            role__in=['warden', 'security', 'admin']
        )
        
        sms_configured = bool(getattr(settings, 'TWILIO_ACCOUNT_SID', ''))
        
        for staff_member in target_staff:
            # Try SMS first (for urgent alerts)
            if sms_configured and staff_member.phone:
                try:
                    sms_result = notification_service._send_sms(
                        recipient=staff_member,
                        subject=alert_title,
                        content=message,
                        timestamp=timezone.now()
                    )
                    if sms_result.success:
                        delivery_results['sms']['sent'] += 1
                        delivery_results['sms']['recipients'].append(staff_member.name)
                    else:
                        delivery_results['sms']['failed'] += 1
                except Exception as e:
                    logger.error(f"SMS failed to {staff_member.name}: {e}")
                    delivery_results['sms']['failed'] += 1
            
            # Always send email as backup
            if staff_member.email:
                try:
                    email_result = notification_service._send_email(
                        recipient=staff_member,
                        subject=f"🚨 URGENT: {alert_title} - Immediate Action Required",
                        content=message,
                        timestamp=timezone.now()
                    )
                    if email_result.success:
                        delivery_results['email']['sent'] += 1
                        delivery_results['email']['recipients'].append(staff_member.name)
                    else:
                        delivery_results['email']['failed'] += 1
                except Exception as e:
                    logger.error(f"Email failed to {staff_member.name}: {e}")
                    delivery_results['email']['failed'] += 1
        
        # Log the emergency activation
        try:
            AuditLog.objects.create(
                action_type='emergency_mode_activated',
                description=f"Emergency Mode ({emergency_type}) activated by {activated_by}: {description}",
                performed_by=activated_by,
                ip_address=request.META.get('REMOTE_ADDR', 'unknown')
            )
        except Exception as e:
            logger.error(f"Failed to create audit log: {e}")
        
        # Prepare response
        total_sms = delivery_results['sms']['sent'] + delivery_results['sms']['failed']
        total_email = delivery_results['email']['sent'] + delivery_results['email']['failed']
        
        return Response({
            'success': True,
            'message': 'Emergency mode activated successfully',
            'emergency_type': emergency_type,
            'alert_title': alert_title,
            'notifications': {
                'sms': {
                    'configured': sms_configured,
                    'sent': delivery_results['sms']['sent'],
                    'failed': delivery_results['sms']['failed'],
                    'recipients': delivery_results['sms']['recipients']
                },
                'email': {
                    'sent': delivery_results['email']['sent'],
                    'failed': delivery_results['email']['failed'],
                    'recipients': delivery_results['email']['recipients']
                }
            },
            'summary': f"Alerts sent: {delivery_results['sms']['sent']} SMS, {delivery_results['email']['sent']} emails"
        })
        
    except Exception as e:
        logger.error(f"Error activating emergency mode: {e}")
        return Response({
            'success': False,
            'error': f'Failed to activate emergency mode: {str(e)}'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ==================== MAINTENANCE MANAGEMENT APIs ====================

@api_view(['POST'])
@permission_classes([AllowAny])
def accept_maintenance_task(request):
    """
    Accept a pending maintenance task and assign it to the current staff member.
    """
    try:
        request_id = request.data.get('request_id')
        if not request_id:
            return Response({
                'success': False,
                'error': 'request_id is required'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Get the maintenance staff member from session
        user_object, auth_type = get_user_from_request(request)
        if not user_object or not isinstance(user_object, Staff):
            return Response({
                'success': False,
                'error': 'Authentication required'
            }, status=status.HTTP_401_UNAUTHORIZED)
        
        # Find the maintenance request
        try:
            maintenance_request = MaintenanceRequest.objects.get(request_id=request_id)
        except MaintenanceRequest.DoesNotExist:
            return Response({
                'success': False,
                'error': 'Maintenance request not found'
            }, status=status.HTTP_404_NOT_FOUND)
        
        if maintenance_request.status != 'pending':
            return Response({
                'success': False,
                'error': f'Cannot accept task with status: {maintenance_request.status}'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Assign the task to the staff member
        maintenance_request.assigned_to = user_object
        maintenance_request.status = 'assigned'
        maintenance_request.save()
        
        # Log the action
        AuditLog.objects.create(
            action_type='maintenance_approval',
            entity_type='maintenance_request',
            entity_id=str(request_id),
            decision='processed',
            reasoning=f'Maintenance task accepted by {user_object.name}',
            confidence_score=1.0,
            rules_applied=['manual_acceptance'],
            user_id=user_object.staff_id,
            user_type='staff',
            metadata={'action': 'task_accepted', 'ip_address': request.META.get('REMOTE_ADDR', 'unknown')}
        )
        
        logger.info(f"Maintenance task {request_id} accepted by {user_object.staff_id}")
        
        return Response({
            'success': True,
            'message': 'Task accepted successfully',
            'request_id': str(request_id),
            'assigned_to': user_object.name,
            'status': 'assigned'
        })
        
    except Exception as e:
        logger.error(f"Error accepting maintenance task: {e}")
        return Response({
            'success': False,
            'error': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([AllowAny])
def update_maintenance_status(request):
    """
    Update the status of a maintenance request and notify warden.
    Supports assignment, ETA, notes, and status changes.
    """
    try:
        request_id = request.data.get('request_id')
        new_status = request.data.get('status')
        notes = request.data.get('notes', '')
        assigned_to_staff_id = request.data.get('assigned_to_staff_id')
        estimated_completion = request.data.get('estimated_completion')
        
        if not request_id:
            return Response({
                'success': False,
                'error': 'request_id is required'
            }, status=status.HTTP_400_BAD_REQUEST)

        if (
            new_status in (None, '')
            and notes in (None, '')
            and not assigned_to_staff_id
            and not estimated_completion
        ):
            return Response({
                'success': False,
                'error': 'Provide at least one update: status, notes, assigned_to_staff_id, or estimated_completion'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        valid_statuses = ['pending', 'assigned', 'in_progress', 'completed', 'cancelled']
        if new_status and new_status not in valid_statuses:
            return Response({
                'success': False,
                'error': f'Invalid status. Valid options: {valid_statuses}'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Get the maintenance staff member from session
        user_object, auth_type = get_user_from_request(request)
        if not user_object or not isinstance(user_object, Staff):
            return Response({
                'success': False,
                'error': 'Authentication required'
            }, status=status.HTTP_401_UNAUTHORIZED)
        
        # Find the maintenance request
        try:
            maintenance_request = MaintenanceRequest.objects.get(request_id=request_id)
        except MaintenanceRequest.DoesNotExist:
            return Response({
                'success': False,
                'error': 'Maintenance request not found'
            }, status=status.HTTP_404_NOT_FOUND)
        
        old_status = maintenance_request.status
        old_assigned_to = maintenance_request.assigned_to.staff_id if maintenance_request.assigned_to else None
        status_changed = False
        assignment_changed = False

        if assigned_to_staff_id:
            try:
                assigned_staff = Staff.objects.get(
                    staff_id=assigned_to_staff_id,
                    role='maintenance',
                    is_active=True
                )
            except Staff.DoesNotExist:
                return Response({
                    'success': False,
                    'error': 'Maintenance staff member not found'
                }, status=status.HTTP_404_NOT_FOUND)

            if maintenance_request.assigned_to_id != assigned_staff.id:
                maintenance_request.assigned_to = assigned_staff
                assignment_changed = True

            if maintenance_request.status == 'pending' and not new_status:
                new_status = 'assigned'
        
        # Validate status transition (allow reopening completed/cancelled tickets)
        valid_transitions = {
            'pending': ['assigned', 'cancelled'],
            'assigned': ['in_progress', 'cancelled', 'pending'],
            'in_progress': ['completed', 'cancelled', 'assigned', 'pending'],
            'completed': ['pending', 'assigned', 'in_progress'],
            'cancelled': ['pending', 'assigned', 'in_progress'],
        }
        
        if new_status and new_status != old_status and new_status not in valid_transitions.get(old_status, []):
            return Response({
                'success': False,
                'error': f'Cannot transition from {old_status} to {new_status}'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Update the request
        if new_status and new_status != old_status:
            maintenance_request.status = new_status
            status_changed = True

        if notes not in (None, ''):
            maintenance_request.notes = notes

        if estimated_completion not in (None, ''):
            maintenance_request.estimated_completion = estimated_completion

        # Only stamp/clear completion time when status actually crosses the completed boundary
        if status_changed and maintenance_request.status == 'completed':
            maintenance_request.actual_completion = timezone.now()
        elif status_changed and old_status == 'completed':
            maintenance_request.actual_completion = None

        maintenance_request.save()

        # Notify the student only for key milestones to avoid notification fatigue.
        if status_changed and maintenance_request.status in ['in_progress', 'completed']:
            _notify_student_maintenance_milestone(maintenance_request, maintenance_request.status, user_object)
        
        # Log the action
        AuditLog.objects.create(
            action_type='maintenance_approval',
            entity_type='maintenance_request',
            entity_id=str(request_id),
            decision='processed',
            reasoning=(
                f'Maintenance request updated by {user_object.name}: '
                f'status {old_status} -> {maintenance_request.status}, '
                f'assignee {old_assigned_to or "unassigned"} -> '
                f'{maintenance_request.assigned_to.staff_id if maintenance_request.assigned_to else "unassigned"}'
            ),
            confidence_score=1.0,
            rules_applied=['manual_status_update', 'manual_assignment_update'],
            user_id=user_object.staff_id,
            user_type='staff',
            metadata={
                'action': 'status_updated',
                'old_status': old_status,
                'new_status': maintenance_request.status,
                'old_assigned_to': old_assigned_to,
                'new_assigned_to': maintenance_request.assigned_to.staff_id if maintenance_request.assigned_to else None,
                'estimated_completion': maintenance_request.estimated_completion.isoformat() if maintenance_request.estimated_completion else None,
                'ip_address': request.META.get('REMOTE_ADDR', 'unknown')
            }
        )
        
        # Notify warden if task is completed or priority is high/emergency
        if maintenance_request.status == 'completed' or maintenance_request.priority in ['high', 'emergency'] or assignment_changed:
            _notify_warden_maintenance_update(maintenance_request, old_status, maintenance_request.status, user_object)
        
        logger.info(f"Maintenance task {request_id} status updated to {new_status} by {user_object.staff_id}")
        
        return Response({
            'success': True,
            'message': 'Maintenance request updated successfully',
            'request_id': str(request_id),
            'old_status': old_status,
            'new_status': maintenance_request.status,
            'updated_by': user_object.name,
            'request': MaintenanceRequestSerializer(maintenance_request).data
        })
        
    except Exception as e:
        logger.error(f"Error updating maintenance status: {e}")
        return Response({
            'success': False,
            'error': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([AllowAny])
def get_maintenance_stats(request):
    """
    Get maintenance statistics for warden dashboard.
    Shows pending, in-progress, completed tasks and staff performance.
    """
    try:
        # Get date range (default last 30 days)
        days = int(request.GET.get('days', 30))
        start_date = timezone.now() - timezone.timedelta(days=days)
        
        # Overall statistics
        pending_count = MaintenanceRequest.objects.filter(status='pending').count()
        assigned_count = MaintenanceRequest.objects.filter(status='assigned').count()
        in_progress_count = MaintenanceRequest.objects.filter(status='in_progress').count()
        completed_count = MaintenanceRequest.objects.filter(
            status='completed',
            actual_completion__gte=start_date
        ).count()
        
        # Today's statistics
        today = timezone.now().date()
        completed_today = MaintenanceRequest.objects.filter(
            status='completed',
            actual_completion__date=today
        ).count()
        
        new_today = MaintenanceRequest.objects.filter(
            created_at__date=today
        ).count()
        
        # Priority breakdown
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
        
        # Issue type breakdown
        issue_types = ['electrical', 'plumbing', 'hvac', 'furniture', 'cleaning', 'other']
        issue_type_stats = {}
        for issue_type in issue_types:
            issue_type_stats[issue_type] = MaintenanceRequest.objects.filter(
                issue_type=issue_type,
                status__in=['pending', 'assigned', 'in_progress']
            ).count()
        
        # Staff performance (completed tasks in date range)
        staff_performance = []
        maintenance_staff = Staff.objects.filter(role='maintenance', is_active=True)
        for staff in maintenance_staff:
            completed_by_staff = MaintenanceRequest.objects.filter(
                assigned_to=staff,
                status='completed',
                actual_completion__gte=start_date
            ).count()
            
            in_progress_by_staff = MaintenanceRequest.objects.filter(
                assigned_to=staff,
                status__in=['assigned', 'in_progress']
            ).count()
            
            staff_performance.append({
                'staff_id': staff.staff_id,
                'name': staff.name,
                'completed': completed_by_staff,
                'in_progress': in_progress_by_staff
            })
        
        # Average resolution time (for completed tasks)
        from django.db.models import Avg, F
        completed_requests = MaintenanceRequest.objects.filter(
            status='completed',
            actual_completion__isnull=False,
            actual_completion__gte=start_date
        )
        
        avg_resolution_hours = 0
        if completed_requests.exists():
            total_hours = 0
            count = 0
            for req in completed_requests:
                delta = req.actual_completion - req.created_at
                total_hours += delta.total_seconds() / 3600
                count += 1
            if count > 0:
                avg_resolution_hours = round(total_hours / count, 1)
        
        return Response({
            'success': True,
            'period_days': days,
            'overview': {
                'pending': pending_count,
                'assigned': assigned_count,
                'in_progress': in_progress_count,
                'completed': completed_count,
                'total_active': pending_count + assigned_count + in_progress_count
            },
            'today': {
                'new_requests': new_today,
                'completed': completed_today
            },
            'priority_breakdown': priority_stats,
            'issue_type_breakdown': issue_type_stats,
            'staff_performance': staff_performance,
            'average_resolution_hours': avg_resolution_hours
        })
        
    except Exception as e:
        logger.error(f"Error getting maintenance stats: {e}")
        return Response({
            'success': False,
            'error': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([AllowAny])
def get_maintenance_history(request):
    """
    Get maintenance request history with filtering options.
    """
    try:
        # Get query parameters
        status_filter = request.GET.get('status', None)
        priority_filter = request.GET.get('priority', None)
        issue_type_filter = request.GET.get('issue_type', None)
        days = int(request.GET.get('days', 30))
        limit = int(request.GET.get('limit', 50))
        
        start_date = timezone.now() - timezone.timedelta(days=days)
        
        # Build query
        queryset = MaintenanceRequest.objects.filter(
            created_at__gte=start_date
        ).select_related('student', 'assigned_to').order_by('-created_at')
        
        if status_filter:
            queryset = queryset.filter(status=status_filter)
        if priority_filter:
            queryset = queryset.filter(priority=priority_filter)
        if issue_type_filter:
            queryset = queryset.filter(issue_type=issue_type_filter)
        
        queryset = queryset[:limit]
        
        # Format response
        requests_list = []
        for req in queryset:
            requests_list.append({
                'request_id': str(req.request_id),
                'room_number': req.room_number,
                'issue_type': req.issue_type,
                'priority': req.priority,
                'status': req.status,
                'description': req.description,
                'student': {
                    'name': req.student.name,
                    'student_id': req.student.student_id,
                    'block': req.student.block
                },
                'assigned_to': req.assigned_to.name if req.assigned_to else None,
                'created_at': req.created_at.isoformat(),
                'actual_completion': req.actual_completion.isoformat() if req.actual_completion else None,
                'notes': req.notes,
                'is_overdue': req.is_overdue,
                'days_pending': req.days_pending
            })
        
        return Response({
            'success': True,
            'count': len(requests_list),
            'requests': requests_list
        })
        
    except Exception as e:
        logger.error(f"Error getting maintenance history: {e}")
        return Response({
            'success': False,
            'error': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


def _notify_warden_maintenance_update(maintenance_request, old_status, new_status, updated_by):
    """
    Send notification to warden about maintenance task status update.
    """
    try:
        from .services.notification_service import notification_service, NotificationPriority
        
        # Determine priority based on task priority
        if maintenance_request.priority in ['emergency', 'high']:
            notification_priority = NotificationPriority.HIGH
        else:
            notification_priority = NotificationPriority.MEDIUM
        
        # Build notification message
        status_emoji = {
            'in_progress': '🔧',
            'completed': '✅',
            'cancelled': '❌'
        }
        
        emoji = status_emoji.get(new_status, '📋')
        
        message_parts = [
            f"{emoji} MAINTENANCE STATUS UPDATE",
            f"=" * 50,
            f"",
            f"Task ID: {maintenance_request.request_id}",
            f"Room: {maintenance_request.room_number} (Block {maintenance_request.student.block})",
            f"Issue Type: {maintenance_request.issue_type.title()}",
            f"Priority: {maintenance_request.priority.upper()}",
            f"",
            f"Status Change: {old_status.upper()} → {new_status.upper()}",
            f"Updated By: {updated_by.name}",
            f"Time: {timezone.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"",
            f"Description: {maintenance_request.description[:100]}...",
        ]
        
        if maintenance_request.notes:
            message_parts.extend([
                f"",
                f"Staff Notes: {maintenance_request.notes}"
            ])
        
        if new_status == 'completed':
            # Calculate resolution time
            if maintenance_request.actual_completion:
                delta = maintenance_request.actual_completion - maintenance_request.created_at
                hours = delta.total_seconds() / 3600
                message_parts.extend([
                    f"",
                    f"Resolution Time: {hours:.1f} hours"
                ])
        
        message = "\n".join(message_parts)
        
        # Send to wardens
        notification_service.deliver_urgent_alert(
            alert_type=f"maintenance_{new_status}",
            message=message,
            priority=notification_priority,
            target_roles=['warden', 'admin']
        )
        
        logger.info(f"Warden notified about maintenance task {maintenance_request.request_id} status update")
        
    except Exception as e:
        logger.error(f"Failed to notify warden about maintenance update: {e}")


def _notify_student_maintenance_milestone(maintenance_request, milestone_status, updated_by):
    """Create an in-app notification for important student-visible maintenance milestones."""
    try:
        student = maintenance_request.student
        if not student:
            return

        is_urgent = maintenance_request.priority in ['high', 'emergency']

        if milestone_status == 'in_progress':
            title = 'Maintenance work started'
            message = (
                f"Work has started for your {maintenance_request.issue_type} complaint "
                f"in Room {maintenance_request.room_number}."
            )
        elif milestone_status == 'completed':
            title = 'Maintenance request completed'
            message = (
                f"Your {maintenance_request.issue_type} complaint in Room "
                f"{maintenance_request.room_number} has been marked as completed."
            )
        else:
            return

        Notification.objects.create(
            recipient_student=student,
            title=title,
            message=message,
            type='maintenance',
            priority='high' if is_urgent else 'medium',
            action_url='/',
            metadata={
                'request_id': str(maintenance_request.request_id),
                'status': milestone_status,
                'issue_type': maintenance_request.issue_type,
                'updated_by_staff_id': getattr(updated_by, 'staff_id', None),
            },
        )
    except Exception as exc:
        logger.error(
            'Failed to create student maintenance milestone notification for %s: %s',
            maintenance_request.request_id,
            exc,
        )