"""
Authentication and authorization for the AI-Powered Hostel Coordination System.
Integrates with Supabase authentication and provides role-based access control.
"""

import logging
from typing import Optional, Dict, Any, Tuple, Union
from django.contrib.auth.models import AnonymousUser
from rest_framework.authentication import BaseAuthentication
from rest_framework.permissions import BasePermission
from rest_framework.exceptions import AuthenticationFailed, PermissionDenied
from django.http import HttpRequest

from .models import Student, Staff
from .services.supabase_service import supabase_service

logger = logging.getLogger(__name__)


def get_authenticated_user(request: HttpRequest) -> Tuple[Optional[Union[Student, Staff]], str]:
    """
    Get authenticated user from either JWT or session authentication.
    
    This function provides a unified way to retrieve the authenticated user
    regardless of the authentication method used (JWT token or session-based).
    
    Args:
        request: Django HttpRequest object
        
    Returns:
        Tuple of (user_object, auth_type) where:
        - user_object: Student or Staff instance, or None if not authenticated
        - auth_type: One of 'jwt', 'session', 'session_invalid', or 'none'
    
    Authentication Priority:
        1. DRF Authentication (request.user.user_object) - set by CustomSessionAuthentication or SupabaseAuthentication
        2. Session authentication fallback (request.session) - for non-DRF views
        3. None (no authentication found)
    
    Example:
        >>> user_object, auth_type = get_authenticated_user(request)
        >>> if user_object and isinstance(user_object, Student):
        >>>     # Process student request
        >>>     pass
    """
    # Check DRF authentication first (set by CustomSessionAuthentication or SupabaseAuthentication)
    if hasattr(request, 'user') and hasattr(request.user, 'user_object') and request.user.user_object:
        # Determine auth type from user ID prefix or session presence
        user_id = getattr(request.user, 'id', '') or ''
        if user_id.startswith('session-'):
            auth_type = 'session'
        elif user_id.startswith('dev-'):
            auth_type = 'dev'
        else:
            auth_type = 'jwt'
        logger.debug(f"DRF authentication found for user: {request.user.user_object} (type: {auth_type})")
        return (request.user.user_object, auth_type)
    
    # Fallback: Check session authentication directly (for non-DRF views)
    if hasattr(request, 'session'):
        user_id = request.session.get('user_id')
        user_type = request.session.get('user_type')
        
        if user_id and user_type:
            logger.debug(f"Session authentication fallback: user_type={user_type}, user_id={user_id}")
            
            try:
                if user_type == 'student':
                    user_object = Student.objects.get(student_id=user_id)
                    logger.info(f"Session authentication successful for student: {user_id}")
                    return (user_object, 'session')
                elif user_type == 'staff':
                    user_object = Staff.objects.get(staff_id=user_id, is_active=True)
                    logger.info(f"Session authentication successful for staff: {user_id}")
                    return (user_object, 'session')
                else:
                    logger.warning(f"Invalid user_type in session: {user_type}")
                    return (None, 'session_invalid')
            except Student.DoesNotExist:
                logger.warning(f"Session user not found: student {user_id}")
                return (None, 'session_invalid')
            except Staff.DoesNotExist:
                logger.warning(f"Session user not found: staff {user_id}")
                return (None, 'session_invalid')
            except Exception as e:
                logger.error(f"Error retrieving session user: {e}")
                return (None, 'session_invalid')
    
    # No authentication found
    logger.debug("No authentication found (neither DRF nor session)")
    return (None, 'none')


class SupabaseUser:
    """Custom user class for Supabase authenticated users."""
    
    def __init__(self, user_data: Dict[str, Any], user_type: str, user_object=None):
        self.id = user_data.get('id')
        self.email = user_data.get('email')
        self.user_metadata = user_data.get('user_metadata', {})
        self.user_type = user_type  # 'student' or 'staff'
        self.user_object = user_object  # Student or Staff model instance
        self.is_authenticated = True
        self.is_anonymous = False
    
    def __str__(self):
        return f"{self.user_type}: {self.email}"
    
    @property
    def is_student(self):
        return self.user_type == 'student'
    
    @property
    def is_staff_member(self):
        return self.user_type == 'staff'
    
    @property
    def permissions(self):
        if self.user_object and hasattr(self.user_object, 'permissions'):
            return self.user_object.permissions
        return {}


class SupabaseAuthentication(BaseAuthentication):
    """
    Authentication backend that validates Supabase JWT tokens.
    """
    
    def authenticate(self, request: HttpRequest):
        """
        Authenticate the request using Supabase JWT token.
        
        Returns:
            Tuple of (user, token) if authentication successful, None otherwise
        """
        auth_header = request.META.get('HTTP_AUTHORIZATION')
        if not auth_header:
            return None
        
        try:
            # Extract token from Authorization header
            if not auth_header.startswith('Bearer '):
                return None
            
            token = auth_header.split(' ')[1]
            
            # Validate token with Supabase
            if not supabase_service.is_configured():
                logger.warning("Supabase not configured, skipping authentication")
                return None
            
            user_data = supabase_service.verify_token(token)
            if not user_data:
                raise AuthenticationFailed('Invalid or expired token')
            
            # Determine user type and get user object
            user_type, user_object = self._get_user_type_and_object(user_data)
            if not user_type:
                raise AuthenticationFailed('User not found in system')
            
            # Create custom user instance
            user = SupabaseUser(user_data, user_type, user_object)
            
            return (user, token)
            
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            raise AuthenticationFailed('Authentication failed')
    
    def _get_user_type_and_object(self, user_data: Dict[str, Any]):
        """
        Determine user type (student/staff) and get corresponding model instance.
        
        Args:
            user_data: User data from Supabase
            
        Returns:
            Tuple of (user_type, user_object)
        """
        email = user_data.get('email')
        user_id = user_data.get('id')
        
        # Check if user is a student
        try:
            # Try to find student by email or user_id in metadata
            student = None
            if email:
                # Assuming student email follows pattern: student_id@hostel.edu
                if '@hostel.edu' in email:
                    student_id = email.split('@')[0].upper()
                    student = Student.objects.get(student_id=student_id)
            
            if student:
                return ('student', student)
        except Student.DoesNotExist:
            pass
        
        # Check if user is staff
        try:
            staff = None
            if email:
                staff = Staff.objects.get(email=email, is_active=True)
            
            if staff:
                return ('staff', staff)
        except Staff.DoesNotExist:
            pass
        
        return (None, None)


class IsStudentOrStaff(BasePermission):
    """
    Permission class that allows access to authenticated students or staff.
    Supports both JWT and session-based authentication.
    """
    
    def has_permission(self, request, view):
        """Check if user is authenticated student or staff."""
        # Try JWT authentication first
        if hasattr(request.user, 'user_type') and request.user.is_authenticated and request.user.user_type in ['student', 'staff']:
            return True
        
        # Try session authentication
        user_type = request.session.get('user_type')
        if user_type in ['student', 'staff']:
            return True
        
        return False


class IsStaffOnly(BasePermission):
    """
    Permission class that allows access only to authenticated staff members.
    Supports both JWT and session-based authentication.
    """
    
    def has_permission(self, request, view):
        """Check if user is authenticated staff member."""
        # Try JWT authentication first
        if hasattr(request.user, 'user_type') and request.user.is_authenticated and request.user.user_type == 'staff':
            return True
        
        # Try session authentication
        user_type = request.session.get('user_type')
        if user_type == 'staff':
            return True
        
        return False


class IsStudentOnly(BasePermission):
    """
    Permission class that allows access only to authenticated students.
    Supports both JWT and session-based authentication.
    """
    
    def has_permission(self, request, view):
        """Check if user is authenticated student."""
        # Try JWT authentication first
        if hasattr(request.user, 'user_type') and request.user.is_authenticated and request.user.user_type == 'student':
            return True
        
        # Try session authentication
        user_type = request.session.get('user_type')
        if user_type == 'student':
            return True
        
        return False


class HasStaffRole(BasePermission):
    """
    Permission class that checks for specific staff roles.
    Usage: Add required_roles attribute to view.
    """
    
    def has_permission(self, request, view):
        """Check if staff member has required role."""
        if not (request.user and request.user.is_authenticated and 
                hasattr(request.user, 'user_type') and 
                request.user.user_type == 'staff'):
            return False
        
        required_roles = getattr(view, 'required_roles', [])
        if not required_roles:
            return True  # No specific role required
        
        user_role = request.user.user_object.role if request.user.user_object else None
        return user_role in required_roles


class CanApproveRequests(BasePermission):
    """
    Permission class that checks if staff can approve requests.
    """
    
    def has_permission(self, request, view):
        """Check if staff member can approve requests."""
        if not (request.user and request.user.is_authenticated and 
                hasattr(request.user, 'user_type') and 
                request.user.user_type == 'staff'):
            return False
        
        # Only wardens and admins can approve requests
        user_role = request.user.user_object.role if request.user.user_object else None
        return user_role in ['warden', 'admin']


class CanAccessOwnDataOnly(BasePermission):
    """
    Permission class that ensures students can only access their own data.
    """
    
    def has_permission(self, request, view):
        """Check if user has basic permission to access the view."""
        if not request.user or not request.user.is_authenticated:
            return False
        
        # Staff can access all data
        if hasattr(request.user, 'user_type') and request.user.user_type == 'staff':
            return True
        
        # Students have basic permission but object-level checks apply
        if hasattr(request.user, 'user_type') and request.user.user_type == 'student':
            return True
        
        return False
    
    def has_object_permission(self, request, view, obj):
        """Check if user can access the specific object."""
        if not request.user or not request.user.is_authenticated:
            return False
        
        # Staff can access all data
        if hasattr(request.user, 'user_type') and request.user.user_type == 'staff':
            return True
        
        # Students can only access their own data
        if hasattr(request.user, 'user_type') and request.user.user_type == 'student':
            if hasattr(obj, 'student'):
                return obj.student == request.user.user_object
            elif hasattr(obj, 'sender'):
                return obj.sender == request.user.user_object
            elif isinstance(obj, Student):
                return obj == request.user.user_object
        
        return False


class CustomSessionAuthentication(BaseAuthentication):
    """
    Custom session authentication that reads user_id and user_type from Django session.
    
    This authentication backend is designed for our custom session-based login
    where we store user_id and user_type directly in the session instead of
    using Django's built-in auth.User model.
    """
    
    def authenticate(self, request: HttpRequest):
        """
        Authenticate using session data (user_id, user_type).
        
        Returns:
            Tuple of (SupabaseUser, None) if authenticated, None otherwise
        """
        # Check if session middleware has attached session
        if not hasattr(request, 'session'):
            logger.debug("CustomSessionAuthentication: No session attribute on request")
            return None
        
        user_id = request.session.get('user_id')
        user_type = request.session.get('user_type')
        
        logger.debug(f"CustomSessionAuthentication: user_id={user_id}, user_type={user_type}")
        
        if not user_id or not user_type:
            logger.debug("CustomSessionAuthentication: No user_id or user_type in session")
            return None
        
        try:
            if user_type == 'student':
                user_object = Student.objects.get(student_id=user_id)
                user_data = {
                    'id': f'session-student-{user_id}',
                    'email': user_object.email or f'{user_id.lower()}@hostel.edu',
                    'user_metadata': {'role': 'student'}
                }
            elif user_type == 'staff':
                user_object = Staff.objects.get(staff_id=user_id, is_active=True)
                user_data = {
                    'id': f'session-staff-{user_id}',
                    'email': user_object.email or f'{user_id.lower()}@staff.hostel.edu',
                    'user_metadata': {'role': 'staff'}
                }
            else:
                logger.warning(f"CustomSessionAuthentication: Invalid user_type {user_type}")
                return None
            
            user = SupabaseUser(user_data, user_type, user_object)
            logger.info(f"CustomSessionAuthentication: Authenticated {user_type} {user_id}")
            return (user, None)  # No token for session auth
            
        except Student.DoesNotExist:
            logger.warning(f"CustomSessionAuthentication: Student {user_id} not found")
            return None
        except Staff.DoesNotExist:
            logger.warning(f"CustomSessionAuthentication: Staff {user_id} not found")
            return None
        except Exception as e:
            logger.error(f"CustomSessionAuthentication error: {e}")
            return None


class DevelopmentBypassAuthentication(BaseAuthentication):
    """
    Development-only authentication that bypasses Supabase for testing.
    DO NOT USE IN PRODUCTION!
    """
    
    def authenticate(self, request: HttpRequest):
        """
        Bypass authentication for development/testing.
        Uses X-Dev-User-Type and X-Dev-User-ID headers.
        """
        # Only allow in development mode
        from django.conf import settings
        if not settings.DEBUG:
            return None
        
        user_type = request.META.get('HTTP_X_DEV_USER_TYPE')
        user_id = request.META.get('HTTP_X_DEV_USER_ID')
        
        logger.debug(f"Development auth attempt: user_type={user_type}, user_id={user_id}")
        
        if not user_type or not user_id:
            logger.debug("Development auth: missing headers")
            return None
        
        try:
            if user_type == 'student':
                user_object = Student.objects.get(student_id=user_id)
                user_data = {
                    'id': f'dev-student-{user_id}',
                    'email': f'{user_id.lower()}@hostel.edu',
                    'user_metadata': {'role': 'student'}
                }
            elif user_type == 'staff':
                user_object = Staff.objects.get(staff_id=user_id, is_active=True)
                user_data = {
                    'id': f'dev-staff-{user_id}',
                    'email': user_object.email or f'{user_id.lower()}@staff.hostel.edu',
                    'user_metadata': {'role': 'staff'}
                }
            else:
                logger.debug(f"Development auth: invalid user_type {user_type}")
                return None
            
            user = SupabaseUser(user_data, user_type, user_object)
            logger.debug(f"Development auth successful: {user}")
            return (user, 'dev-token')
            
        except (Student.DoesNotExist, Staff.DoesNotExist) as e:
            logger.warning(f"Development auth failed: {user_type} {user_id} not found - {e}")
            return None
        except Exception as e:
            logger.error(f"Development auth error: {e}")
            return None


def get_user_permissions(user) -> Dict[str, bool]:
    """
    Get user permissions based on their role and type.
    
    Args:
        user: Authenticated user object
        
    Returns:
        Dictionary of permissions
    """
    if not user or not user.is_authenticated:
        return {}
    
    permissions = {
        'can_send_messages': False,
        'can_view_own_requests': False,
        'can_approve_requests': False,
        'can_view_all_requests': False,
        'can_manage_students': False,
        'can_view_audit_logs': False,
        'can_generate_reports': False,
        'can_manage_staff': False
    }
    
    if hasattr(user, 'user_type'):
        if user.user_type == 'student':
            permissions.update({
                'can_send_messages': True,
                'can_view_own_requests': True
            })
        
        elif user.user_type == 'staff':
            role = user.user_object.role if user.user_object else None
            
            # Base staff permissions
            permissions.update({
                'can_view_all_requests': True,
                'can_view_audit_logs': True,
                'can_generate_reports': True
            })
            
            # Role-specific permissions
            if role in ['warden', 'admin']:
                permissions.update({
                    'can_approve_requests': True,
                    'can_manage_students': True
                })
            
            if role == 'admin':
                permissions.update({
                    'can_manage_staff': True
                })
    
    return permissions