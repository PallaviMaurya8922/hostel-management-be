"""
Authentication views for the AI-Powered Hostel Coordination System.
Handles dual role login (students and staff), password management, and profile views.
"""

import logging
from django.db import transaction, connection
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth import logout as django_logout
from django.http import JsonResponse
from django.template import TemplateDoesNotExist
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.csrf import ensure_csrf_cookie
from django.middleware.csrf import get_token
from django.views.decorators.http import require_http_methods
from django.utils.decorators import method_decorator
from django.utils import timezone
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.conf import settings
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework import status
import json

from .models import Student, Staff
from .security import InputValidator, SecurityAuditLogger

logger = logging.getLogger(__name__)


@ensure_csrf_cookie
@require_http_methods(["GET"])
def csrf_cookie_view(request):
    """Issue CSRF cookie for SPA clients before state-changing requests."""
    return JsonResponse({
        'success': True,
        'csrfToken': get_token(request)
    })


@csrf_exempt
def login_view(request):
    """
    Dual role login view for both students and staff.
    Displays login form and handles authentication.
    """
    if request.method == 'GET':
        # Check if user is already logged in
        if hasattr(request, 'session') and request.session.get('user_id'):
            user_type = request.session.get('user_type')
            if user_type == 'student':
                return redirect('student_dashboard')
            elif user_type == 'staff':
                return redirect('staff_dashboard')
        
        try:
            return render(request, 'auth/login.html')
        except TemplateDoesNotExist:
            # SPA deployments may not provide Django-rendered auth templates.
            return JsonResponse({
                'success': True,
                'message': 'Login is served by the frontend application',
                'login_url': '/auth/login/'
            })
    
    elif request.method == 'POST':
        return handle_login(request)


@csrf_exempt
@require_http_methods(["POST"])
def handle_login(request):
    """
    Handle login form submission for both students and staff.
    """
    try:
        # Parse request data
        if request.content_type == 'application/json':
            data = json.loads(request.body)
        else:
            data = request.POST
        
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        user_type = data.get('user_type', 'student')  # Default to student
        
        # Validate input
        if not email or not password:
            return JsonResponse({
                'success': False,
                'error': 'Email and password are required'
            }, status=400)
        
        try:
            validate_email(email)
        except ValidationError:
            return JsonResponse({
                'success': False,
                'error': 'Please enter a valid email address'
            }, status=400)
        
        # Validate password length (keep compatible with existing seeded users)
        if len(password) < 3:
            return JsonResponse({
                'success': False,
                'error': 'Password must be at least 3 characters long'
            }, status=400)
        
        # Log login attempt
        SecurityAuditLogger.log_security_event(
            event_type='login_attempt',
            details={'email': email, 'user_type': user_type},
            request=request,
            severity='INFO'
        )
        
        # Authenticate based on user type
        user_object = None
        if user_type == 'student':
            try:
                user_object = Student.objects.get(email=email)
                if not user_object.check_password(password):
                    raise Student.DoesNotExist()
            except Student.DoesNotExist:
                # Check if email exists as a staff member (role mismatch)
                staff_check = Staff.objects.filter(email=email, is_active=True).first()
                if staff_check:
                    error_msg = f'This email is registered as {staff_check.get_role_display()}. Please select the correct role and try again.'
                    SecurityAuditLogger.log_security_event(
                        event_type='login_failed',
                        details={'email': email, 'user_type': user_type, 'reason': 'role_mismatch'},
                        request=request,
                        severity='WARNING'
                    )
                else:
                    error_msg = 'Invalid email or password'
                    SecurityAuditLogger.log_security_event(
                        event_type='login_failed',
                        details={'email': email, 'user_type': user_type, 'reason': 'invalid_credentials'},
                        request=request,
                        severity='WARNING'
                    )
                return JsonResponse({
                    'success': False,
                    'error': error_msg
                }, status=401)
        
        elif user_type == 'staff':
            try:
                user_object = Staff.objects.get(email=email, is_active=True)
                if not user_object.check_password(password):
                    raise Staff.DoesNotExist()
            except Staff.DoesNotExist:
                # Check if email exists as a student (role mismatch)
                student_check = Student.objects.filter(email=email).first()
                if student_check:
                    error_msg = 'This email is registered as a Student. Please select the Student role and try again.'
                    SecurityAuditLogger.log_security_event(
                        event_type='login_failed',
                        details={'email': email, 'user_type': user_type, 'reason': 'role_mismatch'},
                        request=request,
                        severity='WARNING'
                    )
                else:
                    error_msg = 'Invalid email or password'
                    SecurityAuditLogger.log_security_event(
                        event_type='login_failed',
                        details={'email': email, 'user_type': user_type, 'reason': 'invalid_credentials'},
                        request=request,
                        severity='WARNING'
                    )
                return JsonResponse({
                    'success': False,
                    'error': error_msg
                }, status=401)
        
        else:
            return JsonResponse({
                'success': False,
                'error': 'Invalid user type'
            }, status=400)
        
        # Create session
        request.session['user_id'] = user_object.student_id if user_type == 'student' else user_object.staff_id
        request.session['user_type'] = user_type
        request.session['user_email'] = email
        request.session['login_time'] = timezone.now().isoformat()
        
        # Check if first-time login for students and staff.
        is_first_login = bool(getattr(user_object, 'is_first_login', False))
        
        # Log successful login
        SecurityAuditLogger.log_security_event(
            event_type='login_success',
            details={
                'email': email, 
                'user_type': user_type, 
                'user_id': user_object.student_id if user_type == 'student' else user_object.staff_id,
                'is_first_login': is_first_login
            },
            request=request,
            severity='INFO'
        )
        
        # Determine redirect URL based on user type and role
        if user_type == 'student':
            redirect_url = '/student/dashboard/'
        else:
            # Route staff based on their role
            staff_role = user_object.role if hasattr(user_object, 'role') else 'staff'
            if staff_role == 'security':
                redirect_url = '/security/dashboard/'
            elif staff_role == 'maintenance':
                redirect_url = '/maintenance/dashboard/'
            else:
                # warden, admin, or other staff roles go to staff dashboard
                redirect_url = '/staff/'
        
        return JsonResponse({
            'success': True,
            'message': 'Login successful',
            'user_type': user_type,
            'is_first_login': is_first_login,
            'redirect_url': redirect_url,
            'user': {
                'name': user_object.name,
                'email': user_object.email,
                'id': user_object.student_id if user_type == 'student' else user_object.staff_id,
                'photoUrl': user_object.profile_photo.url if user_type == 'student' and user_object.profile_photo else None
            }
        })
        
    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        logger.error(f"Login error: {e}\n{error_details}")
        SecurityAuditLogger.log_security_event(
            event_type='login_error',
            details={'error': str(e), 'traceback': error_details},
            request=request,
            severity='ERROR'
        )
        return JsonResponse({
            'success': False,
            'error': 'An error occurred during login. Please try again.'
        }, status=500)


def logout_view(request):
    """
    Logout view that clears session and redirects to login.
    """
    # Log logout event
    user_id = request.session.get('user_id', 'unknown')
    user_type = request.session.get('user_type', 'unknown')
    
    SecurityAuditLogger.log_security_event(
        event_type='logout',
        details={'user_id': user_id, 'user_type': user_type},
        request=request,
        severity='INFO'
    )
    
    # Clear session
    request.session.flush()
    
    messages.success(request, 'You have been logged out successfully.')

    # SPA clients should receive JSON, not an HTML redirect.
    accepts_json = 'application/json' in (request.headers.get('Accept') or '')
    if request.path.startswith('/auth/') or accepts_json:
        return JsonResponse({
            'success': True,
            'message': 'Logged out successfully'
        })

    return redirect('login')


@api_view(['GET'])
@permission_classes([AllowAny])
def current_user_view(request):
    """Return current session user details for SPA auth bootstrap."""
    user_id = request.session.get('user_id')
    user_type = request.session.get('user_type')

    if not user_id or not user_type:
        return Response(
            {
                'success': False,
                'authenticated': False,
                'error': 'Not authenticated',
            },
            status=status.HTTP_401_UNAUTHORIZED,
        )

    try:
        if user_type == 'student':
            student = Student.objects.get(student_id=user_id)
            return Response(
                {
                    'success': True,
                    'authenticated': True,
                    'user_type': 'student',
                    'role': 'student',
                    'isFirstLogin': student.is_first_login,
                    'user': {
                        'id': student.student_id,
                        'name': student.name,
                        'email': student.email,
                        'photoUrl': student.profile_photo.url if student.profile_photo else None,
                    },
                }
            )

        staff = Staff.objects.get(staff_id=user_id, is_active=True)

        return Response(
            {
                'success': True,
                'authenticated': True,
                'user_type': 'staff',
                'role': staff.role,
                'isFirstLogin': staff.is_first_login,
                'user': {
                    'id': staff.staff_id,
                    'name': staff.name,
                    'email': staff.email,
                },
            }
        )

    except (Student.DoesNotExist, Staff.DoesNotExist):
        request.session.flush()
        return Response(
            {
                'success': False,
                'authenticated': False,
                'error': 'Session user not found',
            },
            status=status.HTTP_401_UNAUTHORIZED,
        )


def student_dashboard(request):
    """
    Student dashboard view with authentication check.
    """
    # Check authentication
    if not request.session.get('user_id') or request.session.get('user_type') != 'student':
        return redirect('login')
    
    try:
        student = Student.objects.get(student_id=request.session['user_id'])
        
        # Check if first-time login
        if student.is_first_login:
            return redirect('change_password')
        
        # Get student's recent activity
        recent_messages = student.messages.order_by('-created_at')[:5]
        recent_guest_requests = student.guest_requests.order_by('-created_at')[:5]
        recent_absence_records = student.absence_records.order_by('-created_at')[:5]
        recent_maintenance_requests = student.maintenance_requests.order_by('-created_at')[:5]
        
        context = {
            'student': student,
            'recent_messages': recent_messages,
            'recent_guest_requests': recent_guest_requests,
            'recent_absence_records': recent_absence_records,
            'recent_maintenance_requests': recent_maintenance_requests,
        }
        
        return render(request, 'student/dashboard.html', context)
        
    except Student.DoesNotExist:
        messages.error(request, 'Student account not found.')
        return redirect('login')


def change_password_view(request):
    """
    Password change view for first-time login and regular password changes.
    """
    # Check authentication
    if not request.session.get('user_id'):
        return redirect('login')
    
    user_type = request.session.get('user_type')
    user_id = request.session.get('user_id')
    
    if request.method == 'GET':
        try:
            if user_type == 'student':
                user_object = Student.objects.get(student_id=user_id)
            else:
                user_object = Staff.objects.get(staff_id=user_id)
            
            context = {
                'user': user_object,
                'user_type': user_type,
                'is_first_login': bool(getattr(user_object, 'is_first_login', False))
            }
            
            return render(request, 'auth/change_password.html', context)
            
        except (Student.DoesNotExist, Staff.DoesNotExist):
            messages.error(request, 'User account not found.')
            return redirect('login')
    
    elif request.method == 'POST':
        return handle_password_change(request)


@csrf_exempt
@require_http_methods(["POST"])
def handle_password_change(request):
    """
    Handle password change form submission.
    """
    try:
        # Parse request data
        if request.content_type == 'application/json':
            data = json.loads(request.body)
        else:
            data = request.POST
        
        current_password = data.get('current_password', '')
        new_password = data.get('new_password', '')
        confirm_password = data.get('confirm_password', '')
        mobile_number = data.get('mobile_number', '').strip()
        roll_number = data.get('roll_number', '').strip()
        
        user_type = request.session.get('user_type')
        user_id = request.session.get('user_id')
        
        # Validate input
        if not current_password or not new_password or not confirm_password:
            return JsonResponse({
                'success': False,
                'error': 'All password fields are required'
            }, status=400)
        
        if new_password != confirm_password:
            return JsonResponse({
                'success': False,
                'error': 'New passwords do not match'
            }, status=400)
        
        if len(new_password) < 6:
            return JsonResponse({
                'success': False,
                'error': 'New password must be at least 6 characters long'
            }, status=400)
        
        # Get user object
        try:
            if user_type == 'student':
                user_object = Student.objects.get(student_id=user_id)
            else:
                user_object = Staff.objects.get(staff_id=user_id)
        except (Student.DoesNotExist, Staff.DoesNotExist):
            return JsonResponse({
                'success': False,
                'error': 'User account not found'
            }, status=404)
        
        # Verify current password
        if not user_object.check_password(current_password):
            SecurityAuditLogger.log_security_event(
                event_type='password_change_failed',
                details={'user_id': user_id, 'user_type': user_type, 'reason': 'invalid_current_password'},
                request=request,
                severity='WARNING'
            )
            return JsonResponse({
                'success': False,
                'error': 'Current password is incorrect'
            }, status=401)
        
        # Update password and additional fields
        user_object.set_password(new_password)
        
        if user_type == 'student':
            if mobile_number:
                user_object.mobile_number = mobile_number
            if roll_number:
                user_object.roll_number = roll_number

        user_object.is_first_login = False
        
        user_object.save()
        
        # Log successful password change
        SecurityAuditLogger.log_security_event(
            event_type='password_changed',
            details={'user_id': user_id, 'user_type': user_type},
            request=request,
            severity='INFO'
        )
        
        # Determine redirect URL based on user type and role
        if user_type == 'student':
            password_redirect_url = '/student/dashboard/'
        else:
            staff_role = user_object.role if hasattr(user_object, 'role') else 'staff'
            if staff_role == 'security':
                password_redirect_url = '/security/dashboard/'
            elif staff_role == 'maintenance':
                password_redirect_url = '/maintenance/dashboard/'
            else:
                password_redirect_url = '/staff/'
        
        return JsonResponse({
            'success': True,
            'message': 'Password changed successfully',
            'redirect_url': password_redirect_url
        })
        
    except Exception as e:
        logger.error(f"Password change error: {e}")
        SecurityAuditLogger.log_security_event(
            event_type='password_change_error',
            details={'error': str(e)},
            request=request,
            severity='ERROR'
        )
        return JsonResponse({
            'success': False,
            'error': 'An error occurred while changing password. Please try again.'
        }, status=500)


@csrf_exempt
@require_http_methods(["POST"])
def upload_profile_photo(request):
    """
    Upload profile photo during first login.
    """
    try:
        user_type = request.session.get('user_type')
        user_id = request.session.get('user_id')
        
        if not user_id or user_type != 'student':
            return JsonResponse({
                'success': False,
                'error': 'Only students can upload profile photos'
            }, status=403)
        
        # Get the photo file from the request
        if 'photo' not in request.FILES:
            return JsonResponse({
                'success': False,
                'error': 'No photo file provided'
            }, status=400)
        
        photo_file = request.FILES['photo']
        
        # Validate file size (max 5MB)
        if photo_file.size > 5 * 1024 * 1024:
            return JsonResponse({
                'success': False,
                'error': 'Photo size must be less than 5MB'
            }, status=400)
        
        # Validate file type
        allowed_types = ['image/jpeg', 'image/jpg', 'image/png', 'image/gif']
        if photo_file.content_type not in allowed_types:
            return JsonResponse({
                'success': False,
                'error': 'Only JPEG, PNG, and GIF images are allowed'
            }, status=400)
        
        # Get student object
        try:
            student = Student.objects.get(student_id=user_id)
        except Student.DoesNotExist:
            return JsonResponse({
                'success': False,
                'error': 'Student account not found'
            }, status=404)
        
        # Save the photo
        student.profile_photo = photo_file
        student.save()
        
        # Log the photo upload
        SecurityAuditLogger.log_security_event(
            event_type='profile_photo_uploaded',
            details={'user_id': user_id, 'user_type': user_type},
            request=request,
            severity='INFO'
        )
        
        return JsonResponse({
            'success': True,
            'message': 'Profile photo uploaded successfully',
            'photo_url': student.profile_photo.url if student.profile_photo else None
        })
        
    except Exception as e:
        logger.error(f"Photo upload error: {e}")
        SecurityAuditLogger.log_security_event(
            event_type='photo_upload_error',
            details={'error': str(e)},
            request=request,
            severity='ERROR'
        )
        return JsonResponse({
            'success': False,
            'error': 'An error occurred while uploading photo. Please try again.'
        }, status=500)


def profile_view(request):
    """
    Profile view for both students and staff.
    """
    # Check authentication
    if not request.session.get('user_id'):
        return redirect('login')
    
    user_type = request.session.get('user_type')
    user_id = request.session.get('user_id')
    
    try:
        if user_type == 'student':
            user_object = Student.objects.get(student_id=user_id)
            template = 'student/profile.html'
        else:
            user_object = Staff.objects.get(staff_id=user_id)
            template = 'staff/profile.html'
            
            # For staff, also get all students if they have permission
            if user_object.role in ['warden', 'admin']:
                all_students = Student.objects.all().order_by('student_id')
                context = {
                    'user': user_object,
                    'user_type': user_type,
                    'all_students': all_students
                }
                return render(request, template, context)
        
        context = {
            'user': user_object,
            'user_type': user_type
        }
        
        return render(request, template, context)
        
    except (Student.DoesNotExist, Staff.DoesNotExist):
        messages.error(request, 'User account not found.')
        return redirect('login')


@api_view(['POST'])
@permission_classes([AllowAny])
def upload_student_photo(request):
    """
    API endpoint for students to upload their profile photo.
    Used during first login setup.
    """
    # Check if user is authenticated student
    if not request.session.get('user_id') or request.session.get('user_type') != 'student':
        return Response({
            'success': False,
            'error': 'Student authentication required'
        }, status=status.HTTP_401_UNAUTHORIZED)
    
    try:
        student = Student.objects.get(student_id=request.session['user_id'])
    except Student.DoesNotExist:
        return Response({
            'success': False,
            'error': 'Student account not found'
        }, status=status.HTTP_404_NOT_FOUND)
    
    try:
        # Get uploaded photo
        if 'photo' not in request.FILES:
            return Response({
                'success': False,
                'error': 'Photo file is required'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        photo_file = request.FILES['photo']
        
        # Validate file type (only images allowed)
        allowed_types = ['image/jpeg', 'image/png', 'image/gif', 'image/webp']
        if photo_file.content_type not in allowed_types:
            return Response({
                'success': False,
                'error': 'Only image files (JPEG, PNG, GIF, WebP) are allowed'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Validate file size (max 5MB)
        max_size = 5 * 1024 * 1024  # 5MB
        if photo_file.size > max_size:
            return Response({
                'success': False,
                'error': 'Photo size must be less than 5MB'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Delete old photo if it exists
        if student.profile_photo:
            if student.profile_photo.storage.exists(student.profile_photo.name):
                student.profile_photo.delete(save=False)
        
        # Save the new photo
        student.profile_photo = photo_file
        student.save()
        
        # Log photo upload
        SecurityAuditLogger.log_security_event(
            event_type='profile_photo_uploaded',
            details={
                'student_id': student.student_id,
                'file_name': photo_file.name,
                'file_size': photo_file.size
            },
            request=request,
            severity='INFO'
        )
        
        return Response({
            'success': True,
            'message': 'Profile photo uploaded successfully',
            'photo_url': student.profile_photo.url if student.profile_photo else None
        }, status=status.HTTP_200_OK)
        
    except Exception as e:
        logger.error(f"Error uploading student photo: {e}")
        return Response({
            'success': False,
            'error': 'An error occurred while uploading the photo. Please try again.'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([AllowAny])
def update_student_profile(request):
    """
    API endpoint for students to update their own profile information.
    """
    # Check if user is authenticated student
    if not request.session.get('user_id') or request.session.get('user_type') != 'student':
        return Response({
            'success': False,
            'error': 'Student authentication required'
        }, status=status.HTTP_401_UNAUTHORIZED)
    
    try:
        student = Student.objects.get(student_id=request.session['user_id'])
    except Student.DoesNotExist:
        return Response({
            'success': False,
            'error': 'Student account not found'
        }, status=status.HTTP_404_NOT_FOUND)
    
    try:
        # Get form data
        mobile_number = request.data.get('mobile_number', '').strip()
        
        # Update allowed fields
        if mobile_number:
            student.mobile_number = mobile_number
        
        student.save()
        
        # Log profile update
        SecurityAuditLogger.log_security_event(
            event_type='profile_updated',
            details={
                'student_id': student.student_id,
                'fields_updated': ['mobile_number']
            },
            request=request,
            severity='INFO'
        )
        
        return Response({
            'success': True,
            'message': 'Profile updated successfully',
            'student': {
                'student_id': student.student_id,
                'name': student.name,
                'email': student.email,
                'mobile_number': student.mobile_number,
                'room_number': student.room_number,
                'block': student.block
            }
        }, status=status.HTTP_200_OK)
        
    except Exception as e:
        logger.error(f"Error updating student profile: {e}")
        return Response({
            'success': False,
            'error': 'An error occurred while updating the profile. Please try again.'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([AllowAny])
def update_staff_student_profile(request):
    """
    API endpoint for staff to update student profile information.
    Only accessible by warden and admin staff.
    """
    # Check if user is authenticated staff with proper permissions
    if not request.session.get('user_id') or request.session.get('user_type') != 'staff':
        return Response({
            'success': False,
            'error': 'Staff authentication required'
        }, status=status.HTTP_401_UNAUTHORIZED)
    
    try:
        staff = Staff.objects.get(staff_id=request.session['user_id'])
        if staff.role not in ['warden', 'admin']:
            return Response({
                'success': False,
                'error': 'Insufficient permissions'
            }, status=status.HTTP_403_FORBIDDEN)
    except Staff.DoesNotExist:
        return Response({
            'success': False,
            'error': 'Staff account not found'
        }, status=status.HTTP_404_NOT_FOUND)
    
    try:
        # Get student to update
        student_id = request.data.get('student_id', '').strip()
        if not student_id:
            return Response({
                'success': False,
                'error': 'Student ID is required'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            student = Student.objects.get(student_id=student_id)
        except Student.DoesNotExist:
            return Response({
                'success': False,
                'error': 'Student not found'
            }, status=status.HTTP_404_NOT_FOUND)
        
        # Get form data
        name = request.data.get('name', '').strip()
        email = request.data.get('email', '').strip().lower()
        mobile_number = request.data.get('mobile_number', '').strip()
        room_number = request.data.get('room_number', '').strip()
        block = request.data.get('block', '').strip().upper()
        phone = request.data.get('phone', '').strip()
        parent_phone_raw = request.data.get('parent_phone')

        # Normalize and validate student contact number when provided.
        if phone:
            phone = ''.join(ch for ch in phone if ch.isdigit())
            if len(phone) != 10:
                return Response({
                    'success': False,
                    'error': 'Contact number must be 10 digits'
                }, status=status.HTTP_400_BAD_REQUEST)
        
        updated_fields = []
        
        # Update fields if provided
        if name and name != student.name:
            student.name = name
            updated_fields.append('name')
        
        if email and email != student.email:
            # Check if email is already in use
            if Student.objects.filter(email=email).exclude(student_id=student_id).exists():
                return Response({
                    'success': False,
                    'error': f'Email {email} is already in use'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            try:
                validate_email(email)
                student.email = email
                updated_fields.append('email')
            except ValidationError:
                return Response({
                    'success': False,
                    'error': 'Please enter a valid email address'
                }, status=status.HTTP_400_BAD_REQUEST)
        
        if mobile_number != student.mobile_number:
            student.mobile_number = mobile_number
            updated_fields.append('mobile_number')
        
        if room_number and room_number != student.room_number:
            student.room_number = room_number
            updated_fields.append('room_number')
        
        if block and block != student.block:
            student.block = block
            updated_fields.append('block')
        
        if phone != student.phone:
            student.phone = phone
            updated_fields.append('phone')

        if parent_phone_raw is not None:
            parent_phone = ''.join(ch for ch in str(parent_phone_raw).strip() if ch.isdigit())
            if len(parent_phone) != 12:
                return Response({
                    'success': False,
                    'error': 'Parent contact must be 12 digits with country code (without +)'
                }, status=status.HTTP_400_BAD_REQUEST)
            if parent_phone != student.parent_phone:
                student.parent_phone = parent_phone
                updated_fields.append('parent_phone')
        
        if updated_fields:
            student.save()
            
            # Log profile update
            SecurityAuditLogger.log_security_event(
                event_type='student_profile_updated_by_staff',
                details={
                    'student_id': student.student_id,
                    'updated_by': staff.staff_id,
                    'fields_updated': updated_fields
                },
                request=request,
                severity='INFO'
            )
        
        return Response({
            'success': True,
            'message': f'Student profile updated successfully' + (f' ({len(updated_fields)} fields changed)' if updated_fields else ' (no changes)'),
            'student': {
                'student_id': student.student_id,
                'name': student.name,
                'email': student.email,
                'mobile_number': student.mobile_number,
                'room_number': student.room_number,
                'block': student.block,
                'phone': student.phone,
                'parent_phone': student.parent_phone
            }
        }, status=status.HTTP_200_OK)
        
    except Exception as e:
        logger.error(f"Error updating student profile by staff: {e}")
        return Response({
            'success': False,
            'error': 'An error occurred while updating the profile. Please try again.'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([AllowAny])
def create_staff_account(request):
    """
    API endpoint for admins to create staff accounts.
    Creates only operational roles (warden/security/maintenance).
    """
    if not request.session.get('user_id') or request.session.get('user_type') != 'staff':
        return Response({
            'success': False,
            'error': 'Authentication required'
        }, status=status.HTTP_401_UNAUTHORIZED)

    try:
        actor = Staff.objects.get(staff_id=request.session['user_id'])
        if actor.role != 'admin':
            return Response({
                'success': False,
                'error': 'Only admin can create staff accounts'
            }, status=status.HTTP_403_FORBIDDEN)
    except Staff.DoesNotExist:
        return Response({
            'success': False,
            'error': 'Staff account not found'
        }, status=status.HTTP_404_NOT_FOUND)

    def generate_staff_id(role: str) -> str:
        prefix_map = {
            'warden': 'WRD',
            'security': 'SEC',
            'maintenance': 'MNT',
        }
        prefix = prefix_map[role]
        existing_ids = Staff.objects.filter(
            role=role,
            staff_id__startswith=prefix,
        ).values_list('staff_id', flat=True)

        max_number = 0
        for existing_id in existing_ids:
            suffix = existing_id[len(prefix):]
            if suffix.isdigit():
                max_number = max(max_number, int(suffix))

        return f"{prefix}{max_number + 1:03d}"

    try:
        name = request.data.get('name', '').strip()
        role = request.data.get('role', '').strip().lower()
        email = request.data.get('email', '').strip().lower()
        phone = request.data.get('phone', '').strip()

        if not all([name, role, email, phone]):
            return Response({
                'success': False,
                'error': 'Name, role, email, and phone are required'
            }, status=status.HTTP_400_BAD_REQUEST)

        allowed_roles = {'warden', 'security', 'maintenance'}
        if role not in allowed_roles:
            return Response({
                'success': False,
                'error': 'Role must be one of: warden, security, maintenance'
            }, status=status.HTTP_400_BAD_REQUEST)

        phone = ''.join(ch for ch in phone if ch.isdigit())
        if len(phone) != 10:
            return Response({
                'success': False,
                'error': 'Phone number must be 10 digits'
            }, status=status.HTTP_400_BAD_REQUEST)

        try:
            validate_email(email)
        except ValidationError:
            return Response({
                'success': False,
                'error': 'Please enter a valid email address'
            }, status=status.HTTP_400_BAD_REQUEST)

        if Staff.objects.filter(email=email).exists() or Student.objects.filter(email=email).exists():
            return Response({
                'success': False,
                'error': f'Email {email} is already registered'
            }, status=status.HTTP_400_BAD_REQUEST)

        staff_id = generate_staff_id(role)
        default_password = f"{role}4567"

        created_staff = Staff.objects.create(
            staff_id=staff_id,
            name=name,
            email=email,
            role=role,
            phone=phone,
            permissions={},
            is_first_login=True,
            is_active=True,
        )
        created_staff.set_password(default_password)
        created_staff.save()

        SecurityAuditLogger.log_security_event(
            event_type='staff_account_created',
            details={
                'staff_id': staff_id,
                'created_by': actor.staff_id,
                'role': role,
                'email': email,
            },
            request=request,
            severity='INFO'
        )

        return Response({
            'success': True,
            'message': f'{role.title()} account created successfully for {name}',
            'staff': {
                'staff_id': staff_id,
                'name': name,
                'role': role,
                'email': email,
                'phone': phone,
                'default_password': default_password,
            }
        }, status=status.HTTP_201_CREATED)

    except Exception as e:
        logger.error(f"Error creating staff account: {e}")
        return Response({
            'success': False,
            'error': 'An error occurred while creating the account. Please try again.'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([AllowAny])
def create_student_account(request):
    """
    API endpoint for staff to create new student accounts.
    Only accessible by warden and admin staff.
    """
    # Check if user is authenticated staff with proper permissions
    if not request.session.get('user_id') or request.session.get('user_type') != 'staff':
        return Response({
            'success': False,
            'error': 'Authentication required'
        }, status=status.HTTP_401_UNAUTHORIZED)
    
    try:
        staff = Staff.objects.get(staff_id=request.session['user_id'])
        if staff.role not in ['warden', 'admin']:
            return Response({
                'success': False,
                'error': 'Insufficient permissions'
            }, status=status.HTTP_403_FORBIDDEN)
    except Staff.DoesNotExist:
        return Response({
            'success': False,
            'error': 'Staff account not found'
        }, status=status.HTTP_404_NOT_FOUND)
    
    try:
        # Get form data
        student_id = request.data.get('student_id', '').strip().upper()
        name = request.data.get('name', '').strip()
        email = request.data.get('email', '').strip().lower()
        room_number = request.data.get('room_number', '').strip()
        block = request.data.get('block', '').strip().upper()
        phone = request.data.get('phone', '').strip()
        parent_phone = request.data.get('parent_phone', '').strip()
        
        # Validate required fields
        if not all([student_id, name, email, room_number, block, phone, parent_phone]):
            return Response({
                'success': False,
                'error': 'Student ID, name, email, room number, block, phone, and parent phone are required'
            }, status=status.HTTP_400_BAD_REQUEST)

        # Normalize and validate phone formats
        phone = ''.join(ch for ch in phone if ch.isdigit())
        parent_phone = ''.join(ch for ch in parent_phone if ch.isdigit())

        if len(phone) != 10:
            return Response({
                'success': False,
                'error': 'Phone number must be 10 digits'
            }, status=status.HTTP_400_BAD_REQUEST)

        if len(parent_phone) != 12:
            return Response({
                'success': False,
                'error': 'Parent phone must be 12 digits with country code (without +)'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Validate email format
        try:
            validate_email(email)
        except ValidationError:
            return Response({
                'success': False,
                'error': 'Please enter a valid email address'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Check if student ID or email already exists
        if Student.objects.filter(student_id=student_id).exists():
            return Response({
                'success': False,
                'error': f'Student ID {student_id} already exists'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        if Student.objects.filter(email=email).exists():
            return Response({
                'success': False,
                'error': f'Email {email} is already registered'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Generate default password
        default_password = Student.generate_default_password()
        
        # Create student account
        student = Student.objects.create(
            student_id=student_id,
            name=name,
            email=email,
            room_number=room_number,
            block=block,
            phone=phone,
            parent_phone=parent_phone,
            is_first_login=True
        )
        student.set_password(default_password)
        student.save()
        
        # Log account creation
        SecurityAuditLogger.log_security_event(
            event_type='student_account_created',
            details={
                'student_id': student_id,
                'created_by': staff.staff_id,
                'email': email
            },
            request=request,
            severity='INFO'
        )
        
        # TODO: Send email with login credentials (implement in email notification task)
        
        return Response({
            'success': True,
            'message': f'Student account created successfully for {name}',
            'student': {
                'student_id': student_id,
                'name': name,
                'email': email,
                'room_number': room_number,
                'block': block,
                'default_password': default_password  # In production, this should be sent via email
            }
        }, status=status.HTTP_201_CREATED)
        
    except Exception as e:
        logger.error(f"Error creating student account: {e}")
        return Response({
            'success': False,
            'error': 'An error occurred while creating the account. Please try again.'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([AllowAny])
def delete_student_account(request):
    """
    API endpoint for staff to delete a student account.
    Only accessible by warden and admin staff.
    """
    if not request.session.get('user_id') or request.session.get('user_type') != 'staff':
        return Response({
            'success': False,
            'error': 'Staff authentication required'
        }, status=status.HTTP_401_UNAUTHORIZED)

    try:
        staff = Staff.objects.get(staff_id=request.session['user_id'])
        if staff.role not in ['warden', 'admin']:
            return Response({
                'success': False,
                'error': 'Insufficient permissions'
            }, status=status.HTTP_403_FORBIDDEN)
    except Staff.DoesNotExist:
        return Response({
            'success': False,
            'error': 'Staff account not found'
        }, status=status.HTTP_404_NOT_FOUND)

    student_id = request.data.get('student_id', '').strip().upper()
    delete_reason = request.data.get('reason', '').strip()
    if not student_id:
        return Response({
            'success': False,
            'error': 'Student ID is required'
        }, status=status.HTTP_400_BAD_REQUEST)

    if staff.role != 'admin' and not delete_reason:
        return Response({
            'success': False,
            'error': 'Deletion reason is required'
        }, status=status.HTTP_400_BAD_REQUEST)

    if staff.role == 'admin' and not delete_reason:
        delete_reason = 'Removed by admin'

    try:
        student = Student.objects.get(student_id=student_id)
    except Student.DoesNotExist:
        return Response({
            'success': False,
            'error': 'Student not found'
        }, status=status.HTTP_404_NOT_FOUND)

    try:
        deleted_student_name = student.name

        with transaction.atomic():
            with connection.cursor() as cursor:
                # Resolve internal PK once and delete dependent rows in safe order.
                cursor.execute(
                    "SELECT id FROM students WHERE student_id = %s",
                    [student_id]
                )
                row = cursor.fetchone()
                if not row:
                    return Response({
                        'success': False,
                        'error': 'Student not found'
                    }, status=status.HTTP_404_NOT_FOUND)

                student_pk = row[0]

                # Remove children first to satisfy SQLite FK constraints.
                cursor.execute(
                    "DELETE FROM security_records WHERE student_id = %s",
                    [student_pk]
                )
                cursor.execute(
                    "DELETE FROM digital_passes WHERE student_id = %s",
                    [student_pk]
                )
                cursor.execute(
                    "DELETE FROM maintenance_requests WHERE student_id = %s",
                    [student_pk]
                )
                cursor.execute(
                    "DELETE FROM guest_requests WHERE student_id = %s",
                    [student_pk]
                )
                cursor.execute(
                    "DELETE FROM absence_records WHERE student_id = %s",
                    [student_pk]
                )
                cursor.execute(
                    "DELETE FROM conversation_contexts WHERE student_id = %s",
                    [student_pk]
                )

                # Some DB snapshots include a legacy messages table with FK to students.
                cursor.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'messages'"
                )
                has_messages_table = cursor.fetchone() is not None
                if has_messages_table:
                    cursor.execute(
                        "DELETE FROM messages WHERE sender_id = %s",
                        [student_pk]
                    )

                # Final parent delete.
                cursor.execute(
                    "DELETE FROM students WHERE id = %s",
                    [student_pk]
                )

        SecurityAuditLogger.log_security_event(
            event_type='student_account_deleted',
            details={
                'student_id': student_id,
                'student_name': deleted_student_name,
                'deleted_by': staff.staff_id,
                'reason': delete_reason
            },
            request=request,
            severity='WARNING'
        )

        return Response({
            'success': True,
            'message': f'Student account {student_id} deleted successfully',
            'deleted_student_id': student_id
        }, status=status.HTTP_200_OK)
    except Exception as e:
        logger.error(f"Error deleting student account {student_id}: {e}")
        return Response({
            'success': False,
            'error': 'An error occurred while deleting the student account. Please try again.'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([AllowAny])
def delete_staff_account(request):
    """
    API endpoint for admin to delete staff accounts.
    """
    if not request.session.get('user_id') or request.session.get('user_type') != 'staff':
        return Response({
            'success': False,
            'error': 'Staff authentication required'
        }, status=status.HTTP_401_UNAUTHORIZED)

    try:
        actor = Staff.objects.get(staff_id=request.session['user_id'])
        if actor.role != 'admin':
            return Response({
                'success': False,
                'error': 'Only admin can delete staff accounts'
            }, status=status.HTTP_403_FORBIDDEN)
    except Staff.DoesNotExist:
        return Response({
            'success': False,
            'error': 'Staff account not found'
        }, status=status.HTTP_404_NOT_FOUND)

    staff_id = request.data.get('staff_id', '').strip().upper()
    if not staff_id:
        return Response({
            'success': False,
            'error': 'Staff ID is required'
        }, status=status.HTTP_400_BAD_REQUEST)

    if staff_id == actor.staff_id:
        return Response({
            'success': False,
            'error': 'You cannot delete your own account'
        }, status=status.HTTP_400_BAD_REQUEST)

    try:
        target_staff = Staff.objects.get(staff_id=staff_id)
    except Staff.DoesNotExist:
        return Response({
            'success': False,
            'error': 'Staff not found'
        }, status=status.HTTP_404_NOT_FOUND)

    # Keep at least one admin account in the system.
    if target_staff.role == 'admin' and Staff.objects.filter(role='admin', is_active=True).count() <= 1:
        return Response({
            'success': False,
            'error': 'Cannot delete the last active admin account'
        }, status=status.HTTP_400_BAD_REQUEST)

    try:
        deleted_staff_name = target_staff.name
        deleted_staff_role = target_staff.role
        target_staff.delete()

        SecurityAuditLogger.log_security_event(
            event_type='staff_account_deleted',
            details={
                'staff_id': staff_id,
                'staff_name': deleted_staff_name,
                'staff_role': deleted_staff_role,
                'deleted_by': actor.staff_id,
            },
            request=request,
            severity='WARNING'
        )

        return Response({
            'success': True,
            'message': f'Staff account {staff_id} deleted successfully',
            'deleted_staff_id': staff_id
        }, status=status.HTTP_200_OK)
    except Exception as e:
        logger.error(f"Error deleting staff account {staff_id}: {e}")
        return Response({
            'success': False,
            'error': 'An error occurred while deleting the staff account. Please try again.'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


def require_authentication(view_func):
    """
    Decorator to require session-based authentication.
    """
    def wrapper(request, *args, **kwargs):
        if not request.session.get('user_id'):
            if request.headers.get('Content-Type') == 'application/json':
                return JsonResponse({
                    'success': False,
                    'error': 'Authentication required',
                    'redirect_url': '/login/'
                }, status=401)
            else:
                return redirect('login')
        return view_func(request, *args, **kwargs)
    return wrapper


def require_staff_authentication(view_func):
    """
    Decorator to require staff authentication.
    """
    def wrapper(request, *args, **kwargs):
        if not request.session.get('user_id') or request.session.get('user_type') != 'staff':
            if request.headers.get('Content-Type') == 'application/json':
                return JsonResponse({
                    'success': False,
                    'error': 'Staff authentication required',
                    'redirect_url': '/login/'
                }, status=403)
            else:
                messages.error(request, 'Staff access required.')
                return redirect('login')
        return view_func(request, *args, **kwargs)
    return wrapper