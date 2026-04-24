"""
Unit tests for the get_authenticated_user helper function.
Tests both JWT and session authentication methods.
"""

import pytest
from django.test import TestCase, RequestFactory
from django.contrib.sessions.middleware import SessionMiddleware
from unittest.mock import Mock, patch

from core.authentication import get_authenticated_user, SupabaseUser
from core.models import Student, Staff


class TestGetAuthenticatedUser(TestCase):
    """Test the unified authentication helper function"""
    
    def setUp(self):
        """Set up test data"""
        self.factory = RequestFactory()
        
        # Create test student
        self.student = Student.objects.create(
            student_id='TEST001',
            name='Test Student',
            email='test001@hostel.edu',
            room_number='101',
            block='A'
        )
        self.student.set_password('password123')
        self.student.save()
        
        # Create test staff
        self.staff = Staff.objects.create(
            staff_id='STAFF001',
            name='Test Staff',
            email='staff001@hostel.edu',
            role='warden'
        )
        self.staff.set_password('password123')
        self.staff.save()
    
    def _add_session_to_request(self, request):
        """Helper to add session support to request"""
        middleware = SessionMiddleware(lambda x: None)
        middleware.process_request(request)
        request.session.save()
        return request
    
    def test_jwt_authentication_returns_correct_user(self):
        """Test JWT authentication returns correct user object"""
        request = self.factory.get('/api/test/')
        request = self._add_session_to_request(request)
        
        # Mock JWT authenticated user
        user_data = {
            'id': 'jwt-user-id',
            'email': 'test001@hostel.edu',
            'user_metadata': {}
        }
        request.user = SupabaseUser(user_data, 'student', self.student)
        
        user_object, auth_type = get_authenticated_user(request)
        
        self.assertEqual(user_object, self.student)
        self.assertEqual(auth_type, 'jwt')
        self.assertIsInstance(user_object, Student)
    
    def test_session_authentication_for_students(self):
        """Test session authentication retrieves student correctly"""
        request = self.factory.get('/api/test/')
        request = self._add_session_to_request(request)
        
        # Set up session authentication
        request.session['user_id'] = 'TEST001'
        request.session['user_type'] = 'student'
        request.session.save()
        
        # Mock user without JWT
        request.user = Mock()
        request.user.user_object = None
        
        user_object, auth_type = get_authenticated_user(request)
        
        self.assertEqual(user_object, self.student)
        self.assertEqual(auth_type, 'session')
        self.assertIsInstance(user_object, Student)
        self.assertEqual(user_object.student_id, 'TEST001')
    
    def test_session_authentication_for_staff(self):
        """Test session authentication retrieves staff correctly"""
        request = self.factory.get('/api/test/')
        request = self._add_session_to_request(request)
        
        # Set up session authentication
        request.session['user_id'] = 'STAFF001'
        request.session['user_type'] = 'staff'
        request.session.save()
        
        # Mock user without JWT
        request.user = Mock()
        request.user.user_object = None
        
        user_object, auth_type = get_authenticated_user(request)
        
        self.assertEqual(user_object, self.staff)
        self.assertEqual(auth_type, 'session')
        self.assertIsInstance(user_object, Staff)
        self.assertEqual(user_object.staff_id, 'STAFF001')
    
    def test_no_authentication_returns_none(self):
        """Test no authentication returns (None, 'none')"""
        request = self.factory.get('/api/test/')
        request = self._add_session_to_request(request)
        
        # Mock user without JWT
        request.user = Mock()
        request.user.user_object = None
        
        user_object, auth_type = get_authenticated_user(request)
        
        self.assertIsNone(user_object)
        self.assertEqual(auth_type, 'none')
    
    def test_invalid_session_returns_session_invalid(self):
        """Test invalid session (user not found) returns (None, 'session_invalid')"""
        request = self.factory.get('/api/test/')
        request = self._add_session_to_request(request)
        
        # Set up session with non-existent user
        request.session['user_id'] = 'NONEXISTENT999'
        request.session['user_type'] = 'student'
        request.session.save()
        
        # Mock user without JWT
        request.user = Mock()
        request.user.user_object = None
        
        user_object, auth_type = get_authenticated_user(request)
        
        self.assertIsNone(user_object)
        self.assertEqual(auth_type, 'session_invalid')
    
    def test_jwt_takes_precedence_over_session(self):
        """Test JWT authentication takes precedence over session"""
        request = self.factory.get('/api/test/')
        request = self._add_session_to_request(request)
        
        # Set up both JWT and session authentication
        # JWT for student
        user_data = {
            'id': 'jwt-user-id',
            'email': 'test001@hostel.edu',
            'user_metadata': {}
        }
        request.user = SupabaseUser(user_data, 'student', self.student)
        
        # Session for staff (different user)
        request.session['user_id'] = 'STAFF001'
        request.session['user_type'] = 'staff'
        request.session.save()
        
        user_object, auth_type = get_authenticated_user(request)
        
        # Should return JWT user (student), not session user (staff)
        self.assertEqual(user_object, self.student)
        self.assertEqual(auth_type, 'jwt')
        self.assertIsInstance(user_object, Student)
    
    def test_inactive_staff_returns_session_invalid(self):
        """Test session authentication fails for inactive staff"""
        # Create inactive staff
        inactive_staff = Staff.objects.create(
            staff_id='INACTIVE001',
            name='Inactive Staff',
            email='inactive@hostel.edu',
            role='security',
            is_active=False
        )
        
        request = self.factory.get('/api/test/')
        request = self._add_session_to_request(request)
        
        # Set up session for inactive staff
        request.session['user_id'] = 'INACTIVE001'
        request.session['user_type'] = 'staff'
        request.session.save()
        
        # Mock user without JWT
        request.user = Mock()
        request.user.user_object = None
        
        user_object, auth_type = get_authenticated_user(request)
        
        self.assertIsNone(user_object)
        self.assertEqual(auth_type, 'session_invalid')
    
    def test_invalid_user_type_in_session(self):
        """Test invalid user_type in session returns session_invalid"""
        request = self.factory.get('/api/test/')
        request = self._add_session_to_request(request)
        
        # Set up session with invalid user_type
        request.session['user_id'] = 'TEST001'
        request.session['user_type'] = 'invalid_type'
        request.session.save()
        
        # Mock user without JWT
        request.user = Mock()
        request.user.user_object = None
        
        user_object, auth_type = get_authenticated_user(request)
        
        self.assertIsNone(user_object)
        self.assertEqual(auth_type, 'session_invalid')
    
    def test_session_with_missing_user_id(self):
        """Test session with user_type but no user_id returns none"""
        request = self.factory.get('/api/test/')
        request = self._add_session_to_request(request)
        
        # Set up incomplete session (only user_type)
        request.session['user_type'] = 'student'
        request.session.save()
        
        # Mock user without JWT
        request.user = Mock()
        request.user.user_object = None
        
        user_object, auth_type = get_authenticated_user(request)
        
        self.assertIsNone(user_object)
        self.assertEqual(auth_type, 'none')
    
    def test_session_with_missing_user_type(self):
        """Test session with user_id but no user_type returns none"""
        request = self.factory.get('/api/test/')
        request = self._add_session_to_request(request)
        
        # Set up incomplete session (only user_id)
        request.session['user_id'] = 'TEST001'
        request.session.save()
        
        # Mock user without JWT
        request.user = Mock()
        request.user.user_object = None
        
        user_object, auth_type = get_authenticated_user(request)
        
        self.assertIsNone(user_object)
        self.assertEqual(auth_type, 'none')
