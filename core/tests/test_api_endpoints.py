"""
Tests for REST API endpoints.
Tests core API functionality, authentication, and authorization.
"""

import pytest
from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient
from rest_framework import status
from unittest.mock import patch

from ..models import Student, Staff, Message, GuestRequest
from ..authentication import SupabaseUser


class APIEndpointsTest(TestCase):
    """Test cases for REST API endpoints."""
    
    def setUp(self):
        """Set up test data."""
        self.client = APIClient()
        
        # Create test student
        self.student = Student.objects.create(
            student_id="TEST001",
            name="Test Student",
            room_number="101A",
            block="A",
            phone="1234567890"
        )
        
        # Create test staff
        self.staff = Staff.objects.create(
            staff_id="STAFF001",
            name="Test Staff",
            role="warden",
            permissions={"approve_guests": True},
            phone="0987654321",
            email="staff@hostel.edu"
        )
        
        # Create authenticated users
        self.student_user = SupabaseUser(
            {'id': 'test-student-001', 'email': 'test001@hostel.edu', 'user_metadata': {'role': 'student'}},
            'student',
            self.student
        )
        
        self.staff_user = SupabaseUser(
            {'id': 'test-staff-001', 'email': 'staff@hostel.edu', 'user_metadata': {'role': 'staff'}},
            'staff',
            self.staff
        )
    
    def test_health_check_endpoint(self):
        """Test health check endpoint."""
        url = reverse('core:health_check')
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('status', response.data)
        self.assertIn('services', response.data)
        self.assertIn('version', response.data)
    
    def test_system_info_endpoint(self):
        """Test system info endpoint."""
        url = reverse('core:system_info')
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('project', response.data)
        self.assertIn('features', response.data)
        self.assertIn('endpoints', response.data)
    
    def test_message_creation_without_auth(self):
        """Test that message creation requires authentication."""
        url = reverse('core:message-list')
        data = {
            'sender': self.student.pk,
            'content': 'Test message'
        }
        response = self.client.post(url, data)
        
        # Should require authentication
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
    
    def test_message_creation_with_dev_auth(self):
        """Test message creation with development authentication."""
        # Force authenticate the client
        self.client.force_authenticate(user=self.student_user)
        
        url = reverse('core:message-list')
        data = {
            'sender': self.student.pk,
            'content': 'My friend will stay tonight'
        }
        
        response = self.client.post(url, data)
        
        # Should succeed with proper authentication
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn('success', response.data)
        self.assertIn('message_id', response.data)
        self.assertIn('response_message', response.data)
    
    def test_guest_request_list_with_auth(self):
        """Test guest request list with authentication."""
        # Create a guest request
        guest_request = GuestRequest.objects.create(
            student=self.student,
            guest_name="Test Guest",
            start_date="2024-01-15T18:00:00Z",
            end_date="2024-01-16T10:00:00Z"
        )
        
        # Authenticate as student
        self.client.force_authenticate(user=self.student_user)
        
        url = reverse('core:guestrequest-list')
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('results', response.data)
    
    def test_staff_only_endpoints(self):
        """Test that staff-only endpoints require staff authentication."""
        url = reverse('core:daily_summary')
        
        # Try with student auth - should fail
        self.client.force_authenticate(user=self.student_user)
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        
        # Try with staff auth - should succeed
        self.client.force_authenticate(user=self.staff_user)
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
    
    def test_conversation_status_endpoint(self):
        """Test conversation status endpoint."""
        self.client.force_authenticate(user=self.student_user)
        
        url = reverse('core:conversation_status')
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('conversations', response.data)
    
    def test_student_requests_endpoint(self):
        """Test student requests endpoint."""
        self.client.force_authenticate(user=self.student_user)
        
        url = reverse('core:student-requests', kwargs={'student_id': 'TEST001'})
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('student', response.data)
        self.assertIn('guest_requests', response.data)
        self.assertIn('absence_records', response.data)
        self.assertIn('maintenance_requests', response.data)
    
    def test_api_pagination(self):
        """Test API pagination works correctly."""
        # Create multiple messages
        for i in range(25):
            Message.objects.create(
                sender=self.student,
                content=f'Test message {i}',
                status='processed'
            )
        
        self.client.force_authenticate(user=self.student_user)
        
        url = reverse('core:message-list')
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('results', response.data)
        self.assertIn('count', response.data)
        self.assertIn('next', response.data)
        self.assertEqual(len(response.data['results']), 20)  # Default page size
    
    def test_message_filtering(self):
        """Test message filtering by student."""
        # Create messages for different students
        other_student = Student.objects.create(
            student_id="TEST002",
            name="Other Student",
            room_number="102A",
            block="A"
        )
        
        Message.objects.create(sender=self.student, content="Student 1 message")
        Message.objects.create(sender=other_student, content="Student 2 message")
        
        self.client.force_authenticate(user=self.staff_user)
        
        url = reverse('core:message-by-student')
        response = self.client.get(url, {'student_id': 'TEST001'})
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Should only return messages from TEST001
        for message in response.data:
            self.assertEqual(message['sender_name'], 'Test Student')


class AuthenticationTest(TestCase):
    """Test cases for authentication system."""
    
    def setUp(self):
        """Set up test data."""
        self.student = Student.objects.create(
            student_id="AUTH001",
            name="Auth Test Student",
            room_number="201A",
            block="B"
        )
    
    def test_development_bypass_authentication(self):
        """Test development bypass authentication."""
        from ..authentication import DevelopmentBypassAuthentication
        from django.http import HttpRequest
        import logging
        
        # Enable debug logging
        logging.getLogger('core.authentication').setLevel(logging.DEBUG)
        
        auth = DevelopmentBypassAuthentication()
        request = HttpRequest()
        
        # Test without headers
        result = auth.authenticate(request)
        self.assertIsNone(result)
        
        # Verify student exists
        print(f"Student exists: {Student.objects.filter(student_id='AUTH001').exists()}")
        print(f"Student count: {Student.objects.count()}")
        
        # Test with student headers - use existing student from setUp
        request.META['HTTP_X_DEV_USER_TYPE'] = 'student'
        request.META['HTTP_X_DEV_USER_ID'] = 'AUTH001'
        
        result = auth.authenticate(request)
        print(f"Authentication result: {result}")
        
        self.assertIsNotNone(result)
        
        user, token = result
        self.assertEqual(user.user_type, 'student')
        self.assertEqual(user.user_object, self.student)
        self.assertTrue(user.is_authenticated)
    
    def test_supabase_user_properties(self):
        """Test SupabaseUser properties."""
        user_data = {
            'id': 'test-id',
            'email': 'test@example.com',
            'user_metadata': {'role': 'student'}
        }
        
        user = SupabaseUser(user_data, 'student', self.student)
        
        self.assertTrue(user.is_student)
        self.assertFalse(user.is_staff_member)
        self.assertTrue(user.is_authenticated)
        self.assertFalse(user.is_anonymous)
        self.assertEqual(str(user), 'student: test@example.com')


class PermissionTest(TestCase):
    """Test cases for permission system."""
    
    def setUp(self):
        """Set up test data."""
        self.student = Student.objects.create(
            student_id="PERM001",
            name="Permission Test Student",
            room_number="301A",
            block="C"
        )
        
        self.staff = Staff.objects.create(
            staff_id="PERM_STAFF",
            name="Permission Test Staff",
            role="warden",
            email="perm@hostel.edu"
        )
    
    def test_permission_classes(self):
        """Test custom permission classes."""
        from ..authentication import IsStudentOrStaff, IsStaffOnly, IsStudentOnly
        
        # Create mock request with student user
        class MockRequest:
            def __init__(self, user):
                self.user = user
        
        student_user = SupabaseUser(
            {'id': 'test', 'email': 'test@example.com'},
            'student',
            self.student
        )
        
        staff_user = SupabaseUser(
            {'id': 'test', 'email': 'staff@example.com'},
            'staff',
            self.staff
        )
        
        # Test IsStudentOrStaff
        permission = IsStudentOrStaff()
        self.assertTrue(permission.has_permission(MockRequest(student_user), None))
        self.assertTrue(permission.has_permission(MockRequest(staff_user), None))
        
        # Test IsStaffOnly
        permission = IsStaffOnly()
        self.assertFalse(permission.has_permission(MockRequest(student_user), None))
        self.assertTrue(permission.has_permission(MockRequest(staff_user), None))
        
        # Test IsStudentOnly
        permission = IsStudentOnly()
        self.assertTrue(permission.has_permission(MockRequest(student_user), None))
        self.assertFalse(permission.has_permission(MockRequest(staff_user), None))