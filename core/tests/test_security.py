"""
Tests for security features and hardening.
"""

import pytest
from django.test import TestCase, RequestFactory
from django.core.exceptions import ValidationError
from rest_framework.test import APIClient
from rest_framework import status
from unittest.mock import patch

from ..security import (
    InputValidator, DataProtection, SecurityAuditLogger, 
    APIKeyValidator, SecurityMiddleware
)
from ..models import Student, Staff


class InputValidationTest(TestCase):
    """Test input validation functionality."""
    
    def test_validate_message_content_success(self):
        """Test successful message content validation."""
        content = "My friend will stay tonight"
        validated = InputValidator.validate_message_content(content)
        self.assertEqual(validated, content)
    
    def test_validate_message_content_empty(self):
        """Test validation fails for empty content."""
        with self.assertRaises(ValidationError):
            InputValidator.validate_message_content("")
        
        with self.assertRaises(ValidationError):
            InputValidator.validate_message_content("   ")
    
    def test_validate_message_content_too_long(self):
        """Test validation fails for content that's too long."""
        long_content = "x" * 2001  # Exceeds MAX_MESSAGE_LENGTH
        with self.assertRaises(ValidationError):
            InputValidator.validate_message_content(long_content)
    
    def test_validate_message_content_suspicious(self):
        """Test validation fails for suspicious content."""
        suspicious_content = "DROP TABLE students; --"
        with self.assertRaises(ValidationError):
            InputValidator.validate_message_content(suspicious_content)
    
    def test_validate_message_content_sanitization(self):
        """Test content sanitization removes dangerous characters."""
        content = 'Hello "world" <test>content</test>'
        validated = InputValidator.validate_message_content(content)
        self.assertNotIn('<', validated)
        self.assertNotIn('>', validated)
        self.assertNotIn('"', validated)
        self.assertEqual(validated, 'Hello world testcontent/test')
    
    def test_validate_student_id_success(self):
        """Test successful student ID validation."""
        student_id = "STU123"
        validated = InputValidator.validate_student_id(student_id)
        self.assertEqual(validated, "STU123")
    
    def test_validate_student_id_invalid_format(self):
        """Test validation fails for invalid student ID format."""
        with self.assertRaises(ValidationError):
            InputValidator.validate_student_id("invalid@id")
        
        with self.assertRaises(ValidationError):
            InputValidator.validate_student_id("x")  # Too short
        
        with self.assertRaises(ValidationError):
            InputValidator.validate_student_id("x" * 25)  # Too long
    
    def test_validate_room_number_success(self):
        """Test successful room number validation."""
        room_number = "101A"
        validated = InputValidator.validate_room_number(room_number)
        self.assertEqual(validated, "101A")
    
    def test_validate_room_number_invalid(self):
        """Test validation fails for invalid room number."""
        with self.assertRaises(ValidationError):
            InputValidator.validate_room_number("room@101")
        
        with self.assertRaises(ValidationError):
            InputValidator.validate_room_number("")


class DataProtectionTest(TestCase):
    """Test data protection functionality."""
    
    def test_sanitize_for_logging_phone_numbers(self):
        """Test phone number masking in logging data."""
        data = {
            'message': 'Call me at 123-456-7890',
            'phone': '9876543210'
        }
        sanitized = DataProtection.sanitize_for_logging(data)
        
        self.assertIn('***-***-****', sanitized['message'])
        self.assertIn('***-***-****', sanitized['phone'])
    
    def test_sanitize_for_logging_email_addresses(self):
        """Test email address masking in logging data."""
        data = {
            'message': 'Contact me at user@example.com',
            'email': 'test@domain.org'
        }
        sanitized = DataProtection.sanitize_for_logging(data)
        
        self.assertIn('***@***.***', sanitized['message'])
        self.assertIn('***@***.***', sanitized['email'])
    
    def test_sanitize_for_logging_nested_data(self):
        """Test sanitization works with nested data structures."""
        data = {
            'user': {
                'name': 'John Doe',
                'contact': 'john@example.com'
            },
            'messages': [
                'Call 123-456-7890',
                'Email test@domain.com'
            ]
        }
        sanitized = DataProtection.sanitize_for_logging(data)
        
        self.assertIn('***@***.***', sanitized['user']['contact'])
        self.assertIn('***-***-****', sanitized['messages'][0])
        self.assertIn('***@***.***', sanitized['messages'][1])
    
    def test_hash_sensitive_id(self):
        """Test sensitive ID hashing."""
        identifier = "STUDENT123"
        hashed = DataProtection.hash_sensitive_id(identifier)
        
        self.assertNotEqual(hashed, identifier)
        self.assertEqual(len(hashed), 16)
        
        # Same input should produce same hash
        hashed2 = DataProtection.hash_sensitive_id(identifier)
        self.assertEqual(hashed, hashed2)


class APIKeyValidationTest(TestCase):
    """Test API key validation functionality."""
    
    def test_validate_api_key_success(self):
        """Test successful API key validation."""
        api_key = "test-api-key-123"
        expected_key = "test-api-key-123"
        
        result = APIKeyValidator.validate_api_key(api_key, expected_key)
        self.assertTrue(result)
    
    def test_validate_api_key_failure(self):
        """Test API key validation failure."""
        api_key = "wrong-key"
        expected_key = "correct-key"
        
        result = APIKeyValidator.validate_api_key(api_key, expected_key)
        self.assertFalse(result)
    
    def test_validate_api_key_empty(self):
        """Test API key validation with empty keys."""
        result = APIKeyValidator.validate_api_key("", "expected")
        self.assertFalse(result)
        
        result = APIKeyValidator.validate_api_key("provided", "")
        self.assertFalse(result)
    
    def test_generate_api_key(self):
        """Test API key generation."""
        key1 = APIKeyValidator.generate_api_key()
        key2 = APIKeyValidator.generate_api_key()
        
        self.assertNotEqual(key1, key2)
        self.assertGreater(len(key1), 20)
        self.assertGreater(len(key2), 20)


class SecurityMiddlewareTest(TestCase):
    """Test security middleware functionality."""
    
    def setUp(self):
        """Set up test environment."""
        self.factory = RequestFactory()
        self.middleware = SecurityMiddleware(lambda request: None)
    
    def test_security_headers_added(self):
        """Test that security headers are added to responses."""
        request = self.factory.get('/api/test/')
        
        # Mock response
        class MockResponse:
            def __init__(self):
                self.headers = {}
            
            def __setitem__(self, key, value):
                self.headers[key] = value
        
        response = MockResponse()
        processed_response = self.middleware.process_response(request, response)
        
        self.assertIn('X-Content-Type-Options', processed_response.headers)
        self.assertIn('X-Frame-Options', processed_response.headers)
        self.assertIn('X-XSS-Protection', processed_response.headers)
        self.assertEqual(processed_response.headers['X-Content-Type-Options'], 'nosniff')
        self.assertEqual(processed_response.headers['X-Frame-Options'], 'DENY')
    
    def test_cors_headers_for_api(self):
        """Test that CORS headers are added for API endpoints."""
        request = self.factory.get('/api/health/')
        
        class MockResponse:
            def __init__(self):
                self.headers = {}
            
            def __setitem__(self, key, value):
                self.headers[key] = value
        
        response = MockResponse()
        processed_response = self.middleware.process_response(request, response)
        
        self.assertIn('Access-Control-Allow-Origin', processed_response.headers)
        self.assertIn('Access-Control-Allow-Methods', processed_response.headers)
    
    def test_skip_security_for_static_files(self):
        """Test that security checks are skipped for static files."""
        request = self.factory.get('/static/css/style.css')
        
        # Should return None (no processing needed)
        result = self.middleware.process_request(request)
        self.assertIsNone(result)
    
    def test_get_client_ip(self):
        """Test client IP extraction."""
        # Test with X-Forwarded-For header
        request = self.factory.get('/')
        request.META['HTTP_X_FORWARDED_FOR'] = '192.168.1.1, 10.0.0.1'
        
        ip = self.middleware._get_client_ip(request)
        self.assertEqual(ip, '192.168.1.1')
        
        # Test with REMOTE_ADDR
        request = self.factory.get('/')
        request.META['REMOTE_ADDR'] = '127.0.0.1'
        
        ip = self.middleware._get_client_ip(request)
        self.assertEqual(ip, '127.0.0.1')


class SecurityAuditLoggerTest(TestCase):
    """Test security audit logging functionality."""
    
    def test_log_security_event(self):
        """Test security event logging."""
        with self.assertLogs('core.security', level='INFO') as log:
            SecurityAuditLogger.log_security_event(
                event_type='test_event',
                details={'test': 'data'},
                severity='INFO'
            )
        
        self.assertIn('Security Event', log.output[0])
        self.assertIn('test_event', log.output[0])
    
    def test_log_authentication_event(self):
        """Test authentication event logging."""
        with self.assertLogs('core.security', level='INFO') as log:
            SecurityAuditLogger.log_authentication_event(
                user_id='test_user',
                event='login',
                success=True
            )
        
        self.assertIn('authentication', log.output[0])
    
    def test_log_data_access_event(self):
        """Test data access event logging."""
        with self.assertLogs('core.security', level='INFO') as log:
            SecurityAuditLogger.log_data_access_event(
                user_id='test_user',
                resource='message',
                action='create'
            )
        
        self.assertIn('data_access', log.output[0])


class SecurityIntegrationTest(TestCase):
    """Test security integration with API endpoints."""
    
    def setUp(self):
        """Set up test environment."""
        self.client = APIClient()
        
        # Create test student
        self.student = Student.objects.create(
            student_id="SEC001",
            name="Security Test Student",
            room_number="101A",
            block="A"
        )
    
    def test_security_headers_in_response(self):
        """Test that security headers are present in API responses."""
        url = '/api/health/'
        response = self.client.get(url)
        
        # Check for security headers
        self.assertIn('X-Content-Type-Options', response)
        self.assertIn('X-Frame-Options', response)
        self.assertIn('X-XSS-Protection', response)
        
        self.assertEqual(response['X-Content-Type-Options'], 'nosniff')
        self.assertEqual(response['X-Frame-Options'], 'DENY')