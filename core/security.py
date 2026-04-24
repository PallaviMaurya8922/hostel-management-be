"""
Security utilities and middleware for the AI-Powered Hostel Coordination System.
Provides security hardening, input validation, and protection mechanisms.
"""

import logging
import re
import json
from typing import Dict, Any, List, Optional
from django.conf import settings
from django.http import JsonResponse
from django.utils.deprecation import MiddlewareMixin
from django.core.exceptions import ValidationError
from django.utils import timezone
from datetime import timedelta
import hashlib
import hmac

logger = logging.getLogger(__name__)


class SecurityConfig:
    """Security configuration constants."""
    
    # Rate limiting (defaults; overridden by Django settings for SPA-friendly limits)
    MAX_REQUESTS_PER_MINUTE = 300
    MAX_REQUESTS_PER_HOUR = 15000
    
    # Input validation
    MAX_MESSAGE_LENGTH = 2000
    MAX_QUERY_LENGTH = 500
    
    # Sensitive data patterns
    SENSITIVE_PATTERNS = [
        r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',  # Credit card numbers
        r'\b\d{3}-\d{2}-\d{4}\b',  # SSN
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # Email (for logging)
    ]
    
    # Allowed file extensions for uploads
    ALLOWED_EXTENSIONS = {'.txt', '.pdf', '.doc', '.docx', '.jpg', '.jpeg', '.png'}
    
    # Maximum file size (5MB)
    MAX_FILE_SIZE = 5 * 1024 * 1024


class InputValidator:
    """Input validation and sanitization utilities."""
    
    @staticmethod
    def validate_message_content(content: str) -> str:
        """
        Validate and sanitize message content.
        
        Args:
            content: Raw message content
            
        Returns:
            Sanitized content
            
        Raises:
            ValidationError: If content is invalid
        """
        if not content or not content.strip():
            raise ValidationError("Message content cannot be empty")
        
        content = content.strip()
        
        if len(content) > SecurityConfig.MAX_MESSAGE_LENGTH:
            raise ValidationError(f"Message too long. Maximum {SecurityConfig.MAX_MESSAGE_LENGTH} characters allowed")
        
        # Remove potentially dangerous characters
        content = re.sub(r'[<>"\']', '', content)
        
        # Check for suspicious patterns
        if InputValidator._contains_suspicious_content(content):
            logger.warning(f"Suspicious content detected in message: {content[:100]}...")
            raise ValidationError("Message contains potentially harmful content")
        
        return content
    
    @staticmethod
    def validate_query_content(query: str) -> str:
        """
        Validate and sanitize staff query content.
        
        Args:
            query: Raw query content
            
        Returns:
            Sanitized query
            
        Raises:
            ValidationError: If query is invalid
        """
        if not query or not query.strip():
            raise ValidationError("Query cannot be empty")
        
        query = query.strip()
        
        if len(query) > SecurityConfig.MAX_QUERY_LENGTH:
            raise ValidationError(f"Query too long. Maximum {SecurityConfig.MAX_QUERY_LENGTH} characters allowed")
        
        # Remove potentially dangerous characters
        query = re.sub(r'[<>"\']', '', query)
        
        return query
    
    @staticmethod
    def validate_student_id(student_id: str) -> str:
        """
        Validate student ID format.
        
        Args:
            student_id: Student identifier
            
        Returns:
            Validated student ID
            
        Raises:
            ValidationError: If student ID is invalid
        """
        if not student_id:
            raise ValidationError("Student ID cannot be empty")
        
        # Allow alphanumeric characters and common separators
        if not re.match(r'^[A-Za-z0-9_-]{3,20}$', student_id):
            raise ValidationError("Invalid student ID format")
        
        return student_id.upper()
    
    @staticmethod
    def validate_room_number(room_number: str) -> str:
        """
        Validate room number format.
        
        Args:
            room_number: Room number
            
        Returns:
            Validated room number
            
        Raises:
            ValidationError: If room number is invalid
        """
        if not room_number:
            raise ValidationError("Room number cannot be empty")
        
        # Allow alphanumeric characters for room numbers like "101A", "B-205"
        if not re.match(r'^[A-Za-z0-9-]{1,10}$', room_number):
            raise ValidationError("Invalid room number format")
        
        return room_number.upper()
    
    @staticmethod
    def _contains_suspicious_content(content: str) -> bool:
        """Check if content contains suspicious patterns."""
        suspicious_keywords = [
            'script', 'javascript', 'eval', 'exec', 'system', 'shell',
            'drop table', 'delete from', 'insert into', 'update set'
        ]
        
        content_lower = content.lower()
        return any(keyword in content_lower for keyword in suspicious_keywords)


class DataProtection:
    """Data protection and privacy utilities."""
    
    @staticmethod
    def sanitize_for_logging(data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sanitize data for safe logging by removing sensitive information.
        
        Args:
            data: Data dictionary to sanitize
            
        Returns:
            Sanitized data dictionary
        """
        sanitized = {}
        
        for key, value in data.items():
            if isinstance(value, str):
                sanitized[key] = DataProtection._mask_sensitive_data(value)
            elif isinstance(value, dict):
                sanitized[key] = DataProtection.sanitize_for_logging(value)
            elif isinstance(value, list):
                sanitized[key] = [
                    DataProtection._mask_sensitive_data(item) if isinstance(item, str) else item
                    for item in value
                ]
            else:
                sanitized[key] = value
        
        return sanitized
    
    @staticmethod
    def _mask_sensitive_data(text: str) -> str:
        """Mask sensitive data patterns in text."""
        if not text:
            return text
        
        # Mask phone numbers
        text = re.sub(r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b', '***-***-****', text)
        
        # Mask email addresses
        text = re.sub(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '***@***.***', text)
        
        # Mask potential credit card numbers
        text = re.sub(r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b', '****-****-****-****', text)
        
        return text
    
    @staticmethod
    def hash_sensitive_id(identifier: str, salt: str = None) -> str:
        """
        Create a hash of sensitive identifier for logging/tracking.
        
        Args:
            identifier: Sensitive identifier to hash
            salt: Optional salt for hashing
            
        Returns:
            Hashed identifier
        """
        if not salt:
            salt = getattr(settings, 'SECRET_KEY', 'default_salt')[:16]
        
        return hashlib.sha256(f"{salt}{identifier}".encode()).hexdigest()[:16]


class SecurityMiddleware(MiddlewareMixin):
    """Security middleware for request processing."""
    
    def __init__(self, get_response):
        self.get_response = get_response
        self.rate_limit_cache = {}
        super().__init__(get_response)
    
    def process_request(self, request):
        """Process incoming requests for security checks."""
        
        # Skip security checks for certain paths
        if self._should_skip_security(request.path):
            return None
        
        # Rate limiting (see RATELIMIT_ENABLE and SECURITY_MAX_* in Django settings)
        if getattr(settings, 'RATELIMIT_ENABLE', True) and not self._check_rate_limit(request):
            logger.warning(f"Rate limit exceeded for IP: {self._get_client_ip(request)}")
            return JsonResponse({
                'error': 'Rate limit exceeded. Please try again later.',
                'retry_after': 60
            }, status=429)
        
        # Content length check
        if hasattr(request, 'body') and len(request.body) > 10 * 1024 * 1024:  # 10MB limit
            logger.warning(f"Request body too large from IP: {self._get_client_ip(request)}")
            return JsonResponse({
                'error': 'Request body too large'
            }, status=413)
        
        return None
    
    def process_response(self, request, response):
        """Process outgoing responses for security headers."""
        
        # Add security headers
        response['X-Content-Type-Options'] = 'nosniff'
        response['X-Frame-Options'] = 'DENY'
        response['X-XSS-Protection'] = '1; mode=block'
        response['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        
        # Add CORS headers for API endpoints
        if request.path.startswith('/api/'):
            response['Access-Control-Allow-Origin'] = getattr(settings, 'ALLOWED_HOSTS', ['localhost'])[0]
            response['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
            response['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Requested-With'
        
        return response
    
    def _should_skip_security(self, path: str) -> bool:
        """Check if security checks should be skipped for this path."""
        skip_paths = [
            '/admin/',
            '/static/',
            '/media/',
            '/health/',
            '/favicon.ico'
        ]
        return any(path.startswith(skip_path) for skip_path in skip_paths)
    
    def _check_rate_limit(self, request) -> bool:
        """Check if request is within rate limits."""
        client_ip = self._get_client_ip(request)
        current_time = timezone.now()
        
        # Clean old entries
        self._cleanup_rate_limit_cache(current_time)
        
        # Check rate limits
        if client_ip not in self.rate_limit_cache:
            self.rate_limit_cache[client_ip] = []
        
        # Add current request
        self.rate_limit_cache[client_ip].append(current_time)
        
        # Check minute limit
        minute_ago = current_time - timedelta(minutes=1)
        recent_requests = [
            req_time for req_time in self.rate_limit_cache[client_ip]
            if req_time > minute_ago
        ]
        
        max_per_minute = int(
            getattr(settings, 'SECURITY_MAX_REQUESTS_PER_MINUTE', SecurityConfig.MAX_REQUESTS_PER_MINUTE)
        )
        max_per_hour = int(
            getattr(settings, 'SECURITY_MAX_REQUESTS_PER_HOUR', SecurityConfig.MAX_REQUESTS_PER_HOUR)
        )

        if len(recent_requests) > max_per_minute:
            return False
        
        # Check hour limit
        hour_ago = current_time - timedelta(hours=1)
        hourly_requests = [
            req_time for req_time in self.rate_limit_cache[client_ip]
            if req_time > hour_ago
        ]
        
        if len(hourly_requests) > max_per_hour:
            return False
        
        return True
    
    def _cleanup_rate_limit_cache(self, current_time):
        """Clean up old rate limit entries."""
        hour_ago = current_time - timedelta(hours=1)
        
        for ip in list(self.rate_limit_cache.keys()):
            self.rate_limit_cache[ip] = [
                req_time for req_time in self.rate_limit_cache[ip]
                if req_time > hour_ago
            ]
            
            # Remove empty entries
            if not self.rate_limit_cache[ip]:
                del self.rate_limit_cache[ip]
    
    def _get_client_ip(self, request) -> str:
        """Get client IP address from request."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip or 'unknown'


class APIKeyValidator:
    """API key validation for external integrations."""
    
    @staticmethod
    def validate_api_key(api_key: str, expected_key: str) -> bool:
        """
        Validate API key using constant-time comparison.
        
        Args:
            api_key: Provided API key
            expected_key: Expected API key
            
        Returns:
            True if keys match, False otherwise
        """
        if not api_key or not expected_key:
            return False
        
        return hmac.compare_digest(api_key, expected_key)
    
    @staticmethod
    def generate_api_key() -> str:
        """Generate a secure API key."""
        import secrets
        return secrets.token_urlsafe(32)


class SecurityAuditLogger:
    """Security event logging utilities."""
    
    @staticmethod
    def log_security_event(event_type: str, details: Dict[str, Any], 
                          request=None, severity: str = 'INFO'):
        """
        Log security events for monitoring and analysis.
        
        Args:
            event_type: Type of security event
            details: Event details
            request: HTTP request object (optional)
            severity: Event severity level
        """
        log_data = {
            'event_type': event_type,
            'timestamp': timezone.now().isoformat(),
            'severity': severity,
            'details': DataProtection.sanitize_for_logging(details)
        }
        
        if request:
            log_data.update({
                'ip_address': request.META.get('REMOTE_ADDR', 'unknown'),
                'user_agent': request.META.get('HTTP_USER_AGENT', 'unknown'),
                'path': request.path,
                'method': request.method
            })
        
        # Log based on severity
        if severity == 'ERROR':
            logger.error(f"Security Event: {json.dumps(log_data)}")
        elif severity == 'WARNING':
            logger.warning(f"Security Event: {json.dumps(log_data)}")
        else:
            logger.info(f"Security Event: {json.dumps(log_data)}")
    
    @staticmethod
    def log_authentication_event(user_id: str, event: str, success: bool, 
                               request=None, details: Dict[str, Any] = None):
        """Log authentication-related events."""
        SecurityAuditLogger.log_security_event(
            event_type='authentication',
            details={
                'user_id': DataProtection.hash_sensitive_id(user_id),
                'event': event,
                'success': success,
                'additional_details': details or {}
            },
            request=request,
            severity='WARNING' if not success else 'INFO'
        )
    
    @staticmethod
    def log_data_access_event(user_id: str, resource: str, action: str, 
                            request=None, details: Dict[str, Any] = None):
        """Log data access events."""
        SecurityAuditLogger.log_security_event(
            event_type='data_access',
            details={
                'user_id': DataProtection.hash_sensitive_id(user_id),
                'resource': resource,
                'action': action,
                'additional_details': details or {}
            },
            request=request,
            severity='INFO'
        )


# Security decorators
def require_api_key(view_func):
    """Decorator to require API key for view access."""
    def wrapper(request, *args, **kwargs):
        api_key = request.META.get('HTTP_X_API_KEY') or request.GET.get('api_key')
        expected_key = getattr(settings, 'API_KEY', None)
        
        if not APIKeyValidator.validate_api_key(api_key, expected_key):
            SecurityAuditLogger.log_security_event(
                event_type='unauthorized_api_access',
                details={'provided_key': api_key[:8] + '...' if api_key else None},
                request=request,
                severity='WARNING'
            )
            return JsonResponse({'error': 'Invalid API key'}, status=401)
        
        return view_func(request, *args, **kwargs)
    
    return wrapper


def validate_input(validation_func):
    """Decorator to validate input data."""
    def decorator(view_func):
        def wrapper(request, *args, **kwargs):
            try:
                if hasattr(request, 'data') and request.data:
                    validated_data = validation_func(request.data)
                    request.validated_data = validated_data
                elif request.method == 'POST' and request.POST:
                    validated_data = validation_func(dict(request.POST))
                    request.validated_data = validated_data
                
                return view_func(request, *args, **kwargs)
            
            except ValidationError as e:
                SecurityAuditLogger.log_security_event(
                    event_type='input_validation_error',
                    details={'error': str(e), 'data_keys': list(request.data.keys()) if hasattr(request, 'data') else []},
                    request=request,
                    severity='WARNING'
                )
                return JsonResponse({'error': str(e)}, status=400)
        
        return wrapper
    return decorator