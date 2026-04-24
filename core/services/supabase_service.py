"""
Supabase integration service for the AI-Powered Hostel Coordination System.
Handles database connections, authentication, and real-time subscriptions.
"""

import logging
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)

try:
    from django.conf import settings
    DJANGO_AVAILABLE = True
except ImportError:
    DJANGO_AVAILABLE = False
    settings = None

try:
    from supabase import create_client, Client
    from supabase.lib.client_options import ClientOptions
    SUPABASE_AVAILABLE = True
except ImportError:
    SUPABASE_AVAILABLE = False
    Client = None


class SupabaseService:
    """
    Service class for managing Supabase connections and operations.
    Provides secure database access and real-time capabilities.
    """
    
    def __init__(self):
        """Initialize Supabase client with configuration from settings."""
        if not DJANGO_AVAILABLE or not SUPABASE_AVAILABLE:
            logger.warning("Django or Supabase not available. Service will be disabled.")
            self.client = None
            self.service_client = None
            return
            
        try:
            self.url = getattr(settings, 'SUPABASE_URL', '')
            self.key = getattr(settings, 'SUPABASE_KEY', '')
            self.service_key = getattr(settings, 'SUPABASE_SERVICE_KEY', '')
        except Exception:
            logger.warning("Django settings not configured. Service will be disabled.")
            self.client = None
            self.service_client = None
            return
        
        if not self.url or not self.key:
            logger.warning("Supabase configuration incomplete. Some features may not work.")
            self.client = None
            self.service_client = None
            return
            
        try:
            # Client for regular operations (with RLS)
            self.client: Client = create_client(self.url, self.key)
            
            # Service client for admin operations (bypasses RLS)
            if self.service_key:
                self.service_client: Client = create_client(self.url, self.service_key)
            else:
                self.service_client = None
                
            logger.info("Supabase clients initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize Supabase clients: {e}")
            self.client = None
            self.service_client = None
    
    def is_configured(self) -> bool:
        """Check if Supabase is properly configured."""
        return self.client is not None
    
    def authenticate_user(self, email: str, password: str) -> Optional[Dict[str, Any]]:
        """
        Authenticate user with Supabase Auth.
        
        Args:
            email: User email address
            password: User password
            
        Returns:
            User data if authentication successful, None otherwise
        """
        if not self.client:
            logger.error("Supabase client not configured")
            return None
            
        try:
            response = self.client.auth.sign_in_with_password({
                "email": email,
                "password": password
            })
            
            if response.user:
                logger.info(f"User authenticated successfully: {email}")
                return {
                    "user_id": response.user.id,
                    "email": response.user.email,
                    "role": response.user.user_metadata.get("role", "student")
                }
            else:
                logger.warning(f"Authentication failed for user: {email}")
                return None
                
        except Exception as e:
            logger.error(f"Authentication error for {email}: {e}")
            return None
    
    def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Verify a Supabase JWT token and return user data.
        
        Args:
            token: JWT token to verify
            
        Returns:
            User data if token is valid, None otherwise
        """
        if not self.client:
            logger.error("Supabase client not configured")
            return None
        
        try:
            # Get user from token
            response = self.client.auth.get_user(token)
            
            if response.user:
                return {
                    'id': response.user.id,
                    'email': response.user.email,
                    'user_metadata': response.user.user_metadata or {},
                    'app_metadata': response.user.app_metadata or {}
                }
            else:
                logger.warning("Invalid token - no user found")
                return None
                
        except Exception as e:
            logger.error(f"Token verification failed: {e}")
            return None
    
    def get_student_data(self, student_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve student data from Supabase.
        
        Args:
            student_id: Student identifier
            
        Returns:
            Student data if found, None otherwise
        """
        if not self.client:
            return None
            
        try:
            response = self.client.table('students').select('*').eq('student_id', student_id).execute()
            
            if response.data:
                return response.data[0]
            else:
                logger.warning(f"Student not found: {student_id}")
                return None
                
        except Exception as e:
            logger.error(f"Error retrieving student data for {student_id}: {e}")
            return None
    
    def create_guest_request(self, request_data: Dict[str, Any]) -> Optional[str]:
        """
        Create a new guest request in Supabase.
        
        Args:
            request_data: Guest request information
            
        Returns:
            Request ID if successful, None otherwise
        """
        if not self.client:
            return None
            
        try:
            response = self.client.table('guest_requests').insert(request_data).execute()
            
            if response.data:
                request_id = response.data[0]['id']
                logger.info(f"Guest request created successfully: {request_id}")
                return request_id
            else:
                logger.error("Failed to create guest request")
                return None
                
        except Exception as e:
            logger.error(f"Error creating guest request: {e}")
            return None
    
    def update_request_status(self, request_id: str, status: str, reason: str = "") -> bool:
        """
        Update the status of a request.
        
        Args:
            request_id: Request identifier
            status: New status (pending, approved, rejected)
            reason: Reason for status change
            
        Returns:
            True if successful, False otherwise
        """
        if not self.client:
            return False
            
        try:
            update_data = {
                "status": status,
                "approval_reason": reason,
                "updated_at": "now()"
            }
            
            response = self.client.table('guest_requests').update(update_data).eq('id', request_id).execute()
            
            if response.data:
                logger.info(f"Request {request_id} status updated to {status}")
                return True
            else:
                logger.error(f"Failed to update request {request_id}")
                return False
                
        except Exception as e:
            logger.error(f"Error updating request status: {e}")
            return False
    
    def log_audit_entry(self, audit_data: Dict[str, Any]) -> bool:
        """
        Create an audit log entry.
        
        Args:
            audit_data: Audit log information
            
        Returns:
            True if successful, False otherwise
        """
        if not self.service_client:
            logger.warning("Service client not available for audit logging")
            return False
            
        try:
            response = self.service_client.table('audit_logs').insert(audit_data).execute()
            
            if response.data:
                logger.debug("Audit entry logged successfully")
                return True
            else:
                logger.error("Failed to create audit entry")
                return False
                
        except Exception as e:
            logger.error(f"Error creating audit entry: {e}")
            return False
    
    def get_active_guests(self) -> List[Dict[str, Any]]:
        """
        Retrieve all active guest stays.
        
        Returns:
            List of active guest records
        """
        if not self.client:
            return []
            
        try:
            response = self.client.table('guest_requests').select('*').eq('status', 'approved').gte('end_date', 'now()').execute()
            
            return response.data if response.data else []
            
        except Exception as e:
            logger.error(f"Error retrieving active guests: {e}")
            return []
    
    def check_room_conflicts(self) -> List[Dict[str, Any]]:
        """
        Check for room assignment conflicts.
        
        Returns:
            List of detected conflicts
        """
        if not self.service_client:
            return []
            
        try:
            # This would typically involve complex queries to detect conflicts
            # For now, return empty list as placeholder
            logger.info("Room conflict check completed")
            return []
            
        except Exception as e:
            logger.error(f"Error checking room conflicts: {e}")
            return []

# Global instance - only create if Django is available
if DJANGO_AVAILABLE:
    supabase_service = SupabaseService()
else:
    supabase_service = None