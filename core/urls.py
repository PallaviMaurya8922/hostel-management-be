"""
URL configuration for the core app.
Defines REST API endpoints for the AI-Powered Hostel Coordination System.
"""

from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views
from .views_whatsapp import whatsapp_webhook, check_whatsapp_token

app_name = 'core'

# Create router for ViewSets
router = DefaultRouter()
router.register(r'guest-requests', views.GuestRequestViewSet)
router.register(r'absence-records', views.AbsenceRecordViewSet)
router.register(r'maintenance-requests', views.MaintenanceRequestViewSet)
router.register(r'students', views.StudentViewSet)
router.register(r'staff', views.StaffViewSet)
router.register(r'audit-logs', views.AuditLogViewSet)
router.register(r'notices', views.NoticeBoardViewSet, basename='notice')
router.register(r'notifications', views.NotificationViewSet, basename='notification')

urlpatterns = [
    # Health and system info endpoints
    path('health/', views.health_check, name='health_check'),
    path('info/', views.system_info, name='system_info'),
    
    # Daily summary endpoint
    path('daily-summary/', views.daily_summary, name='daily_summary'),
    
    # Conversation status endpoint
    path('conversation-status/', views.conversation_status, name='conversation_status'),
    
    # Debug endpoint
    path('debug/auth-status/', views.debug_auth_status, name='debug_auth_status'),
    
    # Dashboard endpoints
    path('dashboard-data/', views.dashboard_data, name='dashboard_data'),
    path('students-present/', views.students_present_details, name='students_present_details'),
    path('invalidate-cache/', views.invalidate_dashboard_cache, name='invalidate_dashboard_cache'),
    path('approve-request/', views.approve_request, name='approve_request'),
    path('reject-request/', views.reject_request, name='reject_request'),
    path('guest/verify/<str:qr_token>/', views.verify_guest_qr, name='verify_guest_qr'),
    
    # Enhanced leave request endpoints
    path('submit-leave-request/', views.submit_leave_request, name='submit_leave_request'),
    path('approve-leave-request/', views.approve_leave_request, name='approve_leave_request'),
    path('reject-leave-request/', views.reject_leave_request, name='reject_leave_request'),
    path('digital-passes/', views.get_digital_passes, name='get_digital_passes'),
    path('verify-pass/', views.verify_digital_pass, name='verify_digital_pass'),
    
    # Digital pass PDF endpoints
    path('pass/<str:pass_number>/download/', views.download_digital_pass, name='download_digital_pass'),
    path('pass/<str:pass_number>/view/', views.view_digital_pass, name='view_digital_pass'),
    
    # Pass history endpoints
    path('pass-history/', views.get_pass_history, name='get_pass_history'),
    path('pass-history/export/', views.export_pass_history, name='export_pass_history'),
    
    # Security verification API endpoints
    path('security/stats/', views.get_security_stats, name='get_security_stats'),
    path('security/active-passes/', views.get_all_active_passes, name='get_all_active_passes'),
    path('security/search-students/', views.search_student_passes, name='search_student_passes'),
    path('security/recent-verifications/', views.get_recent_verifications, name='get_recent_verifications'),
    path('security/bulk-verify/', views.bulk_verify_passes, name='bulk_verify_passes'),
    path('security/export-report/', views.export_security_report, name='export_security_report'),
    path('security/students-by-date/', views.get_students_by_date_range, name='get_students_by_date_range'),
    path('security/emergency-mode/', views.activate_emergency_mode, name='activate_emergency_mode'),

    # WhatsApp webhook endpoints
    path('webhook', whatsapp_webhook, name='whatsapp_webhook_no_slash'),
    path('webhook/', whatsapp_webhook, name='whatsapp_webhook'),
    path('whatsapp/token-check/', check_whatsapp_token, name='`check_whatsapp_token`'),
    
    # Maintenance management API endpoints
    path('maintenance/accept-task/', views.accept_maintenance_task, name='accept_maintenance_task'),
    path('maintenance/update-status/', views.update_maintenance_status, name='update_maintenance_status'),
    path('maintenance/stats/', views.get_maintenance_stats, name='get_maintenance_stats'),
    path('maintenance/history/', views.get_maintenance_history, name='get_maintenance_history'),
    
    # Include router URLs
    path('', include(router.urls)),
]