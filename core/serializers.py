"""
Serializers for the AI-Powered Hostel Coordination System API.
Handles serialization and deserialization of model data for REST API endpoints.
"""

import re

from rest_framework import serializers
from django.contrib.auth.models import User
from django.core.exceptions import ObjectDoesNotExist
from .models import Student, Staff, Message, GuestRequest, AbsenceRecord, MaintenanceRequest, AuditLog, NoticeBoard, Notification


class StudentSerializer(serializers.ModelSerializer):
    """Serializer for Student model."""
    
    has_recent_violations = serializers.ReadOnlyField()
    
    class Meta:
        model = Student
        fields = [
            'student_id', 'name', 'room_number', 'block', 'phone', 'parent_phone',
            'violation_count', 'last_violation_date', 'has_recent_violations',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['created_at', 'updated_at']


class StaffSerializer(serializers.ModelSerializer):
    """Serializer for Staff model."""
    
    class Meta:
        model = Staff
        fields = [
            'staff_id', 'name', 'role', 'permissions', 'phone', 'email',
            'is_active', 'created_at', 'updated_at'
        ]
        read_only_fields = ['created_at', 'updated_at']


class MessageSerializer(serializers.ModelSerializer):
    """Serializer for Message model."""
    
    sender_name = serializers.CharField(source='sender.name', read_only=True)
    sender_room = serializers.CharField(source='sender.room_number', read_only=True)
    
    class Meta:
        model = Message
        fields = [
            'message_id', 'sender', 'sender_name', 'sender_room', 'content',
            'status', 'processed', 'confidence_score', 'extracted_intent',
            'response_sent', 'created_at', 'updated_at'
        ]
        read_only_fields = [
            'message_id', 'processed', 'confidence_score', 'extracted_intent',
            'response_sent', 'created_at', 'updated_at'
        ]


class MessageCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating new messages."""
    
    class Meta:
        model = Message
        fields = ['content']  # Only content is required from the client


class GuestRequestSerializer(serializers.ModelSerializer):
    """Serializer for GuestRequest model."""
    
    student_name = serializers.SerializerMethodField()
    student_room = serializers.SerializerMethodField()
    student_contact = serializers.SerializerMethodField()
    approved_by_name = serializers.CharField(source='approved_by.name', read_only=True)
    duration_days = serializers.ReadOnlyField()
    is_short_stay = serializers.ReadOnlyField()
    relationship_display = serializers.CharField(source='get_relationship_display', read_only=True)

    def _get_student(self, obj):
        try:
            return obj.student
        except ObjectDoesNotExist:
            return None

    def get_student_name(self, obj):
        student = self._get_student(obj)
        return student.name if student else 'Unknown Student'

    def get_student_room(self, obj):
        student = self._get_student(obj)
        return student.room_number if student else 'N/A'

    def get_student_contact(self, obj):
        student = self._get_student(obj)
        if not student:
            return None
        return student.phone or student.mobile_number

    def validate_guest_phone(self, value):
        """Accept 10-digit local or 12-digit India format and persist as 12-digit with 91 prefix."""
        if value in (None, ""):
            return value

        digits = re.sub(r"\D", "", str(value))

        if len(digits) == 10:
            return f"91{digits}"

        if len(digits) == 12 and digits.startswith("91"):
            return digits

        raise serializers.ValidationError("Guest phone must be 10 digits or 12 digits starting with 91")
    
    class Meta:
        model = GuestRequest
        fields = [
            'request_id', 'student', 'student_name', 'student_room', 'student_contact',
            'guest_name', 'visit_type', 'relationship', 'relationship_display', 'guest_phone',
            'start_date', 'end_date', 'purpose',
            'status', 'auto_approved', 'qr_token', 'qr_image_path', 'qr_generated_at', 'approval_reason', 'approved_by',
            'approved_by_name', 'duration_days', 'is_short_stay',
            'created_at', 'updated_at'
        ]
        read_only_fields = [
            'request_id',
            'student',
            'status',
            'auto_approved',
            'qr_token',
            'qr_image_path',
            'qr_generated_at',
            'approved_by',
            'created_at',
            'updated_at',
        ]


class AbsenceRecordSerializer(serializers.ModelSerializer):
    """Serializer for AbsenceRecord model."""
    
    student_number = serializers.SerializerMethodField()
    student_name = serializers.SerializerMethodField()
    student_room = serializers.SerializerMethodField()
    student_contact = serializers.SerializerMethodField()
    approved_by_name = serializers.CharField(source='approved_by.name', read_only=True)
    duration_days = serializers.ReadOnlyField()
    is_short_leave = serializers.ReadOnlyField()

    def _get_student(self, obj):
        try:
            return obj.student
        except ObjectDoesNotExist:
            return None

    def get_student_number(self, obj):
        student = self._get_student(obj)
        return student.student_id if student else 'UNKNOWN'

    def get_student_name(self, obj):
        student = self._get_student(obj)
        return student.name if student else 'Unknown Student'

    def get_student_room(self, obj):
        student = self._get_student(obj)
        return student.room_number if student else 'N/A'

    def get_student_contact(self, obj):
        student = self._get_student(obj)
        if not student:
            return None
        return student.phone or student.mobile_number
    
    class Meta:
        model = AbsenceRecord
        fields = [
            'absence_id', 'student', 'student_number', 'student_name', 'student_room', 'student_contact',
            'start_date', 'end_date', 'reason', 'emergency_contact',
            'status', 'auto_approved', 'parent_approval', 'parent_response_at', 'approval_reason', 'approved_by',
            'approved_by_name', 'duration_days', 'is_short_leave',
            'created_at', 'updated_at'
        ]
        read_only_fields = [
            'absence_id', 'student', 'auto_approved', 'approved_by', 'created_at', 'updated_at'
        ]


class MaintenanceRequestSerializer(serializers.ModelSerializer):
    """Serializer for MaintenanceRequest model."""

    student_name = serializers.SerializerMethodField()
    student_id = serializers.SerializerMethodField()
    block = serializers.SerializerMethodField()
    student_contact = serializers.SerializerMethodField()
    assigned_to_name = serializers.CharField(source='assigned_to.name', read_only=True)
    assigned_to_staff_id = serializers.CharField(source='assigned_to.staff_id', read_only=True)
    is_overdue = serializers.ReadOnlyField()
    days_pending = serializers.ReadOnlyField()
    attachment = serializers.ImageField(required=False, allow_null=True, use_url=True)

    def validate_attachment(self, value):
        if value and hasattr(value, 'size') and value.size > 5 * 1024 * 1024:
            raise serializers.ValidationError('File size must not exceed 5MB.')
        return value

    def to_representation(self, instance):
        data = super().to_representation(instance)
        attachment = data.get('attachment')
        request = self.context.get('request')
        if (
            request
            and attachment
            and isinstance(attachment, str)
            and attachment.startswith('/')
            and not attachment.startswith('//')
        ):
            data['attachment'] = request.build_absolute_uri(attachment)
        return data

    def _get_student(self, obj):
        try:
            return obj.student
        except ObjectDoesNotExist:
            return None

    def get_student_name(self, obj):
        student = self._get_student(obj)
        return student.name if student else 'Unknown Student'

    def get_student_id(self, obj):
        student = self._get_student(obj)
        return student.student_id if student else 'UNKNOWN'

    def get_block(self, obj):
        student = self._get_student(obj)
        return student.block if student else ''

    def get_student_contact(self, obj):
        student = self._get_student(obj)
        if not student:
            return None
        return student.phone or student.mobile_number
    
    class Meta:
        model = MaintenanceRequest
        fields = [
            'request_id', 'student', 'student_name', 'student_id', 'block', 'student_contact', 'room_number',
            'issue_type', 'description', 'priority', 'status',
            'auto_approved', 'assigned_to', 'assigned_to_name', 'assigned_to_staff_id',
            'estimated_completion', 'actual_completion', 'notes', 'attachment',
            'is_overdue', 'days_pending', 'created_at', 'updated_at'
        ]
        read_only_fields = [
            'request_id', 'student', 'auto_approved', 'is_overdue', 'days_pending',
            'created_at', 'updated_at'
        ]


class AuditLogSerializer(serializers.ModelSerializer):
    """Serializer for AuditLog model."""
    
    class Meta:
        model = AuditLog
        fields = [
            'log_id', 'action_type', 'entity_type', 'entity_id',
            'decision', 'reasoning', 'confidence_score', 'rules_applied',
            'user_id', 'user_type', 'metadata', 'timestamp'
        ]
        read_only_fields = ['log_id', 'timestamp']


class MessageProcessingResponseSerializer(serializers.Serializer):
    """Serializer for message processing responses."""
    
    success = serializers.BooleanField()
    message_id = serializers.UUIDField()
    response_message = serializers.CharField()
    status = serializers.CharField()
    confidence = serializers.FloatField()
    requires_follow_up = serializers.BooleanField()
    intent_result = serializers.JSONField(required=False)
    approval_result = serializers.JSONField(required=False)
    metadata = serializers.JSONField(required=False)


class HealthCheckSerializer(serializers.Serializer):
    """Serializer for health check responses."""
    
    status = serializers.CharField()
    timestamp = serializers.DateTimeField()
    version = serializers.CharField()
    services = serializers.JSONField()


class SystemInfoSerializer(serializers.Serializer):
    """Serializer for system information responses."""
    
    project = serializers.CharField()
    version = serializers.CharField()
    features = serializers.JSONField()
    environment = serializers.CharField()
    database_status = serializers.CharField()


class StaffQuerySerializer(serializers.Serializer):
    """Serializer for staff natural language queries."""
    
    query = serializers.CharField(max_length=500)
    staff_id = serializers.CharField(max_length=20)
    
    def validate_query(self, value):
        """Validate query is not empty."""
        if not value.strip():
            raise serializers.ValidationError("Query cannot be empty.")
        return value.strip()
    
    def validate_staff_id(self, value):
        """Validate staff member exists."""
        if not Staff.objects.filter(staff_id=value, is_active=True).exists():
            raise serializers.ValidationError("Staff member not found or inactive.")
        return value


class StaffQueryResponseSerializer(serializers.Serializer):
    """Serializer for staff query responses."""
    
    success = serializers.BooleanField()
    query = serializers.CharField()
    response = serializers.CharField()
    query_type = serializers.CharField()
    results = serializers.JSONField()
    metadata = serializers.JSONField()


class DailySummarySerializer(serializers.Serializer):
    """Serializer for daily summary data."""
    
    date = serializers.DateField()
    total_students = serializers.IntegerField()
    absent_students = serializers.IntegerField()
    active_guests = serializers.IntegerField()
    pending_requests = serializers.IntegerField()
    maintenance_issues = serializers.IntegerField()
    summary_text = serializers.CharField()
    generated_at = serializers.DateTimeField()
    metadata = serializers.JSONField()


class RequestApprovalSerializer(serializers.Serializer):
    """Serializer for request approval/rejection."""
    
    request_id = serializers.UUIDField()
    action = serializers.ChoiceField(choices=['approve', 'reject'])
    reason = serializers.CharField(max_length=500, required=False)
    staff_id = serializers.CharField(max_length=20)
    
    def validate_staff_id(self, value):
        """Validate staff member exists and has approval permissions."""
        try:
            staff = Staff.objects.get(staff_id=value, is_active=True)
            if staff.role not in ['warden', 'admin']:
                raise serializers.ValidationError("Staff member does not have approval permissions.")
        except Staff.DoesNotExist:
            raise serializers.ValidationError("Staff member not found or inactive.")
        return value


class ConversationContextSerializer(serializers.Serializer):
    """Serializer for conversation context data."""
    
    user_id = serializers.CharField()
    conversation_id = serializers.CharField()
    state = serializers.CharField()
    exchange_count = serializers.IntegerField()
    missing_information = serializers.ListField(child=serializers.CharField())
    collected_information = serializers.JSONField()
    requires_follow_up = serializers.BooleanField()


class NoticeBoardSerializer(serializers.ModelSerializer):
    """Serializer for NoticeBoard model."""
    
    warden_name = serializers.CharField(source='warden.name', read_only=True)
    warden_id = serializers.CharField(source='warden.staff_id', read_only=True)
    
    class Meta:
        model = NoticeBoard
        fields = [
            'notice_id', 'warden', 'warden_name', 'warden_id', 'title', 'content',
            'priority', 'target_audience', 'is_active', 'created_at', 'updated_at'
        ]
        read_only_fields = ['notice_id', 'created_at', 'updated_at', 'warden', 'warden_name', 'warden_id']


class NotificationSerializer(serializers.ModelSerializer):
    """Serializer for Notification model."""
    
    recipient_type = serializers.SerializerMethodField()
    recipient_name = serializers.SerializerMethodField()
    
    class Meta:
        model = Notification
        fields = [
            'notification_id', 'title', 'message', 'type', 'priority',
            'action_url', 'metadata', 'is_read', 'read_at', 'created_at',
            'recipient_type', 'recipient_name'
        ]
        read_only_fields = ['notification_id', 'created_at']
    
    def get_recipient_type(self, obj):
        """Return the recipient type (student or staff)"""
        if obj.recipient_student:
            return 'student'
        elif obj.recipient_staff:
            return 'staff'
        return None
    
    def get_recipient_name(self, obj):
        """Return the recipient name"""
        if obj.recipient_student:
            return obj.recipient_student.name
        elif obj.recipient_staff:
            return obj.recipient_staff.name
        return None
        read_only_fields = ['notice_id', 'created_at', 'updated_at', 'warden']