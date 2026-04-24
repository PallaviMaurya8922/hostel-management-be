from django.db import models
import uuid
from django.core.validators import MinValueValidator, MaxValueValidator
from django.utils import timezone
from django.contrib.auth.hashers import make_password, check_password
import secrets
import string


class Student(models.Model):
    """Model representing a hostel student with authentication"""
    student_id = models.CharField(max_length=20, unique=True, help_text="Unique student identifier")
    name = models.CharField(max_length=100, help_text="Student's full name")
    email = models.EmailField(unique=True, help_text="Student's email address", default='temp@example.com')
    password_hash = models.CharField(max_length=255, help_text="Hashed password", default='pbkdf2_sha256$600000$temp$temp')
    mobile_number = models.CharField(max_length=15, blank=True, null=True, help_text="Mobile phone number")
    room_number = models.CharField(max_length=10, help_text="Room number assignment")
    block = models.CharField(max_length=5, help_text="Hostel block (e.g., A, B, C)")
    phone = models.CharField(max_length=15, blank=True, null=True, help_text="Contact phone number")
    parent_phone = models.CharField(max_length=15, blank=True, null=True, help_text="Parent WhatsApp phone number")
    is_first_login = models.BooleanField(default=True, help_text="Whether this is the first login")
    profile_photo = models.ImageField(
        upload_to='student_photos/%Y/%m/',
        null=True,
        blank=True,
        help_text="Student's profile photo"
    )
    violation_count = models.IntegerField(
        default=0, 
        validators=[MinValueValidator(0)],
        help_text="Number of policy violations"
    )
    last_violation_date = models.DateTimeField(null=True, blank=True, help_text="Date of most recent violation")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'students'
        ordering = ['student_id']

    def __str__(self):
        return f"{self.student_id} - {self.name}"

    def set_password(self, raw_password):
        """Set password with hashing"""
        self.password_hash = make_password(raw_password)
        
    def check_password(self, raw_password):
        """Check password against hash"""
        return check_password(raw_password, self.password_hash)
    
    @classmethod
    def generate_default_password(cls):
        """Generate a default password"""
        return '123456'

    @property
    def has_recent_violations(self):
        """Check if student has violations in the last 30 days"""
        if not self.last_violation_date:
            return False
        return (timezone.now() - self.last_violation_date).days <= 30


class Staff(models.Model):
    """Model representing hostel staff members with authentication"""
    ROLE_CHOICES = [
        ('warden', 'Warden'),
        ('security', 'Security'),
        ('admin', 'Administrator'),
        ('maintenance', 'Maintenance'),
    ]
    
    staff_id = models.CharField(max_length=20, unique=True, help_text="Unique staff identifier")
    name = models.CharField(max_length=100, help_text="Staff member's full name")
    email = models.EmailField(unique=True, help_text="Staff email address", default='temp@staff.com')
    password_hash = models.CharField(max_length=255, help_text="Hashed password", default='pbkdf2_sha256$600000$temp$temp')
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, help_text="Staff role/position")
    permissions = models.JSONField(default=dict, help_text="Role-based permissions")
    phone = models.CharField(max_length=15, blank=True, null=True, help_text="Contact phone number")
    is_first_login = models.BooleanField(default=False, help_text="Whether this is the first login")
    is_active = models.BooleanField(default=True, help_text="Whether staff member is currently active")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'staff'
        ordering = ['staff_id']

    def __str__(self):
        return f"{self.staff_id} - {self.name} ({self.get_role_display()})"
    
    def set_password(self, raw_password):
        """Set password with hashing"""
        self.password_hash = make_password(raw_password)
        
    def check_password(self, raw_password):
        """Check password against hash"""
        return check_password(raw_password, self.password_hash)


class Message(models.Model):
    """Model representing messages sent by students"""
    MESSAGE_STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('processing', 'Processing'),
        ('processed', 'Processed'),
        ('failed', 'Failed'),
    ]
    
    message_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    sender = models.ForeignKey(Student, on_delete=models.CASCADE, related_name='messages')
    content = models.TextField(help_text="Original message content")
    status = models.CharField(max_length=20, choices=MESSAGE_STATUS_CHOICES, default='pending')
    processed = models.BooleanField(default=False, help_text="Whether message has been processed")
    confidence_score = models.FloatField(
        null=True, 
        blank=True,
        validators=[MinValueValidator(0.0), MaxValueValidator(1.0)],
        help_text="AI confidence score (0.0-1.0)"
    )
    extracted_intent = models.JSONField(null=True, blank=True, help_text="Extracted intent and entities")
    response_sent = models.BooleanField(default=False, help_text="Whether response was sent to student")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'messages'
        ordering = ['-created_at']

    def __str__(self):
        return f"Message {self.message_id} from {self.sender.student_id}"


class GuestRequest(models.Model):
    """Model representing guest stay requests"""
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected'),
        ('expired', 'Expired'),
    ]

    VISIT_TYPE_CHOICES = [
        ('normal', 'Normal'),
        ('overnight', 'Overnight'),
    ]
    
    RELATIONSHIP_CHOICES = [
        ('parent', 'Parent'),
        ('sibling', 'Sibling'),
        ('relative', 'Relative'),
        ('guardian', 'Guardian'),
        ('friend', 'Friend'),
        ('other', 'Other'),
    ]
    
    request_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    student = models.ForeignKey(Student, on_delete=models.CASCADE, related_name='guest_requests')
    guest_name = models.CharField(max_length=100, help_text="Name of the guest")
    visit_type = models.CharField(
        max_length=20,
        choices=VISIT_TYPE_CHOICES,
        default='normal',
        help_text="Normal visits are auto-approved; overnight visits require warden approval",
    )
    relationship = models.CharField(max_length=20, choices=RELATIONSHIP_CHOICES, default='other', help_text="Relationship with the guest")
    guest_phone = models.CharField(max_length=15, blank=True, null=True, help_text="Guest contact number")
    start_date = models.DateTimeField(help_text="Guest arrival date and time")
    end_date = models.DateTimeField(help_text="Guest departure date and time")
    purpose = models.TextField(blank=True, null=True, help_text="Purpose of visit")
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    auto_approved = models.BooleanField(default=False, help_text="Whether request was auto-approved")
    qr_token = models.CharField(max_length=128, blank=True, null=True, help_text="Generated token used to render guest QR")
    qr_generated_at = models.DateTimeField(blank=True, null=True, help_text="Timestamp when guest QR token was generated")
    qr_image_path = models.CharField(max_length=255, blank=True, null=True, help_text="Path to generated QR image file")
    approval_reason = models.TextField(blank=True, null=True, help_text="Reason for approval/rejection")
    approved_by = models.ForeignKey(Staff, on_delete=models.SET_NULL, null=True, blank=True, related_name='approved_guests')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'guest_requests'
        ordering = ['-created_at']

    def __str__(self):
        return f"Guest request {self.request_id} - {self.guest_name} for {self.student.student_id}"

    @property
    def duration_days(self):
        """Calculate duration of guest stay in days"""
        return (self.end_date - self.start_date).days

    @property
    def is_short_stay(self):
        """Check if guest stay is 1 night or less"""
        return self.duration_days <= 1


class AbsenceRecord(models.Model):
    """Model representing student absence records"""
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected'),
        ('expired', 'Expired'),
    ]
    
    absence_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    student = models.ForeignKey(Student, on_delete=models.CASCADE, related_name='absence_records')
    start_date = models.DateTimeField(help_text="Start date of absence")
    end_date = models.DateTimeField(help_text="End date of absence")
    reason = models.TextField(help_text="Reason for absence")
    emergency_contact = models.CharField(max_length=15, blank=True, null=True, help_text="Emergency contact during absence")
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    auto_approved = models.BooleanField(default=False, help_text="Whether request was auto-approved")
    parent_approval = models.BooleanField(null=True, default=None, help_text="Parent decision for leave approval")
    parent_response_at = models.DateTimeField(null=True, blank=True, help_text="Timestamp when parent responded")
    approval_reason = models.TextField(blank=True, null=True, help_text="Reason for approval/rejection")
    approved_by = models.ForeignKey(Staff, on_delete=models.SET_NULL, null=True, blank=True, related_name='approved_absences')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'absence_records'
        ordering = ['-created_at']

    def __str__(self):
        return f"Absence {self.absence_id} - {self.student.student_id}"

    @property
    def duration_days(self):
        """Calculate duration of absence in days"""
        # Ensure both dates are timezone-aware for proper calculation
        from django.utils import timezone
        
        start = self.start_date
        end = self.end_date
        
        # If either date is naive, make it timezone-aware
        if timezone.is_naive(start):
            start = timezone.make_aware(start)
        if timezone.is_naive(end):
            end = timezone.make_aware(end)
            
        return (end - start).days

    @property
    def is_short_leave(self):
        """Check if absence is 2 days or less"""
        return self.duration_days <= 2


class MaintenanceRequest(models.Model):
    """Model representing maintenance requests from students"""
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('assigned', 'Assigned'),
        ('in_progress', 'In Progress'),
        ('completed', 'Completed'),
        ('cancelled', 'Cancelled'),
    ]
    
    PRIORITY_CHOICES = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('emergency', 'Emergency'),
    ]
    
    ISSUE_TYPE_CHOICES = [
        ('electrical', 'Electrical'),
        ('plumbing', 'Plumbing'),
        ('hvac', 'HVAC/Air Conditioning'),
        ('furniture', 'Furniture'),
        ('cleaning', 'Cleaning'),
        ('other', 'Other'),
    ]
    
    request_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    student = models.ForeignKey(Student, on_delete=models.CASCADE, related_name='maintenance_requests')
    room_number = models.CharField(max_length=10, help_text="Room where maintenance is needed")
    issue_type = models.CharField(max_length=20, choices=ISSUE_TYPE_CHOICES, help_text="Type of maintenance issue")
    description = models.TextField(help_text="Detailed description of the issue")
    priority = models.CharField(max_length=20, choices=PRIORITY_CHOICES, default='medium')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    auto_approved = models.BooleanField(default=False, help_text="Whether request was auto-approved")
    assigned_to = models.ForeignKey(Staff, on_delete=models.SET_NULL, null=True, blank=True, related_name='assigned_maintenance')
    estimated_completion = models.DateTimeField(null=True, blank=True, help_text="Estimated completion date")
    actual_completion = models.DateTimeField(null=True, blank=True, help_text="Actual completion date")
    notes = models.TextField(blank=True, null=True, help_text="Additional notes from maintenance staff")
    attachment = models.ImageField(
        upload_to='maintenance/%Y/%m/',
        null=True,
        blank=True,
        help_text="Optional photo from the student showing the issue",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'maintenance_requests'
        ordering = ['-created_at']

    def __str__(self):
        return f"Maintenance {self.request_id} - {self.issue_type} in {self.room_number}"

    @property
    def is_overdue(self):
        """Check if maintenance request is overdue"""
        if not self.estimated_completion or self.status == 'completed':
            return False
        return timezone.now() > self.estimated_completion

    @property
    def days_pending(self):
        """Calculate days since request was created"""
        return (timezone.now() - self.created_at).days


class DigitalPass(models.Model):
    """Model for digital passes generated for approved leave requests"""
    pass_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    pass_number = models.CharField(max_length=20, unique=True, help_text="Unique pass number for verification")
    student = models.ForeignKey(Student, on_delete=models.CASCADE, related_name='digital_passes')
    absence_record = models.OneToOneField(AbsenceRecord, on_delete=models.CASCADE, related_name='digital_pass')
    
    # Pass details
    from_date = models.DateField(help_text="Leave start date")
    to_date = models.DateField(help_text="Leave end date")
    total_days = models.IntegerField(help_text="Total number of leave days")
    reason = models.TextField(help_text="Reason for leave")
    
    # Approval details
    approved_by = models.ForeignKey(Staff, on_delete=models.SET_NULL, null=True, blank=True, related_name='approved_passes')
    approval_type = models.CharField(max_length=20, choices=[
        ('auto', 'Auto-Approved'),
        ('manual', 'Manually Approved')
    ], help_text="Type of approval")
    
    # Pass status
    status = models.CharField(max_length=20, choices=[
        ('active', 'Active'),
        ('expired', 'Expired'),
        ('cancelled', 'Cancelled')
    ], default='active', help_text="Current status of the pass")
    
    # PDF and verification
    pdf_generated = models.BooleanField(default=False, help_text="Whether PDF has been generated")
    pdf_path = models.CharField(max_length=255, blank=True, null=True, help_text="Path to generated PDF file")
    verification_code = models.CharField(max_length=10, help_text="Short verification code for security")
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'digital_passes'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['pass_number']),
            models.Index(fields=['student', 'status']),
            models.Index(fields=['from_date', 'to_date']),
        ]

    def __str__(self):
        return f"Pass {self.pass_number} - {self.student.name}"

    def save(self, *args, **kwargs):
        if not self.pass_number:
            self.pass_number = self.generate_pass_number()
        if not self.verification_code:
            self.verification_code = self.generate_verification_code()
        super().save(*args, **kwargs)

    @classmethod
    def generate_pass_number(cls):
        """Generate a unique pass number"""
        import random
        import string
        while True:
            # Format: LP-YYYYMMDD-XXXX (LP = Leave Pass)
            date_part = timezone.now().strftime('%Y%m%d')
            random_part = ''.join(random.choices(string.digits, k=4))
            pass_number = f"LP-{date_part}-{random_part}"
            if not cls.objects.filter(pass_number=pass_number).exists():
                return pass_number

    @classmethod
    def generate_verification_code(cls):
        """Generate a short verification code"""
        import random
        import string
        return ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))

    @property
    def is_valid(self):
        """Check if pass is currently valid"""
        if self.status != 'active':
            return False
        today = timezone.now().date()
        return self.from_date <= today <= self.to_date

    @property
    def days_remaining(self):
        """Calculate days remaining for the pass"""
        if not self.is_valid:
            return 0
        today = timezone.now().date()
        return max(0, (self.to_date - today).days + 1)


class SecurityRecord(models.Model):
    """Model for security verification and tracking"""
    record_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    student = models.ForeignKey(Student, on_delete=models.CASCADE, related_name='security_records')
    digital_pass = models.ForeignKey(DigitalPass, on_delete=models.CASCADE, related_name='security_records', null=True, blank=True)
    
    # Security status
    status = models.CharField(max_length=20, choices=[
        ('allowed_to_leave', 'Allowed to Leave'),
        ('restricted', 'Restricted'),
        ('returned', 'Returned')
    ], help_text="Current security status")
    
    # Verification details
    verified_by = models.CharField(max_length=100, blank=True, null=True, help_text="Security personnel who verified")
    verification_time = models.DateTimeField(null=True, blank=True, help_text="Time of verification")
    gate_exit_time = models.DateTimeField(null=True, blank=True, help_text="Time student left through gate")
    gate_entry_time = models.DateTimeField(null=True, blank=True, help_text="Time student returned through gate")
    
    # Additional notes
    notes = models.TextField(blank=True, null=True, help_text="Additional security notes")
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'security_records'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['student', 'status']),
            models.Index(fields=['digital_pass']),
            models.Index(fields=['verification_time']),
        ]

    def __str__(self):
        return f"Security Record - {self.student.name} ({self.status})"


class AuditLog(models.Model):
    """Model for comprehensive audit logging of all AI decisions"""
    ACTION_TYPES = [
        ('message_processing', 'Message Processing'),
        ('guest_approval', 'Guest Approval'),
        ('absence_approval', 'Absence Approval'),
        ('maintenance_approval', 'Maintenance Approval'),
        ('rule_validation', 'Rule Validation'),
        ('conflict_detection', 'Conflict Detection'),
        ('staff_query', 'Staff Query'),
        ('system_action', 'System Action'),
        ('pass_generation', 'Pass Generation'),
        ('security_verification', 'Security Verification'),
    ]
    
    DECISION_TYPES = [
        ('approved', 'Approved'),
        ('rejected', 'Rejected'),
        ('escalated', 'Escalated'),
        ('processed', 'Processed'),
        ('failed', 'Failed'),
    ]
    
    log_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    action_type = models.CharField(max_length=50, choices=ACTION_TYPES, help_text="Type of action performed")
    entity_type = models.CharField(max_length=50, help_text="Type of entity affected")
    entity_id = models.CharField(max_length=100, help_text="ID of the affected entity")
    decision = models.CharField(max_length=20, choices=DECISION_TYPES, help_text="Decision made")
    reasoning = models.TextField(help_text="Detailed reasoning for the decision")
    confidence_score = models.FloatField(
        validators=[MinValueValidator(0.0), MaxValueValidator(1.0)],
        help_text="Confidence score for the decision"
    )
    rules_applied = models.JSONField(default=list, help_text="List of rules applied in decision")
    user_id = models.CharField(max_length=50, help_text="ID of user who triggered the action")
    user_type = models.CharField(max_length=20, default='student', help_text="Type of user (student/staff)")
    metadata = models.JSONField(default=dict, help_text="Additional metadata for the action")
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'audit_logs'
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['action_type', 'timestamp']),
            models.Index(fields=['entity_type', 'entity_id']),
            models.Index(fields=['user_id', 'timestamp']),
        ]

    def __str__(self):
        return f"Audit {self.log_id} - {self.action_type} ({self.decision})"


class ConversationContext(models.Model):
    """Model for persisting conversation context across messages"""
    context_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    student = models.OneToOneField(Student, on_delete=models.CASCADE, related_name='conversation_context', null=True, blank=True)
    user_id = models.CharField(max_length=50, help_text="User identifier")
    user_type = models.CharField(max_length=20, default='student', help_text="Type of user (student/staff)")
    conversation_id = models.CharField(max_length=200, unique=True, help_text="Unique conversation identifier")
    
    # Conversation state
    intent_history = models.JSONField(default=list, help_text="History of intents in this conversation")
    last_message_id = models.CharField(max_length=200, blank=True, help_text="ID of the last message processed")
    pending_clarifications = models.JSONField(default=list, help_text="List of pending clarification fields")
    
    # Context data for multi-turn conversations
    context_data = models.JSONField(default=dict, help_text="Conversation context data (e.g., leave_request_data)")
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'conversation_contexts'
        ordering = ['-updated_at']
        indexes = [
            models.Index(fields=['user_id', 'updated_at']),
            models.Index(fields=['conversation_id']),
        ]
    
    def __str__(self):
        return f"Conversation {self.conversation_id} - {self.user_id}"
    
    def is_expired(self, timeout_hours=24):
        """Check if context is expired"""
        return (timezone.now() - self.updated_at).total_seconds() > (timeout_hours * 3600)


class NoticeBoard(models.Model):
    """Model representing hostel notices posted by wardens for all students"""

    TARGET_AUDIENCE_CHOICES = [
        ('student', 'Student'),
        ('security', 'Security'),
    ]
    
    notice_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    warden = models.ForeignKey(Staff, on_delete=models.CASCADE, related_name='notices', help_text="Staff member who posted the notice")
    title = models.CharField(max_length=200, help_text="Title of the notice")
    content = models.TextField(help_text="Detailed content of the notice")
    priority = models.CharField(
        max_length=20,
        choices=[
            ('low', 'Low'),
            ('medium', 'Medium'),
            ('high', 'High'),
            ('urgent', 'Urgent'),
        ],
        default='medium',
        help_text="Priority level of the notice"
    )
    target_audience = models.CharField(
        max_length=20,
        choices=TARGET_AUDIENCE_CHOICES,
        default='student',
        help_text='Which dashboard should receive this notice',
    )
    is_active = models.BooleanField(default=True, help_text="Whether the notice is currently active/visible")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'notice_board'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['is_active', '-created_at']),
        ]
    
    def __str__(self):
        return f"Notice {self.notice_id} - {self.title}"


class Notification(models.Model):
    """Model for in-app notifications to students and staff"""
    
    PRIORITY_CHOICES = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
    ]
    
    notification_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    
    # Recipients (exactly one should be set)
    recipient_student = models.ForeignKey(
        Student, 
        on_delete=models.CASCADE, 
        null=True, 
        blank=True, 
        related_name='notifications_received',
        help_text="Student recipient of the notification"
    )
    recipient_staff = models.ForeignKey(
        Staff, 
        on_delete=models.CASCADE, 
        null=True, 
        blank=True, 
        related_name='notifications_received',
        help_text="Staff recipient of the notification"
    )
    
    # Notification content
    title = models.CharField(max_length=200, help_text="Notification title")
    message = models.TextField(help_text="Notification message")
    type = models.CharField(
        max_length=50, 
        help_text="Type of notification (leave, guest, notice, maintenance, security, etc.)"
    )
    priority = models.CharField(
        max_length=20,
        choices=PRIORITY_CHOICES,
        default='medium',
        help_text="Priority level of the notification"
    )
    
    # Navigation
    action_url = models.CharField(
        max_length=500, 
        blank=True, 
        null=True,
        help_text="URL to navigate to when notification is clicked"
    )
    
    # Metadata for context
    metadata = models.JSONField(
        default=dict,
        help_text="Additional context data (e.g., request_id, approval_type)"
    )
    
    # Read status
    is_read = models.BooleanField(default=False, help_text="Whether the notification has been read")
    read_at = models.DateTimeField(null=True, blank=True, help_text="Timestamp when notification was read")
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'notifications'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['recipient_student', 'is_read', '-created_at']),
            models.Index(fields=['recipient_staff', 'is_read', '-created_at']),
        ]
    
    def __str__(self):
        recipient = self.recipient_student or self.recipient_staff
        return f"Notification {self.notification_id} - {self.title} for {recipient}"
    
    def clean(self):
        """Validate that exactly one recipient is set"""
        from django.core.exceptions import ValidationError
        has_student = self.recipient_student is not None
        has_staff = self.recipient_staff is not None
        
        if not (has_student or has_staff):
            raise ValidationError("Either recipient_student or recipient_staff must be set")
        if has_student and has_staff:
            raise ValidationError("Only one recipient (student or staff) can be set")
