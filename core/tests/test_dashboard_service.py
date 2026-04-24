"""
Tests for Dashboard Service - Leave Request Visibility
Tests that pending leave requests are correctly filtered and displayed.
"""

import pytest
from django.test import TestCase
from django.utils import timezone
from datetime import timedelta

from ..models import Student, Staff, AbsenceRecord
from ..services.dashboard_service import dashboard_service


class DashboardServiceTest(TestCase):
    """Test cases for Dashboard Service pending request filtering."""
    
    def setUp(self):
        """Set up test data."""
        # Create test student
        self.student = Student.objects.create(
            student_id="TEST001",
            name="Test Student",
            room_number="101A",
            block="A",
            phone="1234567890",
            email="test001@hostel.edu"
        )
        
        # Create test staff
        self.staff = Staff.objects.create(
            staff_id="STAFF001",
            name="Test Staff",
            role="warden",
            permissions={"approve_leave": True},
            phone="0987654321",
            email="staff@hostel.edu"
        )
    
    def test_pending_requests_case_insensitive_filtering(self):
        """Test that pending requests are filtered case-insensitively."""
        now = timezone.now()
        
        # Create absence records with different status cases
        AbsenceRecord.objects.create(
            student=self.student,
            start_date=now + timedelta(days=1),
            end_date=now + timedelta(days=3),
            reason="Family emergency",
            status="pending"  # lowercase
        )
        
        AbsenceRecord.objects.create(
            student=self.student,
            start_date=now + timedelta(days=5),
            end_date=now + timedelta(days=7),
            reason="Medical appointment",
            status="Pending"  # capitalized
        )
        
        AbsenceRecord.objects.create(
            student=self.student,
            start_date=now + timedelta(days=10),
            end_date=now + timedelta(days=12),
            reason="Wedding",
            status="PENDING"  # uppercase
        )
        
        # Create approved record (should not be included)
        AbsenceRecord.objects.create(
            student=self.student,
            start_date=now + timedelta(days=15),
            end_date=now + timedelta(days=17),
            reason="Approved leave",
            status="approved",
            approved_by=self.staff
        )
        
        # Get pending requests
        result = dashboard_service.get_pending_requests(force_refresh=True)
        
        # Verify all pending requests are returned regardless of case
        self.assertEqual(len(result['absence_requests']), 3)
        self.assertEqual(result['total_count'], 3)
    
    def test_pending_requests_include_absence_id(self):
        """Test that pending requests include absence_id as string."""
        now = timezone.now()
        
        # Create absence record
        absence = AbsenceRecord.objects.create(
            student=self.student,
            start_date=now + timedelta(days=1),
            end_date=now + timedelta(days=3),
            reason="Test leave",
            status="pending"
        )
        
        # Get pending requests
        result = dashboard_service.get_pending_requests(force_refresh=True)
        
        # Verify absence_id is included and is a string
        self.assertEqual(len(result['absence_requests']), 1)
        absence_request = result['absence_requests'][0]
        self.assertIn('absence_id', absence_request)
        self.assertIsInstance(absence_request['absence_id'], str)
        self.assertEqual(absence_request['absence_id'], str(absence.absence_id))
    
    def test_pending_requests_eager_loading(self):
        """Test that pending requests use eager loading for related objects."""
        now = timezone.now()
        
        # Create absence record
        AbsenceRecord.objects.create(
            student=self.student,
            start_date=now + timedelta(days=1),
            end_date=now + timedelta(days=3),
            reason="Test leave",
            status="pending"
        )
        
        # Get pending requests with force refresh
        result = dashboard_service.get_pending_requests(force_refresh=True)
        
        # Verify student data is included (from eager loading)
        self.assertEqual(len(result['absence_requests']), 1)
        absence_request = result['absence_requests'][0]
        self.assertIn('student__name', absence_request)
        self.assertEqual(absence_request['student__name'], "Test Student")
    
    def test_force_refresh_invalidates_cache(self):
        """Test that force_refresh parameter invalidates cache."""
        now = timezone.now()
        
        # Create initial absence record
        AbsenceRecord.objects.create(
            student=self.student,
            start_date=now + timedelta(days=1),
            end_date=now + timedelta(days=3),
            reason="Test leave 1",
            status="pending"
        )
        
        # Get pending requests (will be cached)
        result1 = dashboard_service.get_pending_requests(force_refresh=False)
        self.assertEqual(len(result1['absence_requests']), 1)
        
        # Create another absence record
        AbsenceRecord.objects.create(
            student=self.student,
            start_date=now + timedelta(days=5),
            end_date=now + timedelta(days=7),
            reason="Test leave 2",
            status="pending"
        )
        
        # Get pending requests with force refresh
        result2 = dashboard_service.get_pending_requests(force_refresh=True)
        self.assertEqual(len(result2['absence_requests']), 2)
    
    def test_old_pending_requests_not_excluded(self):
        """Test that old pending requests are not excluded by date filters."""
        now = timezone.now()
        
        # Create old pending request (created 30 days ago)
        old_absence = AbsenceRecord.objects.create(
            student=self.student,
            start_date=now + timedelta(days=1),
            end_date=now + timedelta(days=3),
            reason="Old pending request",
            status="pending"
        )
        # Manually set created_at to 30 days ago
        old_absence.created_at = now - timedelta(days=30)
        old_absence.save()
        
        # Create recent pending request
        AbsenceRecord.objects.create(
            student=self.student,
            start_date=now + timedelta(days=5),
            end_date=now + timedelta(days=7),
            reason="Recent pending request",
            status="pending"
        )
        
        # Get pending requests
        result = dashboard_service.get_pending_requests(force_refresh=True)
        
        # Verify both old and new pending requests are included
        self.assertEqual(len(result['absence_requests']), 2)
