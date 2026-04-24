"""
Tests for digital pass display functionality.
Tests that digital passes are filtered by authenticated user and display correct user data.
"""

import pytest
from django.test import TestCase
from django.utils import timezone
from datetime import timedelta
from rest_framework.test import APIClient
from rest_framework import status
from core.models import Student, Staff, DigitalPass, AbsenceRecord
from core.authentication import SupabaseUser
from hypothesis import given, strategies as st, settings
from hypothesis.extra.django import TestCase as HypothesisTestCase

# Mark all tests in this module as requiring database access
pytestmark = pytest.mark.django_db


@pytest.mark.django_db
class TestDigitalPassDisplay(TestCase):
    """Test digital pass display with user-specific filtering."""
    
    def setUp(self):
        """Set up test data."""
        # Create test students
        self.student1 = Student.objects.create(
            student_id='TEST001',
            name='Alice Johnson',
            email='alice@test.edu',
            room_number='101',
            block='A',
            phone='1234567890'
        )
        
        self.student2 = Student.objects.create(
            student_id='TEST002',
            name='Bob Smith',
            email='bob@test.edu',
            room_number='102',
            block='A',
            phone='0987654321'
        )
        
        # Create test staff
        self.staff = Staff.objects.create(
            staff_id='STAFF001',
            name='Warden Test',
            role='warden',
            email='warden@test.edu',
            phone='5555555555'
        )
        
        # Create absence records
        self.absence1 = AbsenceRecord.objects.create(
            student=self.student1,
            start_date=timezone.now(),
            end_date=timezone.now() + timedelta(days=2),
            reason='Family emergency',
            status='approved',
            approved_by=self.staff
        )
        
        self.absence2 = AbsenceRecord.objects.create(
            student=self.student2,
            start_date=timezone.now(),
            end_date=timezone.now() + timedelta(days=3),
            reason='Medical appointment',
            status='approved',
            approved_by=self.staff
        )
        
        # Create digital passes
        self.pass1 = DigitalPass.objects.create(
            student=self.student1,
            absence_record=self.absence1,
            from_date=self.absence1.start_date.date(),
            to_date=self.absence1.end_date.date(),
            total_days=2,
            reason='Family emergency',
            approved_by=self.staff,
            approval_type='manual',
            status='active'
        )
        
        self.pass2 = DigitalPass.objects.create(
            student=self.student2,
            absence_record=self.absence2,
            from_date=self.absence2.start_date.date(),
            to_date=self.absence2.end_date.date(),
            total_days=3,
            reason='Medical appointment',
            approved_by=self.staff,
            approval_type='manual',
            status='active'
        )
        
        # Create API client
        self.client = APIClient()
    
    def test_student_sees_only_own_passes(self):
        """Test that a student only sees their own digital passes."""
        # Create Supabase user for student1
        user = SupabaseUser(
            user_data={'id': self.student1.student_id, 'email': self.student1.email},
            user_type='student',
            user_object=self.student1
        )
        
        # Force authenticate
        self.client.force_authenticate(user=user)
        
        # Get digital passes
        response = self.client.get('/api/digital-passes/')
        
        # Verify response
        assert response.status_code == status.HTTP_200_OK
        assert response.data['success'] is True
        
        # Verify only student1's pass is returned
        passes = response.data['passes']
        assert len(passes) == 1
        assert passes[0]['pass_number'] == self.pass1.pass_number
        
        # Verify student data comes from authenticated user
        assert passes[0]['student_name'] == self.student1.name
        assert passes[0]['student_id'] == self.student1.student_id
        assert passes[0]['room_number'] == self.student1.room_number
    
    def test_different_student_sees_different_passes(self):
        """Test that different students see different passes."""
        # Create Supabase user for student2
        user = SupabaseUser(
            user_data={'id': self.student2.student_id, 'email': self.student2.email},
            user_type='student',
            user_object=self.student2
        )
        
        # Force authenticate
        self.client.force_authenticate(user=user)
        
        # Get digital passes
        response = self.client.get('/api/digital-passes/')
        
        # Verify response
        assert response.status_code == status.HTTP_200_OK
        assert response.data['success'] is True
        
        # Verify only student2's pass is returned
        passes = response.data['passes']
        assert len(passes) == 1
        assert passes[0]['pass_number'] == self.pass2.pass_number
        
        # Verify student data comes from authenticated user
        assert passes[0]['student_name'] == self.student2.name
        assert passes[0]['student_id'] == self.student2.student_id
        assert passes[0]['room_number'] == self.student2.room_number
    
    def test_student_with_no_passes_gets_empty_list(self):
        """Test that a student with no passes gets an empty list."""
        # Create a new student with no passes
        student3 = Student.objects.create(
            student_id='TEST003',
            name='Charlie Brown',
            email='charlie@test.edu',
            room_number='103',
            block='A',
            phone='1111111111'
        )
        
        # Create Supabase user for student3
        user = SupabaseUser(
            user_data={'id': student3.student_id, 'email': student3.email},
            user_type='student',
            user_object=student3
        )
        
        # Force authenticate
        self.client.force_authenticate(user=user)
        
        # Get digital passes
        response = self.client.get('/api/digital-passes/')
        
        # Verify response
        assert response.status_code == status.HTTP_200_OK
        assert response.data['success'] is True
        assert len(response.data['passes']) == 0
    
    def test_pass_data_matches_authenticated_user_record(self):
        """Test that all pass data matches the authenticated user's database record."""
        # Create Supabase user for student1
        user = SupabaseUser(
            user_data={'id': self.student1.student_id, 'email': self.student1.email},
            user_type='student',
            user_object=self.student1
        )
        
        # Force authenticate
        self.client.force_authenticate(user=user)
        
        # Get digital passes
        response = self.client.get('/api/digital-passes/')
        
        # Verify response
        assert response.status_code == status.HTTP_200_OK
        passes = response.data['passes']
        
        # Verify all fields match the authenticated user's record
        for pass_data in passes:
            assert pass_data['student_name'] == self.student1.name
            assert pass_data['student_id'] == self.student1.student_id
            assert pass_data['room_number'] == self.student1.room_number
            
            # Verify no hardcoded values
            assert pass_data['student_name'] != 'John Doe'
            assert pass_data['student_name'] != 'Development Student'



@pytest.mark.django_db
class TestUserSpecificPassFilteringProperty(HypothesisTestCase):
    """
    Property-based test for user-specific pass filtering.
    
    **Property 1: User-Specific Pass Filtering**
    **Validates: Requirements 1.1, 1.2, 1.3**
    
    For any authenticated student, when retrieving digital passes, the system should 
    return only passes where the student field matches the authenticated user's ID, 
    and all returned passes should have student_name, student_id, and room_number 
    matching the authenticated user's database record.
    """
    
    def setUp(self):
        """Set up test data that persists across property test runs."""
        # Create a staff member for approvals
        self.staff = Staff.objects.create(
            staff_id='STAFF_PBT',
            name='Property Test Warden',
            role='warden',
            email='warden_pbt@test.edu',
            phone='5555555555'
        )
    
    @settings(max_examples=5, deadline=None)
    @given(
        # Generate random student data
        num_students=st.integers(min_value=2, max_value=3),
        passes_per_student=st.integers(min_value=0, max_value=2),
        student_names=st.lists(
            st.text(alphabet=st.characters(whitelist_categories=('Lu', 'Ll')), min_size=5, max_size=20),
            min_size=2,
            max_size=5,
            unique=True
        ),
        room_numbers=st.lists(
            st.text(alphabet=st.characters(whitelist_categories=('Nd',)), min_size=3, max_size=3),
            min_size=2,
            max_size=5,
            unique=True
        ),
        blocks=st.lists(
            st.sampled_from(['A', 'B', 'C', 'D', 'E']),
            min_size=2,
            max_size=5
        )
    )
    def test_property_user_specific_pass_filtering(
        self, 
        num_students, 
        passes_per_student, 
        student_names, 
        room_numbers, 
        blocks
    ):
        """
        Property test: Each student should only see their own passes with correct data.
        
        This test generates random students and passes, then verifies that:
        1. Each student only sees passes associated with their user ID
        2. All pass data matches the authenticated user's database record
        3. No hardcoded values appear in the response
        """
        # Ensure we have enough data for the number of students
        if len(student_names) < num_students or len(room_numbers) < num_students:
            return
        
        # Create random students
        students = []
        for i in range(num_students):
            student = Student.objects.create(
                student_id=f'PBT{i:04d}',
                name=student_names[i],
                email=f'pbt{i}@test.edu',
                room_number=room_numbers[i],
                block=blocks[i % len(blocks)],
                phone=f'555000{i:04d}'
            )
            students.append(student)
        
        # Create random passes for each student
        all_passes = {}
        for student in students:
            student_passes = []
            for j in range(passes_per_student):
                # Create absence record
                start_date = timezone.now() + timedelta(days=j)
                end_date = start_date + timedelta(days=2)
                
                absence = AbsenceRecord.objects.create(
                    student=student,
                    start_date=start_date,
                    end_date=end_date,
                    reason=f'Test reason {j}',
                    status='approved',
                    approved_by=self.staff
                )
                
                # Create digital pass
                digital_pass = DigitalPass.objects.create(
                    student=student,
                    absence_record=absence,
                    from_date=start_date.date(),
                    to_date=end_date.date(),
                    total_days=2,
                    reason=f'Test reason {j}',
                    approved_by=self.staff,
                    approval_type='manual',
                    status='active'
                )
                student_passes.append(digital_pass)
            
            all_passes[student.student_id] = student_passes
        
        # Test each student's view
        client = APIClient()
        
        for student in students:
            # Create Supabase user for this student
            user = SupabaseUser(
                user_data={'id': student.student_id, 'email': student.email},
                user_type='student',
                user_object=student
            )
            
            # Force authenticate
            client.force_authenticate(user=user)
            
            # Get digital passes
            response = client.get('/api/digital-passes/')
            
            # Verify response is successful
            assert response.status_code == status.HTTP_200_OK, \
                f"Expected 200 OK, got {response.status_code}"
            assert response.data['success'] is True, \
                "Response should indicate success"
            
            # Get returned passes
            returned_passes = response.data['passes']
            
            # Property 1: Verify count matches expected passes for this student
            expected_count = len(all_passes[student.student_id])
            assert len(returned_passes) == expected_count, \
                f"Student {student.student_id} should see {expected_count} passes, got {len(returned_passes)}"
            
            # Property 2: Verify all returned passes belong to this student
            for pass_data in returned_passes:
                # Verify student-specific data matches authenticated user's record
                assert pass_data['student_name'] == student.name, \
                    f"Pass student_name should be '{student.name}', got '{pass_data['student_name']}'"
                assert pass_data['student_id'] == student.student_id, \
                    f"Pass student_id should be '{student.student_id}', got '{pass_data['student_id']}'"
                assert pass_data['room_number'] == student.room_number, \
                    f"Pass room_number should be '{student.room_number}', got '{pass_data['room_number']}'"
                
                # Property 3: Verify no hardcoded values
                assert pass_data['student_name'] != 'John Doe', \
                    "Pass should not contain hardcoded name 'John Doe'"
                assert pass_data['student_name'] != 'Development Student', \
                    "Pass should not contain hardcoded name 'Development Student'"
                assert pass_data['student_id'] != 'DEV001', \
                    "Pass should not contain hardcoded student_id 'DEV001'"
            
            # Property 4: Verify this student doesn't see other students' passes
            returned_pass_numbers = {p['pass_number'] for p in returned_passes}
            expected_pass_numbers = {p.pass_number for p in all_passes[student.student_id]}
            
            assert returned_pass_numbers == expected_pass_numbers, \
                f"Student {student.student_id} should only see their own passes"
            
            # Verify no passes from other students are included
            for other_student in students:
                if other_student.student_id != student.student_id:
                    other_pass_numbers = {p.pass_number for p in all_passes[other_student.student_id]}
                    intersection = returned_pass_numbers & other_pass_numbers
                    assert len(intersection) == 0, \
                        f"Student {student.student_id} should not see passes from {other_student.student_id}"
        
        # Clean up
        for student in students:
            student.delete()
