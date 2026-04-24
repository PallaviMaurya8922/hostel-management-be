"""
Management command to create test users and dummy maintenance data for development.
"""

from django.core.management.base import BaseCommand
from django.utils import timezone

from core.models import MaintenanceRequest, Staff, Student


class Command(BaseCommand):
    help = 'Create test users plus dummy maintenance data for development'

    def handle(self, *args, **options):
        self.stdout.write('Creating test users...')

        students_config = [
            {
                'student_id': 'STU001',
                'name': 'Priya Sharma',
                'email': 'student@hostel.edu',
                'room_number': '304',
                'block': 'A',
                'phone': '9876543210',
                'parent_phone': '919876543210',
                'password': 'student123',
            },
            {
                'student_id': 'STU002',
                'name': 'Rahul Verma',
                'email': 'rahul@hostel.edu',
                'room_number': '112',
                'block': 'B',
                'phone': '9876543212',
                'parent_phone': '919876543212',
                'password': 'student123',
            },
            {
                'student_id': 'STU003',
                'name': 'Anjali Singh',
                'email': 'anjali@hostel.edu',
                'room_number': '215',
                'block': 'C',
                'phone': '9876543213',
                'parent_phone': '919876543213',
                'password': 'student123',
            },
        ]

        staff_config = [
            {
                'staff_id': 'SEC001',
                'name': 'Rajesh Kumar',
                'email': 'security@hostel.edu',
                'role': 'security',
                'phone': '9876543301',
                'password': 'security123',
            },
            {
                'staff_id': 'WAR001',
                'name': 'Sarah Jenkins',
                'email': 'warden@hostel.edu',
                'role': 'warden',
                'phone': '9876543302',
                'password': 'warden123',
            },
            {
                'staff_id': 'MNT001',
                'name': 'Amit Technician',
                'email': 'maintenance@hostel.edu',
                'role': 'maintenance',
                'phone': '9876543303',
                'password': 'maintenance123',
            },
            {
                'staff_id': 'MNT002',
                'name': 'Neha Electric',
                'email': 'neha.maintenance@hostel.edu',
                'role': 'maintenance',
                'phone': '9876543304',
                'password': 'maintenance123',
            },
            {
                'staff_id': 'ADM001',
                'name': 'Admin User',
                'email': 'admin@hostel.edu',
                'role': 'admin',
                'phone': '9876543305',
                'password': 'admin123',
            },
        ]

        created_students = {}
        created_staff = {}

        for item in students_config:
            try:
                student, created = Student.objects.get_or_create(
                    student_id=item['student_id'],
                    defaults={
                        'name': item['name'],
                        'email': item['email'],
                        'room_number': item['room_number'],
                        'block': item['block'],
                        'phone': item['phone'],
                        'parent_phone': item['parent_phone'],
                        'is_first_login': False,
                    },
                )
                if not created:
                    student.name = item['name']
                    student.email = item['email']
                    student.room_number = item['room_number']
                    student.block = item['block']
                    student.phone = item['phone']
                    student.parent_phone = item['parent_phone']
                    student.is_first_login = False
                student.set_password(item['password'])
                student.save()
                created_students[item['student_id']] = student
                self.stdout.write(
                    self.style.SUCCESS(
                        f"✓ {'Created' if created else 'Updated'} student: {item['email']} / {item['password']}"
                    )
                )
            except Exception as e:
                self.stdout.write(self.style.ERROR(f"✗ Error creating student {item['student_id']}: {e}"))

        for item in staff_config:
            try:
                staff, created = Staff.objects.get_or_create(
                    staff_id=item['staff_id'],
                    defaults={
                        'name': item['name'],
                        'email': item['email'],
                        'role': item['role'],
                        'phone': item['phone'],
                        'is_active': True,
                    },
                )
                if not created:
                    staff.name = item['name']
                    staff.email = item['email']
                    staff.role = item['role']
                    staff.phone = item['phone']
                    staff.is_active = True
                staff.set_password(item['password'])
                staff.save()
                created_staff[item['staff_id']] = staff
                self.stdout.write(
                    self.style.SUCCESS(
                        f"✓ {'Created' if created else 'Updated'} {item['role']}: {item['email']} / {item['password']}"
                    )
                )
            except Exception as e:
                self.stdout.write(self.style.ERROR(f"✗ Error creating staff {item['staff_id']}: {e}"))

        self._seed_maintenance_requests(created_students, created_staff)

        self.stdout.write(self.style.SUCCESS('\n=== Dummy Login Credentials ==='))
        self.stdout.write('Student Login:')
        self.stdout.write('  Email: student@hostel.edu')
        self.stdout.write('  Password: student123')
        self.stdout.write('\nMaintenance Login:')
        self.stdout.write('  Email: maintenance@hostel.edu')
        self.stdout.write('  Password: maintenance123')
        self.stdout.write('\nSecurity Login:')
        self.stdout.write('  Email: security@hostel.edu')
        self.stdout.write('  Password: security123')
        self.stdout.write('\nWarden Login:')
        self.stdout.write('  Email: warden@hostel.edu')
        self.stdout.write('  Password: warden123')
        self.stdout.write('\nAdmin Login:')
        self.stdout.write('  Email: admin@hostel.edu')
        self.stdout.write('  Password: admin123')

    def _seed_maintenance_requests(self, students, staff):
        self.stdout.write('\nCreating dummy maintenance requests...')

        now = timezone.now()
        maintenance_primary = staff.get('MNT001')
        maintenance_secondary = staff.get('MNT002')

        requests_config = [
            {
                'student': students.get('STU001'),
                'room_number': '304',
                'issue_type': 'plumbing',
                'description': 'Major leak in washroom. Water is leaking continuously from the main pipe and is flooding the corridor.',
                'priority': 'high',
                'status': 'pending',
                'notes': 'Reported with urgency by student. Requires immediate inspection.',
                'hours_ago': 2,
            },
            {
                'student': students.get('STU002'),
                'room_number': '112',
                'issue_type': 'electrical',
                'description': 'Fan regulator is broken and the fan is stuck at full speed throughout the night.',
                'priority': 'medium',
                'status': 'pending',
                'notes': 'Electrical line seems stable. Regulator replacement likely needed.',
                'hours_ago': 5,
            },
            {
                'student': students.get('STU003'),
                'room_number': '215',
                'issue_type': 'hvac',
                'description': 'Wi-Fi dead zone near the study area and repeated connectivity drops after evening hours.',
                'priority': 'medium',
                'status': 'in_progress',
                'assigned_to': maintenance_secondary,
                'estimated_completion': now + timezone.timedelta(hours=6),
                'notes': 'Router inspection in progress. Signal extender requested.',
                'hours_ago': 10,
            },
            {
                'student': students.get('STU001'),
                'room_number': '304',
                'issue_type': 'cleaning',
                'description': 'Water seepage has left the corridor slippery and requires a cleaning crew after plumbing fix.',
                'priority': 'low',
                'status': 'assigned',
                'assigned_to': maintenance_primary,
                'estimated_completion': now + timezone.timedelta(hours=12),
                'notes': 'Queued after plumbing repair closes.',
                'hours_ago': 12,
            },
            {
                'student': students.get('STU002'),
                'room_number': '112',
                'issue_type': 'furniture',
                'description': 'Study chair leg is cracked and unstable for daily use.',
                'priority': 'low',
                'status': 'completed',
                'assigned_to': maintenance_primary,
                'actual_completion': now - timezone.timedelta(hours=1),
                'notes': 'Chair replaced from spare inventory.',
                'hours_ago': 30,
            },
        ]

        for item in requests_config:
            student = item.pop('student', None)
            if not student:
                continue

            description = item['description']
            request, created = MaintenanceRequest.objects.get_or_create(
                student=student,
                description=description,
                defaults={
                    'room_number': item['room_number'],
                    'issue_type': item['issue_type'],
                    'priority': item['priority'],
                    'status': item['status'],
                    'assigned_to': item.get('assigned_to'),
                    'estimated_completion': item.get('estimated_completion'),
                    'actual_completion': item.get('actual_completion'),
                    'notes': item.get('notes'),
                    'auto_approved': True,
                },
            )

            if not created:
                request.room_number = item['room_number']
                request.issue_type = item['issue_type']
                request.priority = item['priority']
                request.status = item['status']
                request.assigned_to = item.get('assigned_to')
                request.estimated_completion = item.get('estimated_completion')
                request.actual_completion = item.get('actual_completion')
                request.notes = item.get('notes')
                request.auto_approved = True

            created_at = now - timezone.timedelta(hours=item['hours_ago'])
            request.created_at = created_at
            request.updated_at = created_at + timezone.timedelta(minutes=45)
            request.save()

            self.stdout.write(
                self.style.SUCCESS(
                    f"✓ {'Created' if created else 'Updated'} maintenance request for room {request.room_number} ({request.issue_type})"
                )
            )
