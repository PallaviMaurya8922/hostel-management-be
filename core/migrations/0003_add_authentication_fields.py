# Generated manually for authentication fields

from django.db import migrations, models
from django.contrib.auth.hashers import make_password


def populate_authentication_fields(apps, schema_editor):
    """Populate new authentication fields with proper unique values"""
    Student = apps.get_model('core', 'Student')
    Staff = apps.get_model('core', 'Staff')
    
    # Update students with unique emails and default passwords
    for i, student in enumerate(Student.objects.all()):
        student.email = f"{student.student_id.lower()}@hostel.edu"
        student.password_hash = make_password("123")  # Default password: 123
        student.is_first_login = True
        student.save()
    
    # Update staff with proper emails and passwords
    for staff in Staff.objects.all():
        if not hasattr(staff, 'email') or not staff.email:
            staff.email = f"{staff.staff_id.lower()}@staff.hostel.edu"
        staff.password_hash = make_password("Warden@123")  # Default staff password
        staff.save()


def reverse_authentication_fields(apps, schema_editor):
    """Reverse the authentication field population"""
    pass  # Nothing to reverse for data population


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0002_alter_auditlog_action_type_maintenancerequest'),
    ]

    operations = [
        # Add fields without unique constraint first
        migrations.AddField(
            model_name='student',
            name='email',
            field=models.EmailField(help_text="Student's email address", null=True, blank=True),
        ),
        migrations.AddField(
            model_name='student',
            name='password_hash',
            field=models.CharField(default='pbkdf2_sha256$600000$temp$temp', help_text='Hashed password', max_length=255),
        ),
        migrations.AddField(
            model_name='student',
            name='mobile_number',
            field=models.CharField(blank=True, help_text='Mobile phone number', max_length=15, null=True),
        ),
        migrations.AddField(
            model_name='student',
            name='roll_number',
            field=models.CharField(blank=True, help_text='Roll number (optional)', max_length=20, null=True),
        ),
        migrations.AddField(
            model_name='student',
            name='is_first_login',
            field=models.BooleanField(default=True, help_text='Whether this is the first login'),
        ),
        migrations.AddField(
            model_name='staff',
            name='password_hash',
            field=models.CharField(default='pbkdf2_sha256$600000$temp$temp', help_text='Hashed password', max_length=255),
        ),
        
        # Populate the fields with proper unique values
        migrations.RunPython(populate_authentication_fields, reverse_authentication_fields),
        
        # Now make email fields unique and required
        migrations.AlterField(
            model_name='student',
            name='email',
            field=models.EmailField(help_text="Student's email address", unique=True),
        ),
        migrations.AlterField(
            model_name='staff',
            name='email',
            field=models.EmailField(help_text='Staff email address', unique=True),
        ),
    ]