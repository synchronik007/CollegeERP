import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')
django.setup()

from student.models import STUDENT_MASTER
from attendance.models import STUDENT_ENROLLMENT, SUBJECT

subject = SUBJECT.objects.first()

if subject:
    print(f"Enrolling in subject: {subject.SUBJECT_NAME}")
    
    for s_id in ['DIPANSHU001', 'TEJAS001']:
        student = STUDENT_MASTER.objects.filter(STUDENT_ID=s_id).first()
        if student:
            enrollment, created = STUDENT_ENROLLMENT.objects.update_or_create(
                STUDENT=student,
                SUBJECT=subject,
                defaults={'IS_ACTIVE': True, 'IS_DELETED': False}
            )
            print(f"Enrolled {s_id} in {subject.SUBJECT_NAME} - Created: {created}")
        else:
            print(f"Student {s_id} not found!")
else:
    print("No subjects found in the database. Please create a subject first.")




