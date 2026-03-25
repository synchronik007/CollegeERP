from django.db import models

from core.models import AuditModel


class SUBJECT(AuditModel):
    SUBJECT_ID = models.AutoField(primary_key=True, db_column='SUBJECT_ID')
    SUBJECT_CODE = models.CharField(max_length=30, unique=True, db_column='SUBJECT_CODE')
    SUBJECT_NAME = models.CharField(max_length=120, db_column='SUBJECT_NAME')
    IS_ACTIVE = models.BooleanField(default=True, db_column='IS_ACTIVE')

    class Meta:
        db_table = 'ATTENDANCE_SUBJECTS'
        verbose_name = 'Subject'
        verbose_name_plural = 'Subjects'

    def __str__(self):
        return f"{self.SUBJECT_CODE} - {self.SUBJECT_NAME}"


class TEACHER_SUBJECT_ALLOCATION(AuditModel):
    ALLOCATION_ID = models.AutoField(primary_key=True, db_column='ALLOCATION_ID')
    TEACHER = models.ForeignKey(
        'accounts.CustomUser',
        to_field='USER_ID',
        on_delete=models.PROTECT,
        db_column='TEACHER_ID',
        related_name='subject_allocations',
    )
    SUBJECT = models.ForeignKey(
        SUBJECT,
        on_delete=models.PROTECT,
        db_column='SUBJECT_ID',
        related_name='teacher_allocations',
    )
    IS_ACTIVE = models.BooleanField(default=True, db_column='IS_ACTIVE')

    class Meta:
        db_table = 'ATTENDANCE_TEACHER_SUBJECT_ALLOCATIONS'
        verbose_name = 'Teacher Subject Allocation'
        verbose_name_plural = 'Teacher Subject Allocations'
        unique_together = ('TEACHER', 'SUBJECT')


class STUDENT_ENROLLMENT(AuditModel):
    ENROLLMENT_ID = models.AutoField(primary_key=True, db_column='ENROLLMENT_ID')
    STUDENT = models.ForeignKey(
        'student.STUDENT_MASTER',
        on_delete=models.PROTECT,
        db_column='STUDENT_ID',
        related_name='subject_enrollments',
    )
    SUBJECT = models.ForeignKey(
        SUBJECT,
        on_delete=models.PROTECT,
        db_column='SUBJECT_ID',
        related_name='student_enrollments',
    )
    IS_ACTIVE = models.BooleanField(default=True, db_column='IS_ACTIVE')

    class Meta:
        db_table = 'ATTENDANCE_STUDENT_ENROLLMENTS'
        verbose_name = 'Student Enrollment'
        verbose_name_plural = 'Student Enrollments'
        unique_together = ('STUDENT', 'SUBJECT')


class ATTENDANCE_SESSION(AuditModel):
    SESSION_ID = models.AutoField(primary_key=True, db_column='SESSION_ID')
    SUBJECT = models.ForeignKey(
        SUBJECT,
        on_delete=models.PROTECT,
        db_column='SUBJECT_ID',
        related_name='sessions',
    )
    TEACHER = models.ForeignKey(
        'accounts.CustomUser',
        to_field='USER_ID',
        on_delete=models.PROTECT,
        db_column='TEACHER_ID',
        related_name='attendance_sessions',
    )
    SESSION_DATE = models.DateField(db_column='SESSION_DATE')
    STARTED_AT = models.DateTimeField(db_column='STARTED_AT')
    CLIENT_REQUEST_ID = models.CharField(max_length=64, unique=True, db_column='CLIENT_REQUEST_ID')

    class Meta:
        db_table = 'ATTENDANCE_SESSIONS'
        verbose_name = 'Attendance Session'
        verbose_name_plural = 'Attendance Sessions'


class ATTENDANCE_RECORD(AuditModel):
    STATUS_CHOICES = (
        ('Present', 'Present'),
        ('Absent', 'Absent'),
    )

    RECORD_ID = models.AutoField(primary_key=True, db_column='RECORD_ID')
    SESSION = models.ForeignKey(
        ATTENDANCE_SESSION,
        on_delete=models.CASCADE,
        db_column='SESSION_ID',
        related_name='records',
    )
    STUDENT = models.ForeignKey(
        'student.STUDENT_MASTER',
        on_delete=models.PROTECT,
        db_column='STUDENT_ID',
        related_name='attendance_records',
    )
    STATUS = models.CharField(max_length=10, choices=STATUS_CHOICES, db_column='STATUS')
    IS_MANUAL_OVERRIDE = models.BooleanField(default=False, db_column='IS_MANUAL_OVERRIDE')

    class Meta:
        db_table = 'ATTENDANCE_RECORDS'
        verbose_name = 'Attendance Record'
        verbose_name_plural = 'Attendance Records'
        unique_together = ('SESSION', 'STUDENT')
