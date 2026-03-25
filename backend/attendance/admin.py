from django.contrib import admin

from .models import (
    ATTENDANCE_RECORD,
    ATTENDANCE_SESSION,
    STUDENT_ENROLLMENT,
    SUBJECT,
    TEACHER_SUBJECT_ALLOCATION,
)


@admin.register(SUBJECT)
class SubjectAdmin(admin.ModelAdmin):
    list_display = ('SUBJECT_ID', 'SUBJECT_CODE', 'SUBJECT_NAME', 'IS_ACTIVE')
    search_fields = ('SUBJECT_CODE', 'SUBJECT_NAME')


@admin.register(TEACHER_SUBJECT_ALLOCATION)
class TeacherSubjectAllocationAdmin(admin.ModelAdmin):
    list_display = ('ALLOCATION_ID', 'TEACHER', 'SUBJECT', 'IS_ACTIVE')
    list_filter = ('IS_ACTIVE',)


@admin.register(STUDENT_ENROLLMENT)
class StudentEnrollmentAdmin(admin.ModelAdmin):
    list_display = ('ENROLLMENT_ID', 'STUDENT', 'SUBJECT', 'IS_ACTIVE')
    list_filter = ('IS_ACTIVE',)


@admin.register(ATTENDANCE_SESSION)
class AttendanceSessionAdmin(admin.ModelAdmin):
    list_display = ('SESSION_ID', 'SUBJECT', 'TEACHER', 'SESSION_DATE', 'STARTED_AT')
    search_fields = ('CLIENT_REQUEST_ID',)


@admin.register(ATTENDANCE_RECORD)
class AttendanceRecordAdmin(admin.ModelAdmin):
    list_display = ('RECORD_ID', 'SESSION', 'STUDENT', 'STATUS', 'IS_MANUAL_OVERRIDE')
    list_filter = ('STATUS', 'IS_MANUAL_OVERRIDE')
