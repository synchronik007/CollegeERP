from rest_framework import serializers
from accounts.models import CustomUser
from student.models import STUDENT_MASTER

from .models import (
    ATTENDANCE_RECORD,
    ATTENDANCE_SESSION,
    STUDENT_ENROLLMENT,
    SUBJECT,
    TEACHER_SUBJECT_ALLOCATION,
)


class SubjectSerializer(serializers.ModelSerializer):
    class Meta:
        model = SUBJECT
        fields = ('SUBJECT_ID', 'SUBJECT_CODE', 'SUBJECT_NAME', 'IS_ACTIVE')


class TeacherSubjectAllocationSerializer(serializers.ModelSerializer):
    teacher_id = serializers.CharField(source='TEACHER.USER_ID', read_only=True)
    teacher_name = serializers.SerializerMethodField()
    subject_id = serializers.IntegerField(source='SUBJECT.SUBJECT_ID', read_only=True)
    subject_name = serializers.CharField(source='SUBJECT.SUBJECT_NAME', read_only=True)

    TEACHER = serializers.SlugRelatedField(
        slug_field='USER_ID',
        queryset=CustomUser.objects.filter(IS_ACTIVE=True),
    )

    class Meta:
        model = TEACHER_SUBJECT_ALLOCATION
        fields = (
            'ALLOCATION_ID',
            'TEACHER',
            'SUBJECT',
            'IS_ACTIVE',
            'teacher_id',
            'teacher_name',
            'subject_id',
            'subject_name',
        )

    def get_teacher_name(self, obj):
        full_name = f"{obj.TEACHER.FIRST_NAME} {obj.TEACHER.LAST_NAME}".strip()
        return full_name or obj.TEACHER.USERNAME


class StudentEnrollmentSerializer(serializers.ModelSerializer):
    student_id = serializers.CharField(source='STUDENT.STUDENT_ID', read_only=True)
    student_name = serializers.SerializerMethodField()
    subject_id = serializers.IntegerField(source='SUBJECT.SUBJECT_ID', read_only=True)
    subject_name = serializers.CharField(source='SUBJECT.SUBJECT_NAME', read_only=True)

    STUDENT = serializers.SlugRelatedField(
        slug_field='STUDENT_ID',
        queryset=STUDENT_MASTER.objects.filter(IS_DELETED=False),
    )

    class Meta:
        model = STUDENT_ENROLLMENT
        fields = (
            'ENROLLMENT_ID',
            'STUDENT',
            'SUBJECT',
            'IS_ACTIVE',
            'student_id',
            'student_name',
            'subject_id',
            'subject_name',
        )

    def get_student_name(self, obj):
        return f"{obj.STUDENT.NAME} {obj.STUDENT.SURNAME}".strip()


class AttendanceSessionCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = ATTENDANCE_SESSION
        fields = ('SESSION_ID', 'SUBJECT', 'TEACHER', 'SESSION_DATE', 'STARTED_AT', 'CLIENT_REQUEST_ID')


class AttendanceRecordCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = ATTENDANCE_RECORD
        fields = ('RECORD_ID', 'SESSION', 'STUDENT', 'STATUS', 'IS_MANUAL_OVERRIDE')


class AttendanceRecordBulkItemSerializer(serializers.Serializer):
    student_id = serializers.CharField()
    status = serializers.ChoiceField(choices=['Present', 'Absent'])
    is_manual_override = serializers.BooleanField(required=False, default=False)


class StudentSummarySerializer(serializers.Serializer):
    student_id = serializers.CharField()
    total_classes = serializers.IntegerField()
    present_classes = serializers.IntegerField()
    attendance_percentage = serializers.FloatField()
