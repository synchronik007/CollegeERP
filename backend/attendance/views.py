from datetime import datetime

from django.db import transaction
from django.db.models import Count, Q
from rest_framework import status, viewsets
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from accounts.models import CustomUser, BRANCH, SEMESTER
from student.models import STUDENT_MASTER

from .models import (
    ATTENDANCE_RECORD,
    ATTENDANCE_SESSION,
    STUDENT_ENROLLMENT,
    SUBJECT,
    TEACHER_SUBJECT_ALLOCATION,
)
from .serializers import (
    AttendanceRecordBulkItemSerializer,
    AttendanceSessionCreateSerializer,
    StudentEnrollmentSerializer,
    StudentSummarySerializer,
    SubjectSerializer,
    TeacherSubjectAllocationSerializer,
)


def _is_teacher(user):
    designation = getattr(user, 'DESIGNATION', None)
    code = str(getattr(designation, 'CODE', '')).strip().upper()
    name = str(getattr(designation, 'NAME', '')).strip().upper()
    return code in {'TEACHER', 'TEACH', 'FACULTY'} or 'TEACH' in code or 'TEACHER' in name


def _is_student(user):
    code = getattr(getattr(user, 'DESIGNATION', None), 'CODE', '')
    return str(code).upper() == 'STUDENT'


def _is_admin(user):
    code = getattr(getattr(user, 'DESIGNATION', None), 'CODE', '')
    return user.IS_SUPERUSER or str(code).upper() in {'ADMIN', 'SUPERADMIN'}


class SubjectViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    queryset = SUBJECT.objects.filter(IS_DELETED=False)
    serializer_class = SubjectSerializer

    def get_queryset(self):
        if not _is_admin(self.request.user):
            return SUBJECT.objects.none()
        return super().get_queryset()


class TeacherSubjectAllocationViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    queryset = TEACHER_SUBJECT_ALLOCATION.objects.filter(IS_DELETED=False)
    serializer_class = TeacherSubjectAllocationSerializer

    def get_queryset(self):
        if not _is_admin(self.request.user):
            return TEACHER_SUBJECT_ALLOCATION.objects.none()
        return super().get_queryset()


class StudentEnrollmentViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    queryset = STUDENT_ENROLLMENT.objects.filter(IS_DELETED=False)
    serializer_class = StudentEnrollmentSerializer

    def get_queryset(self):
        if not _is_admin(self.request.user):
            return STUDENT_ENROLLMENT.objects.none()
        return super().get_queryset()


class AdminTeachersListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        if not _is_admin(request.user):
            return Response({'message': 'Forbidden'}, status=status.HTTP_403_FORBIDDEN)

        teachers = CustomUser.objects.filter(
            IS_ACTIVE=True,
        ).filter(
            Q(DESIGNATION__CODE__icontains='teach')
            | Q(DESIGNATION__NAME__icontains='teacher')
            | Q(DESIGNATION__CODE__icontains='faculty')
        ).select_related('DESIGNATION')

        data = [
            {
                'user_id': t.USER_ID,
                'name': f"{t.FIRST_NAME} {t.LAST_NAME}".strip() or t.USERNAME,
                'username': t.USERNAME,
            }
            for t in teachers
        ]
        return Response(data)


class AdminStudentsListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        if not _is_admin(request.user):
            return Response({'message': 'Forbidden'}, status=status.HTTP_403_FORBIDDEN)

        query = (request.query_params.get('q') or '').strip()
        students = STUDENT_MASTER.objects.filter(IS_DELETED=False)
        if query:
            students = students.filter(Q(STUDENT_ID__icontains=query) | Q(NAME__icontains=query) | Q(SURNAME__icontains=query))

        students = students.order_by('STUDENT_ID')[:300]
        data = [
            {
                'student_id': s.STUDENT_ID,
                'name': f"{s.NAME} {s.SURNAME}".strip(),
            }
            for s in students
        ]
        return Response(data)


class AdminAttendanceSessionsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        if not _is_admin(request.user):
            return Response({'message': 'Forbidden'}, status=status.HTTP_403_FORBIDDEN)

        subject_id = request.query_params.get('subject_id')
        sessions_qs = ATTENDANCE_SESSION.objects.filter(IS_DELETED=False).select_related('SUBJECT', 'TEACHER')
        if subject_id:
            sessions_qs = sessions_qs.filter(SUBJECT_id=subject_id)

        sessions = sessions_qs.order_by('-SESSION_DATE', '-STARTED_AT')[:200]
        session_ids = [s.SESSION_ID for s in sessions]

        stats = ATTENDANCE_RECORD.objects.filter(SESSION_id__in=session_ids, IS_DELETED=False).values('SESSION_id').annotate(
            total_records=Count('RECORD_ID'),
            present_records=Count('RECORD_ID', filter=Q(STATUS='Present')),
        )
        stats_map = {item['SESSION_id']: item for item in stats}

        payload = []
        for s in sessions:
            stat = stats_map.get(s.SESSION_ID, {})
            payload.append(
                {
                    'session_id': s.SESSION_ID,
                    'subject_id': s.SUBJECT.SUBJECT_ID,
                    'subject_name': s.SUBJECT.SUBJECT_NAME,
                    'teacher_id': s.TEACHER.USER_ID,
                    'teacher_name': f"{s.TEACHER.FIRST_NAME} {s.TEACHER.LAST_NAME}".strip() or s.TEACHER.USERNAME,
                    'session_date': s.SESSION_DATE,
                    'started_at': s.STARTED_AT,
                    'total_records': stat.get('total_records', 0),
                    'present_records': stat.get('present_records', 0),
                }
            )

        return Response(payload)


class TeacherSubjectsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, teacher_id):
        if not (_is_teacher(request.user) or _is_admin(request.user)):
            return Response({'message': 'Forbidden'}, status=status.HTTP_403_FORBIDDEN)

        if not _is_admin(request.user) and str(request.user.USER_ID) != str(teacher_id):
            return Response({'message': 'Forbidden'}, status=status.HTTP_403_FORBIDDEN)

        subject_ids = TEACHER_SUBJECT_ALLOCATION.objects.filter(
            TEACHER_id=teacher_id,
            IS_ACTIVE=True,
            IS_DELETED=False,
        ).values_list('SUBJECT_id', flat=True)

        subjects = SUBJECT.objects.filter(SUBJECT_ID__in=subject_ids, IS_ACTIVE=True, IS_DELETED=False)
        data = [
            {
                'id': s.SUBJECT_ID,
                'subject_id': s.SUBJECT_ID,
                'code': s.SUBJECT_CODE,
                'subject_code': s.SUBJECT_CODE,
                'name': s.SUBJECT_NAME,
                'subject_name': s.SUBJECT_NAME,
            }
            for s in subjects
        ]
        return Response(data)


class SubjectStudentsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, subject_id):
        if not (_is_teacher(request.user) or _is_admin(request.user)):
            return Response({'message': 'Forbidden'}, status=status.HTTP_403_FORBIDDEN)

        if _is_teacher(request.user):
            allocated = TEACHER_SUBJECT_ALLOCATION.objects.filter(
                TEACHER_id=request.user.USER_ID,
                SUBJECT_id=subject_id,
                IS_ACTIVE=True,
                IS_DELETED=False,
            ).exists()
            if not allocated:
                return Response({'message': 'Forbidden'}, status=status.HTTP_403_FORBIDDEN)

        student_ids = STUDENT_ENROLLMENT.objects.filter(
            SUBJECT_id=subject_id,
            IS_ACTIVE=True,
            IS_DELETED=False,
        ).values_list('STUDENT_id', flat=True)

        students = STUDENT_MASTER.objects.filter(
            RECORD_ID__in=student_ids,
            IS_DELETED=False,
        )

        data = [
            {
                'id': s.STUDENT_ID,
                'student_id': s.STUDENT_ID,
                'name': f"{s.NAME} {s.SURNAME}".strip(),
                'student_name': f"{s.NAME} {s.SURNAME}".strip(),
                'face_image_url': getattr(s, 'FACE_IMAGE_URL', None),
                'face_embedding': getattr(s, 'FACE_EMBEDDING', None),
            }
            for s in students
        ]
        return Response(data)


class StudentEmbeddingPatchView(APIView):
    permission_classes = [IsAuthenticated]

    def patch(self, request, student_id):
        # Allow students to save their own embedding, or teachers/admins for any student
        is_own_student = hasattr(request.user, 'USER_ID') and request.user.USER_ID.upper() == student_id.upper()
        if not (is_own_student or _is_teacher(request.user) or _is_admin(request.user)):
            return Response({'message': 'Forbidden'}, status=status.HTTP_403_FORBIDDEN)

        embedding = request.data.get('face_embedding')
        if not isinstance(embedding, list) or len(embedding) == 0:
            return Response({'message': 'face_embedding must be a non-empty list'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            student = STUDENT_MASTER.objects.get(STUDENT_ID=student_id, IS_DELETED=False)
        except STUDENT_MASTER.DoesNotExist:
            return Response({'message': 'Student not found'}, status=status.HTTP_404_NOT_FOUND)

        student.FACE_EMBEDDING = embedding
        student.EMBEDDING_UPDATED_AT = datetime.utcnow()
        student.save(update_fields=['FACE_EMBEDDING', 'EMBEDDING_UPDATED_AT', 'UPDATED_AT'])

        return Response({'status': 'success', 'message': 'Embedding updated'})


class AttendanceSessionCreateView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        if not (_is_teacher(request.user) or _is_admin(request.user)):
            return Response({'message': 'Forbidden'}, status=status.HTTP_403_FORBIDDEN)

        serializer = AttendanceSessionCreateSerializer(data={
            'SUBJECT': request.data.get('subject_id') or request.data.get('SUBJECT'),
            'TEACHER': request.data.get('teacher_id') or request.data.get('TEACHER'),
            'SESSION_DATE': request.data.get('date') or request.data.get('SESSION_DATE'),
            'STARTED_AT': request.data.get('started_at') or request.data.get('STARTED_AT'),
            'CLIENT_REQUEST_ID': request.data.get('client_request_id') or request.data.get('CLIENT_REQUEST_ID'),
        })

        serializer.is_valid(raise_exception=True)

        teacher_id = serializer.validated_data['TEACHER'].USER_ID
        subject_id = serializer.validated_data['SUBJECT'].SUBJECT_ID

        if _is_teacher(request.user) and str(request.user.USER_ID) != str(teacher_id):
            return Response({'message': 'Forbidden'}, status=status.HTTP_403_FORBIDDEN)

        if _is_teacher(request.user):
            allocated = TEACHER_SUBJECT_ALLOCATION.objects.filter(
                TEACHER_id=teacher_id,
                SUBJECT_id=subject_id,
                IS_ACTIVE=True,
                IS_DELETED=False,
            ).exists()
            if not allocated:
                return Response({'message': 'Teacher not allocated to this subject'}, status=status.HTTP_400_BAD_REQUEST)

        client_request_id = serializer.validated_data['CLIENT_REQUEST_ID']
        existing = ATTENDANCE_SESSION.objects.filter(CLIENT_REQUEST_ID=client_request_id).first()
        if existing:
            return Response({'id': existing.SESSION_ID, 'session_id': existing.SESSION_ID, 'message': 'existing'}, status=status.HTTP_200_OK)

        session = serializer.save()
        return Response({'id': session.SESSION_ID, 'session_id': session.SESSION_ID, 'message': 'created'}, status=status.HTTP_201_CREATED)


class AttendanceSessionRecordsBulkCreateView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, session_id):
        if not (_is_teacher(request.user) or _is_admin(request.user)):
            return Response({'message': 'Forbidden'}, status=status.HTTP_403_FORBIDDEN)

        try:
            session = ATTENDANCE_SESSION.objects.get(SESSION_ID=session_id, IS_DELETED=False)
        except ATTENDANCE_SESSION.DoesNotExist:
            return Response({'message': 'Session not found'}, status=status.HTTP_404_NOT_FOUND)

        if _is_teacher(request.user) and str(session.TEACHER.USER_ID) != str(request.user.USER_ID):
            return Response({'message': 'Forbidden'}, status=status.HTTP_403_FORBIDDEN)

        records_data = request.data.get('records', [])
        item_serializer = AttendanceRecordBulkItemSerializer(data=records_data, many=True)
        item_serializer.is_valid(raise_exception=True)

        with transaction.atomic():
            for item in item_serializer.validated_data:
                student = STUDENT_MASTER.objects.filter(STUDENT_ID=item['student_id'], IS_DELETED=False).first()
                if not student:
                    continue
                ATTENDANCE_RECORD.objects.update_or_create(
                    SESSION=session,
                    STUDENT=student,
                    defaults={
                        'STATUS': item['status'],
                        'IS_MANUAL_OVERRIDE': item.get('is_manual_override', False),
                    },
                )

        return Response({'status': 'success', 'message': 'Records saved'})


class StudentSummaryView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, student_id):
        if not (_is_student(request.user) or _is_admin(request.user)):
            return Response({'message': 'Forbidden'}, status=status.HTTP_403_FORBIDDEN)

        if _is_student(request.user) and str(request.user.USER_ID) != str(student_id):
            return Response({'message': 'Forbidden'}, status=status.HTTP_403_FORBIDDEN)

        student = STUDENT_MASTER.objects.filter(STUDENT_ID=student_id, IS_DELETED=False).first()
        if not student:
            return Response({'message': 'Student not found'}, status=status.HTTP_404_NOT_FOUND)

        summary = ATTENDANCE_RECORD.objects.filter(STUDENT=student, IS_DELETED=False).aggregate(
            total_classes=Count('RECORD_ID'),
            present_classes=Count('RECORD_ID', filter=Q(STATUS='Present')),
        )
        total = summary['total_classes'] or 0
        present = summary['present_classes'] or 0
        percentage = (present / total * 100.0) if total else 0.0

        payload = {
            'student_id': student.STUDENT_ID,
            'total_classes': total,
            'present_classes': present,
            'attendance_percentage': round(float(percentage), 2),
        }
        serializer = StudentSummarySerializer(payload)
        return Response(serializer.data)


class TeacherSubjectSessionsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, teacher_id, subject_id):
        if not (_is_teacher(request.user) or _is_admin(request.user)):
            return Response({'message': 'Forbidden'}, status=status.HTTP_403_FORBIDDEN)
            
        sessions = ATTENDANCE_SESSION.objects.filter(
            SUBJECT_id=subject_id, 
            TEACHER_id=teacher_id,
            IS_DELETED=False
        ).order_by('-SESSION_DATE', '-STARTED_AT')

        session_ids = [s.SESSION_ID for s in sessions]
        stats = ATTENDANCE_RECORD.objects.filter(SESSION_id__in=session_ids, IS_DELETED=False).values('SESSION_id').annotate(
            total_records=Count('RECORD_ID'),
            present_records=Count('RECORD_ID', filter=Q(STATUS='Present')),
        )
        stats_map = {item['SESSION_id']: item for item in stats}

        data = []
        for s in sessions:
            stat = stats_map.get(s.SESSION_ID, {})
            data.append({
                'session_id': s.SESSION_ID,
                'session_date': s.SESSION_DATE,
                'started_at': s.STARTED_AT,
                'total_records': stat.get('total_records', 0),
                'present_records': stat.get('present_records', 0),
                'client_request_id': s.CLIENT_REQUEST_ID,
            })
        
        return Response(data)

class SessionDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, session_id):
        if not (_is_teacher(request.user) or _is_admin(request.user)):
            return Response({'message': 'Forbidden'}, status=status.HTTP_403_FORBIDDEN)
            
        try:
            session = ATTENDANCE_SESSION.objects.get(SESSION_ID=session_id, IS_DELETED=False)
        except ATTENDANCE_SESSION.DoesNotExist:
            return Response({'message': 'Session not found'}, status=status.HTTP_404_NOT_FOUND)

        records = ATTENDANCE_RECORD.objects.filter(SESSION=session, IS_DELETED=False).select_related('STUDENT')
        
        records_data = []
        for r in records:
            records_data.append({
                'record_id': r.RECORD_ID,
                'student_id': r.STUDENT.STUDENT_ID,
                'student_name': f"{r.STUDENT.NAME} {r.STUDENT.SURNAME}".strip(),
                'status': r.STATUS,
                'is_manual_override': r.IS_MANUAL_OVERRIDE,
            })

        return Response({
            'session_id': session.SESSION_ID,
            'subject_id': session.SUBJECT_id,
            'session_date': session.SESSION_DATE,
            'started_at': session.STARTED_AT,
            'records': records_data
        })

class StudentDashboardView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, student_id):
        if not (_is_admin(request.user) or str(request.user.USER_ID) == str(student_id)):
            return Response({'message': 'Forbidden'}, status=status.HTTP_403_FORBIDDEN)

        enrollments = STUDENT_ENROLLMENT.objects.filter(
            STUDENT__STUDENT_ID=student_id,
            IS_ACTIVE=True, 
            IS_DELETED=False
        ).select_related('SUBJECT')
        
        subjects_data = []
        for e in enrollments:
            sub = e.SUBJECT
            alloc = TEACHER_SUBJECT_ALLOCATION.objects.filter(
                SUBJECT=sub, IS_ACTIVE=True, IS_DELETED=False
            ).select_related('TEACHER').first()
            teacher_name = f"{alloc.TEACHER.FIRST_NAME} {alloc.TEACHER.LAST_NAME}".strip() if alloc else "Unknown"

            sessions = ATTENDANCE_SESSION.objects.filter(SUBJECT=sub, IS_DELETED=False)
            total_held = sessions.count()
            
            student_records = ATTENDANCE_RECORD.objects.filter(
                SESSION__in=sessions, 
                STUDENT__STUDENT_ID=student_id, 
                IS_DELETED=False
            )
            attended = student_records.filter(STATUS='Present').count()
            
            percentage = (attended / total_held * 100) if total_held > 0 else 0

            subjects_data.append({
                'subject_id': sub.SUBJECT_ID,
                'subject_name': sub.SUBJECT_NAME,
                'subject_code': sub.SUBJECT_CODE,
                'teacher_name': teacher_name,
                'classes_held': total_held,
                'classes_attended': attended,
                'attendance_percentage': round(float(percentage), 2)
            })

        student = STUDENT_MASTER.objects.filter(STUDENT_ID=student_id, IS_DELETED=False).first()
        student_name = f"{student.NAME} {student.SURNAME}".strip() if student else ""
        academic_year = getattr(student, 'ACADEMIC_YEAR', '') if student else ''
        face_status = "Enrolled ✓" if (student and student.FACE_EMBEDDING) else "Not Set Up ⚠️"

        branch_name = student.BRANCH_ID.NAME if student and student.BRANCH_ID else "Unknown"
        semester_name = "Unknown"
        if student and student.YEAR_SEM_ID:
            sem = SEMESTER.objects.filter(SEMESTER_ID=student.YEAR_SEM_ID).first()
            if sem:
                semester_name = sem.SEMESTER

        total_held_overall = 0
        total_attended_overall = 0
        for s in subjects_data:
            total_held_overall += s['classes_held']
            total_attended_overall += s['classes_attended']
        
        overall_percentage = (total_attended_overall / total_held_overall * 100) if total_held_overall > 0 else 0

        return Response({
            'student_id': student_id,
            'student_name': student_name,
            'academic_year': academic_year,
            'branch_name': branch_name,
            'semester': semester_name,
            'batch': student.BATCH if student else "",
            'phone': student.MOB_NO if student else "",
            'email': student.EMAIL_ID if student else "",
            'institute_code': student.INSTITUTE if student else "",
            'face_status': face_status,
            'face_photos_count': 5 if student and student.FACE_EMBEDDING else 0,
            'overall_attendance_percentage': round(float(overall_percentage), 2),
            'total_present': total_attended_overall,
            'total_absent': total_held_overall - total_attended_overall,
            'subjects': subjects_data
        })

class StudentSubjectAttendanceView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, student_id, subject_id):
        if not (_is_admin(request.user) or str(request.user.USER_ID) == str(student_id)):
            return Response({'message': 'Forbidden'}, status=status.HTTP_403_FORBIDDEN)

        records = ATTENDANCE_RECORD.objects.filter(
            STUDENT__STUDENT_ID=student_id,
            SESSION__SUBJECT_id=subject_id,
            IS_DELETED=False
        ).select_related('SESSION').order_by('-SESSION__SESSION_DATE')

        data = []
        for r in records:
            data.append({
                'session_id': r.SESSION.SESSION_ID,
                'date': r.SESSION.SESSION_DATE,
                'started_at': r.SESSION.STARTED_AT,
                'status': r.STATUS,
                'is_manual_override': r.IS_MANUAL_OVERRIDE
            })

        return Response(data)
