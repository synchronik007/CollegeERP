from django.urls import path
from rest_framework.routers import DefaultRouter

from .views import (
    AdminAttendanceSessionsView,
    AdminStudentsListView,
    AdminTeachersListView,
    AttendanceSessionCreateView,
    AttendanceSessionRecordsBulkCreateView,
    StudentEnrollmentViewSet,
    StudentSummaryView,
    SubjectStudentsView,
    SubjectViewSet,
    TeacherSubjectAllocationViewSet,
    TeacherSubjectsView,
    StudentEmbeddingPatchView,
    TeacherSubjectSessionsView,
    SessionDetailView,
    StudentDashboardView,
    StudentSubjectAttendanceView,
)
router = DefaultRouter()
router.register(r'attendance/admin/subjects', SubjectViewSet, basename='attendance-subject')
router.register(
    r'attendance/admin/teacher-subject-allocations',
    TeacherSubjectAllocationViewSet,
    basename='attendance-teacher-allocation',
)
router.register(
    r'attendance/admin/student-enrollments',
    StudentEnrollmentViewSet,
    basename='attendance-student-enrollment',
)

urlpatterns = [
    path('attendance/admin/teachers', AdminTeachersListView.as_view(), name='attendance-admin-teachers'),
    path('attendance/admin/students', AdminStudentsListView.as_view(), name='attendance-admin-students'),
    path('attendance/admin/sessions', AdminAttendanceSessionsView.as_view(), name='attendance-admin-sessions'),
    path('teachers/<str:teacher_id>/subjects', TeacherSubjectsView.as_view(), name='teacher-subjects'),
    path('subjects/<int:subject_id>/students', SubjectStudentsView.as_view(), name='subject-students'),
    path('students/<str:student_id>/embedding', StudentEmbeddingPatchView.as_view(), name='student-embedding-patch'),
    path('attendance/sessions', AttendanceSessionCreateView.as_view(), name='attendance-session-create'),
    path(
        'attendance/sessions/<int:session_id>/records',
        AttendanceSessionRecordsBulkCreateView.as_view(),
        name='attendance-session-records-create',
    ),
    path('students/<str:student_id>/summary', StudentSummaryView.as_view(), name='student-summary'),
    path('teachers/<str:teacher_id>/subjects/<int:subject_id>/sessions', TeacherSubjectSessionsView.as_view(), name='teacher-subject-sessions'),
    path('sessions/<int:session_id>', SessionDetailView.as_view(), name='session-detail'),
    path('students/<str:student_id>/dashboard', StudentDashboardView.as_view(), name='student-dashboard'),
    path('students/<str:student_id>/subjects/<int:subject_id>/attendance', StudentSubjectAttendanceView.as_view(), name='student-subject-attendance'),
]

urlpatterns += router.urls
