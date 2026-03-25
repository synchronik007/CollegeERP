import 'package:intl/intl.dart';
import 'package:uuid/uuid.dart';

import '../../../core/config/app_config.dart';
import '../../../core/network/api_client.dart';
import '../../../core/network/api_client_provider.dart';
import '../models/attendance_record.dart';
import '../models/student_profile.dart';
import '../models/teacher_subject.dart';
import '../../student/models/student_dashboard.dart';
import '../../student/models/student_subject_attendance.dart';
import '../../teacher/models/teacher_session_history.dart';

class AttendanceService {
  AttendanceService({ApiClient? apiClient}) : _apiClient = apiClient ?? appApiClient;

  final ApiClient _apiClient;

  Future<List<TeacherSubject>> getTeacherSubjects(String teacherId) async {
    try {
      final list = await _apiClient.getJsonList('/api/teachers/$teacherId/subjects');
      return list
          .whereType<Map<String, dynamic>>()
          .map(TeacherSubject.fromJson)
          .toList();
    } catch (_) {
      if (!AppConfig.enableMockFallback) rethrow;
      return const [
        TeacherSubject(id: '101', name: 'Data Structures', code: 'CS301'),
        TeacherSubject(id: '102', name: 'Physics', code: 'PH201'),
      ];
    }
  }

  Future<List<StudentProfile>> getSubjectStudents(String subjectId) async {
    try {
      final list = await _apiClient.getJsonList('/api/subjects/$subjectId/students');
      return list
          .whereType<Map<String, dynamic>>()
          .map(StudentProfile.fromJson)
          .toList();
    } catch (_) {
      if (!AppConfig.enableMockFallback) rethrow;
      return const [
        StudentProfile(id: '1', name: 'Sarah Khan'),
        StudentProfile(id: '2', name: 'John Patil'),
        StudentProfile(id: '3', name: 'Riya Sharma'),
      ];
    }
  }

  Future<void> patchStudentEmbedding(String studentId, List<double> embedding) async {
    final encodedId = Uri.encodeComponent(studentId);
    await _apiClient.patchJson(
      '/api/students/$encodedId/embedding',
      body: {'face_embedding': embedding},
    );
  }

  Future<String> createAttendanceSession({
    required String teacherId,
    required String subjectId,
    String? clientRequestId,
  }) async {
    final now = DateTime.now();
    final payload = {
      'teacher_id': teacherId,
      'subject_id': subjectId,
      'date': DateFormat('yyyy-MM-dd').format(now),
      'started_at': now.toIso8601String(),
      'client_request_id': clientRequestId ?? const Uuid().v4(),
    };

    try {
      final response = await _apiClient.postJson(
        '/api/attendance/sessions',
        body: payload,
      );
      return (response['id'] ?? response['session_id'] ?? '').toString();
    } catch (_) {
      if (!AppConfig.enableMockFallback) rethrow;
      return DateTime.now().millisecondsSinceEpoch.toString();
    }
  }

  Future<void> submitAttendanceRecords({
    required String sessionId,
    required List<AttendanceRecord> records,
  }) async {
    await _apiClient.postJson(
      '/api/attendance/sessions/$sessionId/records',
      body: {
        'records': records.map((e) => e.toJson()).toList(),
      },
    );
  }

  Future<StudentDashboard> getStudentDashboard(String studentId) async {
    try {
      final response = await _apiClient.getJson('/api/students/${Uri.encodeComponent(studentId)}/dashboard');
      return StudentDashboard.fromJson(response);
    } catch (_) {
      if (!AppConfig.enableMockFallback) rethrow;
      return const StudentDashboard(
        studentId: 'MOCK_ID',
        studentName: 'Mock Student Specialist',
        academicYear: '2025-26',
        branchName: 'AI & Data Science',
        semester: 'V',
        batch: '2023-2027',
        phone: '+91 9876543210',
        email: 'mock.student@college.edu',
        instituteCode: 'INST-001',
        faceStatus: 'Enrolled ✓',
        facePhotosCount: 5,
        overallAttendancePercentage: 82.5,
        totalPresent: 165,
        totalAbsent: 35,
        subjects: [],
      );
    }
  }

  Future<List<StudentSubjectAttendance>> getStudentSubjectAttendance(String studentId, int subjectId) async {
    try {
      final list = await _apiClient.getJsonList('/api/students/${Uri.encodeComponent(studentId)}/subjects/$subjectId/attendance');
      return list
          .whereType<Map<String, dynamic>>()
          .map(StudentSubjectAttendance.fromJson)
          .toList();
    } catch (_) {
      if (!AppConfig.enableMockFallback) rethrow;
      return [];
    }
  }

  Future<List<TeacherSessionHistoryItem>> getTeacherSessionHistory(String teacherId, int subjectId) async {
    try {
      final list = await _apiClient.getJsonList('/api/teachers/${Uri.encodeComponent(teacherId)}/subjects/$subjectId/sessions');
      return list
          .whereType<Map<String, dynamic>>()
          .map(TeacherSessionHistoryItem.fromJson)
          .toList();
    } catch (_) {
      if (!AppConfig.enableMockFallback) rethrow;
      return [];
    }
  }

  Future<SessionDetail> getSessionDetail(int sessionId) async {
    try {
      final response = await _apiClient.getJson('/api/sessions/$sessionId');
      return SessionDetail.fromJson(response);
    } catch (_) {
      rethrow;
    }
  }
}

