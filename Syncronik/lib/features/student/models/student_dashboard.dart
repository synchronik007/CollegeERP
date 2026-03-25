class StudentDashboardSubject {
  const StudentDashboardSubject({
    required this.subjectId,
    required this.subjectName,
    required this.subjectCode,
    required this.teacherName,
    required this.classesHeld,
    required this.classesAttended,
    required this.attendancePercentage,
  });

  final int subjectId;
  final String subjectName;
  final String subjectCode;
  final String teacherName;
  final int classesHeld;
  final int classesAttended;
  final double attendancePercentage;

  factory StudentDashboardSubject.fromJson(Map<String, dynamic> json) {
    return StudentDashboardSubject(
      subjectId: json['subject_id'] as int? ?? 0,
      subjectName: (json['subject_name'] ?? '').toString(),
      subjectCode: (json['subject_code'] ?? '').toString(),
      teacherName: (json['teacher_name'] ?? 'Unknown').toString(),
      classesHeld: int.tryParse((json['classes_held'] ?? 0).toString()) ?? 0,
      classesAttended: int.tryParse((json['classes_attended'] ?? 0).toString()) ?? 0,
      attendancePercentage: double.tryParse((json['attendance_percentage'] ?? 0).toString()) ?? 0.0,
    );
  }
}

class StudentDashboard {
  const StudentDashboard({
    required this.studentId,
    required this.studentName,
    required this.academicYear,
    required this.branchName,
    required this.semester,
    required this.batch,
    required this.phone,
    required this.email,
    required this.instituteCode,
    required this.faceStatus,
    required this.facePhotosCount,
    required this.overallAttendancePercentage,
    required this.totalPresent,
    required this.totalAbsent,
    required this.subjects,
  });

  final String studentId;
  final String studentName;
  final String academicYear;
  final String branchName;
  final String semester;
  final String batch;
  final String phone;
  final String email;
  final String instituteCode;
  final String faceStatus;
  final int facePhotosCount;
  final double overallAttendancePercentage;
  final int totalPresent;
  final int totalAbsent;
  final List<StudentDashboardSubject> subjects;

  factory StudentDashboard.fromJson(Map<String, dynamic> json) {
    final rawSubjects = json['subjects'] as List? ?? [];
    return StudentDashboard(
      studentId: (json['student_id'] ?? '').toString(),
      studentName: (json['student_name'] ?? '').toString(),
      academicYear: (json['academic_year'] ?? '').toString(),
      branchName: (json['branch_name'] ?? '').toString(),
      semester: (json['semester'] ?? '').toString(),
      batch: (json['batch'] ?? '').toString(),
      phone: (json['phone'] ?? '').toString(),
      email: (json['email'] ?? '').toString(),
      instituteCode: (json['institute_code'] ?? '').toString(),
      faceStatus: (json['face_status'] ?? '').toString(),
      facePhotosCount: int.tryParse((json['face_photos_count'] ?? 0).toString()) ?? 0,
      overallAttendancePercentage: double.tryParse((json['overall_attendance_percentage'] ?? 0).toString()) ?? 0.0,
      totalPresent: int.tryParse((json['total_present'] ?? 0).toString()) ?? 0,
      totalAbsent: int.tryParse((json['total_absent'] ?? 0).toString()) ?? 0,
      subjects: rawSubjects.whereType<Map<String, dynamic>>().map(StudentDashboardSubject.fromJson).toList(),
    );
  }
}
