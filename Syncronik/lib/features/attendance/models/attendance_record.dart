class AttendanceRecord {
  const AttendanceRecord({
    required this.studentId,
    required this.status,
  });

  final String studentId;
  final String status;

  Map<String, dynamic> toJson() {
    return {
      'student_id': studentId,
      'status': status,
    };
  }
}
