class StudentSubjectAttendance {
  const StudentSubjectAttendance({
    required this.sessionId,
    required this.date,
    required this.startedAt,
    required this.status,
    required this.isManualOverride,
  });

  final int sessionId;
  final String date;
  final String startedAt;
  final String status;
  final bool isManualOverride;

  factory StudentSubjectAttendance.fromJson(Map<String, dynamic> json) {
    return StudentSubjectAttendance(
      sessionId: json['session_id'] as int? ?? 0,
      date: (json['date'] ?? '').toString(),
      startedAt: (json['started_at'] ?? '').toString(),
      status: (json['status'] ?? 'Absent').toString(),
      isManualOverride: json['is_manual_override'] as bool? ?? false,
    );
  }
}
