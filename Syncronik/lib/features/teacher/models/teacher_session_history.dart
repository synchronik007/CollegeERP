class TeacherSessionHistoryItem {
  const TeacherSessionHistoryItem({
    required this.sessionId,
    required this.sessionDate,
    required this.startedAt,
    required this.totalRecords,
    required this.presentRecords,
    required this.clientRequestId,
  });

  final int sessionId;
  final String sessionDate;
  final String startedAt;
  final int totalRecords;
  final int presentRecords;
  final String clientRequestId;

  factory TeacherSessionHistoryItem.fromJson(Map<String, dynamic> json) {
    return TeacherSessionHistoryItem(
      sessionId: json['session_id'] as int? ?? 0,
      sessionDate: (json['session_date'] ?? '').toString(),
      startedAt: (json['started_at'] ?? '').toString(),
      totalRecords: int.tryParse((json['total_records'] ?? 0).toString()) ?? 0,
      presentRecords: int.tryParse((json['present_records'] ?? 0).toString()) ?? 0,
      clientRequestId: (json['client_request_id'] ?? '').toString(),
    );
  }
}

class SessionDetailRecord {
  const SessionDetailRecord({
    required this.recordId,
    required this.studentId,
    required this.studentName,
    required this.status,
    required this.isManualOverride,
  });

  final int recordId;
  final String studentId;
  final String studentName;
  final String status;
  final bool isManualOverride;

  factory SessionDetailRecord.fromJson(Map<String, dynamic> json) {
    return SessionDetailRecord(
      recordId: json['record_id'] as int? ?? 0,
      studentId: (json['student_id'] ?? '').toString(),
      studentName: (json['student_name'] ?? '').toString(),
      status: (json['status'] ?? 'Absent').toString(),
      isManualOverride: json['is_manual_override'] as bool? ?? false,
    );
  }
}

class SessionDetail {
  const SessionDetail({
    required this.sessionId,
    required this.subjectId,
    required this.sessionDate,
    required this.startedAt,
    required this.records,
  });

  final int sessionId;
  final int subjectId;
  final String sessionDate;
  final String startedAt;
  final List<SessionDetailRecord> records;

  factory SessionDetail.fromJson(Map<String, dynamic> json) {
    final rawRecords = json['records'] as List? ?? [];
    return SessionDetail(
      sessionId: json['session_id'] as int? ?? 0,
      subjectId: json['subject_id'] as int? ?? 0,
      sessionDate: (json['session_date'] ?? '').toString(),
      startedAt: (json['started_at'] ?? '').toString(),
      records: rawRecords.whereType<Map<String, dynamic>>().map(SessionDetailRecord.fromJson).toList(),
    );
  }
}
