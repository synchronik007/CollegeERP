class StudentSummary {
  const StudentSummary({
    required this.studentId,
    required this.percentage,
    required this.totalClasses,
    required this.presentClasses,
  });

  final String studentId;
  final double percentage;
  final int totalClasses;
  final int presentClasses;

  factory StudentSummary.fromJson(Map<String, dynamic> json) {
    return StudentSummary(
      studentId: (json['student_id'] ?? '').toString(),
      percentage: double.tryParse((json['attendance_percentage'] ?? 0).toString()) ?? 0,
      totalClasses: int.tryParse((json['total_classes'] ?? 0).toString()) ?? 0,
      presentClasses: int.tryParse((json['present_classes'] ?? 0).toString()) ?? 0,
    );
  }
}
