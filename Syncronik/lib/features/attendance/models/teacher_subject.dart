class TeacherSubject {
  const TeacherSubject({
    required this.id,
    required this.name,
    required this.code,
  });

  final String id;
  final String name;
  final String code;

  factory TeacherSubject.fromJson(Map<String, dynamic> json) {
    return TeacherSubject(
      id: (json['id'] ?? json['subject_id'] ?? '').toString(),
      name: (json['name'] ?? json['subject_name'] ?? 'Unknown Subject').toString(),
      code: (json['code'] ?? json['subject_code'] ?? 'NA').toString(),
    );
  }
}
