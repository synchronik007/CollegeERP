import '../../../core/config/app_config.dart';

class StudentProfile {
  const StudentProfile({
    required this.id,
    required this.name,
    this.photoUrl,
    this.embedding,
  });

  final String id;
  final String name;
  final String? photoUrl;
  final List<double>? embedding;

  bool get hasEmbedding => embedding != null && embedding!.isNotEmpty;

  factory StudentProfile.fromJson(Map<String, dynamic> json) {
    List<double>? parsedEmbedding;
    final rawEmbedding = json['face_embedding'] ?? json['embedding'];

    if (rawEmbedding is List) {
      parsedEmbedding = rawEmbedding
          .map((e) => double.tryParse(e.toString()) ?? 0)
          .toList();
    } else if (rawEmbedding is String && rawEmbedding.trim().isNotEmpty) {
      final trimmed = rawEmbedding.replaceAll('[', '').replaceAll(']', '');
      parsedEmbedding = trimmed
          .split(',')
          .map((e) => double.tryParse(e.trim()) ?? 0)
          .toList();
    }

    String? rawPhotoUrl = (json['face_image_url'] ?? json['photo_url'])?.toString();
    if (rawPhotoUrl != null && rawPhotoUrl.isNotEmpty && !rawPhotoUrl.startsWith('http')) {
      rawPhotoUrl = '${AppConfig.baseUrl}$rawPhotoUrl';
    }

    return StudentProfile(
      id: (json['id'] ?? json['student_id'] ?? '').toString(),
      name: (json['name'] ?? json['student_name'] ?? 'Unknown Student').toString(),
      photoUrl: rawPhotoUrl,
      embedding: parsedEmbedding,
    );
  }
}
