import '../models/student_profile.dart';
import 'background_embedding_service.dart';

class LazySyncService {
  LazySyncService({BackgroundEmbeddingService? backgroundService})
      : _backgroundService = backgroundService ?? BackgroundEmbeddingService();

  final BackgroundEmbeddingService _backgroundService;

  /// Syncs missing embeddings by using the background embedding service
  /// which downloads the photo, extracts the face embedding on-device,
  /// and PATCHes it to the backend. Returns the number of students updated.
  Future<int> syncMissingEmbeddings(List<StudentProfile> students) async {
    final missing = students.where((s) => !s.hasEmbedding && s.photoUrl != null && s.photoUrl!.isNotEmpty).toList();
    await _backgroundService.processMissingEmbeddings(students);
    return missing.length;
  }

  void close() {
    // No-op cleanup
  }
}
