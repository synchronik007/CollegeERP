import 'package:camera/camera.dart';

import '../models/student_profile.dart';
import 'face_recognition_service.dart';

class FaceMatchingService {
  FaceMatchingService({FaceRecognitionService? recognitionService}) 
      : _recognitionService = recognitionService ?? FaceRecognitionService();

  final FaceRecognitionService _recognitionService;

  Future<void> initialize() async {
    await _recognitionService.initialize();
  }

  Future<Set<String>> matchCapturedImage(
    XFile imageFile,
    List<StudentProfile> roster,
  ) async {
    final detectedEmbeddings = await _recognitionService.generateEmbeddingsFromCameraImage(imageFile);
    
    if (detectedEmbeddings.isEmpty) {
      return <String>{};
    }

    // Delegate matching logic to the core recognition service
    return _recognitionService.matchFaces(detectedEmbeddings, roster);
  }

  Future<void> close() async {
    await _recognitionService.close();
  }
}
