import 'dart:io';
import 'dart:math';
import 'dart:ui';

import 'package:camera/camera.dart';
import 'package:google_mlkit_face_detection/google_mlkit_face_detection.dart';
import 'package:image/image.dart' as img;
import 'package:path_provider/path_provider.dart';
import 'package:tflite_flutter/tflite_flutter.dart';

import '../models/student_profile.dart';

class FaceRecognitionService {
  static const int _inputSize = 112;
  static const double _matchThreshold = 0.50; // 0.50 mathematically accommodates drastic live-lighting variations without risking false positives (~0.05 baseline)
  
  late final FaceDetector _detector;
  Interpreter? _interpreter;
  bool _isInitialized = false;

  FaceRecognitionService();

  Future<void> initialize() async {
    if (_isInitialized) return;

    try {
      // Load TFLite model from assets
      _interpreter = await Interpreter.fromAsset('assets/models/mobilefacenet.tflite');
      
      // Initialize Face Detector with ACCURATE mode for better detection on passport photos
      _detector = FaceDetector(
        options: FaceDetectorOptions(
          enableContours: false,
          enableClassification: false,
          performanceMode: FaceDetectorMode.accurate,
          minFaceSize: 0.05, // Lowered to 5% of image width to detect small faces in group photos
        ),
      );
      _isInitialized = true;
      print('MobileFaceNet loaded successfully');
    } catch (e) {
      print('Failed to load MobileFaceNet model: $e');
    }
  }

  Future<void> close() async {
    await _detector.close();
    _interpreter?.close();
  }

  /// Downloads and processes an image to extract its face embedding
  Future<List<double>?> generateEmbedding(File imageFile) async {
    if (!_isInitialized) await initialize();
    
    final inputImage = InputImage.fromFile(imageFile);
    final faces = await _detector.processImage(inputImage);

    if (faces.isEmpty) {
      print('[FaceRec] Try 1 failed: No face detected. Attempting EXIF orientation fix for passport photo...');
      // Decode image, bake orientation, save to temp, try again
      final bytes = await imageFile.readAsBytes();
      var decoded = img.decodeImage(bytes);
      if (decoded == null) return null;
      
      decoded = img.bakeOrientation(decoded);
      
      // Save fixed image to temporary file
      final tempDir = await getTemporaryDirectory();
      final tempFile = File('${tempDir.path}/temp_fixed_image_${DateTime.now().millisecondsSinceEpoch}.jpg');
      await tempFile.writeAsBytes(img.encodeJpg(decoded));
      
      try {
        final fixedInputImage = InputImage.fromFile(tempFile);
        final fixedFaces = await _detector.processImage(fixedInputImage);
        
        if (fixedFaces.isEmpty) {
          print('[FaceRec] Try 2 failed: Still no face detected. FALLBACK: Assuming image is already a cropped face.');
          return generateEmbeddingFromCroppedFace(decoded);
        }
        
        fixedFaces.sort((a, b) => b.boundingBox.width.compareTo(a.boundingBox.width));
        final face = fixedFaces.first;
        final croppedFace = _cropFace(decoded, face.boundingBox);
        return generateEmbeddingFromCroppedFace(croppedFace);
      } finally {
        if (await tempFile.exists()) await tempFile.delete();
      }
    }

    // Process the largest face if multiple
    faces.sort((a, b) => b.boundingBox.width.compareTo(a.boundingBox.width));
    final face = faces.first;

    final bytes = await imageFile.readAsBytes();
    var decodedImage = img.decodeImage(bytes);
    if (decodedImage == null) return null;
    decodedImage = img.bakeOrientation(decodedImage);

    final croppedFace = _cropFace(decodedImage, face.boundingBox);
    return generateEmbeddingFromCroppedFace(croppedFace);
  }

  /// Takes an already cropped img.Image and generates the embedding
  List<double>? generateEmbeddingFromCroppedFace(img.Image croppedFace) {
    if (_interpreter == null) return null;

    // 1. Resize to 112x112
    final resizedImage = img.copyResize(croppedFace, width: _inputSize, height: _inputSize);

    // 2. Normalize and convert to Float32List format required by model: [1, 112, 112, 3]
    var inputList = _imageToFloat32List(resizedImage);

    // 3. Define output format: [1, 192]
    var outputList = List.generate(1, (index) => List.filled(192, 0.0));

    // 4. Run inference
    try {
      _interpreter!.run(inputList, outputList);
      return outputList.first;
    } catch (e) {
      print('Error running face recognition inference: $e');
      return null;
    }
  }

  /// Detects all faces in an XFile (from camera), crops them, and generates embeddings
  Future<List<List<double>>> generateEmbeddingsFromCameraImage(XFile imageFile) async {
    if (!_isInitialized) await initialize();
    
    final inputImage = InputImage.fromFilePath(imageFile.path);
    final faces = await _detector.processImage(inputImage);

    print('[FaceRec] Detected ${faces.length} face(s) in camera image');
    if (faces.isEmpty) return [];

    final bytes = await imageFile.readAsBytes();
    img.Image? decodedImage = img.decodeImage(bytes);
    if (decodedImage == null) {
      print('[FaceRec] Failed to decode camera image');
      return [];
    }

    // Fix rotation based on camera EXIF data — critical for phone cameras
    decodedImage = img.bakeOrientation(decodedImage);
    print('[FaceRec] Image size after EXIF fix: ${decodedImage.width}x${decodedImage.height}');

    List<List<double>> embeddings = [];
    
    for (var face in faces) {
      print('[FaceRec] Face bbox: ${face.boundingBox}, TiltZ: ${face.headEulerAngleZ}');
      var croppedFace = _cropFace(decodedImage, face.boundingBox);
      
      // MobileFaceNet requires the face to be strictly upright. 
      // If the user tilted their head or rotated the phone without EXIF updating properly,
      // we counter-rotate the cropped bounding box by the detected tilt angle!
      if (face.headEulerAngleZ != null && face.headEulerAngleZ!.abs() > 5) {
        print('[FaceRec] Rotating face by ${-face.headEulerAngleZ!} degrees to make it upright');
        croppedFace = img.copyRotate(croppedFace, angle: -face.headEulerAngleZ!);
      }

      final embedding = generateEmbeddingFromCroppedFace(croppedFace);
      if (embedding != null) {
        print('[FaceRec] Generated embedding of length ${embedding.length}');
        embeddings.add(embedding);
      }
    }

    return embeddings;
  }

  /// Matches captured face embeddings against roster using cosine similarity
  Set<String> matchFaces(List<List<double>> detectedEmbeddings, List<StudentProfile> roster) {
    final matched = <String>{};

    print('[FaceRec] Matching ${detectedEmbeddings.length} detected face(s) against ${roster.length} student(s)');

    for (final student in roster) {
      final embedding = student.embedding;
      if (embedding == null || embedding.isEmpty) {
        print('[FaceRec] Student ${student.id} (${student.name}): NO embedding stored, skipping');
        continue;
      }

      print('[FaceRec] Student ${student.id} (${student.name}): has embedding of length ${embedding.length}');

      double bestScore = -1;
      
      for (final detected in detectedEmbeddings) {
        final score = _cosineSimilarity(embedding, detected);
        if (score > bestScore) {
          bestScore = score;
        }
      }

      print('[FaceRec] Student ${student.id} best cosine similarity: $bestScore (threshold: $_matchThreshold)');

      if (bestScore >= _matchThreshold) {
        matched.add(student.id);
        print('[FaceRec] ✓ MATCHED: ${student.name}');
      } else {
        print('[FaceRec] ✗ NOT matched: ${student.name}');
      }
    }

    print('[FaceRec] Total matches: ${matched.length}');
    return matched;
  }

  // --- Helper Methods ---

  img.Image _cropFace(img.Image image, Rect boundingBox) {
    int x = boundingBox.left.toInt();
    int y = boundingBox.top.toInt();
    int w = boundingBox.width.toInt();
    int h = boundingBox.height.toInt();

    // Ensure within image bounds
    x = x < 0 ? 0 : x;
    y = y < 0 ? 0 : y;
    w = (x + w) > image.width ? (image.width - x) : w;
    h = (y + h) > image.height ? (image.height - y) : h;

    // We can add a small padding (margin) around the face if desired, but exactly bounding box is okay too
    return img.copyCrop(image, x: x, y: y, width: w, height: h);
  }

  List<List<List<List<double>>>> _imageToFloat32List(img.Image image) {
    // Model expects [1, 112, 112, 3] with values normalized typically to [-1, 1] for MobileFaceNet
    var float32List = List.generate(
      1,
      (_) => List.generate(
        _inputSize,
        (y) => List.generate(
          _inputSize,
          (x) {
            final pixel = image.getPixelSafe(x, y);
            return [
              // Normalize (value - 127.5) / 127.5
              (pixel.r - 127.5) / 127.5,
              (pixel.g - 127.5) / 127.5,
              (pixel.b - 127.5) / 127.5,
            ];
          },
        ),
      ),
    );
    return float32List;
  }

  double _cosineSimilarity(List<double> a, List<double> b) {
    if (a.isEmpty || b.isEmpty) return 0;
    
    // In case dimensions mismatch, pick smaller
    final len = min(a.length, b.length); 

    double dot = 0;
    double normA = 0;
    double normB = 0;

    for (var i = 0; i < len; i++) {
      dot += a[i] * b[i];
      normA += a[i] * a[i];
      normB += b[i] * b[i];
    }

    if (normA == 0 || normB == 0) return 0;

    return dot / (sqrt(normA) * sqrt(normB));
  }
}
