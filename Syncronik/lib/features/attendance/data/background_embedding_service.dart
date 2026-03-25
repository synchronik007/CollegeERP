import 'dart:io';
import 'package:http/http.dart' as http;
import 'package:google_mlkit_face_detection/google_mlkit_face_detection.dart';
import 'package:image/image.dart' as img;
import 'package:path_provider/path_provider.dart';
import '../models/student_profile.dart'; // Add import

class BackgroundEmbeddingService {
  final String baseUrl = 'http://10.0.2.2:8000/api'; // Or your local API IP
  late FaceDetector _faceDetector;

  BackgroundEmbeddingService() {
    _faceDetector = FaceDetector(
      options: FaceDetectorOptions(
        enableContours: false,
        enableLandmarks: false,
      ),
    );
  }

  /// The main loop to process missing students using the StudentProfile model
  Future<void> processMissingEmbeddings(List<StudentProfile> classRoster) async {
    for (var student in classRoster) {
      if (!student.hasEmbedding) {
        if (student.photoUrl != null && student.photoUrl!.isNotEmpty) {
          print('Processing embedding for student: ${student.id}');
          await _processStudent(student.id, student.photoUrl!);
        }
      }
    }
  }

  Future<void> _processStudent(String studentId, String imageUrl) async {
    File? imageFile;
    File? croppedImageFile;
    try {
      // 1. Download Passport Photo
      imageFile = await _downloadImage(imageUrl);
      if (imageFile == null) return;

      // 2. ML Kit finds the face
      final inputImage = InputImage.fromFile(imageFile);
      final faces = await _faceDetector.processImage(inputImage);

      if (faces.isEmpty) {
        print('No face detected remotely for $studentId');
        return;
      }

      // We take the largest bounding box
      final face = faces.first;

      // 3. Crop face strictly
      img.Image? decodedImage = img.decodeImage(imageFile.readAsBytesSync());
      if (decodedImage == null) return;

      int x = face.boundingBox.left.toInt();
      int y = face.boundingBox.top.toInt();
      int w = face.boundingBox.width.toInt();
      int h = face.boundingBox.height.toInt();

      // Ensure bounding box doesn't go outside image boundaries
      x = x < 0 ? 0 : x;
      y = y < 0 ? 0 : y;
      w = (x + w) > decodedImage.width ? (decodedImage.width - x) : w;
      h = (y + h) > decodedImage.height ? (decodedImage.height - y) : h;

      img.Image croppedImage = img.copyCrop(
        decodedImage,
        x: x,
        y: y,
        width: w,
        height: h,
      );

      // Save cropped face locally
      final documentDirectory = await getApplicationDocumentsDirectory();
      croppedImageFile = File('${documentDirectory.path}/cropped_$studentId.jpg');
      await croppedImageFile.writeAsBytes(img.encodeJpg(croppedImage));

      // 4. POST the cropped image to backend API to let it generate the 128 numbers using python `face_recognition`
      await _uploadFaceToBackend(studentId, croppedImageFile);

    } catch (e) {
      print('Failed to process student $studentId: $e');
    } finally {
      // Cleanup temp files
      if (imageFile != null && await imageFile.exists()) await imageFile.delete();
      if (croppedImageFile != null && await croppedImageFile.exists()) await croppedImageFile.delete();
    }
  }

  Future<File?> _downloadImage(String url) async {
    try {
      final formattedUrl = url.startsWith('http') ? url : baseUrl + url;
      final response = await http.get(Uri.parse(formattedUrl));
      if (response.statusCode == 200) {
        final documentDirectory = await getApplicationDocumentsDirectory();
        final file = File('${documentDirectory.path}/temp_${DateTime.now().millisecondsSinceEpoch}.jpg');
        await file.writeAsBytes(response.bodyBytes);
        return file;
      }
    } catch (e) {
      print('Error downloading image: $e');
    }
    return null;
  }

  Future<void> _uploadFaceToBackend(String studentId, File croppedImage) async {
    try {
      final request = http.MultipartRequest(
        'POST',
        Uri.parse('$baseUrl/student/$studentId/generate_embedding/'),
      );
      
      request.files.add(await http.MultipartFile.fromPath(
        'image', 
        croppedImage.path,
      ));

      final streamedResponse = await request.send();
      final response = await http.Response.fromStream(streamedResponse);

      if (response.statusCode == 200) {
        print('Successfully generated embedding for $studentId via Backend');
      } else {
        print('Failed to generate embedding for $studentId. Backend Status: ${response.statusCode}, Body: ${response.body}');
      }
    } catch (e) {
      print('Error sending image to backend: $e');
    }
  }
}

