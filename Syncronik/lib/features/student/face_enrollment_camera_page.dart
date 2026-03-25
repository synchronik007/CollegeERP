
import 'package:camera/camera.dart';
import 'package:flutter/material.dart';
import '../attendance/data/attendance_service.dart';
import '../attendance/data/face_recognition_service.dart';

class FaceEnrollmentCameraPage extends StatefulWidget {
  const FaceEnrollmentCameraPage({super.key, required this.studentId});
  final String studentId;

  @override
  State<FaceEnrollmentCameraPage> createState() => _FaceEnrollmentCameraPageState();
}

class _FaceEnrollmentCameraPageState extends State<FaceEnrollmentCameraPage> {
  CameraController? _cameraController;
  final FaceRecognitionService _faceService = FaceRecognitionService();
  final AttendanceService _attendanceService = AttendanceService();

  final List<List<double>> _capturedEmbeddings = [];
  bool _isInitializing = true;
  bool _isProcessing = false;
  bool _showCamera = false;
  String? _error;

  int _currentStep = 0;
  final List<String> _angles = ['Look straight at camera', 'Turn slightly left', 'Turn slightly right', 'Tilt head slightly up', 'Tilt head slightly down'];
  final List<String> _slotLabels = ['Front', 'Left', 'Right', 'Up', 'Down'];

  @override
  void initState() {
    super.initState();
    _initializeML();
  }

  Future<void> _initializeML() async {
    try {
      await _faceService.initialize();
      if (mounted) setState(() => _isInitializing = false);
    } catch (e) {
      if (mounted) setState(() { _error = 'ML init failed: $e'; _isInitializing = false; });
    }
  }

  Future<void> _initCamera() async {
    try {
      if (_cameraController != null) {
        try { await _cameraController!.pausePreview(); } catch (_) {}
        await _cameraController!.dispose();
        _cameraController = null;
      }

      final cameras = await availableCameras();
      final front = cameras.firstWhere(
        (c) => c.lensDirection == CameraLensDirection.front,
        orElse: () => cameras.first,
      );
      _cameraController = CameraController(
        front, ResolutionPreset.max,
        enableAudio: false,
      );
      await _cameraController!.initialize();
      
      // Explicitly turn off flash to prevent Xiaomi HAL crashes
      try {
        await _cameraController!.setFlashMode(FlashMode.off);
      } catch (_) {}

      // Wait for camera hardware to fully spin up
      await Future.delayed(const Duration(milliseconds: 500));
      if (mounted) setState(() => _showCamera = true);
    } catch (e) {
      if (mounted) setState(() => _error = 'Camera error: $e');
    }
  }

  Future<void> _captureAndProcess() async {
    if (_isProcessing || _cameraController == null || !_cameraController!.value.isInitialized) return;
    setState(() { _isProcessing = true; _error = null; });

    try {
      // Small delay prevents rapid HAL crashes on Android Xiaomi devices
      await Future.delayed(const Duration(milliseconds: 500));
      
      final file = await _cameraController!.takePicture();
      
      // Give the hardware time to recover the live feed after dumping the buffer
      await Future.delayed(const Duration(milliseconds: 200));
      final embeddings = await _faceService.generateEmbeddingsFromCameraImage(file);

      if (embeddings.isEmpty) throw Exception('No face detected. Ensure good lighting and face the camera.');
      if (embeddings.length > 1) throw Exception('Multiple faces detected. Please be alone in frame.');

      _capturedEmbeddings.add(embeddings.first);

      if (_currentStep < 4) {
        setState(() { _currentStep++; _isProcessing = false; });
      } else {
        await _finalizeEnrollment();
      }
    } catch (e) {
      setState(() {
        _error = e.toString().replaceFirst('Exception: ', '');
        _isProcessing = false;
      });
    }
  }

  Future<void> _finalizeEnrollment() async {
    try {
      final List<double> avg = List.filled(192, 0.0);
      for (final emb in _capturedEmbeddings) {
        for (int i = 0; i < 192; i++) {
          avg[i] += emb[i] / _capturedEmbeddings.length;
        }
      }
      await _attendanceService.patchStudentEmbedding(widget.studentId, avg);
      if (!mounted) return;
      _showSuccessScreen();
    } catch (e) {
      setState(() { _error = 'Save failed: $e'; _isProcessing = false; });
      if (_capturedEmbeddings.isNotEmpty) _capturedEmbeddings.removeLast();
    }
  }

  void _showSuccessScreen() async {
    // CRITICAL: Remove CameraPreview from widget tree FIRST,
    // then wait one frame for Flutter to rebuild without it,
    // only THEN dispose the controller safely.
    if (mounted) setState(() => _showCamera = false);
    await Future.delayed(const Duration(milliseconds: 100));

    if (_cameraController != null) {
      try { await _cameraController!.dispose(); } catch (_) {}
      _cameraController = null;
    }
    if (!mounted) return;
    Navigator.pushReplacement(context, MaterialPageRoute(
      builder: (ctx) => _SuccessScreen(onDone: () => Navigator.pop(ctx)),
    ));
  }

  @override
  void dispose() {
    // Set to null first so no widget can reference it during teardown
    final ctrl = _cameraController;
    _cameraController = null;
    ctrl?.dispose();
    _faceService.close();
    super.dispose();
  }

  // ========== MANAGE FACE ID SCREEN ==========
  Widget _buildManageScreen() {
    return Scaffold(
      backgroundColor: const Color(0xFF0D1B2E),
      body: SafeArea(
        child: Column(
          children: [
            // Back button
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
              child: Row(
                children: [
                  GestureDetector(
                    onTap: () => Navigator.pop(context),
                    child: const Row(
                      children: [
                        Icon(Icons.arrow_back_ios, size: 16, color: Color(0xFF4FC3A1)),
                        SizedBox(width: 4),
                        Text('Face ID', style: TextStyle(fontSize: 14, color: Color(0xFF4FC3A1))),
                      ],
                    ),
                  ),
                ],
              ),
            ),
            Expanded(
              child: ListView(
                padding: const EdgeInsets.symmetric(horizontal: 16),
                children: [
                  const Text('Manage Face ID', style: TextStyle(fontSize: 22, fontWeight: FontWeight.w500, color: Color(0xFFE8F0F8))),
                  const SizedBox(height: 4),
                  const Text('More angles = better recognition accuracy', style: TextStyle(fontSize: 12, color: Color(0xFF7A93AB))),
                  const SizedBox(height: 20),

                  // Status card
                  Container(
                    padding: const EdgeInsets.all(16),
                    decoration: BoxDecoration(
                      color: const Color(0xFF132236),
                      borderRadius: BorderRadius.circular(16),
                      border: Border.all(color: const Color(0xFF1E3248)),
                    ),
                    child: Column(
                      children: [
                        Row(
                          children: [
                            const Text('📸', style: TextStyle(fontSize: 28)),
                            const SizedBox(width: 12),
                            Column(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              children: [
                                Text('${_capturedEmbeddings.length} of 5 slots used', style: const TextStyle(fontSize: 15, fontWeight: FontWeight.w500, color: Color(0xFFE8F0F8))),
                                Text('Add ${5 - _capturedEmbeddings.length} more photos for best results', style: const TextStyle(fontSize: 12, color: Color(0xFF7A93AB))),
                              ],
                            ),
                          ],
                        ),
                        const SizedBox(height: 14),
                        // Progress bar
                        Container(
                          height: 6,
                          decoration: BoxDecoration(
                            color: const Color(0xFF1A2A3A),
                            borderRadius: BorderRadius.circular(8),
                          ),
                          child: FractionallySizedBox(
                            widthFactor: _capturedEmbeddings.length / 5,
                            alignment: Alignment.centerLeft,
                            child: Container(
                              decoration: BoxDecoration(
                                color: const Color(0xFF4FC3A1),
                                borderRadius: BorderRadius.circular(8),
                              ),
                            ),
                          ),
                        ),
                        const SizedBox(height: 6),
                        Row(
                          mainAxisAlignment: MainAxisAlignment.spaceBetween,
                          children: [
                            const Text('0', style: TextStyle(fontSize: 11, color: Color(0xFF4A6278))),
                            const Text('Recommended: 5 photos', style: TextStyle(fontSize: 11, color: Color(0xFF4FC3A1))),
                          ],
                        ),
                      ],
                    ),
                  ),
                  const SizedBox(height: 20),

                  // Photo slots
                  const Padding(
                    padding: EdgeInsets.only(bottom: 10),
                    child: Text('YOUR PHOTOS', style: TextStyle(fontSize: 11, color: Color(0xFF7A93AB), fontWeight: FontWeight.w500, letterSpacing: 0.8)),
                  ),
                  Row(
                    children: List.generate(5, (i) {
                      final filled = i < _capturedEmbeddings.length;
                      return Expanded(
                        child: Container(
                          margin: EdgeInsets.only(right: i < 4 ? 8 : 0),
                          height: 64,
                          decoration: BoxDecoration(
                            borderRadius: BorderRadius.circular(10),
                            color: filled ? const Color(0xFF0E2E1E) : const Color(0xFF1A2A3A),
                            border: Border.all(
                              color: filled ? const Color(0xFF2A5E3A) : const Color(0xFF2A4A60),
                              width: 1.5,
                              strokeAlign: BorderSide.strokeAlignInside,
                            ),
                          ),
                          child: Column(
                            mainAxisAlignment: MainAxisAlignment.center,
                            children: [
                              filled
                                ? const Icon(Icons.person, size: 20, color: Color(0xFF4FC3A1))
                                : const Text('+', style: TextStyle(fontSize: 20, color: Color(0xFF4A6278))),
                              const SizedBox(height: 4),
                              Text(_slotLabels[i], style: TextStyle(fontSize: 10, color: filled ? const Color(0xFF4FC3A1) : const Color(0xFF4A6278))),
                            ],
                          ),
                        ),
                      );
                    }),
                  ),
                  const SizedBox(height: 20),

                  // Tips
                  const Padding(
                    padding: EdgeInsets.only(bottom: 8),
                    child: Text('TIPS FOR BETTER ACCURACY', style: TextStyle(fontSize: 11, color: Color(0xFF7A93AB), fontWeight: FontWeight.w500, letterSpacing: 0.8)),
                  ),
                  Container(
                    padding: const EdgeInsets.all(16),
                    decoration: BoxDecoration(
                      color: const Color(0xFF132236),
                      borderRadius: BorderRadius.circular(16),
                      border: Border.all(color: const Color(0xFF1E3248)),
                    ),
                    child: const Column(
                      children: [
                        _TipRow(icon: '✓', text: 'Good lighting — face the light source', color: Color(0xFF4FC3A1)),
                        SizedBox(height: 10),
                        _TipRow(icon: '✓', text: 'Remove glasses if possible', color: Color(0xFF4FC3A1)),
                        SizedBox(height: 10),
                        _TipRow(icon: '✓', text: 'Neutral expression, eyes open', color: Color(0xFF4FC3A1)),
                        SizedBox(height: 10),
                        _TipRow(icon: '✗', text: 'Avoid dark backgrounds or masks', color: Color(0xFFF07070)),
                      ],
                    ),
                  ),
                  const SizedBox(height: 16),

                  // Add photos button
                  SizedBox(
                    width: double.infinity,
                    child: ElevatedButton(
                      onPressed: _isInitializing ? null : () {
                        _initCamera();
                      },
                      style: ElevatedButton.styleFrom(
                        backgroundColor: const Color(0xFF4FC3A1),
                        foregroundColor: const Color(0xFF0A1F14),
                        padding: const EdgeInsets.symmetric(vertical: 14),
                        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(14)),
                      ),
                      child: const Text('+ Add Photos', style: TextStyle(fontSize: 15, fontWeight: FontWeight.w500)),
                    ),
                  ),
                  const SizedBox(height: 16),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }

  // ========== CAMERA CAPTURE SCREEN ==========
  Widget _buildCameraScreen() {
    return Scaffold(
      backgroundColor: const Color(0xFF060E18),
      body: SafeArea(
        child: Column(
          children: [
            // Cancel button
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
              child: Row(
                children: [
                  GestureDetector(
                    onTap: () async {
                      // Remove CameraPreview from widget tree first
                      if (mounted) setState(() => _showCamera = false);
                      await Future.delayed(const Duration(milliseconds: 100));
                      if (_cameraController != null) {
                        try { await _cameraController!.dispose(); } catch (_) {}
                        _cameraController = null;
                      }
                    },
                    child: const Row(
                      children: [
                        Icon(Icons.arrow_back_ios, size: 16, color: Color(0xFF4FC3A1)),
                        SizedBox(width: 4),
                        Text('Cancel', style: TextStyle(fontSize: 14, color: Color(0xFF4FC3A1))),
                      ],
                    ),
                  ),
                ],
              ),
            ),

            // Camera view
            Expanded(
              child: Column(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  // Angle label
                  Text(_angles[_currentStep], style: const TextStyle(fontSize: 14, fontWeight: FontWeight.w500, color: Color(0xFFE8F0F8))),
                  const SizedBox(height: 4),
                  Text('Photo ${_currentStep + 1} of 5', style: const TextStyle(fontSize: 12, color: Color(0xFF7A93AB))),
                  const SizedBox(height: 20),

                  // Face guide with camera preview
                  SizedBox(
                    width: 200,
                    height: 240,
                    child: Stack(
                      alignment: Alignment.center,
                      children: [
                        if (_cameraController != null && _cameraController!.value.isInitialized)
                          ClipOval(
                            child: SizedBox(
                              width: 180,
                              height: 220,
                              child: CameraPreview(_cameraController!),
                            ),
                          ),
                        // Face guide border
                        Container(
                          width: 180,
                          height: 220,
                          decoration: BoxDecoration(
                            borderRadius: BorderRadius.circular(90),
                            border: Border.all(color: const Color(0xFF4FC3A1), width: 2),
                          ),
                        ),
                        // Corner guides
                        Positioned(top: 8, left: 8, child: _corner(true, true)),
                        Positioned(top: 8, right: 8, child: _corner(true, false)),
                        Positioned(bottom: 8, left: 8, child: _corner(false, true)),
                        Positioned(bottom: 8, right: 8, child: _corner(false, false)),
                        if (_isProcessing) const CircularProgressIndicator(color: Color(0xFF4FC3A1)),
                      ],
                    ),
                  ),
                  const SizedBox(height: 20),

                  // Angle dots
                  Row(
                    mainAxisAlignment: MainAxisAlignment.center,
                    children: List.generate(5, (i) {
                      final done = i < _currentStep;
                      final active = i == _currentStep;
                      return Container(
                        width: 10, height: 10,
                        margin: const EdgeInsets.symmetric(horizontal: 4),
                        decoration: BoxDecoration(
                          shape: BoxShape.circle,
                          color: done ? const Color(0xFF4FC3A1) : active ? const Color(0xFFE8B84B) : const Color(0xFF1E3248),
                          border: Border.all(color: done ? const Color(0xFF4FC3A1) : active ? const Color(0xFFE8B84B) : const Color(0xFF2A4A60), width: 1.5),
                        ),
                      );
                    }),
                  ),
                  const SizedBox(height: 8),
                  Row(
                    mainAxisAlignment: MainAxisAlignment.center,
                    children: _slotLabels.map((l) => Padding(
                      padding: const EdgeInsets.symmetric(horizontal: 8),
                      child: Text(l, style: const TextStyle(fontSize: 10, color: Color(0xFF4A6278))),
                    )).toList(),
                  ),
                ],
              ),
            ),

            // Capture button
            if (_error != null)
              Padding(
                padding: const EdgeInsets.symmetric(horizontal: 24),
                child: Text(_error!, style: const TextStyle(fontSize: 12, color: Color(0xFFF07070)), textAlign: TextAlign.center),
              ),
            Padding(
              padding: const EdgeInsets.all(20),
              child: Column(
                children: [
                  GestureDetector(
                    onTap: _isProcessing ? null : _captureAndProcess,
                    child: Container(
                      width: 64, height: 64,
                      decoration: BoxDecoration(
                        shape: BoxShape.circle,
                        color: const Color(0xFF4FC3A1),
                        border: Border.all(color: const Color(0xFF0D1B2E), width: 3),
                        boxShadow: [BoxShadow(color: const Color(0xFF4FC3A1).withOpacity(0.3), blurRadius: 12)],
                      ),
                      child: const Center(child: Icon(Icons.circle, size: 22, color: Color(0xFF0D1B2E))),
                    ),
                  ),
                  const SizedBox(height: 12),
                  const Text('Tap to capture • Auto-detects face', style: TextStyle(fontSize: 12, color: Color(0xFF4A6278))),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _corner(bool top, bool left) {
    return Container(
      width: 20, height: 20,
      decoration: BoxDecoration(
        border: Border(
          top: top ? const BorderSide(color: Color(0xFF4FC3A1), width: 3) : BorderSide.none,
          bottom: !top ? const BorderSide(color: Color(0xFF4FC3A1), width: 3) : BorderSide.none,
          left: left ? const BorderSide(color: Color(0xFF4FC3A1), width: 3) : BorderSide.none,
          right: !left ? const BorderSide(color: Color(0xFF4FC3A1), width: 3) : BorderSide.none,
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    if (_isInitializing) {
      return const Scaffold(
        backgroundColor: Color(0xFF0D1B2E),
        body: Center(child: CircularProgressIndicator(color: Color(0xFF4FC3A1))),
      );
    }
    return _showCamera ? _buildCameraScreen() : _buildManageScreen();
  }
}

// ========== SUCCESS SCREEN ==========
class _SuccessScreen extends StatelessWidget {
  final VoidCallback onDone;
  const _SuccessScreen({required this.onDone});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFF0D1B2E),
      body: Center(
        child: Padding(
          padding: const EdgeInsets.all(32),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Container(
                width: 80, height: 80,
                decoration: BoxDecoration(
                  shape: BoxShape.circle,
                  color: const Color(0xFF0E2E1E),
                  border: Border.all(color: const Color(0xFF4FC3A1), width: 2),
                ),
                child: const Center(child: Text('✓', style: TextStyle(fontSize: 36, color: Color(0xFF4FC3A1)))),
              ),
              const SizedBox(height: 20),
              const Text('Face ID Updated!', style: TextStyle(fontSize: 20, fontWeight: FontWeight.w500, color: Color(0xFFE8F0F8))),
              const SizedBox(height: 10),
              const Text(
                'Your 5 photos have been enrolled. Attendance recognition will now be more accurate.',
                textAlign: TextAlign.center,
                style: TextStyle(fontSize: 14, color: Color(0xFF7A93AB), height: 1.6),
              ),
              const SizedBox(height: 32),
              // Embeddings processed card
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 14),
                decoration: BoxDecoration(
                  color: const Color(0xFF0E2E1E),
                  borderRadius: BorderRadius.circular(14),
                  border: Border.all(color: const Color(0xFF2A5E3A)),
                ),
                child: const Row(
                  children: [
                    Text('⚡', style: TextStyle(fontSize: 20)),
                    SizedBox(width: 12),
                    Expanded(child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text('Embeddings processed', style: TextStyle(fontSize: 13, fontWeight: FontWeight.w500, color: Color(0xFF4FC3A1))),
                        SizedBox(height: 2),
                        Text('5 face vectors averaged and stored', style: TextStyle(fontSize: 12, color: Color(0xFF7A93AB))),
                      ],
                    )),
                  ],
                ),
              ),
              const SizedBox(height: 32),
              SizedBox(
                width: double.infinity,
                child: ElevatedButton(
                  onPressed: onDone,
                  style: ElevatedButton.styleFrom(
                    backgroundColor: const Color(0xFF4FC3A1),
                    foregroundColor: const Color(0xFF0A1F14),
                    padding: const EdgeInsets.symmetric(vertical: 14),
                    shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(14)),
                  ),
                  child: const Text('Back to Profile', style: TextStyle(fontSize: 15, fontWeight: FontWeight.w500)),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

// ========== TIP ROW WIDGET ==========
class _TipRow extends StatelessWidget {
  final String icon;
  final String text;
  final Color color;
  const _TipRow({required this.icon, required this.text, required this.color});

  @override
  Widget build(BuildContext context) {
    return Row(
      children: [
        Text(icon, style: TextStyle(color: color)),
        const SizedBox(width: 10),
        Expanded(child: Text(text, style: const TextStyle(fontSize: 13, color: Color(0xFFC0D0E0)))),
      ],
    );
  }
}
