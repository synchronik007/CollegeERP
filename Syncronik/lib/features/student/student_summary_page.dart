import 'package:flutter/material.dart';
import 'package:intl/intl.dart';
import '../attendance/data/attendance_service.dart';
import 'models/student_dashboard.dart';
import 'subject_attendance_page.dart';
import 'face_enrollment_camera_page.dart';

class StudentSummaryPage extends StatefulWidget {
  const StudentSummaryPage({
    super.key,
    required this.studentId,
    this.user,
    this.onLogout,
  });

  final String studentId;
  final Map<String, dynamic>? user;
  final Future<void> Function()? onLogout;

  @override
  State<StudentSummaryPage> createState() => _StudentSummaryPageState();
}

class _StudentSummaryPageState extends State<StudentSummaryPage> {
  final AttendanceService _attendanceService = AttendanceService();
  late Future<StudentDashboard> _futureDashboard;

  @override
  void initState() {
    super.initState();
    _futureDashboard = _attendanceService.getStudentDashboard(widget.studentId);
  }

  void _reload() {
    setState(() {
      _futureDashboard = _attendanceService.getStudentDashboard(widget.studentId);
    });
  }

  // --- Stats Row: 3 bordered boxes ---
  Widget _buildStatsRow(StudentDashboard d) {
    return Row(
      children: [
        _buildStatBox('${d.overallAttendancePercentage.toInt()}%', 'Overall', const Color(0xFFE8F0F8)),
        const SizedBox(width: 8),
        _buildStatBox('${d.totalPresent}', 'Present', const Color(0xFFE8F0F8)),
        const SizedBox(width: 8),
        _buildStatBox('${d.totalAbsent}', 'Absent', const Color(0xFFF07070)),
      ],
    );
  }

  Widget _buildStatBox(String value, String label, Color valueColor) {
    return Expanded(
      child: Container(
        padding: const EdgeInsets.symmetric(vertical: 10, horizontal: 8),
        decoration: BoxDecoration(
          color: const Color(0xFF132236),
          borderRadius: BorderRadius.circular(12),
          border: Border.all(color: const Color(0xFF1E3248)),
        ),
        child: Column(
          children: [
            Text(value, style: TextStyle(fontSize: 18, fontWeight: FontWeight.w500, color: valueColor)),
            const SizedBox(height: 2),
            Text(label, style: const TextStyle(fontSize: 10, color: Color(0xFF7A93AB))),
          ],
        ),
      ),
    );
  }

  // --- Face ID Banner ---
  Widget _buildFaceBanner(StudentDashboard d) {
    final enrolled = d.faceStatus.contains('Enrolled');
    return GestureDetector(
      onTap: () {
        Navigator.push(context, MaterialPageRoute(
          builder: (_) => FaceEnrollmentCameraPage(studentId: widget.studentId),
        )).then((_) => _reload());
      },
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
        decoration: BoxDecoration(
          color: enrolled ? const Color(0xFF0E2E1E) : const Color(0xFF2E1A0E),
          borderRadius: BorderRadius.circular(14),
          border: Border.all(color: enrolled ? const Color(0xFF1A5E3A) : const Color(0xFF5E3A1A)),
        ),
        child: Row(
          children: [
            Icon(Icons.face_retouching_natural, size: 24, color: enrolled ? const Color(0xFF4FC3A1) : const Color(0xFFE8B84B)),
            const SizedBox(width: 12),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text('Face ID', style: TextStyle(fontSize: 12, color: const Color(0xFF7A93AB))),
                  Text(
                    enrolled ? 'Enrolled — ${d.facePhotosCount} photos' : 'Not Set Up',
                    style: TextStyle(fontSize: 14, fontWeight: FontWeight.w500, color: enrolled ? const Color(0xFF4FC3A1) : const Color(0xFFE8B84B)),
                  ),
                ],
              ),
            ),
            Icon(Icons.chevron_right, size: 16, color: enrolled ? const Color(0xFF4FC3A1) : const Color(0xFFE8B84B)),
          ],
        ),
      ),
    );
  }

  // --- Subject Card (matches mockup exactly) ---
  Widget _buildSubjectCard(StudentDashboardSubject s) {
    final pct = s.attendancePercentage;
    final color = pct < 75 ? const Color(0xFFF07070) : pct < 85 ? const Color(0xFFE8B84B) : const Color(0xFF4FC3A1);
    // SVG-like ring: stroke-dashoffset calculation
    const double circumference = 119.4; // 2 * pi * 19


    return GestureDetector(
      onTap: () {
        Navigator.push(context, MaterialPageRoute(
          builder: (_) => SubjectAttendancePage(
            studentId: widget.studentId,
            subjectId: s.subjectId,
            subjectName: s.subjectName,
          ),
        ));
      },
      child: Container(
        padding: const EdgeInsets.all(14),
        decoration: BoxDecoration(
          color: const Color(0xFF132236),
          borderRadius: BorderRadius.circular(16),
          border: Border.all(color: const Color(0xFF1E3248)),
        ),
        child: Stack(
          children: [
            // Ring in top-right
            Positioned(
              top: 0,
              right: 0,
              child: SizedBox(
                width: 48,
                height: 48,
                child: Stack(
                  alignment: Alignment.center,
                  children: [
                    CustomPaint(
                      size: const Size(48, 48),
                      painter: _RingPainter(pct / 100, color),
                    ),
                    Text('${pct.toInt()}%', style: TextStyle(fontSize: 10, fontWeight: FontWeight.w500, color: color)),
                  ],
                ),
              ),
            ),
            // Content
            Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Padding(
                  padding: const EdgeInsets.only(right: 52),
                  child: Text(
                    s.subjectName,
                    style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w500, color: Color(0xFFE8F0F8)),
                    maxLines: 2,
                    overflow: TextOverflow.ellipsis,
                  ),
                ),
                const SizedBox(height: 4),
                Text(
                  '${s.subjectCode} • ${s.teacherName}',
                  style: const TextStyle(fontSize: 11, color: Color(0xFF7A93AB)),
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                ),
                const SizedBox(height: 24),
                Row(
                  children: [
                    const Icon(Icons.calendar_today, size: 12, color: Color(0xFF4A6278)),
                    const SizedBox(width: 4),
                    Text(
                      '${s.classesAttended} / ${s.classesHeld} classes',
                      style: const TextStyle(fontSize: 11, color: Color(0xFF4A6278)),
                    ),
                  ],
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final today = DateFormat('EEEE, d MMMM').format(DateTime.now());

    return Scaffold(
      backgroundColor: const Color(0xFF0D1B2E),
      body: FutureBuilder<StudentDashboard>(
        future: _futureDashboard,
        builder: (context, snapshot) {
          if (snapshot.connectionState == ConnectionState.waiting) {
            return const Center(child: CircularProgressIndicator(color: Color(0xFF4FC3A1)));
          }
          if (snapshot.hasError || snapshot.data == null) {
            return Center(
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  const Icon(Icons.error_outline, size: 48, color: Color(0xFFF07070)),
                  const SizedBox(height: 16),
                  Text('Failed to load', style: TextStyle(color: Colors.white.withOpacity(0.5))),
                  const SizedBox(height: 16),
                  TextButton(onPressed: _reload, child: const Text('Retry', style: TextStyle(color: Color(0xFF4FC3A1)))),
                ],
              ),
            );
          }

          final d = snapshot.data!;
          final initials = d.studentName.split(' ').map((w) => w.isNotEmpty ? w[0] : '').take(2).join().toUpperCase();

          return RefreshIndicator(
            onRefresh: () async => _reload(),
            color: const Color(0xFF4FC3A1),
            child: ListView(
              padding: const EdgeInsets.only(left: 16, right: 16, top: 16, bottom: 100),
              children: [
                // Status bar placeholder
                SafeArea(
                  bottom: false,
                  child: Padding(
                    padding: const EdgeInsets.only(bottom: 8),
                    child: Row(
                      mainAxisAlignment: MainAxisAlignment.spaceBetween,
                      children: [
                        Text('${d.branchName} • ${d.semester}', style: const TextStyle(fontSize: 11, color: Color(0xFF8FA3B8))),
                      ],
                    ),
                  ),
                ),
                // Header
                Row(
                  mainAxisAlignment: MainAxisAlignment.spaceBetween,
                  children: [
                    Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        const Text('Dashboard', style: TextStyle(fontSize: 22, fontWeight: FontWeight.w500, color: Color(0xFFE8F0F8))),
                        Text(today, style: const TextStyle(fontSize: 12, color: Color(0xFF7A93AB))),
                      ],
                    ),
                    GestureDetector(
                      onTap: () {
                        // Switch to Profile tab via parent
                        final shell = context.findAncestorStateOfType<State>();
                        if (shell != null && shell.mounted) {
                          // We'll navigate through bottom nav by calling setState on parent
                        }
                      },
                      child: Container(
                        width: 40,
                        height: 40,
                        decoration: BoxDecoration(
                          shape: BoxShape.circle,
                          color: const Color(0xFF1E3A5A),
                          border: Border.all(color: const Color(0xFF2A5080), width: 1.5),
                        ),
                        child: Center(
                          child: Text(initials, style: const TextStyle(fontSize: 15, fontWeight: FontWeight.w500, color: Color(0xFF60AAEE))),
                        ),
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 16),

                // Overall stats row
                _buildStatsRow(d),
                const SizedBox(height: 16),

                // Face ID Banner
                _buildFaceBanner(d),
                const SizedBox(height: 16),

                // Subjects header
                Row(
                  mainAxisAlignment: MainAxisAlignment.spaceBetween,
                  children: [
                    const Text('My Subjects', style: TextStyle(fontSize: 18, fontWeight: FontWeight.w500, color: Color(0xFFE8F0F8))),
                    Text('${d.subjects.length} subjects', style: const TextStyle(fontSize: 12, color: Color(0xFF4FC3A1))),
                  ],
                ),
                const SizedBox(height: 12),

                // Subject grid (2 columns)
                GridView.builder(
                  shrinkWrap: true,
                  physics: const NeverScrollableScrollPhysics(),
                  gridDelegate: const SliverGridDelegateWithFixedCrossAxisCount(
                    crossAxisCount: 2,
                    crossAxisSpacing: 12,
                    mainAxisSpacing: 12,
                    childAspectRatio: 1.05,
                  ),
                  itemCount: d.subjects.length,
                  itemBuilder: (context, i) => _buildSubjectCard(d.subjects[i]),
                ),
              ],
            ),
          );
        },
      ),
    );
  }
}

// Custom ring painter matching the SVG ring from the mockup
class _RingPainter extends CustomPainter {
  final double progress;
  final Color color;
  _RingPainter(this.progress, this.color);

  @override
  void paint(Canvas canvas, Size size) {
    final center = Offset(size.width / 2, size.height / 2);
    const radius = 19.0;
    const strokeWidth = 4.0;

    // Background ring
    canvas.drawCircle(center, radius, Paint()
      ..style = PaintingStyle.stroke
      ..strokeWidth = strokeWidth
      ..color = const Color(0xFF1E3248));

    // Progress arc
    final rect = Rect.fromCircle(center: center, radius: radius);
    canvas.drawArc(rect, -1.5708, progress * 6.2832, false, Paint()
      ..style = PaintingStyle.stroke
      ..strokeWidth = strokeWidth
      ..strokeCap = StrokeCap.round
      ..color = color);
  }

  @override
  bool shouldRepaint(covariant _RingPainter old) => old.progress != progress || old.color != color;
}
