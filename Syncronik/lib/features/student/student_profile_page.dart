import 'package:flutter/material.dart';
import '../attendance/data/attendance_service.dart';
import 'models/student_dashboard.dart';
import 'face_enrollment_camera_page.dart';

class StudentProfilePage extends StatefulWidget {
  const StudentProfilePage({
    super.key,
    required this.studentId,
    this.user,
    this.onLogout,
  });

  final String studentId;
  final Map<String, dynamic>? user;
  final Future<void> Function()? onLogout;

  @override
  State<StudentProfilePage> createState() => _StudentProfilePageState();
}

class _StudentProfilePageState extends State<StudentProfilePage> {
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

  Widget _buildInfoRow(String icon, String label, String value, {bool isLast = false}) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 13),
      decoration: BoxDecoration(
        color: const Color(0xFF132236),
        border: isLast ? null : const Border(bottom: BorderSide(color: Color(0xFF1A2E42))),
      ),
      child: Row(
        children: [
          SizedBox(width: 20, child: Text(icon, style: const TextStyle(fontSize: 16), textAlign: TextAlign.center)),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(label, style: const TextStyle(fontSize: 11, color: Color(0xFF7A93AB))),
                const SizedBox(height: 1),
                Text(value, style: const TextStyle(fontSize: 14, fontWeight: FontWeight.w500, color: Color(0xFFE8F0F8))),
              ],
            ),
          ),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFF0D1B2E),
      body: SafeArea(
        child: FutureBuilder<StudentDashboard>(
          future: _futureDashboard,
          builder: (context, snapshot) {
            if (snapshot.connectionState == ConnectionState.waiting) {
              return const Center(child: CircularProgressIndicator(color: Color(0xFF4FC3A1)));
            }
            if (snapshot.hasError || snapshot.data == null) {
              return Center(child: Text('Error', style: TextStyle(color: Colors.white.withOpacity(0.5))));
            }

            final d = snapshot.data!;
            final initials = d.studentName.split(' ').map((w) => w.isNotEmpty ? w[0] : '').take(2).join().toUpperCase();
            final enrolled = d.faceStatus.contains('Enrolled');

            return RefreshIndicator(
              onRefresh: () async => _reload(),
              color: const Color(0xFF4FC3A1),
              child: ListView(
                padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12).copyWith(bottom: 100),
                children: [
                  const Text('My Profile', style: TextStyle(fontSize: 22, fontWeight: FontWeight.w500, color: Color(0xFFE8F0F8))),
                  const SizedBox(height: 20),

                  // Avatar header
                  Column(
                    children: [
                      // Avatar
                      Stack(
                        children: [
                          Container(
                            width: 72,
                            height: 72,
                            decoration: BoxDecoration(
                              shape: BoxShape.circle,
                              color: const Color(0xFF1E3A5A),
                              border: Border.all(color: const Color(0xFF2A5080), width: 2),
                            ),
                            child: Center(
                              child: Text(initials, style: const TextStyle(fontSize: 26, fontWeight: FontWeight.w500, color: Color(0xFF60AAEE))),
                            ),
                          ),
                          Positioned(
                            bottom: 0,
                            right: 0,
                            child: Container(
                              width: 22,
                              height: 22,
                              decoration: const BoxDecoration(shape: BoxShape.circle, color: Color(0xFF4FC3A1)),
                              child: const Icon(Icons.edit, size: 11, color: Color(0xFF0D1B2E)),
                            ),
                          ),
                        ],
                      ),
                      const SizedBox(height: 12),
                      Text(d.studentName, style: const TextStyle(fontSize: 18, fontWeight: FontWeight.w500, color: Color(0xFFE8F0F8))),
                      const SizedBox(height: 2),
                      Text('Student • ${d.branchName}', style: const TextStyle(fontSize: 13, color: Color(0xFF7A93AB))),
                      const SizedBox(height: 10),
                      // Chips
                      Row(
                        mainAxisAlignment: MainAxisAlignment.center,
                        children: [
                          _chip(d.batch, const Color(0xFF0E2A3A), const Color(0xFF60AAEE)),
                          const SizedBox(width: 8),
                          _chip(d.semester, const Color(0xFF1E2F42), const Color(0xFF7A93AB)),
                          const SizedBox(width: 8),
                          _chip(enrolled ? 'Enrolled ✓' : 'Not Enrolled', const Color(0xFF0E3A2A), const Color(0xFF4FC3A1)),
                        ],
                      ),
                    ],
                  ),
                  const SizedBox(height: 24),

                  // Student Details
                  const Padding(
                    padding: EdgeInsets.only(bottom: 8),
                    child: Text('STUDENT DETAILS', style: TextStyle(fontSize: 11, color: Color(0xFF7A93AB), fontWeight: FontWeight.w500, letterSpacing: 0.8)),
                  ),
                  ClipRRect(
                    borderRadius: BorderRadius.circular(14),
                    child: Container(
                      decoration: BoxDecoration(
                        border: Border.all(color: const Color(0xFF1E3248)),
                        borderRadius: BorderRadius.circular(14),
                      ),
                      child: Column(
                        children: [
                          _buildInfoRow('📄', 'Student ID', d.studentId),
                          _buildInfoRow('🏫', 'Branch', d.branchName),
                          _buildInfoRow('📅', 'Year & Semester', '${d.batch} • ${d.semester}'),
                          _buildInfoRow('🏫', 'Institute Code', d.instituteCode, isLast: true),
                        ],
                      ),
                    ),
                  ),
                  const SizedBox(height: 16),

                  // Contact
                  const Padding(
                    padding: EdgeInsets.only(bottom: 8),
                    child: Text('CONTACT', style: TextStyle(fontSize: 11, color: Color(0xFF7A93AB), fontWeight: FontWeight.w500, letterSpacing: 0.8)),
                  ),
                  ClipRRect(
                    borderRadius: BorderRadius.circular(14),
                    child: Container(
                      decoration: BoxDecoration(
                        border: Border.all(color: const Color(0xFF1E3248)),
                        borderRadius: BorderRadius.circular(14),
                      ),
                      child: Column(
                        children: [
                          _buildInfoRow('✉', 'Email', d.email),
                          _buildInfoRow('📱', 'Phone', d.phone, isLast: true),
                        ],
                      ),
                    ),
                  ),
                  const SizedBox(height: 16),

                  // Face ID
                  const Padding(
                    padding: EdgeInsets.only(bottom: 8),
                    child: Text('FACE ID', style: TextStyle(fontSize: 11, color: Color(0xFF7A93AB), fontWeight: FontWeight.w500, letterSpacing: 0.8)),
                  ),
                  GestureDetector(
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
                          const Text('📸', style: TextStyle(fontSize: 28)),
                          const SizedBox(width: 12),
                          Expanded(
                            child: Column(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              children: [
                                Text(
                                  enrolled ? '${d.facePhotosCount} photos enrolled' : 'Not enrolled',
                                  style: TextStyle(fontSize: 13, fontWeight: FontWeight.w500, color: enrolled ? const Color(0xFF4FC3A1) : const Color(0xFFE8B84B)),
                                ),
                                const SizedBox(height: 2),
                                Text(
                                  enrolled ? 'Tap to add more angles for better accuracy' : 'Tap to enroll your face for attendance',
                                  style: const TextStyle(fontSize: 11, color: Color(0xFF7A93AB)),
                                ),
                              ],
                            ),
                          ),
                          Icon(Icons.chevron_right, size: 18, color: enrolled ? const Color(0xFF4FC3A1) : const Color(0xFFE8B84B)),
                        ],
                      ),
                    ),
                  ),
                  const SizedBox(height: 16),

                  // Logout
                  SizedBox(
                    width: double.infinity,
                    child: TextButton(
                      onPressed: widget.onLogout,
                      style: TextButton.styleFrom(
                        backgroundColor: const Color(0xFF3A1515),
                        foregroundColor: const Color(0xFFF07070),
                        side: const BorderSide(color: Color(0xFF5E2A2A), width: 1.5),
                        padding: const EdgeInsets.symmetric(vertical: 13),
                        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(14)),
                      ),
                      child: const Text('→ Logout', style: TextStyle(fontSize: 15, fontWeight: FontWeight.w500)),
                    ),
                  ),
                ],
              ),
            );
          },
        ),
      ),
    );
  }

  Widget _chip(String text, Color bg, Color fg) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
      decoration: BoxDecoration(color: bg, borderRadius: BorderRadius.circular(20)),
      child: Text(text, style: TextStyle(fontSize: 11, fontWeight: FontWeight.w500, color: fg)),
    );
  }
}
