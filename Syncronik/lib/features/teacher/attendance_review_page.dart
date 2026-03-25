import 'package:flutter/material.dart';

import '../attendance/data/attendance_service.dart';
import '../attendance/data/offline_queue_service.dart';
import '../attendance/models/attendance_record.dart';
import '../attendance/models/student_profile.dart';
import '../attendance/models/teacher_subject.dart';
import 'attendance_summary_page.dart';

class AttendanceReviewPage extends StatefulWidget {
  const AttendanceReviewPage({
    super.key,
    required this.teacherId,
    required this.subject,
    required this.students,
    this.initialPresentStudentIds,
  });

  final String teacherId;
  final TeacherSubject subject;
  final List<StudentProfile> students;
  final Set<String>? initialPresentStudentIds;

  @override
  State<AttendanceReviewPage> createState() => _AttendanceReviewPageState();
}

class _AttendanceReviewPageState extends State<AttendanceReviewPage> with SingleTickerProviderStateMixin {
  final AttendanceService _attendanceService = AttendanceService();
  final OfflineQueueService _offlineQueueService = OfflineQueueService();
  final Map<String, bool> _presentMap = <String, bool>{};
  bool _submitting = false;
  late TabController _tabController;

  @override
  void initState() {
    super.initState();
    _tabController = TabController(length: 2, vsync: this);

    final initialMatches = widget.initialPresentStudentIds;
    final isManualEntry = initialMatches == null;

    for (final student in widget.students) {
      if (isManualEntry) {
        _presentMap[student.id] = student.hasEmbedding;
      } else {
        _presentMap[student.id] = initialMatches.contains(student.id);
      }
    }
  }

  @override
  void dispose() {
    _tabController.dispose();
    super.dispose();
  }

  Future<void> _submitAttendance() async {
    setState(() => _submitting = true);

    try {
      await _offlineQueueService.flushPending(_attendanceService);

      final sessionId = await _attendanceService.createAttendanceSession(
        teacherId: widget.teacherId,
        subjectId: widget.subject.id,
      );

      final records = widget.students
          .map(
            (student) => AttendanceRecord(
              studentId: student.id,
              status: (_presentMap[student.id] ?? false) ? 'Present' : 'Absent',
            ),
          )
          .toList();

      await _attendanceService.submitAttendanceRecords(
        sessionId: sessionId,
        records: records,
      );

      if (!mounted) return;

      // Navigate to summary page instead of popping to root
      Navigator.of(context).pushReplacement(
        MaterialPageRoute(
          builder: (_) => AttendanceSummaryPage(
            teacherId: widget.teacherId,
            subject: widget.subject,
            students: widget.students,
            presentMap: Map.from(_presentMap),
          ),
        ),
      );
    } catch (error) {
      final records = widget.students
          .map(
            (student) => AttendanceRecord(
              studentId: student.id,
              status: (_presentMap[student.id] ?? false) ? 'Present' : 'Absent',
            ),
          )
          .toList();

      await _offlineQueueService.enqueue(
        teacherId: widget.teacherId,
        subjectId: widget.subject.id,
        records: records,
      );

      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Network/API failed. Attendance queued for retry.')),
      );
      Navigator.of(context).popUntil((route) => route.isFirst);
    } finally {
      if (mounted) setState(() => _submitting = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final absentStudents = widget.students.where((s) => _presentMap[s.id] != true).toList();
    final presentStudents = widget.students.where((s) => _presentMap[s.id] == true).toList();
    final presentCount = presentStudents.length;
    final absentCount = absentStudents.length;

    return Scaffold(
      body: SafeArea(
        child: Column(
          children: [
            // Custom App Bar
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
              child: Row(
                children: [
                  GestureDetector(
                    onTap: () => Navigator.of(context).pop(),
                    child: Container(
                      padding: const EdgeInsets.all(10),
                      decoration: BoxDecoration(
                        color: Colors.white.withOpacity(0.06),
                        borderRadius: BorderRadius.circular(12),
                        border: Border.all(color: Colors.white.withOpacity(0.08)),
                      ),
                      child: const Icon(Icons.arrow_back_ios_new_rounded, size: 18, color: Colors.white),
                    ),
                  ),
                  const SizedBox(width: 14),
                  const Text(
                    'Review',
                    style: TextStyle(
                      fontSize: 20,
                      fontWeight: FontWeight.w700,
                      color: Colors.white,
                    ),
                  ),
                  const Spacer(),
                  // Present Badge
                  Container(
                    padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
                    decoration: BoxDecoration(
                      color: const Color(0xFF4CAF50),
                      borderRadius: BorderRadius.circular(20),
                    ),
                    child: Text(
                      'Present: $presentCount',
                      style: const TextStyle(
                        fontSize: 12,
                        fontWeight: FontWeight.w600,
                        color: Colors.white,
                      ),
                    ),
                  ),
                  const SizedBox(width: 8),
                  // Absent Badge
                  Container(
                    padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
                    decoration: BoxDecoration(
                      color: const Color(0xFFEF5350),
                      borderRadius: BorderRadius.circular(20),
                    ),
                    child: Text(
                      'Absent: $absentCount',
                      style: const TextStyle(
                        fontSize: 12,
                        fontWeight: FontWeight.w600,
                        color: Colors.white,
                      ),
                    ),
                  ),
                ],
              ),
            ),

            // Tab Bar
            Container(
              margin: const EdgeInsets.symmetric(horizontal: 16),
              decoration: BoxDecoration(
                color: Colors.white.withOpacity(0.06),
                borderRadius: BorderRadius.circular(14),
              ),
              child: TabBar(
                controller: _tabController,
                onTap: (_) => setState(() {}),
                indicator: BoxDecoration(
                  color: _tabController.index == 0
                      ? const Color(0xFFEF5350)
                      : const Color(0xFF4CAF50),
                  borderRadius: BorderRadius.circular(14),
                ),
                indicatorSize: TabBarIndicatorSize.tab,
                labelColor: Colors.white,
                unselectedLabelColor: Colors.white60,
                labelStyle: const TextStyle(fontWeight: FontWeight.w600, fontSize: 14),
                dividerColor: Colors.transparent,
                tabs: [
                  Tab(
                    child: Row(
                      mainAxisAlignment: MainAxisAlignment.center,
                      children: [
                        const Icon(Icons.person_off_outlined, size: 18),
                        const SizedBox(width: 6),
                        Text('Absent ($absentCount)'),
                      ],
                    ),
                  ),
                  Tab(
                    child: Row(
                      mainAxisAlignment: MainAxisAlignment.center,
                      children: [
                        const Icon(Icons.person_outlined, size: 18),
                        const SizedBox(width: 6),
                        Text('Present ($presentCount)'),
                      ],
                    ),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 8),

            // Student Lists
            Expanded(
              child: TabBarView(
                controller: _tabController,
                children: [
                  // Absent Tab
                  _buildStudentList(absentStudents, isAbsentTab: true),
                  // Present Tab
                  _buildStudentList(presentStudents, isAbsentTab: false),
                ],
              ),
            ),

            // Save & Upload Button
            Container(
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                color: const Color(0xFF16213E),
                border: Border(
                  top: BorderSide(color: Colors.white.withOpacity(0.06)),
                ),
              ),
              child: Container(
                width: double.infinity,
                decoration: BoxDecoration(
                  borderRadius: BorderRadius.circular(14),
                  gradient: const LinearGradient(
                    colors: [Color(0xFF4CAF50), Color(0xFF66BB6A)],
                  ),
                  boxShadow: [
                    BoxShadow(
                      color: const Color(0xFF4CAF50).withOpacity(0.35),
                      blurRadius: 12,
                      offset: const Offset(0, 4),
                    ),
                  ],
                ),
                child: Material(
                  color: Colors.transparent,
                  child: InkWell(
                    borderRadius: BorderRadius.circular(14),
                    onTap: _submitting ? null : _submitAttendance,
                    child: Padding(
                      padding: const EdgeInsets.symmetric(vertical: 16),
                      child: Row(
                        mainAxisAlignment: MainAxisAlignment.center,
                        children: [
                          if (_submitting)
                            const SizedBox(
                              width: 20,
                              height: 20,
                              child: CircularProgressIndicator(strokeWidth: 2, color: Colors.white),
                            )
                          else ...[
                            const Icon(Icons.cloud_upload_rounded, color: Colors.white, size: 22),
                            const SizedBox(width: 10),
                            const Text(
                              'Save & Upload',
                              style: TextStyle(
                                fontSize: 17,
                                fontWeight: FontWeight.w700,
                                color: Colors.white,
                              ),
                            ),
                          ],
                        ],
                      ),
                    ),
                  ),
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildStudentList(List<StudentProfile> students, {required bool isAbsentTab}) {
    if (students.isEmpty) {
      return Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(
              isAbsentTab ? Icons.check_circle_outline : Icons.people_outline,
              size: 48,
              color: Colors.white.withOpacity(0.2),
            ),
            const SizedBox(height: 12),
            Text(
              isAbsentTab ? 'All students are present!' : 'No students marked present',
              style: TextStyle(color: Colors.white.withOpacity(0.4), fontSize: 15),
            ),
          ],
        ),
      );
    }

    return ListView.builder(
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
      itemCount: students.length,
      itemBuilder: (context, index) {
        final student = students[index];
        final isPresent = _presentMap[student.id] == true;

        return Container(
          margin: const EdgeInsets.only(bottom: 6),
          padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
          decoration: BoxDecoration(
            color: const Color(0xFF16213E),
            borderRadius: BorderRadius.circular(14),
            border: Border.all(color: Colors.white.withOpacity(0.06)),
          ),
          child: Row(
            children: [
              // Avatar with colored border
              Container(
                width: 46,
                height: 46,
                decoration: BoxDecoration(
                  shape: BoxShape.circle,
                  border: Border.all(
                    color: isPresent ? const Color(0xFF4CAF50) : const Color(0xFFEF5350),
                    width: 2,
                  ),
                ),
                child: Container(
                  margin: const EdgeInsets.all(2),
                  decoration: BoxDecoration(
                    shape: BoxShape.circle,
                    gradient: LinearGradient(
                      colors: isPresent
                          ? [const Color(0xFF4CAF50).withOpacity(0.3), const Color(0xFF66BB6A).withOpacity(0.3)]
                          : [const Color(0xFFEF5350).withOpacity(0.3), const Color(0xFFE57373).withOpacity(0.3)],
                    ),
                  ),
                  child: Center(
                    child: Text(
                      student.name.isNotEmpty ? student.name[0].toUpperCase() : '?',
                      style: TextStyle(
                        fontSize: 16,
                        fontWeight: FontWeight.bold,
                        color: isPresent ? const Color(0xFF4CAF50) : const Color(0xFFEF5350),
                      ),
                    ),
                  ),
                ),
              ),
              const SizedBox(width: 14),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      student.name,
                      style: const TextStyle(
                        fontSize: 15,
                        fontWeight: FontWeight.w600,
                        color: Colors.white,
                      ),
                    ),
                    const SizedBox(height: 2),
                    Text(
                      'Roll No: ${student.id}',
                      style: TextStyle(
                        fontSize: 12,
                        color: Colors.white.withOpacity(0.4),
                      ),
                    ),
                  ],
                ),
              ),
              // Toggle Switch
              Switch(
                value: isPresent,
                activeColor: const Color(0xFF4CAF50),
                activeTrackColor: const Color(0xFF4CAF50).withOpacity(0.4),
                inactiveThumbColor: Colors.grey.shade500,
                inactiveTrackColor: Colors.grey.shade800,
                onChanged: (value) {
                  setState(() {
                    _presentMap[student.id] = value;
                  });
                },
              ),
            ],
          ),
        );
      },
    );
  }
}