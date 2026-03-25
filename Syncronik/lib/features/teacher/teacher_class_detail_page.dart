import 'package:flutter/material.dart';
import 'package:intl/intl.dart';

import '../attendance/data/attendance_service.dart';
import '../attendance/models/teacher_subject.dart';
import 'models/teacher_session_history.dart';
import 'session_detail_page.dart';
import 'subject_students_page.dart';

class TeacherClassDetailPage extends StatefulWidget {
  const TeacherClassDetailPage({
    super.key,
    required this.teacherId,
    required this.subject,
  });

  final String teacherId;
  final TeacherSubject subject;

  @override
  State<TeacherClassDetailPage> createState() => _TeacherClassDetailPageState();
}

class _TeacherClassDetailPageState extends State<TeacherClassDetailPage> {
  final AttendanceService _attendanceService = AttendanceService();
  late Future<List<TeacherSessionHistoryItem>> _futureSessions;

  @override
  void initState() {
    super.initState();
    _reload();
  }

  void _reload() {
    setState(() {
      _futureSessions = _attendanceService.getTeacherSessionHistory(widget.teacherId, int.tryParse(widget.subject.id) ?? 0);
    });
  }

  Widget _buildSessionCard(TeacherSessionHistoryItem session) {
    DateTime? dt;
    try {
      dt = DateTime.parse(session.sessionDate);
    } catch (_) {}

    final dateStr = dt != null ? DateFormat('MMM dd, yyyy').format(dt) : session.sessionDate;
    final dayStr = dt != null ? DateFormat('EEEE').format(dt) : '';
    final pct = session.totalRecords > 0 ? (session.presentRecords / session.totalRecords * 100) : 0.0;
    
    final color = pct < 65 ? Colors.redAccent : pct < 75 ? Colors.orangeAccent : Colors.greenAccent;

    return InkWell(
      onTap: () {
        Navigator.of(context).push(
          MaterialPageRoute(
            builder: (_) => SessionDetailPage(
              sessionSummary: session,
              subject: widget.subject,
            ),
          ),
        );
      },
      borderRadius: BorderRadius.circular(16),
      child: Container(
        margin: const EdgeInsets.only(bottom: 12),
        decoration: BoxDecoration(
          borderRadius: BorderRadius.circular(16),
          color: Colors.white.withOpacity(0.04),
          border: Border.all(color: Colors.white.withOpacity(0.08)),
        ),
        padding: const EdgeInsets.all(16),
        child: Row(
          children: [
            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: const Color(0xFF6C63FF).withOpacity(0.15),
                shape: BoxShape.circle,
              ),
              child: const Icon(Icons.history_edu, color: Color(0xFF7C74FF), size: 24),
            ),
            const SizedBox(width: 16),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    dateStr,
                    style: const TextStyle(fontSize: 16, fontWeight: FontWeight.bold, color: Colors.white),
                  ),
                  const SizedBox(height: 4),
                  Text(
                    dayStr,
                    style: TextStyle(fontSize: 13, color: Colors.white.withOpacity(0.6)),
                  ),
                ],
              ),
            ),
            Column(
              crossAxisAlignment: CrossAxisAlignment.end,
              children: [
                Text(
                  '${pct.toInt()}%',
                  style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold, color: color),
                ),
                Text(
                  '${session.presentRecords}/${session.totalRecords} present',
                  style: TextStyle(fontSize: 12, color: Colors.white.withOpacity(0.5)),
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
    return Scaffold(
      extendBodyBehindAppBar: true,
      appBar: AppBar(
        title: Text('${widget.subject.code} Overview', style: const TextStyle(fontWeight: FontWeight.w700)),
        backgroundColor: Colors.transparent,
        elevation: 0,
        iconTheme: const IconThemeData(color: Colors.white),
      ),
      body: Container(
        decoration: const BoxDecoration(
          gradient: LinearGradient(
            begin: Alignment.topLeft,
            end: Alignment.bottomRight,
            colors: [Color(0xFF1A1A2E), Color(0xFF16213E), Color(0xFF0F3460)],
          ),
        ),
        child: SafeArea(
          child: Column(
            children: [
              // Header actions
              Padding(
                padding: const EdgeInsets.all(24.0),
                child: Column(
                  children: [
                    Text(
                      widget.subject.name,
                      style: const TextStyle(fontSize: 22, fontWeight: FontWeight.bold, color: Colors.white),
                      textAlign: TextAlign.center,
                    ),
                    const SizedBox(height: 24),
                    Container(
                      width: double.infinity,
                      decoration: BoxDecoration(
                        borderRadius: BorderRadius.circular(16),
                        gradient: const LinearGradient(colors: [Color(0xFF6C63FF), Color(0xFF9D4EDD)]),
                        boxShadow: [
                          BoxShadow(color: const Color(0xFF6C63FF).withOpacity(0.3), blurRadius: 16, offset: const Offset(0, 8)),
                        ],
                      ),
                      child: ElevatedButton.icon(
                        onPressed: () {
                          Navigator.of(context).push(
                            MaterialPageRoute(
                              builder: (_) => SubjectStudentsPage(
                                teacherId: widget.teacherId,
                                subject: widget.subject,
                              ),
                            ),
                          ).then((_) => _reload());
                        },
                        icon: const Icon(Icons.qr_code_scanner),
                        label: const Text('New Attendance Session', style: TextStyle(fontSize: 16, fontWeight: FontWeight.bold)),
                        style: ElevatedButton.styleFrom(
                          backgroundColor: Colors.transparent,
                          shadowColor: Colors.transparent,
                          padding: const EdgeInsets.symmetric(vertical: 20),
                          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
                        ),
                      ),
                    ),
                  ],
                ),
              ),
              
              // History List
              Expanded(
                child: Container(
                  width: double.infinity,
                  decoration: const BoxDecoration(
                    color: Color(0xFF16213E),
                    borderRadius: BorderRadius.vertical(top: Radius.circular(32)),
                  ),
                  child: FutureBuilder<List<TeacherSessionHistoryItem>>(
                    future: _futureSessions,
                    builder: (context, snapshot) {
                      if (snapshot.connectionState == ConnectionState.waiting) {
                        return const Center(child: CircularProgressIndicator(color: Colors.white));
                      }
                      
                      if (snapshot.hasError) {
                        return Center(
                          child: Column(
                            mainAxisSize: MainAxisSize.min,
                            children: [
                              const Icon(Icons.error_outline, size: 48, color: Colors.white54),
                              const SizedBox(height: 16),
                              Text('Could not load sessions', style: TextStyle(color: Colors.white.withOpacity(0.8))),
                              TextButton(onPressed: _reload, child: const Text('Retry')),
                            ],
                          ),
                        );
                      }

                      final sessions = snapshot.data ?? [];
                      
                      if (sessions.isEmpty) {
                        return Center(
                          child: Text('No previous classes recorded for this subject.', style: TextStyle(color: Colors.white.withOpacity(0.5))),
                        );
                      }

                      return RefreshIndicator(
                        onRefresh: () async => _reload(),
                        color: const Color(0xFF6C63FF),
                        backgroundColor: const Color(0xFF1A1A2E),
                        child: ListView.builder(
                          padding: const EdgeInsets.all(24),
                          physics: const AlwaysScrollableScrollPhysics(),
                          itemCount: sessions.length + 1,
                          itemBuilder: (context, index) {
                            if (index == 0) {
                              return const Padding(
                                padding: EdgeInsets.only(bottom: 24),
                                child: Text(
                                  'Past Sessions',
                                  style: TextStyle(fontSize: 20, fontWeight: FontWeight.bold, color: Colors.white),
                                ),
                              );
                            }
                            return _buildSessionCard(sessions[index - 1]);
                          },
                        ),
                      );
                    },
                  ),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
