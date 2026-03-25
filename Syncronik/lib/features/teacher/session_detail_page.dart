import 'package:flutter/material.dart';
import 'package:intl/intl.dart';

import '../attendance/data/attendance_service.dart';
import 'models/teacher_session_history.dart';
import '../attendance/models/teacher_subject.dart';

class SessionDetailPage extends StatefulWidget {
  const SessionDetailPage({
    super.key,
    required this.sessionSummary,
    required this.subject,
  });

  final TeacherSessionHistoryItem sessionSummary;
  final TeacherSubject subject;

  @override
  State<SessionDetailPage> createState() => _SessionDetailPageState();
}

class _SessionDetailPageState extends State<SessionDetailPage> {
  final AttendanceService _attendanceService = AttendanceService();
  late Future<SessionDetail> _futureDetail;

  bool _showOnlyAbsent = false;

  @override
  void initState() {
    super.initState();
    _futureDetail = _attendanceService.getSessionDetail(widget.sessionSummary.sessionId);
  }

  void _reload() {
    setState(() {
      _futureDetail = _attendanceService.getSessionDetail(widget.sessionSummary.sessionId);
    });
  }

  @override
  Widget build(BuildContext context) {
    DateTime? dt;
    try {
      dt = DateTime.parse(widget.sessionSummary.sessionDate);
    } catch (_) {}
    final topDateStr = dt != null ? DateFormat('MMMM d, yyyy').format(dt) : widget.sessionSummary.sessionDate;

    return Scaffold(
      extendBodyBehindAppBar: true,
      appBar: AppBar(
        title: const Text('Session Record', style: TextStyle(fontWeight: FontWeight.w700)),
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
              // Header Summary
              Padding(
                padding: const EdgeInsets.all(24.0),
                child: Column(
                  children: [
                    Text(
                      widget.subject.name,
                      style: const TextStyle(fontSize: 20, fontWeight: FontWeight.bold, color: Colors.white),
                      textAlign: TextAlign.center,
                    ),
                    const SizedBox(height: 8),
                    Text(
                      topDateStr,
                      style: TextStyle(fontSize: 16, color: Colors.white.withOpacity(0.7)),
                    ),
                    const SizedBox(height: 24),
                    Row(
                      mainAxisAlignment: MainAxisAlignment.spaceAround,
                      children: [
                        _buildStatBox('Present', widget.sessionSummary.presentRecords, Colors.greenAccent),
                        _buildStatBox(
                          'Absent', 
                          widget.sessionSummary.totalRecords - widget.sessionSummary.presentRecords, 
                          Colors.redAccent
                        ),
                        _buildStatBox('Total', widget.sessionSummary.totalRecords, Colors.white),
                      ],
                    ),
                  ],
                ),
              ),

              // Filter Toggle
              Padding(
                padding: const EdgeInsets.symmetric(horizontal: 24.0, vertical: 8.0),
                child: Row(
                  mainAxisAlignment: MainAxisAlignment.end,
                  children: [
                    const Text('Show Absent Only', style: TextStyle(color: Colors.white)),
                    const SizedBox(width: 8),
                    Switch(
                      value: _showOnlyAbsent,
                      activeColor: Colors.redAccent,
                      onChanged: (val) => setState(() => _showOnlyAbsent = val),
                    ),
                  ],
                ),
              ),

              // List of Records
              Expanded(
                child: Container(
                  width: double.infinity,
                  decoration: const BoxDecoration(
                    color: Color(0xFF16213E),
                    borderRadius: BorderRadius.vertical(top: Radius.circular(32)),
                  ),
                  child: FutureBuilder<SessionDetail>(
                    future: _futureDetail,
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
                              Text('Could not load record details', style: TextStyle(color: Colors.white.withOpacity(0.8))),
                              TextButton(onPressed: _reload, child: const Text('Retry')),
                            ],
                          ),
                        );
                      }

                      final detail = snapshot.data;
                      if (detail == null || detail.records.isEmpty) {
                        return Center(
                          child: Text('No student records found.', style: TextStyle(color: Colors.white.withOpacity(0.5))),
                        );
                      }

                      var displayRecords = detail.records;
                      if (_showOnlyAbsent) {
                        displayRecords = displayRecords.where((r) => r.status.toLowerCase() != 'present').toList();
                      }

                      if (displayRecords.isEmpty) {
                        return Center(
                          child: Text('No students match the selected filter.', style: TextStyle(color: Colors.white.withOpacity(0.5))),
                        );
                      }

                      return ListView.separated(
                        padding: const EdgeInsets.all(24),
                        itemCount: displayRecords.length,
                        separatorBuilder: (_, __) => const Divider(color: Colors.white12, height: 1),
                        itemBuilder: (context, index) {
                          final rec = displayRecords[index];
                          final isPresent = rec.status.toLowerCase() == 'present';

                          return Padding(
                            padding: const EdgeInsets.symmetric(vertical: 8.0),
                            child: Row(
                              children: [
                                CircleAvatar(
                                  radius: 20,
                                  backgroundColor: isPresent ? Colors.greenAccent.withOpacity(0.2) : Colors.redAccent.withOpacity(0.2),
                                  child: Text(
                                    rec.studentName.isNotEmpty ? rec.studentName[0] : 'U',
                                    style: TextStyle(
                                      color: isPresent ? Colors.greenAccent : Colors.redAccent,
                                      fontWeight: FontWeight.bold,
                                    ),
                                  ),
                                ),
                                const SizedBox(width: 16),
                                Expanded(
                                  child: Column(
                                    crossAxisAlignment: CrossAxisAlignment.start,
                                    children: [
                                      Text(
                                        rec.studentName,
                                        style: const TextStyle(fontSize: 16, color: Colors.white, fontWeight: FontWeight.bold),
                                      ),
                                      const SizedBox(height: 4),
                                      Text(
                                        rec.studentId,
                                        style: TextStyle(fontSize: 13, color: Colors.white.withOpacity(0.6)),
                                      ),
                                    ],
                                  ),
                                ),
                                Container(
                                  padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                                  decoration: BoxDecoration(
                                    color: (isPresent ? Colors.greenAccent : Colors.redAccent).withOpacity(0.15),
                                    borderRadius: BorderRadius.circular(12),
                                    border: Border.all(color: (isPresent ? Colors.greenAccent : Colors.redAccent).withOpacity(0.3)),
                                  ),
                                  child: Text(
                                    isPresent ? 'Present' : 'Absent',
                                    style: TextStyle(
                                      color: isPresent ? Colors.greenAccent : Colors.redAccent,
                                      fontWeight: FontWeight.bold,
                                      fontSize: 12,
                                    ),
                                  ),
                                ),
                              ],
                            ),
                          );
                        },
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

  Widget _buildStatBox(String label, int value, Color color) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 16),
      decoration: BoxDecoration(
        color: Colors.white.withOpacity(0.05),
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: Colors.white.withOpacity(0.1)),
      ),
      child: Column(
        children: [
          Text(
            '$value',
            style: TextStyle(fontSize: 24, fontWeight: FontWeight.bold, color: color),
          ),
          const SizedBox(height: 4),
          Text(label, style: TextStyle(color: Colors.white.withOpacity(0.7), fontSize: 13)),
        ],
      ),
    );
  }
}
