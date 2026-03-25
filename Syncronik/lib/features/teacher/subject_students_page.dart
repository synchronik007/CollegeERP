import 'package:flutter/material.dart';

import '../attendance/data/attendance_service.dart';
import '../attendance/data/lazy_sync_service.dart';
import '../attendance/data/background_embedding_service.dart';
import '../attendance/models/student_profile.dart';
import '../attendance/models/teacher_subject.dart';
import 'attendance_review_page.dart';
import 'camera_scan_page.dart';

class SubjectStudentsPage extends StatefulWidget {
  const SubjectStudentsPage({
    super.key,
    required this.teacherId,
    required this.subject,
  });

  final String teacherId;
  final TeacherSubject subject;

  @override
  State<SubjectStudentsPage> createState() => _SubjectStudentsPageState();
}

class _SubjectStudentsPageState extends State<SubjectStudentsPage> {
  final AttendanceService _attendanceService = AttendanceService();
  final LazySyncService _lazySyncService = LazySyncService();
  final BackgroundEmbeddingService _backgroundEmbeddingService = BackgroundEmbeddingService();
  late Future<List<StudentProfile>> _futureStudents;
  bool _syncing = false;
  int _syncedCount = 0;

  String _compactError(Object error) {
    final raw = error.toString().replaceAll('\n', ' ').trim();
    if (raw.length <= 220) {
      return raw;
    }
    return '${raw.substring(0, 220)}...';
  }

  void _reload() {
    setState(() {
      _futureStudents = _attendanceService.getSubjectStudents(widget.subject.id);
    });
    
    // Automatically trigger the background embedding scan on reload
    _futureStudents.then((students) {
      _backgroundEmbeddingService.processMissingEmbeddings(students);
    });
    
    _runLazySync();
  }

  @override
  void initState() {
    super.initState();
    _futureStudents = _attendanceService.getSubjectStudents(widget.subject.id);
    
    // Automatically trigger the background embedding scan silently when page loads
    _futureStudents.then((students) {
      _backgroundEmbeddingService.processMissingEmbeddings(students);
    });
    
    _runLazySync();
  }

  Future<void> _runLazySync() async {
    setState(() {
      _syncing = true;
      _syncedCount = 0;
    });

    try {
      final students = await _futureStudents;
      final updated = await _lazySyncService.syncMissingEmbeddings(students);
      if (!mounted) return;
      setState(() {
        _syncedCount = updated;
      });
    } finally {
      if (mounted) {
        setState(() {
          _syncing = false;
        });
      }
    }
  }

  @override
  void dispose() {
    _lazySyncService.close();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: Text(widget.subject.name)),
      body: FutureBuilder<List<StudentProfile>>(
        future: _futureStudents,
        builder: (context, snapshot) {
          if (snapshot.connectionState != ConnectionState.done) {
            return const Center(child: CircularProgressIndicator());
          }

          if (snapshot.hasError) {
            return SingleChildScrollView(
              padding: const EdgeInsets.all(16),
              child: Card(
                child: Padding(
                  padding: const EdgeInsets.all(16),
                  child: Column(
                    mainAxisSize: MainAxisSize.min,
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      const Text(
                        'Could not load class roster',
                        style: TextStyle(fontWeight: FontWeight.w700),
                      ),
                      const SizedBox(height: 8),
                      Text(
                        _compactError(snapshot.error!),
                        style: TextStyle(color: Colors.grey.shade700),
                      ),
                      const SizedBox(height: 12),
                      OutlinedButton.icon(
                        onPressed: _reload,
                        icon: const Icon(Icons.refresh),
                        label: const Text('Retry'),
                      ),
                    ],
                  ),
                ),
              ),
            );
          }

          final students = snapshot.data ?? const <StudentProfile>[];
          if (students.isEmpty) {
            return const Center(child: Text('No enrolled students.'));
          }

          return Column(
            children: [
              if (_syncing || _syncedCount > 0)
                Container(
                  width: double.infinity,
                  padding: const EdgeInsets.all(12),
                  color: Theme.of(context).colorScheme.secondaryContainer,
                  child: Text(
                    _syncing
                        ? 'Syncing missing embeddings...'
                        : 'Lazy sync complete. Updated embeddings: $_syncedCount',
                  ),
                ),
              Expanded(
                child: ListView.separated(
                  itemCount: students.length,
                  separatorBuilder: (_, __) => const Divider(height: 1),
                  itemBuilder: (context, index) {
                    final student = students[index];
                    return ListTile(
                      title: Text(student.name),
                      subtitle: Text('ID: ${student.id}'),
                      trailing: student.hasEmbedding
                          ? const Icon(Icons.verified_outlined, color: Colors.green)
                          : const Icon(Icons.warning_amber, color: Colors.orange),
                    );
                  },
                ),
              ),
              Padding(
                padding: const EdgeInsets.all(16),
                child: Row(
                  children: [
                    Expanded(
                      child: OutlinedButton.icon(
                        onPressed: () {
                          Navigator.of(context).push(
                            MaterialPageRoute(
                              builder: (_) => AttendanceReviewPage(
                                teacherId: widget.teacherId,
                                subject: widget.subject,
                                students: students,
                              ),
                            ),
                          );
                        },
                        icon: const Icon(Icons.checklist_rtl),
                        label: const Text('Manual Review'),
                      ),
                    ),
                    const SizedBox(width: 12),
                    Expanded(
                      child: ElevatedButton.icon(
                        onPressed: () async {
                          final matched = await Navigator.of(context).push<Set<String>>(
                            MaterialPageRoute(
                              builder: (_) => CameraScanPage(students: students),
                            ),
                          );

                          if (!mounted) return;

                          Navigator.of(context).push(
                            MaterialPageRoute(
                              builder: (_) => AttendanceReviewPage(
                                teacherId: widget.teacherId,
                                subject: widget.subject,
                                students: students,
                                initialPresentStudentIds: matched,
                              ),
                            ),
                          );
                        },
                        icon: const Icon(Icons.camera_alt_outlined),
                        label: const Text('Scan & Review'),
                      ),
                    ),
                  ],
                ),
              ),
            ],
          );
        },
      ),
    );
  }
}
