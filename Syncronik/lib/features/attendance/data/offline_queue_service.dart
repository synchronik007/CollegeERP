import 'dart:convert';

import 'package:flutter/services.dart';
import 'package:shared_preferences/shared_preferences.dart';

import '../models/attendance_record.dart';
import 'attendance_service.dart';

class OfflineQueueService {
  static const _queueKey = 'pending_attendance_submissions';
  static final List<Map<String, dynamic>> _memoryQueue = <Map<String, dynamic>>[];

  Future<SharedPreferences?> _safePrefs() async {
    try {
      return await SharedPreferences.getInstance();
    } on MissingPluginException {
      return null;
    }
  }

  Future<void> enqueue({
    required String teacherId,
    required String subjectId,
    required List<AttendanceRecord> records,
  }) async {
    final prefs = await _safePrefs();
    final existingRaw = prefs?.getString(_queueKey);
    final queue = (existingRaw == null || existingRaw.isEmpty)
      ? List<Map<String, dynamic>>.from(_memoryQueue)
        : (jsonDecode(existingRaw) as List<dynamic>)
            .cast<Map<String, dynamic>>();

    queue.add({
      'teacher_id': teacherId,
      'subject_id': subjectId,
      'records': records.map((e) => e.toJson()).toList(),
      'created_at': DateTime.now().toIso8601String(),
    });

    _memoryQueue
      ..clear()
      ..addAll(queue);
    if (prefs != null) {
      await prefs.setString(_queueKey, jsonEncode(queue));
    }
  }

  Future<void> flushPending(AttendanceService attendanceService) async {
    final prefs = await _safePrefs();
    final existingRaw = prefs?.getString(_queueKey);
    final queue = (existingRaw == null || existingRaw.isEmpty)
        ? List<Map<String, dynamic>>.from(_memoryQueue)
        : (jsonDecode(existingRaw) as List<dynamic>).cast<Map<String, dynamic>>();

    if (queue.isEmpty) {
      return;
    }

    final remaining = <Map<String, dynamic>>[];

    for (final item in queue) {
      try {
        final teacherId = (item['teacher_id'] ?? '').toString();
        final subjectId = (item['subject_id'] ?? '').toString();
        final recordsRaw = (item['records'] as List<dynamic>? ?? <dynamic>[])
            .cast<Map<String, dynamic>>();

        final records = recordsRaw
            .map(
              (record) => AttendanceRecord(
                studentId: (record['student_id'] ?? '').toString(),
                status: (record['status'] ?? 'Absent').toString(),
              ),
            )
            .toList();

        final sessionId = await attendanceService.createAttendanceSession(
          teacherId: teacherId,
          subjectId: subjectId,
        );

        await attendanceService.submitAttendanceRecords(
          sessionId: sessionId,
          records: records,
        );
      } catch (_) {
        remaining.add(item);
      }
    }

    _memoryQueue
      ..clear()
      ..addAll(remaining);
    if (prefs != null) {
      await prefs.setString(_queueKey, jsonEncode(remaining));
    }
  }
}
