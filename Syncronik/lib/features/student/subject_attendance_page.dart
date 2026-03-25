import 'package:flutter/material.dart';
import 'package:intl/intl.dart';
import '../attendance/data/attendance_service.dart';
import 'models/student_subject_attendance.dart';

class SubjectAttendancePage extends StatefulWidget {
  const SubjectAttendancePage({
    super.key,
    required this.studentId,
    required this.subjectId,
    required this.subjectName,
  });

  final String studentId;
  final int subjectId;
  final String subjectName;

  @override
  State<SubjectAttendancePage> createState() => _SubjectAttendancePageState();
}

class _SubjectAttendancePageState extends State<SubjectAttendancePage> {
  final AttendanceService _attendanceService = AttendanceService();
  late Future<List<StudentSubjectAttendance>> _futureAttendance;

  @override
  void initState() {
    super.initState();
    _futureAttendance = _attendanceService.getStudentSubjectAttendance(widget.studentId, widget.subjectId);
  }



  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFF0D1B2E),
      body: SafeArea(
        child: FutureBuilder<List<StudentSubjectAttendance>>(
          future: _futureAttendance,
          builder: (context, snapshot) {
            if (snapshot.connectionState == ConnectionState.waiting) {
              return const Center(child: CircularProgressIndicator(color: Color(0xFF4FC3A1)));
            }
            if (snapshot.hasError) {
              return Center(child: Text('Error', style: TextStyle(color: Colors.white.withOpacity(0.5))));
            }

            final records = snapshot.data ?? [];
            final total = records.length;
            final present = records.where((r) => r.status.toLowerCase() == 'present').length;

            final pct = total > 0 ? (present / total * 100) : 0.0;
            final isCritical = pct < 75;
            final color = isCritical ? const Color(0xFFF07070) : const Color(0xFF4FC3A1);

            // Calculate classes needed to reach 75%
            int classesNeeded = 0;
            if (isCritical && total > 0) {
              int p = present;
              int t = total;
              while ((p / t * 100) < 75) { p++; t++; classesNeeded++; }
            }

            // Group records by month for calendar
            final Map<String, List<StudentSubjectAttendance>> byMonth = {};
            for (final r in records) {
              try {
                final dt = DateTime.parse(r.date);
                final key = DateFormat('MMMM yyyy').format(dt);
                byMonth.putIfAbsent(key, () => []);
                byMonth[key]!.add(r);
              } catch (_) {}
            }

            return Column(
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
                            Text('Back', style: TextStyle(fontSize: 14, color: Color(0xFF4FC3A1))),
                          ],
                        ),
                      ),
                    ],
                  ),
                ),

                // Content
                Expanded(
                  child: ListView(
                    padding: const EdgeInsets.symmetric(horizontal: 16),
                    children: [
                      // Title + chip
                      Text(widget.subjectName, style: const TextStyle(fontSize: 22, fontWeight: FontWeight.w500, color: Color(0xFFE8F0F8))),
                      const SizedBox(height: 4),
                      Row(
                        children: [
                          Container(
                            padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
                            decoration: BoxDecoration(
                              color: isCritical ? const Color(0xFF3A0E0E) : const Color(0xFF0E3A2A),
                              borderRadius: BorderRadius.circular(20),
                            ),
                            child: Text(
                              '${pct.toInt()}%${isCritical ? " — At Risk" : " — Good"}',
                              style: TextStyle(fontSize: 11, fontWeight: FontWeight.w500, color: color),
                            ),
                          ),
                        ],
                      ),
                      const SizedBox(height: 16),

                      // Big stat card
                      Container(
                        padding: const EdgeInsets.all(16),
                        decoration: BoxDecoration(
                          color: const Color(0xFF132236),
                          borderRadius: BorderRadius.circular(16),
                          border: Border.all(color: const Color(0xFF1E3248)),
                        ),
                        child: Row(
                          children: [
                            Expanded(
                              child: Column(
                                children: [
                                  Text('${pct.toInt()}%', style: TextStyle(fontSize: 36, fontWeight: FontWeight.w500, color: color)),
                                  const Text('Attendance', style: TextStyle(fontSize: 12, color: Color(0xFF7A93AB))),
                                ],
                              ),
                            ),
                            Container(width: 1, height: 48, color: const Color(0xFF1E3248)),
                            Expanded(
                              child: Column(
                                children: [
                                  Text('$present/$total', style: const TextStyle(fontSize: 24, fontWeight: FontWeight.w500, color: Color(0xFFE8F0F8))),
                                  const Text('Classes', style: TextStyle(fontSize: 12, color: Color(0xFF7A93AB))),
                                ],
                              ),
                            ),
                            Container(width: 1, height: 48, color: const Color(0xFF1E3248)),
                            Expanded(
                              child: Column(
                                children: [
                                  Text(
                                    isCritical ? '+$classesNeeded' : '✓',
                                    style: TextStyle(fontSize: 24, fontWeight: FontWeight.w500, color: isCritical ? const Color(0xFFE8B84B) : const Color(0xFF4FC3A1)),
                                  ),
                                  Text(
                                    isCritical ? 'Need to reach 75%' : 'On track',
                                    style: const TextStyle(fontSize: 12, color: Color(0xFF7A93AB)),
                                    textAlign: TextAlign.center,
                                  ),
                                ],
                              ),
                            ),
                          ],
                        ),
                      ),
                      const SizedBox(height: 16),

                      // Warning card (only if below 75%)
                      if (isCritical)
                        Container(
                          padding: const EdgeInsets.all(14),
                          margin: const EdgeInsets.only(bottom: 16),
                          decoration: BoxDecoration(
                            color: const Color(0xFF2E1A0E),
                            borderRadius: BorderRadius.circular(12),
                            border: Border.all(color: const Color(0xFF5E3A1A)),
                          ),
                          child: Row(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              const Text('⚠', style: TextStyle(fontSize: 18)),
                              const SizedBox(width: 10),
                              Expanded(
                                child: Column(
                                  crossAxisAlignment: CrossAxisAlignment.start,
                                  children: [
                                    const Text('Below 75% threshold', style: TextStyle(fontSize: 13, fontWeight: FontWeight.w500, color: Color(0xFFE8B84B))),
                                    const SizedBox(height: 2),
                                    Text(
                                      'You need to attend $classesNeeded more consecutive classes to reach the minimum requirement.',
                                      style: const TextStyle(fontSize: 12, color: Color(0xFFA07040)),
                                    ),
                                  ],
                                ),
                              ),
                            ],
                          ),
                        ),

                      // Calendar view per month
                      ...byMonth.entries.map((entry) {
                        final monthRecords = entry.value;
                        // Build a map of day -> status
                        final Map<int, String> dayStatus = {};
                        for (final r in monthRecords) {
                          try {
                            final dt = DateTime.parse(r.date);
                            dayStatus[dt.day] = r.status.toLowerCase();
                          } catch (_) {}
                        }

                        return Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Padding(
                              padding: const EdgeInsets.only(bottom: 10),
                              child: Text(
                                entry.key.toUpperCase(),
                                style: const TextStyle(fontSize: 11, color: Color(0xFF7A93AB), fontWeight: FontWeight.w500, letterSpacing: 0.8),
                              ),
                            ),
                            Container(
                              padding: const EdgeInsets.all(16),
                              margin: const EdgeInsets.only(bottom: 16),
                              decoration: BoxDecoration(
                                color: const Color(0xFF132236),
                                borderRadius: BorderRadius.circular(16),
                                border: Border.all(color: const Color(0xFF1E3248)),
                              ),
                              child: Column(
                                children: [
                                  // Day labels
                                  Row(
                                    mainAxisAlignment: MainAxisAlignment.spaceAround,
                                    children: ['M', 'T', 'W', 'T', 'F'].map((d) => Text(d, style: const TextStyle(fontSize: 10, color: Color(0xFF4A6278)))).toList(),
                                  ),
                                  const SizedBox(height: 10),
                                  // Calendar dots
                                  Wrap(
                                    spacing: 6,
                                    runSpacing: 6,
                                    alignment: WrapAlignment.center,
                                    children: dayStatus.entries.map((e) {
                                      final isPresent = e.value == 'present';
                                      return Container(
                                        width: 32,
                                        height: 32,
                                        decoration: BoxDecoration(
                                          shape: BoxShape.circle,
                                          color: isPresent ? const Color(0xFF0E3A2A) : const Color(0xFF3A0E0E),
                                        ),
                                        child: Center(
                                          child: Text(
                                            '${e.key}',
                                            style: TextStyle(
                                              fontSize: 11,
                                              fontWeight: FontWeight.w500,
                                              color: isPresent ? const Color(0xFF4FC3A1) : const Color(0xFFF07070),
                                            ),
                                          ),
                                        ),
                                      );
                                    }).toList(),
                                  ),
                                  const SizedBox(height: 12),
                                  // Legend
                                  Row(
                                    mainAxisAlignment: MainAxisAlignment.center,
                                    children: [
                                      _legendDot(const Color(0xFF4FC3A1), 'Present'),
                                      const SizedBox(width: 16),
                                      _legendDot(const Color(0xFFF07070), 'Absent'),
                                    ],
                                  ),
                                ],
                              ),
                            ),
                          ],
                        );
                      }),

                      // Datewise Record
                      const Padding(
                        padding: EdgeInsets.only(bottom: 8),
                        child: Text('DATEWISE RECORD', style: TextStyle(fontSize: 11, color: Color(0xFF7A93AB), fontWeight: FontWeight.w500, letterSpacing: 0.8)),
                      ),
                      Container(
                        padding: const EdgeInsets.all(16),
                        margin: const EdgeInsets.only(bottom: 16),
                        decoration: BoxDecoration(
                          color: const Color(0xFF132236),
                          borderRadius: BorderRadius.circular(16),
                          border: Border.all(color: const Color(0xFF1E3248)),
                        ),
                        child: Column(
                          children: records.asMap().entries.map((entry) {
                            final i = entry.key;
                            final r = entry.value;
                            final isPresent = r.status.toLowerCase() == 'present';
                            DateTime? dt;
                            try { dt = DateTime.parse(r.date); } catch (_) {}
                            final dateStr = dt != null ? DateFormat('d MMM, E').format(dt) : r.date;

                            return Container(
                              padding: const EdgeInsets.symmetric(vertical: 11),
                              decoration: BoxDecoration(
                                border: i < records.length - 1 ? const Border(bottom: BorderSide(color: Color(0xFF1A2E42))) : null,
                              ),
                              child: Row(
                                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                                children: [
                                  Text(dateStr, style: const TextStyle(fontSize: 13, color: Color(0xFFE8F0F8))),
                                  Container(
                                    padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
                                    decoration: BoxDecoration(
                                      color: isPresent ? const Color(0xFF0E3A2A) : const Color(0xFF3A0E0E),
                                      borderRadius: BorderRadius.circular(20),
                                    ),
                                    child: Text(
                                      isPresent ? 'Present' : 'Absent',
                                      style: TextStyle(fontSize: 11, fontWeight: FontWeight.w500, color: isPresent ? const Color(0xFF4FC3A1) : const Color(0xFFF07070)),
                                    ),
                                  ),
                                ],
                              ),
                            );
                          }).toList(),
                        ),
                      ),
                    ],
                  ),
                ),
              ],
            );
          },
        ),
      ),
    );
  }

  Widget _legendDot(Color color, String label) {
    return Row(
      children: [
        Container(width: 8, height: 8, decoration: BoxDecoration(shape: BoxShape.circle, color: color)),
        const SizedBox(width: 4),
        Text(label, style: TextStyle(fontSize: 11, color: color)),
      ],
    );
  }
}
