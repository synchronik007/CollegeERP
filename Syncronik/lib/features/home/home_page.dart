import 'package:flutter/material.dart';

import '../teacher/teacher_subjects_page.dart';
import '../student/student_summary_page.dart';

class HomePage extends StatelessWidget {
  const HomePage({super.key});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Syncronik Attendance')),
      body: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            const SizedBox(height: 24),
            const Text(
              'Choose role',
              style: TextStyle(fontSize: 24, fontWeight: FontWeight.bold),
            ),
            const SizedBox(height: 20),
            ElevatedButton.icon(
              onPressed: () {
                Navigator.of(context).push(
                  MaterialPageRoute(
                    builder: (_) => const TeacherSubjectsPage(teacherId: '1'),
                  ),
                );
              },
              icon: const Icon(Icons.school_outlined),
              label: const Text('Teacher Flow'),
            ),
            const SizedBox(height: 12),
            OutlinedButton.icon(
              onPressed: () {
                Navigator.of(context).push(
                  MaterialPageRoute(
                    builder: (_) => const StudentSummaryPage(studentId: '1'),
                  ),
                );
              },
              icon: const Icon(Icons.person_outline),
              label: const Text('Student Summary Flow'),
            ),
            const SizedBox(height: 24),
            const Text(
              'This build is wired to your attendance API contract with mock fallback enabled for incomplete endpoints.',
            ),
          ],
        ),
      ),
    );
  }
}
