import 'package:flutter/material.dart';
import 'student_summary_page.dart';
import 'student_profile_page.dart';

class StudentMainShell extends StatefulWidget {
  const StudentMainShell({
    super.key,
    required this.studentId,
    this.user,
    this.onLogout,
  });

  final String studentId;
  final Map<String, dynamic>? user;
  final Future<void> Function()? onLogout;

  @override
  State<StudentMainShell> createState() => _StudentMainShellState();
}

class _StudentMainShellState extends State<StudentMainShell> {
  int _currentIndex = 0;

  late final List<Widget> _pages;

  @override
  void initState() {
    super.initState();
    _pages = [
      StudentSummaryPage(
        studentId: widget.studentId,
        user: widget.user,
        onLogout: widget.onLogout,
      ),
      StudentProfilePage(
        studentId: widget.studentId,
        user: widget.user,
        onLogout: widget.onLogout,
      ),
    ];
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: IndexedStack(
        index: _currentIndex,
        children: _pages,
      ),
      bottomNavigationBar: Container(
        decoration: const BoxDecoration(
          color: Color(0xFF0D1B2E),
          border: Border(top: BorderSide(color: Color(0xFF1E2F42), width: 1)),
        ),
        child: BottomNavigationBar(
          currentIndex: _currentIndex,
          onTap: (index) => setState(() => _currentIndex = index),
          backgroundColor: Colors.transparent,
          elevation: 0,
          selectedItemColor: const Color(0xFF4FC3A1),
          unselectedItemColor: const Color(0xFF4A6278),
          selectedFontSize: 11,
          unselectedFontSize: 11,
          showSelectedLabels: true,
          showUnselectedLabels: true,
          type: BottomNavigationBarType.fixed,
          items: const [
            BottomNavigationBarItem(
              icon: Icon(Icons.home_rounded, size: 18),
              label: 'Home',
            ),
            BottomNavigationBarItem(
              icon: Icon(Icons.person_rounded, size: 18),
              label: 'Profile',
            ),
          ],
        ),
      ),
    );
  }
}
