import 'package:flutter/material.dart';

import '../auth/auth_service.dart';
import '../auth/login_page.dart';
import 'splash_screen.dart';
import '../student/student_main_shell.dart';
import '../teacher/teacher_subjects_page.dart';

class AppShell extends StatefulWidget {
  const AppShell({
    super.key,
    this.initialUser,
  });

  final Map<String, dynamic>? initialUser;

  @override
  State<AppShell> createState() => _AppShellState();
}

class _AppShellState extends State<AppShell> {
  final AuthService _authService = AuthService();
  Map<String, dynamic>? _user;
  bool _booting = true;

  @override
  void initState() {
    super.initState();
    _bootstrap();
  }

  Future<void> _bootstrap() async {
    await Future<void>.delayed(const Duration(milliseconds: 1200));
    if (!mounted) return;
    setState(() {
      _user = widget.initialUser;
      _booting = false;
    });
  }

  Future<void> _logout() async {
    await _authService.logout();
    if (!mounted) return;
    setState(() {
      _user = null;
    });
  }

  @override
  Widget build(BuildContext context) {
    if (_booting) {
      return const SplashScreen();
    }

    if (_user == null) {
      return LoginPage(
        onAuthenticated: (user) {
          setState(() {
            _user = user;
          });
        },
      );
    }

    final designation = ((_user!['designation'] as Map?)?['code'] ?? '').toString().toUpperCase();
    final userId = (_user!['user_id'] ?? '').toString().toUpperCase();

    final isTeacher = designation == 'TEACHER' ||
        designation.contains('TEACH') ||
        designation == 'FACULTY' ||
        userId.startsWith('EMP');
    final isAdmin = designation == 'ADMIN' || designation == 'SUPERADMIN';

    if (!isTeacher && !isAdmin) {
      return StudentMainShell(
        studentId: userId,
        user: _user,
        onLogout: _logout,
      );
    }

    return TeacherSubjectsPage(
      teacherId: userId,
      user: _user,
      onLogout: _logout,
    );
  }
}
