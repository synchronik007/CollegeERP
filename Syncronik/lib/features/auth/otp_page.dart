import 'package:flutter/material.dart';
import 'dart:convert';

import 'auth_service.dart';

class OtpPage extends StatefulWidget {
  const OtpPage({
    super.key,
    required this.userId,
    required this.maskedEmail,
    required this.onVerified,
  });

  final String userId;
  final String maskedEmail;
  final void Function(Map<String, dynamic> user) onVerified;

  @override
  State<OtpPage> createState() => _OtpPageState();
}

class _OtpPageState extends State<OtpPage> with SingleTickerProviderStateMixin {
  final _otpController = TextEditingController();
  final AuthService _authService = AuthService();

  bool _loading = false;
  String? _error;
  int _timer = 180;
  bool _resendDisabled = true;

  late AnimationController _animController;
  late Animation<double> _fadeIn;

  String _extractMessage(Object error) {
    final text = error.toString();
    try {
      final jsonStart = text.indexOf('{');
      if (jsonStart >= 0) {
        final parsed = jsonDecode(text.substring(jsonStart));
        if (parsed is Map<String, dynamic>) {
          final message = parsed['message']?.toString();
          if (message != null && message.isNotEmpty) {
            return message;
          }
        }
      }
    } catch (_) {
      // Fallback
    }

    if (text.contains('HTTP 400')) {
      return 'Invalid OTP. Please enter the latest code.';
    }
    if (text.contains('SocketException')) {
      return 'Network issue. Please check internet and try again.';
    }
    return 'OTP verification failed. Please try again.';
  }

  @override
  void initState() {
    super.initState();
    _startTimer();

    _animController = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 600),
    );
    _fadeIn = CurvedAnimation(parent: _animController, curve: Curves.easeOut);
    _animController.forward();
  }

  void _startTimer() {
    _timer = 180;
    _resendDisabled = true;
    Future.doWhile(() async {
      if (!mounted || _timer <= 0) {
        if (mounted) {
          setState(() {
            _resendDisabled = false;
          });
        }
        return false;
      }
      await Future<void>.delayed(const Duration(seconds: 1));
      if (!mounted) return false;
      setState(() {
        _timer -= 1;
      });
      return _timer > 0;
    });
  }

  String _formatTime(int seconds) {
    final mins = seconds ~/ 60;
    final secs = seconds % 60;
    return '$mins:${secs.toString().padLeft(2, '0')}';
  }

  @override
  void dispose() {
    _animController.dispose();
    _otpController.dispose();
    super.dispose();
  }

  Future<void> _verify() async {
    final otp = _otpController.text.trim();
    if (otp.length != 6) {
      setState(() => _error = 'Please enter a valid 6-digit OTP');
      return;
    }

    setState(() {
      _loading = true;
      _error = null;
    });

    try {
      final response = await _authService.verifyOtp(userId: widget.userId, otp: otp);

      if (!mounted) return;

      if ((response['status'] ?? '').toString().toLowerCase() != 'success') {
        setState(() {
          _error = (response['message'] ?? 'OTP verification failed').toString();
        });
        return;
      }

      final user = (response['user'] as Map<String, dynamic>? ?? <String, dynamic>{});
      widget.onVerified(user);

      Navigator.of(context).popUntil((route) => route.isFirst);
    } catch (e) {
      setState(() => _error = _extractMessage(e));
    } finally {
      if (mounted) {
        setState(() => _loading = false);
      }
    }
  }

  Future<void> _resendOtp() async {
    if (_resendDisabled || _loading) return;

    setState(() {
      _loading = true;
      _error = null;
    });

    try {
      final response = await _authService.sendOtp(userId: widget.userId);
      if ((response['status'] ?? '').toString().toLowerCase() != 'success') {
        setState(() {
          _error = (response['message'] ?? 'Failed to resend OTP').toString();
        });
        return;
      }

      if (!mounted) return;
      setState(() {
        _otpController.clear();
      });
      _startTimer();
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('OTP resent successfully')),
      );
    } catch (e) {
      setState(() => _error = _extractMessage(e));
    } finally {
      if (mounted) setState(() => _loading = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
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
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              // Back Button
              Padding(
                padding: const EdgeInsets.all(16),
                child: GestureDetector(
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
              ),
              Expanded(
                child: Center(
                  child: SingleChildScrollView(
                    padding: const EdgeInsets.all(24),
                    child: FadeTransition(
                      opacity: _fadeIn,
                      child: Column(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          // Lock Icon
                          Container(
                            width: 80,
                            height: 80,
                            decoration: BoxDecoration(
                              shape: BoxShape.circle,
                              gradient: const LinearGradient(
                                colors: [Color(0xFF6C63FF), Color(0xFF9D4EDD)],
                              ),
                              boxShadow: [
                                BoxShadow(
                                  color: const Color(0xFF6C63FF).withOpacity(0.4),
                                  blurRadius: 24,
                                  offset: const Offset(0, 8),
                                ),
                              ],
                            ),
                            child: const Icon(Icons.lock_person_rounded, size: 40, color: Colors.white),
                          ),
                          const SizedBox(height: 36),

                          // Card
                          Container(
                            decoration: BoxDecoration(
                              borderRadius: BorderRadius.circular(20),
                              color: Colors.white.withOpacity(0.06),
                              border: Border.all(color: Colors.white.withOpacity(0.1)),
                              boxShadow: [
                                BoxShadow(
                                  color: Colors.black.withOpacity(0.2),
                                  blurRadius: 20,
                                  offset: const Offset(0, 10),
                                ),
                              ],
                            ),
                            child: Padding(
                              padding: const EdgeInsets.all(24),
                              child: Column(
                                crossAxisAlignment: CrossAxisAlignment.stretch,
                                children: [
                                  const Text(
                                    'Verify Email OTP',
                                    style: TextStyle(
                                      fontSize: 22,
                                      fontWeight: FontWeight.w700,
                                      color: Colors.white,
                                    ),
                                  ),
                                  const SizedBox(height: 6),
                                  Text(
                                    'Code sent to ${widget.maskedEmail}',
                                    style: TextStyle(
                                      fontSize: 14,
                                      color: Colors.white.withOpacity(0.6),
                                    ),
                                  ),
                                  const SizedBox(height: 24),

                                  TextField(
                                    controller: _otpController,
                                    keyboardType: TextInputType.number,
                                    maxLength: 6,
                                    style: const TextStyle(
                                      color: Colors.white,
                                      letterSpacing: 4,
                                      fontWeight: FontWeight.w600,
                                      fontSize: 18,
                                    ),
                                    textAlign: TextAlign.center,
                                    decoration: InputDecoration(
                                      labelText: 'Enter 6-digit OTP',
                                      counterText: '',
                                      prefixIcon: Icon(Icons.password_outlined, color: Colors.white.withOpacity(0.5)),
                                    ),
                                  ),
                                  const SizedBox(height: 12),

                                  // Timer
                                  Row(
                                    mainAxisAlignment: MainAxisAlignment.center,
                                    children: [
                                      Icon(Icons.timer_outlined, size: 14, color: Colors.white.withOpacity(0.5)),
                                      const SizedBox(width: 6),
                                      Text(
                                        'Expires in: ${_formatTime(_timer)}',
                                        style: TextStyle(
                                          fontSize: 13,
                                          fontWeight: FontWeight.w600,
                                          color: _timer < 60 ? const Color(0xFFEF5350) : Colors.white.withOpacity(0.5),
                                        ),
                                      ),
                                    ],
                                  ),
                                  const SizedBox(height: 20),

                                  if (_error != null)
                                    Container(
                                      margin: const EdgeInsets.only(bottom: 16),
                                      padding: const EdgeInsets.all(12),
                                      decoration: BoxDecoration(
                                        color: const Color(0xFFEF5350).withOpacity(0.15),
                                        borderRadius: BorderRadius.circular(12),
                                        border: Border.all(color: const Color(0xFFEF5350).withOpacity(0.3)),
                                      ),
                                      child: Row(
                                        children: [
                                          const Icon(Icons.error_outline, color: Color(0xFFEF5350), size: 20),
                                          const SizedBox(width: 10),
                                          Expanded(
                                            child: Text(
                                              _error!,
                                              style: const TextStyle(color: Color(0xFFEF5350), fontSize: 13),
                                            ),
                                          ),
                                        ],
                                      ),
                                    ),

                                  // Verify Button
                                  Container(
                                    decoration: BoxDecoration(
                                      borderRadius: BorderRadius.circular(14),
                                      gradient: const LinearGradient(
                                        colors: [Color(0xFF6C63FF), Color(0xFF9D4EDD)],
                                      ),
                                      boxShadow: [
                                        BoxShadow(
                                          color: const Color(0xFF6C63FF).withOpacity(0.4),
                                          blurRadius: 12,
                                          offset: const Offset(0, 4),
                                        ),
                                      ],
                                    ),
                                    child: ElevatedButton(
                                      onPressed: _loading ? null : _verify,
                                      style: ElevatedButton.styleFrom(
                                        backgroundColor: Colors.transparent,
                                        shadowColor: Colors.transparent,
                                        padding: const EdgeInsets.symmetric(vertical: 16),
                                        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(14)),
                                      ),
                                      child: _loading
                                          ? const SizedBox(
                                              width: 20,
                                              height: 20,
                                              child: CircularProgressIndicator(strokeWidth: 2, color: Colors.white),
                                            )
                                          : const Text(
                                              'Verify & Login',
                                              style: TextStyle(fontSize: 16, fontWeight: FontWeight.w600, color: Colors.white),
                                            ),
                                    ),
                                  ),
                                  const SizedBox(height: 16),

                                  // Resend
                                  TextButton(
                                    onPressed: _resendDisabled || _loading ? null : _resendOtp,
                                    style: TextButton.styleFrom(
                                      foregroundColor: const Color(0xFF6C63FF),
                                    ),
                                    child: const Text('Resend New Code'),
                                  ),
                                ],
                              ),
                            ),
                          ),
                        ],
                      ),
                    ),
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
