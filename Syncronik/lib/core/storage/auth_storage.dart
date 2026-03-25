import 'dart:convert';

import 'package:flutter/services.dart';
import 'package:shared_preferences/shared_preferences.dart';

class AuthStorage {
  static const _tokenKey = 'auth_token';
  static const _refreshTokenKey = 'auth_refresh_token';
  static const _userKey = 'auth_user';
  static final Map<String, String> _memoryFallback = <String, String>{};

  Future<SharedPreferences?> _safePrefs() async {
    try {
      return await SharedPreferences.getInstance();
    } on MissingPluginException {
      return null;
    }
  }

  Future<void> saveAuth({
    required String token,
    required String refreshToken,
    required Map<String, dynamic> user,
  }) async {
    final encodedUser = jsonEncode(user);
    _memoryFallback[_tokenKey] = token;
    _memoryFallback[_refreshTokenKey] = refreshToken;
    _memoryFallback[_userKey] = encodedUser;

    final prefs = await _safePrefs();
    if (prefs == null) {
      return;
    }

    await prefs.setString(_tokenKey, token);
    await prefs.setString(_refreshTokenKey, refreshToken);
    await prefs.setString(_userKey, encodedUser);
  }

  Future<String?> getToken() async {
    final prefs = await _safePrefs();
    return prefs?.getString(_tokenKey) ?? _memoryFallback[_tokenKey];
  }

  Future<Map<String, dynamic>?> getUser() async {
    final prefs = await _safePrefs();
    final raw = prefs?.getString(_userKey) ?? _memoryFallback[_userKey];
    if (raw == null || raw.isEmpty) {
      return null;
    }
    return jsonDecode(raw) as Map<String, dynamic>;
  }

  Future<void> clear() async {
    _memoryFallback.remove(_tokenKey);
    _memoryFallback.remove(_refreshTokenKey);
    _memoryFallback.remove(_userKey);

    final prefs = await _safePrefs();
    if (prefs == null) {
      return;
    }

    await prefs.remove(_tokenKey);
    await prefs.remove(_refreshTokenKey);
    await prefs.remove(_userKey);
  }
}
