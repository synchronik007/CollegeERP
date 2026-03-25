import 'dart:convert';

import 'package:http/http.dart' as http;

import '../config/app_config.dart';

class ApiClient {
  ApiClient({http.Client? client}) : _client = client ?? http.Client();

  final http.Client _client;
  String? _authToken;

  void setAuthToken(String? token) {
    _authToken = token;
  }

  Uri _uri(String path, [Map<String, String>? queryParameters]) {
    final normalized = path.startsWith('/') ? path : '/$path';
    return Uri.parse('${AppConfig.baseUrl}$normalized').replace(
      queryParameters: queryParameters,
    );
  }

  Future<Map<String, dynamic>> getJson(
    String path, {
    Map<String, String>? queryParameters,
    Map<String, String>? headers,
  }) async {
    final response = await _client.get(
      _uri(path, queryParameters),
      headers: _headers(headers),
    ).timeout(const Duration(seconds: 10));
    return _decodeJsonObject(response);
  }

  Future<List<dynamic>> getJsonList(
    String path, {
    Map<String, String>? queryParameters,
    Map<String, String>? headers,
  }) async {
    final response = await _client.get(
      _uri(path, queryParameters),
      headers: _headers(headers),
    ).timeout(const Duration(seconds: 10));
    return _decodeJsonArray(response);
  }

  Future<Map<String, dynamic>> postJson(
    String path, {
    required Map<String, dynamic> body,
    Map<String, String>? headers,
  }) async {
    final response = await _client.post(
      _uri(path),
      headers: _headers(headers),
      body: jsonEncode(body),
    ).timeout(const Duration(seconds: 10));
    return _decodeJsonObject(response);
  }

  Future<Map<String, dynamic>> patchJson(
    String path, {
    required Map<String, dynamic> body,
    Map<String, String>? headers,
  }) async {
    final response = await _client.patch(
      _uri(path),
      headers: _headers(headers),
      body: jsonEncode(body),
    ).timeout(const Duration(seconds: 10));
    return _decodeJsonObject(response);
  }

  Map<String, String> _headers(Map<String, String>? extra) {
    return {
      'Content-Type': 'application/json',
      if (_authToken != null && _authToken!.isNotEmpty)
        'Authorization': 'Bearer $_authToken',
      ...?extra,
    };
  }

  Map<String, dynamic> _decodeJsonObject(http.Response response) {
    if (response.statusCode < 200 || response.statusCode >= 300) {
      throw Exception('HTTP ${response.statusCode}: ${response.body}');
    }

    if (response.body.trim().isEmpty) {
      return <String, dynamic>{};
    }

    final decoded = jsonDecode(response.body);
    if (decoded is Map<String, dynamic>) {
      return decoded;
    }

    throw Exception('Expected JSON object but got ${decoded.runtimeType}');
  }

  List<dynamic> _decodeJsonArray(http.Response response) {
    if (response.statusCode < 200 || response.statusCode >= 300) {
      throw Exception('HTTP ${response.statusCode}: ${response.body}');
    }

    if (response.body.trim().isEmpty) {
      return <dynamic>[];
    }

    final decoded = jsonDecode(response.body);
    if (decoded is List<dynamic>) {
      return decoded;
    }

    throw Exception('Expected JSON list but got ${decoded.runtimeType}');
  }
}
