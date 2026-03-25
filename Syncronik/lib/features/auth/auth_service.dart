import '../../core/network/api_client.dart';
import '../../core/network/api_client_provider.dart';
import '../../core/storage/auth_storage.dart';

class AuthService {
  AuthService({ApiClient? apiClient, AuthStorage? authStorage})
      : _apiClient = apiClient ?? appApiClient,
        _authStorage = authStorage ?? AuthStorage();

  final ApiClient _apiClient;
  final AuthStorage _authStorage;

  Future<Map<String, dynamic>> login({
    required String userId,
    required String password,
  }) {
    return _apiClient.postJson(
      '/api/auth/login/',
      body: {
        'user_id': userId.toUpperCase(),
        'password': password,
      },
    );
  }

  Future<Map<String, dynamic>> verifyOtp({
    required String userId,
    required String otp,
  }) async {
    final response = await _apiClient.postJson(
      '/api/auth/verify-otp/',
      body: {
        'user_id': userId.toUpperCase(),
        'otp': otp,
      },
    );

    if (response['status'] == 'success') {
      final token = (response['token'] ?? '').toString();
      final refresh = (response['refresh'] ?? '').toString();
      final user = (response['user'] as Map<String, dynamic>? ?? <String, dynamic>{});
      await _authStorage.saveAuth(token: token, refreshToken: refresh, user: user);
      _apiClient.setAuthToken(token);
    }

    return response;
  }

  Future<Map<String, dynamic>> sendOtp({
    required String userId,
  }) {
    return _apiClient.postJson(
      '/api/auth/send-otp/',
      body: {
        'user_id': userId.toUpperCase(),
      },
    );
  }

  Future<Map<String, dynamic>?> restoreSession() async {
    final token = await _authStorage.getToken();
    final user = await _authStorage.getUser();
    _apiClient.setAuthToken(token);

    if (token == null || user == null) {
      return null;
    }

    return {
      'token': token,
      'user': user,
    };
  }

  Future<void> logout() async {
    await _authStorage.clear();
    _apiClient.setAuthToken(null);
  }
}
