class AppConfig {
  static const String appName = 'Syncronik';

  // For Android emulator use 10.0.2.2, for physical device use your LAN IP.
  static const String baseUrl = 'http://192.168.31.140:8000';

  // Keep app usable while backend attendance APIs are under active development.
  static const bool enableMockFallback = false;
}
