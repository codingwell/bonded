import 'package:flutter/services.dart';

class BackgroundService {
  static const MethodChannel _channel = MethodChannel('bonded/native');
  static const EventChannel _eventChannel = EventChannel('bonded/background-events');

  /// Start VPN service that continues running in background
  static Future<void> startBackgroundService({
    required String deviceId,
  }) async {
    try {
      await _channel.invokeMethod<void>(
        'startBackgroundVpn',
        {
          'deviceId': deviceId,
        },
      );
    } on PlatformException catch (e) {
      throw BackgroundServiceException(
        'Failed to start background service: ${e.message}',
      );
    }
  }

  /// Stop background VPN service
  static Future<void> stopBackgroundService() async {
    try {
      await _channel.invokeMethod<void>('stopBackgroundVpn');
    } on PlatformException catch (e) {
      throw BackgroundServiceException(
        'Failed to stop background service: ${e.message}',
      );
    }
  }

  /// Get current background service status
  static Future<bool> isBackgroundVpnRunning() async {
    try {
      final bool running = await _channel.invokeMethod<bool>(
        'isBackgroundVpnRunning',
      ) ?? false;
      return running;
    } on PlatformException catch (e) {
      throw BackgroundServiceException(
        'Failed to get background service status: ${e.message}',
      );
    }
  }

  /// Listen for background service state changes
  static Stream<BackgroundServiceEvent> get backgroundEvents {
    return _eventChannel
        .receiveBroadcastStream()
        .map((dynamic event) => BackgroundServiceEvent.fromMap(
              Map<String, dynamic>.from(event as Map),
            ));
  }
}

class BackgroundServiceEvent {
  final String type; // 'started', 'stopped', 'error', 'connection_lost'
  final String? message;

  BackgroundServiceEvent({
    required this.type,
    this.message,
  });

  factory BackgroundServiceEvent.fromMap(Map<String, dynamic> map) {
    return BackgroundServiceEvent(
      type: map['type'] ?? 'unknown',
      message: map['message'],
    );
  }
}

class BackgroundServiceException implements Exception {
  final String message;
  BackgroundServiceException(this.message);

  @override
  String toString() => message;
}
