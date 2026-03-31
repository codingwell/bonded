import 'package:flutter/material.dart';

/// Helper class for displaying persistent notifications when VPN runs in background
class BackgroundNotificationHelper {
  static void showBackgroundVpnNotification(
    BuildContext context,
    bool isRunning,
    String serverAddress,
  ) {
    if (isRunning) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Row(
            children: [
              const Icon(Icons.vpn_lock, color: Colors.white),
              const SizedBox(width: 12),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    const Text(
                      'VPN Running in Background',
                      style: TextStyle(fontWeight: FontWeight.bold),
                    ),
                    Text(
                      'Connected to $serverAddress',
                      style: const TextStyle(fontSize: 12),
                    ),
                  ],
                ),
              ),
            ],
          ),
          backgroundColor: Colors.green[700],
          duration: const Duration(seconds: 4),
        ),
      );
    }
  }

  /// Display a persistent notification indicator in the app
  static Widget buildBackgroundIndicator(bool isRunning, String serverAddress) {
    if (!isRunning) {
      return const SizedBox.shrink();
    }

    return Material(
      color: Colors.green[100],
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
        child: Row(
          children: [
            const Icon(Icons.cloud_done, color: Colors.green, size: 20),
            const SizedBox(width: 12),
            Expanded(
              child: Text(
                'Background VPN Active: $serverAddress',
                style: const TextStyle(
                  fontSize: 13,
                  color: Colors.green,
                  fontWeight: FontWeight.w500,
                ),
                maxLines: 1,
                overflow: TextOverflow.ellipsis,
              ),
            ),
          ],
        ),
      ),
    );
  }
}
