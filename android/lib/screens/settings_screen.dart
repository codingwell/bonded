import 'package:flutter/material.dart';

class SettingsScreen extends StatelessWidget {
  const SettingsScreen({super.key});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Settings')),
      body: ListView(
        children: [
          ListTile(
            title: const Text('About Bonded'),
            subtitle: const Text('App information and licenses'),
            trailing: const Icon(Icons.arrow_forward),
            onTap: () {
              showAboutDialog(
                context: context,
                applicationName: 'Bonded VPN',
                applicationVersion: '1.0.0',
                children: [
                  const Text(
                    'Bonded is a secure VPN solution with multi-path support.',
                  ),
                ],
              );
            },
          ),
          const Divider(),
          ListTile(
            title: const Text('Debug Info'),
            subtitle: const Text('View technical details'),
            trailing: const Icon(Icons.arrow_forward),
            onTap: () => _showDebugInfo(context),
          ),
        ],
      ),
    );
  }

  void _showDebugInfo(BuildContext context) {
    showDialog(
      context: context,
      builder:
          (context) => AlertDialog(
            title: const Text('Debug Information'),
            content: const SingleChildScrollView(
              child: Text(
                'Bonded VPN Android Client\n'
                'Version: 1.0.0\n'
                'Platform: Flutter 3.x\n'
                'Rust FFI: Enabled\n'
                '\n'
                'Features:\n'
                '- QR code pairing\n'
                '- Multi-path VPN\n'
                '- WebSocket + TLS support\n',
              ),
            ),
            actions: [
              TextButton(
                onPressed: Navigator.of(context).pop,
                child: const Text('Close'),
              ),
            ],
          ),
    );
  }
}
