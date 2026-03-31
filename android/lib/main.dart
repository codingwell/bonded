import 'package:flutter/material.dart';
import 'screens/home_screen.dart';
import 'screens/qr_scanner_screen.dart';
import 'screens/pairing_confirm_screen.dart';
import 'screens/dashboard_screen.dart';
import 'screens/server_config_screen.dart';
import 'screens/settings_screen.dart';
import 'models/pairing_model.dart';

void main() {
  runApp(const BondedApp());
}

class BondedApp extends StatelessWidget {
  const BondedApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Bonded',
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(seedColor: Colors.teal),
        useMaterial3: true,
      ),
      initialRoute: '/home',
      routes: {
        '/home': (context) => const HomeScreen(),
        '/qr-scanner': (context) => const QRScannerScreen(),
        '/settings': (context) => const SettingsScreen(),
      },
      onGenerateRoute: (settings) {
        if (settings.name == '/pairing-confirm') {
          final payload = settings.arguments as ServerPairingPayload?;
          if (payload != null) {
            return MaterialPageRoute(
              builder: (context) => PairingConfirmScreen(payload: payload),
            );
          }
        }
        if (settings.name == '/dashboard') {
          final args = settings.arguments as Map<String, dynamic>?;
          final deviceId = args?['deviceId'] as String? ?? '';
          return MaterialPageRoute(
            builder: (context) => DashboardScreen(deviceId: deviceId),
          );
        }
        if (settings.name == '/server-config') {
          final server = settings.arguments as PairedServer?;
          if (server != null) {
            return MaterialPageRoute(
              builder: (context) => ServerConfigScreen(server: server),
            );
          }
        }
        return null;
      },
      onUnknownRoute: (settings) {
        return MaterialPageRoute(builder: (context) => const HomeScreen());
      },
    );
  }
}
