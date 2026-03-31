import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

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
      ),
      home: const BridgeStatusScreen(),
    );
  }
}

class BridgeStatusScreen extends StatefulWidget {
  const BridgeStatusScreen({super.key});

  @override
  State<BridgeStatusScreen> createState() => _BridgeStatusScreenState();
}

class _BridgeStatusScreenState extends State<BridgeStatusScreen> {
  static const MethodChannel _channel = MethodChannel('bonded/native');
  String _status = 'Unknown';
  String _vpnStatus = 'Stopped';

  Future<void> _refreshStatus() async {
    try {
      final int version =
          await _channel.invokeMethod<int>('getNativeApiVersion') ?? -1;
      final bool vpnRunning =
          await _channel.invokeMethod<bool>('getVpnStatus') ?? false;

      setState(() {
        _status =
            version >= 0 ? 'Rust bridge API version: $version' : 'Rust bridge unavailable';
        _vpnStatus = vpnRunning ? 'Running' : 'Stopped';
      });
    } on PlatformException {
      setState(() {
        _status = 'Bridge unavailable';
        _vpnStatus = 'Unknown';
      });
    } on MissingPluginException {
      setState(() {
        _status = 'Bridge unavailable';
        _vpnStatus = 'Unknown';
      });
    }
  }

  Future<void> _startVpn() async {
    await _channel.invokeMethod<String>('startVpnService');
    await _refreshStatus();
  }

  Future<void> _stopVpn() async {
    await _channel.invokeMethod<String>('stopVpnService');
    await _refreshStatus();
  }

  @override
  void initState() {
    super.initState();
    _refreshStatus();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        backgroundColor: Theme.of(context).colorScheme.inversePrimary,
        title: const Text('Bonded Android Shell'),
      ),
      body: Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: <Widget>[
            const Text('Bridge status'),
            Text(
              _status,
              style: Theme.of(context).textTheme.headlineMedium,
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 12),
            Text('VPN status: $_vpnStatus'),
            const SizedBox(height: 16),
            ElevatedButton(
              onPressed: _refreshStatus,
              child: const Text('Refresh bridge status'),
            ),
            const SizedBox(height: 8),
            ElevatedButton(
              onPressed: _startVpn,
              child: const Text('Start VPN'),
            ),
            const SizedBox(height: 8),
            ElevatedButton(
              onPressed: _stopVpn,
              child: const Text('Stop VPN'),
            ),
          ],
        ),
      ),
    );
  }
}
