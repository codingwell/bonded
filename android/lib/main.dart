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

  Future<void> _refreshStatus() async {
    final int version =
        await _channel.invokeMethod<int>('getNativeApiVersion') ?? -1;

    setState(() {
      _status =
          version >= 0 ? 'Rust bridge API version: $version' : 'Rust bridge unavailable';
    });
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
            const SizedBox(height: 16),
            ElevatedButton(
              onPressed: _refreshStatus,
              child: const Text('Refresh bridge status'),
            ),
          ],
        ),
      ),
    );
  }
}
