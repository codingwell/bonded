import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

class NetworkTestsScreen extends StatefulWidget {
  const NetworkTestsScreen({super.key});

  @override
  State<NetworkTestsScreen> createState() => _NetworkTestsScreenState();
}

class _NetworkTestsScreenState extends State<NetworkTestsScreen> {
  static const MethodChannel _channel = MethodChannel('bonded/native');

  final TextEditingController _dnsHostController = TextEditingController(
    text: 'unifi.g.codingwell.net',
  );
  final TextEditingController _dnsExpectedIpController = TextEditingController(
    text: '34.82.88.79',
  );
  final TextEditingController _tcpHostController = TextEditingController(
    text: 'example.com',
  );
  final TextEditingController _tcpPortController = TextEditingController(
    text: '443',
  );
  final TextEditingController _httpUrlController = TextEditingController(
    text: 'https://example.com',
  );

  String _lastResult = 'No tests run yet.';
  bool _running = false;
  bool _autoRefreshLogs = true;
  bool _loadingLogs = false;
  List<String> _logs = const [];
  Timer? _logRefreshTimer;

  @override
  void initState() {
    super.initState();
    _refreshLogs();
    _setAutoRefresh(true);
  }

  void _setAutoRefresh(bool enabled) {
    _logRefreshTimer?.cancel();
    if (!enabled) {
      return;
    }
    _logRefreshTimer = Timer.periodic(const Duration(seconds: 2), (_) {
      _refreshLogs();
    });
  }

  Future<void> _refreshLogs() async {
    if (_loadingLogs) return;
    setState(() {
      _loadingLogs = true;
    });
    try {
      final logs = await _channel.invokeMethod<List<dynamic>>(
        'getNetworkTestLogs',
      );
      if (!mounted) return;
      setState(() {
        _logs = (logs ?? const []).map((e) => e.toString()).toList();
      });
    } on PlatformException {
      if (!mounted) return;
      setState(() {
        _logs = const ['Failed to load logs from native layer.'];
      });
    } finally {
      if (mounted) {
        setState(() {
          _loadingLogs = false;
        });
      }
    }
  }

  Future<void> _clearLogs() async {
    try {
      await _channel.invokeMethod<void>('clearNetworkTestLogs');
      if (!mounted) return;
      setState(() {
        _logs = const [];
      });
    } on PlatformException catch (e) {
      if (!mounted) return;
      setState(() {
        _lastResult = 'Failed to clear logs: ${e.code} ${e.message ?? ''}';
      });
    }
  }

  Future<void> _runTest(String action, {Map<String, dynamic>? extras}) async {
    setState(() {
      _running = true;
      _lastResult = 'Running $action...';
    });

    try {
      final payload = <String, dynamic>{'action': action, ...?extras};
      await _channel.invokeMethod<String>('runNetworkTest', payload);
      await Future<void>.delayed(const Duration(milliseconds: 350));
      await _refreshLogs();
      if (!mounted) return;
      setState(() {
        _lastResult = 'Sent $action at ${DateTime.now().toIso8601String()}';
      });
    } on PlatformException catch (e) {
      if (!mounted) return;
      setState(() {
        _lastResult = 'Failed to send $action: ${e.code} ${e.message ?? ''}';
      });
    } finally {
      if (mounted) {
        setState(() {
          _running = false;
        });
      }
    }
  }

  @override
  void dispose() {
    _logRefreshTimer?.cancel();
    _dnsHostController.dispose();
    _dnsExpectedIpController.dispose();
    _tcpHostController.dispose();
    _tcpPortController.dispose();
    _httpUrlController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Network Tests')),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          Text(
            'Run Android network diagnostics from inside the app.',
            style: Theme.of(context).textTheme.bodyMedium,
          ),
          const SizedBox(height: 12),
          Card(
            child: Padding(
              padding: const EdgeInsets.all(12),
              child: Text(_lastResult),
            ),
          ),
          const SizedBox(height: 12),
          Wrap(
            spacing: 8,
            runSpacing: 8,
            children: [
              ElevatedButton(
                onPressed: _running
                    ? null
                    : () => _runTest('com.bonded.bonded_app.TEST_VPN_PREPARED'),
                child: const Text('VPN Prepared'),
              ),
              ElevatedButton(
                onPressed: _running
                    ? null
                    : () => _runTest('com.bonded.bonded_app.TEST_VPN_STATUS'),
                child: const Text('VPN Status'),
              ),
              ElevatedButton(
                onPressed: _running
                    ? null
                    : () => _runTest('com.bonded.bonded_app.TEST_VPN_CONNECT'),
                child: const Text('VPN Connect'),
              ),
              ElevatedButton(
                onPressed: _running
                    ? null
                    : () =>
                          _runTest('com.bonded.bonded_app.TEST_VPN_DISCONNECT'),
                child: const Text('VPN Disconnect'),
              ),
              ElevatedButton(
                onPressed: _running
                    ? null
                    : () => _runTest(
                        'com.bonded.bonded_app.TEST_HTTP_CODINGWELL',
                      ),
                child: const Text('HTTP Codingwell'),
              ),
              OutlinedButton(
                onPressed: _running
                    ? null
                    : () => _runTest('com.bonded.bonded_app.TEST_ALL'),
                child: const Text('Run TEST_ALL'),
              ),
            ],
          ),
          const SizedBox(height: 20),
          TextField(
            controller: _dnsHostController,
            decoration: const InputDecoration(
              labelText: 'DNS host',
              border: OutlineInputBorder(),
            ),
          ),
          const SizedBox(height: 8),
          TextField(
            controller: _dnsExpectedIpController,
            decoration: const InputDecoration(
              labelText: 'Expected IP (optional)',
              border: OutlineInputBorder(),
            ),
          ),
          const SizedBox(height: 8),
          ElevatedButton(
            onPressed: _running
                ? null
                : () => _runTest(
                    'com.bonded.bonded_app.TEST_DNS',
                    extras: {
                      'host': _dnsHostController.text.trim(),
                      'expected_ip': _dnsExpectedIpController.text.trim(),
                    },
                  ),
            child: const Text('Run DNS Test'),
          ),
          const SizedBox(height: 16),
          TextField(
            controller: _tcpHostController,
            decoration: const InputDecoration(
              labelText: 'TCP host',
              border: OutlineInputBorder(),
            ),
          ),
          const SizedBox(height: 8),
          TextField(
            controller: _tcpPortController,
            keyboardType: TextInputType.number,
            decoration: const InputDecoration(
              labelText: 'TCP port',
              border: OutlineInputBorder(),
            ),
          ),
          const SizedBox(height: 8),
          ElevatedButton(
            onPressed: _running
                ? null
                : () => _runTest(
                    'com.bonded.bonded_app.TEST_TCP',
                    extras: {
                      'host': _tcpHostController.text.trim(),
                      'port':
                          int.tryParse(_tcpPortController.text.trim()) ?? 443,
                    },
                  ),
            child: const Text('Run TCP Test'),
          ),
          const SizedBox(height: 16),
          TextField(
            controller: _httpUrlController,
            decoration: const InputDecoration(
              labelText: 'HTTP/HTTPS URL',
              border: OutlineInputBorder(),
            ),
          ),
          const SizedBox(height: 8),
          ElevatedButton(
            onPressed: _running
                ? null
                : () => _runTest(
                    'com.bonded.bonded_app.TEST_HTTP',
                    extras: {'url': _httpUrlController.text.trim()},
                  ),
            child: const Text('Run HTTP Test'),
          ),
          const SizedBox(height: 20),
          Row(
            children: [
              Text(
                'In-app Logs',
                style: Theme.of(context).textTheme.titleMedium,
              ),
              const Spacer(),
              const Text('Auto refresh'),
              Switch(
                value: _autoRefreshLogs,
                onChanged: (value) {
                  setState(() {
                    _autoRefreshLogs = value;
                  });
                  _setAutoRefresh(value);
                },
              ),
            ],
          ),
          const SizedBox(height: 8),
          Wrap(
            spacing: 8,
            runSpacing: 8,
            children: [
              OutlinedButton.icon(
                onPressed: _loadingLogs ? null : _refreshLogs,
                icon: const Icon(Icons.refresh),
                label: const Text('Refresh Logs'),
              ),
              OutlinedButton.icon(
                onPressed: _logs.isEmpty ? null : _clearLogs,
                icon: const Icon(Icons.clear_all),
                label: const Text('Clear Logs'),
              ),
            ],
          ),
          const SizedBox(height: 8),
          Container(
            height: 260,
            padding: const EdgeInsets.all(10),
            decoration: BoxDecoration(
              color: Colors.black,
              borderRadius: BorderRadius.circular(8),
            ),
            child: _logs.isEmpty
                ? const Center(
                    child: Text(
                      'No logs yet. Run a test.',
                      style: TextStyle(color: Colors.white70),
                    ),
                  )
                : ListView.builder(
                    itemCount: _logs.length,
                    itemBuilder: (context, index) {
                      return SelectableText(
                        _logs[index],
                        style: const TextStyle(
                          color: Colors.white,
                          fontFamily: 'monospace',
                          fontSize: 12,
                        ),
                      );
                    },
                  ),
          ),
        ],
      ),
    );
  }
}
