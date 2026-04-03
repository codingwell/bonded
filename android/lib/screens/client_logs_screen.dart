import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

class ClientLogsScreen extends StatefulWidget {
  const ClientLogsScreen({super.key});

  @override
  State<ClientLogsScreen> createState() => _ClientLogsScreenState();
}

class _ClientLogsScreenState extends State<ClientLogsScreen> {
  static const MethodChannel _channel = MethodChannel('bonded/native');

  final ScrollController _scrollController = ScrollController();
  Timer? _refreshTimer;

  List<String> _logs = const [];
  bool _loading = false;
  String? _error;
  bool _autoRefresh = true;

  @override
  void initState() {
    super.initState();
    _refreshLogs();
    _startAutoRefresh();
  }

  @override
  void dispose() {
    _refreshTimer?.cancel();
    _scrollController.dispose();
    super.dispose();
  }

  void _startAutoRefresh() {
    _refreshTimer?.cancel();
    if (!_autoRefresh) {
      return;
    }
    _refreshTimer = Timer.periodic(const Duration(seconds: 2), (_) {
      _refreshLogs(silent: true);
    });
  }

  Future<void> _refreshLogs({bool silent = false}) async {
    if (!silent && mounted) {
      setState(() {
        _loading = true;
        _error = null;
      });
    }

    try {
      final List<dynamic>? raw = await _channel.invokeMethod<List<dynamic>>(
        'getClientLogs',
        {'maxLines': 500},
      );

      final nextLogs = (raw ?? const <dynamic>[])
          .map((line) => line.toString())
          .toList(growable: false);

      if (!mounted) {
        return;
      }

      setState(() {
        _logs = nextLogs;
        _loading = false;
        _error = null;
      });

      WidgetsBinding.instance.addPostFrameCallback((_) {
        if (!_scrollController.hasClients) {
          return;
        }
        _scrollController.jumpTo(_scrollController.position.maxScrollExtent);
      });
    } on PlatformException catch (e) {
      if (!mounted) {
        return;
      }
      setState(() {
        _loading = false;
        _error = e.message ?? 'Failed to load logs';
      });
    }
  }

  Future<void> _copyLogs() async {
    final text = _logs.join('\n');
    await Clipboard.setData(ClipboardData(text: text));
    if (!mounted) {
      return;
    }
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(content: Text('Logs copied to clipboard')),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Client Logs'),
        actions: [
          IconButton(
            icon: const Icon(Icons.copy_all_outlined),
            tooltip: 'Copy',
            onPressed: _logs.isEmpty ? null : _copyLogs,
          ),
          IconButton(
            icon: const Icon(Icons.refresh),
            tooltip: 'Refresh',
            onPressed: () => _refreshLogs(),
          ),
        ],
      ),
      body: Column(
        children: [
          SwitchListTile(
            title: const Text('Auto-refresh (2s)'),
            value: _autoRefresh,
            onChanged: (value) {
              setState(() => _autoRefresh = value);
              _startAutoRefresh();
            },
          ),
          if (_loading)
            const LinearProgressIndicator(minHeight: 2),
          if (_error != null)
            Padding(
              padding: const EdgeInsets.all(12),
              child: Text(
                _error!,
                style: const TextStyle(color: Colors.red),
              ),
            ),
          Expanded(
            child: _logs.isEmpty
                ? const Center(child: Text('No client logs yet'))
                : ListView.builder(
                    controller: _scrollController,
                    itemCount: _logs.length,
                    itemBuilder: (context, index) {
                      return Padding(
                        padding: const EdgeInsets.symmetric(
                          horizontal: 12,
                          vertical: 4,
                        ),
                        child: SelectableText(
                          _logs[index],
                          style: const TextStyle(
                            fontFamily: 'monospace',
                            fontSize: 12,
                            height: 1.35,
                          ),
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
