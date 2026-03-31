import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import '../services/background_service.dart';
import '../utils/background_notification_helper.dart';

class DashboardScreen extends StatefulWidget {
  final String deviceId;

  const DashboardScreen({
    super.key,
    required this.deviceId,
  });

  @override
  State<DashboardScreen> createState() => _DashboardScreenState();
}

class _DashboardScreenState extends State<DashboardScreen> {
  static const MethodChannel _channel = MethodChannel('bonded/native');

  String _vpnStatus = 'Unknown';
  String _connectedServer = 'Not connected';
  String _dataTransferred = '0 B';
  bool _isConnecting = false;
  bool _isBackgroundRunning = false;

  @override
  void initState() {
    super.initState();
    _refreshStatus();
    _listenToBackgroundEvents();
  }

  void _listenToBackgroundEvents() {
    try {
      BackgroundService.backgroundEvents.listen(
        (event) {
          if (mounted) {
            setState(() {
              if (event.type == 'started') {
                _isBackgroundRunning = true;
              } else if (event.type == 'stopped' || event.type == 'error') {
                _isBackgroundRunning = false;
              }
            });

            if (event.message != null) {
              ScaffoldMessenger.of(context).showSnackBar(
                SnackBar(content: Text(event.message!)),
              );
            }
          }
        },
        onError: (error) {
          // Background event stream errors are non-fatal
          debugPrint('Background service event error: $error');
        },
      );
    } catch (e) {
      debugPrint('Failed to listen to background events: $e');
    }
  }

  Future<void> _refreshStatus() async {
    try {
      final bool vpnRunning =
          await _channel.invokeMethod<bool>('getVpnStatus') ?? false;

      if (mounted) {
        setState(() {
          _vpnStatus = vpnRunning ? 'Connected' : 'Disconnected';
          _connectedServer = 'bonded.example.com';
          _dataTransferred = vpnRunning ? '1.2 MB' : '0 B';
        });
      }
    } on PlatformException {
      if (mounted) {
        setState(() {
          _vpnStatus = 'Unknown';
        });
      }
    }
  }

  Future<void> _toggleVpn() async {
    setState(() => _isConnecting = true);

    try {
      if (_vpnStatus == 'Connected') {
        await _channel.invokeMethod('stopVpnService');
      } else {
        await _channel.invokeMethod('startVpnService', {
          'deviceId': widget.deviceId,
        });
      }
      await _refreshStatus();
    } on PlatformException catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Error: ${e.message}'),
            backgroundColor: Colors.red,
          ),
        );
      }
    } finally {
      if (mounted) {
        setState(() => _isConnecting = false);
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final isConnected = _vpnStatus == 'Connected';
    final statusColor = isConnected ? Colors.green : Colors.grey;

    return Scaffold(
      appBar: AppBar(
        title: const Text('Bonded VPN'),
        actions: [
          IconButton(
            icon: const Icon(Icons.refresh),
            onPressed: _refreshStatus,
          ),
          IconButton(
            icon: const Icon(Icons.settings),
            onPressed: () =>
                Navigator.of(context).pushNamed('/settings'),
          ),
        ],
      ),
      body: Column(
        children: [
          if (_isBackgroundRunning)
            BackgroundNotificationHelper.buildBackgroundIndicator(
              _isBackgroundRunning,
              _connectedServer,
            ),
          Expanded(
            child: Center(
              child: SingleChildScrollView(
                padding: const EdgeInsets.all(24),
                child: Column(
                  mainAxisAlignment: MainAxisAlignment.center,
                  children: [
                    // Large VPN status indicator
                    Container(
                      width: 120,
                      height: 120,
                      decoration: BoxDecoration(
                        shape: BoxShape.circle,
                        color: statusColor.withAlpha(50),
                        border: Border.all(color: statusColor, width: 3),
                      ),
                      child: Center(
                        child: Icon(
                          isConnected ? Icons.vpn_lock : Icons.lock_open,
                          size: 60,
                          color: statusColor,
                        ),
                      ),
                    ),
                    const SizedBox(height: 24),
                    // Status text
                    Text(
                      _vpnStatus,
                      style: TextStyle(
                        fontSize: 28,
                        fontWeight: FontWeight.bold,
                        color: statusColor,
                      ),
                    ),
                    const SizedBox(height: 8),
                    Text(
                      'Device ID: ${widget.deviceId}',
                      style: TextStyle(fontSize: 12, color: Colors.grey[600]),
                    ),
                    const SizedBox(height: 32),
                    // Connection details
                    Container(
                      width: double.infinity,
                      padding: const EdgeInsets.all(16),
                      decoration: BoxDecoration(
                        color: Colors.grey[100],
                        borderRadius: BorderRadius.circular(8),
                        border: Border.all(color: Colors.grey[300]!),
                      ),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          _buildDetailItem('Server', _connectedServer),
                          const Divider(),
                          _buildDetailItem('Data Transferred', _dataTransferred),
                        ],
                      ),
                    ),
                    const SizedBox(height: 32),
                    // Main action button
                    ElevatedButton(
                      onPressed: _isConnecting ? null : _toggleVpn,
                      style: ElevatedButton.styleFrom(
                        padding: const EdgeInsets.symmetric(
                          horizontal: 48,
                          vertical: 16,
                        ),
                        backgroundColor:
                            isConnected ? Colors.red : Colors.green,
                        disabledBackgroundColor: Colors.grey,
                      ),
                      child: _isConnecting
                          ? const SizedBox(
                              width: 20,
                              height: 20,
                              child: CircularProgressIndicator(
                                strokeWidth: 2,
                                valueColor:
                                    AlwaysStoppedAnimation<Color>(Colors.white),
                              ),
                            )
                          : Text(
                              isConnected ? 'Disconnect' : 'Connect',
                              style: const TextStyle(fontSize: 18),
                            ),
                    ),
                    const SizedBox(height: 16),
                    OutlinedButton(
                      onPressed: () => Navigator.of(context).pop(),
                      child: const Text('Back'),
                    ),
                  ],
                ),
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildDetailItem(String label, String value) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 8),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        children: [
          Text(
            label,
            style: const TextStyle(color: Colors.grey),
          ),
          Text(
            value,
            style: const TextStyle(fontWeight: FontWeight.bold),
          ),
        ],
      ),
    );
  }
}
