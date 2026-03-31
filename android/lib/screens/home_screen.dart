import 'package:flutter/material.dart';
import '../services/pairing_service.dart';

class HomeScreen extends StatefulWidget {
  const HomeScreen({super.key});

  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> {
  Future<List<Map<String, dynamic>>>? _pairedServersFuture;

  @override
  void initState() {
    super.initState();
    _loadPairedServers();
  }

  void _loadPairedServers() {
    setState(() {
      _pairedServersFuture = PairingService.getPairedServers();
    });
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Bonded VPN'),
        backgroundColor: Theme.of(context).colorScheme.inversePrimary,
      ),
      body: FutureBuilder<List<Map<String, dynamic>>>(
        future: _pairedServersFuture,
        builder: (context, snapshot) {
          if (snapshot.connectionState == ConnectionState.waiting) {
            return const Center(child: CircularProgressIndicator());
          }

          final pairedServers = snapshot.data ?? [];

          if (pairedServers.isEmpty) {
            return Center(
              child: Column(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  const Icon(
                    Icons.security,
                    size: 64,
                    color: Colors.grey,
                  ),
                  const SizedBox(height: 16),
                  const Text(
                    'No paired servers',
                    style: TextStyle(
                      fontSize: 18,
                      fontWeight: FontWeight.w500,
                    ),
                  ),
                  const SizedBox(height: 8),
                  Text(
                    'Scan a server QR code to get started',
                    style: TextStyle(
                      fontSize: 14,
                      color: Colors.grey[600],
                    ),
                  ),
                  const SizedBox(height: 32),
                  ElevatedButton.icon(
                    onPressed: () =>
                        Navigator.of(context).pushNamed('/qr-scanner'),
                    icon: const Icon(Icons.qr_code_2),
                    label: const Text('Scan QR Code'),
                    style: ElevatedButton.styleFrom(
                      padding: const EdgeInsets.symmetric(
                        horizontal: 32,
                        vertical: 16,
                      ),
                    ),
                  ),
                ],
              ),
            );
          }

          return ListView.builder(
            padding: const EdgeInsets.all(16),
            itemCount: pairedServers.length + 1,
            itemBuilder: (context, index) {
              if (index == pairedServers.length) {
                // Add new server button at the end
                return Padding(
                  padding: const EdgeInsets.symmetric(vertical: 16),
                  child: ElevatedButton.icon(
                    onPressed: () =>
                        Navigator.of(context).pushNamed('/qr-scanner'),
                    icon: const Icon(Icons.add),
                    label: const Text('Add Server'),
                  ),
                );
              }

              final server = pairedServers[index];
              return _buildServerCard(context, server);
            },
          );
        },
      ),
    );
  }

  Widget _buildServerCard(
    BuildContext context,
    Map<String, dynamic> server,
  ) {
    return Card(
      child: ListTile(
        leading: const Icon(Icons.dns, color: Colors.teal),
        title: Text(
          server['publicAddress'] ?? 'Unknown Server',
          style: const TextStyle(fontWeight: FontWeight.bold),
        ),
        subtitle: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const SizedBox(height: 4),
            Text(
              'Protocols: ${(server['supportedProtocols'] as List?)?.join(', ') ?? 'unknown'}',
              style: const TextStyle(fontSize: 12),
            ),
          ],
        ),
        trailing: const Icon(Icons.arrow_forward),
        onTap: () {
          Navigator.of(context).pushNamed(
            '/dashboard',
            arguments: {'deviceId': server['id'] ?? ''},
          );
        },
      ),
    );
  }
}
