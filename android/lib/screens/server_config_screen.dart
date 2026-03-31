import 'package:flutter/material.dart';
import '../models/pairing_model.dart';
import '../services/pairing_service.dart';

class ServerConfigScreen extends StatefulWidget {
  final PairedServer server;

  const ServerConfigScreen({super.key, required this.server});

  @override
  State<ServerConfigScreen> createState() => _ServerConfigScreenState();
}

class _ServerConfigScreenState extends State<ServerConfigScreen> {
  late TextEditingController _serverAddressController;
  late TextEditingController _publicKeyController;
  late List<String> _selectedProtocols;
  bool _isSaving = false;

  @override
  void initState() {
    super.initState();
    _serverAddressController = TextEditingController(
      text: widget.server.publicAddress,
    );
    _publicKeyController = TextEditingController(
      text: widget.server.serverPublicKey,
    );
    _selectedProtocols = List.from(widget.server.supportedProtocols);
  }

  @override
  void dispose() {
    _serverAddressController.dispose();
    _publicKeyController.dispose();
    super.dispose();
  }

  Future<void> _saveConfiguration() async {
    final updatedServer = PairedServer(
      id: widget.server.id,
      publicAddress: _serverAddressController.text.trim(),
      serverPublicKey: _publicKeyController.text.trim(),
      supportedProtocols: List<String>.from(_selectedProtocols),
      pairedAt: widget.server.pairedAt,
    );

    if (updatedServer.publicAddress.isEmpty ||
        updatedServer.serverPublicKey.isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('Server address and public key are required'),
          backgroundColor: Colors.red,
        ),
      );
      return;
    }

    setState(() => _isSaving = true);

    try {
      await PairingService.updatePairedServer(updatedServer);

      if (!mounted) {
        return;
      }

      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('Configuration saved'),
          backgroundColor: Colors.green,
        ),
      );
      setState(() => _isSaving = false);
      Navigator.of(context).pop(true);
    } on PairingException catch (e) {
      if (!mounted) {
        return;
      }

      setState(() => _isSaving = false);
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text(e.message), backgroundColor: Colors.red),
      );
    } catch (e) {
      if (!mounted) {
        return;
      }

      setState(() => _isSaving = false);
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text('Failed to save configuration: $e'),
          backgroundColor: Colors.red,
        ),
      );
    }
  }

  Future<void> _deleteServer() async {
    final confirm = await showDialog<bool>(
      context: context,
      builder:
          (context) => AlertDialog(
            title: const Text('Delete Server?'),
            content: Text(
              'Remove ${widget.server.publicAddress} from paired servers?',
            ),
            actions: [
              TextButton(
                onPressed: () => Navigator.pop(context, false),
                child: const Text('Cancel'),
              ),
              TextButton(
                onPressed: () => Navigator.pop(context, true),
                child: const Text(
                  'Delete',
                  style: TextStyle(color: Colors.red),
                ),
              ),
            ],
          ),
    );

    if (confirm != true || !mounted) {
      return;
    }

    setState(() => _isSaving = true);

    try {
      await PairingService.deletePairedServer(widget.server.id);

      if (!mounted) {
        return;
      }

      ScaffoldMessenger.of(
        context,
      ).showSnackBar(const SnackBar(content: Text('Server removed')));
      setState(() => _isSaving = false);
      Navigator.of(context).pop(true);
    } on PairingException catch (e) {
      if (!mounted) {
        return;
      }

      setState(() => _isSaving = false);
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text(e.message), backgroundColor: Colors.red),
      );
    } catch (e) {
      if (!mounted) {
        return;
      }

      setState(() => _isSaving = false);
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text('Failed to delete server: $e'),
          backgroundColor: Colors.red,
        ),
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Server Configuration')),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              'Server Address',
              style: TextStyle(fontSize: 14, fontWeight: FontWeight.bold),
            ),
            const SizedBox(height: 8),
            TextField(
              controller: _serverAddressController,
              decoration: InputDecoration(
                hintText: 'Server address',
                border: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(8),
                ),
                filled: true,
                fillColor: Colors.grey[100],
              ),
            ),
            const SizedBox(height: 24),
            const Text(
              'Server Public Key',
              style: TextStyle(fontSize: 14, fontWeight: FontWeight.bold),
            ),
            const SizedBox(height: 8),
            TextField(
              controller: _publicKeyController,
              maxLines: 3,
              decoration: InputDecoration(
                hintText: 'Server public key (base64)',
                border: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(8),
                ),
                filled: true,
                fillColor: Colors.grey[100],
              ),
            ),
            const SizedBox(height: 24),
            const Text(
              'Supported Protocols',
              style: TextStyle(fontSize: 14, fontWeight: FontWeight.bold),
            ),
            const SizedBox(height: 12),
            Wrap(
              spacing: 8,
              children:
                  _selectedProtocols
                      .map(
                        (protocol) => Chip(
                          label: Text(protocol),
                          onDeleted: () {
                            setState(() {
                              _selectedProtocols.remove(protocol);
                            });
                          },
                        ),
                      )
                      .toList(),
            ),
            const SizedBox(height: 32),
            const Text(
              'Device Information',
              style: TextStyle(fontSize: 14, fontWeight: FontWeight.bold),
            ),
            const SizedBox(height: 12),
            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: Colors.grey[100],
                borderRadius: BorderRadius.circular(8),
                border: Border.all(color: Colors.grey[300]!),
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  _buildInfoRow('Device ID', widget.server.id),
                  const SizedBox(height: 12),
                  _buildInfoRow(
                    'Paired At',
                    widget.server.pairedAt.toString().split('.')[0],
                  ),
                ],
              ),
            ),
            const SizedBox(height: 32),
            // Action buttons
            Row(
              mainAxisAlignment: MainAxisAlignment.spaceEvenly,
              children: [
                ElevatedButton.icon(
                  onPressed: _isSaving ? null : _saveConfiguration,
                  icon:
                      _isSaving
                          ? const SizedBox(
                            width: 20,
                            height: 20,
                            child: CircularProgressIndicator(strokeWidth: 2),
                          )
                          : const Icon(Icons.save),
                  label: Text(_isSaving ? 'Saving...' : 'Save'),
                  style: ElevatedButton.styleFrom(backgroundColor: Colors.teal),
                ),
                OutlinedButton.icon(
                  onPressed: _isSaving ? null : _deleteServer,
                  icon: const Icon(Icons.delete),
                  label: const Text('Delete'),
                  style: OutlinedButton.styleFrom(
                    foregroundColor: Colors.red,
                    side: const BorderSide(color: Colors.red),
                  ),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildInfoRow(String label, String value) {
    return Row(
      mainAxisAlignment: MainAxisAlignment.spaceBetween,
      children: [
        Text(label, style: const TextStyle(fontSize: 12, color: Colors.grey)),
        Flexible(
          child: Text(
            value,
            textAlign: TextAlign.end,
            style: const TextStyle(fontSize: 12, fontWeight: FontWeight.w500),
            maxLines: 2,
            overflow: TextOverflow.ellipsis,
          ),
        ),
      ],
    );
  }
}
