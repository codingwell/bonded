import 'dart:convert';

class ServerPairingPayload {
  final String publicAddress;
  final String inviteToken;
  final String serverPublicKey;
  final List<String> supportedProtocols;

  ServerPairingPayload({
    required this.publicAddress,
    required this.inviteToken,
    required this.serverPublicKey,
    required this.supportedProtocols,
  });

  factory ServerPairingPayload.fromJson(Map<String, dynamic> json) {
    final publicAddress =
        (json['server_public_address'] ?? json['public_address'] ?? '')
            .toString()
            .trim();

    return ServerPairingPayload(
      publicAddress: publicAddress,
      inviteToken: (json['invite_token'] ?? '').toString().trim(),
      serverPublicKey: (json['server_public_key'] ?? '').toString().trim(),
      supportedProtocols: List<String>.from(json['supported_protocols'] ?? []),
    );
  }

  static ServerPairingPayload? parseQrData(String data) {
    try {
      final json = jsonDecode(data) as Map<String, dynamic>;
      final payload = ServerPairingPayload.fromJson(json);

      if (payload.publicAddress.isEmpty ||
          payload.inviteToken.isEmpty ||
          payload.serverPublicKey.isEmpty) {
        return null;
      }

      return payload;
    } catch (e) {
      return null;
    }
  }
}

class PairedServer {
  final String id;
  final String publicAddress;
  final String serverPublicKey;
  final List<String> supportedProtocols;
  final DateTime pairedAt;

  PairedServer({
    required this.id,
    required this.publicAddress,
    required this.serverPublicKey,
    required this.supportedProtocols,
    required this.pairedAt,
  });

  Map<String, dynamic> toJson() => {
    'id': id,
    'publicAddress': publicAddress,
    'serverPublicKey': serverPublicKey,
    'supportedProtocols': supportedProtocols,
    'pairedAt': pairedAt.toIso8601String(),
  };

  factory PairedServer.fromJson(Map<String, dynamic> json) => PairedServer(
    id: json['id'] ?? '',
    publicAddress: json['publicAddress'] ?? '',
    serverPublicKey: json['serverPublicKey'] ?? '',
    supportedProtocols: List<String>.from(json['supportedProtocols'] ?? []),
    pairedAt: DateTime.parse(
      json['pairedAt'] ?? DateTime.now().toIso8601String(),
    ),
  );
}
