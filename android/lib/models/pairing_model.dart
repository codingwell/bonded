import 'dart:convert';

class ServerPairingPayload {
  final String publicAddress;
  final String inviteToken;
  final String serverIdentityPublicKey;
  final List<String> supportedProtocols;

  ServerPairingPayload({
    required this.publicAddress,
    required this.inviteToken,
    required this.serverIdentityPublicKey,
    required this.supportedProtocols,
  });

  String get serverPublicKey => serverIdentityPublicKey;

  factory ServerPairingPayload.fromJson(Map<String, dynamic> json) {
    final publicAddress =
        (json['server_public_address'] ?? json['public_address'] ?? '')
            .toString()
            .trim();

    return ServerPairingPayload(
      publicAddress: publicAddress,
      inviteToken: (json['invite_token'] ?? '').toString().trim(),
      serverIdentityPublicKey: (json['server_identity_public_key'] ??
              json['server_public_key'] ??
              '')
          .toString()
          .trim(),
      supportedProtocols: List<String>.from(json['supported_protocols'] ?? []),
    );
  }

  static ServerPairingPayload? parseQrData(String data) {
    try {
      final json = jsonDecode(data) as Map<String, dynamic>;
      final payload = ServerPairingPayload.fromJson(json);

      if (payload.publicAddress.isEmpty ||
          payload.inviteToken.isEmpty ||
          payload.serverIdentityPublicKey.isEmpty) {
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
  final String serverIdentityPublicKey;
  final List<String> supportedProtocols;
  final bool peerShareEnabled;
  final String peerShareBindAddress;
  final String peerShareAdvertiseIp;
  final DateTime pairedAt;

  PairedServer({
    required this.id,
    required this.publicAddress,
    required this.serverIdentityPublicKey,
    required this.supportedProtocols,
    this.peerShareEnabled = false,
    this.peerShareBindAddress = '',
    this.peerShareAdvertiseIp = '',
    required this.pairedAt,
  });

  String get serverPublicKey => serverIdentityPublicKey;

  Map<String, dynamic> toJson() => {
    'id': id,
    'publicAddress': publicAddress,
    'serverIdentityPublicKey': serverIdentityPublicKey,
    'serverPublicKey': serverIdentityPublicKey,
    'supportedProtocols': supportedProtocols,
    'peerShareEnabled': peerShareEnabled,
    'peerShareBindAddress': peerShareBindAddress,
    'peerShareAdvertiseIp': peerShareAdvertiseIp,
    'pairedAt': pairedAt.toIso8601String(),
  };

  factory PairedServer.fromJson(Map<String, dynamic> json) => PairedServer(
    id: json['id'] ?? '',
    publicAddress: json['publicAddress'] ?? '',
    serverIdentityPublicKey:
      (json['serverIdentityPublicKey'] ?? json['serverPublicKey'] ?? '')
        .toString(),
    supportedProtocols: List<String>.from(json['supportedProtocols'] ?? []),
    peerShareEnabled: json['peerShareEnabled'] == true,
    peerShareBindAddress: (json['peerShareBindAddress'] ?? '').toString(),
    peerShareAdvertiseIp: (json['peerShareAdvertiseIp'] ?? '').toString(),
    pairedAt: DateTime.parse(
      json['pairedAt'] ?? DateTime.now().toIso8601String(),
    ),
  );
}
