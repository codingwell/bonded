import 'package:bonded_app/models/pairing_model.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  group('ServerPairingPayload.parseQrData', () {
    test('parses server_public_address payload from server QR JSON', () {
      const qrData =
          '{"server_public_address":"bonded.example.com:8080","invite_token":"token-123","server_public_key":"pub-key","supported_protocols":["naive_tcp"]}';

      final payload = ServerPairingPayload.parseQrData(qrData);

      expect(payload, isNotNull);
      expect(payload!.publicAddress, 'bonded.example.com:8080');
      expect(payload.inviteToken, 'token-123');
      expect(payload.serverPublicKey, 'pub-key');
      expect(payload.supportedProtocols, ['naive_tcp']);
    });

    test('accepts legacy public_address key for compatibility', () {
      const qrData =
          '{"public_address":"legacy.example.com:9000","invite_token":"token-legacy","server_public_key":"legacy-key","supported_protocols":["naive_tcp"]}';

      final payload = ServerPairingPayload.parseQrData(qrData);

      expect(payload, isNotNull);
      expect(payload!.publicAddress, 'legacy.example.com:9000');
    });

    test('returns null when required fields are missing', () {
      const qrData =
          '{"server_public_address":"bonded.example.com:8080","invite_token":"","server_public_key":"pub-key","supported_protocols":["naive_tcp"]}';

      final payload = ServerPairingPayload.parseQrData(qrData);

      expect(payload, isNull);
    });
  });
}
