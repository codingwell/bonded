import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:bonded_app/screens/network_tests_screen.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  const channel = MethodChannel('bonded/native');

  late List<MethodCall> calls;
  late List<Map<String, dynamic>> pairedServers;
  late List<String> logs;

  Future<void> pumpScreen(WidgetTester tester) async {
    await tester.pumpWidget(
      const MaterialApp(home: NetworkTestsScreen()),
    );
    await tester.pump();
  }

  tearDown(() async {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, null);
  });

  setUp(() {
    calls = <MethodCall>[];
    pairedServers = <Map<String, dynamic>>[];
    logs = <String>[];

    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) async {
          calls.add(call);
          switch (call.method) {
            case 'getPairedServers':
              return pairedServers;
            case 'getNetworkTestLogs':
              return logs;
            case 'runNetworkTest':
              return 'ok';
            case 'clearNetworkTestLogs':
              logs = <String>[];
              return null;
            default:
              return null;
          }
        });
  });

  testWidgets('shows first paired server and loads its values into the form', (
    WidgetTester tester,
  ) async {
    pairedServers = <Map<String, dynamic>>[
      <String, dynamic>{
        'id': 'device-1',
        'publicAddress': 'example.com:443',
        'serverPublicKey': 'server-key',
        'supportedProtocols': <String>['wss', 'wireguard'],
        'pairedAt': DateTime(2026).toIso8601String(),
      },
    ];

    await pumpScreen(tester);

    expect(find.text('Paired Server Checks'), findsOneWidget);
    expect(find.text('Server: example.com:443'), findsOneWidget);
    expect(find.text('Protocols: wss, wireguard'), findsOneWidget);

    await tester.tap(find.text('Use First Paired Server'));
    await tester.pump();

    expect(
      find.textContaining('Loaded paired server example.com:443'),
      findsOneWidget,
    );
  });

  testWidgets('run paired server checks queues vpn status dns and tcp tests', (
    WidgetTester tester,
  ) async {
    pairedServers = <Map<String, dynamic>>[
      <String, dynamic>{
        'id': 'device-1',
        'publicAddress': 'example.com:443',
        'serverPublicKey': 'server-key',
        'supportedProtocols': <String>['wss'],
        'pairedAt': DateTime(2026).toIso8601String(),
      },
    ];

    await pumpScreen(tester);

    calls.clear();

    await tester.tap(find.text('Run Paired Server Checks'));
    await tester.pump();
    await tester.pump(const Duration(milliseconds: 1200));
    await tester.pump();

    final runCalls = calls
        .where((call) => call.method == 'runNetworkTest')
        .toList();

    expect(runCalls, hasLength(3));
    expect(
      runCalls[0].arguments,
      <String, dynamic>{'action': 'com.bonded.bonded_app.TEST_VPN_STATUS'},
    );
    expect(
      runCalls[1].arguments,
      <String, dynamic>{
        'action': 'com.bonded.bonded_app.TEST_DNS',
        'host': 'example.com',
        'expected_ip': '',
      },
    );
    expect(
      runCalls[2].arguments,
      <String, dynamic>{
        'action': 'com.bonded.bonded_app.TEST_TCP',
        'host': 'example.com',
        'port': 443,
      },
    );
    expect(
      find.text('Queued 3 paired-server checks for example.com:443.'),
      findsOneWidget,
    );
  });
}