import 'package:flutter_test/flutter_test.dart';

import 'package:bonded_app/main.dart';

void main() {
  testWidgets('Bridge status screen renders', (WidgetTester tester) async {
    await tester.pumpWidget(const BondedApp());
    await tester.pump();

    expect(find.text('Bonded Android Shell'), findsOneWidget);
    expect(find.text('Bridge status'), findsOneWidget);
    expect(find.text('Refresh bridge status'), findsOneWidget);
    expect(find.text('Start VPN'), findsOneWidget);
    expect(find.text('Stop VPN'), findsOneWidget);
  });
}
