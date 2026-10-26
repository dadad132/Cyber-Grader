import 'package:building_network_audit/main.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

void main() {
  testWidgets('shows the audit form with remembered details', (tester) async {
    SharedPreferences.setMockInitialValues({'site': 'Company A office', 'server': 'https://grader.example.co.za'});
    await tester.pumpWidget(const BuildingAuditApp());
    await tester.pumpAndSettle();
    expect(find.text('Run audit'), findsOneWidget);
    expect(find.text('Company A office'), findsOneWidget);
    expect(find.text('https://grader.example.co.za'), findsOneWidget);
  });

  testWidgets('asks for an API key before running', (tester) async {
    SharedPreferences.setMockInitialValues({});
    await tester.pumpWidget(const BuildingAuditApp());
    await tester.pumpAndSettle();
    await tester.tap(find.widgetWithText(FilledButton, 'Run audit'));
    await tester.pumpAndSettle();
    expect(find.textContaining('Enter your API key'), findsOneWidget);
  });
}
