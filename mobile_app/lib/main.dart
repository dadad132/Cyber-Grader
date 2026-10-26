// Building network audit: the phone version of tools/lan_agent.py.
// Measures what a phone can (router ports, devices exposed on the network, UPnP, latency), sends
// null for anything it can't measure, and uploads to the grader with the customer's API key.
// Only audit networks you own or are authorised to test.
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math' as math;

import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import 'package:network_info_plus/network_info_plus.dart';
import 'package:shared_preferences/shared_preferences.dart';

const gatewayPorts = [21, 22, 23, 80, 161, 8291, 8728, 8729];
const lanPorts = [445, 3389, 554, 9100];

void main() => runApp(const BuildingAuditApp());

class BuildingAuditApp extends StatelessWidget {
  const BuildingAuditApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Building network audit',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(colorSchemeSeed: const Color(0xFF1F5BD6), useMaterial3: true),
      darkTheme: ThemeData(colorSchemeSeed: const Color(0xFF1F5BD6), brightness: Brightness.dark, useMaterial3: true),
      home: const AuditScreen(),
    );
  }
}

class AuditScreen extends StatefulWidget {
  const AuditScreen({super.key});

  @override
  State<AuditScreen> createState() => _AuditScreenState();
}

class _AuditScreenState extends State<AuditScreen> {
  final _server = TextEditingController(text: 'https://check.easymikrotik.com');
  final _apiKey = TextEditingController();
  final _site = TextEditingController();
  final _domain = TextEditingController();
  String? _wifiSecurity; // null = not sure, so it isn't scored
  bool _running = false;
  String _status = '';
  Map<String, dynamic>? _result;
  String? _error;

  @override
  void initState() {
    super.initState();
    _loadSaved();
  }

  /// The address, key and site are remembered between runs.
  Future<void> _loadSaved() async {
    final prefs = await SharedPreferences.getInstance();
    setState(() {
      _server.text = prefs.getString('server') ?? _server.text;
      _apiKey.text = prefs.getString('apiKey') ?? '';
      _site.text = prefs.getString('site') ?? '';
      _domain.text = prefs.getString('domain') ?? '';
      _wifiSecurity = prefs.getString('wifiSecurity');
    });
  }

  Future<void> _save() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString('server', _server.text.trim());
    await prefs.setString('apiKey', _apiKey.text.trim());
    await prefs.setString('site', _site.text.trim());
    await prefs.setString('domain', _domain.text.trim());
    if (_wifiSecurity == null) {
      await prefs.remove('wifiSecurity');
    } else {
      await prefs.setString('wifiSecurity', _wifiSecurity!);
    }
  }

  Future<bool> _open(String ip, int port, int timeoutMs) async {
    try {
      final socket = await Socket.connect(ip, port, timeout: Duration(milliseconds: timeoutMs));
      socket.destroy();
      return true;
    } catch (_) {
      return false;
    }
  }

  /// TCP connect time in milliseconds, or null if it couldn't connect (never a made-up number).
  Future<double?> _latency(String ip, int port) async {
    final watch = Stopwatch()..start();
    final ok = await _open(ip, port, 2000);
    return ok ? watch.elapsedMicroseconds / 1000.0 : null;
  }

  /// true/false if the SSDP query worked, null if this phone couldn't run it.
  Future<bool?> _upnpGateway() async {
    RawDatagramSocket? socket;
    try {
      socket = await RawDatagramSocket.bind(InternetAddress.anyIPv4, 0);
      const query = 'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\nMX: 1\r\n'
          'ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n';
      final found = Completer<bool>();
      final receiver = socket;
      receiver.listen((event) {
        if (event != RawSocketEvent.read) return;
        final datagram = receiver.receive();
        if (datagram != null &&
            utf8.decode(datagram.data, allowMalformed: true).contains('InternetGatewayDevice') &&
            !found.isCompleted) {
          found.complete(true);
        }
      });
      receiver.send(utf8.encode(query), InternetAddress('239.255.255.250'), 1900);
      return await found.future.timeout(const Duration(seconds: 2), onTimeout: () => false);
    } catch (_) {
      return null;
    } finally {
      socket?.close();
    }
  }

  void _progress(String message) => setState(() => _status = message);

  Future<void> _run() async {
    if (_apiKey.text.trim().isEmpty) {
      setState(() => _error = 'Enter your API key (Account > API access on the website).');
      return;
    }
    setState(() {
      _running = true;
      _error = null;
      _result = null;
    });
    await _save();
    try {
      _progress('Finding the router…');
      final info = NetworkInfo();
      final gateway = await info.getWifiGatewayIP();
      final myIp = await info.getWifiIP();
      final rawSsid = (await info.getWifiName())?.replaceAll('"', '');
      // Without location permission Android reports "<unknown ssid>"; send nothing rather than that.
      final ssid = (rawSsid == null || rawSsid.isEmpty || rawSsid.contains('unknown')) ? null : rawSsid;
      if (gateway == null || gateway.isEmpty || !gateway.contains('.')) {
        throw Exception('Connect to the building Wi-Fi first.');
      }

      _progress('Checking router ports…');
      final openPorts = <int>[];
      for (final port in gatewayPorts) {
        if (await _open(gateway, port, 1000)) openPorts.add(port);
      }

      final prefix = gateway.substring(0, gateway.lastIndexOf('.'));
      final hosts = [for (var i = 1; i < 255; i++) '$prefix.$i']..removeWhere((ip) => ip == gateway || ip == myIp);
      final targets = [for (final ip in hosts) for (final port in lanPorts) MapEntry(ip, port)];
      final exposed = <Map<String, Object>>[];
      for (var i = 0; i < targets.length; i += 64) {
        _progress('Checking devices on the network… ${(100 * i / targets.length).round()}%');
        final batch = targets.sublist(i, math.min(i + 64, targets.length));
        final results = await Future.wait(batch.map((t) => _open(t.key, t.value, 400)));
        for (var j = 0; j < batch.length; j++) {
          if (results[j]) exposed.add({'ip': batch[j].key, 'port': batch[j].value});
        }
      }

      _progress('Checking UPnP and latency…');
      final upnp = await _upnpGateway();
      final gatewayLatency = openPorts.isEmpty ? null : await _latency(gateway, openPorts.first);
      final internetLatency = gatewayLatency == null ? null : await _latency('1.1.1.1', 443);

      final payload = <String, Object?>{
        'site_name': _site.text.trim(),
        'domain': _domain.text.trim(),
        'gateway_ip': gateway,
        'gateway_ports_checked': gatewayPorts,
        'open_gateway_ports': openPorts,
        'hosts_scanned': hosts.length,
        'lan_ports_checked': lanPorts,
        'exposed_lan_services': exposed,
        'upnp_enabled': upnp,
        'wifi': {'ssid': ssid, 'security': _wifiSecurity, 'signal_dbm': null, 'source': 'app'},
        'rogue_aps': null,
        'dns_filtering': null,
        'gateway_latency_ms': gatewayLatency,
        'internet_latency_ms': internetLatency,
        // The server checks this network's own public IP (where the phone is connected) from the internet.
        'check_external': true,
        'agent': 'mobile app 2.0',
      };

      _progress('Uploading…');
      final server = _server.text.trim().replaceAll(RegExp(r'/+$'), '');
      final response = await http.post(
        Uri.parse('$server/api/lan-audit'),
        headers: {'Content-Type': 'application/json', 'X-API-Key': _apiKey.text.trim()},
        body: jsonEncode(payload),
      );
      final body = jsonDecode(response.body) as Map<String, dynamic>;
      if (response.statusCode != 201) {
        throw Exception(body['error'] ?? 'The server answered ${response.statusCode}.');
      }
      setState(() => _result = body);
    } catch (e) {
      setState(() => _error = e.toString().replaceFirst('Exception: ', ''));
    } finally {
      setState(() {
        _running = false;
        _status = '';
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    final result = _result;
    return Scaffold(
      appBar: AppBar(title: const Text('Building network audit')),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          const Text('1. Connect this phone to the building Wi-Fi.\n'
              '2. Fill in the details below (they are remembered).\n'
              '3. Tap Run audit. It takes 1 to 2 minutes; keep the screen on.\n\n'
              'Only audit networks you are authorised to test.'),
          const SizedBox(height: 12),
          TextField(
            controller: _server,
            keyboardType: TextInputType.url,
            decoration: const InputDecoration(labelText: 'Grader address'),
          ),
          TextField(
            controller: _apiKey,
            obscureText: true,
            decoration: const InputDecoration(labelText: 'API key (Account > API access)'),
          ),
          TextField(controller: _site, decoration: const InputDecoration(labelText: 'Site name, e.g. Client office')),
          TextField(
            controller: _domain,
            keyboardType: TextInputType.url,
            decoration: const InputDecoration(labelText: "Client's domain (optional)"),
          ),
          const SizedBox(height: 8),
          DropdownButtonFormField<String?>(
            // Keyed on the value so it shows the saved choice once it has loaded.
            key: ValueKey(_wifiSecurity),
            initialValue: _wifiSecurity,
            decoration: const InputDecoration(
              labelText: 'Wi-Fi security',
              helperText: "Tap the connected network in the phone's Wi-Fi settings to see it",
            ),
            items: const [
              DropdownMenuItem(value: null, child: Text("Not sure (don't score it)")),
              DropdownMenuItem(value: 'WPA3', child: Text('WPA3')),
              DropdownMenuItem(value: 'WPA2', child: Text('WPA2 (AES)')),
              DropdownMenuItem(value: 'WPA-TKIP', child: Text('WPA / TKIP (old)')),
              DropdownMenuItem(value: 'WEP', child: Text('WEP (very old)')),
              DropdownMenuItem(value: 'OPEN', child: Text('Open, no password')),
            ],
            onChanged: (value) => setState(() => _wifiSecurity = value),
          ),
          const SizedBox(height: 16),
          FilledButton(onPressed: _running ? null : _run, child: Text(_running ? _status : 'Run audit')),
          if (_error != null)
            Padding(
              padding: const EdgeInsets.only(top: 12),
              child: Text(_error!, style: TextStyle(color: Theme.of(context).colorScheme.error)),
            ),
          if (result != null) _ResultCard(result: result),
        ],
      ),
    );
  }
}

class _ResultCard extends StatelessWidget {
  const _ResultCard({required this.result});

  final Map<String, dynamic> result;

  @override
  Widget build(BuildContext context) {
    final findings = (result['findings'] as List).cast<Map<String, dynamic>>();
    final notChecked = (result['not_checked'] as List).cast<String>();
    return Card(
      margin: const EdgeInsets.only(top: 20),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text('Grade ${result['grade']} (${result['score']}/100)', style: Theme.of(context).textTheme.headlineSmall),
            Text('${findings.length} thing(s) to fix'),
            const Divider(height: 24),
            for (final f in findings)
              Padding(
                padding: const EdgeInsets.only(bottom: 12),
                child: Text('[${(f['severity'] as String).toUpperCase()}] ${f['title']}\nFix: ${f['fix']}'),
              ),
            if (notChecked.isNotEmpty) Text('Not checked: ${notChecked.join(', ')}'),
            const SizedBox(height: 8),
            SelectableText('Full audit: ${result['url']}'),
          ],
        ),
      ),
    );
  }
}
