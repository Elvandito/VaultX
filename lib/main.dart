import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:cryptography/cryptography.dart';
import 'package:qr_flutter/qr_flutter.dart';
import 'package:screenshot/screenshot.dart';
import 'package:share_plus/share_plus.dart';
import 'package:path_provider/path_provider.dart';
import 'package:url_launcher/url_launcher.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  SystemChrome.setSystemUIOverlayStyle(
    const SystemUiOverlayStyle(
      statusBarColor: Colors.transparent,
      systemNavigationBarColor: AppTheme.bgBase,
    ),
  );
  runApp(const VaultXApp());
}

class AppTheme {
  static const bgBase = Color(0xFF000000);
  static const bgSurface = Color(0xFF0A0A0A);
  static const bgCard = Color(0xFF121212);
  static const border = Color(0xFF1F1F1F);
  static const textMain = Color(0xFFEDEDED);
  static const textMuted = Color(0xFF888888);
  static const accent = Color(0xFF5E6AD2);
  static const danger = Color(0xFFE5484D);
  static const warning = Color(0xFFF5A623);

  static ThemeData get darkTheme {
    return ThemeData(
      brightness: Brightness.dark,
      scaffoldBackgroundColor: bgBase,
      primaryColor: Colors.white,
      colorScheme: const ColorScheme.dark(
        primary: Colors.white,
        secondary: accent,
        surface: bgSurface,
      ),
      fontFamily: 'Inter',
      cardTheme: CardTheme(
        color: bgCard,
        elevation: 0,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(12),
          side: const BorderSide(color: border),
        ),
      ),
    );
  }
}

// Crypto Logic (AES-GCM 256)
class CryptoEngine {
  static final _aes = AesGcm.with256bits();
  static final _mac = Hmac.sha256();

  static Future<SecretKey> deriveKey(String pin, List<int> salt) async {
    final pbkdf2 = Pbkdf2(macAlgorithm: _mac, iterations: 100000, bits: 256);
    return await pbkdf2.deriveKey(secretKey: SecretKey(utf8.encode(pin)), nonce: salt);
  }

  static Future<Map<String, String>> encrypt(Map<String, dynamic> data, SecretKey key) async {
    final iv = List<int>.generate(12, (i) => Random.secure().nextInt(256));
    final secretBox = await _aes.encrypt(utf8.encode(jsonEncode(data)), secretKey: key, nonce: iv);
    return {'c': base64Encode(secretBox.cipherText + secretBox.mac.bytes), 'i': base64Encode(iv)};
  }

  static Future<Map<String, dynamic>> decrypt(String c64, String i64, SecretKey key) async {
    final iv = base64Decode(i64);
    final combined = base64Decode(c64);
    final cipherText = combined.sublist(0, combined.length - 16);
    final mac = combined.sublist(combined.length - 16);
    final dec = await _aes.decrypt(SecretBox(cipherText, nonce: iv, mac: Mac(mac)), secretKey: key);
    return jsonDecode(utf8.decode(dec));
  }
}

class VaultState extends ChangeNotifier {
  SecretKey? _key;
  Map<String, dynamic>? vault;
  bool isAuthenticated = false;
  
  final String kData = 'vlt_pro_d';
  final String kSalt = 'vlt_pro_s';

  Future<void> init(String pin) async {
    final salt = List<int>.generate(16, (i) => Random.secure().nextInt(256));
    _key = await CryptoEngine.deriveKey(pin, salt);
    vault = {'set': {'lockMin': 3}, 'items': []};
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(kSalt, base64Encode(salt));
    await save();
    isAuthenticated = true;
    notifyListeners();
  }

  Future<bool> unlock(String pin) async {
    try {
      final prefs = await SharedPreferences.getInstance();
      final salt = base64Decode(prefs.getString(kSalt)!);
      final data = jsonDecode(prefs.getString(kData)!);
      _key = await CryptoEngine.deriveKey(pin, salt);
      vault = await CryptoEngine.decrypt(data['c'], data['i'], _key!);
      isAuthenticated = true;
      notifyListeners();
      return true;
    } catch (_) { return false; }
  }

  Future<void> save() async {
    if (_key == null) return;
    final enc = await CryptoEngine.encrypt(vault!, _key!);
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(kData, jsonEncode(enc));
    notifyListeners();
  }

  void logout() { _key = null; vault = null; isAuthenticated = false; notifyListeners(); }
}

class VaultXApp extends StatelessWidget {
  const VaultXApp({super.key});
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      theme: AppTheme.darkTheme,
      home: AuthWrapper(),
      debugShowCheckedModeBanner: false,
    );
  }
}

class AuthWrapper extends StatefulWidget {
  @override
  _AuthWrapperState createState() => _AuthWrapperState();
}

class _AuthWrapperState extends State<AuthWrapper> {
  final state = VaultState();
  @override
  Widget build(BuildContext context) {
    return ListenableBuilder(
      listenable: state,
      builder: (ctx, _) => state.isAuthenticated ? Dashboard(state: state) : Login(state: state),
    );
  }
}

class Login extends StatefulWidget {
  final VaultState state;
  Login({required this.state});
  @override
  _LoginState createState() => _LoginState();
}

class _LoginState extends State<Login> {
  String pin = "";
  bool error = false;

  void _press(String v) {
    setState(() {
      error = false;
      if (v == "C") pin = "";
      else if (v == "D") pin = pin.isNotEmpty ? pin.substring(0, pin.length - 1) : "";
      else if (pin.length < 8) pin += v;
    });
  }

  Future<void> _go() async {
    final prefs = await SharedPreferences.getInstance();
    bool success = prefs.containsKey('vlt_pro_d') ? await widget.state.unlock(pin) : (await widget.state.init(pin), true).item2;
    if (!success) setState(() => error = true);
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.all(32),
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              const Icon(Icons.shield, size: 64, color: AppTheme.accent),
              const SizedBox(height: 16),
              const Text("VaultX", style: TextStyle(fontSize: 28, fontWeight: FontWeight.bold)),
              const Text("Secure Offline Vault", style: TextStyle(color: AppTheme.textMuted)),
              const SizedBox(height: 48),
              Container(
                padding: const EdgeInsets.all(20),
                decoration: BoxDecoration(
                  color: AppTheme.bgSurface,
                  borderRadius: BorderRadius.circular(16),
                  border: Border.all(color: error ? AppTheme.danger : AppTheme.border),
                ),
                child: Text(pin.isEmpty ? "ENTER PIN" : "•" * pin.length, style: const TextStyle(fontSize: 24, letterSpacing: 8)),
              ),
              const SizedBox(height: 32),
              Expanded(
                child: GridView.count(
                  crossAxisCount: 3,
                  mainAxisSpacing: 12,
                  crossAxisSpacing: 12,
                  children: [
                    for (var i = 1; i <= 9; i++) _btn(i.toString()),
                    _btn("C", color: AppTheme.textMuted), _btn("0"), _btn("D", icon: Icons.backspace),
                  ],
                ),
              ),
              const SizedBox(height: 16),
              SizedBox(
                width: double.infinity, height: 56,
                child: ElevatedButton(
                  style: ElevatedButton.styleFrom(backgroundColor: Colors.white, foregroundColor: Colors.black),
                  onPressed: pin.length >= 4 ? _go : null,
                  child: const Text("Unlock"),
                ),
              )
            ],
          ),
        ),
      ),
    );
  }

  Widget _btn(String v, {Color? color, IconData? icon}) {
    return InkWell(
      onTap: () => _press(v),
      borderRadius: BorderRadius.circular(12),
      child: Container(
        decoration: BoxDecoration(border: Border.all(color: AppTheme.border), borderRadius: BorderRadius.circular(12)),
        alignment: Alignment.center,
        child: icon != null ? Icon(icon, color: AppTheme.textMuted) : Text(v, style: TextStyle(fontSize: 20, color: color)),
      ),
    );
  }
}

class Dashboard extends StatefulWidget {
  final VaultState state;
  Dashboard({required this.state});
  @override
  _DashboardState createState() => _DashboardState();
}

class _DashboardState extends State<Dashboard> {
  int tab = 0;
  String query = "";

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: tab == 4 ? const Text("Settings") : TextField(
          onChanged: (v) => setState(() => query = v.toLowerCase()),
          decoration: const InputDecoration(hintText: "Search...", border: InputBorder.none, icon: Icon(Icons.search, size: 20)),
        ),
        actions: [
          IconButton(onPressed: widget.state.logout, icon: const Icon(Icons.lock_outline)),
        ],
      ),
      body: tab == 4 ? SettingsView(state: widget.state) : _list(),
      bottomNavigationBar: BottomNavigationBar(
        currentIndex: tab,
        onTap: (i) => setState(() => tab = i),
        type: BottomNavigationBarType.fixed,
        items: const [
          BottomNavigationBarItem(icon: Icon(Icons.apps), label: "All"),
          BottomNavigationBarItem(icon: Icon(Icons.star), label: "Favs"),
          BottomNavigationBarItem(icon: Icon(Icons.password), label: "Pass"),
          BottomNavigationBarItem(icon: Icon(Icons.key), label: "Keys"),
          BottomNavigationBarItem(icon: Icon(Icons.settings), label: "Settings"),
        ],
      ),
      floatingActionButton: tab != 4 ? FloatingActionButton(
        onPressed: () => _showForm(),
        child: const Icon(Icons.add),
      ) : null,
    );
  }

  Widget _list() {
    final items = (widget.state.vault?['items'] as List).where((i) {
      if (tab == 1 && i['fav'] != true) return false;
      if (tab == 2 && i['type'] != 'password') return false;
      if (tab == 3 && i['type'] != 'api_key') return false;
      return i['title'].toString().toLowerCase().contains(query);
    }).toList();

    return ListView.builder(
      padding: const EdgeInsets.all(16),
      itemCount: items.length,
      itemBuilder: (ctx, i) => ItemTile(item: items[i], state: widget.state, onEdit: () => _showForm(items[i])),
    );
  }

  void _showForm([Map? item]) {
    showModalBottomSheet(context: context, isScrollControlled: true, builder: (ctx) => ItemForm(state: widget.state, item: item));
  }
}

class ItemTile extends StatefulWidget {
  final Map item;
  final VaultState state;
  final VoidCallback onEdit;
  ItemTile({required this.item, required this.state, required this.onEdit});
  @override
  _ItemTileState createState() => _ItemTileState();
}

class _ItemTileState extends State<ItemTile> {
  bool visible = false;
  final ss = ScreenshotController();

  void _share() async {
    final image = await ss.captureFromWidget(Container(
      width: 400, padding: const EdgeInsets.all(32),
      decoration: BoxDecoration(
        gradient: const LinearGradient(colors: [Color(0xFF5E6AD2), Color(0xFF9B51E0)]),
        borderRadius: BorderRadius.circular(20),
      ),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Container(
            padding: const EdgeInsets.all(24),
            decoration: BoxDecoration(color: Colors.black, borderRadius: BorderRadius.circular(16)),
            child: Column(
              children: [
                Text(widget.item['title'], style: const TextStyle(fontSize: 22, fontWeight: FontWeight.bold, color: Colors.white)),
                Text(widget.item['username'] ?? "Secure Credential", style: const TextStyle(color: Colors.grey)),
                const SizedBox(height: 20),
                Container(
                  color: Colors.white, padding: const EdgeInsets.all(12),
                  child: QrImageView(data: widget.item['secret'], size: 200),
                ),
              ],
            ),
          ),
          const SizedBox(height: 16),
          const Text("VaultX Pro Share", style: TextStyle(color: Colors.white70)),
        ],
      ),
    ));
    
    final dir = await getTemporaryDirectory();
    final file = await File('${dir.path}/snap.png').create();
    await file.writeAsBytes(image);
    await Share.shareXFiles([XFile(file.path)], text: 'VaultX Share: ${widget.item['title']}');
  }

  @override
  Widget build(BuildContext context) {
    return Card(
      margin: const EdgeInsets.only(bottom: 12),
      child: Padding(
        padding: const EdgeInsets.all(4),
        child: Column(
          children: [
            ListTile(
              leading: const CircleAvatar(backgroundColor: AppTheme.bgBase, child: Icon(Icons.lock, size: 18)),
              title: Text(widget.item['title']),
              subtitle: Text(widget.item['username'] ?? ""),
              trailing: IconButton(
                icon: Icon(widget.item['fav'] == true ? Icons.star : Icons.star_border, color: widget.item['fav'] == true ? AppTheme.warning : null),
                onPressed: () { widget.item['fav'] = !(widget.item['fav'] ?? false); widget.state.save(); },
              ),
            ),
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 16),
              child: Container(
                width: double.infinity, padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(color: Colors.black, borderRadius: BorderRadius.circular(8)),
                child: GestureDetector(
                  onTap: () => setState(() => visible = !visible),
                  child: Text(visible ? widget.item['secret'] : "••••••••••••", textAlign: TextAlign.center, style: const TextStyle(fontFamily: 'monospace')),
                ),
              ),
            ),
            Row(
              mainAxisAlignment: MainAxisAlignment.end,
              children: [
                IconButton(onPressed: _share, icon: const Icon(Icons.qr_code, size: 20)),
                IconButton(onPressed: () => Clipboard.setData(ClipboardData(text: widget.item['secret'])), icon: const Icon(Icons.copy, size: 20)),
                IconButton(onPressed: widget.onEdit, icon: const Icon(Icons.edit, size: 20)),
              ],
            )
          ],
        ),
      ),
    );
  }
}

class ItemForm extends StatefulWidget {
  final VaultState state;
  final Map? item;
  ItemForm({required this.state, this.item});
  @override
  _ItemFormState createState() => _ItemFormState();
}

class _ItemFormState extends State<ItemForm> {
  final title = TextEditingController();
  final user = TextEditingController();
  final secret = TextEditingController();
  String type = "password";

  @override
  void initState() {
    super.initState();
    if (widget.item != null) {
      title.text = widget.item!['title'];
      user.text = widget.item!['username'] ?? "";
      secret.text = widget.item!['secret'];
      type = widget.item!['type'] ?? "password";
    }
  }

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: EdgeInsets.only(bottom: MediaQuery.of(context).viewInsets.bottom, left: 24, right: 24, top: 24),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          const Text("Credential Details", style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold)),
          const SizedBox(height: 20),
          DropdownButton<String>(
            isExpanded: true,
            value: type,
            items: const [
              DropdownMenuItem(value: "password", child: Text("Password")),
              DropdownMenuItem(value: "api_key", child: Text("API Key")),
              DropdownMenuItem(value: "note", child: Text("Secure Note")),
            ],
            onChanged: (v) => setState(() => type = v!),
          ),
          TextField(controller: title, decoration: const InputDecoration(labelText: "Title")),
          TextField(controller: user, decoration: const InputDecoration(labelText: "Username")),
          TextField(controller: secret, decoration: const InputDecoration(labelText: "Secret")),
          const SizedBox(height: 32),
          Row(
            children: [
              if (widget.item != null)
                TextButton(
                  onPressed: () { widget.state.vault?['items'].remove(widget.item); widget.state.save(); Navigator.pop(context); },
                  child: const Text("Delete", style: TextStyle(color: AppTheme.danger)),
                ),
              const Spacer(),
              ElevatedButton(
                onPressed: () {
                  final data = {
                    'title': title.text, 'username': user.text, 'secret': secret.text,
                    'type': type, 'id': widget.item?['id'] ?? DateTime.now().msSinceEpoch,
                    'fav': widget.item?['fav'] ?? false
                  };
                  if (widget.item != null) {
                    final idx = widget.state.vault?['items'].indexOf(widget.item);
                    widget.state.vault?['items'][idx] = data;
                  } else {
                    widget.state.vault?['items'].add(data);
                  }
                  widget.state.save();
                  Navigator.pop(context);
                },
                child: const Text("Save"),
              ),
            ],
          ),
          const SizedBox(height: 24),
        ],
      ),
    );
  }
}

class SettingsView extends StatelessWidget {
  final VaultState state;
  const SettingsView({required this.state});

  void _launch(String url) async => await launchUrl(Uri.parse(url));

  @override
  Widget build(BuildContext context) {
    return ListView(
      padding: const EdgeInsets.all(24),
      children: [
        const Text("Developer Contact", style: TextStyle(fontWeight: FontWeight.bold, color: AppTheme.textMuted)),
        const SizedBox(height: 12),
        _contact("Telegram", "@Vann759", Icons.send, () => _launch("https://t.me/Vann759")),
        _contact("GitHub", "Elvandito", Icons.code, () => _launch("https://github.com/Elvandito")),
        _contact("Email", "ditoelvan2@gmail.com", Icons.email, () => _launch("mailto:ditoelvan2@gmail.com")),
        const SizedBox(height: 32),
        const Text("Security", style: TextStyle(fontWeight: FontWeight.bold, color: AppTheme.textMuted)),
        const SizedBox(height: 12),
        ListTile(
          tileColor: AppTheme.bgSurface,
          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
          title: const Text("Clear All Data", style: TextStyle(color: AppTheme.danger)),
          trailing: const Icon(Icons.delete_forever, color: AppTheme.danger),
          onTap: () async {
            final prefs = await SharedPreferences.getInstance();
            await prefs.clear();
            state.logout();
          },
        ),
      ],
    );
  }

  Widget _contact(String lbl, String val, IconData icon, VoidCallback tap) {
    return ListTile(
      onTap: tap,
      leading: Icon(icon, color: AppTheme.accent),
      title: Text(lbl),
      subtitle: Text(val),
      trailing: const Icon(Icons.open_in_new, size: 16),
    );
  }
}

extension Ms on DateTime { int get msSinceEpoch => millisecondsSinceEpoch; }