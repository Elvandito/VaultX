import 'dart:convert';
import 'dart:io';
import 'dart:math';
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
  SystemChrome.setSystemUIOverlayStyle(const SystemUiOverlayStyle(
    statusBarColor: Colors.transparent,
    systemNavigationBarColor: Colors.black,
    systemNavigationBarIconBrightness: Brightness.light,
  ));
  runApp(const VaultXApp());
}

class AppTheme {
  static const Color accent = Color(0xFF6366F1);
  static const Color surface = Color(0xFF0F0F0F);
  static const Color border = Color(0xFF262626);
  static const Color textMuted = Color(0xFFA1A1AA);

  static ThemeData get dark => ThemeData(
    useMaterial3: true,
    brightness: Brightness.dark,
    scaffoldBackgroundColor: Colors.black,
    fontFamily: 'Inter',
    colorScheme: const ColorScheme.dark(primary: accent, surface: surface, outline: border),
    appBarTheme: const AppBarTheme(backgroundColor: Colors.transparent, elevation: 0, centerTitle: true),
    floatingActionButtonTheme: const FloatingActionButtonThemeData(
      backgroundColor: accent,
      foregroundColor: Colors.white,
      shape: CircleBorder(),
    ),
  );
}

class CryptoEngine {
  static final _aes = AesGcm.with256bits();
  static Future<SecretKey> deriveKey(String pin, List<int> salt) async {
    final pbkdf2 = Pbkdf2(macAlgorithm: Hmac.sha256(), iterations: 100000, bits: 256);
    return await pbkdf2.deriveKey(secretKey: SecretKey(utf8.encode(pin)), nonce: salt);
  }
  static Future<Map<String, String>> encrypt(Map<String, dynamic> data, SecretKey key) async {
    final iv = List<int>.generate(12, (i) => Random.secure().nextInt(256));
    final box = await _aes.encrypt(utf8.encode(jsonEncode(data)), secretKey: key, nonce: iv);
    return {'c': base64Encode(box.cipherText + box.mac.bytes), 'i': base64Encode(iv)};
  }
  static Future<Map<String, dynamic>> decrypt(String c64, String i64, SecretKey key) async {
    final iv = base64Decode(i64);
    final combined = base64Decode(c64);
    final cipher = combined.sublist(0, combined.length - 16);
    final mac = combined.sublist(combined.length - 16);
    final dec = await _aes.decrypt(SecretBox(cipher, nonce: iv, mac: Mac(mac)), secretKey: key);
    return jsonDecode(utf8.decode(dec));
  }
}

class VaultState extends ChangeNotifier {
  SecretKey? _key;
  Map<String, dynamic>? vault;
  bool isAuth = false;

  Future<void> init(String pin) async {
    final salt = List<int>.generate(16, (i) => Random.secure().nextInt(256));
    _key = await CryptoEngine.deriveKey(pin, salt);
    vault = {'items': []};
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString('v_salt', base64Encode(salt));
    await save();
    isAuth = true;
    notifyListeners();
  }

  Future<bool> unlock(String pin) async {
    try {
      final prefs = await SharedPreferences.getInstance();
      final salt = base64Decode(prefs.getString('v_salt')!);
      final data = jsonDecode(prefs.getString('v_data')!);
      _key = await CryptoEngine.deriveKey(pin, salt);
      vault = await CryptoEngine.decrypt(data['c'], data['i'], _key!);
      isAuth = true;
      notifyListeners();
      return true;
    } catch (_) { return false; }
  }

  Future<void> save() async {
    if (_key == null || vault == null) return;
    final enc = await CryptoEngine.encrypt(vault!, _key!);
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString('v_data', jsonEncode(enc));
    notifyListeners();
  }

  void logout() { _key = null; vault = null; isAuth = false; notifyListeners(); }
}

class VaultXApp extends StatelessWidget {
  const VaultXApp({super.key});
  @override
  Widget build(BuildContext context) {
    return MaterialApp(theme: AppTheme.dark, home: const MainWrapper(), debugShowCheckedModeBanner: false);
  }
}

class MainWrapper extends StatefulWidget {
  const MainWrapper({super.key});
  @override
  State<MainWrapper> createState() => _MainWrapperState();
}

class _MainWrapperState extends State<MainWrapper> {
  final state = VaultState();
  @override
  Widget build(BuildContext ctx) => ListenableBuilder(listenable: state, builder: (c, _) => state.isAuth ? Dashboard(state: state) : Login(state: state));
}

class Login extends StatefulWidget {
  final VaultState state;
  const Login({super.key, required this.state});
  @override
  State<Login> createState() => _LoginState();
}

class _LoginState extends State<Login> {
  String pin = "";
  bool error = false;

  void _onPress(String v) {
    HapticFeedback.selectionClick();
    setState(() {
      error = false;
      if (v == "C") pin = "";
      else if (v == "D") pin = pin.isNotEmpty ? pin.substring(0, pin.length - 1) : "";
      else if (pin.length < 4) pin += v;
    });
    if (pin.length == 4) _submit();
  }

  Future<void> _submit() async {
    final prefs = await SharedPreferences.getInstance();
    bool ok = false;
    
    if (prefs.containsKey('v_data')) {
      ok = await widget.state.unlock(pin);
    } else {
      await widget.state.init(pin);
      ok = true;
    }

    if (!ok) {
      HapticFeedback.vibrate();
      setState(() { error = true; pin = ""; });
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: SafeArea(
        child: Column(
          children: [
            const Spacer(),
            const Icon(Icons.shield_rounded, size: 72, color: AppTheme.accent),
            const SizedBox(height: 24),
            const Text("VAULTX", style: TextStyle(fontSize: 32, fontWeight: FontWeight.w900, letterSpacing: 8)),
            const Text("SECURE LOCAL STORAGE", style: TextStyle(color: AppTheme.textMuted, fontSize: 10, letterSpacing: 2)),
            const SizedBox(height: 64),
            Row(
              mainAxisAlignment: MainAxisAlignment.center,
              children: List.generate(4, (i) => AnimatedContainer(
                duration: const Duration(milliseconds: 200),
                margin: const EdgeInsets.symmetric(horizontal: 16),
                width: 16, height: 16,
                decoration: BoxDecoration(
                  shape: BoxShape.circle,
                  border: Border.all(color: error ? Colors.redAccent : AppTheme.border, width: 2),
                  color: pin.length > i ? (error ? Colors.redAccent : AppTheme.accent) : Colors.transparent,
                ),
              )),
            ),
            const Spacer(),
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 40),
              child: GridView.count(
                shrinkWrap: true,
                crossAxisCount: 3,
                mainAxisSpacing: 24,
                crossAxisSpacing: 24,
                children: [
                  ...List.generate(9, (i) => _keyBtn((i + 1).toString())),
                  _keyBtn("C", icon: Icons.refresh_rounded),
                  _keyBtn("0"),
                  _keyBtn("D", icon: Icons.backspace_outlined),
                ],
              ),
            ),
            const SizedBox(height: 48),
          ],
        ),
      ),
    );
  }

  Widget _keyBtn(String v, {IconData? icon}) {
    return InkWell(
      onTap: () => _onPress(v),
      borderRadius: BorderRadius.circular(50),
      child: Container(
        decoration: BoxDecoration(shape: BoxShape.circle, border: Border.all(color: AppTheme.border)),
        alignment: Alignment.center,
        child: icon != null ? Icon(icon, color: Colors.white60, size: 20) : Text(v, style: const TextStyle(fontSize: 24, fontWeight: FontWeight.w500)),
      ),
    );
  }
}

class Dashboard extends StatefulWidget {
  final VaultState state;
  const Dashboard({super.key, required this.state});
  @override
  State<Dashboard> createState() => _DashboardState();
}

class _DashboardState extends State<Dashboard> {
  int tab = 0;
  String query = "";

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: tab == 4 ? const Text("SETTINGS") : const Text("VAULTX", style: TextStyle(fontWeight: FontWeight.w900, letterSpacing: 4)),
        actions: [IconButton(onPressed: widget.state.logout, icon: const Icon(Icons.lock_outline_rounded, size: 20))],
      ),
      body: tab == 4 ? SettingsView(state: widget.state) : _buildList(),
      bottomNavigationBar: BottomNavigationBar(
        backgroundColor: Colors.black,
        selectedItemColor: AppTheme.accent,
        unselectedItemColor: AppTheme.textMuted,
        currentIndex: tab,
        onTap: (i) => setState(() => tab = i),
        type: BottomNavigationBarType.fixed,
        items: const [
          BottomNavigationBarItem(icon: Icon(Icons.grid_view_rounded), label: "All"),
          BottomNavigationBarItem(icon: Icon(Icons.star_rounded), label: "Fav"),
          BottomNavigationBarItem(icon: Icon(Icons.password_rounded), label: "Pass"),
          BottomNavigationBarItem(icon: Icon(Icons.key_rounded), label: "Keys"),
          BottomNavigationBarItem(icon: Icon(Icons.person_rounded), label: "Dev"),
        ],
      ),
      floatingActionButton: tab != 4 ? FloatingActionButton(onPressed: () => _showForm(), child: const Icon(Icons.add_rounded)) : null,
    );
  }

  Widget _buildList() {
    final items = (widget.state.vault?['items'] as List? ?? []).where((i) {
      if (tab == 1 && i['fav'] != true) return false;
      if (tab == 2 && i['type'] != 'pass') return false;
      if (tab == 3 && i['type'] != 'key') return false;
      return i['title'].toString().toLowerCase().contains(query.toLowerCase());
    }).toList();

    return Column(
      children: [
        if (tab == 0) Padding(
          padding: const EdgeInsets.all(20),
          child: TextField(
            onChanged: (v) => setState(() => query = v),
            decoration: InputDecoration(hintText: "Search vault...", prefixIcon: const Icon(Icons.search, size: 18), filled: true, fillColor: AppTheme.surface, border: OutlineInputBorder(borderRadius: BorderRadius.circular(16), borderSide: BorderSide.none)),
          ),
        ),
        Expanded(
          child: items.isEmpty 
            ? const Center(child: Text("Empty", style: TextStyle(color: AppTheme.textMuted))) 
            : ListView.builder(
                padding: const EdgeInsets.symmetric(horizontal: 20),
                itemCount: items.length,
                itemBuilder: (c, i) => _ItemCard(item: items[i], state: widget.state, onEdit: () => _showForm(items[i])),
              ),
        ),
      ],
    );
  }

  void _showForm([Map? item]) {
    showModalBottomSheet(context: context, isScrollControlled: true, backgroundColor: Colors.transparent, builder: (c) => _ItemForm(state: widget.state, item: item));
  }
}

class _ItemCard extends StatefulWidget {
  final Map item;
  final VaultState state;
  final VoidCallback onEdit;
  const _ItemCard({required this.item, required this.state, required this.onEdit});
  @override
  State<_ItemCard> createState() => _ItemCardState();
}

class _ItemCardState extends State<_ItemCard> {
  bool show = false;
  final screenshot = ScreenshotController();

  void _showPreview() {
    showDialog(
      context: context,
      builder: (ctx) => Dialog(
        backgroundColor: Colors.transparent,
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Screenshot(
              controller: screenshot,
              child: Container(
                width: 320,
                padding: const EdgeInsets.all(32),
                decoration: BoxDecoration(
                  color: const Color(0xFF0A0A0A),
                  borderRadius: BorderRadius.circular(24),
                  border: Border.all(color: AppTheme.accent, width: 1.5),
                ),
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    const Icon(Icons.shield_rounded, color: AppTheme.accent, size: 40),
                    const SizedBox(height: 16),
                    Text(widget.item['title'].toUpperCase(), style: const TextStyle(fontSize: 20, fontWeight: FontWeight.w900, letterSpacing: 2)),
                    Text(widget.item['user'] ?? "SECURE ACCESS", style: const TextStyle(color: AppTheme.textMuted, fontSize: 12)),
                    const SizedBox(height: 24),
                    Container(
                      padding: const EdgeInsets.all(12),
                      decoration: BoxDecoration(color: Colors.white, borderRadius: BorderRadius.circular(16)),
                      child: QrImageView(data: widget.item['sec'], size: 160),
                    ),
                    const SizedBox(height: 24),
                    const Text("VAULTX PROTECTION", style: TextStyle(fontSize: 8, letterSpacing: 4, color: AppTheme.accent)),
                  ],
                ),
              ),
            ),
            const SizedBox(height: 24),
            Row(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                TextButton(onPressed: () => Navigator.pop(ctx), child: const Text("CLOSE", style: TextStyle(color: Colors.white60))),
                const SizedBox(width: 16),
                ElevatedButton.icon(
                  onPressed: () async {
                    final bytes = await screenshot.capture();
                    if (bytes != null) {
                      final path = (await getTemporaryDirectory()).path;
                      final file = await File('$path/vault_snap.png').create();
                      await file.writeAsBytes(bytes);
                      await Share.shareXFiles([XFile(file.path)], text: "VaultX Secure Snapshot: ${widget.item['title']}");
                    }
                  },
                  icon: const Icon(Icons.share_rounded, size: 18),
                  label: const Text("SHARE SNAP"),
                ),
              ],
            )
          ],
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Container(
      margin: const EdgeInsets.only(bottom: 16),
      decoration: BoxDecoration(color: AppTheme.surface, borderRadius: BorderRadius.circular(20), border: Border.all(color: AppTheme.border)),
      child: Column(
        children: [
          ListTile(
            title: Text(widget.item['title'], style: const TextStyle(fontWeight: FontWeight.bold)),
            subtitle: Text(widget.item['user'] ?? "", style: const TextStyle(color: AppTheme.textMuted, fontSize: 12)),
            trailing: IconButton(
              icon: Icon(widget.item['fav'] == true ? Icons.star_rounded : Icons.star_border_rounded, color: widget.item['fav'] == true ? Colors.amber : AppTheme.textMuted),
              onPressed: () { widget.item['fav'] = !(widget.item['fav'] ?? false); widget.state.save(); },
            ),
          ),
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 0, 16, 16),
            child: Row(
              children: [
                Expanded(
                  child: GestureDetector(
                    onTap: () => setState(() => show = !show),
                    child: Container(
                      padding: const EdgeInsets.all(12),
                      decoration: BoxDecoration(color: Colors.black, borderRadius: BorderRadius.circular(12), border: Border.all(color: AppTheme.border)),
                      child: Text(show ? widget.item['sec'] : "••••••••••••", style: const TextStyle(fontFamily: 'monospace')),
                    ),
                  ),
                ),
                const SizedBox(width: 8),
                _btn(Icons.qr_code_2_rounded, _showPreview),
                const SizedBox(width: 8),
                _btn(Icons.copy_rounded, () { 
                  Clipboard.setData(ClipboardData(text: widget.item['sec']));
                  ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text("Copied to clipboard"), duration: Duration(seconds: 1)));
                }),
                const SizedBox(width: 8),
                _btn(Icons.edit_note_rounded, widget.onEdit),
              ],
            ),
          )
        ],
      ),
    );
  }

  Widget _btn(IconData i, VoidCallback t) => InkWell(onTap: t, child: Container(padding: const EdgeInsets.all(10), decoration: BoxDecoration(color: AppTheme.border, borderRadius: BorderRadius.circular(12)), child: Icon(i, size: 18)));
}

class _ItemForm extends StatefulWidget {
  final VaultState state;
  final Map? item;
  const _ItemForm({required this.state, this.item});
  @override
  State<_ItemForm> createState() => _ItemFormState();
}

class _ItemFormState extends State<_ItemForm> {
  late TextEditingController t, u, s;
  String type = 'pass';

  @override
  void initState() {
    super.initState();
    t = TextEditingController(text: widget.item?['title']);
    u = TextEditingController(text: widget.item?['user']);
    s = TextEditingController(text: widget.item?['sec']);
    type = widget.item?['type'] ?? 'pass';
  }

  @override
  Widget build(BuildContext context) {
    return Container(
      decoration: const BoxDecoration(color: Color(0xFF121212), borderRadius: BorderRadius.vertical(top: Radius.circular(24))),
      padding: EdgeInsets.fromLTRB(24, 16, 24, MediaQuery.of(context).viewInsets.bottom + 24),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Container(width: 40, height: 4, decoration: BoxDecoration(color: AppTheme.border, borderRadius: BorderRadius.circular(2))),
          const SizedBox(height: 24),
          Row(
            children: [
              _chip("PASSWORD", "pass"),
              const SizedBox(width: 12),
              _chip("API KEY", "key"),
            ],
          ),
          const SizedBox(height: 24),
          _field(t, "Title"),
          const SizedBox(height: 16),
          _field(u, "Username"),
          const SizedBox(height: 16),
          _field(s, "Secret"),
          const SizedBox(height: 32),
          Row(
            children: [
              if (widget.item != null) IconButton(onPressed: () { widget.state.vault?['items'].remove(widget.item); widget.state.save(); Navigator.pop(context); }, icon: const Icon(Icons.delete_outline, color: Colors.redAccent)),
              const Spacer(),
              ElevatedButton(
                onPressed: () {
                  final data = {'title': t.text, 'user': u.text, 'sec': s.text, 'type': type, 'fav': widget.item?['fav'] ?? false};
                  if (widget.item != null) {
                    final i = (widget.state.vault?['items'] as List).indexOf(widget.item);
                    widget.state.vault?['items'][i] = data;
                  } else {
                    (widget.state.vault?['items'] as List).add(data);
                  }
                  widget.state.save();
                  Navigator.pop(context);
                },
                child: const Text("SAVE"),
              )
            ],
          )
        ],
      ),
    );
  }

  Widget _chip(String l, String v) => Expanded(child: GestureDetector(onTap: () => setState(() => type = v), child: Container(padding: const EdgeInsets.all(12), decoration: BoxDecoration(color: type == v ? AppTheme.accent : Colors.black, borderRadius: BorderRadius.circular(12), border: Border.all(color: type == v ? AppTheme.accent : AppTheme.border)), alignment: Alignment.center, child: Text(l, style: const TextStyle(fontSize: 10, fontWeight: FontWeight.bold)))));
  Widget _field(TextEditingController c, String l) => TextField(controller: c, decoration: InputDecoration(labelText: l, filled: true, fillColor: Colors.black, border: OutlineInputBorder(borderRadius: BorderRadius.circular(12), borderSide: BorderSide.none)));
}

class SettingsView extends StatelessWidget {
  final VaultState state;
  const SettingsView({super.key, required this.state});
  @override
  Widget build(BuildContext context) {
    return ListView(
      padding: const EdgeInsets.all(24),
      children: [
        const Text("DEVELOPER CONTACT", style: TextStyle(color: AppTheme.textMuted, fontSize: 10, letterSpacing: 2, fontWeight: FontWeight.bold)),
        const SizedBox(height: 16),
        _card("Telegram", "@Vann759", Icons.telegram, "https://t.me/Vann759"),
        _card("GitHub", "Elvandito", Icons.code_rounded, "https://github.com/Elvandito"),
        _card("Email", "ditoelvan2@gmail.com", Icons.email_rounded, "mailto:ditoelvan2@gmail.com"),
        const SizedBox(height: 48),
        ListTile(
          tileColor: AppTheme.surface,
          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
          title: const Text("Logout & Lock", style: TextStyle(color: Colors.redAccent)),
          trailing: const Icon(Icons.logout_rounded, color: Colors.redAccent),
          onTap: state.logout,
        ),
      ],
    );
  }

  Widget _card(String t, String v, IconData i, String url) => Card(color: AppTheme.surface, margin: const EdgeInsets.only(bottom: 12), shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)), child: ListTile(leading: Icon(i, color: AppTheme.accent), title: Text(t, style: const TextStyle(fontSize: 12)), subtitle: Text(v, style: const TextStyle(fontWeight: FontWeight.bold)), onTap: () => launchUrl(Uri.parse(url))));
}