import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'package:flutter/cupertino.dart';
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
  SystemChrome.setSystemUIOverlayStyle(SystemUiOverlayStyle.light);
  runApp(const VaultXApp());
}

class AppTheme {
  static const Color primary = CupertinoColors.activeBlue;
  static const Color bg = CupertinoColors.black;
  static const Color surface = Color(0xFF1C1C1E);
  static const Color border = Color(0xFF2C2C2E);
  static const Color textMuted = CupertinoColors.systemGrey;

  static CupertinoThemeData get iosTheme => const CupertinoThemeData(
    brightness: Brightness.dark,
    primaryColor: primary,
    scaffoldBackgroundColor: bg,
    barBackgroundColor: Color(0xEE1C1C1E),
    textTheme: CupertinoTextThemeData(primaryColor: CupertinoColors.white),
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
      final saltStr = prefs.getString('v_salt');
      final dataStr = prefs.getString('v_data');
      if (saltStr == null || dataStr == null) return false;
      _key = await CryptoEngine.deriveKey(pin, base64Decode(saltStr));
      final data = jsonDecode(dataStr);
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
    return CupertinoApp(theme: AppTheme.iosTheme, home: const MainWrapper(), debugShowCheckedModeBanner: false);
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
    HapticFeedback.lightImpact();
    setState(() {
      error = false;
      if (v == "D") pin = pin.isNotEmpty ? pin.substring(0, pin.length - 1) : "";
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
    if (!ok) { HapticFeedback.heavyImpact(); setState(() { error = true; pin = ""; }); }
  }

  @override
  Widget build(BuildContext context) {
    return CupertinoPageScaffold(
      child: SafeArea(
        child: Column(
          children: [
            const Spacer(),
            const Icon(CupertinoIcons.shield_fill, size: 80, color: AppTheme.primary),
            const SizedBox(height: 12),
            const Text("VaultX", style: TextStyle(fontSize: 34, fontWeight: FontWeight.bold, letterSpacing: -1)),
            const SizedBox(height: 48),
            Row(
              mainAxisAlignment: MainAxisAlignment.center,
              children: List.generate(4, (i) => Container(
                margin: const EdgeInsets.symmetric(horizontal: 12),
                width: 14, height: 14,
                decoration: BoxDecoration(
                  shape: BoxShape.circle,
                  border: Border.all(color: error ? CupertinoColors.systemRed : AppTheme.border, width: 2),
                  color: pin.length > i ? (error ? CupertinoColors.systemRed : CupertinoColors.white) : Colors.transparent,
                ),
              )),
            ),
            const Spacer(),
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 40, vertical: 40),
              child: GridView.count(
                shrinkWrap: true,
                crossAxisCount: 3,
                mainAxisSpacing: 20,
                crossAxisSpacing: 20,
                children: [
                  ...List.generate(9, (i) => _kBtn((i + 1).toString())),
                  const SizedBox(), _kBtn("0"), _kBtn("D", icon: CupertinoIcons.delete_left),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _kBtn(String v, {IconData? icon}) => CupertinoButton(
    padding: EdgeInsets.zero,
    onPressed: () => _onPress(v),
    child: Container(
      decoration: const BoxDecoration(shape: BoxShape.circle, color: AppTheme.surface),
      alignment: Alignment.center,
      child: icon != null ? Icon(icon, color: Colors.white, size: 28) : Text(v, style: const TextStyle(fontSize: 32, color: Colors.white, fontWeight: FontWeight.w400)),
    ),
  );
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
    return CupertinoTabScaffold(
      tabBar: CupertinoTabBar(
        currentIndex: tab,
        onTap: (i) => setState(() => tab = i),
        items: const [
          BottomNavigationBarItem(icon: Icon(CupertinoIcons.lock_shield_fill), label: 'Vault'),
          BottomNavigationBarItem(icon: Icon(CupertinoIcons.star_fill), label: 'Favs'),
          BottomNavigationBarItem(icon: Icon(CupertinoIcons.person_crop_circle_fill), label: 'Dev'),
        ],
      ),
      tabBuilder: (c, i) => CupertinoPageScaffold(
        navigationBar: CupertinoNavigationBar(
          middle: const Text("VaultX"),
          trailing: CupertinoButton(padding: EdgeInsets.zero, child: const Icon(CupertinoIcons.add_circled, size: 28), onPressed: () => _showForm()),
        ),
        child: i == 2 ? SettingsView(state: widget.state) : _buildList(i),
      ),
    );
  }

  Widget _buildList(int type) {
    final items = (widget.state.vault?['items'] as List? ?? []).where((i) {
      if (type == 1 && i['fav'] != true) return false;
      return i['title'].toString().toLowerCase().contains(query.toLowerCase());
    }).toList();

    return Column(
      children: [
        const SizedBox(height: 90),
        Padding(
          padding: const EdgeInsets.all(16),
          child: CupertinoSearchTextField(onChanged: (v) => setState(() => query = v)),
        ),
        Expanded(
          child: items.isEmpty 
          ? const Center(child: Text("Empty Vault", style: TextStyle(color: AppTheme.textMuted)))
          : ListView.separated(
              padding: const EdgeInsets.symmetric(horizontal: 16),
              itemCount: items.length,
              separatorBuilder: (c, i) => const Divider(color: AppTheme.border, height: 1),
              itemBuilder: (c, i) => _ItemTile(item: items[i], state: widget.state, onEdit: () => _showForm(items[i])),
            ),
        ),
      ],
    );
  }

  void _showForm([Map? item]) {
    showCupertinoModalPopup(context: context, builder: (c) => _ItemForm(state: widget.state, item: item));
  }
}

class _ItemTile extends StatefulWidget {
  final Map item;
  final VaultState state;
  final VoidCallback onEdit;
  const _ItemTile({required this.item, required this.state, required this.onEdit});
  @override
  State<_ItemTile> createState() => _ItemTileState();
}

class _ItemTileState extends State<_ItemTile> {
  bool show = false;
  final ss = ScreenshotController();

  IconData _getTypeIcon(String t) {
    switch(t) {
      case 'pass': return CupertinoIcons.lock_fill;
      case 'key': return CupertinoIcons.key; // FIXED: key_fill changed to key
      case 'note': return CupertinoIcons.doc_text_fill;
      case 'card': return CupertinoIcons.creditcard_fill;
      case 'wifi': return CupertinoIcons.wifi;
      default: return CupertinoIcons.lock_shield_fill;
    }
  }

  void _preview() {
    showCupertinoDialog(context: context, builder: (ctx) => CupertinoAlertDialog(
      title: Text(widget.item['title']),
      content: Screenshot(
        controller: ss,
        child: Container(
          padding: const EdgeInsets.all(20),
          decoration: BoxDecoration(color: AppTheme.bg, borderRadius: BorderRadius.circular(12), border: Border.all(color: AppTheme.primary)),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Icon(_getTypeIcon(widget.item['type']), color: AppTheme.primary, size: 40),
              const SizedBox(height: 12),
              Text(widget.item['user'] ?? "", style: const TextStyle(fontWeight: FontWeight.bold, color: Colors.white)),
              const SizedBox(height: 16),
              Container(color: Colors.white, padding: const EdgeInsets.all(8), child: QrImageView(data: widget.item['sec'], size: 140)),
            ],
          ),
        ),
      ),
      actions: [
        CupertinoDialogAction(child: const Text("Close"), onPressed: () => Navigator.pop(ctx)),
        CupertinoDialogAction(child: const Text("Share Snap"), onPressed: () async {
          final b = await ss.capture();
          if (b != null) {
            final p = (await getTemporaryDirectory()).path;
            final f = await File('$p/v.png').create();
            await f.writeAsBytes(b);
            await Share.shareXFiles([XFile(f.path)]);
          }
        }),
      ],
    ));
  }

  @override
  Widget build(BuildContext context) {
    return Container(
      color: AppTheme.surface,
      child: CupertinoButton(
        padding: const EdgeInsets.all(16),
        onPressed: () => setState(() => show = !show),
        child: Row(
          children: [
            Icon(_getTypeIcon(widget.item['type'] ?? 'pass'), color: AppTheme.primary, size: 24),
            const SizedBox(width: 16),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(widget.item['title'], style: const TextStyle(color: Colors.white, fontWeight: FontWeight.w600)),
                  Text(show ? widget.item['sec'] : "••••••••", style: const TextStyle(color: AppTheme.textMuted, fontSize: 13)),
                ],
              ),
            ),
            CupertinoButton(padding: EdgeInsets.zero, child: Icon(widget.item['fav'] == true ? CupertinoIcons.star_fill : CupertinoIcons.star, size: 20), onPressed: () { widget.item['fav'] = !(widget.item['fav'] ?? false); widget.state.save(); }),
            CupertinoButton(padding: EdgeInsets.zero, child: const Icon(CupertinoIcons.qrcode, size: 20), onPressed: _preview),
            CupertinoButton(padding: EdgeInsets.zero, child: const Icon(CupertinoIcons.pencil_circle, size: 20), onPressed: widget.onEdit),
          ],
        ),
      ),
    );
  }
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
    return CupertinoActionSheet(
      title: const Text("Credential Details"),
      message: Column(
        children: [
          const SizedBox(height: 12),
          SizedBox(
            height: 40,
            child: ListView(
              scrollDirection: Axis.horizontal,
              children: [
                _tBtn("Password", "pass"), _tBtn("API Key", "key"), _tBtn("Note", "note"), _tBtn("Card", "card"), _tBtn("WiFi", "wifi"),
              ],
            ),
          ),
          const SizedBox(height: 16),
          CupertinoTextField(controller: t, placeholder: "Title (e.g. GitHub)", padding: const EdgeInsets.all(12)),
          const SizedBox(height: 10),
          CupertinoTextField(controller: u, placeholder: "Username / Email", padding: const EdgeInsets.all(12)),
          const SizedBox(height: 10),
          CupertinoTextField(controller: s, placeholder: "Secret Data", padding: const EdgeInsets.all(12)),
        ],
      ),
      actions: [
        CupertinoActionSheetAction(
          onPressed: () {
            final data = {'title': t.text, 'user': u.text, 'sec': s.text, 'type': type, 'fav': widget.item?['fav'] ?? false};
            final list = (widget.state.vault?['items'] as List);
            if (widget.item != null) {
              list[list.indexOf(widget.item)] = data;
            } else {
              list.add(data);
            }
            widget.state.save();
            Navigator.pop(context);
          },
          child: const Text("Save Securely"),
        ),
        if (widget.item != null) CupertinoActionSheetAction(
          isDestructiveAction: true,
          onPressed: () { (widget.state.vault?['items'] as List).remove(widget.item); widget.state.save(); Navigator.pop(context); },
          child: const Text("Delete"),
        ),
      ],
      cancelButton: CupertinoActionSheetAction(child: const Text("Cancel"), onPressed: () => Navigator.pop(context)),
    );
  }

  Widget _tBtn(String l, String v) => Padding(
    padding: const EdgeInsets.only(right: 8),
    child: CupertinoButton(
      padding: const EdgeInsets.symmetric(horizontal: 16),
      color: type == v ? AppTheme.primary : AppTheme.surface,
      borderRadius: BorderRadius.circular(20),
      onPressed: () => setState(() => type = v),
      child: Text(l, style: TextStyle(fontSize: 12, color: type == v ? Colors.white : AppTheme.textMuted)),
    ),
  );
}

class SettingsView extends StatelessWidget {
  final VaultState state;
  const SettingsView({super.key, required this.state});
  @override
  Widget build(BuildContext context) {
    return ListView(
      padding: const EdgeInsets.fromLTRB(16, 110, 16, 16),
      children: [
        const Text("DEVELOPER CONTACT", style: TextStyle(color: AppTheme.textMuted, fontSize: 13, fontWeight: FontWeight.bold)),
        const SizedBox(height: 12),
        _row("Telegram", "@Vann759", "https://t.me/Vann759"),
        _row("GitHub", "Elvandito", "https://github.com/Elvandito"),
        _row("Email", "ditoelvan2@gmail.com", "mailto:ditoelvan2@gmail.com"),
        const SizedBox(height: 40),
        CupertinoButton(
          color: CupertinoColors.systemRed.withOpacity(0.1),
          child: const Text("Wipe All Data", style: TextStyle(color: CupertinoColors.systemRed)),
          onPressed: () async {
            final p = await SharedPreferences.getInstance();
            await p.clear();
            state.logout();
          },
        ),
        const SizedBox(height: 12),
        CupertinoButton(child: const Text("Logout & Lock"), onPressed: state.logout),
      ],
    );
  }
  Widget _row(String l, String v, String u) => Container(
    margin: const EdgeInsets.only(bottom: 1),
    color: AppTheme.surface,
    child: CupertinoButton(
      padding: const EdgeInsets.all(16),
      onPressed: () => launchUrl(Uri.parse(u)),
      child: Row(children: [Text(l, style: const TextStyle(color: Colors.white)), const Spacer(), Text(v, style: const TextStyle(color: AppTheme.textMuted, fontSize: 14)), const SizedBox(width: 8), const Icon(CupertinoIcons.chevron_right, size: 14, color: AppTheme.textMuted)]),
    ),
  );
}