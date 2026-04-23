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
    barBackgroundColor: Color(0xCC1C1C1E), // Glassmorphism blur
    textTheme: CupertinoTextThemeData(
      primaryColor: CupertinoColors.white,
      navLargeTitleTextStyle: TextStyle(
        inherit: false,
        fontSize: 34,
        fontWeight: FontWeight.w800,
        color: CupertinoColors.white,
        letterSpacing: -1.0,
      ),
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
    return CupertinoApp(
      theme: AppTheme.iosTheme,
      home: const MainWrapper(),
      debugShowCheckedModeBanner: false,
    );
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
  Widget build(BuildContext ctx) => ListenableBuilder(
    listenable: state, 
    builder: (c, _) => state.isAuth ? Dashboard(state: state) : Login(state: state)
  );
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
    HapticFeedback.mediumImpact();
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
    if (!ok) {
      HapticFeedback.heavyImpact();
      setState(() { error = true; pin = ""; });
    }
  }

  @override
  Widget build(BuildContext context) {
    return CupertinoPageScaffold(
      child: SafeArea(
        child: Column(
          children: [
            const Spacer(flex: 2),
            const Icon(CupertinoIcons.lock_shield_fill, size: 84, color: AppTheme.primary),
            const SizedBox(height: 20),
            const Text("VaultX", style: TextStyle(fontSize: 34, fontWeight: FontWeight.bold, letterSpacing: -0.5)),
            const Text("Private Offline Vault", style: TextStyle(color: AppTheme.textMuted, fontSize: 15)),
            const SizedBox(height: 48),
            Row(
              mainAxisAlignment: MainAxisAlignment.center,
              children: List.generate(4, (i) => AnimatedContainer(
                duration: const Duration(milliseconds: 200),
                margin: const EdgeInsets.symmetric(horizontal: 14),
                width: 16, height: 16,
                decoration: BoxDecoration(
                  shape: BoxShape.circle,
                  border: Border.all(color: error ? CupertinoColors.systemRed : AppTheme.border, width: 2),
                  color: pin.length > i ? (error ? CupertinoColors.systemRed : CupertinoColors.white) : Colors.transparent,
                ),
              )),
            ),
            const Spacer(flex: 3),
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 40, vertical: 40),
              child: GridView.count(
                shrinkWrap: true,
                crossAxisCount: 3,
                mainAxisSpacing: 24,
                crossAxisSpacing: 24,
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
      decoration: const BoxDecoration(
        shape: BoxShape.circle, 
        color: AppTheme.surface,
      ),
      alignment: Alignment.center,
      child: icon != null 
        ? Icon(icon, color: Colors.white, size: 28) 
        : Text(v, style: const TextStyle(fontSize: 32, color: Colors.white, fontWeight: FontWeight.w400)),
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
          BottomNavigationBarItem(icon: Icon(CupertinoIcons.person_crop_circle_fill), label: 'Setup'),
        ],
      ),
      tabBuilder: (c, i) => i == 2 ? SettingsView(state: widget.state) : _buildVaultList(i),
    );
  }

  Widget _buildVaultList(int filterType) {
    final items = (widget.state.vault?['items'] as List? ?? []).where((i) {
      if (filterType == 1 && i['fav'] != true) return false;
      return i['title'].toString().toLowerCase().contains(query.toLowerCase());
    }).toList();

    return CupertinoPageScaffold(
      child: CustomScrollView(
        slivers: [
          CupertinoSliverNavigationBar(
            largeTitle: const Text("VaultX"),
            trailing: CupertinoButton(
              padding: EdgeInsets.zero, 
              child: const Icon(CupertinoIcons.add_circled, size: 28), 
              onPressed: () => _showForm()
            ),
          ),
          SliverToBoxAdapter(
            child: Padding(
              padding: const EdgeInsets.all(16.0),
              child: CupertinoSearchTextField(onChanged: (v) => setState(() => query = v)),
            ),
          ),
          SliverFillRemaining(
            hasScrollBody: false,
            child: items.isEmpty 
              ? const Center(child: Text("Empty Vault", style: TextStyle(color: AppTheme.textMuted)))
              : Padding(
                  padding: const EdgeInsets.symmetric(horizontal: 16),
                  child: Container(
                    decoration: BoxDecoration(
                      color: AppTheme.surface,
                      borderRadius: BorderRadius.circular(12),
                    ),
                    child: ListView.separated(
                      padding: EdgeInsets.zero,
                      shrinkWrap: true,
                      physics: const NeverScrollableScrollPhysics(),
                      itemCount: items.length,
                      separatorBuilder: (c, i) => const Padding(
                        padding: EdgeInsets.only(left: 56),
                        child: Divider(color: AppTheme.border, height: 1),
                      ),
                      itemBuilder: (c, i) => _ItemTile(
                        item: items[i], 
                        state: widget.state, 
                        onEdit: () => _showForm(items[i])
                      ),
                    ),
                  ),
                ),
          ),
          const SliverToBoxAdapter(child: SizedBox(height: 100)),
        ],
      ),
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
      case 'key': return CupertinoIcons.lock_open_fill;
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
          decoration: BoxDecoration(
            color: AppTheme.bg, 
            borderRadius: BorderRadius.circular(16), 
            border: Border.all(color: AppTheme.primary, width: 0.5)
          ),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Icon(_getTypeIcon(widget.item['type']), color: AppTheme.primary, size: 40),
              const SizedBox(height: 12),
              Text(widget.item['user'] ?? "", style: const TextStyle(fontWeight: FontWeight.bold, color: Colors.white)),
              const SizedBox(height: 16),
              Container(color: Colors.white, padding: const EdgeInsets.all(8), child: QrImageView(data: widget.item['sec'], size: 140)),
              const SizedBox(height: 12),
              const Text("VAULTX PROTECTION", style: TextStyle(fontSize: 8, letterSpacing: 2, color: AppTheme.textMuted)),
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
    return CupertinoButton(
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
      onPressed: () => setState(() => show = !show),
      child: Row(
        children: [
          Container(
            padding: const EdgeInsets.all(8),
            decoration: BoxDecoration(
              color: AppTheme.bg,
              borderRadius: BorderRadius.circular(8),
            ),
            child: Icon(_getTypeIcon(widget.item['type'] ?? 'pass'), color: AppTheme.primary, size: 20),
          ),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(widget.item['title'], style: const TextStyle(color: Colors.white, fontWeight: FontWeight.w600, fontSize: 17)),
                Text(show ? widget.item['sec'] : "••••••••", style: const TextStyle(color: AppTheme.textMuted, fontSize: 13)),
              ],
            ),
          ),
          CupertinoButton(
            padding: EdgeInsets.zero, 
            child: Icon(widget.item['fav'] == true ? CupertinoIcons.star_fill : CupertinoIcons.star, size: 20), 
            onPressed: () { widget.item['fav'] = !(widget.item['fav'] ?? false); widget.state.save(); }
          ),
          CupertinoButton(
            padding: EdgeInsets.zero, 
            child: const Icon(CupertinoIcons.qrcode, size: 20), 
            onPressed: _preview
          ),
          CupertinoButton(
            padding: EdgeInsets.zero, 
            child: const Icon(CupertinoIcons.pencil_circle, size: 20), 
            onPressed: widget.onEdit
          ),
        ],
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
            height: 36,
            child: ListView(
              scrollDirection: Axis.horizontal,
              children: [
                _tBtn("Password", "pass"), _tBtn("API Key", "key"), _tBtn("Note", "note"), _tBtn("Card", "card"), _tBtn("WiFi", "wifi"),
              ],
            ),
          ),
          const SizedBox(height: 20),
          CupertinoFormSection.insetGrouped(
            backgroundColor: Colors.transparent,
            margin: EdgeInsets.zero,
            children: [
              CupertinoFormRow(
                prefix: const Text("Title", style: TextStyle(fontSize: 14)),
                child: CupertinoTextFormFieldRow(controller: t, placeholder: "e.g. Google", style: const TextStyle(fontSize: 14)),
              ),
              CupertinoFormRow(
                prefix: const Text("User", style: TextStyle(fontSize: 14)),
                child: CupertinoTextFormFieldRow(controller: u, placeholder: "Username", style: const TextStyle(fontSize: 14)),
              ),
              CupertinoFormRow(
                prefix: const Text("Secret", style: TextStyle(fontSize: 14)),
                child: CupertinoTextFormFieldRow(controller: s, placeholder: "••••••••", style: const TextStyle(fontSize: 14)),
              ),
            ],
          ),
        ],
      ),
      actions: [
        CupertinoActionSheetAction(
          isDefaultAction: true,
          onPressed: () {
            if (t.text.isEmpty || s.text.isEmpty) return;
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
          child: const Text("Save"),
        ),
        if (widget.item != null) CupertinoActionSheetAction(
          isDestructiveAction: true,
          onPressed: () { 
            (widget.state.vault?['items'] as List).remove(widget.item); 
            widget.state.save(); 
            Navigator.pop(context); 
          },
          child: const Text("Delete"),
        ),
      ],
      cancelButton: CupertinoActionSheetAction(
        child: const Text("Cancel"), 
        onPressed: () => Navigator.pop(context)
      ),
    );
  }

  Widget _tBtn(String l, String v) => Padding(
    padding: const EdgeInsets.only(right: 8),
    child: CupertinoButton(
      padding: const EdgeInsets.symmetric(horizontal: 16),
      color: type == v ? AppTheme.primary : AppTheme.surface,
      borderRadius: BorderRadius.circular(20),
      onPressed: () => setState(() => type = v),
      child: Text(l, style: TextStyle(fontSize: 11, color: type == v ? Colors.white : AppTheme.textMuted)),
    ),
  );
}

class SettingsView extends StatelessWidget {
  final VaultState state;
  const SettingsView({super.key, required this.state});
  @override
  Widget build(BuildContext context) {
    return CupertinoPageScaffold(
      child: CustomScrollView(
        slivers: [
          const CupertinoSliverNavigationBar(largeTitle: Text("Setup")),
          SliverToBoxAdapter(
            child: Column(
              children: [
                const SizedBox(height: 16),
                CupertinoListSection.insetGrouped(
                  header: const Text("DEVELOPER CONTACT"),
                  children: [
                    _row("Telegram", "@Vann759", "https://t.me/Vann759"),
                    _row("GitHub", "Elvandito", "https://github.com/Elvandito"),
                    _row("Email", "ditoelvan2@gmail.com", "mailto:ditoelvan2@gmail.com"),
                  ],
                ),
                CupertinoListSection.insetGrouped(
                  header: const Text("SECURITY"),
                  children: [
                    CupertinoListTile(
                      title: const Text("Wipe All Data", style: TextStyle(color: CupertinoColors.systemRed)),
                      trailing: const Icon(CupertinoIcons.delete, color: CupertinoColors.systemRed, size: 20),
                      onTap: () async {
                        final p = await SharedPreferences.getInstance();
                        await p.clear();
                        state.logout();
                      },
                    ),
                    CupertinoListTile(
                      title: const Text("Logout & Lock"),
                      trailing: const Icon(CupertinoIcons.lock, size: 20),
                      onTap: state.logout,
                    ),
                  ],
                ),
                const SizedBox(height: 40),
                const Text("VaultX v1.2.0", style: TextStyle(color: AppTheme.textMuted, fontSize: 12)),
              ],
            ),
          )
        ],
      ),
    );
  }

  Widget _row(String l, String v, String u) => CupertinoListTile(
    title: Text(l),
    additionalInfo: Text(v),
    trailing: const Icon(CupertinoIcons.chevron_right, size: 14),
    onTap: () => launchUrl(Uri.parse(u)),
  );
}