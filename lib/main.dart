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
  static const Color primary = CupertinoColors.systemBlue;
  static const Color bg = CupertinoColors.black;
  static const Color groupedBg = Color(0xFF000000); // Black for OLED
  static const Color surface = Color(0xFF1C1C1E); // iOS Elevated Element
  static const Color surfaceHighlight = Color(0xFF2C2C2E);
  static const Color border = Color(0xFF38383A);
  static const Color textMuted = CupertinoColors.systemGrey;

  static CupertinoThemeData get iosTheme => const CupertinoThemeData(
    brightness: Brightness.dark,
    primaryColor: primary,
    scaffoldBackgroundColor: bg,
    barBackgroundColor: Color(0xCC1C1C1E), // Glassmorphism
    textTheme: CupertinoTextThemeData(primaryColor: CupertinoColors.white),
  );
}

// Data model for category types
final Map<String, Map<String, dynamic>> kTypes = {
  'pass': {'label': 'Password', 'icon': CupertinoIcons.lock_fill, 'color': CupertinoColors.systemBlue},
  'key': {'label': 'API Key', 'icon': CupertinoIcons.link, 'color': CupertinoColors.systemPurple},
  'note': {'label': 'Note', 'icon': CupertinoIcons.doc_text_fill, 'color': CupertinoColors.systemYellow},
  'card': {'label': 'Card', 'icon': CupertinoIcons.creditcard_fill, 'color': CupertinoColors.systemOrange},
  'wifi': {'label': 'WiFi', 'icon': CupertinoIcons.wifi, 'color': CupertinoColors.systemGreen},
};

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
            const Icon(CupertinoIcons.lock_shield_fill, size: 72, color: CupertinoColors.white),
            const SizedBox(height: 16),
            const Text("Enter Passcode", style: TextStyle(fontSize: 22, fontWeight: FontWeight.w600)),
            const SizedBox(height: 40),
            Row(
              mainAxisAlignment: MainAxisAlignment.center,
              children: List.generate(4, (i) => AnimatedContainer(
                duration: const Duration(milliseconds: 150),
                margin: const EdgeInsets.symmetric(horizontal: 14),
                width: 14, height: 14,
                decoration: BoxDecoration(
                  shape: BoxShape.circle,
                  border: Border.all(color: error ? CupertinoColors.systemRed : (pin.length > i ? Colors.transparent : AppTheme.border), width: 1.5),
                  color: error ? CupertinoColors.systemRed : (pin.length > i ? CupertinoColors.white : Colors.transparent),
                ),
              )),
            ),
            const Spacer(flex: 3),
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 50, vertical: 40),
              child: GridView.count(
                shrinkWrap: true,
                crossAxisCount: 3,
                mainAxisSpacing: 20,
                crossAxisSpacing: 25,
                childAspectRatio: 1,
                physics: const NeverScrollableScrollPhysics(),
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
      child: icon != null 
        ? Icon(icon, color: Colors.white, size: 28) 
        : Text(v, style: const TextStyle(fontSize: 34, color: Colors.white, fontWeight: FontWeight.w400)),
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
          BottomNavigationBarItem(icon: Icon(CupertinoIcons.gear_alt_fill), label: 'Settings'),
        ],
      ),
      tabBuilder: (c, i) => i == 2 ? SettingsView(state: widget.state) : _buildVault(i),
    );
  }

  Widget _buildVault(int type) {
    final items = (widget.state.vault?['items'] as List? ?? []).where((i) {
      if (type == 1 && i['fav'] != true) return false;
      return i['title'].toString().toLowerCase().contains(query.toLowerCase());
    }).toList();

    return CupertinoPageScaffold(
      backgroundColor: AppTheme.groupedBg,
      child: CustomScrollView(
        slivers: [
          CupertinoSliverNavigationBar(
            largeTitle: Text(type == 0 ? "Passwords" : "Favorites"),
            trailing: CupertinoButton(
              padding: EdgeInsets.zero, 
              child: const Icon(CupertinoIcons.add, size: 28), 
              onPressed: () => _showForm()
            ),
          ),
          SliverToBoxAdapter(
            child: Padding(
              padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
              child: CupertinoSearchTextField(
                onChanged: (v) => setState(() => query = v),
                placeholder: "Search",
              ),
            ),
          ),
          SliverFillRemaining(
            hasScrollBody: false,
            child: items.isEmpty 
            ? const Center(child: Text("No items found.", style: TextStyle(color: AppTheme.textMuted)))
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
                      padding: EdgeInsets.only(left: 60),
                      child: Divider(color: AppTheme.border, height: 1, thickness: 0.5),
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
    showCupertinoModalPopup(
      context: context, 
      builder: (c) => _FormModal(state: widget.state, item: item)
    );
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

class _ItemTileState extends State<_ItemTile> with SingleTickerProviderStateMixin {
  bool expanded = false;
  final ss = ScreenshotController();

  void _toggle() {
    HapticFeedback.selectionClick();
    setState(() => expanded = !expanded);
  }

  void _preview() {
    showCupertinoDialog(context: context, builder: (ctx) => CupertinoAlertDialog(
      content: Screenshot(
        controller: ss,
        child: Container(
          padding: const EdgeInsets.all(24),
          decoration: BoxDecoration(
            color: AppTheme.bg, 
            borderRadius: BorderRadius.circular(16), 
            border: Border.all(color: AppTheme.border)
          ),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              _buildIcon(48, 24),
              const SizedBox(height: 16),
              Text(widget.item['title'], style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 18, color: Colors.white)),
              const SizedBox(height: 4),
              Text(widget.item['user'] ?? "", style: const TextStyle(color: AppTheme.textMuted, fontSize: 13)),
              const SizedBox(height: 24),
              Container(
                color: Colors.white, 
                padding: const EdgeInsets.all(8), 
                child: QrImageView(data: widget.item['sec'], size: 160)
              ),
            ],
          ),
        ),
      ),
      actions: [
        CupertinoDialogAction(child: const Text("Close"), onPressed: () => Navigator.pop(ctx)),
        CupertinoDialogAction(
          child: const Text("Share Snap", style: TextStyle(fontWeight: FontWeight.bold)), 
          onPressed: () async {
            final b = await ss.capture();
            if (b != null) {
              final p = (await getTemporaryDirectory()).path;
              final f = await File('$p/vaultx_snap.png').create();
              await f.writeAsBytes(b);
              await Share.shareXFiles([XFile(f.path)]);
            }
          }
        ),
      ],
    ));
  }

  Widget _buildIcon(double size, double iconSize) {
    final typeData = kTypes[widget.item['type'] ?? 'pass']!;
    return Container(
      width: size, height: size,
      decoration: BoxDecoration(
        color: typeData['color'],
        borderRadius: BorderRadius.circular(size * 0.25),
      ),
      child: Icon(typeData['icon'], color: Colors.white, size: iconSize),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Material(
      color: Colors.transparent,
      child: InkWell(
        onTap: _toggle,
        child: AnimatedSize(
          duration: const Duration(milliseconds: 250),
          curve: Curves.easeInOutCubic,
          child: Padding(
            padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    _buildIcon(40, 20),
                    const SizedBox(width: 14),
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(widget.item['title'], style: const TextStyle(color: Colors.white, fontWeight: FontWeight.w500, fontSize: 17)),
                          Text(widget.item['user'] ?? "", style: const TextStyle(color: AppTheme.textMuted, fontSize: 13)),
                        ],
                      ),
                    ),
                    Icon(expanded ? CupertinoIcons.chevron_up : CupertinoIcons.chevron_down, color: AppTheme.textMuted, size: 16)
                  ],
                ),
                if (expanded) ...[
                  const SizedBox(height: 16),
                  Container(
                    width: double.infinity,
                    padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
                    decoration: BoxDecoration(
                      color: AppTheme.bg,
                      borderRadius: BorderRadius.circular(8),
                      border: Border.all(color: AppTheme.border)
                    ),
                    child: Text(widget.item['sec'], style: const TextStyle(fontFamily: 'monospace', fontSize: 14, color: Colors.white)),
                  ),
                  const SizedBox(height: 12),
                  Row(
                    mainAxisAlignment: MainAxisAlignment.spaceEvenly,
                    children: [
                      _actionBtn(CupertinoIcons.doc_on_clipboard, "Copy", () {
                        Clipboard.setData(ClipboardData(text: widget.item['sec']));
                        HapticFeedback.mediumImpact();
                      }),
                      _actionBtn(CupertinoIcons.qrcode, "QR Code", _preview),
                      _actionBtn(widget.item['fav'] == true ? CupertinoIcons.star_fill : CupertinoIcons.star, "Favorite", () {
                        setState(() { widget.item['fav'] = !(widget.item['fav'] ?? false); });
                        widget.state.save();
                      }, color: widget.item['fav'] == true ? CupertinoColors.systemYellow : null),
                      _actionBtn(CupertinoIcons.pencil, "Edit", widget.onEdit),
                    ],
                  )
                ]
              ],
            ),
          ),
        ),
      ),
    );
  }

  Widget _actionBtn(IconData i, String l, VoidCallback t, {Color? color}) => CupertinoButton(
    padding: EdgeInsets.zero,
    onPressed: t,
    child: Column(
      children: [
        Container(
          padding: const EdgeInsets.all(10),
          decoration: BoxDecoration(color: AppTheme.surfaceHighlight, shape: BoxShape.circle),
          child: Icon(i, size: 20, color: color ?? AppTheme.primary),
        ),
        const SizedBox(height: 4),
        Text(l, style: TextStyle(fontSize: 10, color: color ?? AppTheme.primary))
      ],
    ),
  );
}

// True iOS Native Form Modal
class _FormModal extends StatefulWidget {
  final VaultState state;
  final Map? item;
  const _FormModal({required this.state, this.item});
  @override
  State<_FormModal> createState() => _FormModalState();
}

class _FormModalState extends State<_FormModal> {
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

  void _save() {
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
  }

  @override
  Widget build(BuildContext context) {
    return Container(
      height: MediaQuery.of(context).size.height * 0.85,
      decoration: const BoxDecoration(
        color: AppTheme.groupedBg,
        borderRadius: BorderRadius.vertical(top: Radius.circular(12)),
      ),
      child: Column(
        children: [
          CupertinoNavigationBar(
            backgroundColor: AppTheme.groupedBg,
            leading: CupertinoButton(
              padding: EdgeInsets.zero,
              child: const Text("Cancel"),
              onPressed: () => Navigator.pop(context),
            ),
            middle: Text(widget.item == null ? "New Item" : "Edit Item"),
            trailing: CupertinoButton(
              padding: EdgeInsets.zero,
              onPressed: _save,
              child: const Text("Save", style: TextStyle(fontWeight: FontWeight.bold)),
            ),
          ),
          Expanded(
            child: ListView(
              children: [
                const SizedBox(height: 20),
                SizedBox(
                  height: 40,
                  child: ListView(
                    scrollDirection: Axis.horizontal,
                    padding: const EdgeInsets.symmetric(horizontal: 16),
                    children: kTypes.entries.map((e) => _tBtn(e.value['label'], e.key)).toList(),
                  ),
                ),
                const SizedBox(height: 12),
                CupertinoFormSection.insetGrouped(
                  backgroundColor: Colors.transparent,
                  children: [
                    CupertinoTextFormFieldRow(controller: t, prefix: const Text("Title"), placeholder: "Required"),
                    CupertinoTextFormFieldRow(controller: u, prefix: const Text("User"), placeholder: "Optional"),
                  ],
                ),
                CupertinoFormSection.insetGrouped(
                  backgroundColor: Colors.transparent,
                  children: [
                    CupertinoTextFormFieldRow(
                      controller: s, 
                      prefix: const Text("Secret"), 
                      placeholder: "Required",
                      obscureText: false, // Keep visible while editing
                    ),
                  ],
                ),
                if (widget.item != null) ...[
                  const SizedBox(height: 20),
                  CupertinoButton(
                    child: const Text("Delete Credential", style: TextStyle(color: CupertinoColors.systemRed)),
                    onPressed: () {
                      (widget.state.vault?['items'] as List).remove(widget.item);
                      widget.state.save();
                      Navigator.pop(context);
                    },
                  )
                ]
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _tBtn(String l, String v) => Padding(
    padding: const EdgeInsets.only(right: 8),
    child: CupertinoButton(
      padding: const EdgeInsets.symmetric(horizontal: 16),
      color: type == v ? AppTheme.primary : AppTheme.surfaceHighlight,
      borderRadius: BorderRadius.circular(20),
      onPressed: () => setState(() => type = v),
      child: Text(l, style: TextStyle(fontSize: 13, color: type == v ? Colors.white : AppTheme.textMuted)),
    ),
  );
}

class SettingsView extends StatelessWidget {
  final VaultState state;
  const SettingsView({super.key, required this.state});
  @override
  Widget build(BuildContext context) {
    return CupertinoPageScaffold(
      backgroundColor: AppTheme.groupedBg,
      child: CustomScrollView(
        slivers: [
          const CupertinoSliverNavigationBar(largeTitle: Text("Settings")),
          SliverToBoxAdapter(
            child: Column(
              children: [
                CupertinoListSection.insetGrouped(
                  header: const Text("DEVELOPER"),
                  children: [
                    _row(CupertinoIcons.paperplane_fill, "Telegram", "@Vann759", "https://t.me/Vann759", CupertinoColors.systemBlue),
                    _row(CupertinoIcons.chevron_left_slash_chevron_right, "GitHub", "Elvandito", "https://github.com/Elvandito", CupertinoColors.black),
                    _row(CupertinoIcons.mail_solid, "Email", "ditoelvan2@gmail.com", "mailto:ditoelvan2@gmail.com", CupertinoColors.systemRed),
                  ],
                ),
                CupertinoListSection.insetGrouped(
                  header: const Text("SECURITY"),
                  children: [
                    CupertinoListTile(
                      leading: _iconBg(CupertinoIcons.lock_fill, AppTheme.textMuted),
                      title: const Text("Lock Vault"),
                      onTap: state.logout,
                    ),
                    CupertinoListTile(
                      leading: _iconBg(CupertinoIcons.trash_fill, CupertinoColors.systemRed),
                      title: const Text("Wipe All Data", style: TextStyle(color: CupertinoColors.systemRed)),
                      onTap: () async {
                        final p = await SharedPreferences.getInstance();
                        await p.clear();
                        state.logout();
                      },
                    ),
                  ],
                ),
                const SizedBox(height: 40),
                const Text("VaultX v1.3.0", style: TextStyle(color: AppTheme.textMuted, fontSize: 12)),
                const SizedBox(height: 40),
              ],
            ),
          )
        ],
      ),
    );
  }

  Widget _iconBg(IconData icon, Color color) => Container(
    padding: const EdgeInsets.all(4),
    decoration: BoxDecoration(color: color, borderRadius: BorderRadius.circular(6)),
    child: Icon(icon, color: Colors.white, size: 18),
  );

  Widget _row(IconData icon, String l, String v, String u, Color c) => CupertinoListTile(
    leading: _iconBg(icon, c),
    title: Text(l),
    additionalInfo: Text(v),
    trailing: const Icon(CupertinoIcons.chevron_right, size: 14, color: AppTheme.textMuted),
    onTap: () => launchUrl(Uri.parse(u)),
  );
}