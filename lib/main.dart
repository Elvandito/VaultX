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
  // Apple True OLED Black for backgrounds
  static const Color systemBackground = Color(0xFF000000); 
  // Apple Elevated Surface (Cards/Lists)
  static const Color secondarySystemBackground = Color(0xFF1C1C1E); 
  // Apple Borders
  static const Color separator = Color(0xFF38383A);
  static const Color textSecondary = Color(0xFF8E8E93);
  static const Color textPlaceholder = Color(0xFF48484A);

  static CupertinoThemeData get iosTheme => const CupertinoThemeData(
    brightness: Brightness.dark,
    primaryColor: primary,
    scaffoldBackgroundColor: systemBackground,
    barBackgroundColor: Color(0xCC1C1C1E), // Deep frosted glass
    textTheme: CupertinoTextThemeData(
      primaryColor: CupertinoColors.white,
      textStyle: TextStyle(fontFamily: '.SF Pro Text', color: Colors.white, letterSpacing: -0.4),
      navLargeTitleTextStyle: TextStyle(
        fontFamily: '.SF Pro Display',
        fontSize: 34,
        fontWeight: FontWeight.w700,
        color: CupertinoColors.white,
        letterSpacing: -1.2,
      ),
      navTitleTextStyle: TextStyle(
        fontFamily: '.SF Pro Text',
        fontSize: 17,
        fontWeight: FontWeight.w600,
        color: CupertinoColors.white,
        letterSpacing: -0.4,
      ),
    ),
  );
}

// Data model for category types matching Apple's Passwords app
final Map<String, Map<String, dynamic>> kTypes = {
  'pass': {'label': 'Kata Laluan', 'icon': CupertinoIcons.lock_fill, 'color': CupertinoColors.systemBlue},
  'key': {'label': 'Kunci API', 'icon': CupertinoIcons.link, 'color': CupertinoColors.systemIndigo},
  'note': {'label': 'Nota Selamat', 'icon': CupertinoIcons.doc_text_fill, 'color': CupertinoColors.systemYellow},
  'card': {'label': 'Kad Kredit', 'icon': CupertinoIcons.creditcard_fill, 'color': CupertinoColors.systemOrange},
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

class _LoginState extends State<Login> with SingleTickerProviderStateMixin {
  String pin = "";
  bool error = false;
  late AnimationController _shakeCtrl;
  late Animation<double> _shakeAnim;

  @override
  void initState() {
    super.initState();
    _shakeCtrl = AnimationController(duration: const Duration(milliseconds: 400), vsync: this);
    _shakeAnim = TweenSequence([
      TweenSequenceItem(tween: Tween(begin: 0.0, end: -10.0), weight: 1),
      TweenSequenceItem(tween: Tween(begin: -10.0, end: 10.0), weight: 2),
      TweenSequenceItem(tween: Tween(begin: 10.0, end: -10.0), weight: 2),
      TweenSequenceItem(tween: Tween(begin: -10.0, end: 10.0), weight: 2),
      TweenSequenceItem(tween: Tween(begin: 10.0, end: 0.0), weight: 1),
    ]).animate(CurvedAnimation(parent: _shakeCtrl, curve: Curves.easeInOut));
  }

  @override
  void dispose() { _shakeCtrl.dispose(); super.dispose(); }

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
      setState(() => error = true);
      _shakeCtrl.forward(from: 0).then((_) => setState(() => pin = ""));
    }
  }

  @override
  Widget build(BuildContext context) {
    return CupertinoPageScaffold(
      backgroundColor: AppTheme.systemBackground,
      child: SafeArea(
        child: Column(
          children: [
            const Spacer(flex: 2),
            const Icon(CupertinoIcons.lock_fill, size: 48, color: CupertinoColors.white),
            const SizedBox(height: 16),
            const Text("Masukkan Kod Laluan", style: TextStyle(fontSize: 17, fontWeight: FontWeight.w400)),
            const SizedBox(height: 24),
            AnimatedBuilder(
              animation: _shakeAnim,
              builder: (c, _) => Transform.translate(
                offset: Offset(_shakeAnim.value, 0),
                child: Row(
                  mainAxisAlignment: MainAxisAlignment.center,
                  children: List.generate(4, (i) => AnimatedContainer(
                    duration: const Duration(milliseconds: 100),
                    margin: const EdgeInsets.symmetric(horizontal: 10),
                    width: 14, height: 14,
                    decoration: BoxDecoration(
                      shape: BoxShape.circle,
                      border: Border.all(color: error ? CupertinoColors.systemRed : (pin.length > i ? Colors.transparent : AppTheme.separator), width: 1.5),
                      color: error ? CupertinoColors.systemRed : (pin.length > i ? CupertinoColors.white : Colors.transparent),
                    ),
                  )),
                ),
              ),
            ),
            const Spacer(flex: 3),
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 50, vertical: 30),
              child: GridView.count(
                shrinkWrap: true,
                crossAxisCount: 3,
                mainAxisSpacing: 20,
                crossAxisSpacing: 25,
                childAspectRatio: 1.1,
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
      decoration: const BoxDecoration(shape: BoxShape.circle, color: AppTheme.secondarySystemBackground),
      alignment: Alignment.center,
      child: icon != null 
        ? Icon(icon, color: Colors.white, size: 24) 
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
        backgroundColor: AppTheme.systemBackground.withOpacity(0.85),
        activeColor: AppTheme.primary,
        inactiveColor: AppTheme.textSecondary,
        currentIndex: tab,
        onTap: (i) => setState(() => tab = i),
        items: const [
          BottomNavigationBarItem(icon: Icon(CupertinoIcons.shield_fill), label: 'Peti Besi'),
          BottomNavigationBarItem(icon: Icon(CupertinoIcons.star_fill), label: 'Kegemaran'),
          BottomNavigationBarItem(icon: Icon(CupertinoIcons.settings), label: 'Tetapan'),
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
      backgroundColor: AppTheme.systemBackground,
      child: CustomScrollView(
        physics: const AlwaysScrollableScrollPhysics(parent: BouncingScrollPhysics()),
        slivers: [
          CupertinoSliverNavigationBar(
            largeTitle: Text(type == 0 ? "Kredensial" : "Kegemaran"),
            backgroundColor: AppTheme.systemBackground.withOpacity(0.85),
            border: null,
            trailing: CupertinoButton(
              padding: EdgeInsets.zero, 
              child: const Icon(CupertinoIcons.add, size: 24), 
              onPressed: () => _showForm()
            ),
          ),
          SliverToBoxAdapter(
            child: Padding(
              padding: const EdgeInsets.fromLTRB(16, 0, 16, 12),
              child: SizedBox(
                height: 36,
                child: CupertinoSearchTextField(
                  onChanged: (v) => setState(() => query = v),
                  backgroundColor: AppTheme.secondarySystemBackground,
                  placeholderStyle: const TextStyle(color: AppTheme.textPlaceholder, fontSize: 17),
                  style: const TextStyle(color: Colors.white, fontSize: 17),
                  placeholder: "Cari",
                ),
              ),
            ),
          ),
          SliverFillRemaining(
            hasScrollBody: false,
            child: items.isEmpty 
            ? const Center(child: Text("Tiada Butiran.", style: TextStyle(color: AppTheme.textSecondary, fontSize: 15)))
            : Padding(
                padding: const EdgeInsets.symmetric(horizontal: 16),
                child: Container(
                  decoration: BoxDecoration(
                    color: AppTheme.secondarySystemBackground,
                    borderRadius: BorderRadius.circular(10), // Perfect iOS radius
                  ),
                  child: ListView.separated(
                    padding: EdgeInsets.zero,
                    shrinkWrap: true,
                    physics: const NeverScrollableScrollPhysics(),
                    itemCount: items.length,
                    separatorBuilder: (c, i) => const Padding(
                      padding: EdgeInsets.only(left: 60), // Align with text
                      child: Divider(color: AppTheme.separator, height: 1, thickness: 0.5),
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
          const SliverToBoxAdapter(child: SizedBox(height: 120)),
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
            color: AppTheme.secondarySystemBackground, 
            borderRadius: BorderRadius.circular(16), 
          ),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              _buildIcon(48, 24),
              const SizedBox(height: 16),
              Text(widget.item['title'], style: const TextStyle(fontWeight: FontWeight.w600, fontSize: 18, color: Colors.white)),
              const SizedBox(height: 4),
              Text(widget.item['user'] ?? "", style: const TextStyle(color: AppTheme.textSecondary, fontSize: 13)),
              const SizedBox(height: 24),
              Container(
                color: Colors.white, 
                padding: const EdgeInsets.all(12), 
                child: QrImageView(data: widget.item['sec'], size: 160)
              ),
            ],
          ),
        ),
      ),
      actions: [
        CupertinoDialogAction(child: const Text("Tutup"), onPressed: () => Navigator.pop(ctx)),
        CupertinoDialogAction(
          child: const Text("Kongsi", style: TextStyle(fontWeight: FontWeight.bold)), 
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
        borderRadius: BorderRadius.circular(8),
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
          duration: const Duration(milliseconds: 300),
          curve: Curves.fastOutSlowIn,
          child: Padding(
            padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    _buildIcon(32, 16),
                    const SizedBox(width: 12),
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(widget.item['title'], style: const TextStyle(color: Colors.white, fontWeight: FontWeight.w500, fontSize: 17, letterSpacing: -0.4)),
                          Text(widget.item['user'] ?? "", style: const TextStyle(color: AppTheme.textSecondary, fontSize: 15, letterSpacing: -0.2)),
                        ],
                      ),
                    ),
                    Icon(expanded ? CupertinoIcons.chevron_up : CupertinoIcons.chevron_down, color: AppTheme.textSecondary, size: 14)
                  ],
                ),
                if (expanded) ...[
                  const SizedBox(height: 16),
                  Container(
                    width: double.infinity,
                    padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 14),
                    decoration: BoxDecoration(
                      color: AppTheme.systemBackground,
                      borderRadius: BorderRadius.circular(8),
                      border: Border.all(color: AppTheme.separator, width: 0.5)
                    ),
                    child: SelectableText(widget.item['sec'], style: const TextStyle(fontFamily: 'Courier', fontSize: 15, color: Colors.white)),
                  ),
                  const SizedBox(height: 16),
                  Row(
                    mainAxisAlignment: MainAxisAlignment.spaceEvenly,
                    children: [
                      _actionBtn(CupertinoIcons.doc_on_clipboard, "Salin", () {
                        Clipboard.setData(ClipboardData(text: widget.item['sec']));
                        HapticFeedback.mediumImpact();
                      }),
                      _actionBtn(CupertinoIcons.qrcode, "QR", _preview),
                      _actionBtn(widget.item['fav'] == true ? CupertinoIcons.star_fill : CupertinoIcons.star, "Kegemaran", () {
                        setState(() { widget.item['fav'] = !(widget.item['fav'] ?? false); });
                        widget.state.save();
                      }, color: widget.item['fav'] == true ? CupertinoColors.systemYellow : null),
                      _actionBtn(CupertinoIcons.pencil, "Sunting", widget.onEdit),
                    ],
                  ),
                  const SizedBox(height: 4),
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
          padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(color: AppTheme.systemBackground, shape: BoxShape.circle, border: Border.all(color: AppTheme.separator, width: 0.5)),
          child: Icon(i, size: 20, color: color ?? AppTheme.primary),
        ),
        const SizedBox(height: 6),
        Text(l, style: TextStyle(fontSize: 10, color: color ?? AppTheme.primary, fontWeight: FontWeight.w500))
      ],
    ),
  );
}

// True Native iOS Modal (Swipe down to dismiss)
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
      height: MediaQuery.of(context).size.height * 0.90, // Native Modal Height
      decoration: const BoxDecoration(
        color: AppTheme.systemBackground,
        borderRadius: BorderRadius.vertical(top: Radius.circular(10)),
      ),
      child: Column(
        children: [
          // Drag Handle
          const SizedBox(height: 8),
          Container(width: 36, height: 5, decoration: BoxDecoration(color: AppTheme.separator, borderRadius: BorderRadius.circular(2.5))),
          
          CupertinoNavigationBar(
            backgroundColor: AppTheme.systemBackground,
            border: null,
            leading: CupertinoButton(
              padding: EdgeInsets.zero,
              child: const Text("Batal"),
              onPressed: () => Navigator.pop(context),
            ),
            middle: Text(widget.item == null ? "Item Baru" : "Sunting Item", style: const TextStyle(fontWeight: FontWeight.w600)),
            trailing: CupertinoButton(
              padding: EdgeInsets.zero,
              onPressed: _save,
              child: const Text("Simpan", style: TextStyle(fontWeight: FontWeight.w600)),
            ),
          ),
          Expanded(
            child: ListView(
              children: [
                const SizedBox(height: 16),
                SizedBox(
                  height: 32,
                  child: ListView(
                    scrollDirection: Axis.horizontal,
                    padding: const EdgeInsets.symmetric(horizontal: 16),
                    children: kTypes.entries.map((e) => _tBtn(e.value['label'], e.key)).toList(),
                  ),
                ),
                const SizedBox(height: 16),
                CupertinoFormSection.insetGrouped(
                  backgroundColor: Colors.transparent,
                  margin: const EdgeInsets.symmetric(horizontal: 16),
                  decoration: BoxDecoration(color: AppTheme.secondarySystemBackground, borderRadius: BorderRadius.circular(10)),
                  children: [
                    CupertinoTextFormFieldRow(controller: t, prefix: const Text("Tajuk", style: TextStyle(fontSize: 17)), placeholder: "Wajib"),
                    CupertinoTextFormFieldRow(controller: u, prefix: const Text("Nama Pengguna", style: TextStyle(fontSize: 17)), placeholder: "Pilihan"),
                  ],
                ),
                CupertinoFormSection.insetGrouped(
                  backgroundColor: Colors.transparent,
                  margin: const EdgeInsets.symmetric(horizontal: 16, vertical: 20),
                  decoration: BoxDecoration(color: AppTheme.secondarySystemBackground, borderRadius: BorderRadius.circular(10)),
                  children: [
                    CupertinoTextFormFieldRow(
                      controller: s, 
                      prefix: const Text("Rahsia", style: TextStyle(fontSize: 17)), 
                      placeholder: "Wajib",
                      obscureText: false,
                    ),
                  ],
                ),
                if (widget.item != null) ...[
                  Padding(
                    padding: const EdgeInsets.symmetric(horizontal: 16),
                    child: CupertinoButton(
                      color: AppTheme.secondarySystemBackground,
                      borderRadius: BorderRadius.circular(10),
                      onPressed: () {
                        (widget.state.vault?['items'] as List).remove(widget.item);
                        widget.state.save();
                        Navigator.pop(context);
                      },
                      child: const Text("Padam Item", style: TextStyle(color: CupertinoColors.systemRed, fontSize: 17)),
                    ),
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
      color: type == v ? AppTheme.primary : AppTheme.secondarySystemBackground,
      borderRadius: BorderRadius.circular(16),
      minSize: 0,
      onPressed: () => setState(() => type = v),
      child: Text(l, style: TextStyle(fontSize: 13, color: type == v ? Colors.white : AppTheme.textSecondary)),
    ),
  );
}

class SettingsView extends StatelessWidget {
  final VaultState state;
  const SettingsView({super.key, required this.state});
  @override
  Widget build(BuildContext context) {
    return CupertinoPageScaffold(
      backgroundColor: AppTheme.systemBackground,
      child: CustomScrollView(
        slivers: [
          const CupertinoSliverNavigationBar(
            largeTitle: Text("Tetapan"),
            backgroundColor: AppTheme.systemBackground,
            border: null,
          ),
          SliverToBoxAdapter(
            child: Column(
              children: [
                const SizedBox(height: 16),
                CupertinoListSection.insetGrouped(
                  backgroundColor: Colors.transparent,
                  decoration: BoxDecoration(color: AppTheme.secondarySystemBackground, borderRadius: BorderRadius.circular(10)),
                  children: [
                    _row(CupertinoIcons.paperplane_fill, "Telegram", "@Vann759", "https://t.me/Vann759", CupertinoColors.systemBlue),
                    _row(CupertinoIcons.chevron_left_slash_chevron_right, "GitHub", "Elvandito", "https://github.com/Elvandito", CupertinoColors.black),
                    _row(CupertinoIcons.mail_solid, "E-mel", "ditoelvan2@gmail.com", "mailto:ditoelvan2@gmail.com", CupertinoColors.systemRed),
                  ],
                ),
                CupertinoListSection.insetGrouped(
                  backgroundColor: Colors.transparent,
                  decoration: BoxDecoration(color: AppTheme.secondarySystemBackground, borderRadius: BorderRadius.circular(10)),
                  children: [
                    CupertinoListTile(
                      leading: _iconBg(CupertinoIcons.lock_fill, AppTheme.textSecondary),
                      title: const Text("Kunci Peti Besi", style: TextStyle(color: Colors.white)),
                      onTap: state.logout,
                    ),
                    CupertinoListTile(
                      leading: _iconBg(CupertinoIcons.trash_fill, CupertinoColors.systemRed),
                      title: const Text("Padam Semua Data", style: TextStyle(color: CupertinoColors.systemRed)),
                      onTap: () async {
                        final p = await SharedPreferences.getInstance();
                        await p.clear();
                        state.logout();
                      },
                    ),
                  ],
                ),
                const SizedBox(height: 40),
                const Text("VaultX v1.4.0", style: TextStyle(color: AppTheme.textSecondary, fontSize: 13)),
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
    title: Text(l, style: const TextStyle(color: Colors.white)),
    additionalInfo: Text(v),
    trailing: const Icon(CupertinoIcons.chevron_right, size: 14, color: AppTheme.textSecondary),
    onTap: () => launchUrl(Uri.parse(u)),
  );
}