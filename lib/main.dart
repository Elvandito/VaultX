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

// ==========================================
// 1. IOS NATIVE THEME (PIXEL PERFECT)
// ==========================================
class AppTheme {
  static const Color primary = CupertinoColors.systemBlue;
  static const Color systemBackground = Color(0xFF000000); // OLED Black
  static const Color secondarySystemBackground = Color(0xFF1C1C1E); // Elevated Card
  static const Color tertiarySystemBackground = Color(0xFF2C2C2E); // Highlight
  static const Color separator = Color(0xFF38383A);
  static const Color textSecondary = Color(0xFF8E8E93);
  static const Color textPlaceholder = Color(0xFF48484A);

  static CupertinoThemeData get iosTheme => const CupertinoThemeData(
    brightness: Brightness.dark,
    primaryColor: primary,
    scaffoldBackgroundColor: systemBackground,
    barBackgroundColor: Color(0xCC1C1C1E), // Frosted glass nav bar
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

final Map<String, Map<String, dynamic>> kTypes = {
  'pass': {'label': 'Password', 'icon': CupertinoIcons.lock_fill, 'color': CupertinoColors.systemBlue},
  'key': {'label': 'API Key', 'icon': CupertinoIcons.link, 'color': CupertinoColors.systemIndigo},
  'note': {'label': 'Secure Note', 'icon': CupertinoIcons.doc_text_fill, 'color': CupertinoColors.systemYellow},
  'card': {'label': 'Credit Card', 'icon': CupertinoIcons.creditcard_fill, 'color': CupertinoColors.systemOrange},
  'wifi': {'label': 'WiFi', 'icon': CupertinoIcons.wifi, 'color': CupertinoColors.systemGreen},
};

// ==========================================
// 2. CRYPTOGRAPHY CORE
// ==========================================
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

  void logout() { 
    _key = null; vault = null; isAuth = false; 
    HapticFeedback.mediumImpact();
    notifyListeners(); 
  }
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

// ==========================================
// 3. IOS NATIVE TOUCH & ANIMATION WIDGETS
// ==========================================
class TouchButton extends StatefulWidget {
  final Widget child;
  final VoidCallback onTap;
  final Color baseColor;
  final Color highlightColor;
  final bool isCircle;

  const TouchButton({
    super.key, 
    required this.child, 
    required this.onTap, 
    required this.baseColor,
    required this.highlightColor,
    this.isCircle = false,
  });

  @override
  State<TouchButton> createState() => _TouchButtonState();
}

class _TouchButtonState extends State<TouchButton> with SingleTickerProviderStateMixin {
  bool _isDown = false;

  @override
  Widget build(BuildContext context) {
    return GestureDetector(
      onTapDown: (_) {
        HapticFeedback.selectionClick();
        setState(() => _isDown = true);
      },
      onTapUp: (_) {
        setState(() => _isDown = false);
        widget.onTap();
      },
      onTapCancel: () => setState(() => _isDown = false),
      child: AnimatedContainer(
        duration: const Duration(milliseconds: 100),
        decoration: BoxDecoration(
          color: _isDown ? widget.highlightColor : widget.baseColor,
          shape: widget.isCircle ? BoxShape.circle : BoxShape.rectangle,
          borderRadius: widget.isCircle ? null : BorderRadius.circular(16),
        ),
        alignment: Alignment.center,
        child: AnimatedScale(
          scale: _isDown ? 0.92 : 1.0,
          duration: const Duration(milliseconds: 100),
          child: widget.child,
        ),
      ),
    );
  }
}

// ==========================================
// 4. LOGIN / LOCK SCREEN
// ==========================================
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
      TweenSequenceItem(tween: Tween(begin: 0.0, end: -12.0), weight: 1),
      TweenSequenceItem(tween: Tween(begin: -12.0, end: 12.0), weight: 2),
      TweenSequenceItem(tween: Tween(begin: 12.0, end: -12.0), weight: 2),
      TweenSequenceItem(tween: Tween(begin: -12.0, end: 12.0), weight: 2),
      TweenSequenceItem(tween: Tween(begin: 12.0, end: 0.0), weight: 1),
    ]).animate(CurvedAnimation(parent: _shakeCtrl, curve: Curves.easeInOut));
  }

  @override
  void dispose() { _shakeCtrl.dispose(); super.dispose(); }

  void _onPress(String v) {
    setState(() {
      error = false;
      if (v == "D") {
        pin = pin.isNotEmpty ? pin.substring(0, pin.length - 1) : "";
      } else if (pin.length < 4) {
        pin += v;
      }
    });
    if (pin.length == 4) _submit();
  }

  Future<void> _submit() async {
    final prefs = await SharedPreferences.getInstance();
    bool ok = false;
    
    // Easter Egg specific PIN check (Example: 0000 gives a funny vibration before clearing)
    if (pin == "0000" && !prefs.containsKey('v_data')) {
      HapticFeedback.vibrate();
      await Future.delayed(const Duration(milliseconds: 200));
      HapticFeedback.vibrate();
    }

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
            const Text("Enter Passcode", style: TextStyle(fontSize: 18, fontWeight: FontWeight.w500, letterSpacing: 0.5)),
            const SizedBox(height: 32),
            
            // Passcode Dots
            AnimatedBuilder(
              animation: _shakeAnim,
              builder: (c, _) => Transform.translate(
                offset: Offset(_shakeAnim.value, 0),
                child: Row(
                  mainAxisAlignment: MainAxisAlignment.center,
                  children: List.generate(4, (i) => AnimatedContainer(
                    duration: const Duration(milliseconds: 150),
                    margin: const EdgeInsets.symmetric(horizontal: 12),
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
            
            // Numpad
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 48, vertical: 30),
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

  Widget _kBtn(String v, {IconData? icon}) => TouchButton(
    isCircle: true,
    baseColor: AppTheme.secondarySystemBackground,
    highlightColor: AppTheme.tertiarySystemBackground,
    onTap: () => _onPress(v),
    child: icon != null 
      ? Icon(icon, color: Colors.white, size: 26) 
      : Text(v, style: const TextStyle(fontSize: 34, color: Colors.white, fontWeight: FontWeight.w400)),
  );
}

// ==========================================
// 5. DASHBOARD & NAVIGATION
// ==========================================
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
        onTap: (i) {
          HapticFeedback.selectionClick();
          setState(() => tab = i);
        },
        items: const [
          BottomNavigationBarItem(icon: Icon(CupertinoIcons.lock_shield_fill), label: 'Vault'),
          BottomNavigationBarItem(icon: Icon(CupertinoIcons.star_fill), label: 'Favorites'),
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
      backgroundColor: AppTheme.systemBackground,
      child: CustomScrollView(
        physics: const AlwaysScrollableScrollPhysics(parent: BouncingScrollPhysics()),
        slivers: [
          CupertinoSliverNavigationBar(
            largeTitle: Text(type == 0 ? "Passwords" : "Favorites"),
            backgroundColor: AppTheme.systemBackground.withOpacity(0.85),
            border: null,
            trailing: CupertinoButton(
              padding: EdgeInsets.zero, 
              child: const Icon(CupertinoIcons.add, size: 28), 
              onPressed: () {
                HapticFeedback.lightImpact();
                _showForm();
              }
            ),
          ),
          SliverToBoxAdapter(
            child: Padding(
              padding: const EdgeInsets.fromLTRB(16, 0, 16, 12),
              child: SizedBox(
                height: 38,
                child: CupertinoSearchTextField(
                  onChanged: (v) => setState(() => query = v),
                  backgroundColor: AppTheme.secondarySystemBackground,
                  placeholderStyle: const TextStyle(color: AppTheme.textPlaceholder, fontSize: 17),
                  style: const TextStyle(color: Colors.white, fontSize: 17),
                  placeholder: "Search",
                ),
              ),
            ),
          ),
          SliverFillRemaining(
            hasScrollBody: false,
            child: items.isEmpty 
            ? const Center(child: Text("No Items Found.", style: TextStyle(color: AppTheme.textSecondary, fontSize: 15)))
            : Padding(
                padding: const EdgeInsets.symmetric(horizontal: 16),
                child: Container(
                  decoration: BoxDecoration(
                    color: AppTheme.secondarySystemBackground,
                    borderRadius: BorderRadius.circular(10), // Apple standard list radius
                  ),
                  child: ListView.separated(
                    padding: EdgeInsets.zero,
                    shrinkWrap: true,
                    physics: const NeverScrollableScrollPhysics(),
                    itemCount: items.length,
                    separatorBuilder: (c, i) => const Padding(
                      padding: EdgeInsets.only(left: 60), 
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

// ==========================================
// 6. LIST ITEM WITH FLUID EXPANSION
// ==========================================
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
    HapticFeedback.lightImpact();
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
        highlightColor: AppTheme.tertiarySystemBackground,
        splashColor: Colors.transparent,
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
                      _actionBtn(CupertinoIcons.doc_on_clipboard, "Copy", () {
                        Clipboard.setData(ClipboardData(text: widget.item['sec']));
                        HapticFeedback.lightImpact();
                      }),
                      _actionBtn(CupertinoIcons.qrcode, "QR", _preview),
                      _actionBtn(widget.item['fav'] == true ? CupertinoIcons.star_fill : CupertinoIcons.star, "Favorite", () {
                        HapticFeedback.selectionClick();
                        setState(() { widget.item['fav'] = !(widget.item['fav'] ?? false); });
                        widget.state.save();
                      }, color: widget.item['fav'] == true ? CupertinoColors.systemYellow : null),
                      _actionBtn(CupertinoIcons.pencil, "Edit", () {
                        HapticFeedback.lightImpact();
                        widget.onEdit();
                      }),
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

// ==========================================
// 7. MODAL FORM 
// ==========================================
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
    if (t.text.isEmpty || s.text.isEmpty) {
      HapticFeedback.heavyImpact();
      return;
    }
    
    HapticFeedback.mediumImpact();
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
      height: MediaQuery.of(context).size.height * 0.90,
      decoration: const BoxDecoration(
        color: AppTheme.systemBackground,
        borderRadius: BorderRadius.vertical(top: Radius.circular(10)),
      ),
      child: Column(
        children: [
          // Native iOS Modal Handle
          const SizedBox(height: 8),
          Container(width: 36, height: 5, decoration: BoxDecoration(color: AppTheme.separator, borderRadius: BorderRadius.circular(2.5))),
          
          CupertinoNavigationBar(
            backgroundColor: AppTheme.systemBackground,
            border: null,
            leading: CupertinoButton(
              padding: EdgeInsets.zero,
              child: const Text("Cancel"),
              onPressed: () {
                HapticFeedback.selectionClick();
                Navigator.pop(context);
              },
            ),
            middle: Text(widget.item == null ? "New Item" : "Edit Item", style: const TextStyle(fontWeight: FontWeight.w600)),
            trailing: CupertinoButton(
              padding: EdgeInsets.zero,
              onPressed: _save,
              child: const Text("Save", style: TextStyle(fontWeight: FontWeight.w600)),
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
                    CupertinoTextFormFieldRow(controller: t, prefix: const Text("Title", style: TextStyle(fontSize: 17)), placeholder: "Required"),
                    CupertinoTextFormFieldRow(controller: u, prefix: const Text("Username", style: TextStyle(fontSize: 17)), placeholder: "Optional"),
                  ],
                ),
                CupertinoFormSection.insetGrouped(
                  backgroundColor: Colors.transparent,
                  margin: const EdgeInsets.symmetric(horizontal: 16, vertical: 20),
                  decoration: BoxDecoration(color: AppTheme.secondarySystemBackground, borderRadius: BorderRadius.circular(10)),
                  children: [
                    CupertinoTextFormFieldRow(
                      controller: s, 
                      prefix: const Text("Secret", style: TextStyle(fontSize: 17)), 
                      placeholder: "Required",
                      obscureText: false,
                    ),
                  ],
                ),
                if (widget.item != null) ...[
                  Padding(
                    padding: const EdgeInsets.symmetric(horizontal: 16),
                    child: TouchButton(
                      baseColor: AppTheme.secondarySystemBackground,
                      highlightColor: AppTheme.tertiarySystemBackground,
                      onTap: () {
                        HapticFeedback.mediumImpact();
                        (widget.state.vault?['items'] as List).remove(widget.item);
                        widget.state.save();
                        Navigator.pop(context);
                      },
                      child: const Padding(
                        padding: EdgeInsets.symmetric(vertical: 14),
                        child: Text("Delete Item", style: TextStyle(color: CupertinoColors.systemRed, fontSize: 17, fontWeight: FontWeight.w500)),
                      ),
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
    child: TouchButton(
      baseColor: type == v ? AppTheme.primary : AppTheme.secondarySystemBackground,
      highlightColor: AppTheme.tertiarySystemBackground,
      onTap: () {
        HapticFeedback.selectionClick();
        setState(() => type = v);
      },
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 16),
        child: Text(l, style: TextStyle(fontSize: 13, color: type == v ? Colors.white : AppTheme.textSecondary, fontWeight: FontWeight.w500)),
      ),
    ),
  );
}

// ==========================================
// 8. SETTINGS & EASTER EGG
// ==========================================
class SettingsView extends StatefulWidget {
  final VaultState state;
  const SettingsView({super.key, required this.state});

  @override
  State<SettingsView> createState() => _SettingsViewState();
}

class _SettingsViewState extends State<SettingsView> {
  int _easterEggCounter = 0;

  void _triggerEasterEgg() {
    _easterEggCounter++;
    if (_easterEggCounter == 5) {
      _easterEggCounter = 0;
      HapticFeedback.heavyImpact();
      showCupertinoDialog(
        context: context,
        builder: (ctx) => CupertinoAlertDialog(
          title: const Text("🎉 You found a Secret!"),
          content: const Text("\nAlways remember to keep your VaultX PIN safe. There is no recovery button here. \n\nStay secure, friend!"),
          actions: [
            CupertinoDialogAction(
              isDefaultAction: true,
              onPressed: () => Navigator.pop(ctx),
              child: const Text("Awesome"),
            ),
          ],
        )
      );
    } else {
      HapticFeedback.lightImpact();
    }
  }

  @override
  Widget build(BuildContext context) {
    return CupertinoPageScaffold(
      backgroundColor: AppTheme.systemBackground,
      child: CustomScrollView(
        slivers: [
          const CupertinoSliverNavigationBar(
            largeTitle: Text("Settings"),
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
                    _row(CupertinoIcons.mail_solid, "Email", "ditoelvan2@gmail.com", "mailto:ditoelvan2@gmail.com", CupertinoColors.systemRed),
                  ],
                ),
                CupertinoListSection.insetGrouped(
                  backgroundColor: Colors.transparent,
                  decoration: BoxDecoration(color: AppTheme.secondarySystemBackground, borderRadius: BorderRadius.circular(10)),
                  children: [
                    CupertinoListTile(
                      leading: _iconBg(CupertinoIcons.lock_fill, AppTheme.textSecondary),
                      title: const Text("Lock Vault", style: TextStyle(color: Colors.white)),
                      onTap: widget.state.logout,
                    ),
                    CupertinoListTile(
                      leading: _iconBg(CupertinoIcons.trash_fill, CupertinoColors.systemRed),
                      title: const Text("Erase All Data", style: TextStyle(color: CupertinoColors.systemRed)),
                      onTap: () async {
                        HapticFeedback.heavyImpact();
                        showCupertinoDialog(
                          context: context, 
                          builder: (ctx) => CupertinoAlertDialog(
                            title: const Text("Are you sure?"),
                            content: const Text("This will permanently delete all your data. This action cannot be undone."),
                            actions: [
                              CupertinoDialogAction(child: const Text("Cancel"), onPressed: () => Navigator.pop(ctx)),
                              CupertinoDialogAction(
                                isDestructiveAction: true,
                                child: const Text("Erase Data"), 
                                onPressed: () async {
                                  final p = await SharedPreferences.getInstance();
                                  await p.clear();
                                  widget.state.logout();
                                  Navigator.pop(ctx);
                                }
                              ),
                            ]
                          )
                        );
                      },
                    ),
                  ],
                ),
                const SizedBox(height: 40),
                GestureDetector(
                  onTap: _triggerEasterEgg,
                  child: const Text("VaultX v1.5.0", style: TextStyle(color: AppTheme.textSecondary, fontSize: 13, letterSpacing: 0.5)),
                ),
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
    onTap: () {
      HapticFeedback.lightImpact();
      launchUrl(Uri.parse(u));
    },
  );
}
