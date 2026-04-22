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

// ==========================================
// 1. THEME & STYLES
// ==========================================
class AppTheme {
  static const bgBase = Color(0xFF000000);
  static const bgSurface = Color(0xFF121212);
  static const bgPanel = Color(0xFF0A0A0A);
  static const borderLight = Color(0x20FFFFFF);
  static const borderFocus = Color(0x60FFFFFF);
  static const textMain = Color(0xFFEDEDED);
  static const textMuted = Color(0xFF888888);
  static const primary = Color(0xFFFFFFFF);
  static const primaryInvert = Color(0xFF000000);
  static const accent = Color(0xFF5E6AD2);
  static const danger = Color(0xFFE5484D);
  static const success = Color(0xFF30A46C);
  static const warning = Color(0xFFF5A623);

  static ThemeData get darkTheme {
    return ThemeData(
      brightness: Brightness.dark,
      scaffoldBackgroundColor: bgBase,
      primaryColor: primary,
      colorScheme: const ColorScheme.dark(
        primary: primary,
        secondary: accent,
        surface: bgSurface,
        error: danger,
      ),
      fontFamily: 'Roboto',
      appBarTheme: const AppBarTheme(
        backgroundColor: bgBase,
        elevation: 0,
        surfaceTintColor: Colors.transparent,
      ),
    );
  }
}

// ==========================================
// 2. CRYPTOGRAPHY ENGINE
// ==========================================
class CryptoEngine {
  static final _aes = AesGcm.with256bits();
  static final _mac = Hmac.sha256();

  static Future<SecretKey> deriveKey(String pin, List<int> salt) async {
    final pbkdf2 = Pbkdf2(macAlgorithm: _mac, iterations: 100000, bits: 256);
    return await pbkdf2.deriveKey(
      secretKey: SecretKey(utf8.encode(pin)),
      nonce: salt,
    );
  }

  static Future<Map<String, String>> encryptJSON(Map<String, dynamic> data, SecretKey key) async {
    final iv = _generateRandomBytes(12);
    final jsonStr = jsonEncode(data);
    
    final secretBox = await _aes.encrypt(
      utf8.encode(jsonStr),
      secretKey: key,
      nonce: iv,
    );

    return {
      'c': base64Encode(secretBox.cipherText + secretBox.mac.bytes),
      'i': base64Encode(iv),
    };
  }

  static Future<Map<String, dynamic>> decryptJSON(String c64, String i64, SecretKey key) async {
    final iv = base64Decode(i64);
    final cipherWithMac = base64Decode(c64);
    
    final cipherText = cipherWithMac.sublist(0, cipherWithMac.length - 16);
    final macBytes = cipherWithMac.sublist(cipherWithMac.length - 16);

    final secretBox = SecretBox(cipherText, nonce: iv, mac: Mac(macBytes));
    
    final clearText = await _aes.decrypt(secretBox, secretKey: key);
    return jsonDecode(utf8.decode(clearText));
  }

  static List<int> _generateRandomBytes(int length) {
    final random = Random.secure();
    return List<int>.generate(length, (i) => random.nextInt(256));
  }
}

// ==========================================
// 3. STATE MANAGEMENT
// ==========================================
class VaultState extends ChangeNotifier {
  SecretKey? _key;
  Map<String, dynamic>? vault;
  bool isAuthenticated = false;
  
  final String kData = 'vlt_pro_d';
  final String kSalt = 'vlt_pro_s';

  Future<bool> hasVault() async {
    final prefs = await SharedPreferences.getInstance();
    return prefs.containsKey(kData);
  }

  Future<void> initVault(String pin) async {
    final salt = CryptoEngine._generateRandomBytes(16);
    final key = await CryptoEngine.deriveKey(pin, salt);
    
    vault = {
      'set': {'lockMin': 3},
      'items': []
    };
    
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(kSalt, base64Encode(salt));
    
    _key = key;
    await saveVault();
    isAuthenticated = true;
    notifyListeners();
  }

  Future<bool> unlockVault(String pin) async {
    try {
      final prefs = await SharedPreferences.getInstance();
      final salt = base64Decode(prefs.getString(kSalt)!);
      final data = jsonDecode(prefs.getString(kData)!);
      
      final key = await CryptoEngine.deriveKey(pin, salt);
      final decoded = await CryptoEngine.decryptJSON(data['c'], data['i'], key);
      
      vault = decoded;
      _key = key;
      isAuthenticated = true;
      notifyListeners();
      return true;
    } catch (e) {
      return false;
    }
  }

  Future<void> saveVault() async {
    if (_key == null || vault == null) return;
    final enc = await CryptoEngine.encryptJSON(vault!, _key!);
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(kData, jsonEncode(enc));
    notifyListeners();
  }

  void lockVault() {
    _key = null;
    vault = null;
    isAuthenticated = false;
    notifyListeners();
  }

  Future<void> deleteVault() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.remove(kData);
    await prefs.remove(kSalt);
    lockVault();
  }

  Future<void> changePin(String newPin) async {
    if (_key == null || vault == null) return;
    final salt = CryptoEngine._generateRandomBytes(16);
    final nKey = await CryptoEngine.deriveKey(newPin, salt);
    
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(kSalt, base64Encode(salt));
    
    _key = nKey;
    await saveVault();
  }

  // Auto-Lock Lifecycle Logic
  DateTime? _pausedAt;
  void handleLifecycleChange(AppLifecycleState state) {
    if (!isAuthenticated || vault == null) return;
    
    if (state == AppLifecycleState.paused) {
      _pausedAt = DateTime.now();
    } else if (state == AppLifecycleState.resumed && _pausedAt != null) {
      int lockMin = vault!['set']['lockMin'] ?? 3;
      if (lockMin > 0) {
        final diff = DateTime.now().difference(_pausedAt!);
        if (diff.inMinutes >= lockMin) {
          lockVault();
        }
      }
      _pausedAt = null;
    }
  }
}

// ==========================================
// 4. MAIN APP WIDGET
// ==========================================
class VaultXApp extends StatefulWidget {
  const VaultXApp({super.key});
  @override
  State<VaultXApp> createState() => _VaultXAppState();
}

class _VaultXAppState extends State<VaultXApp> with WidgetsBindingObserver {
  final VaultState _vaultState = VaultState();

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    _vaultState.dispose();
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    _vaultState.handleLifecycleChange(state);
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'VaultX',
      theme: AppTheme.darkTheme,
      debugShowCheckedModeBanner: false,
      home: AnimatedBuilder(
        animation: _vaultState,
        builder: (context, _) {
          return _vaultState.isAuthenticated 
            ? DashboardScreen(state: _vaultState) 
            : AuthScreen(state: _vaultState);
        },
      ),
    );
  }
}

// ==========================================
// 5. AUTHENTICATION SCREEN
// ==========================================
class AuthScreen extends StatefulWidget {
  final VaultState state;
  const AuthScreen({super.key, required this.state});

  @override
  State<AuthScreen> createState() => _AuthScreenState();
}

class _AuthScreenState extends State<AuthScreen> {
  String _pin = '';
  bool _hasVault = false;
  bool _isError = false;
  bool _isLoading = true;

  @override
  void initState() {
    super.initState();
    _checkVault();
  }

  Future<void> _checkVault() async {
    _hasVault = await widget.state.hasVault();
    setState(() => _isLoading = false);
  }

  void _onKeyPress(String val) {
    if (val == 'C') {
      setState(() { _pin = ''; _isError = false; });
    } else if (val == 'DEL') {
      if (_pin.isNotEmpty) {
        setState(() { _pin = _pin.substring(0, _pin.length - 1); _isError = false; });
      }
    } else {
      if (_pin.length < 8) {
        setState(() { _pin += val; _isError = false; });
      }
    }
  }

  Future<void> _submit() async {
    if (_pin.length < 4) {
      setState(() => _isError = true);
      ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text("PIN minimal 4 digit")));
      return;
    }

    setState(() => _isLoading = true);
    if (_hasVault) {
      final success = await widget.state.unlockVault(_pin);
      if (!success) {
        setState(() { _isError = true; _isLoading = false; _pin = ''; });
      }
    } else {
      await widget.state.initVault(_pin);
    }
  }

  @override
  Widget build(BuildContext context) {
    if (_isLoading) return const Scaffold(body: Center(child: CircularProgressIndicator()));

    return Scaffold(
      body: Container(
        decoration: const BoxDecoration(
          gradient: RadialGradient(
            center: Alignment(0, -0.6),
            radius: 1.0,
            colors: [Color(0xFF1A1A1A), AppTheme.bgBase],
          ),
        ),
        child: Center(
          child: SingleChildScrollView(
            padding: const EdgeInsets.all(24),
            child: Container(
              padding: const EdgeInsets.all(24),
              decoration: BoxDecoration(
                color: AppTheme.bgPanel.withOpacity(0.8),
                borderRadius: BorderRadius.circular(24),
                border: Border.all(color: AppTheme.borderLight),
                boxShadow: const [BoxShadow(color: Colors.black54, blurRadius: 40, offset: Offset(0, 20))],
              ),
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Container(
                    width: 56, height: 56,
                    decoration: BoxDecoration(
                      color: AppTheme.bgSurface,
                      borderRadius: BorderRadius.circular(16),
                      border: Border.all(color: AppTheme.borderLight),
                    ),
                    child: const Icon(Icons.shield_outlined, size: 28, color: AppTheme.textMain),
                  ),
                  const SizedBox(height: 16),
                  Text("VaultX", style: Theme.of(context).textTheme.headlineSmall?.copyWith(fontWeight: FontWeight.bold)),
                  const SizedBox(height: 8),
                  Text(
                    _hasVault ? "Masukkan Master PIN" : "Setup Master PIN Baru",
                    style: const TextStyle(color: AppTheme.textMuted),
                  ),
                  const SizedBox(height: 32),
                  
                  // PIN Display
                  Container(
                    width: double.infinity,
                    padding: const EdgeInsets.symmetric(vertical: 16),
                    decoration: BoxDecoration(
                      color: AppTheme.bgSurface,
                      borderRadius: BorderRadius.circular(12),
                      border: Border.all(color: _isError ? AppTheme.danger : AppTheme.borderLight),
                    ),
                    child: Text(
                      _pin.padRight(8, '•').substring(0, max(_pin.length, 4)),
                      textAlign: TextAlign.center,
                      style: TextStyle(
                        fontSize: 24, letterSpacing: 8, fontFamily: 'monospace',
                        color: _pin.isEmpty ? AppTheme.textMuted : AppTheme.accent,
                      ),
                    ),
                  ),
                  if (_isError)
                    const Padding(
                      padding: EdgeInsets.only(top: 8),
                      child: Text("PIN salah atau rusak", style: TextStyle(color: AppTheme.danger, fontSize: 12)),
                    ),
                  
                  const SizedBox(height: 24),
                  
                  // Virtual Keypad
                  GridView.count(
                    shrinkWrap: true,
                    physics: const NeverScrollableScrollPhysics(),
                    crossAxisCount: 3,
                    mainAxisSpacing: 8,
                    crossAxisSpacing: 8,
                    childAspectRatio: 1.5,
                    children: [
                      for (var i = 1; i <= 9; i++) _buildKey(i.toString()),
                      _buildKey('C', isAction: true),
                      _buildKey('0'),
                      _buildKey('DEL', isAction: true),
                    ],
                  ),
                  
                  const SizedBox(height: 24),
                  SizedBox(
                    width: double.infinity,
                    height: 50,
                    child: ElevatedButton(
                      style: ElevatedButton.styleFrom(
                        backgroundColor: AppTheme.primary,
                        foregroundColor: AppTheme.primaryInvert,
                        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
                      ),
                      onPressed: _pin.length >= 4 ? _submit : null,
                      child: Text(_hasVault ? 'Unlock Vault' : 'Initialize Vault', style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 16)),
                    ),
                  )
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildKey(String val, {bool isAction = false}) {
    return Material(
      color: Colors.transparent,
      child: InkWell(
        onTap: () => _onKeyPress(val),
        borderRadius: BorderRadius.circular(8),
        child: Container(
          decoration: BoxDecoration(
            color: AppTheme.bgSurface,
            borderRadius: BorderRadius.circular(8),
            border: Border.all(color: AppTheme.borderLight),
          ),
          alignment: Alignment.center,
          child: val == 'DEL' 
            ? const Icon(Icons.backspace_outlined, size: 20, color: AppTheme.textMuted)
            : Text(val, style: TextStyle(
                fontSize: isAction ? 16 : 22,
                fontWeight: isAction ? FontWeight.normal : FontWeight.w500,
                color: isAction ? AppTheme.textMuted : AppTheme.textMain,
              )),
        ),
      ),
    );
  }
}

// ==========================================
// 6. MAIN DASHBOARD SCREEN
// ==========================================
class DashboardScreen extends StatefulWidget {
  final VaultState state;
  const DashboardScreen({super.key, required this.state});

  @override
  State<DashboardScreen> createState() => _DashboardScreenState();
}

class _DashboardScreenState extends State<DashboardScreen> {
  int _currentIndex = 0;
  String _searchQuery = "";

  final List<Map<String, dynamic>> _navItems = [
    {'title': 'All Items', 'icon': Icons.list_alt, 'filter': 'all'},
    {'title': 'Favorites', 'icon': Icons.star_border, 'filter': 'fav'},
    {'title': 'Passwords', 'icon': Icons.password, 'filter': 'password'},
    {'title': 'API Keys', 'icon': Icons.key, 'filter': 'api_key'},
    {'title': 'Settings', 'icon': Icons.settings, 'filter': 'settings'},
  ];

  void _showForm([Map<String, dynamic>? item]) {
    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      backgroundColor: Colors.transparent,
      builder: (ctx) => ItemFormSheet(state: widget.state, existingItem: item),
    );
  }

  void _showGenerator() {
    showModalBottomSheet(
      context: context,
      backgroundColor: Colors.transparent,
      builder: (ctx) => const GeneratorSheet(),
    );
  }

  @override
  Widget build(BuildContext context) {
    final nav = _navItems[_currentIndex];
    final filter = nav['filter'];

    return Scaffold(
      appBar: AppBar(
        title: filter == 'settings' 
          ? const Text("Settings", style: TextStyle(fontWeight: FontWeight.bold))
          : TextField(
              onChanged: (v) => setState(() => _searchQuery = v.toLowerCase()),
              style: const TextStyle(color: AppTheme.textMain),
              decoration: const InputDecoration(
                hintText: "Search saved data...",
                hintStyle: TextStyle(color: AppTheme.textMuted),
                border: InputBorder.none,
                icon: Icon(Icons.search, color: AppTheme.textMuted),
              ),
            ),
        actions: [
          if (filter != 'settings')
            IconButton(icon: const Icon(Icons.add_circle_outline), onPressed: _showForm),
          IconButton(icon: const Icon(Icons.lock_outline), onPressed: widget.state.lockVault),
          const SizedBox(width: 8),
        ],
      ),
      body: filter == 'settings' 
        ? SettingsView(state: widget.state)
        : _buildListView(filter),
      floatingActionButton: filter != 'settings' ? FloatingActionButton(
        backgroundColor: AppTheme.accent,
        foregroundColor: Colors.white,
        onPressed: _showGenerator,
        child: const Icon(Icons.password),
      ) : null,
      bottomNavigationBar: BottomNavigationBar(
        backgroundColor: AppTheme.bgPanel,
        type: BottomNavigationBarType.fixed,
        selectedItemColor: AppTheme.primary,
        unselectedItemColor: AppTheme.textMuted,
        currentIndex: _currentIndex,
        onTap: (i) => setState(() { _currentIndex = i; _searchQuery = ''; }),
        items: _navItems.map((e) => BottomNavigationBarItem(
          icon: Icon(e['icon']), label: e['title'],
        )).toList(),
      ),
    );
  }

  Widget _buildListView(String filter) {
    List<dynamic> items = widget.state.vault!['items'];
    
    // Filtering
    var filtered = items.where((i) {
      bool matchNav = true;
      if (filter == 'fav') matchNav = i['fav'] == true;
      else if (filter != 'all') matchNav = i['type'] == filter;
      
      bool matchSearch = i['title'].toString().toLowerCase().contains(_searchQuery) ||
                         (i['username'] ?? '').toString().toLowerCase().contains(_searchQuery);
                         
      return matchNav && matchSearch;
    }).toList().reversed.toList();

    if (filtered.isEmpty) {
      return const Center(child: Text("No data found.", style: TextStyle(color: AppTheme.textMuted)));
    }

    return ListView.builder(
      padding: const EdgeInsets.all(16),
      itemCount: filtered.length,
      itemBuilder: (ctx, i) => ItemCard(
        item: filtered[i], 
        state: widget.state,
        onEdit: () => _showForm(filtered[i]),
      ),
    );
  }
}

// ==========================================
// 7. WIDGETS & SHEETS
// ==========================================
class ItemCard extends StatefulWidget {
  final dynamic item;
  final VaultState state;
  final VoidCallback onEdit;

  const ItemCard({super.key, required this.item, required this.state, required this.onEdit});

  @override
  State<ItemCard> createState() => _ItemCardState();
}

class _ItemCardState extends State<ItemCard> {
  bool _showSecret = false;

  void _toggleFav() {
    widget.item['fav'] = !(widget.item['fav'] ?? false);
    widget.state.saveVault();
  }

  void _copy(String text) {
    Clipboard.setData(ClipboardData(text: text));
    ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text("Copied to clipboard!")));
  }

  void _showSnap() {
    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      backgroundColor: Colors.transparent,
      builder: (ctx) => SnapShareSheet(item: widget.item),
    );
  }

  IconData _getIcon() {
    if (widget.item['type'] == 'password') return Icons.password;
    if (widget.item['type'] == 'api_key') return Icons.vpn_key;
    return Icons.notes;
  }

  @override
  Widget build(BuildContext context) {
    return Container(
      margin: const EdgeInsets.only(bottom: 12),
      decoration: BoxDecoration(
        color: AppTheme.bgSurface,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: AppTheme.borderLight),
      ),
      child: Column(
        children: [
          ListTile(
            leading: Container(
              padding: const EdgeInsets.all(10),
              decoration: BoxDecoration(color: AppTheme.bgPanel, borderRadius: BorderRadius.circular(8)),
              child: Icon(_getIcon(), color: AppTheme.textMuted, size: 20),
            ),
            title: Text(widget.item['title'], style: const TextStyle(fontWeight: FontWeight.bold)),
            subtitle: Text(widget.item['username'] ?? '', style: const TextStyle(color: AppTheme.textMuted, fontSize: 12)),
            trailing: IconButton(
              icon: Icon(widget.item['fav'] == true ? Icons.star : Icons.star_border, color: widget.item['fav'] == true ? AppTheme.warning : AppTheme.textMuted),
              onPressed: _toggleFav,
            ),
          ),
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 16),
            child: InkWell(
              onTap: () {
                setState(() => _showSecret = !_showSecret);
                if (_showSecret) Future.delayed(const Duration(seconds: 5), () { if(mounted) setState(() => _showSecret=false); });
              },
              child: Container(
                width: double.infinity,
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(color: AppTheme.bgPanel, borderRadius: BorderRadius.circular(8)),
                child: Text(
                  _showSecret ? widget.item['secret'] : '••••••••••••••••',
                  textAlign: TextAlign.center,
                  style: TextStyle(fontFamily: 'monospace', letterSpacing: _showSecret ? 1 : 4, color: AppTheme.textMuted),
                ),
              ),
            ),
          ),
          Row(
            mainAxisAlignment: MainAxisAlignment.end,
            children: [
              IconButton(icon: const Icon(Icons.qr_code, color: AppTheme.textMuted, size: 20), onPressed: _showSnap),
              IconButton(icon: const Icon(Icons.copy, color: AppTheme.textMuted, size: 20), onPressed: () => _copy(widget.item['secret'])),
              IconButton(icon: const Icon(Icons.edit, color: AppTheme.textMuted, size: 20), onPressed: widget.onEdit),
              const SizedBox(width: 8),
            ],
          )
        ],
      ),
    );
  }
}

class SnapShareSheet extends StatelessWidget {
  final dynamic item;
  SnapShareSheet({super.key, required this.item});

  final ScreenshotController _ssController = ScreenshotController();

  Future<void> _shareSnap(BuildContext context) async {
    final Uint8List? image = await _ssController.capture();
    if (image == null) return;
    
    final dir = await getApplicationDocumentsDirectory();
    final file = File('${dir.path}/VaultX_Snap_${item['title']}.png');
    await file.writeAsBytes(image);
    
    await Share.shareXFiles([XFile(file.path)], text: 'Secure Share from VaultX');
  }

  @override
  Widget build(BuildContext context) {
    String payload = "Service: ${item['title']}\n";
    if (item['username']?.isNotEmpty == true) payload += "User: ${item['username']}\n";
    payload += "Secret: ${item['secret']}";

    return Container(
      padding: const EdgeInsets.all(24),
      decoration: const BoxDecoration(
        color: AppTheme.bgPanel,
        borderRadius: BorderRadius.vertical(top: Radius.circular(24)),
      ),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          const Text("Share Credential Snap", style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold)),
          const SizedBox(height: 24),
          
          Screenshot(
            controller: _ssController,
            child: Container(
              padding: const EdgeInsets.all(24),
              decoration: BoxDecoration(
                gradient: const LinearGradient(colors: [Color(0xFF5E6AD2), Color(0xFF9B51E0)]),
                borderRadius: BorderRadius.circular(16),
              ),
              child: Column(
                children: [
                  Container(
                    width: double.infinity,
                    padding: const EdgeInsets.all(16),
                    decoration: BoxDecoration(
                      color: AppTheme.bgPanel,
                      borderRadius: BorderRadius.circular(12),
                      boxShadow: const [BoxShadow(color: Colors.black54, blurRadius: 20, offset: Offset(0, 10))],
                    ),
                    child: Column(
                      children: [
                        Row(
                          children: [
                            _dot(Color(0xFFFF5F56)), SizedBox(width: 6),
                            _dot(Color(0xFFFFBD2E)), SizedBox(width: 6),
                            _dot(Color(0xFF27C93F)),
                          ],
                        ),
                        const SizedBox(height: 16),
                        Text(item['title'], style: const TextStyle(fontSize: 20, fontWeight: FontWeight.bold, color: Colors.white)),
                        const SizedBox(height: 4),
                        Text(item['username'] ?? 'Secure Data', style: const TextStyle(color: AppTheme.textMuted)),
                        const SizedBox(height: 24),
                        Container(
                          padding: const EdgeInsets.all(12),
                          decoration: BoxDecoration(color: Colors.white, borderRadius: BorderRadius.circular(8)),
                          child: QrImageView(data: payload, version: QrVersions.auto, size: 200),
                        ),
                      ],
                    ),
                  ),
                  const SizedBox(height: 16),
                  const Text("VaultX Secure Share", style: TextStyle(color: Colors.white70, fontSize: 12)),
                ],
              ),
            ),
          ),
          
          const SizedBox(height: 24),
          SizedBox(
            width: double.infinity, height: 50,
            child: ElevatedButton.icon(
              icon: const Icon(Icons.download),
              label: const Text("Share Snap"),
              style: ElevatedButton.styleFrom(backgroundColor: AppTheme.primary, foregroundColor: AppTheme.primaryInvert),
              onPressed: () => _shareSnap(context),
            ),
          )
        ],
      ),
    );
  }

  Widget _dot(Color c) => Container(width: 12, height: 12, decoration: BoxDecoration(color: c, shape: BoxShape.circle));
}

// FORM SHEET
class ItemFormSheet extends StatefulWidget {
  final VaultState state;
  final Map<String, dynamic>? existingItem;

  const ItemFormSheet({super.key, required this.state, this.existingItem});

  @override
  State<ItemFormSheet> createState() => _ItemFormSheetState();
}

class _ItemFormSheetState extends State<ItemFormSheet> {
  final _formKey = GlobalKey<FormState>();
  String _type = 'password';
  String _title = '';
  String _user = '';
  String _secret = '';
  String _notes = '';

  @override
  void initState() {
    super.initState();
    if (widget.existingItem != null) {
      _type = widget.existingItem!['type'];
      _title = widget.existingItem!['title'];
      _user = widget.existingItem!['username'] ?? '';
      _secret = widget.existingItem!['secret'];
      _notes = widget.existingItem!['notes'] ?? '';
    }
  }

  void _save() {
    if (!_formKey.currentState!.validate()) return;
    _formKey.currentState!.save();

    final newItem = {
      'id': widget.existingItem?['id'] ?? DateTime.now().millisecondsSinceEpoch.toString(),
      'type': _type,
      'title': _title,
      'username': _user,
      'secret': _secret,
      'notes': _notes,
      'fav': widget.existingItem?['fav'] ?? false,
    };

    List<dynamic> items = widget.state.vault!['items'];
    if (widget.existingItem != null) {
      int idx = items.indexWhere((e) => e['id'] == newItem['id']);
      if (idx != -1) items[idx] = newItem;
    } else {
      items.add(newItem);
    }

    widget.state.saveVault();
    Navigator.pop(context);
  }

  void _delete() {
    List<dynamic> items = widget.state.vault!['items'];
    items.removeWhere((e) => e['id'] == widget.existingItem!['id']);
    widget.state.saveVault();
    Navigator.pop(context);
  }

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: EdgeInsets.only(bottom: MediaQuery.of(context).viewInsets.bottom),
      child: Container(
        padding: const EdgeInsets.all(24),
        decoration: const BoxDecoration(
          color: AppTheme.bgPanel,
          borderRadius: BorderRadius.vertical(top: Radius.circular(24)),
        ),
        child: Form(
          key: _formKey,
          child: SingleChildScrollView(
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(widget.existingItem == null ? "Add Credential" : "Edit Credential", style: const TextStyle(fontSize: 20, fontWeight: FontWeight.bold)),
                const SizedBox(height: 16),
                
                DropdownButtonFormField<String>(
                  value: _type,
                  dropdownColor: AppTheme.bgSurface,
                  decoration: _inputDeco("Type"),
                  items: const [
                    DropdownMenuItem(value: 'password', child: Text("Login & Password")),
                    DropdownMenuItem(value: 'api_key', child: Text("API Key")),
                    DropdownMenuItem(value: 'note', child: Text("Secure Note")),
                  ],
                  onChanged: (v) => setState(() => _type = v!),
                ),
                const SizedBox(height: 12),
                
                TextFormField(
                  initialValue: _title,
                  decoration: _inputDeco("Title / Service"),
                  validator: (v) => v!.isEmpty ? "Required" : null,
                  onSaved: (v) => _title = v!,
                ),
                const SizedBox(height: 12),
                
                TextFormField(
                  initialValue: _user,
                  decoration: _inputDeco("Username / Email (Optional)"),
                  onSaved: (v) => _user = v!,
                ),
                const SizedBox(height: 12),
                
                TextFormField(
                  initialValue: _secret,
                  decoration: _inputDeco("Secret Data"),
                  obscureText: true,
                  validator: (v) => v!.isEmpty ? "Required" : null,
                  onSaved: (v) => _secret = v!,
                ),
                const SizedBox(height: 12),
                
                TextFormField(
                  initialValue: _notes,
                  decoration: _inputDeco("Additional Notes"),
                  maxLines: 2,
                  onSaved: (v) => _notes = v!,
                ),
                const SizedBox(height: 24),
                
                Row(
                  mainAxisAlignment: MainAxisAlignment.spaceBetween,
                  children: [
                    if (widget.existingItem != null)
                      TextButton(onPressed: _delete, child: const Text("Delete", style: TextStyle(color: AppTheme.danger))),
                    if (widget.existingItem == null) const SizedBox(),
                    ElevatedButton(
                      style: ElevatedButton.styleFrom(backgroundColor: AppTheme.primary, foregroundColor: AppTheme.primaryInvert),
                      onPressed: _save,
                      child: const Text("Save Data"),
                    )
                  ],
                )
              ],
            ),
          ),
        ),
      ),
    );
  }

  InputDecoration _inputDeco(String label) => InputDecoration(
    labelText: label,
    labelStyle: const TextStyle(color: AppTheme.textMuted),
    filled: true,
    fillColor: AppTheme.bgSurface,
    border: OutlineInputBorder(borderRadius: BorderRadius.circular(8), borderSide: BorderSide.none),
    focusedBorder: OutlineInputBorder(borderRadius: BorderRadius.circular(8), borderSide: const BorderSide(color: AppTheme.borderFocus)),
  );
}

// GENERATOR SHEET
class GeneratorSheet extends StatefulWidget {
  const GeneratorSheet({super.key});
  @override
  State<GeneratorSheet> createState() => _GeneratorSheetState();
}

class _GeneratorSheetState extends State<GeneratorSheet> {
  double _len = 16;
  String _pwd = "";

  @override
  void initState() { super.initState(); _generate(); }

  void _generate() {
    const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#\$%^&*+?";
    final rnd = Random.secure();
    _pwd = String.fromCharCodes(Iterable.generate(_len.toInt(), (_) => chars.codeUnitAt(rnd.nextInt(chars.length))));
    setState(() {});
  }

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(24),
      decoration: const BoxDecoration(color: AppTheme.bgPanel, borderRadius: BorderRadius.vertical(top: Radius.circular(24))),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          const Text("Password Generator", style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold)),
          const SizedBox(height: 24),
          Container(
            width: double.infinity, padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(color: AppTheme.bgSurface, borderRadius: BorderRadius.circular(8), border: Border.all(color: AppTheme.borderLight)),
            child: Text(_pwd, textAlign: TextAlign.center, style: const TextStyle(color: AppTheme.accent, fontFamily: 'monospace', fontSize: 18, letterSpacing: 2)),
          ),
          const SizedBox(height: 24),
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [const Text("Length"), Text(_len.toInt().toString(), style: const TextStyle(fontWeight: FontWeight.bold))],
          ),
          Slider(
            value: _len, min: 8, max: 32, divisions: 24,
            activeColor: AppTheme.primary, inactiveColor: AppTheme.borderLight,
            onChanged: (v) { setState(() => _len = v); _generate(); },
          ),
          const SizedBox(height: 16),
          Row(
            children: [
              Expanded(child: OutlinedButton(onPressed: _generate, child: const Text("Regenerate", style: TextStyle(color: AppTheme.textMain)))),
              const SizedBox(width: 12),
              Expanded(child: ElevatedButton(
                style: ElevatedButton.styleFrom(backgroundColor: AppTheme.primary, foregroundColor: AppTheme.primaryInvert),
                onPressed: () { Clipboard.setData(ClipboardData(text: _pwd)); Navigator.pop(context); },
                child: const Text("Copy"),
              )),
            ],
          )
        ],
      ),
    );
  }
}

// SETTINGS VIEW
class SettingsView extends StatelessWidget {
  final VaultState state;
  const SettingsView({super.key, required this.state});

  void _export(BuildContext context) async {
    final prefs = await SharedPreferences.getInstance();
    final d = prefs.getString(state.kData);
    final s = prefs.getString(state.kSalt);
    final jsonStr = jsonEncode({'s': s, 'd': d});
    
    // Copy to clipboard is safer & universally works across devices without permission issues
    Clipboard.setData(ClipboardData(text: jsonStr));
    ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text("Backup Code Copied to Clipboard! Save it safely.")));
  }

  void _import(BuildContext context) async {
    TextEditingController ctrl = TextEditingController();
    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: AppTheme.bgPanel,
        title: const Text("Import Backup Code"),
        content: TextField(
          controller: ctrl,
          maxLines: 4,
          decoration: const InputDecoration(hintText: "Paste JSON backup code here..."),
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx), child: const Text("Cancel")),
          ElevatedButton(
            onPressed: () async {
              try {
                final Map<String, dynamic> p = jsonDecode(ctrl.text);
                if (p.containsKey('s') && p.containsKey('d')) {
                  final prefs = await SharedPreferences.getInstance();
                  await prefs.setString(state.kSalt, p['s']);
                  await prefs.setString(state.kData, p['d']);
                  Navigator.pop(ctx);
                  state.lockVault(); // Force re-login
                }
              } catch (e) {
                ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text("Invalid Backup Code")));
              }
            },
            child: const Text("Restore"),
          )
        ],
      )
    );
  }

  void _changePin(BuildContext context) {
    TextEditingController ctrl = TextEditingController();
    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: AppTheme.bgPanel,
        title: const Text("Change Master PIN"),
        content: TextField(
          controller: ctrl,
          keyboardType: TextInputType.number,
          obscureText: true,
          decoration: const InputDecoration(hintText: "Enter New PIN (Min 4 digit)"),
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx), child: const Text("Cancel")),
          ElevatedButton(
            onPressed: () {
              if (ctrl.text.length >= 4) {
                state.changePin(ctrl.text);
                Navigator.pop(ctx);
                ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text("PIN Changed Successfully")));
              }
            },
            child: const Text("Update"),
          )
        ],
      )
    );
  }

  void _nuke(BuildContext context) {
    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: AppTheme.bgPanel,
        title: const Text("Danger Zone", style: TextStyle(color: AppTheme.danger)),
        content: const Text("Are you sure you want to permanently delete the vault? This cannot be undone."),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx), child: const Text("Cancel")),
          ElevatedButton(
            style: ElevatedButton.styleFrom(backgroundColor: AppTheme.danger, foregroundColor: Colors.white),
            onPressed: () { state.deleteVault(); Navigator.pop(ctx); },
            child: const Text("DELETE VAULT"),
          )
        ],
      )
    );
  }

  @override
  Widget build(BuildContext context) {
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        _buildBlock(
          "Auto-Lock",
          "Locks automatically in background.",
          DropdownButton<int>(
            value: state.vault!['set']['lockMin'],
            dropdownColor: AppTheme.bgSurface,
            underline: const SizedBox(),
            items: const [
              DropdownMenuItem(value: 1, child: Text("1 Minute")),
              DropdownMenuItem(value: 3, child: Text("3 Minutes")),
              DropdownMenuItem(value: 5, child: Text("5 Minutes")),
              DropdownMenuItem(value: 0, child: Text("Never")),
            ],
            onChanged: (v) {
              state.vault!['set']['lockMin'] = v;
              state.saveVault();
            },
          )
        ),
        
        _buildBlock(
          "Backup & Restore",
          "Export or Import vault using Base64 Encrypted JSON strings.",
          Row(
            children: [
              Expanded(child: OutlinedButton(onPressed: () => _export(context), child: const Text("Copy Backup Code", style: TextStyle(color: AppTheme.textMain)))),
              const SizedBox(width: 8),
              Expanded(child: OutlinedButton(onPressed: () => _import(context), child: const Text("Restore Backup", style: TextStyle(color: AppTheme.textMain)))),
            ],
          )
        ),

        _buildBlock(
          "Change PIN",
          "Change your master PIN and re-encrypt data.",
          ElevatedButton(onPressed: () => _changePin(context), child: const Text("Change PIN"))
        ),

        Container(
          padding: const EdgeInsets.all(16),
          decoration: BoxDecoration(border: Border.all(color: AppTheme.danger.withOpacity(0.5)), borderRadius: BorderRadius.circular(8)),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const Text("Danger Zone", style: TextStyle(color: AppTheme.danger, fontWeight: FontWeight.bold)),
              const SizedBox(height: 4),
              const Text("Permanently delete the vault from this device.", style: TextStyle(color: AppTheme.textMuted, fontSize: 12)),
              const SizedBox(height: 12),
              SizedBox(width: double.infinity, child: ElevatedButton(
                style: ElevatedButton.styleFrom(backgroundColor: AppTheme.danger.withOpacity(0.2), foregroundColor: AppTheme.danger, elevation: 0),
                onPressed: () => _nuke(context),
                child: const Text("Delete Vault"),
              ))
            ],
          )
        )
      ],
    );
  }

  Widget _buildBlock(String title, String sub, Widget action) {
    return Container(
      margin: const EdgeInsets.only(bottom: 16),
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(color: AppTheme.bgSurface, borderRadius: BorderRadius.circular(12), border: Border.all(color: AppTheme.borderLight)),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(title, style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 16)),
          const SizedBox(height: 4),
          Text(sub, style: const TextStyle(color: AppTheme.textMuted, fontSize: 13)),
          const SizedBox(height: 16),
          action
        ],
      ),
    );
  }
}
