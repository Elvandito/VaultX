import 'dart:async';
import 'dart:convert';
import 'dart:math';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:cryptography/cryptography.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:uuid/uuid.dart';

void main() {
  runApp(const VaultKryptApp());
}

class VaultKryptApp extends StatelessWidget {
  const VaultKryptApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'VaultKrypt',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        brightness: Brightness.dark,
        primaryColor: const Color(0xFF3B82F6),
        scaffoldBackgroundColor: const Color(0xFF0A0A0C),
        cardTheme: CardTheme(
          color: const Color(0xFF16161E),
          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(24)),
          elevation: 0,
        ),
      ),
      home: const MainGate(),
    );
  }
}

// --- ENCRYPTION ENGINE ---
class CryptoService {
  static const String _storageKey = "encrypted_vault";
  static final _algorithm = AesGcm.with256bits();

  static Future<SecretKey> deriveKey(String password, List<int> salt) async {
    final pbkdf2 = Pbkdf2(
      macAlgorithm: Hmac.sha256(),
      iterations: 100000,
      bits: 256,
    );
    return await pbkdf2.deriveKeyFromPassword(
      password: password,
      nonce: salt,
    );
  }

  static Future<void> saveVault(String plaintext, String password) async {
    final prefs = await SharedPreferences.getInstance();
    final salt = List<int>.generate(16, (i) => Random.secure().nextInt(256));
    final nonce = List<int>.generate(12, (i) => Random.secure().nextInt(256));
    
    final secretKey = await deriveKey(password, salt);
    final secretBox = await _algorithm.encrypt(
      utf8.encode(plaintext),
      secretKey: secretKey,
      nonce: nonce,
    );

    final packed = {
      'salt': base64.encode(salt),
      'nonce': base64.encode(nonce),
      'ciphertext': base64.encode(secretBox.cipherText),
      'mac': base64.encode(secretBox.mac.bytes),
    };

    await prefs.setString(_storageKey, json.encode(packed));
  }

  static Future<String?> loadVault(String password) async {
    final prefs = await SharedPreferences.getInstance();
    final raw = prefs.getString(_storageKey);
    if (raw == null) return null;

    try {
      final packed = json.decode(raw);
      final salt = base64.decode(packed['salt']);
      final nonce = base64.decode(packed['nonce']);
      final ciphertext = base64.decode(packed['ciphertext']);
      final mac = Mac(base64.decode(packed['mac']));

      final secretKey = await deriveKey(password, salt);
      final secretBox = SecretBox(ciphertext, nonce: nonce, mac: mac);
      
      final decryptedBytes = await _algorithm.decrypt(
        secretBox,
        secretKey: secretKey,
      );
      return utf8.decode(decryptedBytes);
    } catch (e) {
      throw Exception("Invalid password.");
    }
  }
}

// --- DATA MODEL ---
class VaultItem {
  final String id;
  String type;
  String title;
  String username;
  String secret;
  String notes;
  String createdAt;

  VaultItem({
    required this.id, required this.type, required this.title,
    required this.username, required this.secret, required this.notes,
    required this.createdAt,
  });

  Map<String, dynamic> toJson() => {
    'id': id, 'type': type, 'title': title, 'username': username,
    'secret': secret, 'notes': notes, 'created_at': createdAt
  };

  factory VaultItem.fromJson(Map<String, dynamic> json) => VaultItem(
    id: json['id'], type: json['type'], title: json['title'],
    username: json['username'], secret: json['secret'],
    notes: json['notes'], createdAt: json['created_at']
  );
}

// --- MAIN ENTRANCE (LOCK SCREEN) ---
class MainGate extends StatefulWidget {
  const MainGate({super.key});

  @override
  State<MainGate> createState() => _MainGateState();
}

class _MainGateState extends State<MainGate> with SingleTickerProviderStateMixin {
  final TextEditingController _passCtrl = TextEditingController();
  late AnimationController _pulseController;
  bool _isNewUser = true;
  String? _masterPassword;
  List<VaultItem> _items = [];
  bool _isLoading = false;

  @override
  void initState() {
    super.initState();
    _checkStatus();
    _pulseController = AnimationController(
      vsync: this,
      duration: const Duration(seconds: 2),
    )..repeat(reverse: true);
  }

  @override
  void dispose() {
    _pulseController.dispose();
    _passCtrl.dispose();
    super.dispose();
  }

  void _checkStatus() async {
    final prefs = await SharedPreferences.getInstance();
    setState(() => _isNewUser = !prefs.containsKey("encrypted_vault"));
  }

  Future<void> _unlock() async {
    if (_passCtrl.text.isEmpty) return;
    setState(() => _isLoading = true);
    
    try {
      if (_isNewUser) {
        _masterPassword = _passCtrl.text;
        await _saveData();
        setState(() => _isNewUser = false);
      } else {
        final decrypted = await CryptoService.loadVault(_passCtrl.text);
        if (decrypted != null) {
          final data = json.decode(decrypted);
          _items = (data['items'] as List).map((i) => VaultItem.fromJson(i)).toList();
          _masterPassword = _passCtrl.text;
        }
      }
      _passCtrl.clear();
    } catch (e) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text("Access Denied: Incorrect Password"), backgroundColor: Colors.redAccent),
      );
    } finally {
      setState(() => _isLoading = false);
    }
  }

  Future<void> _saveData() async {
    if (_masterPassword == null) return;
    final vault = {
      'metadata': {'updated': DateTime.now().toIso8601String()},
      'items': _items.map((e) => e.toJson()).toList(),
    };
    await CryptoService.saveVault(json.encode(vault), _masterPassword!);
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: AnimatedSwitcher(
        duration: const Duration(milliseconds: 600),
        child: _masterPassword == null 
          ? _buildLockScreen() 
          : Dashboard(
              items: _items,
              onLock: () => setState(() => _masterPassword = null),
              onUpdate: (item) async {
                setState(() {
                  final idx = _items.indexWhere((it) => it.id == item.id);
                  if (idx != -1) _items[idx] = item; else _items.add(item);
                });
                await _saveData();
              },
              onDelete: (id) async {
                setState(() => _items.removeWhere((it) => it.id == id));
                await _saveData();
              },
            ),
      ),
    );
  }

  Widget _buildLockScreen() {
    return Center(
      key: const ValueKey('lock_screen'),
      child: SingleChildScrollView(
        padding: const EdgeInsets.all(32),
        child: Column(
          children: [
            ScaleTransition(
              scale: Tween(begin: 1.0, end: 1.1).animate(_pulseController),
              child: Container(
                padding: const EdgeInsets.all(24),
                decoration: BoxDecoration(
                  color: Colors.blue.withOpacity(0.2),
                  shape: BoxShape.circle,
                  border: Border.all(color: Colors.blue.withOpacity(0.5), width: 2),
                ),
                child: const Icon(Icons.security, size: 64, color: Colors.blue),
              ),
            ),
            const SizedBox(height: 40),
            Text(
              _isNewUser ? "Create Your Vault" : "Vault Locked",
              style: const TextStyle(fontSize: 28, fontWeight: FontWeight.bold),
            ),
            const SizedBox(height: 12),
            Text(
              _isNewUser ? "Setup a master password to encrypt your data." : "Enter your master password to unlock.",
              textAlign: TextAlign.center,
              style: TextStyle(color: Colors.grey[500]),
            ),
            const SizedBox(height: 48),
            _buildAnimatedInput(),
            const SizedBox(height: 24),
            _buildUnlockButton(),
          ],
        ),
      ),
    );
  }

  Widget _buildAnimatedInput() {
    return TweenAnimationBuilder(
      tween: Tween<double>(begin: 0, end: 1),
      duration: const Duration(milliseconds: 800),
      builder: (context, double val, child) {
        return Opacity(
          opacity: val,
          child: Transform.translate(
            offset: Offset(0, 20 * (1 - val)),
            child: TextField(
              controller: _passCtrl,
              obscureText: true,
              textAlign: TextAlign.center,
              style: const TextStyle(letterSpacing: 8),
              decoration: InputDecoration(
                hintText: "••••••••",
                hintStyle: const TextStyle(letterSpacing: 2),
                filled: true,
                fillColor: Colors.white.withOpacity(0.05),
                border: OutlineInputBorder(borderRadius: BorderRadius.circular(20), borderSide: BorderSide.none),
              ),
            ),
          ),
        );
      },
    );
  }

  Widget _buildUnlockButton() {
    return SizedBox(
      width: double.infinity,
      child: ElevatedButton(
        onPressed: _isLoading ? null : _unlock,
        style: ElevatedButton.styleFrom(
          backgroundColor: Colors.blue,
          padding: const EdgeInsets.symmetric(vertical: 18),
          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(20)),
        ),
        child: _isLoading 
          ? const SizedBox(height: 20, width: 20, child: CircularProgressIndicator(strokeWidth: 2, color: Colors.white))
          : Text(_isNewUser ? "Initialize Vault" : "Unlock Securely"),
      ),
    );
  }
}

// --- DASHBOARD (BENTO STYLE) ---
class Dashboard extends StatefulWidget {
  final List<VaultItem> items;
  final VoidCallback onLock;
  final Function(VaultItem) onUpdate;
  final Function(String) onDelete;

  const Dashboard({super.key, required this.items, required this.onLock, required this.onUpdate, required this.onDelete});

  @override
  State<Dashboard> createState() => _DashboardState();
}

class _DashboardState extends State<Dashboard> {
  String _filter = 'all';
  String _query = '';

  @override
  Widget build(BuildContext context) {
    final filtered = widget.items.where((it) {
      final matchType = _filter == 'all' || it.type == _filter;
      final matchQuery = it.title.toLowerCase().contains(_query.toLowerCase()) || it.username.toLowerCase().contains(_query.toLowerCase());
      return matchType && matchQuery;
    }).toList();

    return Scaffold(
      appBar: AppBar(
        title: const Text("VaultKrypt", style: TextStyle(fontWeight: FontWeight.w800)),
        backgroundColor: Colors.transparent,
        elevation: 0,
        actions: [
          IconButton(onPressed: widget.onLock, icon: const Icon(Icons.power_settings_new, color: Colors.redAccent)),
        ],
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.symmetric(horizontal: 20),
        child: Column(
          children: [
            _buildAnimatedSearchBar(),
            const SizedBox(height: 24),
            _buildBentoStats(),
            const SizedBox(height: 24),
            _buildFilterChips(),
            const SizedBox(height: 24),
            _buildAnimatedList(filtered),
          ],
        ),
      ),
      floatingActionButton: FloatingActionButton(
        onPressed: () => _openForm(null),
        backgroundColor: Colors.blue,
        child: const Icon(Icons.add),
      ),
    );
  }

  Widget _buildAnimatedSearchBar() {
    return TweenAnimationBuilder(
      tween: Tween<double>(begin: 0, end: 1),
      duration: const Duration(milliseconds: 500),
      builder: (context, double val, child) {
        return Opacity(
          opacity: val,
          child: TextField(
            onChanged: (v) => setState(() => _query = v),
            decoration: InputDecoration(
              prefixIcon: const Icon(Icons.search, color: Colors.blue),
              hintText: "Search your vault...",
              filled: true,
              fillColor: const Color(0xFF16161E),
              border: OutlineInputBorder(borderRadius: BorderRadius.circular(20), borderSide: BorderSide.none),
            ),
          ),
        );
      },
    );
  }

  Widget _buildBentoStats() {
    return Row(
      children: [
        _buildStatCard("Credentials", widget.items.length.toString(), Icons.folder_special, Colors.blue, 0),
        const SizedBox(width: 16),
        _buildStatCard("Strength", "Strong", Icons.verified_user, Colors.greenAccent, 1),
      ],
    );
  }

  Widget _buildStatCard(String label, String value, IconData icon, Color color, int index) {
    return Expanded(
      child: TweenAnimationBuilder(
        tween: Tween<double>(begin: 0, end: 1),
        duration: Duration(milliseconds: 500 + (index * 200)),
        builder: (context, double val, child) {
          return Transform.scale(
            scale: val,
            child: Container(
              padding: const EdgeInsets.all(20),
              decoration: BoxDecoration(
                color: const Color(0xFF16161E),
                borderRadius: BorderRadius.circular(28),
                border: Border.all(color: Colors.white.withOpacity(0.05)),
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Icon(icon, color: color, size: 28),
                  const SizedBox(height: 16),
                  Text(value, style: const TextStyle(fontSize: 24, fontWeight: FontWeight.bold)),
                  Text(label, style: const TextStyle(color: Colors.grey, fontSize: 13)),
                ],
              ),
            ),
          );
        },
      ),
    );
  }

  Widget _buildFilterChips() {
    final types = ['all', 'password', 'api_key', 'token'];
    return SizedBox(
      height: 45,
      child: ListView.builder(
        scrollDirection: Axis.horizontal,
        itemCount: types.length,
        itemBuilder: (context, i) {
          final type = types[i];
          final isSelected = _filter == type;
          return Padding(
            padding: const EdgeInsets.only(right: 10),
            child: GestureDetector(
              onTap: () => setState(() => _filter = type),
              child: AnimatedContainer(
                duration: const Duration(milliseconds: 300),
                padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 10),
                decoration: BoxDecoration(
                  color: isSelected ? Colors.blue : Colors.white.withOpacity(0.05),
                  borderRadius: BorderRadius.circular(15),
                ),
                child: Text(
                  type.toUpperCase().replaceAll('_', ' '),
                  style: TextStyle(
                    fontSize: 12,
                    fontWeight: FontWeight.bold,
                    color: isSelected ? Colors.white : Colors.grey,
                  ),
                ),
              ),
            ),
          );
        },
      ),
    );
  }

  Widget _buildAnimatedList(List<VaultItem> items) {
    if (items.isEmpty) {
      return Padding(
        padding: const EdgeInsets.only(top: 100),
        child: Opacity(
          opacity: 0.5,
          child: Column(
            children: [
              const Icon(Icons.inbox, size: 64),
              const SizedBox(height: 16),
              Text(_query.isEmpty ? "No items in vault" : "No results found"),
            ],
          ),
        ),
      );
    }

    return ListView.builder(
      shrinkWrap: true,
      physics: const NeverScrollableScrollPhysics(),
      itemCount: items.length,
      itemBuilder: (context, index) {
        final item = items[index];
        return TweenAnimationBuilder(
          key: ValueKey(item.id),
          tween: Tween<double>(begin: 0, end: 1),
          duration: Duration(milliseconds: 400 + (index * 100)),
          builder: (context, double val, child) {
            return Opacity(
              opacity: val,
              child: Transform.translate(
                offset: Offset(0, 30 * (1 - val)),
                child: Card(
                  margin: const EdgeInsets.only(bottom: 16),
                  child: ListTile(
                    contentPadding: const EdgeInsets.all(16),
                    leading: Container(
                      padding: const EdgeInsets.all(10),
                      decoration: BoxDecoration(color: Colors.blue.withOpacity(0.1), borderRadius: BorderRadius.circular(12)),
                      child: Icon(_getIcon(item.type), color: Colors.blue),
                    ),
                    title: Text(item.title, style: const TextStyle(fontWeight: FontWeight.bold)),
                    subtitle: Text(item.username, style: const TextStyle(color: Colors.grey)),
                    trailing: const Icon(Icons.chevron_right, color: Colors.grey),
                    onTap: () => _openItemDetails(item),
                  ),
                ),
              ),
            );
          },
        );
      },
    );
  }

  IconData _getIcon(String type) {
    switch (type) {
      case 'password': return Icons.password;
      case 'api_key': return Icons.key;
      case 'token': return Icons.generating_tokens;
      default: return Icons.note;
    }
  }

  void _openItemDetails(VaultItem item) {
    showModalBottomSheet(
      context: context,
      backgroundColor: const Color(0xFF16161E),
      shape: const RoundedRectangleBorder(borderRadius: BorderRadius.vertical(top: Radius.circular(30))),
      builder: (context) => Padding(
        padding: const EdgeInsets.all(32),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Text(item.title, style: const TextStyle(fontSize: 22, fontWeight: FontWeight.bold)),
            const SizedBox(height: 24),
            _buildDetailRow("Username", item.username, Icons.person),
            _buildDetailRow("Secret", "••••••••••••", Icons.lock, onCopy: () => _copy(item.secret)),
            const SizedBox(height: 32),
            Row(
              children: [
                Expanded(
                  child: TextButton(
                    onPressed: () { Navigator.pop(context); _openForm(item); },
                    child: const Text("Edit"),
                  ),
                ),
                Expanded(
                  child: TextButton(
                    onPressed: () { Navigator.pop(context); widget.onDelete(item.id); },
                    child: const Text("Delete", style: TextStyle(color: Colors.redAccent)),
                  ),
                ),
              ],
            )
          ],
        ),
      ),
    );
  }

  Widget _buildDetailRow(String label, String value, IconData icon, {VoidCallback? onCopy}) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 16),
      child: Row(
        children: [
          Icon(icon, size: 20, color: Colors.blue),
          const SizedBox(width: 16),
          Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(label, style: const TextStyle(color: Colors.grey, fontSize: 12)),
              Text(value, style: const TextStyle(fontWeight: FontWeight.w500)),
            ],
          ),
          const Spacer(),
          if (onCopy != null) IconButton(onPressed: onCopy, icon: const Icon(Icons.copy, size: 18, color: Colors.grey)),
        ],
      ),
    );
  }

  void _copy(String text) {
    Clipboard.setData(ClipboardData(text: text));
    ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text("Copied to clipboard")));
  }

  void _openForm(VaultItem? existing) {
    final titleCtrl = TextEditingController(text: existing?.title);
    final userCtrl = TextEditingController(text: existing?.username);
    final secretCtrl = TextEditingController(text: existing?.secret);
    String type = existing?.type ?? 'password';

    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      backgroundColor: const Color(0xFF0A0A0C),
      shape: const RoundedRectangleBorder(borderRadius: BorderRadius.vertical(top: Radius.circular(30))),
      builder: (context) => Padding(
        padding: EdgeInsets.only(bottom: MediaQuery.of(context).viewInsets.bottom, left: 32, right: 32, top: 32),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            const Text("Credential Details", style: TextStyle(fontSize: 20, fontWeight: FontWeight.bold)),
            const SizedBox(height: 24),
            DropdownButtonFormField<String>(
              value: type,
              decoration: const InputDecoration(labelText: "Type"),
              items: ['password', 'api_key', 'token'].map((e) => DropdownMenuItem(value: e, child: Text(e.toUpperCase()))).toList(),
              onChanged: (v) => type = v!,
            ),
            TextField(controller: titleCtrl, decoration: const InputDecoration(labelText: "Title")),
            TextField(controller: userCtrl, decoration: const InputDecoration(labelText: "Username")),
            TextField(controller: secretCtrl, decoration: const InputDecoration(labelText: "Secret / Password"), obscureText: true),
            const SizedBox(height: 40),
            SizedBox(
              width: double.infinity,
              child: ElevatedButton(
                onPressed: () {
                  final item = VaultItem(
                    id: existing?.id ?? const Uuid().v4(),
                    type: type,
                    title: titleCtrl.text,
                    username: userCtrl.text,
                    secret: secretCtrl.text,
                    notes: '',
                    createdAt: existing?.createdAt ?? DateTime.now().toIso8601String(),
                  );
                  widget.onUpdate(item);
                  Navigator.pop(context);
                },
                child: const Text("Save Item"),
              ),
            ),
            const SizedBox(height: 32),
          ],
        ),
      ),
    );
  }
}
