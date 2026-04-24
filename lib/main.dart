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
        primarySwatch: Colors.blue,
        scaffoldBackgroundColor: const Color(0xFF0A0A0C),
        cardTheme: CardTheme(
          color: const Color(0xFF16161E),
          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(24)),
          elevation: 0,
        ),
        fontFamily: 'sans-serif',
      ),
      home: const MainGate(),
    );
  }
}

// --- CORE CRYPTO ENGINE ---
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
      throw Exception("Password salah atau data korup.");
    }
  }
}

// --- MODELS ---
class VaultItem {
  final String id;
  String type;
  String title;
  String username;
  String secret;
  String notes;
  String createdAt;

  VaultItem({
    required this.id,
    required this.type,
    required this.title,
    required this.username,
    required this.secret,
    required this.notes,
    required this.createdAt,
  });

  Map<String, dynamic> toJson() => {
    'id': id, 'type': type, 'title': title, 'username': username, 'secret': secret, 'notes': notes, 'created_at': createdAt
  };

  factory VaultItem.fromJson(Map<String, dynamic> json) => VaultItem(
    id: json['id'], type: json['type'], title: json['title'], username: json['username'], secret: json['secret'], notes: json['notes'], createdAt: json['created_at']
  );
}

// --- UI SCREENS ---
class MainGate extends StatefulWidget {
  const MainGate({super.key});

  @override
  State<MainGate> createState() => _MainGateState();
}

class _MainGateState extends State<MainGate> {
  final TextEditingController _passCtrl = TextEditingController();
  bool _isNewUser = true;
  String? _masterPassword;
  List<VaultItem> _items = [];
  Timer? _autoLockTimer;

  @override
  void initState() {
    super.initState();
    _checkStatus();
  }

  void _checkStatus() async {
    final prefs = await SharedPreferences.getInstance();
    setState(() {
      _isNewUser = !prefs.containsKey("encrypted_vault");
    });
  }

  void _startAutoLock() {
    _autoLockTimer?.cancel();
    _autoLockTimer = Timer(const Duration(minutes: 3), () {
      if (mounted) {
        setState(() {
          _masterPassword = null;
          _items = [];
        });
      }
    });
  }

  Future<void> _unlock() async {
    try {
      if (_isNewUser) {
        _masterPassword = _passCtrl.text;
        await _saveData();
        setState(() { _isNewUser = false; });
      } else {
        final decrypted = await CryptoService.loadVault(_passCtrl.text);
        if (decrypted != null) {
          final data = json.decode(decrypted);
          _items = (data['items'] as List).map((i) => VaultItem.fromJson(i)).toList();
          _masterPassword = _passCtrl.text;
        }
      }
      _passCtrl.clear();
      _startAutoLock();
      setState(() {});
    } catch (e) {
      ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text("Akses Ditolak: Password Salah")));
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
    if (_masterPassword == null) {
      return Scaffold(
        body: Center(
          child: Padding(
            padding: const EdgeInsets.all(32.0),
            child: Column(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                Container(
                  padding: const EdgeInsets.all(20),
                  decoration: BoxDecoration(color: Colors.blue, borderRadius: BorderRadius.circular(20)),
                  child: const Icon(Icons.lock_person, size: 40, color: Colors.white),
                ),
                const SizedBox(height: 24),
                Text(_isNewUser ? "Setup Vault" : "Welcome Back", style: const TextStyle(fontSize: 24, fontWeight: FontWeight.bold)),
                const SizedBox(height: 8),
                Text(_isNewUser ? "Tentukan master password Anda." : "Masukkan password untuk dekripsi data.", textAlign: TextAlign.center, style: TextStyle(color: Colors.grey[500])),
                const SizedBox(height: 32),
                TextField(
                  controller: _passCtrl,
                  obscureText: true,
                  textAlign: TextAlign.center,
                  decoration: InputDecoration(
                    hintText: "Master Password",
                    filled: true,
                    fillColor: Colors.white.withOpacity(0.05),
                    border: OutlineInputBorder(borderRadius: BorderRadius.circular(16), borderSide: BorderSide.none),
                  ),
                ),
                const SizedBox(height: 16),
                SizedBox(
                  width: double.infinity,
                  child: ElevatedButton(
                    onPressed: _unlock,
                    style: ElevatedButton.styleFrom(backgroundColor: Colors.blue, padding: const EdgeInsets.symmetric(vertical: 16), shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16))),
                    child: Text(_isNewUser ? "Buat Brankas" : "Buka Brankas"),
                  ),
                )
              ],
            ),
          ),
        ),
      );
    }

    return Dashboard(
      items: _items, 
      onLock: () => setState(() => _masterPassword = null),
      onUpdate: (newItem) async {
        setState(() {
          final idx = _items.indexWhere((element) => element.id == newItem.id);
          if (idx != -1) _items[idx] = newItem; else _items.add(newItem);
        });
        await _saveData();
      },
      onDelete: (id) async {
        setState(() => _items.removeWhere((element) => element.id == id));
        await _saveData();
      },
    );
  }
}

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
    final filtered = widget.items.where((i) {
      final matchType = _filter == 'all' || i.type == _filter;
      final matchQuery = i.title.toLowerCase().contains(_query.toLowerCase()) || i.username.toLowerCase().contains(_query.toLowerCase());
      return matchType && matchQuery;
    }).toList();

    return Scaffold(
      appBar: AppBar(
        backgroundColor: Colors.transparent,
        elevation: 0,
        title: const Text("VaultKrypt", style: TextStyle(fontWeight: FontWeight.bold)),
        actions: [
          IconButton(onPressed: widget.onLock, icon: const Icon(Icons.logout_rounded, color: Colors.redAccent))
        ],
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            TextField(
              onChanged: (v) => setState(() => _query = v),
              decoration: InputDecoration(
                hintText: "Cari kredensial...",
                prefixIcon: const Icon(Icons.search),
                filled: true,
                fillColor: const Color(0xFF16161E),
                border: OutlineInputBorder(borderRadius: BorderRadius.circular(16), borderSide: BorderSide.none),
              ),
            ),
            const SizedBox(height: 20),
            Row(
              children: [
                Expanded(
                  child: _buildBentoCard("Total Items", widget.items.length.toString(), Icons.inventory_2, Colors.blue),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: _buildBentoCard("Status", "Offline", Icons.cloud_off, Colors.green),
                ),
              ],
            ),
            const SizedBox(height: 20),
            SizedBox(
              height: 40,
              child: ListView(
                scrollDirection: Axis.horizontal,
                children: ['all', 'password', 'api_key', 'token', 'note'].map((type) {
                  return Padding(
                    padding: const EdgeInsets.only(right: 8.0),
                    child: FilterChip(
                      selected: _filter == type,
                      label: Text(type.toUpperCase()),
                      onSelected: (s) => setState(() => _filter = type),
                    ),
                  );
                }).toList(),
              ),
            ),
            const SizedBox(height: 20),
            ListView.builder(
              shrinkWrap: true,
              physics: const NeverScrollableScrollPhysics(),
              itemCount: filtered.length,
              itemBuilder: (context, index) {
                final item = filtered[index];
                return Card(
                  margin: const EdgeInsets.only(bottom: 12),
                  child: ListTile(
                    contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
                    leading: CircleAvatar(
                      backgroundColor: Colors.blue.withOpacity(0.1),
                      child: Icon(_getIcon(item.type), color: Colors.blue, size: 20),
                    ),
                    title: Text(item.title, style: const TextStyle(fontWeight: FontWeight.bold)),
                    subtitle: Text(item.username),
                    trailing: PopupMenuButton(
                      itemBuilder: (context) => [
                        const PopupMenuItem(value: 'copy', child: Text("Salin Rahasia")),
                        const PopupMenuItem(value: 'edit', child: Text("Edit")),
                        const PopupMenuItem(value: 'delete', child: Text("Hapus", style: TextStyle(color: Colors.red))),
                      ],
                      onSelected: (v) {
                        if (v == 'copy') {
                          Clipboard.setData(ClipboardData(text: item.secret));
                          ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text("Disalin!")));
                        } else if (v == 'edit') {
                          _showForm(item);
                        } else if (v == 'delete') {
                          widget.onDelete(item.id);
                        }
                      },
                    ),
                  ),
                );
              },
            ),
          ],
        ),
      ),
      floatingActionButton: FloatingActionButton(
        onPressed: () => _showForm(null),
        backgroundColor: Colors.blue,
        child: const Icon(Icons.add),
      ),
    );
  }

  Widget _buildBentoCard(String label, String value, IconData icon, Color color) {
    return Container(
      padding: const EdgeInsets.all(20),
      decoration: BoxDecoration(
        color: const Color(0xFF16161E), 
        borderRadius: BorderRadius.circular(24), 
        border: Border.all(color: Colors.white.withOpacity(0.05))
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Icon(icon, color: color, size: 24),
          const SizedBox(height: 12),
          Text(value, style: const TextStyle(fontSize: 24, fontWeight: FontWeight.bold)),
          Text(label, style: const TextStyle(color: Colors.grey, fontSize: 12)),
        ],
      ),
    );
  }

  IconData _getIcon(String type) {
    switch (type) {
      case 'password': return Icons.password;
      case 'api_key': return Icons.vpn_key;
      case 'token': return Icons.token;
      default: return Icons.notes;
    }
  }

  void _showForm(VaultItem? existing) {
    final titleCtrl = TextEditingController(text: existing?.title);
    final userCtrl = TextEditingController(text: existing?.username);
    final secretCtrl = TextEditingController(text: existing?.secret);
    final notesCtrl = TextEditingController(text: existing?.notes);
    String type = existing?.type ?? 'password';

    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      backgroundColor: const Color(0xFF0A0A0C),
      shape: const RoundedRectangleBorder(borderRadius: BorderRadius.vertical(top: Radius.circular(32))),
      builder: (context) => Padding(
        padding: EdgeInsets.only(bottom: MediaQuery.of(context).viewInsets.bottom, left: 24, right: 24, top: 24),
        child: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(existing == null ? "Tambah Baru" : "Edit Kredensial", style: const TextStyle(fontSize: 20, fontWeight: FontWeight.bold)),
              const SizedBox(height: 24),
              DropdownButtonFormField<String>(
                value: type,
                items: ['password', 'api_key', 'token', 'note'].map((e) => DropdownMenuItem(value: e, child: Text(e.toUpperCase()))).toList(),
                onChanged: (v) => type = v!,
                decoration: const InputDecoration(labelText: "Tipe"),
              ),
              TextField(controller: titleCtrl, decoration: const InputDecoration(labelText: "Judul")),
              TextField(controller: userCtrl, decoration: const InputDecoration(labelText: "Username / ID")),
              TextField(controller: secretCtrl, decoration: const InputDecoration(labelText: "Rahasia / Password"), obscureText: true),
              TextField(controller: notesCtrl, decoration: const InputDecoration(labelText: "Catatan"), maxLines: 2),
              const SizedBox(height: 32),
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
                      notes: notesCtrl.text,
                      createdAt: existing?.createdAt ?? DateTime.now().toIso8601String(),
                    );
                    widget.onUpdate(item);
                    Navigator.pop(context);
                  },
                  child: const Text("Simpan Data"),
                ),
              ),
              const SizedBox(height: 24),
            ],
          ),
        ),
      ),
    );
  }
}
