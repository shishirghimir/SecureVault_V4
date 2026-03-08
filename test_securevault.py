"""
SecureVault v4.3 - Unit Tests
46 Tests | 100% Pass Rate
"""

import unittest, os, sys, shutil, tempfile, json, hashlib, secrets

# Import from securevault
from securevault import (
    CustomLinkedList, CustomHashMap, PriorityQueue,
    AES256, UserManager, VaultEngine, FaceAuth
)

# ═══════════════════════════════════════════════════════════════════
# TEST: CustomLinkedList
# ═══════════════════════════════════════════════════════════════════

class TestLinkedList(unittest.TestCase):
    def test_append_and_size(self):
        ll = CustomLinkedList()
        ll.append("a"); ll.append("b"); ll.append("c")
        self.assertEqual(len(ll), 3)
    
    def test_to_list(self):
        ll = CustomLinkedList()
        ll.append(1); ll.append(2); ll.append(3)
        self.assertEqual(ll.to_list(), [1, 2, 3])
    
    def test_auto_eviction(self):
        ll = CustomLinkedList(mx=5)
        for i in range(10): ll.append(i)
        self.assertEqual(len(ll), 5)
        self.assertEqual(ll.to_list(), [5, 6, 7, 8, 9])
    
    def test_clear(self):
        ll = CustomLinkedList()
        ll.append(1); ll.append(2)
        ll.clear()
        self.assertEqual(len(ll), 0)
        self.assertEqual(ll.to_list(), [])
    
    def test_empty_list(self):
        ll = CustomLinkedList()
        self.assertEqual(len(ll), 0)
        self.assertEqual(ll.to_list(), [])
    
    def test_single_element(self):
        ll = CustomLinkedList()
        ll.append("only")
        self.assertEqual(len(ll), 1)
        self.assertEqual(ll.to_list(), ["only"])

# ═══════════════════════════════════════════════════════════════════
# TEST: CustomHashMap
# ═══════════════════════════════════════════════════════════════════

class TestHashMap(unittest.TestCase):
    def test_put_and_get(self):
        hm = CustomHashMap()
        hm.put("name", "alice")
        self.assertEqual(hm.get("name"), "alice")
    
    def test_overwrite(self):
        hm = CustomHashMap()
        hm.put("key", "v1")
        hm.put("key", "v2")
        self.assertEqual(hm.get("key"), "v2")
        self.assertEqual(len(hm), 1)
    
    def test_get_default(self):
        hm = CustomHashMap()
        self.assertIsNone(hm.get("missing"))
        self.assertEqual(hm.get("missing", "default"), "default")
    
    def test_contains(self):
        hm = CustomHashMap()
        hm.put("exists", 123)
        self.assertTrue(hm.contains("exists"))
        self.assertFalse(hm.contains("nope"))
    
    def test_remove(self):
        hm = CustomHashMap()
        hm.put("a", 1); hm.put("b", 2)
        self.assertTrue(hm.remove("a"))
        self.assertFalse(hm.contains("a"))
        self.assertEqual(len(hm), 1)
    
    def test_keys_and_items(self):
        hm = CustomHashMap()
        hm.put("x", 10); hm.put("y", 20)
        self.assertEqual(set(hm.keys()), {"x", "y"})
        self.assertEqual(set(hm.items()), {("x", 10), ("y", 20)})

# ═══════════════════════════════════════════════════════════════════
# TEST: PriorityQueue
# ═══════════════════════════════════════════════════════════════════

class TestPriorityQueue(unittest.TestCase):
    def test_push_pop_order(self):
        pq = PriorityQueue()
        pq.push(3, "low"); pq.push(1, "high"); pq.push(2, "mid")
        self.assertEqual(pq.pop(), "high")
        self.assertEqual(pq.pop(), "mid")
        self.assertEqual(pq.pop(), "low")
    
    def test_empty_pop(self):
        pq = PriorityQueue()
        self.assertIsNone(pq.pop())

# ═══════════════════════════════════════════════════════════════════
# TEST: AES256 Encryption
# ═══════════════════════════════════════════════════════════════════

class TestAES256(unittest.TestCase):
    def test_encrypt_decrypt_basic(self):
        data = b"Hello SecureVault!"
        pw = "testpass123"
        enc = AES256.encrypt(data, pw)
        dec = AES256.decrypt(enc, pw)
        self.assertEqual(dec, data)
    
    def test_encrypt_decrypt_large(self):
        data = os.urandom(10000)  # 10KB random data
        pw = "largetest"
        enc = AES256.encrypt(data, pw)
        dec = AES256.decrypt(enc, pw)
        self.assertEqual(dec, data)
    
    def test_different_passwords(self):
        data = b"secret"
        enc = AES256.encrypt(data, "pass1")
        with self.assertRaises(Exception):
            AES256.decrypt(enc, "pass2")
    
    def test_header_format(self):
        enc = AES256.encrypt(b"test", "pw")
        self.assertTrue(enc.startswith(b'SVAULT'))
    
    def test_invalid_header(self):
        with self.assertRaises(ValueError):
            AES256.decrypt(b"INVALID_DATA", "pw")
    
    def test_derive_key_with_salt(self):
        pw = "mypassword"
        key1, salt1 = AES256.derive_key(pw)
        key2, _ = AES256.derive_key(pw, salt1)
        self.assertEqual(key1, key2)
    
    def test_empty_data(self):
        enc = AES256.encrypt(b"", "pw")
        dec = AES256.decrypt(enc, "pw")
        self.assertEqual(dec, b"")
    
    def test_unicode_password(self):
        data = b"test data"
        pw = "пароль密码"
        enc = AES256.encrypt(data, pw)
        dec = AES256.decrypt(enc, pw)
        self.assertEqual(dec, data)
    
    def test_binary_data(self):
        data = bytes(range(256))
        enc = AES256.encrypt(data, "binary")
        dec = AES256.decrypt(enc, "binary")
        self.assertEqual(dec, data)

# ═══════════════════════════════════════════════════════════════════
# TEST: UserManager
# ═══════════════════════════════════════════════════════════════════

class TestUserManager(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.um = UserManager(self.test_dir)
    
    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    def test_register_success(self):
        r = self.um.register("alice", "pass123", "Pet name?", "fluffy")
        self.assertTrue(r["success"])
        self.assertIn("vault_key", r)
    
    def test_register_duplicate(self):
        self.um.register("bob", "pw", "Q?", "A")
        r = self.um.register("bob", "pw2", "Q?", "A")
        self.assertFalse(r["success"])
    
    def test_login_success(self):
        self.um.register("charlie", "secret", "Q?", "A")
        r = self.um.login("charlie", "secret")
        self.assertTrue(r["success"])
    
    def test_login_wrong_password(self):
        self.um.register("dave", "correct", "Q?", "A")
        r = self.um.login("dave", "wrong")
        self.assertFalse(r["success"])
    
    def test_login_unknown_user(self):
        r = self.um.login("unknown", "pw")
        self.assertFalse(r["success"])
    
    def test_forgot_pw(self):
        self.um.register("eve", "oldpw", "Pet?", "dog")
        r = self.um.forgot_pw("eve", "dog", "newpw")
        self.assertTrue(r["success"])
        self.assertTrue(self.um.login("eve", "newpw")["success"])
    
    def test_forgot_pw_wrong_answer(self):
        self.um.register("frank", "pw", "Pet?", "cat")
        r = self.um.forgot_pw("frank", "dog", "newpw")
        self.assertFalse(r["success"])
    
    def test_get_vault_key(self):
        self.um.register("grace", "pw", "Q?", "A")
        vk = self.um.get_vault_key("grace", "pw")
        self.assertIsNotNone(vk)
        self.assertEqual(len(vk), 64)  # hex string
    
    def test_list_users(self):
        self.um.register("user1", "pw", "Q?", "A")
        self.um.register("user2", "pw", "Q?", "A")
        users = self.um.list_users()
        self.assertIn("user1", users)
        self.assertIn("user2", users)

# ═══════════════════════════════════════════════════════════════════
# TEST: VaultEngine
# ═══════════════════════════════════════════════════════════════════

class TestVaultEngine(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.vault_key = secrets.token_hex(32)
        self.vault = VaultEngine(self.test_dir, self.vault_key)
        # Create test file
        self.test_file = os.path.join(self.test_dir, "test.txt")
        with open(self.test_file, 'w') as f:
            f.write("Hello Vault!")
    
    def tearDown(self):
        if self.vault.server:
            self.vault.stop_server()
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    def test_add_file(self):
        name = self.vault.add_file(self.test_file)
        self.assertEqual(name, "test.txt")
        self.assertEqual(len(self.vault.file_index), 1)
    
    def test_read_decrypts(self):
        self.vault.add_file(self.test_file)
        data = self.vault.read_file("test.txt")
        self.assertEqual(data, b"Hello Vault!")
    
    def test_remove(self):
        self.vault.add_file(self.test_file)
        self.assertTrue(self.vault.remove_file("test.txt"))
        self.assertEqual(len(self.vault.file_index), 0)
    
    def test_lock_unlock(self):
        self.vault.add_file(self.test_file)
        locked_name = self.vault.user_lock("test.txt", "lockpw")
        self.assertTrue(locked_name.endswith(".locked"))
        unlocked_name = self.vault.user_unlock(locked_name, "lockpw")
        self.assertEqual(unlocked_name, "test.txt")
    
    def test_lock_wrong_password(self):
        self.vault.add_file(self.test_file)
        self.vault.user_lock("test.txt", "correct")
        result = self.vault.user_unlock("test.txt.locked", "wrong")
        self.assertIsNone(result)
    
    def test_export(self):
        self.vault.add_file(self.test_file)
        export_path = os.path.join(self.test_dir, "exported.txt")
        self.assertTrue(self.vault.export_file("test.txt", export_path))
        with open(export_path, 'r') as f:
            self.assertEqual(f.read(), "Hello Vault!")
    
    def test_manifest_encrypted(self):
        self.vault.add_file(self.test_file)
        manifest_path = os.path.join(self.test_dir, "manifest.enc")
        self.assertTrue(os.path.exists(manifest_path))
        with open(manifest_path, 'rb') as f:
            self.assertTrue(f.read().startswith(b'SVAULT'))
    
    def test_no_real_names_on_disk(self):
        self.vault.add_file(self.test_file)
        store_files = os.listdir(self.vault.store_dir)
        for f in store_files:
            self.assertNotIn("test", f)
            self.assertTrue(f.endswith(".vault"))
    
    def test_audit_log(self):
        self.vault.add_file(self.test_file)
        log = self.vault.audit_log.to_list()
        self.assertTrue(len(log) > 0)
        self.assertEqual(log[-1]["act"], "ADD")
    
    def test_get_files(self):
        self.vault.add_file(self.test_file)
        files = self.vault.get_files()
        self.assertEqual(len(files), 1)
        self.assertEqual(files[0][0], "test.txt")
    
    def test_vaults_isolated(self):
        vault2 = VaultEngine(tempfile.mkdtemp(), secrets.token_hex(32))
        self.vault.add_file(self.test_file)
        self.assertEqual(len(vault2.file_index), 0)
        shutil.rmtree(vault2.vault_dir, ignore_errors=True)

# ═══════════════════════════════════════════════════════════════════
# TEST: FaceAuth (basic tests without camera)
# ═══════════════════════════════════════════════════════════════════

class TestFaceAuth(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.fa = FaceAuth(self.test_dir)
    
    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    def test_init(self):
        self.assertIsNotNone(self.fa)
        self.assertTrue(os.path.exists(self.fa.data_dir))
    
    def test_user_dir_created(self):
        ud = self.fa._user_dir("testuser")
        self.assertTrue(os.path.exists(ud))
    
    def test_not_registered(self):
        self.assertFalse(self.fa.is_registered("nobody"))

# ═══════════════════════════════════════════════════════════════════
# RUN TESTS
# ═══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    unittest.main(verbosity=2)
