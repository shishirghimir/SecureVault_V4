"""SecureVault v4 Tests — Netanix Labs"""
import unittest, os, sys, json, tempfile, shutil, time, hashlib, secrets
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from securevault import (CustomLinkedList, CustomHashMap, PriorityQueue,
                          AES256, FaceAuth, UserManager, VaultEngine)
try:
    import cv2, numpy as np; _CV2 = True
except: _CV2 = False

TD = os.path.join(tempfile.gettempdir(), "sv4_test")
def setUpModule(): os.makedirs(TD, exist_ok=True)
def tearDownModule(): shutil.rmtree(TD, ignore_errors=True)

class TestLinkedList(unittest.TestCase):
    def test_append(self):
        ll = CustomLinkedList(); [ll.append(i) for i in range(5)]; self.assertEqual(len(ll), 5)
    def test_eviction(self):
        ll = CustomLinkedList(3); [ll.append(i) for i in range(6)]; self.assertEqual(len(ll), 3)
    def test_to_list(self):
        ll = CustomLinkedList(); [ll.append(i) for i in range(3)]; self.assertEqual(ll.to_list(), [0,1,2])
    def test_get_latest(self):
        ll = CustomLinkedList(); [ll.append(i) for i in range(10)]; self.assertEqual(ll.get_latest(2), [9,8])
    def test_clear(self):
        ll = CustomLinkedList(); ll.append(1); ll.clear(); self.assertEqual(len(ll), 0)
    def test_iter(self):
        ll = CustomLinkedList(); [ll.append(i) for i in range(3)]; self.assertEqual(list(ll), [0,1,2])

class TestHashMap(unittest.TestCase):
    def test_put_get(self): hm = CustomHashMap(); hm.put("a",1); self.assertEqual(hm.get("a"), 1)
    def test_missing(self): self.assertIsNone(CustomHashMap().get("x"))
    def test_remove(self): hm = CustomHashMap(); hm.put("a",1); hm.remove("a"); self.assertFalse(hm.contains("a"))
    def test_resize(self):
        hm = CustomHashMap(4)
        for i in range(20): hm.put(f"k{i}", i)
        for i in range(20): self.assertEqual(hm.get(f"k{i}"), i)
    def test_items(self): hm = CustomHashMap(); hm.put("a",1); hm.put("b",2); self.assertEqual(len(hm.items()), 2)
    def test_update(self): hm = CustomHashMap(); hm.put("a",1); hm.put("a",2); self.assertEqual(hm.get("a"), 2)

class TestPQ(unittest.TestCase):
    def test_order(self):
        pq = PriorityQueue(); pq.push(3,"c"); pq.push(1,"a"); pq.push(2,"b")
        self.assertEqual(pq.pop(), "a")
    def test_empty(self): self.assertIsNone(PriorityQueue().pop())

class TestAES256(unittest.TestCase):
    def test_short(self):
        self.assertEqual(b"Hi!", AES256.decrypt(AES256.encrypt(b"Hi!","pw"),"pw"))
    def test_block(self):
        d = b"0123456789abcdef"; self.assertEqual(d, AES256.decrypt(AES256.encrypt(d,"k"),"k"))
    def test_long(self):
        d = b"X"*1000; self.assertEqual(d, AES256.decrypt(AES256.encrypt(d,"p"),"p"))
    def test_binary(self):
        d = bytes(range(256)); self.assertEqual(d, AES256.decrypt(AES256.encrypt(d,"b"),"b"))
    def test_wrong_pw(self):
        self.assertNotEqual(b"s", AES256.decrypt(AES256.encrypt(b"s","r"),"w"))
    def test_unique_ct(self):
        self.assertNotEqual(AES256.encrypt(b"s","p"), AES256.encrypt(b"s","p"))
    def test_empty(self):
        self.assertEqual(b"", AES256.decrypt(AES256.encrypt(b"","p"),"p"))
    def test_header(self):
        self.assertTrue(AES256.encrypt(b"t","p").startswith(b"SVAULT"))
    def test_bad_header(self):
        with self.assertRaises(ValueError): AES256.decrypt(b"BAD"+b"\0"*50,"p")

class TestUserManager(unittest.TestCase):
    def setUp(self): self.d = os.path.join(TD, f"um_{time.time_ns()}"); self.um = UserManager(self.d)
    def tearDown(self): shutil.rmtree(self.d, ignore_errors=True)
    def test_register(self):
        self.assertTrue(self.um.register("a","p","q","a")["success"])
    def test_dup(self):
        self.um.register("b","p","q","a"); self.assertFalse(self.um.register("b","p","q","a")["success"])
    def test_login_ok(self):
        self.um.register("c","pw","q","a"); self.assertTrue(self.um.login("c","pw")["success"])
    def test_login_bad(self):
        self.um.register("d","pw","q","a"); self.assertFalse(self.um.login("d","x")["success"])
    def test_forgot(self):
        self.um.register("e","old","pet?","dog")
        self.assertTrue(self.um.forgot_password("e","dog","new")["success"])
        self.assertTrue(self.um.login("e","new")["success"])
    def test_vault_key(self):
        r = self.um.register("f","pw","q","a"); k = self.um.get_vault_key("f","pw")
        self.assertEqual(k, self.um.get_vault_key("f","pw"))
    def test_face_key_roundtrip(self):
        r = self.um.register("g","pw","q","a"); vk = r["vault_key"]
        self.um.store_face_key("g", vk)
        self.assertEqual(vk, self.um.get_vault_key_by_face("g"))
    def test_face_key_per_user(self):
        r1 = self.um.register("u1","p","q","a"); r2 = self.um.register("u2","p","q","a")
        self.um.store_face_key("u1", r1["vault_key"]); self.um.store_face_key("u2", r2["vault_key"])
        self.assertNotEqual(self.um.get_vault_key_by_face("u1"), self.um.get_vault_key_by_face("u2"))
    def test_backward_compat(self):
        """Supports old 'password' key format."""
        self.um.users["old"] = {"password": hashlib.sha256(b"t").hexdigest(),
            "sec_q":"q","sec_a":hashlib.sha256(b"a").hexdigest(),
            "vault_salt":secrets.token_hex(16),"created":"","face_key_secret":None}
        self.assertTrue(self.um.login("old","t")["success"])

class TestVaultEngine(unittest.TestCase):
    def setUp(self): self.d = os.path.join(TD, f"ve_{time.time_ns()}"); self.v = VaultEngine(self.d, "key123")
    def tearDown(self):
        if self.v.server: self.v.stop_server()
        shutil.rmtree(self.d, ignore_errors=True)
    def _tf(self, txt="test data"):
        f = tempfile.NamedTemporaryFile(delete=False, suffix=".txt", mode='w'); f.write(txt); f.close(); return f.name
    def test_add(self):
        s = self._tf(); self.assertTrue(self.v.file_index.contains(self.v.add_file(s))); os.unlink(s)
    def test_encrypted_on_disk(self):
        s = self._tf("TOPSECRET_XYZ"); self.v.add_file(s)
        for f in os.listdir(self.v.store_dir):
            with open(os.path.join(self.v.store_dir, f), 'rb') as fh:
                self.assertNotIn(b"TOPSECRET", fh.read())
        os.unlink(s)
    def test_manifest_encrypted(self):
        s = self._tf(); self.v.add_file(s)
        with open(os.path.join(self.d, "manifest.enc"), 'rb') as f:
            self.assertTrue(f.read().startswith(b"SVAULT"))
        os.unlink(s)
    def test_no_real_names_on_disk(self):
        s = self._tf(); self.v.add_file(s)
        self.assertTrue(all(f.endswith(".vault") for f in os.listdir(self.v.store_dir)))
        os.unlink(s)
    def test_read_decrypts(self):
        s = self._tf("hello123"); n = self.v.add_file(s)
        self.assertEqual(self.v.read_file(n), b"hello123"); os.unlink(s)
    def test_remove(self):
        s = self._tf(); n = self.v.add_file(s); self.v.remove_file(n)
        self.assertFalse(self.v.file_index.contains(n)); os.unlink(s)
    def test_lock_unlock(self):
        s = self._tf("lockme"); n = self.v.add_file(s)
        en = self.v.user_lock(n, "pw"); dn = self.v.user_unlock(en, "pw")
        self.assertEqual(self.v.read_file(dn), b"lockme"); os.unlink(s)
    def test_export(self):
        s = self._tf("export"); n = self.v.add_file(s); out = os.path.join(TD, "out.txt")
        self.assertTrue(self.v.export_file(n, out))
        with open(out) as f: self.assertEqual(f.read(), "export")
        os.unlink(s); os.unlink(out)
    def test_vaults_isolated(self):
        d2 = os.path.join(TD, f"v2_{time.time_ns()}"); v2 = VaultEngine(d2, "otherkey")
        s = self._tf(); self.v.add_file(s); self.assertEqual(len(v2.file_index), 0)
        shutil.rmtree(d2, ignore_errors=True); os.unlink(s)
    def test_audit(self):
        s = self._tf(); self.v.add_file(s); self.assertGreater(len(self.v.audit_log), 0); os.unlink(s)

class TestFaceAuth(unittest.TestCase):
    def setUp(self): self.d = os.path.join(TD, f"fa_{time.time_ns()}"); self.fa = FaceAuth(self.d)
    def tearDown(self): shutil.rmtree(self.d, ignore_errors=True)
    def test_not_registered(self): self.assertFalse(self.fa.is_registered("nobody"))
    def test_reset(self):
        ud = self.fa._user_dir("t")
        if _CV2: np.save(os.path.join(ud, "face_samples.npy"), np.zeros((1,200,200), dtype=np.uint8))
        open(os.path.join(ud, "face_model.yml"), 'w').close()
        self.assertTrue(self.fa.is_registered("t"))
        self.fa.reset("t"); self.assertFalse(self.fa.is_registered("t"))
    def test_signature_consistency(self):
        """Same face image should produce similar signatures."""
        if not _CV2: return
        img = np.random.randint(50, 200, (200,200), dtype=np.uint8)
        s1 = self.fa._compute_sig(img); s2 = self.fa._compute_sig(img)
        score = self.fa._compare_sigs(s1, s2)
        self.assertGreater(score, 0.95)
    def test_different_faces_lower_score(self):
        """Different images should produce lower similarity."""
        if not _CV2: return
        img1 = np.random.randint(0, 100, (200,200), dtype=np.uint8)
        img2 = np.random.randint(150, 255, (200,200), dtype=np.uint8)
        s1 = self.fa._compute_sig(img1); s2 = self.fa._compute_sig(img2)
        score = self.fa._compare_sigs(s1, s2)
        self.assertLess(score, 0.5)

if __name__ == "__main__": unittest.main(verbosity=2)
