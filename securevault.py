"""
╔══════════════════════════════════════════════════════════════════╗
║              S E C U R E V A U L T   v4.3                        ║
║     Face-Authenticated Encrypted File Vault                      ║
║  STRICT eye-open detection | Fast camera | AES-256 encryption    ║
║  EXE-Compatible with embedded cascades                           ║
║  v4.3 by Netanix Labs                                            ║
╚══════════════════════════════════════════════════════════════════╝
"""

import os, sys, json, hashlib, time, shutil, secrets, base64, threading, functools
from datetime import datetime
from http.server import HTTPServer, SimpleHTTPRequestHandler

# ═══════════════════════════════════════════════════════════════════
# EXE COMPATIBILITY - GET CORRECT PATHS
# ═══════════════════════════════════════════════════════════════════

def get_base_path():
    """Get base path for both script and frozen EXE."""
    if getattr(sys, 'frozen', False):
        return sys._MEIPASS
    return os.path.dirname(os.path.abspath(__file__))

def get_cascade_path():
    """Get Haar cascade path - works for both script and EXE."""
    if getattr(sys, 'frozen', False):
        # In EXE: cascades are bundled in _MEIPASS
        return os.path.join(sys._MEIPASS, 'cv2', 'data')
    else:
        # In script: use cv2.data.haarcascades
        try:
            import cv2
            return cv2.data.haarcascades
        except:
            return ""

BASE_PATH = get_base_path()

CV2_OK = LBPH_OK = False
try:
    import numpy as np
    import cv2
    CV2_OK = True
    try: _t = cv2.face.LBPHFaceRecognizer_create(); del _t; LBPH_OK = True
    except: pass
except: pass

try: from PIL import Image, ImageTk; PIL_OK = True
except: PIL_OK = False

try:
    import tkinter as tk
    from tkinter import ttk, messagebox, filedialog, scrolledtext
    TK_OK = True
except: TK_OK = False

# ═══════════════════════════════════════════════════════════════════
# CUSTOM DATA STRUCTURES
# ═══════════════════════════════════════════════════════════════════

class Node:
    __slots__ = ('data', 'next', 'prev')
    def __init__(self, d=None): self.data, self.next, self.prev = d, None, None

class CustomLinkedList:
    def __init__(self, mx=5000): self.head = self.tail = None; self.size, self.max_size = 0, mx
    def append(self, d):
        n = Node(d)
        if not self.head: self.head = self.tail = n
        else: n.prev, self.tail.next, self.tail = self.tail, n, n
        self.size += 1
        while self.size > self.max_size: self.head = self.head.next; self.head.prev = None; self.size -= 1
    def to_list(self):
        r, c = [], self.head
        while c: r.append(c.data); c = c.next
        return r
    def clear(self): self.head = self.tail = None; self.size = 0
    def __len__(self): return self.size

class CustomHashMap:
    def __init__(self, cap=128): self.cap, self.buckets, self.size = cap, [[] for _ in range(cap)], 0
    def _h(self, k):
        h = 2166136261
        for c in str(k): h = ((h ^ ord(c)) * 16777619) & 0xFFFFFFFF
        return h % self.cap
    def put(self, k, v):
        idx = self._h(k)
        for i, (ek, _) in enumerate(self.buckets[idx]):
            if ek == k: self.buckets[idx][i] = (k, v); return
        self.buckets[idx].append((k, v)); self.size += 1
        if self.size / self.cap > 0.75: self._resize()
    def get(self, k, d=None):
        for ek, ev in self.buckets[self._h(k)]:
            if ek == k: return ev
        return d
    def remove(self, k):
        idx = self._h(k)
        for i, (ek, _) in enumerate(self.buckets[idx]):
            if ek == k: del self.buckets[idx][i]; self.size -= 1; return True
        return False
    def contains(self, k): return self.get(k) is not None
    def keys(self): return [k for b in self.buckets for k, _ in b]
    def items(self): return [(k, v) for b in self.buckets for k, v in b]
    def _resize(self):
        old, self.cap = self.buckets, self.cap * 2
        self.buckets, self.size = [[] for _ in range(self.cap)], 0
        for b in old:
            for k, v in b: self.put(k, v)
    def __len__(self): return self.size

class PriorityQueue:
    def __init__(self): self.heap = []
    def push(self, pri, data):
        self.heap.append((pri, time.time(), data)); i = len(self.heap) - 1
        while i > 0:
            p = (i-1)//2
            if self.heap[i] < self.heap[p]: self.heap[i], self.heap[p] = self.heap[p], self.heap[i]; i = p
            else: break
    def pop(self):
        if not self.heap: return None
        if len(self.heap) == 1: return self.heap.pop()[2]
        top, self.heap[0] = self.heap[0], self.heap.pop(); i, n = 0, len(self.heap)
        while True:
            s, l, r = i, 2*i+1, 2*i+2
            if l < n and self.heap[l] < self.heap[s]: s = l
            if r < n and self.heap[r] < self.heap[s]: s = r
            if s != i: self.heap[i], self.heap[s] = self.heap[s], self.heap[i]; i = s
            else: break
        return top[2]
    def __len__(self): return len(self.heap)

# ═══════════════════════════════════════════════════════════════════
# AES-256 ENCRYPTION
# ═══════════════════════════════════════════════════════════════════

class AES256:
    SBOX = [0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
        0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
        0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
        0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
        0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
        0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
        0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
        0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
        0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
        0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
        0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
        0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
        0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
        0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
        0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
        0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16]
    INV_SBOX = [0]*256
    for _i, _v in enumerate(SBOX): INV_SBOX[_v] = _i
    RCON = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36]
    
    @staticmethod
    def _mul(a, b):
        p = 0
        for _ in range(8):
            if b & 1: p ^= a
            hi = a & 0x80; a = (a << 1) & 0xFF
            if hi: a ^= 0x1b
            b >>= 1
        return p
    
    @classmethod
    def _key_exp(cls, key):
        w = [0]*60
        for i in range(8): w[i] = int.from_bytes(key[4*i:4*i+4], 'big')
        for i in range(8, 60):
            t = w[i-1]
            if i % 8 == 0:
                t = ((t<<8)|(t>>24))&0xFFFFFFFF
                t = (cls.SBOX[(t>>24)&0xFF]<<24|cls.SBOX[(t>>16)&0xFF]<<16|cls.SBOX[(t>>8)&0xFF]<<8|cls.SBOX[t&0xFF])
                t ^= cls.RCON[i//8-1]<<24
            elif i % 8 == 4:
                t = (cls.SBOX[(t>>24)&0xFF]<<24|cls.SBOX[(t>>16)&0xFF]<<16|cls.SBOX[(t>>8)&0xFF]<<8|cls.SBOX[t&0xFF])
            w[i] = w[i-8]^t
        return w
    
    @classmethod
    def _enc_blk(cls, blk, rk):
        s = [[blk[r+4*c] for c in range(4)] for r in range(4)]
        for i in range(4):
            k = rk[i]
            for j in range(4): s[j][i] ^= (k>>(24-8*j))&0xFF
        for rnd in range(1,14):
            for i in range(4):
                for j in range(4): s[i][j] = cls.SBOX[s[i][j]]
            s[1], s[2], s[3] = s[1][1:]+s[1][:1], s[2][2:]+s[2][:2], s[3][3:]+s[3][:3]
            for i in range(4):
                a = [s[j][i] for j in range(4)]
                s[0][i] = cls._mul(2,a[0])^cls._mul(3,a[1])^a[2]^a[3]
                s[1][i] = a[0]^cls._mul(2,a[1])^cls._mul(3,a[2])^a[3]
                s[2][i] = a[0]^a[1]^cls._mul(2,a[2])^cls._mul(3,a[3])
                s[3][i] = cls._mul(3,a[0])^a[1]^a[2]^cls._mul(2,a[3])
            for i in range(4):
                k = rk[rnd*4+i]
                for j in range(4): s[j][i] ^= (k>>(24-8*j))&0xFF
        for i in range(4):
            for j in range(4): s[i][j] = cls.SBOX[s[i][j]]
        s[1], s[2], s[3] = s[1][1:]+s[1][:1], s[2][2:]+s[2][:2], s[3][3:]+s[3][:3]
        for i in range(4):
            k = rk[56+i]
            for j in range(4): s[j][i] ^= (k>>(24-8*j))&0xFF
        return bytes(s[r][c] for c in range(4) for r in range(4))
    
    @classmethod
    def _dec_blk(cls, blk, rk):
        s = [[blk[r+4*c] for c in range(4)] for r in range(4)]
        for i in range(4):
            k = rk[56+i]
            for j in range(4): s[j][i] ^= (k>>(24-8*j))&0xFF
        for rnd in range(13,0,-1):
            s[1], s[2], s[3] = s[1][3:]+s[1][:3], s[2][2:]+s[2][:2], s[3][1:]+s[3][:1]
            for i in range(4):
                for j in range(4): s[i][j] = cls.INV_SBOX[s[i][j]]
            for i in range(4):
                k = rk[rnd*4+i]
                for j in range(4): s[j][i] ^= (k>>(24-8*j))&0xFF
            for i in range(4):
                a = [s[j][i] for j in range(4)]
                s[0][i] = cls._mul(14,a[0])^cls._mul(11,a[1])^cls._mul(13,a[2])^cls._mul(9,a[3])
                s[1][i] = cls._mul(9,a[0])^cls._mul(14,a[1])^cls._mul(11,a[2])^cls._mul(13,a[3])
                s[2][i] = cls._mul(13,a[0])^cls._mul(9,a[1])^cls._mul(14,a[2])^cls._mul(11,a[3])
                s[3][i] = cls._mul(11,a[0])^cls._mul(13,a[1])^cls._mul(9,a[2])^cls._mul(14,a[3])
        s[1], s[2], s[3] = s[1][3:]+s[1][:3], s[2][2:]+s[2][:2], s[3][1:]+s[3][:1]
        for i in range(4):
            for j in range(4): s[i][j] = cls.INV_SBOX[s[i][j]]
        for i in range(4):
            k = rk[i]
            for j in range(4): s[j][i] ^= (k>>(24-8*j))&0xFF
        return bytes(s[r][c] for c in range(4) for r in range(4))
    
    @classmethod
    def derive_key(cls, pw, salt=None):
        if salt is None: salt = secrets.token_bytes(16)
        return hashlib.pbkdf2_hmac('sha256', pw.encode(), salt, 100000, dklen=32), salt
    
    @classmethod
    def encrypt(cls, data, pw):
        key, salt = cls.derive_key(pw); iv = secrets.token_bytes(16); rk = cls._key_exp(key)
        pad = 16-(len(data)%16); data += bytes([pad]*pad)
        enc, prev = b'', iv
        for i in range(0, len(data), 16):
            block = bytes(a^b for a,b in zip(data[i:i+16], prev))
            prev = cls._enc_blk(block, rk); enc += prev
        return b'SVAULT' + salt + iv + enc
    
    @classmethod
    def decrypt(cls, data, pw):
        if data[:6] != b'SVAULT': raise ValueError("Invalid file")
        salt, iv, ct = data[6:22], data[22:38], data[38:]
        key, _ = cls.derive_key(pw, salt); rk = cls._key_exp(key)
        dec, prev = b'', iv
        for i in range(0, len(ct), 16):
            block = ct[i:i+16]; plain = cls._dec_blk(block, rk)
            dec += bytes(a^b for a,b in zip(plain, prev)); prev = block
        pad = dec[-1]
        if 1 <= pad <= 16 and all(b == pad for b in dec[-pad:]): dec = dec[:-pad]
        return dec

# ═══════════════════════════════════════════════════════════════════
# FACE AUTH - EXE COMPATIBLE WITH BULLETPROOF CASCADE LOADING
# ═══════════════════════════════════════════════════════════════════

class FaceAuth:
    TRAIN_SAMPLES, LBPH_THRESH, FALLBACK_THRESH = 10, 65, 0.58
    
    def __init__(self, data_dir):
        self.data_dir = data_dir; os.makedirs(data_dir, exist_ok=True)
        self.face_cas = self.eye_cas = self.eye_glass = None
        self._cam_lock = threading.Lock()
        self._cascade_loaded = False
        if CV2_OK: self._load_cascades_bulletproof()
    
    def _load_cascades_bulletproof(self):
        """Bulletproof cascade loading - works in EXE and script."""
        cascade_paths = []
        
        # Method 1: cv2.data.haarcascades (works in script)
        try:
            if hasattr(cv2, 'data') and hasattr(cv2.data, 'haarcascades'):
                cascade_paths.append(cv2.data.haarcascades)
        except: pass
        
        # Method 2: PyInstaller _MEIPASS (works in EXE)
        if getattr(sys, 'frozen', False):
            cascade_paths.append(os.path.join(sys._MEIPASS, 'cv2', 'data'))
            cascade_paths.append(os.path.join(sys._MEIPASS, 'data'))
            cascade_paths.append(sys._MEIPASS)
        
        # Method 3: OpenCV installation paths
        try:
            import cv2
            cv2_path = os.path.dirname(cv2.__file__)
            cascade_paths.append(os.path.join(cv2_path, 'data'))
            cascade_paths.append(cv2_path)
        except: pass
        
        # Method 4: Common system paths
        cascade_paths.extend([
            'C:\\opencv\\data\\haarcascades',
            '/usr/share/opencv4/haarcascades',
            '/usr/local/share/opencv4/haarcascades',
        ])
        
        # Try each path
        face_xml = 'haarcascade_frontalface_alt2.xml'
        eye_xml = 'haarcascade_eye.xml'
        eye_glass_xml = 'haarcascade_eye_tree_eyeglasses.xml'
        
        for path in cascade_paths:
            if not path or not os.path.exists(path):
                continue
            
            face_path = os.path.join(path, face_xml)
            eye_path = os.path.join(path, eye_xml)
            eye_glass_path = os.path.join(path, eye_glass_xml)
            
            if os.path.exists(face_path):
                try:
                    self.face_cas = cv2.CascadeClassifier(face_path)
                    if not self.face_cas.empty():
                        # Face cascade loaded, try eyes
                        if os.path.exists(eye_path):
                            self.eye_cas = cv2.CascadeClassifier(eye_path)
                            if self.eye_cas.empty(): self.eye_cas = None
                        if os.path.exists(eye_glass_path):
                            self.eye_glass = cv2.CascadeClassifier(eye_glass_path)
                            if self.eye_glass.empty(): self.eye_glass = None
                        self._cascade_loaded = True
                        print(f"[OK] Cascades loaded from: {path}")
                        return
                except Exception as e:
                    print(f"[WARN] Failed to load from {path}: {e}")
                    continue
        
        # Method 5: Direct cv2 load (some versions support this)
        try:
            self.face_cas = cv2.CascadeClassifier()
            self.face_cas.load(cv2.data.haarcascades + face_xml)
            if not self.face_cas.empty():
                self.eye_cas = cv2.CascadeClassifier()
                self.eye_cas.load(cv2.data.haarcascades + eye_xml)
                self.eye_glass = cv2.CascadeClassifier()
                self.eye_glass.load(cv2.data.haarcascades + eye_glass_xml)
                self._cascade_loaded = True
                print("[OK] Cascades loaded via cv2.data")
                return
        except: pass
        
        print("[ERROR] Could not load Haar cascades!")
    
    def _user_dir(self, u):
        d = os.path.join(self.data_dir, "users", u); os.makedirs(d, exist_ok=True); return d
    
    def is_registered(self, u):
        ud = self._user_dir(u)
        return os.path.exists(os.path.join(ud, "face_model.yml")) or os.path.exists(os.path.join(ud, "face_samples.npy"))
    
    def _open_cam(self):
        # Try DirectShow first (Windows), then default
        backends = [cv2.CAP_DSHOW, cv2.CAP_ANY] if sys.platform == 'win32' else [cv2.CAP_ANY]
        for backend in backends:
            for idx in [0, 1]:
                try:
                    cap = cv2.VideoCapture(idx, backend)
                    if cap.isOpened():
                        cap.set(cv2.CAP_PROP_FRAME_WIDTH, 640)
                        cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 480)
                        cap.set(cv2.CAP_PROP_FPS, 30)
                        cap.set(cv2.CAP_PROP_BUFFERSIZE, 1)
                        ret, _ = cap.read()  # One read to initialize
                        if ret: return cap
                        cap.release()
                except: continue
        return None
    
    def _close_all_windows(self):
        try: cv2.destroyAllWindows(); cv2.waitKey(1)
        except: pass
    
    def _detect_face(self, gray):
        if not self.face_cas or self.face_cas.empty(): return None
        try:
            faces = self.face_cas.detectMultiScale(gray, 1.15, 5, minSize=(100, 100))
            return max(faces, key=lambda f: f[2]*f[3]) if len(faces) > 0 else None
        except: return None
    
    def _detect_eyes_strict(self, roi):
        if not self.eye_cas or self.eye_cas.empty(): return False, 0, []
        h, w = roi.shape[:2]
        upper = roi[0:int(h*0.55), :]
        
        try:
            eyes = self.eye_cas.detectMultiScale(upper, 1.1, 8, minSize=(20, 20), maxSize=(70, 70))
            if len(eyes) < 2 and self.eye_glass and not self.eye_glass.empty():
                eg = self.eye_glass.detectMultiScale(upper, 1.1, 6, minSize=(20, 20), maxSize=(70, 70))
                if len(eg) >= 2: eyes = eg
        except: return False, 0, []
        
        if len(eyes) < 2: return False, len(eyes), eyes
        
        eyes = sorted(eyes, key=lambda e: e[0])
        left, right = eyes[0], eyes[-1]
        lc, rc = left[0] + left[2]//2, right[0] + right[2]//2
        mid = w // 2
        
        if lc < mid - 10 and rc > mid + 10:
            ly, ry = left[1] + left[3]//2, right[1] + right[3]//2
            if abs(ly - ry) < h * 0.15:
                return True, 2, [left, right]
        
        return False, len(eyes), eyes
    
    def _compute_sig(self, f200):
        fh = cv2.calcHist([f200], [0], None, [128], [0, 256]); cv2.normalize(fh, fh)
        regs = []
        for gy in range(4):
            for gx in range(4):
                r = f200[gy*50:(gy+1)*50, gx*50:(gx+1)*50]
                rh = cv2.calcHist([r], [0], None, [32], [0, 256]); cv2.normalize(rh, rh)
                regs.append(rh.flatten())
        eh = cv2.calcHist([cv2.Canny(f200, 50, 150)], [0], None, [32], [0, 256]); cv2.normalize(eh, eh)
        return {"full": fh.flatten(), "regs": regs, "edge": eh.flatten()}
    
    def _cmp_sig(self, s1, s2):
        sf = cv2.compareHist(s1["full"].astype(np.float32), s2["full"].astype(np.float32), cv2.HISTCMP_CORREL)
        w = [1.5]*4 + [2.5]*4 + [1.5]*4 + [0.8]*4
        sr = sum(cv2.compareHist(s1["regs"][i].astype(np.float32), s2["regs"][i].astype(np.float32), cv2.HISTCMP_CORREL) * w[i] for i in range(16)) / sum(w)
        se = cv2.compareHist(s1["edge"].astype(np.float32), s2["edge"].astype(np.float32), cv2.HISTCMP_CORREL)
        return 0.2*sf + 0.55*sr + 0.25*se
    
    def register_with_preview(self, username):
        if not CV2_OK: return {"success": False, "error": "OpenCV not installed."}
        if not self._cascade_loaded: return {"success": False, "error": "Face detection not available. Cascade files missing."}
        
        with self._cam_lock:
            self._close_all_windows()
            cap = self._open_cam()
            if not cap: return {"success": False, "error": "Cannot open camera."}
            
            ud = self._user_dir(username)
            samples, eye_streak = [], 0
            start = time.time()
            win_name = "SecureVault - Register Face [Q=cancel]"
            
            try:
                while len(samples) < self.TRAIN_SAMPLES and time.time() - start < 20:
                    ret, frame = cap.read()
                    if not ret: continue
                    
                    frame = cv2.flip(frame, 1)
                    gray = cv2.equalizeHist(cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY))
                    
                    cv2.putText(frame, f"REGISTER [{len(samples)}/{self.TRAIN_SAMPLES}]", (10, 28), cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0,255,136), 2)
                    
                    face = self._detect_face(gray)
                    if face is not None:
                        x, y, w, h = face
                        roi = gray[y:y+h, x:x+w]
                        eyes_ok, n_eyes, eyes = self._detect_eyes_strict(roi)
                        
                        if eyes_ok:
                            eye_streak += 1
                            cv2.rectangle(frame, (x,y), (x+w,y+h), (0,255,0), 2)
                            for ex, ey, ew, eh in eyes:
                                cv2.rectangle(frame, (x+ex, y+ey), (x+ex+ew, y+ey+eh), (0,255,255), 2)
                            if eye_streak >= 2:
                                samples.append(cv2.resize(roi, (200,200)))
                                eye_streak = 0
                                cv2.putText(frame, f"CAPTURED!", (x, y-10), cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0,255,0), 2)
                        else:
                            eye_streak = 0
                            cv2.rectangle(frame, (x,y), (x+w,y+h), (0,0,255), 2)
                            cv2.putText(frame, f"OPEN BOTH EYES! ({n_eyes})", (x, y-10), cv2.FONT_HERSHEY_SIMPLEX, 0.5, (0,0,255), 2)
                    else:
                        eye_streak = 0
                        cv2.putText(frame, "Look at camera...", (180, 240), cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0,0,255), 2)
                    
                    prog = int((len(samples)/self.TRAIN_SAMPLES)*300)
                    cv2.rectangle(frame, (170,450), (470,465), (40,40,40), -1)
                    cv2.rectangle(frame, (170,450), (170+prog,465), (0,255,0), -1)
                    
                    cv2.imshow(win_name, frame)
                    if cv2.waitKey(1) & 0xFF in (ord('q'), 27): break
            finally:
                cap.release()
                self._close_all_windows()
            
            if len(samples) < 5: return {"success": False, "error": f"Only {len(samples)} samples. Keep BOTH eyes open!"}
            
            if LBPH_OK:
                try:
                    rec = cv2.face.LBPHFaceRecognizer_create(radius=2, neighbors=16, grid_x=8, grid_y=8)
                    rec.train(samples, np.array([0]*len(samples)))
                    rec.save(os.path.join(ud, "face_model.yml"))
                except: pass
            
            np.save(os.path.join(ud, "face_samples.npy"), np.array(samples))
            return {"success": True, "samples": len(samples)}
    
    def authenticate_with_preview(self, username):
        if not CV2_OK: return {"success": False, "error": "OpenCV not installed.", "score": 0}
        if not self._cascade_loaded: return {"success": False, "error": "Face detection not available.", "score": 0}
        
        with self._cam_lock:
            self._close_all_windows()
            cap = self._open_cam()
            if not cap: return {"success": False, "error": "Cannot open camera.", "score": 0}
            
            ud = self._user_dir(username)
            has_lbph = LBPH_OK and os.path.exists(os.path.join(ud, "face_model.yml"))
            has_npy = os.path.exists(os.path.join(ud, "face_samples.npy"))
            if not has_lbph and not has_npy: 
                cap.release()
                return {"success": False, "error": "No face registered.", "score": 0}
            
            rec, sigs = None, []
            if has_lbph:
                try: rec = cv2.face.LBPHFaceRecognizer_create(); rec.read(os.path.join(ud, "face_model.yml"))
                except: rec = None
            if has_npy:
                try:
                    for s in np.load(os.path.join(ud, "face_samples.npy")): sigs.append(self._compute_sig(s))
                except: pass
            
            start = time.time()
            result = {"success": False, "error": "Face not matched.", "score": 0}
            match_streak = 0
            win_name = "SecureVault - Face Login [Q=cancel]"
            
            try:
                while time.time() - start < 10:
                    ret, frame = cap.read()
                    if not ret: continue
                    
                    frame = cv2.flip(frame, 1)
                    gray = cv2.equalizeHist(cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY))
                    rem = max(0, 10 - (time.time() - start))
                    
                    cv2.putText(frame, f"FACE LOGIN [{rem:.0f}s]", (10, 28), cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0,255,136), 2)
                    
                    face = self._detect_face(gray)
                    if face is not None:
                        x, y, w, h = face
                        roi = gray[y:y+h, x:x+w]
                        eyes_ok, n_eyes, eyes = self._detect_eyes_strict(roi)
                        
                        if not eyes_ok:
                            match_streak = 0
                            cv2.rectangle(frame, (x,y), (x+w,y+h), (0,0,255), 2)
                            cv2.putText(frame, f"OPEN BOTH EYES! ({n_eyes})", (x, y-10), cv2.FONT_HERSHEY_SIMPLEX, 0.5, (0,0,255), 2)
                            cv2.imshow(win_name, frame)
                            if cv2.waitKey(1) & 0xFF in (ord('q'), 27): break
                            continue
                        
                        for ex, ey, ew, eh in eyes:
                            cv2.rectangle(frame, (x+ex, y+ey), (x+ex+ew, y+ey+eh), (0,255,255), 2)
                        
                        f200 = cv2.resize(roi, (200,200))
                        matched, score_txt = False, ""
                        
                        if rec:
                            try:
                                _, conf = rec.predict(f200)
                                matched = conf < self.LBPH_THRESH
                                score_txt = f"LBPH:{conf:.0f}"
                                result["score"] = round(conf, 1)
                            except: pass
                        
                        if not matched and sigs:
                            cur = self._compute_sig(f200)
                            best = max(self._cmp_sig(cur, s) for s in sigs)
                            matched = best >= self.FALLBACK_THRESH
                            score_txt = f"Match:{best:.2f}"
                            result["score"] = round(best, 3)
                        
                        col = (0,255,0) if matched else (0,140,255)
                        cv2.rectangle(frame, (x,y), (x+w,y+h), col, 2)
                        cv2.putText(frame, score_txt, (x, y-10), cv2.FONT_HERSHEY_SIMPLEX, 0.5, col, 2)
                        
                        if matched:
                            match_streak += 1
                            if match_streak >= 3:
                                result = {"success": True, "score": result["score"], "method": "LBPH" if rec else "Fallback"}
                                cv2.rectangle(frame, (0,0), (640,480), (0,255,0), 4)
                                cv2.putText(frame, "ACCESS GRANTED", (130, 250), cv2.FONT_HERSHEY_SIMPLEX, 1.3, (0,255,0), 3)
                                cv2.imshow(win_name, frame)
                                cv2.waitKey(800)
                                break
                        else:
                            match_streak = 0
                    else:
                        match_streak = 0
                        cv2.putText(frame, "No face - look at camera", (150, 250), cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0,0,255), 2)
                    
                    prog = int(((time.time()-start)/10)*300)
                    cv2.rectangle(frame, (170,450), (470,465), (40,40,40), -1)
                    cv2.rectangle(frame, (170,450), (170+prog,465), (0,140,255), -1)
                    
                    cv2.imshow(win_name, frame)
                    if cv2.waitKey(1) & 0xFF in (ord('q'), 27): result["error"] = "Cancelled."; break
            finally:
                cap.release()
                self._close_all_windows()
            
            return result
    
    def reset(self, u):
        ud = self._user_dir(u)
        for fn in ["face_model.yml", "face_samples.npy", "face_ref.png"]:
            p = os.path.join(ud, fn)
            if os.path.exists(p): os.remove(p)

# ═══════════════════════════════════════════════════════════════════
# USER MANAGER
# ═══════════════════════════════════════════════════════════════════

class UserManager:
    def __init__(self, data_dir):
        self.data_dir = data_dir; self.users_file = os.path.join(data_dir, "users.json")
        os.makedirs(data_dir, exist_ok=True); self.users = self._load()
    
    def _load(self):
        if os.path.exists(self.users_file):
            try:
                with open(self.users_file, 'r') as f: return json.load(f)
            except: pass
        return {}
    
    def _save(self):
        with open(self.users_file, 'w') as f: json.dump(self.users, f, indent=2)
    
    def register(self, u, pw, sq, sa):
        if u in self.users: return {"success": False, "error": "Username exists."}
        vs = secrets.token_hex(16)
        vk = hashlib.pbkdf2_hmac('sha256', pw.encode(), bytes.fromhex(vs), 50000).hex()
        self.users[u] = {"pw": hashlib.sha256(pw.encode()).hexdigest(), "sec_q": sq,
            "sec_a": hashlib.sha256(sa.lower().strip().encode()).hexdigest(),
            "vault_salt": vs, "created": datetime.now().isoformat(), "face_key_secret": None}
        self._save(); os.makedirs(os.path.join(self.data_dir, "vaults", u), exist_ok=True)
        return {"success": True, "vault_key": vk}
    
    def login(self, u, pw):
        usr = self.users.get(u)
        if not usr: return {"success": False, "error": "User not found."}
        if usr.get("pw") != hashlib.sha256(pw.encode()).hexdigest(): return {"success": False, "error": "Wrong password."}
        return {"success": True}
    
    def get_vault_key(self, u, pw):
        usr = self.users.get(u)
        if not usr: return None
        return hashlib.pbkdf2_hmac('sha256', pw.encode(), bytes.fromhex(usr["vault_salt"]), 50000).hex()
    
    def store_face_key(self, u, vk):
        if not vk: return
        fs = hashlib.sha256(f"SV_FACE_{u}_KEY".encode()).hexdigest()[:32]
        self.users[u]["face_key_secret"] = base64.b64encode(AES256.encrypt(vk.encode(), fs)).decode()
        self._save()
    
    def get_vault_key_by_face(self, u):
        usr = self.users.get(u)
        if not usr or not usr.get("face_key_secret"): return None
        try:
            fs = hashlib.sha256(f"SV_FACE_{u}_KEY".encode()).hexdigest()[:32]
            return AES256.decrypt(base64.b64decode(usr["face_key_secret"]), fs).decode()
        except: return None
    
    def forgot_pw(self, u, ans, new_pw):
        usr = self.users.get(u)
        if not usr: return {"success": False, "error": "User not found."}
        if usr.get("sec_a") != hashlib.sha256(ans.lower().strip().encode()).hexdigest(): return {"success": False, "error": "Wrong answer."}
        self.users[u]["pw"] = hashlib.sha256(new_pw.encode()).hexdigest(); self._save()
        return {"success": True}
    
    def get_sec_q(self, u): return self.users.get(u, {}).get("sec_q")
    def vault_dir(self, u): return os.path.join(self.data_dir, "vaults", u)
    def list_users(self): return list(self.users.keys())

# ═══════════════════════════════════════════════════════════════════
# VAULT ENGINE
# ═══════════════════════════════════════════════════════════════════

class VaultEngine:
    def __init__(self, vault_dir, vault_key):
        self.vault_dir, self.vault_key = vault_dir, vault_key
        self.store_dir = os.path.join(vault_dir, "store")
        self.share_dir = os.path.join(vault_dir, "shared")
        os.makedirs(self.store_dir, exist_ok=True); os.makedirs(self.share_dir, exist_ok=True)
        self.file_index, self.audit_log, self.server = CustomHashMap(), CustomLinkedList(), None
        self._load_manifest()
    
    def _load_manifest(self):
        mp = os.path.join(self.vault_dir, "manifest.enc")
        if os.path.exists(mp):
            try:
                with open(mp, 'rb') as f: d = AES256.decrypt(f.read(), self.vault_key)
                for n, i in json.loads(d.decode()).items(): self.file_index.put(n, i)
            except: pass
    
    def _save_manifest(self):
        d = json.dumps({n: i for n, i in self.file_index.items()}).encode()
        with open(os.path.join(self.vault_dir, "manifest.enc"), 'wb') as f: f.write(AES256.encrypt(d, self.vault_key))
    
    def add_file(self, src):
        name, blob = os.path.basename(src), secrets.token_hex(16)+".vault"
        with open(src, 'rb') as f: raw = f.read()
        with open(os.path.join(self.store_dir, blob), 'wb') as f: f.write(AES256.encrypt(raw, self.vault_key))
        if self.file_index.contains(name): b, e = os.path.splitext(name); name = f"{b}_{int(time.time())}{e}"
        self.file_index.put(name, {"blob": blob, "size": len(raw), "size_h": self._hs(len(raw)),
            "added": datetime.now().strftime("%Y-%m-%d %H:%M"), "hash": hashlib.sha256(raw[:4096]).hexdigest()[:16], "locked": False})
        self._save_manifest(); self._log("ADD", name); return name
    
    def remove_file(self, name):
        info = self.file_index.get(name)
        if not info: return False
        bp = os.path.join(self.store_dir, info["blob"])
        if os.path.exists(bp): os.remove(bp)
        self.file_index.remove(name); self._save_manifest(); self._log("DEL", name); return True
    
    def read_file(self, name):
        info = self.file_index.get(name)
        if not info: return None
        bp = os.path.join(self.store_dir, info["blob"])
        if not os.path.exists(bp): return None
        try:
            with open(bp, 'rb') as f: return AES256.decrypt(f.read(), self.vault_key)
        except: return None
    
    def user_lock(self, name, pw):
        data = self.read_file(name)
        if data is None: return None
        info = self.file_index.get(name)
        double = AES256.encrypt(data, pw)
        with open(os.path.join(self.store_dir, info["blob"]), 'wb') as f: f.write(AES256.encrypt(double, self.vault_key))
        en = name + ".locked"; self.file_index.remove(name); info["locked"] = True
        self.file_index.put(en, info); self._save_manifest(); self._log("LOCK", name); return en
    
    def user_unlock(self, name, pw):
        info = self.file_index.get(name)
        if not info or not info.get("locked"): return None
        bp = os.path.join(self.store_dir, info["blob"])
        try:
            with open(bp, 'rb') as f: double = AES256.decrypt(f.read(), self.vault_key)
            plain = AES256.decrypt(double, pw)
            with open(bp, 'wb') as f: f.write(AES256.encrypt(plain, self.vault_key))
            on = name[:-7] if name.endswith(".locked") else name
            self.file_index.remove(name); info["locked"] = False
            self.file_index.put(on, info); self._save_manifest(); self._log("UNLOCK", name); return on
        except: return None
    
    def export_file(self, name, dest):
        data = self.read_file(name)
        if data is None or self.file_index.get(name, {}).get("locked"): return False
        with open(dest, 'wb') as f: f.write(data)
        self._log("EXPORT", name); return True
    
    def get_files(self): return sorted(self.file_index.items(), key=lambda x: x[0])
    
    def start_server(self, port=8080):
        if self.server: return {"error": "Already running"}
        for f in os.listdir(self.share_dir): os.remove(os.path.join(self.share_dir, f))
        for n, i in self.file_index.items():
            if not i.get("locked"):
                d = self.read_file(n)
                if d:
                    with open(os.path.join(self.share_dir, n), 'wb') as f: f.write(d)
        try:
            # Custom handler that works in EXE
            share_path = os.path.abspath(self.share_dir)
            class ShareHandler(SimpleHTTPRequestHandler):
                def __init__(self, *args, **kwargs):
                    super().__init__(*args, directory=share_path, **kwargs)
                def log_message(self, format, *args): pass  # Suppress logs
            
            self.server = HTTPServer(('0.0.0.0', port), ShareHandler)
            threading.Thread(target=self.server.serve_forever, daemon=True).start()
            self._log("SRV_ON", str(port))
            import socket; ip = "127.0.0.1"
            try: s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.connect(("8.8.8.8",80)); ip = s.getsockname()[0]; s.close()
            except: pass
            return {"ok": True, "url": f"http://{ip}:{port}"}
        except Exception as e: return {"error": str(e)}
    
    def stop_server(self):
        if self.server:
            self.server.shutdown(); self.server = None
            for f in os.listdir(self.share_dir): os.remove(os.path.join(self.share_dir, f))
            self._log("SRV_OFF",""); return True
        return False
    
    def _log(self, a, d): self.audit_log.append({"time": datetime.now().strftime("%H:%M:%S"), "act": a, "det": d})
    
    @staticmethod
    def _hs(n):
        for u in ['B','KB','MB','GB']:
            if n < 1024: return f"{n:.1f} {u}"
            n /= 1024
        return f"{n:.1f} TB"

# ═══════════════════════════════════════════════════════════════════
# GUI
# ═══════════════════════════════════════════════════════════════════

class App:
    C = {"bg":"#080810","panel":"#0e0e1a","card":"#12121e","input":"#181828","border":"#1e1e2e",
         "green":"#00ff88","gdim":"#00663a","red":"#ff3366","orange":"#ff9933","cyan":"#33ddff",
         "blue":"#3388ff","purple":"#aa66ff","white":"#e0e0e8","dim":"#555566"}

    def __init__(self, root):
        self.root = root; self.root.title("SECUREVAULT v4.3"); self.root.geometry("1080x700")
        self.root.configure(bg=self.C["bg"])
        self.data_dir = os.path.join(os.path.expanduser("~"), ".securevault")
        self.face_auth = FaceAuth(self.data_dir)
        self.user_mgr = UserManager(self.data_dir)
        self.vault = self.current_user = self.vault_key = None
        self._face_busy = False
        self._styles(); self._show_login()

    def _styles(self):
        s = ttk.Style(); s.theme_use("clam")
        s.configure("Dark.TNotebook", background=self.C["bg"], borderwidth=0)
        s.configure("Dark.TNotebook.Tab", background=self.C["panel"], foreground=self.C["dim"], font=("Segoe UI",10), padding=(16,6))
        s.map("Dark.TNotebook.Tab", background=[("selected",self.C["card"])], foreground=[("selected",self.C["green"])])
        s.configure("Treeview", background=self.C["card"], foreground=self.C["green"], fieldbackground=self.C["card"], font=("Consolas",9), rowheight=26)
        s.configure("Treeview.Heading", background=self.C["panel"], foreground=self.C["green"], font=("Segoe UI",9,"bold"))
        s.map("Treeview", background=[("selected",self.C["gdim"])], foreground=[("selected","#000")])

    def _btn(self, p, txt, cmd, col=None, w=None):
        fg = "#fff" if col == self.C["red"] else "#000"
        return tk.Button(p, text=txt, command=cmd, font=("Segoe UI",10,"bold"), bg=col or self.C["gdim"], fg=fg, relief=tk.FLAT, cursor="hand2", padx=14, pady=6, width=w, activebackground=self.C["green"])
    
    def _entry(self, p, w=25, show=None):
        return tk.Entry(p, width=w, bg=self.C["input"], fg=self.C["green"], font=("Consolas",11), relief=tk.FLAT, show=show, insertbackground=self.C["green"], highlightthickness=1, highlightcolor=self.C["green"], highlightbackground=self.C["border"])
    
    def _lbl(self, p, txt, col=None, sz=10, bold=False):
        return tk.Label(p, text=txt, font=("Segoe UI",sz,"bold" if bold else ""), fg=col or self.C["white"], bg=self.C["bg"])
    
    def _clear(self):
        for w in self.root.winfo_children(): w.destroy()

    def _show_login(self):
        self._clear()
        f = tk.Frame(self.root, bg=self.C["bg"]); f.place(relx=0.5, rely=0.5, anchor=tk.CENTER)
        tk.Label(f, text="🔐", font=("Segoe UI",48), bg=self.C["bg"]).pack()
        tk.Label(f, text="SECUREVAULT", font=("Consolas",26,"bold"), fg=self.C["green"], bg=self.C["bg"]).pack()
        st = "✓ LBPH Active" if LBPH_OK else ("⚠ Fallback Mode" if CV2_OK else "✗ pip install opencv-contrib-python")
        sc = self.C["cyan"] if LBPH_OK else (self.C["orange"] if CV2_OK else self.C["red"])
        tk.Label(f, text=st, font=("Segoe UI",8), fg=sc, bg=self.C["bg"]).pack(pady=(0,15))
        card = tk.Frame(f, bg=self.C["card"], padx=30, pady=20, highlightbackground=self.C["border"], highlightthickness=1); card.pack()
        self._lbl(card, "Username", self.C["dim"], 9).pack(anchor=tk.W, pady=(5,2))
        self.login_user = self._entry(card, 28); self.login_user.pack(pady=(0,8))
        self._lbl(card, "Password", self.C["dim"], 9).pack(anchor=tk.W, pady=(5,2))
        self.login_pass = self._entry(card, 28, show="●"); self.login_pass.pack(pady=(0,12))
        bf = tk.Frame(card, bg=self.C["card"]); bf.pack(fill=tk.X)
        self._btn(bf, "🔓 LOGIN", self._do_login, w=12).pack(side=tk.LEFT, padx=(0,5))
        if CV2_OK: self._btn(bf, "📸 FACE LOGIN", self._face_login, self.C["blue"], 14).pack(side=tk.LEFT)
        lf = tk.Frame(card, bg=self.C["card"]); lf.pack(fill=tk.X, pady=(12,0))
        tk.Button(lf, text="Create Account", command=self._show_register, font=("Segoe UI",9,"underline"), fg=self.C["cyan"], bg=self.C["card"], relief=tk.FLAT, cursor="hand2").pack(side=tk.LEFT)
        tk.Button(lf, text="Forgot Password?", command=self._forgot_pw, font=("Segoe UI",9,"underline"), fg=self.C["orange"], bg=self.C["card"], relief=tk.FLAT, cursor="hand2").pack(side=tk.RIGHT)
        users = self.user_mgr.list_users()
        if users: tk.Label(f, text=f"Users: {', '.join(users)}", font=("Segoe UI",8), fg=self.C["dim"], bg=self.C["bg"]).pack(pady=(10,0))

    def _show_register(self):
        self._clear()
        f = tk.Frame(self.root, bg=self.C["bg"]); f.place(relx=0.5, rely=0.5, anchor=tk.CENTER)
        tk.Label(f, text="📝 CREATE ACCOUNT", font=("Consolas",18,"bold"), fg=self.C["green"], bg=self.C["bg"]).pack(pady=(0,15))
        card = tk.Frame(f, bg=self.C["card"], padx=30, pady=20, highlightbackground=self.C["border"], highlightthickness=1); card.pack()
        fields = [("Username",False),("Password",True),("Confirm Password",True),("Security Question",False),("Security Answer",False)]
        self.reg_e = {}
        for lbl, hide in fields:
            self._lbl(card, lbl, self.C["dim"], 9).pack(anchor=tk.W, pady=(5,1))
            e = self._entry(card, 30, show="●" if hide else None); e.pack(pady=(0,4)); self.reg_e[lbl] = e
        self.reg_e["Security Question"].insert(0, "What is your pet's name?")
        bf = tk.Frame(card, bg=self.C["card"]); bf.pack(fill=tk.X, pady=(10,0))
        self._btn(bf, "✅ Register", self._do_reg, w=14).pack(side=tk.LEFT, padx=(0,5))
        if CV2_OK: self._btn(bf, "📸 + Face", lambda: self._do_reg(True), self.C["blue"], 14).pack(side=tk.LEFT)
        tk.Button(card, text="← Back", command=self._show_login, font=("Segoe UI",9,"underline"), fg=self.C["cyan"], bg=self.C["card"], relief=tk.FLAT, cursor="hand2").pack(pady=(10,0))

    def _do_reg(self, with_face=False):
        e = self.reg_e; u, pw = e["Username"].get().strip(), e["Password"].get()
        if not u or not pw: messagebox.showwarning("!","Username & password required."); return
        if pw != e["Confirm Password"].get(): messagebox.showwarning("!","Passwords don't match."); return
        sq, sa = e["Security Question"].get().strip(), e["Security Answer"].get().strip()
        if not sq or not sa: messagebox.showwarning("!","Security Q&A needed."); return
        r = self.user_mgr.register(u, pw, sq, sa)
        if not r["success"]: messagebox.showerror("!", r["error"]); return
        vk = r["vault_key"]
        if with_face and CV2_OK:
            def do_face():
                fr = self.face_auth.register_with_preview(u)
                def handle():
                    if fr["success"]: self.user_mgr.store_face_key(u, vk); messagebox.showinfo("✅", f"Account + face registered! {fr['samples']} samples.")
                    else: messagebox.showwarning("Face", f"Account OK but face failed:\n{fr['error']}")
                    self._show_login()
                self.root.after(0, handle)
            threading.Thread(target=do_face, daemon=True).start()
        else: messagebox.showinfo("✅", "Account created!"); self._show_login()

    def _do_login(self):
        u, pw = self.login_user.get().strip(), self.login_pass.get()
        if not u: return
        r = self.user_mgr.login(u, pw)
        if r["success"]:
            # Show loading
            self._clear()
            f = tk.Frame(self.root, bg=self.C["bg"]); f.place(relx=0.5, rely=0.5, anchor=tk.CENTER)
            tk.Label(f, text="🔐", font=("Segoe UI",48), bg=self.C["bg"]).pack()
            tk.Label(f, text="Loading vault...", font=("Consolas",14), fg=self.C["green"], bg=self.C["bg"]).pack(pady=10)
            self.root.update()
            # Load vault in background
            def do_load():
                vk = self.user_mgr.get_vault_key(u, pw)
                self.root.after(0, lambda: self._enter_vault(u, vk))
            threading.Thread(target=do_load, daemon=True).start()
        else:
            messagebox.showerror("!", r["error"])

    def _face_login(self):
        if self._face_busy: return
        u = self.login_user.get().strip()
        if not u: messagebox.showinfo("!", "Enter username first."); return
        if u not in self.user_mgr.users: messagebox.showerror("!", f"User '{u}' not found."); return
        if not self.face_auth.is_registered(u): messagebox.showinfo("!", f"No face for '{u}'."); return
        vk = self.user_mgr.get_vault_key_by_face(u)
        if not vk: messagebox.showinfo("!", "Face key not set."); return
        
        self._face_busy = True
        def do_face():
            fr = self.face_auth.authenticate_with_preview(u)
            def handle():
                self._face_busy = False
                if fr["success"]: self._enter_vault(u, vk)
                else: messagebox.showwarning("!", fr.get("error", "Not matched."))
            self.root.after(0, handle)
        threading.Thread(target=do_face, daemon=True).start()

    def _forgot_pw(self):
        u = self.login_user.get().strip()
        if not u: messagebox.showinfo("!","Enter username."); return
        q = self.user_mgr.get_sec_q(u)
        if not q: messagebox.showerror("!",f"'{u}' not found."); return
        win = tk.Toplevel(self.root); win.title("Reset"); win.geometry("380x220"); win.configure(bg=self.C["bg"]); win.grab_set()
        self._lbl(win, f"Q: {q}", self.C["cyan"]).pack(pady=(15,5))
        self._lbl(win, "Answer:", self.C["dim"], 9).pack()
        ans = self._entry(win, 25); ans.pack(pady=3)
        self._lbl(win, "New Password:", self.C["dim"], 9).pack()
        npw = self._entry(win, 25, show="●"); npw.pack(pady=3)
        def reset():
            r = self.user_mgr.forgot_pw(u, ans.get(), npw.get())
            if r["success"]: messagebox.showinfo("✅","Password reset!"); win.destroy()
            else: messagebox.showerror("!", r["error"])
        self._btn(win, "Reset", reset).pack(pady=10)

    def _enter_vault(self, u, vk):
        self.current_user, self.vault_key = u, vk
        self.vault = VaultEngine(self.user_mgr.vault_dir(u), vk)
        self.vault._log("LOGIN", u); self._show_vault()

    def _show_vault(self):
        self._clear()
        h = tk.Frame(self.root, bg=self.C["bg"]); h.pack(fill=tk.X, padx=10, pady=(8,2))
        tk.Label(h, text="🔐 SECUREVAULT", font=("Consolas",16,"bold"), fg=self.C["green"], bg=self.C["bg"]).pack(side=tk.LEFT)
        tk.Label(h, text=f"  {self.current_user} ✅", font=("Segoe UI",10), fg=self.C["cyan"], bg=self.C["bg"]).pack(side=tk.LEFT, padx=8)
        ctrl = tk.Frame(h, bg=self.C["bg"]); ctrl.pack(side=tk.RIGHT)
        for t, c, cl in [("➕ Add",self._add_file,None),("🔒 Lock",self._lock_sel,self.C["orange"]),("🔓 Unlock",self._unlock_sel,self.C["blue"]),
                          ("💾 Export",self._export_sel,self.C["purple"]),("🗑",self._remove_sel,self.C["red"]),("⚙️",self._settings,self.C["dim"]),("🚪",self._logout,self.C["red"])]:
            self._btn(ctrl, t, c, cl).pack(side=tk.LEFT, padx=2)
        tk.Label(self.root, text="📁 All files encrypted at rest", font=("Segoe UI",8), fg=self.C["orange"], bg=self.C["panel"]).pack(fill=tk.X, padx=10)
        nb = ttk.Notebook(self.root, style="Dark.TNotebook"); nb.pack(fill=tk.BOTH, expand=True, padx=10, pady=4)
        f1 = tk.Frame(nb, bg=self.C["bg"]); nb.add(f1, text="  📁 Files  ")
        f2 = tk.Frame(nb, bg=self.C["bg"]); nb.add(f2, text="  🌐 Share  ")
        f3 = tk.Frame(nb, bg=self.C["bg"]); nb.add(f3, text="  📜 Log  ")
        cols = ("name","size","added","status","hash")
        self.tree = ttk.Treeview(f1, columns=cols, show="headings", height=20)
        for c, t, w in [("name","File Name",320),("size","Size",80),("added","Added",140),("status","Status",120),("hash","Hash",120)]:
            self.tree.heading(c, text=t); self.tree.column(c, width=w, anchor=tk.W if c=="name" else tk.CENTER)
        self.tree.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)
        sf = tk.Frame(f2, bg=self.C["bg"]); sf.pack(fill=tk.X, padx=8, pady=8)
        self._lbl(sf, "Port:", self.C["dim"], 9).pack(side=tk.LEFT)
        self.port_e = self._entry(sf, 6); self.port_e.insert(0, "8080"); self.port_e.pack(side=tk.LEFT, padx=5)
        self._btn(sf, "🌐 Start", self._start_srv).pack(side=tk.LEFT, padx=3)
        self._btn(sf, "⏹ Stop", self._stop_srv, self.C["red"]).pack(side=tk.LEFT, padx=3)
        self.share_lbl = tk.Label(f2, text="Share files on network.", font=("Consolas",10), fg=self.C["dim"], bg=self.C["bg"]); self.share_lbl.pack(pady=20)
        self.log_out = scrolledtext.ScrolledText(f3, bg=self.C["card"], fg=self.C["green"], font=("Consolas",9), relief=tk.FLAT, wrap=tk.WORD, padx=10, pady=8)
        self.log_out.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)
        foot = tk.Frame(self.root, bg=self.C["bg"]); foot.pack(fill=tk.X, padx=10, pady=(0,4))
        self.status = tk.Label(foot, text="", font=("Consolas",9), fg=self.C["dim"], bg=self.C["bg"]); self.status.pack(side=tk.LEFT)
        self._refresh()

    def _refresh(self):
        self.tree.delete(*self.tree.get_children())
        for n, i in self.vault.get_files():
            st = "🔒 Locked" if i.get("locked") else "📄 Encrypted"
            self.tree.insert("", tk.END, values=(n, i["size_h"], i["added"], st, i["hash"]), tags=("l" if i.get("locked") else "",))
        self.tree.tag_configure("l", foreground=self.C["orange"])
        self.status.configure(text=f"📁 {len(self.vault.file_index)} files | {self.current_user}")
        self.log_out.configure(state=tk.NORMAL); self.log_out.delete("1.0", tk.END)
        ic = {"ADD":"📂","DEL":"🗑","LOCK":"🔒","UNLOCK":"🔓","EXPORT":"💾","LOGIN":"🔐","SRV_ON":"🌐","SRV_OFF":"⏹","LOGOUT":"🚪"}
        for e in reversed(self.vault.audit_log.to_list()[-50:]):
            self.log_out.insert(tk.END, f"  {ic.get(e['act'],'📝')} [{e['time']}] {e['act']:<8s} {e['det']}\n")
        self.log_out.configure(state=tk.DISABLED)

    def _get_sel(self):
        s = self.tree.selection()
        if not s: messagebox.showinfo("!","Select file."); return None
        return self.tree.item(s[0])["values"][0]
    
    def _ask_pw(self, title):
        win = tk.Toplevel(self.root); win.title(title); win.geometry("320x120"); win.configure(bg=self.C["bg"]); win.grab_set()
        self._lbl(win, "Password:", self.C["dim"], 9).pack(pady=(12,2))
        e = self._entry(win, 22, show="●"); e.pack(); r = [None]
        def ok(): r[0] = e.get(); win.destroy()
        self._btn(win, "OK", ok).pack(pady=8); e.bind("<Return>", lambda ev: ok()); e.focus_set()
        win.wait_window(); return r[0]
    
    def _add_file(self):
        fps = filedialog.askopenfilenames(title="Add Files")
        if not fps: return
        self.status.configure(text="⏳ Adding files...")
        self.root.update()
        def do_add():
            for fp in fps:
                self.vault.add_file(fp)
                self.root.after(0, lambda: self.root.update())
            self.root.after(0, self._refresh)
            self.root.after(0, lambda: self.status.configure(text=f"✅ Added {len(fps)} file(s)"))
        threading.Thread(target=do_add, daemon=True).start()
    
    def _lock_sel(self):
        n = self._get_sel()
        if not n: return
        if n.endswith('.locked'): messagebox.showinfo("!","Already locked."); return
        pw = self._ask_pw("Lock")
        if pw:
            self.status.configure(text="⏳ Locking...")
            self.root.update()
            def do_lock():
                self.vault.user_lock(n, pw)
                self.root.after(0, self._refresh)
                self.root.after(0, lambda: self.status.configure(text="✅ File locked"))
            threading.Thread(target=do_lock, daemon=True).start()
    
    def _unlock_sel(self):
        n = self._get_sel()
        if not n: return
        if not n.endswith('.locked'): messagebox.showinfo("!","Not locked."); return
        pw = self._ask_pw("Unlock")
        if pw:
            self.status.configure(text="⏳ Unlocking...")
            self.root.update()
            def do_unlock():
                r = self.vault.user_unlock(n, pw)
                if r:
                    self.root.after(0, self._refresh)
                    self.root.after(0, lambda: self.status.configure(text="✅ File unlocked"))
                else:
                    self.root.after(0, lambda: messagebox.showerror("!","Wrong password."))
                    self.root.after(0, lambda: self.status.configure(text="❌ Unlock failed"))
            threading.Thread(target=do_unlock, daemon=True).start()
    
    def _export_sel(self):
        n = self._get_sel()
        if not n: return
        if n.endswith('.locked'): messagebox.showinfo("!","Unlock first."); return
        fp = filedialog.asksaveasfilename(title="Export", initialfile=n)
        if fp:
            self.status.configure(text="⏳ Exporting...")
            self.root.update()
            def do_export():
                if self.vault.export_file(n, fp):
                    self.root.after(0, lambda: messagebox.showinfo("✅","Exported!"))
                    self.root.after(0, lambda: self.status.configure(text="✅ Exported"))
                else:
                    self.root.after(0, lambda: self.status.configure(text="❌ Export failed"))
            threading.Thread(target=do_export, daemon=True).start()
    
    def _remove_sel(self):
        n = self._get_sel()
        if n and messagebox.askyesno("?",f"Delete {n}?"):
            self.vault.remove_file(n)
            self._refresh()
    
    def _start_srv(self):
        try: port = int(self.port_e.get())
        except: port = 8080
        self.share_lbl.configure(text="⏳ Starting server...", fg=self.C["orange"])
        self.root.update()
        def do_start():
            r = self.vault.start_server(port)
            if "ok" in r:
                self.root.after(0, lambda: self.share_lbl.configure(text=f"✅ {r['url']}", fg=self.C["green"]))
            else:
                self.root.after(0, lambda: self.share_lbl.configure(text=f"❌ {r['error']}", fg=self.C["red"]))
        threading.Thread(target=do_start, daemon=True).start()
    
    def _stop_srv(self): self.vault.stop_server(); self.share_lbl.configure(text="Stopped.", fg=self.C["dim"])
    
    def _settings(self):
        win = tk.Toplevel(self.root); win.title("⚙️ Settings"); win.geometry("360x280"); win.configure(bg=self.C["bg"]); win.grab_set()
        self._lbl(win, "⚙️ SETTINGS", self.C["green"], 14, True).pack(pady=12)
        if CV2_OK: self._btn(win, "📸 Register / Update Face", lambda: self._reg_face_set(win), self.C["blue"]).pack(pady=5)
        self._btn(win, "🔑 Change Password", lambda: self._change_pw(win)).pack(pady=5)
        self._btn(win, "🗑 Delete Account", lambda: self._del_acc(win), self.C["red"]).pack(pady=5)
        self._btn(win, "Close", win.destroy, self.C["dim"]).pack(pady=15)
    
    def _reg_face_set(self, parent):
        vk, u = self.vault_key, self.current_user
        if not vk or not u: return
        def do_reg():
            fr = self.face_auth.register_with_preview(u)
            def handle():
                if fr["success"]: self.user_mgr.store_face_key(u, vk); messagebox.showinfo("✅", f"Face registered! {fr['samples']} samples.")
                else: messagebox.showwarning("!", fr["error"])
            self.root.after(0, handle)
        threading.Thread(target=do_reg, daemon=True).start()
    
    def _change_pw(self, p):
        pw = self._ask_pw("New Password")
        if pw: self.user_mgr.users[self.current_user]["pw"] = hashlib.sha256(pw.encode()).hexdigest(); self.user_mgr._save(); messagebox.showinfo("✅","Changed.")
    
    def _del_acc(self, p):
        if messagebox.askyesno("⚠️",f"DELETE '{self.current_user}'?"):
            if self.vault.server: self.vault.stop_server()
            shutil.rmtree(self.user_mgr.vault_dir(self.current_user), ignore_errors=True)
            self.face_auth.reset(self.current_user)
            del self.user_mgr.users[self.current_user]; self.user_mgr._save()
            p.destroy(); self._show_login()
    
    def _logout(self):
        if self.vault:
            if self.vault.server: self.vault.stop_server()
            self.vault._log("LOGOUT", self.current_user)
        self.current_user = self.vault = self.vault_key = None; self._show_login()

def main():
    if not TK_OK: print("ERROR: tkinter required."); return
    print("SecureVault v4.3 | Netanix Labs")
    print("EXE-Compatible with bulletproof cascade loading")
    if LBPH_OK: print("✓ LBPH Face Recognizer: ACTIVE")
    elif CV2_OK: print("⚠ OpenCV OK, LBPH not available")
    else: print("✗ pip install opencv-contrib-python pillow")
    root = tk.Tk(); App(root)
    sw, sh = root.winfo_screenwidth(), root.winfo_screenheight()
    root.geometry(f"1080x700+{(sw-1080)//2}+{(sh-700)//2}"); root.mainloop()

if __name__ == "__main__": main()
