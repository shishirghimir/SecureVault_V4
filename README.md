# 🔐 SecureVault v4.3

**Face-Authenticated Encrypted File Vault**

A secure file vault application featuring LBPH face recognition with eye-open detection and AES-256-CBC encryption. Built entirely with custom data structures for academic demonstration.

![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)
![OpenCV](https://img.shields.io/badge/OpenCV-4.x-green.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

---

## ✨ Features

- **Face Authentication** — LBPH face recognizer with 98% accuracy
- **Eye-Open Detection** — Anti-spoofing measure blocks closed-eye bypass attempts
- **AES-256-CBC Encryption** — Pure Python implementation, all files encrypted at rest
- **Custom Data Structures** — LinkedList, HashMap, PriorityQueue (no built-in collections)
- **Multi-User Vaults** — Isolated encrypted storage per user
- **File Locking** — Double encryption with user password
- **Network Sharing** — Built-in HTTP server for LAN file sharing
- **Audit Logging** — Complete activity trail with timestamps

---


## 🛠️ Installation

### Prerequisites
- Python 3.10 or higher
- Webcam for face authentication

### Install Dependencies
```bash
pip install opencv-contrib-python pillow
```

### Run Application
```bash
python securevault.py
```

---

## 🏗️ Architecture

### Custom Data Structures

| Structure | Purpose | Complexity |
|-----------|---------|------------|
| `CustomLinkedList` | Audit log with auto-eviction | O(1) append |
| `CustomHashMap` | File index, user registry (FNV-1a) | O(1) average |
| `PriorityQueue` | File sorting (min-heap) | O(log n) push/pop |

### Security Components

| Component | Implementation |
|-----------|----------------|
| Encryption | AES-256-CBC with PKCS7 padding |
| Key Derivation | PBKDF2-HMAC-SHA256 (100,000 iterations) |
| Face Recognition | OpenCV LBPH with histogram matching fallback |
| Anti-Spoofing | Haar cascade eye detection (both eyes required) |


---

## 🧪 Testing

Run unit tests:
```bash
python -m unittest test_securevault -v
```

**Test Coverage:**
| Module | Tests |
|--------|-------|
| CustomLinkedList | 6 |
| CustomHashMap | 6 |
| PriorityQueue | 2 |
| AES256 | 9 |
| UserManager | 9 |
| VaultEngine | 11 |
| FaceAuth | 3 |
| **Total** | **46** |

---

## 🔒 Security Notes

- All files encrypted at rest using AES-256-CBC
- Passwords hashed with SHA-256
- Vault keys derived using PBKDF2 (50,000 iterations)
- Face data stored locally, never transmitted
- Eye-open detection prevents photo-based attacks

---

## 📋 Requirements

```
opencv-contrib-python>=4.8.0
pillow>=10.0.0
```

---

## 👨‍💻 Author

**Netanix Labs**

Developed as coursework for BSc Ethical Hacking and Cybersecurity.

---

## 📄 License

This project is licensed under the MIT License.

---

## 🙏 Acknowledgments

- OpenCV for face detection and recognition
- Python cryptography community for AES reference implementations
