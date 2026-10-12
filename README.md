# SecurePass 🔐

SecurePass is a lightweight cryptographic password generator, vault, and security assessment service built with **Python (CLI & Flask REST API)**, **SQLite3**, and native **C interoperability**.

---

## 🌟 Features

1. **Interactive Terminal CLI**: Simple, menu-driven command-line interface to generate passwords, compute PBKDF2 hashes, verify candidate passwords, manage SQLite credentials, and run C strength checks.
2. **Configurable Password Generator**: Generates unpredictable passwords using Python's cryptographically secure `secrets` module. Configurable by length and character sets.
3. **PBKDF2 Hashing & Verification**: Uses `hashlib.pbkdf2_hmac` (SHA-256, 100,000 iterations) with 16-byte random salts and constant-time verification (`secrets.compare_digest`).
4. **Native C Integration (`ctypes`)**: Invokes a compiled C function (`password_check.c`) directly from Python for password strength evaluation (0–100).
5. **SQLite Database Persistence**: Securely stores credentials in `passwords.db` using parameterized SQL queries.
6. **REST Service**: Standard JSON REST endpoints for external API clients or automated tools.

---

## 📁 Project Structure

```text
Securepass/
├── app.py                  # Interactive Terminal CLI & REST API endpoints
├── database.py             # SQLite database layer (parameterized queries)
├── requirements.txt        # Dependencies (Flask >= 3.0.0)
├── test_app.py             # Automated unit tests (7 test cases)
└── c_module/               # Native C code
    ├── password_check.c    # C function calculating password strength score
    └── build_c.py          # Cross-platform compiler script (Clang/GCC)
```

---

## 🚀 Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Run Terminal CLI
```bash
python app.py
```
This launches the interactive terminal menu:
```text
=============================================
        SECUREPASS - TERMINAL VAULT
=============================================
1. Generate Password
2. PBKDF2 Hash Password
3. Verify Password Hash
4. Check Strength via C (ctypes)
5. Save Password to SQLite
6. List Saved Passwords
7. Delete Saved Password
8. Start Flask REST API Server
9. Exit
=============================================
```

### 3. Run REST API Directly (Optional)
To launch the REST service directly:
```bash
python app.py --server
```

### 4. Run Unit Tests
```bash
python test_app.py
```

---

## 📡 REST API Reference

| Method | Endpoint | Description | Request Body Example |
| :--- | :--- | :--- | :--- |
| `GET` | `/` | API status | *None* |
| `POST` | `/api/generate` | Generate secure password | `{"length": 16, "upper": true, "lower": true, "digits": true, "symbols": true}` |
| `POST` | `/api/hash` | Compute PBKDF2 hash | `{"password": "MySecretPassword"}` |
| `POST` | `/api/verify` | Verify candidate password | `{"password": "MySecretPassword", "salt": "<hex>", "hash": "<hex>"}` |
| `POST` | `/api/check_strength` | Calculate strength via C | `{"password": "MySecretPassword"}` |
| `GET` | `/api/passwords` | Retrieve all saved entries | *None* |
| `POST` | `/api/passwords` | Save credential entry | `{"service_name": "GitHub", "username": "user", "password": "pass"}` |
| `DELETE` | `/api/passwords/<id>` | Delete saved credential | *None* |
