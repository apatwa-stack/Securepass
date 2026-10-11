# SecurePass 🔐

SecurePass is a lightweight cryptographic password generator, vault, and security assessment service built with **Python (Flask)**, **SQLite3**, and native **C interoperability**.

It provides both an interactive web dashboard and a standard JSON REST API.

---

## 🌟 Features

1. **Configurable Password Generator**: Generates unpredictable passwords using Python's cryptographically secure `secrets` module. Configurable by length and character types (uppercase, lowercase, digits, symbols).
2. **PBKDF2 Hashing & Verification**: Uses `hashlib.pbkdf2_hmac` (SHA-256, 100,000 iterations) and 16-byte cryptographic salts. Compares hashes in constant time using `secrets.compare_digest` to prevent timing attacks.
3. **Native C Integration (`ctypes`)**: Calls a compiled C function (`password_check.c`) directly from Python to evaluate password strength (score 0–100).
4. **SQLite Database Persistence**: Securely stores and manages saved credentials in `passwords.db` using parameterized SQL queries to prevent SQL injection.
5. **Interactive Web Dashboard**: A single-page interface with direct controls to generate, hash, verify, and store credentials.

---

## 📁 Project Structure

```text
Securepass/
├── app.py                  # Flask web server & REST API endpoints
├── database.py             # SQLite database layer (table creation, CRUD operations)
├── requirements.txt        # Dependencies (Flask >= 3.0.0)
├── test_app.py             # Automated unit tests (7 test cases)
│
├── c_module/               # Native C code
│   ├── password_check.c    # C function calculating password strength score
│   └── build_c.py          # Cross-platform compiler script (Clang/GCC)
│
├── templates/
│   └── index.html          # Web dashboard user interface
│
└── static/
    └── style.css           # Styling for the web dashboard
```

---

## 🚀 Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Compile the C Module (Optional)
If GCC or Clang is installed on your system:
```bash
python c_module/build_c.py
```
*(If no C compiler is available, SecurePass automatically uses a built-in Python fallback).*

### 3. Run the Application
```bash
python app.py
```
Open your browser and navigate to: **http://127.0.0.1:5000**

### 4. Run Unit Tests
```bash
python test_app.py
```

---

## 📡 REST API Reference

| Method | Endpoint | Description | Request Body Example |
| :--- | :--- | :--- | :--- |
| `GET` | `/` | Web dashboard | *None* |
| `POST` | `/api/generate` | Generate secure password | `{"length": 16, "upper": true, "lower": true, "digits": true, "symbols": true}` |
| `POST` | `/api/hash` | Compute PBKDF2 hash | `{"password": "MySecretPassword"}` |
| `POST` | `/api/verify` | Verify candidate password | `{"password": "MySecretPassword", "salt": "<hex>", "hash": "<hex>"}` |
| `POST` | `/api/check_strength` | Calculate strength via C | `{"password": "MySecretPassword"}` |
| `GET` | `/api/passwords` | Retrieve all saved entries | *None* |
| `POST` | `/api/passwords` | Save credential entry | `{"service_name": "GitHub", "username": "user", "password": "pass"}` |
| `DELETE` | `/api/passwords/<id>` | Delete saved credential | *None* |

---

## 🛠️ Tech Stack

- **Backend**: Python 3, Flask
- **Native Extension**: C99 (compiled to `.dll` on Windows / `.so` on Linux via `ctypes`)
- **Database**: SQLite3
- **Frontend**: HTML5, CSS3, JavaScript (Fetch API)
- **Testing**: Python `unittest`
