# SecurePass: Cryptographic Password Service & REST API

[![Tests](https://img.shields.io/badge/tests-27%20passed-brightgreen.svg)]()
[![Python](https://img.shields.io/badge/python-3.9%20%7C%203.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue.svg)]()
[![C-Language](https://img.shields.io/badge/native-C99%20via%20ctypes-orange.svg)]()
[![Database](https://img.shields.io/badge/storage-SQLite3-lightgrey.svg)]()

SecurePass is an enterprise-grade cryptographic password generator, vault, and security assessment service built with **Python 3**, **Flask**, **SQLite3**, and native **C interoperability**.

---

## 🌟 Key Features

1. **Configurable Password & Passphrase Generator**
   - Cryptographically secure randomness powered by the OS CSPRNG (`secrets` module).
   - Fully customizable character classes (uppercase, lowercase, digits, symbols).
   - Ambiguous character filtering (`1`, `l`, `I`, `0`, `O`, etc.) and custom character blacklisting.
   - Guaranteed minimum distribution policy and Diceware passphrase mode.

2. **PBKDF2-HMAC-SHA256 Password Hashing**
   - Implemented using Python's `secrets` and `hashlib` standard libraries.
   - High-entropy salt generation (256-bit / 32 bytes via `secrets.token_bytes`).
   - Configurable work factor (default: **600,000 iterations**, aligned with current OWASP recommendations).
   - Timing-attack-resistant constant-time verification using `secrets.compare_digest`.

3. **High-Performance C Entropy Engine (Native C Interoperability)**
   - Core security analysis routines implemented in C99 (`c_modules/entropy_analyzer.c`).
   - Shannon Information Entropy calculation: $H(X) = -\sum p_i \log_2(p_i)$.
   - Combinatorial search space analysis and offline GPU brute-force crack-time estimation ($10^{10}$ hashes/second).
   - Seamless Python-to-C binding via Python's standard `ctypes` library, with automatic compilation and zero-downtime Python fallback.

4. **Thread-Safe SQLite3 Persistence Layer**
   - Tables for users, credential vaults, and operational security audit logs.
   - Parameterized queries to eliminate SQL injection vectors.
   - Foreign keys and cascade deletion support.

5. **RESTful Web Service & Interactive Dashboard**
   - JSON REST API over HTTP powered by Flask.
   - Modern, responsive web frontend with real-time entropy gauges, copy-to-clipboard, vault management, and API documentation.

---

## 📁 Project Architecture

```
Securepass/
├── c_modules/                      # Native C Code & Build Toolchain
│   ├── entropy_analyzer.h          # C Header (structs and exported symbols)
│   ├── entropy_analyzer.c          # C Implementation (Shannon entropy & analysis)
│   ├── Makefile                    # Cross-platform Makefile (Windows, Linux, macOS)
│   └── build.py                    # Automated Python compiler & build script
├── core/                           # Core Cryptographic & Interop Modules
│   ├── __init__.py
│   ├── generator.py                # CSPRNG generator (secrets module)
│   ├── hasher.py                   # PBKDF2 hasher & verifier (secrets + hashlib)
│   └── c_bridge.py                 # Python ctypes bridge to native C shared library
├── database/                       # SQLite3 Persistence Layer
│   ├── __init__.py
│   └── db.py                       # Connection pooling, CRUD & audit logging
├── static/                         # Frontend Assets
│   ├── css/style.css               # Modern responsive styling
│   └── js/app.js                   # Client-side API integration & reactive UI
├── templates/                      # Flask HTML Templates
│   └── index.html                  # Interactive Single-Page Dashboard
├── tests/                          # Automated Unit & Integration Tests
│   ├── test_generator.py           # Parameter validation & randomness tests
│   ├── test_hasher.py              # Salt uniqueness & PBKDF2 verification tests
│   ├── test_c_bridge.py            # C foreign function interface tests
│   └── test_api.py                 # Flask REST endpoints integration tests
├── report/                         # Academic Report
│   ├── REPORT.md                   # 3-5 Page Technical Report
│   └── generate_report_pdf.py      # Automated report PDF/HTML generator
├── .gitlab-ci.yml                  # GitLab CI pipeline for HSO Edugit
├── .gitignore                      # Git exclusion rules
├── edugit_instructions.md          # Step-by-step submission guide for Edugit
├── requirements.txt                # Python dependencies
├── app.py                          # Main Flask Application Entry Point
└── README.md                       # Documentation
```

---

## 🚀 Quick Start Guide

### 1. Prerequisites
- Python 3.9+ (Python 3.13 recommended)
- GCC, Clang, or MSVC compiler (optional; automatically detected by `build.py`)

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Compile the C Module
Compile the C shared library (`.dll` on Windows, `.so` on Linux):
```bash
python c_modules/build.py
```
*(If no compiler is installed on the host, SecurePass automatically uses its built-in Python fallback engine).*

### 4. Run Automated Tests
Execute the full test suite (27 unit and integration tests):
```bash
python -m unittest discover -s tests -p "test_*.py" -v
```

### 5. Launch the Web Server
Start the Flask web service:
```bash
python app.py
```
Open your browser and navigate to:
👉 **`http://127.0.0.1:5000`**

---

## 📡 REST API Reference

### 1. Health Check
- **`GET /api/health`**
- **Response:**
  ```json
  {
    "status": "healthy",
    "service": "SecurePass REST Service",
    "c_engine_loaded": true,
    "c_library_file": "libentropy.dll",
    "database": "SQLite3 (active)"
  }
  ```

---

### 2. Generate Password
- **`POST /api/generate`**
- **Request Body (JSON):**
  ```json
  {
    "length": 20,
    "include_uppercase": true,
    "include_lowercase": true,
    "include_digits": true,
    "include_symbols": true,
    "exclude_ambiguous": false,
    "count": 1
  }
  ```
- **Response (JSON):**
  ```json
  {
    "mode": "password",
    "password": "x9#Wk!82Lq@mZ19$vP3&",
    "analysis": {
      "engine": "Native C Library via ctypes",
      "shannon_entropy_bits": 74.44,
      "pool_entropy_bits": 131.4,
      "crack_time_human": "Centuries / Practically Uncrackable",
      "strength_score": 100,
      "strength_label": "Very Strong"
    }
  }
  ```

---

### 3. Generate Passphrase (Diceware Mode)
- **`POST /api/generate`**
- **Request Body:**
  ```json
  {
    "mode": "passphrase",
    "word_count": 4,
    "separator": "-",
    "capitalize": true,
    "include_number": true
  }
  ```
- **Response:**
  ```json
  {
    "mode": "passphrase",
    "password": "Breeze-Canary-Cosmos-Anchor-42"
  }
  ```

---

### 4. PBKDF2 Password Hashing
- **`POST /api/hash`**
- **Request Body:**
  ```json
  {
    "password": "MasterUserPassword123!",
    "iterations": 600000,
    "algorithm": "sha256"
  }
  ```
- **Response:**
  ```json
  {
    "algorithm": "sha256",
    "iterations": 600000,
    "salt_hex": "31d946928ab4ee33cbb2051ea437ca81...",
    "hash_hex": "515352d24ba9d931bffe933bc818edc9...",
    "encoded": "pbkdf2:sha256:600000$31d9469...$515352..."
  }
  ```

---

### 5. Constant-Time Password Verification
- **`POST /api/verify`**
- **Request Body:**
  ```json
  {
    "password": "MasterUserPassword123!",
    "encoded": "pbkdf2:sha256:600000$31d9469...$515352..."
  }
  ```
- **Response:**
  ```json
  {
    "valid": true,
    "message": "Password matches hash"
  }
  ```

---

### 6. C-Native Entropy Analysis
- **`POST /api/analyze`**
- **Request Body:**
  ```json
  {
    "password": "CandidatePassword!99"
  }
  ```

---

### 7. SQLite Vault CRUD
- **`GET /api/vault`**: List all saved credentials.
- **`POST /api/vault`**: Save new credential (`service_name`, `username_or_email`, `password_value`, `category`).
- **`DELETE /api/vault/<id>`**: Delete credential by ID.

---

## 🔒 Security Architecture Highlights

1. **CSPRNG vs Pseudo-Randomness**: We strictly avoid `random.random()` or `random.choice()`. All entropy originates from `os.urandom()` through Python's `secrets` module, preventing linear congruential or Mersenne Twister predictability attacks.
2. **Work Factor Calibration**: Using 600,000 iterations for PBKDF2-HMAC-SHA256 drastically slows down brute-force and dictionary attacks on leaked databases.
3. **Constant-Time Verification**: `secrets.compare_digest` prevents side-channel timing analysis that could reveal password lengths or character matches.
4. **C Memory Safety**: The C module performs strict bounds checking, defensive pointer validation, and fixed stack allocation, avoiding memory leaks or buffer overflows.

---

## 🎓 Hochschule Offenburg (HSO) Submission

For detailed step-by-step instructions on pushing this repository to **https://edugit.hs-offenburg.de** and inviting your instructor as "Reporter", please see [edugit_instructions.md](edugit_instructions.md).
