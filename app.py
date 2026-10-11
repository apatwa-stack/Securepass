"""
app.py: Flask Webserver & REST API for Password Service.
Features:
- Configurable password generation (secrets module)
- PBKDF2 hashing & verification (secrets + hashlib)
- SQLite database persistence (database.py)
- C function invocation for password strength (ctypes)
"""
import os
import sys
import string
import secrets
import hashlib
import ctypes
from pathlib import Path
from flask import Flask, request, jsonify, render_template

import database as db

app = Flask(__name__)

# --- 1. Load C Library via ctypes ---
C_LIB = None
C_MODULE_DIR = Path(__file__).resolve().parent / "c_module"

def load_c_library():
    global C_LIB
    if sys.platform.startswith("win"):
        dll_name = "password_check.dll"
    elif sys.platform == "darwin":
        dll_name = "password_check.dylib"
    else:
        dll_name = "password_check.so"

    dll_path = C_MODULE_DIR / dll_name
    if dll_path.exists():
        try:
            C_LIB = ctypes.CDLL(str(dll_path))
            # Define argument and return types for the C function
            C_LIB.check_password_strength.argtypes = [ctypes.c_char_p]
            C_LIB.check_password_strength.restype = ctypes.c_int
            print(f"[+] Loaded native C library: {dll_path.name}")
        except Exception as e:
            print(f"[!] Warning: Could not load C library: {e}")
            C_LIB = None

load_c_library()

def call_c_strength_check(password: str) -> int:
    """Calls the C function to calculate password strength (0 to 100)."""
    if C_LIB:
        return C_LIB.check_password_strength(password.encode("utf-8"))
    
    # Simple Python fallback if C library is not compiled
    score = len(password) * 4
    if any(c.isupper() for c in password): score += 10
    if any(c.islower() for c in password): score += 10
    if any(c.isdigit() for c in password): score += 10
    if any(c in string.punctuation for c in password): score += 15
    return min(score, 100)


# --- 2. Password Generation (secrets module) ---
def generate_password(length=16, use_upper=True, use_lower=True, use_digits=True, use_symbols=True) -> str:
    """Generates a secure password using the CSPRNG 'secrets' module."""
    pool = ""
    guaranteed = []

    if use_upper:
        pool += string.ascii_uppercase
        guaranteed.append(secrets.choice(string.ascii_uppercase))
    if use_lower:
        pool += string.ascii_lowercase
        guaranteed.append(secrets.choice(string.ascii_lowercase))
    if use_digits:
        pool += string.digits
        guaranteed.append(secrets.choice(string.digits))
    if use_symbols:
        pool += "!@#$%^&*()-_=+"
        guaranteed.append(secrets.choice("!@#$%^&*()-_=+"))

    if not pool:
        pool = string.ascii_letters + string.digits

    # Fill the remaining characters randomly using secrets.choice
    remaining_count = max(0, length - len(guaranteed))
    password_chars = guaranteed + [secrets.choice(pool) for _ in range(remaining_count)]

    # Shuffle characters using secrets.SystemRandom so order is unpredictable
    secrets.SystemRandom().shuffle(password_chars)
    return "".join(password_chars[:length])


# --- 3. PBKDF2 Password Hashing (secrets + hashlib) ---
def hash_password_pbkdf2(password: str, iterations=100000):
    """
    Hashes a password with PBKDF2:
    - Generates a unique 16-byte random salt using secrets.token_hex(16)
    - Hashes with hashlib.pbkdf2_hmac using SHA-256
    """
    salt_hex = secrets.token_hex(16)
    salt_bytes = bytes.fromhex(salt_hex)

    derived_bytes = hashlib.pbkdf2_hmac(
        hash_name="sha256",
        password=password.encode("utf-8"),
        salt=salt_bytes,
        iterations=iterations
    )
    hash_hex = derived_bytes.hex()
    return salt_hex, hash_hex, iterations

def verify_password_pbkdf2(password: str, salt_hex: str, expected_hash_hex: str, iterations=100000) -> bool:
    """Verifies a password against salt and hash using constant-time comparison."""
    salt_bytes = bytes.fromhex(salt_hex)
    candidate_bytes = hashlib.pbkdf2_hmac(
        hash_name="sha256",
        password=password.encode("utf-8"),
        salt=salt_bytes,
        iterations=iterations
    )
    candidate_hex = candidate_bytes.hex()
    # secrets.compare_digest prevents side-channel timing attacks
    return secrets.compare_digest(candidate_hex, expected_hash_hex)


# --- 4. Web & REST API Routes ---

@app.route("/")
def index():
    """Serves the simple single-page dashboard."""
    return render_template("index.html")

@app.route("/api/generate", methods=["POST", "GET"])
def api_generate():
    """REST endpoint: Generate a password with configurable parameters."""
    data = request.get_json(silent=True) or request.args.to_dict()
    length = int(data.get("length", 16))
    use_upper = str(data.get("upper", "true")).lower() == "true"
    use_lower = str(data.get("lower", "true")).lower() == "true"
    use_digits = str(data.get("digits", "true")).lower() == "true"
    use_symbols = str(data.get("symbols", "true")).lower() == "true"

    password = generate_password(length, use_upper, use_lower, use_digits, use_symbols)
    strength_score = call_c_strength_check(password)

    return jsonify({
        "password": password,
        "length": len(password),
        "strength_score": strength_score,
        "c_function_used": C_LIB is not None
    }), 200

@app.route("/api/hash", methods=["POST"])
def api_hash():
    """REST endpoint: Hash a password with PBKDF2."""
    data = request.get_json(silent=True) or {}
    password = data.get("password", "")
    if not password:
        return jsonify({"error": "Password cannot be empty"}), 400

    salt_hex, hash_hex, iterations = hash_password_pbkdf2(password)
    return jsonify({
        "salt": salt_hex,
        "hash": hash_hex,
        "iterations": iterations,
        "algorithm": "PBKDF2-HMAC-SHA256"
    }), 200

@app.route("/api/verify", methods=["POST"])
def api_verify():
    """REST endpoint: Verify a password against salt and hash."""
    data = request.get_json(silent=True) or {}
    password = data.get("password", "")
    salt = data.get("salt", "")
    stored_hash = data.get("hash", "")
    iterations = int(data.get("iterations", 100000))

    if not password or not salt or not stored_hash:
        return jsonify({"error": "Must provide password, salt, and hash"}), 400

    valid = verify_password_pbkdf2(password, salt, stored_hash, iterations)
    return jsonify({
        "valid": valid,
        "message": "Password matches!" if valid else "Password is WRONG!"
    }), 200

@app.route("/api/check_strength", methods=["POST"])
def api_check_strength():
    """REST endpoint: Directly calls C function via ctypes."""
    data = request.get_json(silent=True) or {}
    password = data.get("password", "")
    score = call_c_strength_check(password)
    return jsonify({
        "password": password,
        "strength_score": score,
        "c_library_active": C_LIB is not None
    }), 200

@app.route("/api/passwords", methods=["GET", "POST"])
def api_passwords():
    """REST endpoint: List all saved passwords or save a new one to SQLite."""
    if request.method == "GET":
        items = db.get_all_passwords()
        return jsonify({"passwords": items}), 200

    elif request.method == "POST":
        data = request.get_json(silent=True) or {}
        service = data.get("service_name", "").strip()
        username = data.get("username", "").strip()
        password = data.get("password", "").strip()

        if not service or not username or not password:
            return jsonify({"error": "service_name, username, and password are required"}), 400

        # Also store the PBKDF2 hash of the password
        salt, hash_val, _ = hash_password_pbkdf2(password)
        new_id = db.save_password(service, username, password, hash_val)
        return jsonify({"message": "Saved to SQLite!", "id": new_id}), 201

@app.route("/api/passwords/<int:item_id>", methods=["DELETE"])
def api_delete_password(item_id):
    """REST endpoint: Delete a password by ID from SQLite."""
    deleted = db.delete_password(item_id)
    if deleted:
        return jsonify({"message": f"Deleted password {item_id}"}), 200
    return jsonify({"error": "Not found"}), 404


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"[*] Starting Simple Password Service on http://127.0.0.1:{port}")
    app.run(host="127.0.0.1", port=port, debug=False)
