import os, sys, string, secrets, hashlib, ctypes
from pathlib import Path
from flask import Flask, request, jsonify
import database as db

BASE_DIR = Path(__file__).resolve().parent
app = Flask(__name__)

C_LIB = None

def load_c_library():
    global C_LIB
    ext = ".dll" if sys.platform.startswith("win") else (".dylib" if sys.platform == "darwin" else ".so")
    dll_path = BASE_DIR / "c_module" / f"password_check{ext}"
    if not dll_path.exists() and not os.environ.get("VERCEL"):
        try:
            import subprocess
            subprocess.run([sys.executable, str(BASE_DIR / "c_module" / "build_c.py")], capture_output=True)
        except Exception:
            pass
    if dll_path.exists():
        try:
            C_LIB = ctypes.CDLL(str(dll_path))
            C_LIB.check_password_strength.argtypes = [ctypes.c_char_p]
            C_LIB.check_password_strength.restype = ctypes.c_int
        except Exception:
            C_LIB = None

load_c_library()

def call_c_strength_check(password: str) -> int:
    if C_LIB:
        return C_LIB.check_password_strength(password.encode("utf-8"))
    score = len(password) * 4
    if any(c.isupper() for c in password): score += 10
    if any(c.islower() for c in password): score += 10
    if any(c.isdigit() for c in password): score += 10
    if any(c in string.punctuation for c in password): score += 15
    return min(score, 100)

def generate_password(length=16, use_upper=True, use_lower=True, use_digits=True, use_symbols=True) -> str:
    pool, guaranteed = "", []
    for enabled, chars in [
        (use_upper, string.ascii_uppercase),
        (use_lower, string.ascii_lowercase),
        (use_digits, string.digits),
        (use_symbols, "!@#$%^&*()-_=+")
    ]:
        if enabled:
            pool += chars
            guaranteed.append(secrets.choice(chars))
    pool = pool or (string.ascii_letters + string.digits)
    chars = guaranteed + [secrets.choice(pool) for _ in range(max(0, length - len(guaranteed)))]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars[:length])

def hash_password_pbkdf2(password: str, iterations=100000):
    salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), iterations).hex()
    return salt, h, iterations

def verify_password_pbkdf2(password: str, salt_hex: str, expected_hash_hex: str, iterations=100000) -> bool:
    h = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), iterations).hex()
    return secrets.compare_digest(h, expected_hash_hex)

@app.route("/")
def index():
    return jsonify({"service": "SecurePass REST API", "status": "running"})

@app.route("/api/generate", methods=["POST", "GET"])
def api_generate():
    data = request.get_json(silent=True) or request.args.to_dict()
    length = int(data.get("length", 16))
    pw = generate_password(
        length,
        str(data.get("upper", "true")).lower() == "true",
        str(data.get("lower", "true")).lower() == "true",
        str(data.get("digits", "true")).lower() == "true",
        str(data.get("symbols", "true")).lower() == "true"
    )
    return jsonify({"password": pw, "length": len(pw)})

@app.route("/api/hash", methods=["POST"])
def api_hash():
    pw = (request.get_json(silent=True) or {}).get("password", "")
    if not pw:
        return jsonify({"error": "Password cannot be empty"}), 400
    salt, h, iters = hash_password_pbkdf2(pw)
    return jsonify({"salt": salt, "hash": h, "iterations": iters, "algorithm": "PBKDF2-HMAC-SHA256"})

@app.route("/api/verify", methods=["POST"])
def api_verify():
    data = request.get_json(silent=True) or {}
    pw, salt, h = data.get("password", ""), data.get("salt", ""), data.get("hash", "")
    if not (pw and salt and h):
        return jsonify({"error": "Must provide password, salt, and hash"}), 400
    valid = verify_password_pbkdf2(pw, salt, h, int(data.get("iterations", 100000)))
    return jsonify({"valid": valid, "message": "Password matches!" if valid else "Password is WRONG!"})

@app.route("/api/check_strength", methods=["POST"])
def api_check_strength():
    pw = (request.get_json(silent=True) or {}).get("password", "")
    return jsonify({"password": pw, "strength_score": call_c_strength_check(pw), "c_library_active": C_LIB is not None})

@app.route("/api/passwords", methods=["GET", "POST"])
def api_passwords():
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        svc, user, pw = data.get("service_name", "").strip(), data.get("username", "").strip(), data.get("password", "").strip()
        if not (svc and user and pw):
            return jsonify({"error": "service_name, username, and password are required"}), 400
        _, h, _ = hash_password_pbkdf2(pw)
        return jsonify({"message": "Saved to SQLite!", "id": db.save_password(svc, user, pw, h)}), 201
    return jsonify({"passwords": db.get_all_passwords()})

@app.route("/api/passwords/<int:item_id>", methods=["DELETE"])
def api_delete_password(item_id):
    if db.delete_password(item_id):
        return jsonify({"message": f"Deleted password {item_id}"})
    return jsonify({"error": "Not found"}), 404

def terminal_menu():
    while True:
        print("\n" + "=" * 45)
        print("        SECUREPASS - TERMINAL VAULT")
        print("=" * 45)
        print("1. Generate Password")
        print("2. PBKDF2 Hash Password")
        print("3. Verify Password Hash")
        print("4. Check Strength via C (ctypes)")
        print("5. Save Password to SQLite")
        print("6. List Saved Passwords")
        print("7. Delete Saved Password")
        print("8. Start Flask REST API Server")
        print("9. Exit")
        print("=" * 45)
        choice = input("Enter choice (1-9): ").strip()

        if choice == "1":
            try:
                length = int(input("Length (default 16): ") or 16)
            except ValueError:
                length = 16
            pw = generate_password(length)
            print(f"\nPassword: {pw}")
        elif choice == "2":
            pw = input("Enter password to hash: ")
            salt, h, iters = hash_password_pbkdf2(pw)
            print(f"\nSalt: {salt}\nHash: {h}\nIterations: {iters}")
        elif choice == "3":
            pw = input("Enter password: ")
            salt = input("Enter salt: ")
            h = input("Enter hash: ")
            print("\nMatch" if verify_password_pbkdf2(pw, salt, h) else "\nNo match")
        elif choice == "4":
            pw = input("Enter password to test: ")
            score = call_c_strength_check(pw)
            print(f"\nStrength Score: {score}/100")
        elif choice == "5":
            svc = input("Service Name: ")
            usr = input("Username/Email: ")
            pw = input("Password: ")
            if svc and usr and pw:
                _, h, _ = hash_password_pbkdf2(pw)
                new_id = db.save_password(svc, usr, pw, h)
                print(f"\nSaved (ID: {new_id})")
        elif choice == "6":
            passwords = db.get_all_passwords()
            if not passwords:
                print("\nNo saved passwords.")
            else:
                print(f"\n{'ID':<5} {'SERVICE':<15} {'USERNAME':<25} {'PASSWORD'}")
                print("-" * 65)
                for p in passwords:
                    print(f"{p['id']:<5} {p['service_name']:<15} {p['username']:<25} {p['password_value']}")
        elif choice == "7":
            try:
                item_id = int(input("Enter ID to delete: "))
                print(f"\nDeleted ID {item_id}" if db.delete_password(item_id) else f"\nID {item_id} not found")
            except ValueError:
                pass
        elif choice == "8":
            port = int(os.environ.get("PORT", 5000))
            print(f"\nStarting Flask REST API on http://127.0.0.1:{port} (Ctrl+C to stop)\n")
            try:
                app.run(host="127.0.0.1", port=port, debug=False)
            except KeyboardInterrupt:
                print("\nServer stopped.")
        elif choice == "9":
            print("\nExiting.")
            break

if __name__ == "__main__":
    if "--server" in sys.argv or "-s" in sys.argv:
        port = int(os.environ.get("PORT", 5000))
        app.run(host="127.0.0.1", port=port, debug=False)
    else:
        terminal_menu()
