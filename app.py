"""
SecurePass Flask Web Server & REST Service.
Provides comprehensive endpoints for password generation, PBKDF2 hashing,
C-driven entropy analysis, and SQLite vault persistence.
"""

import os
import sys
from pathlib import Path
from flask import Flask, request, jsonify, render_template

# Add root directory to sys.path so modules import reliably
sys.path.insert(0, str(Path(__file__).resolve().parent))

from core.generator import (
    generate_password,
    generate_multiple_passwords,
    generate_passphrase,
    PasswordGenerationError
)
from core.hasher import (
    hash_password,
    verify_password,
    verify_encoded,
    PasswordHashingError,
    DEFAULT_ITERATIONS
)
from core.c_bridge import bridge
import database.db as db

app = Flask(__name__, template_folder='templates', static_folder='static')
app.config['JSON_SORT_KEYS'] = False

@app.route('/')
def index():
    """Serves the interactive web UI dashboard."""
    return render_template('index.html')

@app.route('/api/health', methods=['GET'])
def health_check():
    """System health check and diagnostic status."""
    return jsonify({
        "status": "healthy",
        "service": "SecurePass REST Service",
        "version": "1.0.0",
        "c_engine_loaded": bridge.is_c_loaded,
        "c_library_file": bridge._lib_path if bridge.is_c_loaded else None,
        "database": "SQLite3 (active)"
    }), 200

# --- Password Generation REST Endpoints ---

@app.route('/api/generate', methods=['POST', 'GET'])
def api_generate():
    """
    Generate secure passwords based on configurable parameters.
    Supports both JSON body (POST) and Query parameters (GET/POST).
    """
    data = request.get_json(silent=True) or request.args.to_dict()

    mode = data.get('mode', 'password')

    try:
        if mode == 'passphrase':
            word_count = int(data.get('word_count', 4))
            separator = str(data.get('separator', '-'))
            capitalize = str(data.get('capitalize', 'true')).lower() in ['true', '1', 'yes']
            include_number = str(data.get('include_number', 'true')).lower() in ['true', '1', 'yes']

            generated = generate_passphrase(
                word_count=word_count,
                separator=separator,
                capitalize=capitalize,
                include_number=include_number
            )
            analysis = bridge.analyze(generated)

            db.log_audit("GENERATE_PASSPHRASE", f"Generated passphrase (words: {word_count})", request.remote_addr)

            return jsonify({
                "mode": "passphrase",
                "password": generated,
                "analysis": analysis
            }), 200

        else:
            length = int(data.get('length', 16))
            include_uppercase = str(data.get('include_uppercase', 'true')).lower() in ['true', '1', 'yes']
            include_lowercase = str(data.get('include_lowercase', 'true')).lower() in ['true', '1', 'yes']
            include_digits = str(data.get('include_digits', 'true')).lower() in ['true', '1', 'yes']
            include_symbols = str(data.get('include_symbols', 'true')).lower() in ['true', '1', 'yes']
            exclude_ambiguous = str(data.get('exclude_ambiguous', 'false')).lower() in ['true', '1', 'yes']
            custom_exclude = data.get('custom_exclude', None)
            count = int(data.get('count', 1))

            if count > 1:
                passwords = generate_multiple_passwords(
                    count=count,
                    length=length,
                    include_uppercase=include_uppercase,
                    include_lowercase=include_lowercase,
                    include_digits=include_digits,
                    include_symbols=include_symbols,
                    exclude_ambiguous=exclude_ambiguous,
                    custom_exclude=custom_exclude
                )
                results = []
                for pw in passwords:
                    results.append({
                        "password": pw,
                        "analysis": bridge.analyze(pw)
                    })

                db.log_audit("GENERATE_BATCH", f"Batch generated {count} passwords", request.remote_addr)
                return jsonify({
                    "mode": "batch_passwords",
                    "count": count,
                    "passwords": results
                }), 200
            else:
                pw = generate_password(
                    length=length,
                    include_uppercase=include_uppercase,
                    include_lowercase=include_lowercase,
                    include_digits=include_digits,
                    include_symbols=include_symbols,
                    exclude_ambiguous=exclude_ambiguous,
                    custom_exclude=custom_exclude
                )
                analysis = bridge.analyze(pw)

                db.log_audit("GENERATE_PASSWORD", f"Generated password (length: {length})", request.remote_addr)
                return jsonify({
                    "mode": "password",
                    "password": pw,
                    "analysis": analysis,
                    "parameters": {
                        "length": length,
                        "include_uppercase": include_uppercase,
                        "include_lowercase": include_lowercase,
                        "include_digits": include_digits,
                        "include_symbols": include_symbols,
                        "exclude_ambiguous": exclude_ambiguous,
                        "custom_exclude": custom_exclude
                    }
                }), 200

    except PasswordGenerationError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500

# --- C Entropy Analysis REST Endpoint ---

@app.route('/api/analyze', methods=['POST'])
def api_analyze():
    """
    Evaluates password strength and entropy using native C shared library.
    """
    data = request.get_json(silent=True) or {}
    password = data.get('password', '')

    if not isinstance(password, str):
        return jsonify({"error": "Field 'password' must be a string."}), 400

    try:
        analysis = bridge.analyze(password)
        return jsonify(analysis), 200
    except Exception as e:
        return jsonify({"error": f"Analysis failed: {str(e)}"}), 500

# --- PBKDF2 Hashing and Verification REST Endpoints ---

@app.route('/api/hash', methods=['POST'])
def api_hash():
    """
    Hashes a password using PBKDF2 with CSPRNG salt via secrets and hashlib.
    """
    data = request.get_json(silent=True) or {}
    password = data.get('password')
    iterations = int(data.get('iterations', DEFAULT_ITERATIONS))
    algorithm = data.get('algorithm', 'sha256')
    custom_salt = data.get('salt')

    if not password:
        return jsonify({"error": "Field 'password' is required."}), 400

    try:
        result = hash_password(
            password=password,
            salt=custom_salt,
            iterations=iterations,
            algorithm=algorithm
        )
        db.log_audit("HASH_PASSWORD", f"Hashed password (iter: {iterations}, algo: {algorithm})", request.remote_addr)
        return jsonify(result), 200
    except PasswordHashingError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": f"Hashing failed: {str(e)}"}), 500

@app.route('/api/verify', methods=['POST'])
def api_verify():
    """
    Verifies a candidate password against PBKDF2 hash and salt using constant-time comparison.
    """
    data = request.get_json(silent=True) or {}
    password = data.get('password')
    encoded = data.get('encoded')

    if not password:
        return jsonify({"error": "Field 'password' is required."}), 400

    if encoded:
        valid = verify_encoded(password, encoded)
    else:
        stored_hash = data.get('stored_hash') or data.get('hash_hex')
        stored_salt = data.get('stored_salt') or data.get('salt_hex')
        iterations = int(data.get('iterations', DEFAULT_ITERATIONS))
        algorithm = data.get('algorithm', 'sha256')

        if not stored_hash or not stored_salt:
            return jsonify({"error": "Must provide either 'encoded' or ('stored_hash' and 'stored_salt')."}), 400

        valid = verify_password(
            password=password,
            stored_hash_hex=stored_hash,
            stored_salt_hex=stored_salt,
            iterations=iterations,
            algorithm=algorithm
        )

    db.log_audit("VERIFY_PASSWORD", f"Verification outcome: {valid}", request.remote_addr)
    return jsonify({
        "valid": valid,
        "message": "Password matches hash" if valid else "Password does not match hash"
    }), 200

# --- User Management REST Endpoints ---

@app.route('/api/users/register', methods=['POST'])
def api_register_user():
    """
    Registers a new user and persists their PBKDF2 hash & salt in SQLite.
    """
    data = request.get_json(silent=True) or {}
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"error": "Both 'username' and 'password' are required."}), 400

    if db.get_user_by_username(username):
        return jsonify({"error": f"Username '{username}' already exists."}), 409

    hashed = hash_password(password)
    user_id = db.create_user(
        username=username,
        password_hash=hashed['hash_hex'],
        salt=hashed['salt_hex'],
        iterations=hashed['iterations']
    )

    db.log_audit("USER_REGISTER", f"User registered: {username} (ID: {user_id})", request.remote_addr)
    return jsonify({
        "message": "User registered successfully.",
        "user_id": user_id,
        "username": username
    }), 201

@app.route('/api/users/login', methods=['POST'])
def api_login_user():
    """
    Authenticates a user by retrieving salt & hash from SQLite and verifying.
    """
    data = request.get_json(silent=True) or {}
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"error": "Both 'username' and 'password' are required."}), 400

    user = db.get_user_by_username(username)
    if not user:
        db.log_audit("LOGIN_FAILED", f"User not found: {username}", request.remote_addr)
        return jsonify({"authenticated": False, "error": "Invalid username or password."}), 401

    valid = verify_password(
        password=password,
        stored_hash_hex=user['password_hash'],
        stored_salt_hex=user['salt'],
        iterations=user['iterations']
    )

    if valid:
        db.log_audit("LOGIN_SUCCESS", f"User logged in: {username}", request.remote_addr)
        return jsonify({
            "authenticated": True,
            "message": "Login successful.",
            "user": {
                "id": user['id'],
                "username": user['username'],
                "created_at": user['created_at']
            }
        }), 200
    else:
        db.log_audit("LOGIN_FAILED", f"Incorrect password for user: {username}", request.remote_addr)
        return jsonify({"authenticated": False, "error": "Invalid username or password."}), 401

# --- SQLite Vault REST Endpoints ---

@app.route('/api/vault', methods=['GET', 'POST'])
def api_vault():
    """
    GET: List saved vault items.
    POST: Store a new credential into SQLite.
    """
    if request.method == 'GET':
        user_id = request.args.get('user_id', type=int)
        items = db.get_vault_items(user_id=user_id)
        return jsonify({"count": len(items), "vault": items}), 200

    elif request.method == 'POST':
        data = request.get_json(silent=True) or {}
        service_name = data.get('service_name')
        username_or_email = data.get('username_or_email')
        password_value = data.get('password_value')
        category = data.get('category', 'General')
        notes = data.get('notes', '')
        user_id = data.get('user_id')

        if not service_name or not username_or_email or not password_value:
            return jsonify({"error": "service_name, username_or_email, and password_value are required."}), 400

        item_id = db.create_vault_item(
            service_name=service_name,
            username_or_email=username_or_email,
            password_value=password_value,
            category=category,
            notes=notes,
            user_id=user_id
        )

        db.log_audit("VAULT_STORE", f"Stored credential for {service_name} (ID: {item_id})", request.remote_addr)
        return jsonify({
            "message": "Credential stored in SQLite vault successfully.",
            "item_id": item_id
        }), 201

@app.route('/api/vault/<int:item_id>', methods=['DELETE'])
def api_delete_vault(item_id):
    """Deletes a credential from the SQLite vault."""
    success = db.delete_vault_item(item_id)
    if success:
        db.log_audit("VAULT_DELETE", f"Deleted vault item ID {item_id}", request.remote_addr)
        return jsonify({"message": f"Vault item {item_id} deleted."}), 200
    else:
        return jsonify({"error": f"Item {item_id} not found."}), 404

# --- Audit Logs REST Endpoint ---

@app.route('/api/audit-logs', methods=['GET'])
def api_audit_logs():
    """Returns recent security audit logs."""
    limit = request.args.get('limit', default=50, type=int)
    logs = db.get_audit_logs(limit=limit)
    return jsonify({"count": len(logs), "logs": logs}), 200

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print(f"[*] Starting SecurePass server on http://127.0.0.1:{port}")
    app.run(host='127.0.0.1', port=port, debug=True)
