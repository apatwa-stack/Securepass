"""
database.py: Simple SQLite database for storing passwords.
Compatible with both local environments and serverless platforms like Vercel.
"""
import os
import sqlite3
import tempfile
from pathlib import Path

def get_db_path() -> Path:
    # On Vercel, AWS Lambda, or serverless environments, the project root is read-only.
    # We use the system temporary directory (/tmp on Linux/Vercel) as writable storage.
    if os.environ.get("VERCEL") or os.environ.get("AWS_LAMBDA_FUNCTION_NAME"):
        return Path(tempfile.gettempdir()) / "passwords.db"

    local_path = Path(__file__).resolve().parent / "passwords.db"
    try:
        # Check if local directory is writable
        test_file = Path(__file__).resolve().parent / ".write_test"
        test_file.touch(exist_ok=True)
        test_file.unlink(missing_ok=True)
        return local_path
    except (OSError, PermissionError):
        return Path(tempfile.gettempdir()) / "passwords.db"

DB_FILE = get_db_path()

def get_connection():
    global DB_FILE
    try:
        conn = sqlite3.connect(str(DB_FILE))
        conn.row_factory = sqlite3.Row
        return conn
    except sqlite3.OperationalError:
        # Fallback to temp directory if current path fails
        DB_FILE = Path(tempfile.gettempdir()) / "passwords.db"
        try:
            conn = sqlite3.connect(str(DB_FILE))
            conn.row_factory = sqlite3.Row
            return conn
        except sqlite3.OperationalError:
            conn = sqlite3.connect(":memory:", check_same_thread=False)
            conn.row_factory = sqlite3.Row
            return conn

def init_db():
    """Creates the passwords table if it does not exist yet."""
    try:
        conn = get_connection()
        try:
            with conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS passwords (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        service_name TEXT NOT NULL,
                        username TEXT NOT NULL,
                        password_value TEXT NOT NULL,
                        hash_value TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    );
                """)
        finally:
            conn.close()
    except Exception as e:
        print(f"[!] Warning: Could not initialize database at {DB_FILE}: {e}")

def save_password(service_name: str, username: str, password_value: str, hash_value: str = ""):
    """Inserts a new password record using parameterized queries (safe from SQL injection)."""
    init_db()
    conn = get_connection()
    try:
        with conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO passwords (service_name, username, password_value, hash_value)
                VALUES (?, ?, ?, ?);
            """, (service_name.strip(), username.strip(), password_value.strip(), hash_value.strip()))
            return cursor.lastrowid
    finally:
        conn.close()

def get_all_passwords():
    """Retrieves all stored passwords, ordered from newest to oldest."""
    init_db()
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT id, service_name, username, password_value, hash_value, created_at FROM passwords ORDER BY id DESC;")
        rows = cursor.fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()

def delete_password(item_id: int):
    """Deletes a password entry by ID."""
    init_db()
    conn = get_connection()
    try:
        with conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM passwords WHERE id = ?;", (item_id,))
            return cursor.rowcount > 0
    finally:
        conn.close()

# Safe initialize on module load
init_db()

