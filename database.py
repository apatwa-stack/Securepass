"""
database.py: Simple SQLite database for storing passwords.
"""
import sqlite3
from pathlib import Path

DB_FILE = Path(__file__).resolve().parent / "passwords.db"

def get_connection():
    conn = sqlite3.connect(str(DB_FILE))
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Creates the passwords table if it does not exist yet."""
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

def save_password(service_name: str, username: str, password_value: str, hash_value: str = ""):
    """Inserts a new password record using parameterized queries (safe from SQL injection)."""
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
    conn = get_connection()
    try:
        with conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM passwords WHERE id = ?;", (item_id,))
            return cursor.rowcount > 0
    finally:
        conn.close()

# Initialize DB on load
init_db()
