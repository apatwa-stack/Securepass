"""
SQLite3 Persistence Layer for SecurePass.
Provides thread-safe connections, parameterized statements, and automatic schema migration.
"""

import sqlite3
import os
from pathlib import Path
from typing import List, Dict, Any, Optional

DB_FILE = Path(__file__).resolve().parent / 'securepass.db'

def get_connection() -> sqlite3.Connection:
    """Returns a SQLite connection configured with Row factory and foreign keys enabled."""
    conn = sqlite3.connect(str(DB_FILE))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

def init_db():
    """Initializes SQLite database tables and indices."""
    conn = get_connection()
    try:
        with conn:
            cursor = conn.cursor()
            
            # 1. Users table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    salt TEXT NOT NULL,
                    iterations INTEGER NOT NULL DEFAULT 600000,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            # 2. Vault Items table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS vault_items (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    service_name TEXT NOT NULL,
                    username_or_email TEXT NOT NULL,
                    password_value TEXT NOT NULL,
                    category TEXT DEFAULT 'General',
                    notes TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
                )
            ''')

            # 3. Audit Logs table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    action TEXT NOT NULL,
                    ip_address TEXT DEFAULT '127.0.0.1',
                    details TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            # Indices for optimal query performance
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_vault_service ON vault_items(service_name);')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp);')
    finally:
        conn.close()

# --- User Management ---

def create_user(username: str, password_hash: str, salt: str, iterations: int = 600000) -> int:
    """Registers a new user with PBKDF2 hash credentials."""
    conn = get_connection()
    try:
        with conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO users (username, password_hash, salt, iterations)
                VALUES (?, ?, ?, ?)
            ''', (username.strip(), password_hash, salt, iterations))
            return cursor.lastrowid
    finally:
        conn.close()

def get_user_by_username(username: str) -> Optional[Dict[str, Any]]:
    """Retrieves a user by username."""
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username.strip(),))
        row = cursor.fetchone()
        if row:
            return dict(row)
        return None
    finally:
        conn.close()

def get_user_by_id(user_id: int) -> Optional[Dict[str, Any]]:
    """Retrieves a user by user ID."""
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
        row = cursor.fetchone()
        if row:
            return dict(row)
        return None
    finally:
        conn.close()

# --- Vault Management ---

def create_vault_item(
    service_name: str,
    username_or_email: str,
    password_value: str,
    category: str = 'General',
    notes: str = '',
    user_id: Optional[int] = None
) -> int:
    """Stores a generated or saved credential in the SQLite vault."""
    conn = get_connection()
    try:
        with conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO vault_items (user_id, service_name, username_or_email, password_value, category, notes)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (user_id, service_name.strip(), username_or_email.strip(), password_value, category.strip(), notes.strip()))
            return cursor.lastrowid
    finally:
        conn.close()

def get_vault_items(user_id: Optional[int] = None) -> List[Dict[str, Any]]:
    """Returns stored vault items, optionally filtered by user_id."""
    conn = get_connection()
    try:
        cursor = conn.cursor()
        if user_id is not None:
            cursor.execute('SELECT * FROM vault_items WHERE user_id = ? ORDER BY id DESC', (user_id,))
        else:
            cursor.execute('SELECT * FROM vault_items ORDER BY id DESC')
        rows = cursor.fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()

def get_vault_item_by_id(item_id: int) -> Optional[Dict[str, Any]]:
    """Returns a specific vault entry by ID."""
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM vault_items WHERE id = ?', (item_id,))
        row = cursor.fetchone()
        if row:
            return dict(row)
        return None
    finally:
        conn.close()

def delete_vault_item(item_id: int) -> bool:
    """Deletes a vault entry by ID."""
    conn = get_connection()
    try:
        with conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM vault_items WHERE id = ?', (item_id,))
            return cursor.rowcount > 0
    finally:
        conn.close()

# --- Audit Logging ---

def log_audit(action: str, details: str = '', ip_address: str = '127.0.0.1'):
    """Logs an operational security event into the audit table."""
    try:
        conn = get_connection()
        try:
            with conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO audit_logs (action, ip_address, details)
                    VALUES (?, ?, ?)
                ''', (action, ip_address, details))
        finally:
            conn.close()
    except Exception as e:
        print(f"[Audit Log Error] {e}")

def get_audit_logs(limit: int = 50) -> List[Dict[str, Any]]:
    """Returns recent audit logs."""
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT ?', (limit,))
        rows = cursor.fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()

# Initialize tables when module is imported
init_db()
