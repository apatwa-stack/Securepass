import os, sqlite3, tempfile
from pathlib import Path

DB_FILE = Path(tempfile.gettempdir() if os.environ.get("VERCEL") else Path(__file__).parent) / "passwords.db"

def _execute(query, params=(), fetch=False):
    conn = sqlite3.connect(str(DB_FILE))
    conn.row_factory = sqlite3.Row
    try:
        with conn:
            cur = conn.execute(query, params)
            return [dict(r) for r in cur.fetchall()] if fetch else (cur.lastrowid or cur.rowcount)
    finally:
        conn.close()

def init_db():
    _execute("""CREATE TABLE IF NOT EXISTS passwords (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        service_name TEXT NOT NULL,
        username TEXT NOT NULL,
        password_value TEXT NOT NULL,
        hash_value TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""")

def save_password(service_name: str, username: str, password_value: str, hash_value: str = ""):
    return _execute(
        "INSERT INTO passwords (service_name, username, password_value, hash_value) VALUES (?, ?, ?, ?)",
        (service_name.strip(), username.strip(), password_value.strip(), hash_value.strip())
    )

def get_all_passwords():
    return _execute("SELECT * FROM passwords ORDER BY id DESC", fetch=True)

def delete_password(item_id: int) -> bool:
    return _execute("DELETE FROM passwords WHERE id = ?", (item_id,)) > 0

init_db()
