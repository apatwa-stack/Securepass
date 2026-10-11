# Plain English Guide: How to Explain Every Single Point to Your Professor

This guide explains **every single requirement from your lab task slide** in simple, plain English. You can read this before meeting your professor so you understand 100% of the code and can explain it smoothly without feeling nervous.

---

## Slide Point 1: "Generate passwords based on configurable parameters"

### Where is the code?
Inside [`app.py`](app.py), function `generate_password()`:
```python
def generate_password(length=16, use_upper=True, use_lower=True, use_digits=True, use_symbols=True):
```

### How to explain it simply:
> *"Professor, my generator function accepts parameters for length and boolean flags for uppercase, lowercase, numbers, and symbols.  
> Instead of using Python's basic `random` module, I used the **`secrets`** module (`secrets.choice`), which draws true cryptographic randomness from the operating system.  
> First, it guarantees at least one character from each enabled category so the password is never missing a required type. Then, it fills the rest of the requested length from the character pool, and finally shuffles the characters so their positions are random."*

---

## Slide Point 2: "Offer this as a REST service"

### Where is the code?
Inside [`app.py`](app.py), routes like:
- `@app.route("/api/generate", methods=["POST", "GET"])`
- `@app.route("/api/hash", methods=["POST"])`
- `@app.route("/api/verify", methods=["POST"])`
- `@app.route("/api/passwords", methods=["GET", "POST"])`
- `@app.route("/api/check_strength", methods=["POST"])`

### How to explain it simply:
> *"Professor, I structured the backend as a RESTful JSON API. Any client — like a web browser, mobile app, or a command-line tool using `curl` — can send HTTP requests (GET, POST, DELETE) with JSON bodies, and the server returns standard JSON data along with standard HTTP status codes (`200 OK`, `201 Created`, `400 Bad Request`)."*

---

## Slide Point 3: "Use Flask as a webserver"

### Where is the code?
At the top and bottom of [`app.py`](app.py):
```python
from flask import Flask, request, jsonify, render_template

app = Flask(__name__)
...
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
```

### How to explain it simply:
> *"I used Flask because it is Python's most lightweight and flexible web framework. It handles the HTTP routing, parses incoming JSON payloads with `request.get_json()`, formats JSON responses with `jsonify()`, and serves the frontend user interface using `render_template('index.html')`."*

---

## Slide Point 4: "Use SQLite for persisting data"

### Where is the code?
In [`database.py`](database.py):
```python
def init_db():
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
```

### How to explain it simply:
> *"I used Python's built-in `sqlite3` library. It creates a local relational database file called `passwords.db`.  
> It has a table called `passwords` with columns for ID, service name, username, password value, its hash, and timestamp.  
> To protect against SQL injection attacks, I always use parameterized SQL queries with `?` placeholders instead of concatenating strings."*

---

## Slide Point 5: "Use secrets and hashlib to realize a pbkdf2 based password hashing"

### Where is the code?
In [`app.py`](app.py), functions `hash_password_pbkdf2()` and `verify_password_pbkdf2()`:
```python
salt_hex = secrets.token_hex(16)
derived_bytes = hashlib.pbkdf2_hmac(
    hash_name="sha256",
    password=password.encode("utf-8"),
    salt=bytes.fromhex(salt_hex),
    iterations=100000
)
```

### How to explain it simply:
> *"To hash passwords securely, I used two standard Python libraries:
> 1. **`secrets.token_hex(16)`**: Generates a cryptographically random 16-byte salt for each password. This ensures that even if two users have the same password, their hashes are completely different, defeating rainbow tables.
> 2. **`hashlib.pbkdf2_hmac`**: Computes PBKDF2 using SHA-256 with 100,000 iterations. The high iteration count intentionally slows down the calculation so an attacker cannot brute-force passwords quickly with GPUs.
> 3. **`secrets.compare_digest`**: When verifying passwords, I use constant-time comparison to prevent side-channel timing attacks."*

---

## Slide Point 6: "Revise your C coding by calling a C function from your python code"

### Where is the code?
- The C source file: [`c_module/password_check.c`](c_module/password_check.c)
- The compiled DLL: `c_module/password_check.dll`
- The Python call: inside [`app.py`](app.py) using `ctypes`

```c
// In C (password_check.c):
EXPORT int check_password_strength(const char *password) {
    int len = (int)strlen(password);
    // loops through characters, checks upper, lower, digits, symbols
    // returns a score from 0 to 100
}
```

```python
# In Python (app.py):
import ctypes
c_lib = ctypes.CDLL("./c_module/password_check.dll")
c_lib.check_password_strength.argtypes = [ctypes.c_char_p]
c_lib.check_password_strength.restype = ctypes.c_int

score = c_lib.check_password_strength(password.encode("utf-8"))
```

### How to explain it simply:
> *"Professor, I wrote a C function called `check_password_strength` in `password_check.c`. It takes a password string, loops through each character in native C code, checks whether it contains uppercase, lowercase, numbers, or symbols, and computes a score from 0 to 100 based on length and variety.  
> To call it from Python, I compiled it into a shared library (`.dll` on Windows / `.so` on Linux) and used Python's built-in **`ctypes`** library. `ctypes` allows Python to load compiled C libraries, set the argument types (`c_char_p`), pass data directly to C, and receive the integer return value with native execution speed."*

---

## Slide Point 7: "Upload your code to HSO Github repo (https://edugit.hs-offenburg.de) and invite me as reporter"

### How to explain it simply:
> *"I pushed the code to my project repository on the university's GitLab platform (`https://edugit.hs-offenburg.de`). Under the project's 'Members' settings, I invited you with the role **Reporter** so you have full read access to inspect the repository and test the code."*

---

## Slide Point 8: "Submit: your repo link AND report (3-5 pages) to Moodle"

### How to explain it simply:
> *"I submitted my EduGit repository link and attached a comprehensive 4-page PDF report (`SecurePass_Academic_Report.pdf`) explaining the architecture, the cryptographic reasoning behind PBKDF2, the C integration using ctypes, and the test results."*
