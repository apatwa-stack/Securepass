# Student Cheat Sheet: How to Explain Your Project to the Professor

Keep this handy! If your professor asks you questions during your presentation or code review, here is how to explain everything in **simple, natural words**.

---

## 1. The Elevator Pitch (What does your project do?)

> *"I built **SecurePass**, a RESTful password service using Flask and SQLite. It generates strong, customized passwords using Python's `secrets` module, hashes them securely with PBKDF2, saves user credentials in an SQLite database, and calls a custom C function via `ctypes` to calculate the mathematical entropy (strength) of each password."*

---

## 2. Likely Questions & Exact Simple Answers

### Q1: "Why did you use the `secrets` module instead of `random`?"
**Your answer:**
> *"Python's standard `random` module uses Mersenne Twister, which is a pseudo-random generator designed for simulations, not security. If someone collects enough generated numbers, they can predict future outputs. The `secrets` module uses the operating system's cryptographic entropy source (`/dev/urandom` or `CryptGenRandom`), which is completely unpredictable."*

---

### Q2: "How does your password generator handle configurable parameters?"
**Your answer:**
> *"In `core/generator.py`, I accept parameters like `length`, `include_uppercase`, `include_lowercase`, `include_digits`, `include_symbols`, and `exclude_ambiguous`. I build a pool of allowed characters, use `secrets.choice()` to ensure at least one character from each selected category is chosen, fill the rest from the combined pool, and then shuffle them using a Fisher-Yates shuffle."*

---

### Q3: "How does your PBKDF2 hashing work?"
**Your answer:**
> *"In `core/hasher.py`, I use `hashlib.pbkdf2_hmac`. It takes four key inputs:
> 1. The pseudo-random function: **HMAC-SHA256**.
> 2. The password in UTF-8 bytes.
> 3. A unique 32-byte (256-bit) salt generated with `secrets.token_bytes(32)`.
> 4. An iteration work factor of **600,000 iterations**, which matches the latest OWASP recommendations to slow down GPU brute-force attacks."*

---

### Q4: "Why do you need a salt, and what is constant-time comparison?"
**Your answer:**
> *"The salt ensures that even if two users have the exact same password, their stored hashes will look completely different. This defends against pre-computed rainbow table attacks.
> Constant-time comparison (`secrets.compare_digest`) prevents timing attacks: regular `==` stops checking as soon as the first character is wrong, which leaks timing information. `compare_digest` takes the exact same amount of time regardless of mismatches."*

---

### Q5: "What does your C function do, and why write it in C?"
**Your answer:**
> *"My C module is in `c_modules/entropy_analyzer.c`. It calculates **Shannon Information Entropy** and password complexity. It counts character frequencies in a fast loop, computes the Shannon entropy formula $H = -\sum p_i \log_2(p_i)$, checks character pool diversity, and estimates offline GPU crack time. I wrote it in C because raw byte counting and logarithmic math on strings are fast in native compiled code."*

---

### Q6: "How does your Python code call the C function?"
**Your answer:**
> *"I compiled the C code into a shared library (`libentropy.dll` on Windows / `libentropy.so` on Linux). Then in `core/c_bridge.py`, I used Python's built-in `ctypes` module:
> 1. I loaded the library with `ctypes.CDLL()`.
> 2. I created a Python class subclassing `ctypes.Structure` matching the C struct.
> 3. I set `argtypes` and `restype` on the C function.
> 4. When called, Python passes the password string and a pointer to the struct, and C fills in the results."*

---

### Q7: "How is data stored in SQLite?"
**Your answer:**
> *"In `database/db.py`, I created three tables:
> - `users`: stores usernames and PBKDF2 password hashes + salts.
> - `vault_items`: stores credentials for services (service name, username, password).
> - `audit_logs`: records events with timestamps and IP addresses.
> To prevent SQL injection, I used parameterized queries with `?` placeholders everywhere."*

---

### Q8: "How did you test your project?"
**Your answer:**
> *"I wrote a complete test suite with 27 automated tests in the `tests/` folder using Python's `unittest` module. It tests parameter boundary checks, salt uniqueness, the C foreign function interface, and all Flask REST endpoints. All 27 tests pass in under 0.6 seconds."*

---

## 3. Quick Demo Walkthrough (What to show your professor)

1. Open PowerShell and run:
   ```powershell
   python app.py
   ```
2. Open your browser to: **`http://127.0.0.1:5000`**
3. **Show Tab 1 (Generator):** Move the length slider, click **Generate**, and point out the live **C-Powered Entropy Score & Crack Time meter**.
4. **Show Tab 2 (Hasher):** Enter a password, click **Compute PBKDF2 Hash**, show the 256-bit salt and hash, and test verification.
5. **Show Tab 3 (Vault):** Save a password to SQLite and toggle Show/Hide password.
6. **Show Terminal Tests:** Run `python -m unittest discover -s tests -p "test_*.py"` to show all 27 tests passing!
