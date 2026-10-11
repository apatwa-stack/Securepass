"""
PBKDF2 Password Hashing and Verification Module
Implements cryptographically sound key derivation using Python's standard 'secrets' and 'hashlib' libraries.
Complies with OWASP Password Storage Cheat Sheet recommendations.
"""

import hashlib
import secrets
from typing import Tuple, Dict, Any, Optional

DEFAULT_ALGORITHM = 'sha256'
DEFAULT_ITERATIONS = 600000  # OWASP current recommendation for PBKDF2-HMAC-SHA256
DEFAULT_SALT_BYTES = 32     # 256 bits of cryptographic entropy

class PasswordHashingError(ValueError):
    """Raised when hashing parameters or inputs are invalid."""
    pass

def generate_salt(num_bytes: int = DEFAULT_SALT_BYTES) -> bytes:
    """
    Generates a cryptographically secure random salt using the operating system's CSPRNG (secrets).
    """
    if num_bytes < 16:
        raise PasswordHashingError("Salt length should be at least 16 bytes for cryptographic security.")
    return secrets.token_bytes(num_bytes)

def hash_password(
    password: str,
    salt: Optional[bytes] = None,
    iterations: int = DEFAULT_ITERATIONS,
    algorithm: str = DEFAULT_ALGORITHM
) -> Dict[str, Any]:
    """
    Derives a cryptographic key/hash from a plaintext password using PBKDF2.

    :param password: The plaintext password string.
    :param salt: Optional explicit salt bytes. If None, a new 32-byte salt is generated via secrets.
    :param iterations: Work factor / iteration count (default 600,000).
    :param algorithm: HMAC pseudorandom function (default 'sha256').
    :return: Dictionary containing formatted hash string, hex values, salt, and metadata.
    """
    if not isinstance(password, str):
        raise PasswordHashingError("Password must be a string.")
    if len(password) == 0:
        raise PasswordHashingError("Password cannot be empty.")
    if iterations < 1000:
        raise PasswordHashingError("Iteration count must be at least 1,000 for brute-force resistance.")

    # Generate fresh cryptographically secure salt if not provided
    if salt is None:
        salt_bytes = generate_salt(DEFAULT_SALT_BYTES)
    elif isinstance(salt, str):
        # Allow hex string input
        salt_bytes = bytes.fromhex(salt)
    else:
        salt_bytes = salt

    # Derive hash using PBKDF2 HMAC
    derived_key = hashlib.pbkdf2_hmac(
        hash_name=algorithm,
        password=password.encode('utf-8'),
        salt=salt_bytes,
        iterations=iterations,
        dklen=32  # 256-bit derived key length
    )

    salt_hex = salt_bytes.hex()
    hash_hex = derived_key.hex()

    # Standard encoded string format: pbkdf2:algorithm:iterations$salt$hash
    encoded = f"pbkdf2:{algorithm}:{iterations}${salt_hex}${hash_hex}"

    return {
        "encoded": encoded,
        "algorithm": algorithm,
        "iterations": iterations,
        "salt_hex": salt_hex,
        "hash_hex": hash_hex
    }

def verify_password(
    password: str,
    stored_hash_hex: str,
    stored_salt_hex: str,
    iterations: int = DEFAULT_ITERATIONS,
    algorithm: str = DEFAULT_ALGORITHM
) -> bool:
    """
    Verifies a candidate plaintext password against stored hash and salt in constant time.

    :param password: Plaintext password attempt.
    :param stored_hash_hex: Expected derived key in hexadecimal.
    :param stored_salt_hex: The salt used during hashing in hexadecimal.
    :param iterations: Work factor used when originally hashing.
    :param algorithm: The HMAC PRF algorithm (default 'sha256').
    :return: True if the password matches, False otherwise.
    """
    if not password or not stored_hash_hex or not stored_salt_hex:
        return False

    try:
        salt_bytes = bytes.fromhex(stored_salt_hex)
        candidate_key = hashlib.pbkdf2_hmac(
            hash_name=algorithm,
            password=password.encode('utf-8'),
            salt=salt_bytes,
            iterations=iterations,
            dklen=len(bytes.fromhex(stored_hash_hex))
        )
        candidate_hex = candidate_key.hex()

        # Constant-time comparison using secrets.compare_digest prevents timing attacks
        return secrets.compare_digest(candidate_hex, stored_hash_hex)
    except Exception:
        return False

def verify_encoded(password: str, encoded_string: str) -> bool:
    """
    Verifies a candidate password directly against a formatted string:
    'pbkdf2:algorithm:iterations$salt_hex$hash_hex'
    """
    try:
        parts = encoded_string.split('$')
        if len(parts) != 3:
            return False

        header, salt_hex, hash_hex = parts
        header_parts = header.split(':')
        if len(header_parts) != 3 or header_parts[0] != 'pbkdf2':
            return False

        algorithm = header_parts[1]
        iterations = int(header_parts[2])

        return verify_password(
            password=password,
            stored_hash_hex=hash_hex,
            stored_salt_hex=salt_hex,
            iterations=iterations,
            algorithm=algorithm
        )
    except Exception:
        return False
