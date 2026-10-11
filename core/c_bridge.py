"""
Python Ctypes Bridge to Native C Password Entropy & Complexity Library.
Binds to libentropy.dll / libentropy.so with automatic discovery and pure-Python fallback.
"""

import os
import sys
import math
import ctypes
from pathlib import Path
from typing import Dict, Any, Optional

class PasswordAnalysisResultStruct(ctypes.Structure):
    """Corresponds exactly to PasswordAnalysisResult struct defined in entropy_analyzer.h"""
    _fields_ = [
        ("length", ctypes.c_int),
        ("uppercase_count", ctypes.c_int),
        ("lowercase_count", ctypes.c_int),
        ("digit_count", ctypes.c_int),
        ("symbol_count", ctypes.c_int),
        ("pool_size", ctypes.c_int),
        ("shannon_entropy", ctypes.c_double),
        ("pool_entropy", ctypes.c_double),
        ("crack_time_seconds", ctypes.c_double),
        ("score", ctypes.c_int),
        ("strength_label", ctypes.c_char * 32),
    ]

class CEntropyBridge:
    def __init__(self):
        self._c_lib = None
        self._lib_path = None
        self._load_c_library()

    def _get_library_name(self) -> str:
        if sys.platform.startswith('win'):
            return 'libentropy.dll'
        elif sys.platform == 'darwin':
            return 'libentropy.dylib'
        else:
            return 'libentropy.so'

    def _find_library_path(self) -> Optional[Path]:
        lib_name = self._get_library_name()
        c_modules_dir = Path(__file__).resolve().parent.parent / 'c_modules'
        
        # Check c_modules directory
        target = c_modules_dir / lib_name
        if target.exists():
            return target
            
        # Check current working directory
        cwd_target = Path.cwd() / 'c_modules' / lib_name
        if cwd_target.exists():
            return cwd_target

        return None

    def _load_c_library(self):
        lib_path = self._find_library_path()
        if lib_path and lib_path.exists():
            try:
                # Load the dynamic shared library via ctypes
                if sys.platform.startswith('win'):
                    self._c_lib = ctypes.CDLL(str(lib_path))
                else:
                    self._c_lib = ctypes.CDLL(str(lib_path))

                # Configure C function signatures
                # 1. calculate_shannon_entropy(const char *password) -> double
                self._c_lib.calculate_shannon_entropy.argtypes = [ctypes.c_char_p]
                self._c_lib.calculate_shannon_entropy.restype = ctypes.c_double

                # 2. calculate_strength_score(const char *password) -> int
                self._c_lib.calculate_strength_score.argtypes = [ctypes.c_char_p]
                self._c_lib.calculate_strength_score.restype = ctypes.c_int

                # 3. analyze_password(const char *password, PasswordAnalysisResult *result) -> int
                self._c_lib.analyze_password.argtypes = [
                    ctypes.c_char_p,
                    ctypes.POINTER(PasswordAnalysisResultStruct)
                ]
                self._c_lib.analyze_password.restype = ctypes.c_int

                self._lib_path = str(lib_path)
            except Exception as e:
                print(f"[C Bridge Warning] Could not load compiled C library {lib_path}: {e}")
                self._c_lib = None

    @property
    def is_c_loaded(self) -> bool:
        return self._c_lib is not None

    def format_crack_time(self, seconds: float) -> str:
        """Formats crack time into human-readable duration."""
        if seconds < 1e-4:
            return "Instant (under 1 ms)"
        elif seconds < 1.0:
            return f"{seconds * 1000:.1f} milliseconds"
        elif seconds < 60.0:
            return f"{seconds:.1f} seconds"
        elif seconds < 3600.0:
            return f"{seconds / 60.0:.1f} minutes"
        elif seconds < 86400.0:
            return f"{seconds / 3600.0:.1f} hours"
        elif seconds < 31536000.0:
            return f"{seconds / 86400.0:.1f} days"
        elif seconds < 3.1536e9:
            return f"{seconds / 31536000.0:.1f} years"
        elif seconds < 3.1536e12:
            return f"{seconds / 3.1536e9:.1f} thousand years"
        elif seconds < 3.1536e15:
            return f"{seconds / 3.1536e12:.1f} million years"
        else:
            return "Centuries / Practically Uncrackable"

    def analyze(self, password: str) -> Dict[str, Any]:
        """
        Analyzes password strength and entropy using native C code if available,
        falling back to Python implementation.
        """
        if self._c_lib is not None:
            return self._analyze_via_c(password)
        else:
            return self._analyze_via_python_fallback(password)

    def _analyze_via_c(self, password: str) -> Dict[str, Any]:
        pw_bytes = password.encode('utf-8')
        result_struct = PasswordAnalysisResultStruct()

        ret = self._c_lib.analyze_password(pw_bytes, ctypes.byref(result_struct))
        if ret != 0:
            raise RuntimeError(f"C function analyze_password returned error code {ret}")

        label = result_struct.strength_label.decode('utf-8', errors='ignore')
        crack_time_str = self.format_crack_time(result_struct.crack_time_seconds)

        return {
            "engine": "Native C Library via ctypes",
            "library_file": Path(self._lib_path).name,
            "length": result_struct.length,
            "uppercase_count": result_struct.uppercase_count,
            "lowercase_count": result_struct.lowercase_count,
            "digit_count": result_struct.digit_count,
            "symbol_count": result_struct.symbol_count,
            "pool_size": result_struct.pool_size,
            "shannon_entropy_bits": round(result_struct.shannon_entropy, 2),
            "pool_entropy_bits": round(result_struct.pool_entropy, 2),
            "crack_time_seconds": result_struct.crack_time_seconds,
            "crack_time_human": crack_time_str,
            "strength_score": result_struct.score,
            "strength_label": label
        }

    def _analyze_via_python_fallback(self, password: str) -> Dict[str, Any]:
        """Faithful Python mirror of the C algorithm."""
        length = len(password)
        if length == 0:
            return {
                "engine": "Pure Python Fallback (C module uncompiled)",
                "length": 0,
                "uppercase_count": 0,
                "lowercase_count": 0,
                "digit_count": 0,
                "symbol_count": 0,
                "pool_size": 0,
                "shannon_entropy_bits": 0.0,
                "pool_entropy_bits": 0.0,
                "crack_time_seconds": 0.0,
                "crack_time_human": "Instant",
                "strength_score": 0,
                "strength_label": "Empty"
            }

        upper = sum(1 for c in password if c.isupper())
        lower = sum(1 for c in password if c.islower())
        digit = sum(1 for c in password if c.isdigit())
        symbol = length - (upper + lower + digit)

        pool = 0
        if lower > 0: pool += 26
        if upper > 0: pool += 26
        if digit > 0: pool += 10
        if symbol > 0: pool += 33
        if pool == 0: pool = 1

        pool_entropy = length * (math.log2(pool) if pool > 0 else 0)

        freq = {}
        for c in password:
            freq[c] = freq.get(c, 0) + 1

        shannon_per_char = -sum((cnt / length) * math.log2(cnt / length) for cnt in freq.values())
        shannon_entropy = shannon_per_char * length

        if pool_entropy >= 120.0:
            crack_seconds = 1e25
        else:
            combinations = 2.0 ** pool_entropy
            crack_seconds = combinations / (2.0 * 1e10)

        effective_entropy = (shannon_entropy * 0.6) + (pool_entropy * 0.4)
        max_rep = max(freq.values())
        if max_rep / length > 0.5 and length > 3:
            effective_entropy -= 15.0

        variety = (1 if lower > 0 else 0) + (1 if upper > 0 else 0) + (1 if digit > 0 else 0) + (1 if symbol > 0 else 0)
        if variety == 4 and length >= 12:
            effective_entropy += 10.0

        score = max(0, min(100, int((effective_entropy / 80.0) * 100.0)))

        if score < 25:
            label = "Very Weak"
        elif score < 50:
            label = "Weak"
        elif score < 70:
            label = "Moderate"
        elif score < 88:
            label = "Strong"
        else:
            label = "Very Strong"

        return {
            "engine": "Pure Python Fallback (C module uncompiled)",
            "library_file": None,
            "length": length,
            "uppercase_count": upper,
            "lowercase_count": lower,
            "digit_count": digit,
            "symbol_count": symbol,
            "pool_size": pool,
            "shannon_entropy_bits": round(shannon_entropy, 2),
            "pool_entropy_bits": round(pool_entropy, 2),
            "crack_time_seconds": crack_seconds,
            "crack_time_human": self.format_crack_time(crack_seconds),
            "strength_score": score,
            "strength_label": label
        }

# Global singleton instance
bridge = CEntropyBridge()
