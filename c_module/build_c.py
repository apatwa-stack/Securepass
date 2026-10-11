"""
Compiles password_check.c into a shared library (.dll on Windows, .so on Linux).
"""
import os
import sys
import shutil
import subprocess
from pathlib import Path

def build():
    dir_path = Path(__file__).resolve().parent
    c_source = dir_path / "password_check.c"
    
    # Choose output file name based on OS
    if sys.platform.startswith("win"):
        dll_name = "password_check.dll"
    elif sys.platform == "darwin":
        dll_name = "password_check.dylib"
    else:
        dll_name = "password_check.so"
    out_file = dir_path / dll_name

    # Check for compiler in PATH or winget LLVM
    compiler = shutil.which("clang") or shutil.which("gcc")
    if not compiler and sys.platform.startswith("win"):
        local_app = Path(os.environ.get("LOCALAPPDATA", ""))
        matches = list(local_app.glob("**/llvm-mingw-*/bin/clang.exe"))
        if matches:
            compiler = str(matches[0])

    if not compiler:
        print("[!] No C compiler found. Using fallback.")
        return False

    print(f"[*] Compiling {c_source.name} with {compiler} -> {dll_name}")
    cmd = [compiler, "-shared", "-fPIC", "-O2", "-o", str(out_file), str(c_source)]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode == 0:
        print(f"[SUCCESS] Compiled: {out_file}")
        return True
    else:
        print(f"[ERROR] Failed to compile: {res.stderr}")
        return False

if __name__ == "__main__":
    build()
