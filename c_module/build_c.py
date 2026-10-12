import os, sys, shutil, subprocess
from pathlib import Path

def build():
    src = Path(__file__).parent / "password_check.c"
    ext = ".dll" if sys.platform.startswith("win") else (".dylib" if sys.platform == "darwin" else ".so")
    out = Path(__file__).parent / f"password_check{ext}"

    compiler = shutil.which("clang") or shutil.which("gcc")
    if not compiler and sys.platform.startswith("win"):
        matches = list(Path(os.environ.get("LOCALAPPDATA", "")).glob("**/llvm-mingw-*/bin/clang.exe"))
        if matches:
            compiler = str(matches[0])

    if not compiler:
        return False
    return subprocess.run([compiler, "-shared", "-fPIC", "-O2", "-o", str(out), str(src)], capture_output=True).returncode == 0

if __name__ == "__main__":
    build()
