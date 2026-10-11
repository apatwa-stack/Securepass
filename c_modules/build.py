"""
Cross-platform build script for the C entropy analyzer library.
Automatically locates available C compilers (gcc, clang, cl) or compiles on Linux/Windows/macOS.
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path

def get_output_filename():
    if sys.platform.startswith('win'):
        return 'libentropy.dll'
    elif sys.platform == 'darwin':
        return 'libentropy.dylib'
    else:
        return 'libentropy.so'

def find_compiler():
    # Common compiler names
    compilers = ['gcc', 'clang', 'clang-cl', 'cl']
    
    # Check system PATH first
    for comp in compilers:
        found = shutil.which(comp)
        if found:
            return comp, found
            
    # On Windows, search in common toolchain directories if not in PATH
    if sys.platform.startswith('win'):
        search_paths = [
            Path(os.environ.get('LOCALAPPDATA', '')) / 'Microsoft' / 'WinGet' / 'Packages',
            Path(r"C:\Program Files\LLVM\bin"),
            Path(r"C:\msys64\mingw64\bin"),
            Path(r"C:\msys64\ucrt64\bin"),
            Path(r"C:\MinGW\bin"),
            Path(os.environ.get('USERPROFILE', '')) / 'llvm-mingw' / 'bin',
        ]
        for base in search_paths:
            if base.exists():
                for comp in ['clang.exe', 'gcc.exe']:
                    for match in base.rglob(comp):
                        return 'clang' if 'clang' in comp else 'gcc', str(match)
                        
    return None, None

def build():
    script_dir = Path(__file__).resolve().parent
    source_file = script_dir / 'entropy_analyzer.c'
    output_name = get_output_filename()
    output_path = script_dir / output_name

    print(f"[*] Building C module: {source_file.name} -> {output_name}")
    comp_type, comp_path = find_compiler()

    if not comp_path:
        print("[!] No C compiler (gcc, clang, cl) found on system PATH or standard directories.")
        print("    If needed, please install GCC or Clang (e.g. MSYS2, LLVM, or MinGW).")
        return False

    print(f"[+] Found compiler: {comp_path} ({comp_type})")

    try:
        if comp_type in ['gcc', 'clang']:
            cmd = [
                comp_path,
                '-O3',
                '-shared',
                '-std=c99',
            ]
            if not sys.platform.startswith('win'):
                cmd.append('-fPIC')
            cmd.extend([
                '-o', str(output_path),
                str(source_file),
                '-lm'
            ])
        elif comp_type == 'cl':
            cmd = [
                comp_path,
                '/LD',
                '/O2',
                str(source_file),
                f'/Fe:{output_path}'
            ]
        else:
            print(f"[!] Unsupported compiler type: {comp_type}")
            return False

        print(f"[*] Executing: {' '.join(cmd)}")
        result = subprocess.run(cmd, cwd=str(script_dir), capture_output=True, text=True)
        if result.returncode == 0 and output_path.exists():
            print(f"[SUCCESS] Shared library built successfully: {output_path}")
            return True
        else:
            print(f"[ERROR] Compilation failed with return code {result.returncode}:")
            print(result.stdout)
            print(result.stderr)
            return False
    except Exception as e:
        print(f"[ERROR] Failed to execute compiler: {e}")
        return False

if __name__ == '__main__':
    success = build()
    sys.exit(0 if success else 1)
