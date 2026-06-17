#!/usr/bin/env python3
"""
Patch ELF EI_OSABI byte in Solana program .so files.

Platform-tools v1.52+ produces ELF binaries with EI_OSABI=3 (GNU/Linux),
but the Solana validator requires EI_OSABI=0 (ELFOSABI_NONE).
This script patches byte 7 of the ELF header for all .so files in the
target/deploy directory and per-program target/deploy directories.
"""
import glob
import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)

patterns = [
    os.path.join(PROJECT_ROOT, "target", "deploy", "*.so"),
    os.path.join(PROJECT_ROOT, "programs", "*", "target", "deploy", "*.so"),
]

patched = 0
for pattern in patterns:
    for so_path in glob.glob(pattern):
        with open(so_path, "r+b") as f:
            header = f.read(16)
            if len(header) < 8:
                continue
            # Check ELF magic
            if header[:4] != b"\x7fELF":
                continue
            ei_osabi = header[7]
            if ei_osabi != 0:
                f.seek(7)
                f.write(bytes([0]))
                print(f"  Patched {os.path.basename(so_path)}: EI_OSABI {ei_osabi} -> 0")
                patched += 1
            else:
                print(f"  OK {os.path.basename(so_path)}: EI_OSABI already 0")

if patched > 0:
    print(f"Patched {patched} ELF file(s)")
else:
    print("All ELF files already patched")
