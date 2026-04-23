#!/bin/bash
set -e

# 1. Build the implant DLL
echo "[*] Building implant DLL..."
cargo build -p implant --target x86_64-pc-windows-gnu --release

# 2. Build the injector EXE
echo "[*] Building injector EXE..."
cargo build -p injector --target x86_64-pc-windows-gnu --release

echo "[+] Build complete. Artifacts are in target/x86_64-pc-windows-gnu/release/"
echo "    - implant.dll"
echo "    - injector.exe"
