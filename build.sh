#!/bin/bash
# Windows PIC Shellcode Loader Build & Test Script

set -e

echo "[*] Compiling Loader..."
# Compile loader.c to Windows x64 PIC
clang -target x86_64-pc-windows-msvc -ffreestanding -fno-stack-protector -O2 -c loader.c -o loader.o
objcopy -O binary --only-section=.text loader.o loader.bin

echo "[*] Compiling Sample Payload..."
# Compile sample_payload.c to Windows x64 PIC
clang -target x86_64-pc-windows-msvc -ffreestanding -fno-stack-protector -O2 -c sample_payload.c -o payload.o
objcopy -O binary --only-section=.text payload.o payload.bin

echo "[*] Encoding and Appending Payload..."
# Create the final shellcode by appending the marker and the base64 encoded payload
PAYLOAD_B64=$(base64 -w 0 payload.bin)
cp loader.bin final_shellcode.bin
echo -n "PLDB64:${PAYLOAD_B64}" >> final_shellcode.bin

echo "[+] Success!"
echo "    Loader binary: loader.bin"
echo "    Sample payload binary: payload.bin"
echo "    Final combined shellcode: final_shellcode.bin"
echo ""
echo "To use:"
echo "1. Inject 'final_shellcode.bin' into a Windows x64 process."
echo "2. The loader will find the 'PLDB64:' marker, decode the payload, and execute it."

# Cleanup intermediate files
rm loader.o payload.o
