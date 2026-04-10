#!/bin/bash
# Windows PIC Shellcode Loader Build Script
# This script compiles loader.c and extracts the raw shellcode.

# 1. Compile loader.c to an object file
# -target x86_64-pc-windows-msvc: Target Windows x64
# -ffreestanding: Do not assume standard library
# -fno-stack-protector: Disable stack canaries for PIC
# -O2: Optimize for size/speed
clang -target x86_64-pc-windows-msvc -ffreestanding -fno-stack-protector -O2 -c loader.c -o loader.o

# 2. Extract the .text section (code) as a raw binary
objcopy -O binary --only-section=.text loader.o loader.bin

echo "[+] Loader shellcode generated: loader.bin"

# 3. Instruction for adding a payload:
# To add a base64 encoded payload:
#   echo -n "PLDB64:$(base64 -w 0 your_executable_shellcode.bin)" >> loader.bin
# Then the resulting loader.bin is ready for execution in a remote process.

# Cleanup
rm loader.o
