# PIC Loader for Linux x86_64

This project implements a Position-Independent Code (PIC) loader that can execute an ELF binary entirely from memory. It is designed to be used as shellcode.

## How it Works
1. **Entry**: The shellcode starts at `_start`, which finds the address of the base64-encoded payload (appended to the end of the shellcode) and jumps to `loader_main`.
2. **Decoding**: `loader_main` uses a custom base64 decoder to process the payload.
3. **In-Memory File**: It creates an anonymous file in memory using the `memfd_create` syscall.
4. **Populate**: The decoded ELF bytes are written to the memfd.
5. **Execute**: The `execveat` syscall is used with the `AT_EMPTY_PATH` flag to execute the file descriptor directly.

## Prerequisites
- GCC
- Binutils (objcopy, objdump, nm)
- Linux x86_64 environment

## Build Instructions

### 1. Build the Payload
Create your payload (e.g., `payload_src.c`) and compile it as a static binary.
```bash
gcc -static -nostdlib payload_src.c -o payload
```

### 2. Convert Payload to Base64
The loader expects the payload to be base64-encoded.
```bash
base64 -w 0 payload > payload.b64
```

### 3. Build the Loader and Extract Shellcode
Use the provided linker script to ensure the entry point is at the beginning of the binary.
```bash
gcc -Os -fPIC -nostdlib -fno-stack-protector -static -T linker.ld -e _start -fcf-protection=none loader.c -o loader
objcopy -O binary --only-section=.text loader shellcode.bin
```

### 4. Create the Final Payload
Concatenate the shellcode and the base64 payload.
```bash
cat shellcode.bin payload.b64 > final_payload.bin
```

## Usage (Testing)
You can use the provided `runner.c` to test the shellcode. The runner simulates an injection by mapping the shellcode into executable memory and jumping to it.

```bash
gcc runner.c -o runner
./runner
```

## Files
- `loader.c`: The C source for the PIC loader.
- `linker.ld`: Linker script for correct section placement.
- `runner.c`: A test runner/injector simulation.
- `payload_src.c`: Example payload.
- `shellcode.bin`: The compiled loader shellcode (without payload appended).
