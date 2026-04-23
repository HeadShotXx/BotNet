# PIC Loader for Linux x86_64

This project implements a Position-Independent Code (PIC) loader that can execute an ELF binary entirely from memory. It is designed to be used as shellcode.

## How it Works
1. **Entry**: The shellcode starts at `_start`, which finds the address of the embedded base64-encoded payload and jumps to `loader_main`.
2. **Decoding**: `loader_main` uses a custom base64 decoder to process the payload.
3. **In-Memory File**: It creates an anonymous file in memory using the `memfd_create` syscall.
4. **Populate**: The decoded ELF bytes are written to the memfd.
5. **Execute**: The `execveat` syscall is used with the `AT_EMPTY_PATH` flag to execute the file descriptor directly.

## Prerequisites
- GCC
- Binutils (objcopy, objdump, nm)
- Linux x86_64 environment

## Build Instructions

### 1. Build and Encode your Payload
Create your payload and convert it to a base64 string.
```bash
gcc -static -nostdlib payload_src.c -o payload
base64 -w 0 payload > payload.b64
```

### 2. Embed the Payload
Copy the content of `payload.b64` and paste it into `loader.c`, replacing the `REPLACE_WITH_BASE64_PAYLOAD` placeholder in the `payload_loc` function's assembly.

Example in `loader.c`:
```c
__attribute__((section(".text.payload")))
void payload_loc() {
    __asm__(
        ".global payload\n"
        "payload:\n"
        ".ascii \"f0VMRgIBAQAAAAAAAAAAAAIAPgABAAAA...\"\n"
        ".byte 0\n"
    );
}
```

### 3. Build the Loader and Extract Shellcode
Use the provided linker script to ensure the correct layout.
```bash
gcc -Os -fPIC -nostdlib -fno-stack-protector -static -T linker.ld -e _start -fcf-protection=none loader.c -o loader
objcopy -O binary --only-section=.text loader shellcode.bin
```

## Usage (Testing)
You can use the provided `runner.c` to test the shellcode.

```bash
gcc runner.c -o runner
./runner
```

## Files
- `loader.c`: The C source for the PIC loader.
- `linker.ld`: Linker script for correct section placement.
- `runner.c`: A test runner/injector simulation.
- `payload_src.c`: Example payload source.
- `shellcode.bin`: The final, ready-to-use PIC shellcode.
