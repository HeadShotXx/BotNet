# Windows x64 PIC Shellcode Loader

A Position Independent Code (PIC) loader written in C for Windows x64. It is designed to be executed as raw shellcode and can load/execute an appended Base64-encoded payload.

## Features

- **Self-Contained**: No external dependencies or imports.
- **Dynamic API Resolution**: Resolves `VirtualAlloc` from `kernel32.dll` by traversing the PEB (Process Environment Block) and Export Directory using DJB2 name hashing.
- **Payload Search**: Automatically locates its own payload by searching for a unique marker (`PLDB64:`) in memory.
- **Base64 Support**: Decodes the appended payload at runtime, allowing for easier transport/embedding of the actual shellcode.

## Files

- `loader.c`: The core loader source code.
- `sample_payload.c`: A simple example payload that can be loaded.
- `build.sh`: A bash script to compile and assemble the final shellcode on Linux.

## Requirements

- `clang`: For cross-compiling to Windows x64.
- `binutils` (`objcopy`): For extracting the raw `.text` section from object files.

## Compilation Instructions

To compile the loader and create the final shellcode binary:

```bash
chmod +x build.sh
./build.sh
```

This will produce:
- `loader.bin`: The raw loader shellcode.
- `payload.bin`: The raw sample payload shellcode.
- `final_shellcode.bin`: The combined shellcode (loader + marker + base64 payload).

## How it Works

1. **Entry Point**: The `entry()` function is placed at offset 0 of the binary.
2. **PEB Traversal**: The loader finds the base address of `kernel32.dll` from the `InMemoryOrderModuleList` inside the PEB.
3. **Export Parsing**: It scans the Export Directory of `kernel32.dll` to find the address of `VirtualAlloc`.
4. **Marker Search**: It uses RIP-relative addressing to find its own location in memory and searches forward for the string `PLDB64:`.
5. **Decoding & Execution**: It decodes the Base64 data following the marker into a new RWX memory region and jumps to it.

## Adding Your Own Payload

To use your own shellcode as the payload:

1. Prepare your shellcode in a binary file (e.g., `myshellcode.bin`).
2. Generate the base64 string: `PAYLOAD_B64=$(base64 -w 0 myshellcode.bin)`
3. Append it to the loader: `cat loader.bin > final.bin && echo -n "PLDB64:${PAYLOAD_B64}" >> final.bin`
4. `final.bin` is now ready for injection.
