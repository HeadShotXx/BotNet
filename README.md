# EXE to Shellcode Pipeline (v4)

This project provides a multi-stage pipeline to convert almost any Windows executable (EXE) into position-independent shellcode.

## Core Features

-   **Architecture Aware**: The host tools support both x86 (PE32) and x64 (PE32+) payloads.
-   **Advanced Reflective Loading**:
    -   Manual Mapping (Sections, Imports, Relocations).
    -   x64 Exception Handling (`RtlAddFunctionTable`).
    -   Thread Local Storage (TLS) Initialization.
    -   PEB `ImageBaseAddress` Patching (improves compatibility with `GetModuleHandle(NULL)`).
    -   `ExitProcess` Hooking (prevents host termination).

## Multi-Stage Loading Process

1.  **Stub (PIC)**: The entry point. Resolves kernel32/ntdll from the PEB, searches for the marker, and reflectively loads the intermediate loader.
2.  **Intermediate Loader**: A standalone PE that acts as a wrapper. It reflectively loads the final payload and sets up its environment (PEB, TLS, Exceptions).
3.  **Payload**: Your target `.exe` file.

## Build Instructions

### 1. Host Utilities
```bash
gcc exe_to_embedded_loader.c -o exe_to_embedded_loader
gcc pe_to_shellcode.c -o pe_to_shellcode
```

### 2. Reflective Stub
```bash
x86_64-w64-mingw32-gcc -c stub.c -o stub.o -fno-stack-protector -fPIC -O2
x86_64-w64-mingw32-objcopy -O binary --only-section=.text.prologue --only-section=.text stub.o stub.bin
```

### 3. Target Payload
Compile your program as a standard Windows EXE:
```bash
x86_64-w64-mingw32-gcc my_payload.c -o payload.exe -mwindows -ladvapi32
```

### 4. Conversion
```bash
./exe_to_embedded_loader payload.exe
x86_64-w64-mingw32-gcc final_loader.c -o final_loader.exe -mwindows
./pe_to_shellcode final_loader.exe stub.bin
```

## Result

-   `final_shellcode.bin`: Injectable position-independent shellcode.
-   `shellcode.c`: C-formatted shellcode array.
