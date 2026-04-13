# EXE to Shellcode Pipeline

This project provides a multi-stage pipeline to convert a Windows executable (EXE) into position-independent shellcode.

## How it Works

The pipeline consists of three main stages:

1.  **EXE to Embedded Loader**: The `payload.exe` (your target program) is embedded as a raw byte array into `final_loader.c`.
2.  **Embedded Loader**: When `final_loader.exe` runs, it manually maps the embedded `payload.exe` into its own memory, fixes its imports/relocations, and executes it.
3.  **PE to Shellcode**: The `final_loader.exe` is mapped into its virtual memory format. A reflective **PIC stub** (`stub.c`) is prepended to it, separated by a 64-bit marker (`0xDEADBEEFCAFEBABE`).

**The Final Shellcode** is: `[PIC Stub] + [Marker] + [Mapped final_loader.exe]`.

When the shellcode is executed:
1.  The **PIC Stub** runs first. It finds `kernel32.dll` via the PEB.
2.  It resolves `VirtualAlloc`, `LoadLibraryA`, and `GetProcAddress`.
3.  It searches memory for the `Marker` to find the start of the `final_loader.exe` blob.
4.  It maps `final_loader.exe` into a new buffer, fixes its imports/relocations, and jumps to it.
5.  `final_loader.exe` then repeats the process to load and run the original `payload.exe`.

## Components

*   `payload.c`: Example Windows program.
*   `exe_to_embedded_loader.c`: Embedding tool.
*   `loader_template.c`: Base template for the intermediate loader.
*   `stub.c`: The x64 PIC reflective loader stub.
*   `pe_to_shellcode.c`: The final shellcode generator.

## Compilation and Usage

### 1. Build Tools
```bash
gcc exe_to_embedded_loader.c -o exe_to_embedded_loader
gcc pe_to_shellcode.c -o pe_to_shellcode
```

### 2. Prepare Stub
```bash
# Compile stub.c. Section naming (.text$00, .text$01) ensures correct order.
x86_64-w64-mingw32-gcc -c stub.c -o stub.o -fno-stack-protector -fPIC -O2

# Link to merge sections and extract final binary
x86_64-w64-mingw32-ld -T <<<'SECTIONS { .text : { *(.text$00) *(.text$01) *(.text) } }' stub.o -o stub.elf
x86_64-w64-mingw32-objcopy -O binary --only-section=.text stub.elf stub.bin
```

### 3. Build Payload
```bash
x86_64-w64-mingw32-gcc payload.c -o payload.exe -mwindows
```

### 4. Generate Intermediate Loader
```bash
./exe_to_embedded_loader payload.exe
x86_64-w64-mingw32-gcc final_loader.c -o final_loader.exe
```

### 5. Generate Final Shellcode
```bash
./pe_to_shellcode final_loader.exe stub.bin
```

## Results

*   `final_shellcode.bin`: Raw shellcode binary.
*   `shellcode.c`: C-style array of the shellcode.
