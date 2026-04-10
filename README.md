# EXE to Shellcode Pipeline

This project provides a multi-stage pipeline to convert a Windows executable (EXE) into position-independent shellcode.

## Components

1.  **payload.c**: A simple test payload that displays a MessageBox.
2.  **exe_to_embedded_loader.c**: A tool that parses an EXE and embeds it into a C loader template.
3.  **loader_template.c**: A standalone PE loader template that maps the embedded EXE into memory, resolves imports, and fixes relocations.
4.  **stub.c**: A Position Independent Code (PIC) reflective stub that loads and executes a PE image.
5.  **pe_to_shellcode.c**: A tool that prepends the PIC stub to the mapped loader EXE, producing the final shellcode.

## Usage Instructions

### 1. Prerequisites

Ensure you have `gcc` and the `mingw-w64` cross-compiler installed on your system.

### 2. Step-by-Step Execution

Follow these steps in order to generate the final shellcode:

#### Step A: Prepare the Payload
Compile the test payload to a Windows executable.
```bash
x86_64-w64-mingw32-gcc payload.c -o payload.exe -mwindows
```

#### Step B: Build the Embedding Tool
Compile the host-side tool that will embed the payload into the loader.
```bash
gcc exe_to_embedded_loader.c -o exe_to_embedded_loader
```

#### Step C: Generate the Embedded Loader Source
Run the embedding tool. This uses `loader_template.c` as a base and produces `final_loader.c`.
```bash
./exe_to_embedded_loader payload.exe
```

#### Step D: Compile the Embedded Loader
Compile the generated `final_loader.c` into a Windows executable.
```bash
x86_64-w64-mingw32-gcc final_loader.c -o final_loader.exe
```

#### Step E: Build the PIC Stub
Compile the reflective stub and extract its raw binary code.
```bash
x86_64-w64-mingw32-gcc -c stub.c -o stub.o -fno-stack-protector -fPIC -O2
x86_64-w64-mingw32-objcopy -O binary --only-section=.text stub.o stub.bin
```

#### Step F: Build the Shellcode Generator
Compile the tool that combines the stub and the loader EXE.
```bash
gcc pe_to_shellcode.c -o pe_to_shellcode
```

#### Step G: Generate Final Shellcode
Run the final tool to produce the shellcode files.
```bash
./pe_to_shellcode final_loader.exe stub.bin
```

### 3. Output

After completing Step G, you will have two final files:
*   **final_shellcode.bin**: Raw binary shellcode.
*   **shellcode.c**: The same shellcode formatted as a C byte array for easy inclusion in other projects.

## Notes
*   The pipeline is designed for x64 Windows targets.
*   The final shellcode is position-independent and can be injected into any process.
