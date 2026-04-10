#include <windows.h>

int main() {
    MessageBoxA(NULL, "Payload executed successfully!", "Shellcode Test", MB_OK);
    return 0;
}

// Compilation: x86_64-w64-mingw32-gcc payload.c -o payload.exe -mwindows
