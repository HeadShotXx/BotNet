#include <windows.h>
#include <stdio.h>

int main() {
    printf("Payload Executed!\n");
    MessageBoxA(NULL, "Payload Executed!", "PIC Loader Test", MB_OK);
    return 0;
}
