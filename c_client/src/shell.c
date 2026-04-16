#include "shell.h"
#include <stdio.h>
#include <stdlib.h>

static char* run_process(const char* command, const char* args) {
    HANDLE hRead, hWrite;
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
    if (!CreatePipe(&hRead, &hWrite, &sa, 0)) return _strdup("(error: pipe)");

    STARTUPINFOA si = { sizeof(si) };
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = hWrite;
    si.hStdError = hWrite;
    PROCESS_INFORMATION pi = { 0 };

    char full_cmd[4096];
    sprintf(full_cmd, "%s %s", command, args);

    if (!CreateProcessA(NULL, full_cmd, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        CloseHandle(hRead); CloseHandle(hWrite);
        return _strdup("(error: CreateProcess)");
    }

    CloseHandle(hWrite);

    char* result = malloc(1);
    result[0] = 0;
    DWORD total_read = 0;
    char buffer[1024];
    DWORD read;
    while (ReadFile(hRead, buffer, sizeof(buffer) - 1, &read, NULL) && read > 0) {
        result = realloc(result, total_read + read + 1);
        memcpy(result + total_read, buffer, read);
        total_read += read;
        result[total_read] = 0;
    }

    CloseHandle(hRead);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    if (total_read == 0) {
        free(result);
        return _strdup("(no output)\n");
    }
    return result;
}

char* run_powershell(const char* cmd) {
    char args[4096];
    sprintf(args, "-NoProfile -NonInteractive -WindowStyle Hidden -Command \"%s\"", cmd);
    return run_process("powershell", args);
}

char* run_cmd(const char* cmd) {
    char args[4096];
    sprintf(args, "/c %s", cmd);
    return run_process("cmd", args);
}
