#include "tasks.h"
#include <tlhelp32.h>
#include <psapi.h>
#include <stdio.h>
#include "cJSON.h"

static double get_process_mem(DWORD pid) {
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return 0.0;
    PROCESS_MEMORY_COUNTERS pmc;
    if (GetProcessMemoryInfo(h, &pmc, sizeof(pmc))) {
        CloseHandle(h);
        return (double)pmc.WorkingSetSize / 1024.0 / 1024.0;
    }
    CloseHandle(h);
    return 0.0;
}

void handle_tasklist(SOCKET sock, HANDLE mutex) {
    cJSON* root = cJSON_CreateArray();
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe;
        pe.dwSize = sizeof(pe);
        if (Process32FirstW(snap, &pe)) {
            do {
                cJSON* item = cJSON_CreateObject();
                char pid_str[16];
                sprintf(pid_str, "%lu", pe.th32ProcessID);
                cJSON_AddStringToObject(item, "pid", pid_str);

                char name[MAX_PATH];
                WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1, name, MAX_PATH, NULL, NULL);
                cJSON_AddStringToObject(item, "name", name);
                cJSON_AddStringToObject(item, "cpu", "0");

                char mem_str[32];
                sprintf(mem_str, "%.1f", get_process_mem(pe.th32ProcessID));
                cJSON_AddStringToObject(item, "mem", mem_str);

                cJSON_AddItemToArray(root, item);
            } while (Process32NextW(snap, &pe));
        }
        CloseHandle(snap);
    }
    char* json_str = cJSON_PrintUnformatted(root);
    char* msg = malloc(strlen(json_str) + 32);
    sprintf(msg, "[tasklist_result]%s", json_str);
    sock_send(sock, mutex, msg);
    free(msg);
    free(json_str);
    cJSON_Delete(root);
}

void handle_taskkill(SOCKET sock, HANDLE mutex, const char* pid_str) {
    DWORD pid = atoi(pid_str);
    HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (!h) {
        char buf[128];
        sprintf(buf, "[taskkill_result]error:OpenProcess failed %lu", GetLastError());
        sock_send(sock, mutex, buf);
        return;
    }
    if (TerminateProcess(h, 1)) {
        char buf[128];
        sprintf(buf, "[taskkill_result]ok:PID %lu terminated", pid);
        sock_send(sock, mutex, buf);
    } else {
        char buf[128];
        sprintf(buf, "[taskkill_result]error:TerminateProcess failed %lu", GetLastError());
        sock_send(sock, mutex, buf);
    }
    CloseHandle(h);
}
