#ifndef CLIPBOARD_H
#define CLIPBOARD_H

#include <windows.h>
#include "utils.h"

void handle_clipboard_get(SOCKET sock, HANDLE mutex);
void handle_clipboard_set(SOCKET sock, HANDLE mutex, const char* text);

#endif
