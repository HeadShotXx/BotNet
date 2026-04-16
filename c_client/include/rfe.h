#ifndef RFE_H
#define RFE_H

#include <windows.h>
#include "utils.h"

void handle_rfe_exe(SOCKET sock, HANDLE mutex, const char* payload);
void handle_rfe_dll(SOCKET sock, HANDLE mutex, const char* url);

#endif
