#ifndef SCREEN_H
#define SCREEN_H

#include <windows.h>
#include "utils.h"

void screen_stream_loop(SOCKET sock, HANDLE mutex, HANDLE stop_event, int fps);

#endif
