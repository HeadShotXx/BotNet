#ifndef CAMERA_H
#define CAMERA_H

#include <windows.h>
#include "utils.h"

void camera_stream_loop(SOCKET sock, HANDLE mutex, HANDLE stop_event, int fps);

#endif
