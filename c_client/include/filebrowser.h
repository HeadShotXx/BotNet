#ifndef FILEBROWSER_H
#define FILEBROWSER_H

#include <windows.h>
#include "utils.h"

void handle_ls(SOCKET sock, HANDLE mutex, const char* path);
void handle_download(SOCKET sock, HANDLE mutex, const char* path);
void handle_delete(SOCKET sock, HANDLE mutex, const char* path);
void handle_mkdir(SOCKET sock, HANDLE mutex, const char* path);
void handle_upload(SOCKET sock, HANDLE mutex, const char* payload);
void handle_rename(SOCKET sock, HANDLE mutex, const char* payload);

#endif
