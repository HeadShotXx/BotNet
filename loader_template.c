/**
 * loader_template.c - Maximum Compatibility Reflective Loader
 */

#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <setjmp.h>

// PE_BLOB_ARRAY
unsigned char pe_blob[] = { 0 };
// ENTRY_POINT_RVA
DWORD entry_point_rva = 0;
// IMAGE_BASE
ULONG_PTR image_base = 0;
// SIZE_OF_IMAGE
SIZE_T size_of_image = 0;

static jmp_buf exit_buf;
void WINAPI HookedExitProcess(UINT uExitCode) { longjmp(exit_buf, 1); }

void load_pe() {
    PIMAGE_DOS_HEADER dr = (PIMAGE_DOS_HEADER)pe_blob;
    PIMAGE_NT_HEADERS nr = (PIMAGE_NT_HEADERS)((char*)pe_blob + dr->e_lfanew);

    char* pb = (char*)VirtualAlloc(NULL, nr->OptionalHeader.SizeOfImage, MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!pb) return;

    memcpy(pb, pe_blob, nr->OptionalHeader.SizeOfHeaders);
    PIMAGE_SECTION_HEADER sh = IMAGE_FIRST_SECTION(nr);
    for (int i=0; i<nr->FileHeader.NumberOfSections; i++) {
        if (sh[i].PointerToRawData) memcpy(pb + sh[i].VirtualAddress, (char*)pe_blob + sh[i].PointerToRawData, sh[i].SizeOfRawData);
    }

    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(pb + ((PIMAGE_DOS_HEADER)pb)->e_lfanew);
    IMAGE_DATA_DIRECTORY id = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (id.Size > 0) {
        PIMAGE_IMPORT_DESCRIPTOR im = (PIMAGE_IMPORT_DESCRIPTOR)(pb + id.VirtualAddress);
        while (im->Name) {
            HMODULE hm = LoadLibraryA(pb + im->Name);
            if (hm) {
                PIMAGE_THUNK_DATA ft = (PIMAGE_THUNK_DATA)(pb + im->FirstThunk);
                PIMAGE_THUNK_DATA ot = (PIMAGE_THUNK_DATA)(pb + im->OriginalFirstThunk);
                if (!im->OriginalFirstThunk) ot = ft;
                while (ot->u1.AddressOfData) {
                    FARPROC pr = NULL;
                    if (IMAGE_SNAP_BY_ORDINAL(ot->u1.Ordinal)) pr = GetProcAddress(hm, (LPCSTR)IMAGE_ORDINAL(ot->u1.Ordinal));
                    else {
                        PIMAGE_IMPORT_BY_NAME ibn = (PIMAGE_IMPORT_BY_NAME)(pb + ot->u1.AddressOfData);
                        pr = GetProcAddress(hm, ibn->Name);
                        if (strcmp(ibn->Name, "ExitProcess") == 0 || strcmp(ibn->Name, "_exit") == 0) pr = (FARPROC)HookedExitProcess;
                    }
                    ft->u1.Function = (ULONG_PTR)pr;
                    ft++; ot++;
                }
            }
            im++;
        }
    }

    ULONG_PTR de = (ULONG_PTR)pb - nt->OptionalHeader.ImageBase;
    if (de != 0 && nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size > 0) {
        PIMAGE_BASE_RELOCATION re = (PIMAGE_BASE_RELOCATION)(pb + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
        while (re->VirtualAddress != 0) {
            DWORD ct = (re->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            WORD* li = (WORD*)((char*)re + sizeof(IMAGE_BASE_RELOCATION));
            for (DWORD i=0; i<ct; i++) {
                if ((li[i] >> 12) == IMAGE_REL_BASED_DIR64) *(ULONG_PTR*)(pb + re->VirtualAddress + (li[i] & 0xFFF)) += de;
                else if ((li[i] >> 12) == IMAGE_REL_BASED_HIGHLOW) *(DWORD*)(pb + re->VirtualAddress + (li[i] & 0xFFF)) += (DWORD)de;
            }
            re = (PIMAGE_BASE_RELOCATION)((char*)re + re->SizeOfBlock);
        }
    }

#ifdef _WIN64
    void** pib = (void**)((char*)__readgsqword(0x60) + 0x10);
    *pib = pb;
    IMAGE_DATA_DIRECTORY ed = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (ed.Size > 0) {
        typedef BOOL (WINAPI *RAFA)(PRUNTIME_FUNCTION, DWORD, DWORD64);
        RAFA pR = (RAFA)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlAddFunctionTable");
        if (pR) pR((PRUNTIME_FUNCTION)(pb + ed.VirtualAddress), ed.Size / sizeof(RUNTIME_FUNCTION), (ULONG_PTR)pb);
    }
#else
    void** pib = (void**)((char*)__readfsdword(0x30) + 0x08);
    *pib = pb;
#endif

    IMAGE_DATA_DIRECTORY td = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (td.Size > 0) {
        PIMAGE_TLS_DIRECTORY tl = (PIMAGE_TLS_DIRECTORY)(pb + td.VirtualAddress);
        PIMAGE_TLS_CALLBACK* cb = (PIMAGE_TLS_CALLBACK*)tl->AddressOfCallBacks;
        if (cb) while (*cb) { (*cb)(pb, DLL_PROCESS_ATTACH, NULL); cb++; }
    }

    // Set protections
    for (int i=0; i<nt->FileHeader.NumberOfSections; i++) {
        DWORD p=0, old;
        if (sh[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            if (sh[i].Characteristics & IMAGE_SCN_MEM_WRITE) p=PAGE_EXECUTE_READWRITE;
            else p=PAGE_EXECUTE_READ;
        } else {
            if (sh[i].Characteristics & IMAGE_SCN_MEM_WRITE) p=PAGE_READWRITE;
            else p=PAGE_READONLY;
        }
        VirtualProtect(pb + sh[i].VirtualAddress, sh[i].Misc.VirtualSize, p, &old);
    }

    if (setjmp(exit_buf) == 0) ((void(*)())(pb + entry_point_rva))();
}

int main() { load_pe(); printf("\nDone. Press Enter."); getchar(); return 0; }
