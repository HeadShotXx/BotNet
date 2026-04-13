/**
 * loader_template.c - Enhanced Reflective Loader
 *
 * This template is used to wrap a payload EXE.
 * It provides better support for exceptions (x64) and TLS.
 */

#include <windows.h>
#include <stdio.h>

// PE_BLOB_ARRAY
unsigned char pe_blob[] = { 0 };

// ENTRY_POINT_RVA
DWORD entry_point_rva = 0;

// IMAGE_BASE
ULONG_PTR image_base = 0;

// SIZE_OF_IMAGE
SIZE_T size_of_image = 0;

typedef BOOL (WINAPI *DllEntryProc)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved);

void load_pe() {
    PIMAGE_DOS_HEADER dos_header_raw = (PIMAGE_DOS_HEADER)pe_blob;
    PIMAGE_NT_HEADERS nt_headers_raw = (PIMAGE_NT_HEADERS)((char*)pe_blob + dos_header_raw->e_lfanew);

    LPVOID pe_buffer = VirtualAlloc(NULL, nt_headers_raw->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!pe_buffer) return;

    // 1. Copy Headers
    memcpy(pe_buffer, pe_blob, nt_headers_raw->OptionalHeader.SizeOfHeaders);

    // 2. Copy Sections
    PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(nt_headers_raw);
    for (int i = 0; i < nt_headers_raw->FileHeader.NumberOfSections; i++) {
        if (sections[i].PointerToRawData != 0) {
            memcpy((char*)pe_buffer + sections[i].VirtualAddress,
                   (char*)pe_blob + sections[i].PointerToRawData,
                   sections[i].SizeOfRawData);
        }
    }

    PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)((char*)pe_buffer + ((PIMAGE_DOS_HEADER)pe_buffer)->e_lfanew);

    // 3. Fix Imports
    IMAGE_DATA_DIRECTORY import_dir = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (import_dir.Size > 0) {
        PIMAGE_IMPORT_DESCRIPTOR import_desc = (PIMAGE_IMPORT_DESCRIPTOR)((char*)pe_buffer + import_dir.VirtualAddress);
        while (import_desc->Name) {
            HMODULE h_module = LoadLibraryA((char*)pe_buffer + import_desc->Name);
            if (h_module) {
                PIMAGE_THUNK_DATA first_thunk = (PIMAGE_THUNK_DATA)((char*)pe_buffer + import_desc->FirstThunk);
                PIMAGE_THUNK_DATA original_first_thunk = (PIMAGE_THUNK_DATA)((char*)pe_buffer + import_desc->OriginalFirstThunk);
                if (!import_desc->OriginalFirstThunk) original_first_thunk = first_thunk;

                while (original_first_thunk->u1.AddressOfData) {
                    if (IMAGE_SNAP_BY_ORDINAL(original_first_thunk->u1.Ordinal)) {
                        first_thunk->u1.Function = (ULONG_PTR)GetProcAddress(h_module, (LPCSTR)IMAGE_ORDINAL(original_first_thunk->u1.Ordinal));
                    } else {
                        PIMAGE_IMPORT_BY_NAME import_by_name = (PIMAGE_IMPORT_BY_NAME)((char*)pe_buffer + original_first_thunk->u1.AddressOfData);
                        first_thunk->u1.Function = (ULONG_PTR)GetProcAddress(h_module, import_by_name->Name);
                    }
                    first_thunk++;
                    original_first_thunk++;
                }
            }
            import_desc++;
        }
    }

    // 4. Base Relocations
    ULONG_PTR delta = (ULONG_PTR)pe_buffer - nt_headers->OptionalHeader.ImageBase;
    if (delta != 0) {
        IMAGE_DATA_DIRECTORY reloc_dir = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (reloc_dir.Size > 0) {
            PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)((char*)pe_buffer + reloc_dir.VirtualAddress);
            while (reloc->VirtualAddress != 0) {
                DWORD count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                WORD* list = (WORD*)((char*)reloc + sizeof(IMAGE_BASE_RELOCATION));
                for (DWORD i = 0; i < count; i++) {
                    WORD type = list[i] >> 12;
                    WORD offset = list[i] & 0xFFF;
                    if (type == IMAGE_REL_BASED_DIR64) {
                        *(ULONG_PTR*)((char*)pe_buffer + reloc->VirtualAddress + offset) += delta;
                    } else if (type == IMAGE_REL_BASED_HIGHLOW) {
                        *(DWORD*)((char*)pe_buffer + reloc->VirtualAddress + offset) += (DWORD)delta;
                    }
                }
                reloc = (PIMAGE_BASE_RELOCATION)((char*)reloc + reloc->SizeOfBlock);
            }
        }
    }

    // 5. x64 Exceptions (RtlAddFunctionTable)
#ifdef _WIN64
    IMAGE_DATA_DIRECTORY exception_dir = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (exception_dir.Size > 0) {
        typedef BOOL (WINAPI *RAFA)(PRUNTIME_FUNCTION, DWORD, DWORD64);
        HMODULE h_ntdll = GetModuleHandleA("ntdll.dll");
        RAFA pRtlAddFunctionTable = (RAFA)GetProcAddress(h_ntdll, "RtlAddFunctionTable");
        if (pRtlAddFunctionTable) {
            pRtlAddFunctionTable((PRUNTIME_FUNCTION)((char*)pe_buffer + exception_dir.VirtualAddress), exception_dir.Size / sizeof(RUNTIME_FUNCTION), (ULONG_PTR)pe_buffer);
        }
    }
#endif

    // 6. TLS Callbacks
    IMAGE_DATA_DIRECTORY tls_dir = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (tls_dir.Size > 0) {
        PIMAGE_TLS_DIRECTORY tls = (PIMAGE_TLS_DIRECTORY)((char*)pe_buffer + tls_dir.VirtualAddress);
        PIMAGE_TLS_CALLBACK* callbacks = (PIMAGE_TLS_CALLBACK*)tls->AddressOfCallBacks;
        if (callbacks) {
            while (*callbacks) {
                (*callbacks)(pe_buffer, DLL_PROCESS_ATTACH, NULL);
                callbacks++;
            }
        }
    }

    // 7. Memory Protections
    sections = IMAGE_FIRST_SECTION(nt_headers);
    for (int i = 0; i < nt_headers->FileHeader.NumberOfSections; i++) {
        DWORD protection = 0;
        if (sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            if (sections[i].Characteristics & IMAGE_SCN_MEM_WRITE) protection = PAGE_EXECUTE_READWRITE;
            else if (sections[i].Characteristics & IMAGE_SCN_MEM_READ) protection = PAGE_EXECUTE_READ;
            else protection = PAGE_EXECUTE;
        } else {
            if (sections[i].Characteristics & IMAGE_SCN_MEM_WRITE) protection = PAGE_READWRITE;
            else if (sections[i].Characteristics & IMAGE_SCN_MEM_READ) protection = PAGE_READONLY;
            else protection = PAGE_NOACCESS;
        }
        DWORD old;
        VirtualProtect((char*)pe_buffer + sections[i].VirtualAddress, sections[i].Misc.VirtualSize, protection, &old);
    }

    // 8. Execute
    ((void(*)())((char*)pe_buffer + entry_point_rva))();
}

int main() {
    load_pe();
    return 0;
}
