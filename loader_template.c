/**
 * loader_template.c - Enhanced Reflective Loader
 *
 * This template is used to wrap a payload EXE.
 * It provides better support for exceptions (x64) and TLS.
 */

#include <windows.h>
#include <stdio.h>

typedef LONG NTSTATUS;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _ANSI_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PSTR   Buffer;
} ANSI_STRING, *PANSI_STRING;

typedef NTSTATUS (NTAPI *pLdrLoadDll)(
    PWSTR DllPath,
    PULONG DllCharacteristics,
    PUNICODE_STRING DllName,
    PVOID *DllHandle
);

typedef NTSTATUS (NTAPI *pLdrGetProcedureAddress)(
    PVOID DllHandle,
    PANSI_STRING ProcedureName,
    ULONG ProcedureNumber,
    PVOID *ProcedureAddress
);

typedef VOID (NTAPI *pRtlInitAnsiString)(
    PANSI_STRING DestinationString,
    PCSZ SourceString
);

typedef NTSTATUS (NTAPI *pRtlAnsiStringToUnicodeString)(
    PUNICODE_STRING DestinationString,
    PANSI_STRING SourceString,
    BOOLEAN AllocateDestinationString
);

typedef VOID (NTAPI *pRtlFreeUnicodeString)(
    PUNICODE_STRING UnicodeString
);

typedef struct _API_SET_NAMESPACE {
    ULONG Version;
    ULONG Size;
    ULONG Flags;
    ULONG Count;
    ULONG EntryOffset;
    ULONG HashOffset;
    ULONG HashFactor;
} API_SET_NAMESPACE, *PAPI_SET_NAMESPACE;

typedef struct _API_SET_NAMESPACE_ENTRY {
    ULONG Flags;
    ULONG NameOffset;
    ULONG NameLength;
    ULONG AliasLength;
    ULONG ValueOffset;
    ULONG ValueCount;
} API_SET_NAMESPACE_ENTRY, *PAPI_SET_NAMESPACE_ENTRY;

typedef struct _API_SET_VALUE_ENTRY {
    ULONG Flags;
    ULONG NameOffset;
    ULONG NameLength;
    ULONG ValueOffset;
    ULONG ValueLength;
} API_SET_VALUE_ENTRY, *PAPI_SET_VALUE_ENTRY;

#ifndef MAX_PATH
#define MAX_PATH 260
#endif

#ifdef _MSC_VER
#include <intrin.h>
#define READ_PEB() (PVOID)__readgsqword(0x60)
#else
#ifdef _WIN64
static __inline__ PVOID READ_PEB() {
    PVOID peb;
    __asm__("mov %%gs:0x60, %0" : "=r" (peb));
    return peb;
}
#else
static __inline__ PVOID READ_PEB() {
    PVOID peb;
    __asm__("mov %%fs:0x30, %0" : "=r" (peb));
    return peb;
}
#endif
#endif

// Helper functions for manual resolution
static int my_strlen(const char* s) {
    int l = 0;
    while (s[l]) l++;
    return l;
}

static int my_strcmp(const char* s1, const char* s2) {
    while (*s1 && (*s1 == *s2)) {
        s1++; s2++;
    }
    return *(unsigned char*)s1 - *(unsigned char*)s2;
}

static int my_strncmp(const char* s1, const char* s2, size_t n) {
    while (n && *s1 && (*s1 == *s2)) {
        s1++; s2++; n--;
    }
    if (n == 0) return 0;
    return *(unsigned char*)s1 - *(unsigned char*)s2;
}

PVOID get_export_address_manual(HMODULE h_module, const char* func_name, pRtlInitAnsiString _RtlInitAnsiString, pLdrGetProcedureAddress _LdrGetProcedureAddress, pLdrLoadDll _LdrLoadDll, pRtlAnsiStringToUnicodeString _RtlAnsiStringToUnicodeString, pRtlFreeUnicodeString _RtlFreeUnicodeString);

void resolve_api_set(const char* dll_name, char* out_name) {
    if (my_strncmp(dll_name, "api-", 4) != 0 && my_strncmp(dll_name, "ext-", 4) != 0) {
        int i = 0;
        while (dll_name[i]) { out_name[i] = dll_name[i]; i++; }
        out_name[i] = '\0';
        return;
    }

    PVOID peb = READ_PEB();
    // ApiSetMap is at 0x68 on x64, 0x38 on x86
    PAPI_SET_NAMESPACE api_set_map = *(PAPI_SET_NAMESPACE*)((char*)peb + (sizeof(PVOID) == 8 ? 0x68 : 0x38));

    if (api_set_map->Version < 6) {
        int i = 0;
        while (dll_name[i]) { out_name[i] = dll_name[i]; i++; }
        out_name[i] = '\0';
        return;
    }

    PAPI_SET_NAMESPACE_ENTRY entries = (PAPI_SET_NAMESPACE_ENTRY)((char*)api_set_map + api_set_map->EntryOffset);

    size_t dll_name_len = my_strlen(dll_name);
    if (dll_name_len > 4 && (dll_name[dll_name_len - 4] == '.')) {
        dll_name_len -= 4;
    }

    for (ULONG i = 0; i < api_set_map->Count; i++) {
        PAPI_SET_NAMESPACE_ENTRY entry = &entries[i];
        PWCHAR name = (PWCHAR)((char*)api_set_map + entry->NameOffset);

        if (dll_name_len == (size_t)entry->NameLength / 2) {
            int match = 1;
            for (size_t j = 0; j < dll_name_len; j++) {
                WCHAR c1 = (WCHAR)dll_name[j];
                WCHAR c2 = name[j];
                if (c1 >= 'A' && c1 <= 'Z') c1 += 32;
                if (c2 >= L'A' && c2 <= L'Z') c2 += 32;
                if (c1 != c2) {
                    match = 0;
                    break;
                }
            }

            if (match) {
                PAPI_SET_VALUE_ENTRY values = (PAPI_SET_VALUE_ENTRY)((char*)api_set_map + entry->ValueOffset);
                if (entry->ValueCount > 0) {
                    PAPI_SET_VALUE_ENTRY value = &values[0]; // Take default
                    PWCHAR target_dll_wide = (PWCHAR)((char*)api_set_map + value->ValueOffset);
                    ULONG target_dll_len = value->ValueLength / 2;
                    for (ULONG k = 0; k < target_dll_len; k++) {
                        out_name[k] = (char)target_dll_wide[k];
                    }
                    out_name[target_dll_len] = '\0';
                    return;
                }
            }
        }
    }

    int k = 0;
    while (dll_name[k]) { out_name[k] = dll_name[k]; k++; }
    out_name[k] = '\0';
}

PVOID get_export_address_manual(HMODULE h_module, const char* func_name, pRtlInitAnsiString _RtlInitAnsiString, pLdrGetProcedureAddress _LdrGetProcedureAddress, pLdrLoadDll _LdrLoadDll, pRtlAnsiStringToUnicodeString _RtlAnsiStringToUnicodeString, pRtlFreeUnicodeString _RtlFreeUnicodeString) {
    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)h_module;
    PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)((char*)h_module + dos_header->e_lfanew);
    IMAGE_DATA_DIRECTORY export_dir_info = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    if (export_dir_info.Size == 0) return NULL;

    PIMAGE_EXPORT_DIRECTORY export_dir = (PIMAGE_EXPORT_DIRECTORY)((char*)h_module + export_dir_info.VirtualAddress);
    PDWORD names = (PDWORD)((char*)h_module + export_dir->AddressOfNames);
    PDWORD functions = (PDWORD)((char*)h_module + export_dir->AddressOfFunctions);
    PWORD ordinals = (PWORD)((char*)h_module + export_dir->AddressOfNameOrdinals);

    PVOID addr = NULL;
    if (IMAGE_SNAP_BY_ORDINAL((ULONG_PTR)func_name)) {
        WORD ordinal = IMAGE_ORDINAL((ULONG_PTR)func_name) - (WORD)export_dir->Base;
        addr = (PVOID)((char*)h_module + functions[ordinal]);
    } else {
        for (DWORD i = 0; i < export_dir->NumberOfNames; i++) {
            if (my_strcmp(func_name, (char*)h_module + names[i]) == 0) {
                addr = (PVOID)((char*)h_module + functions[ordinals[i]]);
                break;
            }
        }
    }

    if (!addr) return NULL;

    // Check for forwarded export
    if ((char*)addr >= (char*)export_dir && (char*)addr < (char*)export_dir + export_dir_info.Size) {
        char forward_str[MAX_PATH];
        int i = 0;
        while (((char*)addr)[i] != '\0' && i < MAX_PATH - 1) {
            forward_str[i] = ((char*)addr)[i];
            i++;
        }
        forward_str[i] = '\0';

        char* dot = NULL;
        for (int j = 0; j < i; j++) {
            if (forward_str[j] == '.') {
                dot = &forward_str[j];
                break;
            }
        }

        if (dot) {
            *dot = '\0';
            char dll_name[MAX_PATH];
            int k = 0;
            while (forward_str[k]) { dll_name[k] = forward_str[k]; k++; }
            // If it doesn't have an extension, add .dll
            int has_ext = 0;
            for(int m=0; m<k; m++) if(dll_name[m] == '.') has_ext = 1;
            if(!has_ext) {
                dll_name[k++] = '.'; dll_name[k++] = 'd'; dll_name[k++] = 'l'; dll_name[k++] = 'l'; dll_name[k] = '\0';
            } else {
                dll_name[k] = '\0';
            }

            char real_dll[MAX_PATH];
            resolve_api_set(dll_name, real_dll);

            HMODULE h_forward = GetModuleHandleA(real_dll);
            if (!h_forward) {
                ANSI_STRING a_dll;
                UNICODE_STRING u_dll;
                _RtlInitAnsiString(&a_dll, real_dll);
                _RtlAnsiStringToUnicodeString(&u_dll, &a_dll, TRUE);
                _LdrLoadDll(NULL, NULL, &u_dll, (PVOID*)&h_forward);
                _RtlFreeUnicodeString(&u_dll);
            }
            if (h_forward) {
                return get_export_address_manual(h_forward, dot + 1, _RtlInitAnsiString, _LdrGetProcedureAddress, _LdrLoadDll, _RtlAnsiStringToUnicodeString, _RtlFreeUnicodeString);
            }
        }
    }

    return addr;
}

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
    HMODULE h_ntdll = GetModuleHandleA("ntdll.dll");
    pLdrLoadDll _LdrLoadDll = (pLdrLoadDll)GetProcAddress(h_ntdll, "LdrLoadDll");
    pLdrGetProcedureAddress _LdrGetProcedureAddress = (pLdrGetProcedureAddress)GetProcAddress(h_ntdll, "LdrGetProcedureAddress");
    pRtlInitAnsiString _RtlInitAnsiString = (pRtlInitAnsiString)GetProcAddress(h_ntdll, "RtlInitAnsiString");
    pRtlAnsiStringToUnicodeString _RtlAnsiStringToUnicodeString = (pRtlAnsiStringToUnicodeString)GetProcAddress(h_ntdll, "RtlAnsiStringToUnicodeString");
    pRtlFreeUnicodeString _RtlFreeUnicodeString = (pRtlFreeUnicodeString)GetProcAddress(h_ntdll, "RtlFreeUnicodeString");

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
            const char* dll_name = (char*)pe_buffer + import_desc->Name;
            char resolved_dll[MAX_PATH];
            resolve_api_set(dll_name, resolved_dll);

            ANSI_STRING ansi_dll;
            UNICODE_STRING uni_dll;
            _RtlInitAnsiString(&ansi_dll, resolved_dll);
            _RtlAnsiStringToUnicodeString(&uni_dll, &ansi_dll, TRUE);

            HANDLE h_module = NULL;
            _LdrLoadDll(NULL, NULL, &uni_dll, &h_module);
            _RtlFreeUnicodeString(&uni_dll);

            if (h_module) {
                PIMAGE_THUNK_DATA first_thunk = (PIMAGE_THUNK_DATA)((char*)pe_buffer + import_desc->FirstThunk);
                PIMAGE_THUNK_DATA original_first_thunk = (PIMAGE_THUNK_DATA)((char*)pe_buffer + import_desc->OriginalFirstThunk);
                if (!import_desc->OriginalFirstThunk) original_first_thunk = first_thunk;

                while (original_first_thunk->u1.AddressOfData) {
                    PVOID addr = NULL;
                    if (IMAGE_SNAP_BY_ORDINAL(original_first_thunk->u1.Ordinal)) {
                        addr = get_export_address_manual((HMODULE)h_module, (char*)original_first_thunk->u1.Ordinal, _RtlInitAnsiString, _LdrGetProcedureAddress, _LdrLoadDll, _RtlAnsiStringToUnicodeString, _RtlFreeUnicodeString);
                    } else {
                        PIMAGE_IMPORT_BY_NAME import_by_name = (PIMAGE_IMPORT_BY_NAME)((char*)pe_buffer + original_first_thunk->u1.AddressOfData);
                        addr = get_export_address_manual((HMODULE)h_module, (char*)import_by_name->Name, _RtlInitAnsiString, _LdrGetProcedureAddress, _LdrLoadDll, _RtlAnsiStringToUnicodeString, _RtlFreeUnicodeString);
                    }
                    first_thunk->u1.Function = (ULONG_PTR)addr;
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
        HMODULE h_nt_internal = GetModuleHandleA("ntdll.dll");
        RAFA pRtlAddFunctionTable = (RAFA)GetProcAddress(h_nt_internal, "RtlAddFunctionTable");
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
    printf("Press Enter to exit...");
    getchar();
    return 0;
}
