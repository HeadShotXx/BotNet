/**
 * loader_template.c - Advanced Reflective Loader (Zero Dependencies)
 * Optimized for Rust and modern Windows environments.
 */

#define NULL ((void*)0)

#ifdef _WIN64
typedef unsigned long long QWORD;
typedef unsigned long long ULONG_PTR;
typedef unsigned long long UINT_PTR;
#else
typedef unsigned int QWORD;
typedef unsigned int ULONG_PTR;
typedef unsigned int UINT_PTR;
#endif

typedef unsigned int DWORD;
typedef unsigned short WORD;
typedef unsigned char BYTE;
typedef void* PVOID;
typedef PVOID HANDLE;
typedef PVOID HMODULE;
typedef PVOID HINSTANCE;
typedef QWORD SIZE_T;
typedef int BOOL;
typedef long LONG;
typedef unsigned long ULONG;
typedef void VOID;
typedef ULONG* PULONG;
typedef unsigned short USHORT;
typedef USHORT* PWSTR;
typedef char* PSTR;
typedef USHORT WCHAR;
typedef unsigned char BOOLEAN;
typedef void* LPVOID;
typedef unsigned long long DWORD64;
typedef DWORD* PDWORD;
typedef WORD* PWORD;
typedef LONG NTSTATUS;
typedef DWORD* LPDWORD;

#define TRUE 1
#define FALSE 0

#define DLL_PROCESS_ATTACH 1
#define DLL_THREAD_ATTACH  2
#define DLL_THREAD_DETACH  3
#define DLL_PROCESS_DETACH 0

#define MEM_COMMIT 0x00001000
#define MEM_RESERVE 0x00002000
#define MEM_RELEASE 0x00008000
#define PAGE_READWRITE 0x04
#define PAGE_EXECUTE_READWRITE 0x40
#define PAGE_EXECUTE_READ 0x20
#define PAGE_EXECUTE 0x10
#define PAGE_READONLY 0x02
#define PAGE_NOACCESS 0x01

#define IMAGE_DIRECTORY_ENTRY_EXPORT 0
#define IMAGE_DIRECTORY_ENTRY_IMPORT 1
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION 3
#define IMAGE_DIRECTORY_ENTRY_BASERELOC 5
#define IMAGE_DIRECTORY_ENTRY_TLS 9
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT 13

#define IMAGE_FILE_DLL 0x2000

#define IMAGE_SCN_MEM_EXECUTE 0x20000000
#define IMAGE_SCN_MEM_READ 0x40000000
#define IMAGE_SCN_MEM_WRITE 0x80000000

#define IMAGE_REL_BASED_HIGHLOW 3
#define IMAGE_REL_BASED_DIR64 10

#ifdef _WIN64
#define IMAGE_ORDINAL_FLAG 0x8000000000000000ULL
#else
#define IMAGE_ORDINAL_FLAG 0x80000000
#endif

#define IMAGE_SNAP_BY_ORDINAL(Ordinal) ((Ordinal & IMAGE_ORDINAL_FLAG) != 0)
#define IMAGE_ORDINAL(Ordinal) (Ordinal & 0xffff)

#ifndef MAX_PATH
#define MAX_PATH 260
#endif

#ifdef _WIN64
#define WINABI
#else
#define WINABI __attribute__((stdcall))
#endif

#ifdef _WIN64
#ifndef _MSC_VER
__asm__(
    ".global call_aligned\n"
    "call_aligned:\n"
    "push %rbp\n"
    "mov %rsp, %rbp\n"
    "and $-16, %rsp\n"
    "sub $48, %rsp\n"
    "mov %rcx, %rax\n"        // RAX = func
    "mov %rdx, %rcx\n"        // RCX = p1
    "mov %r8, %rdx\n"         // RDX = p2
    "mov %r9, %r8\n"          // R8  = p3
    "mov 48(%rbp), %r9\n"     // R9  = p4
    "call *%rax\n"
    "mov %rbp, %rsp\n"
    "pop %rbp\n"
    "ret\n"
);
extern ULONG_PTR call_aligned(PVOID func, PVOID p1, PVOID p2, PVOID p3, PVOID p4);
#endif
#endif

// --- Structures ---

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

typedef struct _LIST_ENTRY {
    struct _LIST_ENTRY *Flink;
    struct _LIST_ENTRY *Blink;
} LIST_ENTRY, *PLIST_ENTRY;

typedef struct _PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB {
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    union {
        BOOLEAN BitField;
        struct {
            BOOLEAN ImageUsesLargePages : 1;
            BOOLEAN IsProtectedProcess : 1;
            BOOLEAN IsImageDynamicallyRelocated : 1;
            BOOLEAN SkipPatchingLocals : 1;
            BOOLEAN IsPackagedProcess : 1;
            BOOLEAN IsAppContainer : 1;
            BOOLEAN IsProtectedProcessLight : 1;
            BOOLEAN IsLongPathAwareProcess : 1;
        };
    };
    HANDLE Mutant;
    PVOID ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
} PEB, *PPEB;

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
    LONG e_lfanew;
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

#ifdef _WIN64
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
typedef IMAGE_OPTIONAL_HEADER64 IMAGE_OPTIONAL_HEADER;
#else
typedef struct _IMAGE_OPTIONAL_HEADER32 {
    WORD Magic;
    BYTE MajorLinkerVersion;
    BYTE MinorLinkerVersion;
    DWORD SizeOfCode;
    DWORD SizeOfInitializedData;
    DWORD SizeOfUninitializedData;
    DWORD AddressOfEntryPoint;
    DWORD BaseOfCode;
    DWORD ImageBase;
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
    DWORD SizeOfStackReserve;
    DWORD SizeOfStackCommit;
    DWORD SizeOfHeapReserve;
    DWORD SizeOfHeapCommit;
    DWORD LoaderFlags;
    DWORD NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[16];
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;
typedef IMAGE_OPTIONAL_HEADER32 IMAGE_OPTIONAL_HEADER;
#endif

typedef struct _IMAGE_NT_HEADERS {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER OptionalHeader;
} IMAGE_NT_HEADERS, *PIMAGE_NT_HEADERS;

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

#define IMAGE_FIRST_SECTION(ntheader) ((PIMAGE_SECTION_HEADER)((ULONG_PTR)(ntheader) + \
    sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + (ntheader)->FileHeader.SizeOfOptionalHeader))

typedef struct _IMAGE_EXPORT_DIRECTORY {
    DWORD Characteristics;
    DWORD TimeDateStamp;
    WORD MajorVersion;
    WORD MinorVersion;
    DWORD Name;
    DWORD Base;
    DWORD NumberOfFunctions;
    DWORD NumberOfNames;
    DWORD AddressOfFunctions;
    DWORD AddressOfNames;
    DWORD AddressOfNameOrdinals;
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;

typedef struct _IMAGE_IMPORT_DESCRIPTOR {
    union {
        DWORD Characteristics;
        DWORD OriginalFirstThunk;
    };
    DWORD TimeDateStamp;
    DWORD ForwarderChain;
    DWORD Name;
    DWORD FirstThunk;
} IMAGE_IMPORT_DESCRIPTOR, *PIMAGE_IMPORT_DESCRIPTOR;

typedef struct _IMAGE_DELAYLOAD_DESCRIPTOR {
    union {
        DWORD AllAttributes;
        struct {
            DWORD RvaBased : 1;
            DWORD ReservedAttributes : 31;
        } Attributes;
    } Attributes;
    DWORD DllNameRVA;
    DWORD ModuleHandleRVA;
    DWORD ImportAddressTableRVA;
    DWORD ImportNameTableRVA;
    DWORD BoundImportAddressTableRVA;
    DWORD UnloadInformationTableRVA;
    DWORD TimeDateStamp;
} IMAGE_DELAYLOAD_DESCRIPTOR, *PIMAGE_DELAYLOAD_DESCRIPTOR;

typedef struct _IMAGE_THUNK_DATA {
    union {
        ULONG_PTR ForwarderString;
        ULONG_PTR Function;
        ULONG_PTR Ordinal;
        ULONG_PTR AddressOfData;
    } u1;
} IMAGE_THUNK_DATA, *PIMAGE_THUNK_DATA;

typedef struct _IMAGE_IMPORT_BY_NAME {
    WORD Hint;
    char Name[1];
} IMAGE_IMPORT_BY_NAME, *PIMAGE_IMPORT_BY_NAME;

typedef struct _IMAGE_BASE_RELOCATION {
    DWORD VirtualAddress;
    DWORD SizeOfBlock;
} IMAGE_BASE_RELOCATION, *PIMAGE_BASE_RELOCATION;

typedef struct _IMAGE_TLS_DIRECTORY {
    ULONG_PTR StartAddressOfRawData;
    ULONG_PTR EndAddressOfRawData;
    ULONG_PTR AddressOfIndex;
    ULONG_PTR AddressOfCallBacks;
    DWORD SizeOfZeroFill;
    DWORD Characteristics;
} IMAGE_TLS_DIRECTORY, *PIMAGE_TLS_DIRECTORY;

typedef struct _RUNTIME_FUNCTION {
    DWORD BeginAddress;
    DWORD EndAddress;
    DWORD UnwindData;
} RUNTIME_FUNCTION, *PRUNTIME_FUNCTION;

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

// --- Function Pointer Types ---

typedef NTSTATUS (WINABI *fLdrLoadDll)(PWSTR, PULONG, PUNICODE_STRING, PVOID*);
typedef NTSTATUS (WINABI *fLdrGetProcedureAddress)(PVOID, PANSI_STRING, ULONG, PVOID*);
typedef VOID (WINABI *fRtlInitAnsiString)(PANSI_STRING, const char*);
typedef NTSTATUS (WINABI *fRtlAnsiStringToUnicodeString)(PUNICODE_STRING, PANSI_STRING, BOOLEAN);
typedef VOID (WINABI *fRtlFreeUnicodeString)(PUNICODE_STRING);
typedef LPVOID (WINABI *fVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL (WINABI *fVirtualFree)(LPVOID, SIZE_T, DWORD);
typedef BOOL (WINABI *fVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef BOOL (WINABI *fRtlAddFunctionTable)(PRUNTIME_FUNCTION, DWORD, DWORD64);
typedef VOID (WINABI *PIMAGE_TLS_CALLBACK)(PVOID, DWORD, PVOID);
typedef DWORD (WINABI *fTlsAlloc)(VOID);
typedef LPVOID (WINABI *fTlsGetValue)(DWORD);
typedef BOOL (WINABI *fTlsSetValue)(DWORD, LPVOID);
typedef LPVOID (WINABI *fGetProcAddress)(HMODULE, const char*);
typedef HANDLE (WINABI *fGetProcessHeap)(VOID);
typedef LPVOID (WINABI *fHeapAlloc)(HANDLE, DWORD, SIZE_T);
typedef BOOL (WINABI *fHeapFree)(HANDLE, DWORD, LPVOID);
typedef HANDLE (WINABI *fCreateThread)(LPVOID, SIZE_T, LPVOID, LPVOID, DWORD, LPDWORD);
typedef HANDLE (WINABI *fGetStdHandle)(DWORD);
typedef BOOL (WINABI *fWriteFile)(HANDLE, LPVOID, DWORD, LPDWORD, LPVOID);
typedef BOOL (WINABI *fReadFile)(HANDLE, LPVOID, DWORD, LPDWORD, LPVOID);
typedef HMODULE (WINABI *fGetModuleHandleA)(const char*);
typedef HMODULE (WINABI *fGetModuleHandleW)(const WCHAR*);
typedef DWORD (WINABI *fGetModuleFileNameA)(HMODULE, char*, DWORD);
typedef DWORD (WINABI *fGetModuleFileNameW)(HMODULE, WCHAR*, DWORD);

#define STD_INPUT_HANDLE  ((DWORD)-10)
#define STD_OUTPUT_HANDLE ((DWORD)-11)

// --- PEB / TEB Access ---

#ifdef _MSC_VER
#include <intrin.h>
#define GET_PEB() (PVOID)(sizeof(PVOID) == 8 ? __readgsqword(0x60) : __readfsdword(0x30))
#define GET_TEB() (PVOID)(sizeof(PVOID) == 8 ? __readgsqword(0x30) : __readfsdword(0x18))
#else
static __inline__ PVOID GET_PEB() {
    PVOID peb;
#ifdef _WIN64
    __asm__("mov %%gs:0x60, %0" : "=r" (peb));
#else
    __asm__("mov %%fs:0x30, %0" : "=r" (peb));
#endif
    return peb;
}
static __inline__ PVOID GET_TEB() {
    PVOID teb;
#ifdef _WIN64
    __asm__("mov %%gs:0x30, %0" : "=r" (teb));
#else
    __asm__("mov %%fs:0x18, %0" : "=r" (teb));
#endif
    return teb;
}
#endif

// --- Global Variables ---
static PIMAGE_TLS_DIRECTORY g_tls_dir = NULL;
static DWORD g_tls_index = 0xFFFFFFFF;
static fVirtualAlloc g_vAlloc = NULL;
static fVirtualFree g_vFree = NULL;
static fTlsGetValue g_fTlsGetValue = NULL;
static fTlsSetValue g_fTlsSetValue = NULL;
static fGetProcessHeap g_fGetProcessHeap = NULL;
static fHeapAlloc g_fHeapAlloc = NULL;
static fHeapFree g_fHeapFree = NULL;
static fCreateThread g_origCreateThread = NULL;
static fGetProcAddress g_origGetProcAddress = NULL;
static fGetModuleHandleA g_origGetModuleHandleA = NULL;
static fGetModuleHandleW g_origGetModuleHandleW = NULL;
static fGetModuleFileNameA g_origGetModuleFileNameA = NULL;
static fGetModuleFileNameW g_origGetModuleFileNameW = NULL;
static fRtlInitAnsiString g_RtlInitAnsiString = NULL;
static fLdrGetProcedureAddress g_LdrGetProcedureAddress = NULL;
static fLdrLoadDll g_LdrLoadDll = NULL;
static fRtlAnsiStringToUnicodeString g_RtlAnsiStringToUnicodeString = NULL;
static fRtlFreeUnicodeString g_RtlFreeUnicodeString = NULL;

static PVOID g_pe_base = NULL;
static BOOL g_is_dll = FALSE;
static DWORD g_entry_point_rva = 0;

// --- Helper Functions ---

static void* my_memcpy(void* dest, const void* src, SIZE_T n) {
    char* d = (char*)dest;
    const char* s = (const char*)src;
    if (!d || !s) return dest;
    while (n--) *d++ = *s++;
    return dest;
}

static void* my_memset(void* s, int c, SIZE_T n) {
    unsigned char* p = (unsigned char*)s;
    if (!p) return s;
    while (n--) *p++ = (unsigned char)c;
    return s;
}

static int my_strlen(const char* s) {
    int l = 0;
    while (s && s[l]) l++;
    return l;
}

static int my_strcmp(const char* s1, const char* s2) {
    if (!s1 || !s2) return -1;
    while (*s1 && (*s1 == *s2)) { s1++; s2++; }
    return *(unsigned char*)s1 - *(unsigned char*)s2;
}

static int my_strncmp(const char* s1, const char* s2, SIZE_T n) {
    if (!s1 || !s2) return -1;
    while (n && *s1 && (*s1 == *s2)) { s1++; s2++; n--; }
    if (n == 0) return 0;
    return *(unsigned char*)s1 - *(unsigned char*)s2;
}

// --- Manual Resolution Logic ---

static PVOID get_module_handle_manual(const char* dll_name) {
    PPEB peb = (PPEB)GET_PEB();
    PLIST_ENTRY head = &peb->Ldr->InLoadOrderModuleList;
    PLIST_ENTRY curr = head->Flink;
    while (curr != head) {
        PLDR_DATA_TABLE_ENTRY entry = (PLDR_DATA_TABLE_ENTRY)curr;
        if (dll_name == NULL) return entry->DllBase;
        WCHAR w_dll_name[MAX_PATH];
        int i = 0;
        while (dll_name[i] && i < MAX_PATH - 1) { w_dll_name[i] = (WCHAR)dll_name[i]; i++; }
        w_dll_name[i] = 0;
        int match = 1;
        if (entry->BaseDllName.Length / 2 >= (USHORT)i) {
            for (int j = 0; j < i; j++) {
                WCHAR c1 = w_dll_name[j];
                WCHAR c2 = entry->BaseDllName.Buffer[j];
                if (c1 >= 'A' && c1 <= 'Z') c1 += 32;
                if (c2 >= 'A' && c2 <= 'Z') c2 += 32;
                if (c1 != c2) { match = 0; break; }
            }
            if (match && (entry->BaseDllName.Length / 2 == (USHORT)i || entry->BaseDllName.Buffer[i] == 0)) return entry->DllBase;
        }
        curr = curr->Flink;
    }
    return NULL;
}

#define API_SET_NAMESPACE_OFFSET (sizeof(PVOID) == 8 ? 0x68 : 0x38)

static void resolve_api_set(const char* dll_name, char* out_name) {
    if (my_strncmp(dll_name, "api-", 4) != 0 && my_strncmp(dll_name, "ext-", 4) != 0) {
        int i = 0; while (dll_name[i]) { out_name[i] = dll_name[i]; i++; } out_name[i] = '\0';
        return;
    }
    PVOID peb = GET_PEB();
    PAPI_SET_NAMESPACE api_set_map = *(PAPI_SET_NAMESPACE*)((char*)peb + API_SET_NAMESPACE_OFFSET);
    if (api_set_map->Version < 6) {
        int i = 0; while (dll_name[i]) { out_name[i] = dll_name[i]; i++; } out_name[i] = '\0';
        return;
    }
    PAPI_SET_NAMESPACE_ENTRY entries = (PAPI_SET_NAMESPACE_ENTRY)((char*)api_set_map + api_set_map->EntryOffset);
    SIZE_T dll_name_len = my_strlen(dll_name);
    if (dll_name_len > 4 && (dll_name[dll_name_len - 4] == '.')) dll_name_len -= 4;
    for (ULONG i = 0; i < api_set_map->Count; i++) {
        PAPI_SET_NAMESPACE_ENTRY entry = &entries[i];
        PWSTR name = (PWSTR)((char*)api_set_map + entry->NameOffset);
        if (dll_name_len == (SIZE_T)entry->NameLength / 2) {
            int match = 1;
            for (SIZE_T j = 0; j < dll_name_len; j++) {
                WCHAR c1 = (WCHAR)dll_name[j]; WCHAR c2 = name[j];
                if (c1 >= 'A' && c1 <= 'Z') c1 += 32;
                if (c2 >= 'A' && c2 <= 'Z') c2 += 32;
                if (c1 != c2) { match = 0; break; }
            }
            if (match) {
                PAPI_SET_VALUE_ENTRY values = (PAPI_SET_VALUE_ENTRY)((char*)api_set_map + entry->ValueOffset);
                if (entry->ValueCount > 0) {
                    PAPI_SET_VALUE_ENTRY value = &values[0];
                    PWSTR target_dll_wide = (PWSTR)((char*)api_set_map + value->ValueOffset);
                    ULONG target_dll_len = value->ValueLength / 2;
                    for (ULONG k = 0; k < target_dll_len; k++) out_name[k] = (char)target_dll_wide[k];
                    out_name[target_dll_len] = '\0';
                    return;
                }
            }
        }
    }
    int k = 0; while (dll_name[k]) { out_name[k] = dll_name[k]; k++; } out_name[k] = '\0';
}

static PVOID get_export_address_manual_recursive(HMODULE h_module, const char* func_name, fRtlInitAnsiString _RtlInitAnsiString, fLdrGetProcedureAddress _LdrGetProcedureAddress, fLdrLoadDll _LdrLoadDll, fRtlAnsiStringToUnicodeString _RtlAnsiStringToUnicodeString, fRtlFreeUnicodeString _RtlFreeUnicodeString, int depth) {
    if (!h_module || depth > 10) return NULL;

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
        WORD ordinal = (WORD)IMAGE_ORDINAL((ULONG_PTR)func_name) - (WORD)export_dir->Base;
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
    if ((char*)addr >= (char*)export_dir && (char*)addr < (char*)export_dir + export_dir_info.Size) {
        char forward_str[MAX_PATH];
        int i = 0;
        while (((char*)addr)[i] != '\0' && i < MAX_PATH - 1) { forward_str[i] = ((char*)addr)[i]; i++; }
        forward_str[i] = '\0';
        char* dot = NULL;
        for (int j = 0; j < i; j++) { if (forward_str[j] == '.') { dot = &forward_str[j]; break; } }
        if (dot) {
            *dot = '\0';
            char dll_name[MAX_PATH];
            int k = 0;
            while (forward_str[k]) { dll_name[k] = forward_str[k]; k++; }
            int has_ext = 0;
            for(int m=0; m<k; m++) if(dll_name[m] == '.') has_ext = 1;
            if(!has_ext) { dll_name[k++] = '.'; dll_name[k++] = 'd'; dll_name[k++] = 'l'; dll_name[k++] = 'l'; dll_name[k] = '\0'; }
            else { dll_name[k] = '\0'; }
            char real_dll[MAX_PATH];
            resolve_api_set(dll_name, real_dll);
            HMODULE h_forward = get_module_handle_manual(real_dll);
            if (!h_forward && _RtlInitAnsiString && _RtlAnsiStringToUnicodeString && _LdrLoadDll && _RtlFreeUnicodeString) {
                ANSI_STRING a_dll; UNICODE_STRING u_dll;
                _RtlInitAnsiString(&a_dll, real_dll);
                _RtlAnsiStringToUnicodeString(&u_dll, &a_dll, TRUE);
                _LdrLoadDll(NULL, NULL, &u_dll, (PVOID*)&h_forward);
                _RtlFreeUnicodeString(&u_dll);
            }
            if (h_forward) {
                return get_export_address_manual_recursive(h_forward, dot + 1, _RtlInitAnsiString, _LdrGetProcedureAddress, _LdrLoadDll, _RtlAnsiStringToUnicodeString, _RtlFreeUnicodeString, depth + 1);
            }
        }
    }
    return addr;
}

static PVOID get_export_address_manual(HMODULE h_module, const char* func_name, fRtlInitAnsiString _RtlInitAnsiString, fLdrGetProcedureAddress _LdrGetProcedureAddress, fLdrLoadDll _LdrLoadDll, fRtlAnsiStringToUnicodeString _RtlAnsiStringToUnicodeString, fRtlFreeUnicodeString _RtlFreeUnicodeString) {
    return get_export_address_manual_recursive(h_module, func_name, _RtlInitAnsiString, _LdrGetProcedureAddress, _LdrLoadDll, _RtlAnsiStringToUnicodeString, _RtlFreeUnicodeString, 0);
}

// --- TLS Initialization Helper ---

static VOID init_thread_tls() {
    if (!g_tls_dir || !g_fTlsSetValue || !g_fTlsGetValue || !g_vAlloc || g_tls_index == 0xFFFFFFFF) return;

    if (g_fTlsGetValue(g_tls_index) != NULL) return;

    SIZE_T tls_data_size = (SIZE_T)(g_tls_dir->EndAddressOfRawData - g_tls_dir->StartAddressOfRawData);
    SIZE_T total_tls_size = tls_data_size + g_tls_dir->SizeOfZeroFill;
    if (total_tls_size == 0) total_tls_size = 8;

    // Use VirtualAlloc for TLS data to ensure 4KB alignment (critical for some SIMD/Rust structures)
    LPVOID thread_tls_data = g_vAlloc(NULL, total_tls_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (thread_tls_data) {
        if (tls_data_size > 0 && g_tls_dir->StartAddressOfRawData) {
            my_memcpy(thread_tls_data, (const void*)g_tls_dir->StartAddressOfRawData, tls_data_size);
        }
        if (g_tls_dir->SizeOfZeroFill > 0) {
            my_memset((char*)thread_tls_data + tls_data_size, 0, g_tls_dir->SizeOfZeroFill);
        }

        g_fTlsSetValue(g_tls_index, thread_tls_data);

        // Update the static TLS pointer array in the TEB (ThreadLocalStoragePointer)
        // This is where __declspec(thread) variables are looked up via the TLS index.
        void*** tls_pointer_array_ptr = (void***)((char*)GET_TEB() + (sizeof(PVOID) == 8 ? 0x58 : 0x2C));
        if (*tls_pointer_array_ptr && g_tls_index < 64) {
            // 64 is a conservative limit for the pre-allocated array in most Windows processes.
            (*tls_pointer_array_ptr)[g_tls_index] = thread_tls_data;
        }
    }
}

static VOID run_tls_callbacks(DWORD reason) {
    if (!g_tls_dir) return;
    PIMAGE_TLS_CALLBACK* callbacks = (PIMAGE_TLS_CALLBACK*)g_tls_dir->AddressOfCallBacks;
    if (callbacks) {
        while (*callbacks) {
#ifdef _WIN64
            call_aligned((PVOID)*callbacks, (PVOID)g_pe_base, (PVOID)(ULONG_PTR)reason, NULL, NULL);
#else
            (*callbacks)(g_pe_base, reason, NULL);
#endif
            callbacks++;
        }
    }
}

// --- Thread Wrapper & Hook ---

typedef struct _WRAPPER_ARGS {
    LPVOID func;
    LPVOID param;
} WRAPPER_ARGS, *PWRAPPER_ARGS;

static DWORD WINABI ThreadWrapper(LPVOID lpParam) {
    if (!lpParam) return 0;
    PWRAPPER_ARGS args = (PWRAPPER_ARGS)lpParam;
    LPVOID func = args->func;
    LPVOID param = args->param;

    init_thread_tls();
    run_tls_callbacks(DLL_THREAD_ATTACH);

    if (g_is_dll) {
        typedef BOOL (WINABI *fDllMain)(HINSTANCE, DWORD, LPVOID);
        PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((char*)g_pe_base + ((PIMAGE_DOS_HEADER)g_pe_base)->e_lfanew);
        fDllMain dll_main = (fDllMain)((char*)g_pe_base + nt->OptionalHeader.AddressOfEntryPoint);
#ifdef _WIN64
        call_aligned((PVOID)dll_main, (PVOID)g_pe_base, (PVOID)DLL_THREAD_ATTACH, NULL, NULL);
#else
        dll_main((HINSTANCE)g_pe_base, DLL_THREAD_ATTACH, NULL);
#endif
    }

    DWORD result;
#ifdef _WIN64
    result = (DWORD)call_aligned((PVOID)func, (PVOID)param, NULL, NULL, NULL);
#else
    result = ((DWORD(WINABI*)(LPVOID))func)(param);
#endif

    if (g_is_dll) {
        typedef BOOL (WINABI *fDllMain)(HINSTANCE, DWORD, LPVOID);
        PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((char*)g_pe_base + ((PIMAGE_DOS_HEADER)g_pe_base)->e_lfanew);
        fDllMain dll_main = (fDllMain)((char*)g_pe_base + nt->OptionalHeader.AddressOfEntryPoint);
#ifdef _WIN64
        call_aligned((PVOID)dll_main, (PVOID)g_pe_base, (PVOID)DLL_THREAD_DETACH, NULL, NULL);
#else
        dll_main((HINSTANCE)g_pe_base, DLL_THREAD_DETACH, NULL);
#endif
    }

    run_tls_callbacks(DLL_THREAD_DETACH);

    // DONT free TLS data here. It causes "global allocator may not use TLS with destructors" in Rust.
    // System thread cleanup will eventually reclaim what it can, and modern allocators handle this better if we don't yank memory early.

    if (g_fHeapFree && g_fGetProcessHeap) g_fHeapFree(g_fGetProcessHeap(), 0, args);
    return result;
}

static HANDLE WINABI HookedCreateThread(LPVOID lpThreadAttributes, SIZE_T dwStackSize, LPVOID lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId) {
    if (!g_origCreateThread || !g_fHeapAlloc || !g_fGetProcessHeap) return NULL;
    PWRAPPER_ARGS args = (PWRAPPER_ARGS)g_fHeapAlloc(g_fGetProcessHeap(), 0, sizeof(WRAPPER_ARGS));
    if (!args) return NULL;
    args->func = lpStartAddress;
    args->param = lpParameter;
    HANDLE hThread = g_origCreateThread(lpThreadAttributes, dwStackSize, (LPVOID)ThreadWrapper, args, dwCreationFlags, lpThreadId);
    if (!hThread && g_fHeapFree) {
        g_fHeapFree(g_fGetProcessHeap(), 0, args);
    }
    return hThread;
}

static LPVOID WINABI HookedTlsGetValue(DWORD dwTlsIndex) {
    if (dwTlsIndex == g_tls_index) {
        LPVOID val = g_fTlsGetValue(dwTlsIndex);
        if (val == NULL) {
            init_thread_tls();
            val = g_fTlsGetValue(dwTlsIndex);
        }
        return val;
    }
    return g_fTlsGetValue(dwTlsIndex);
}

static LPVOID WINABI HookedGetProcAddress(HMODULE hModule, const char* lpProcName) {
    if (hModule == (HMODULE)g_pe_base) {
        return get_export_address_manual((HMODULE)g_pe_base, lpProcName, g_RtlInitAnsiString, g_LdrGetProcedureAddress, g_LdrLoadDll, g_RtlAnsiStringToUnicodeString, g_RtlFreeUnicodeString);
    }
    if (lpProcName && !IMAGE_SNAP_BY_ORDINAL((ULONG_PTR)lpProcName)) {
        if (my_strcmp(lpProcName, "CreateThread") == 0) return (LPVOID)HookedCreateThread;
        if (my_strcmp(lpProcName, "GetProcAddress") == 0) return (LPVOID)HookedGetProcAddress;
        if (my_strcmp(lpProcName, "TlsGetValue") == 0) return (LPVOID)HookedTlsGetValue;
    }
    return g_origGetProcAddress(hModule, lpProcName);
}

static HMODULE WINABI HookedGetModuleHandleA(const char* lpModuleName) {
    if (lpModuleName == NULL) return (HMODULE)g_pe_base;
    return g_origGetModuleHandleA(lpModuleName);
}

static HMODULE WINABI HookedGetModuleHandleW(const WCHAR* lpModuleName) {
    if (lpModuleName == NULL) return (HMODULE)g_pe_base;
    return g_origGetModuleHandleW(lpModuleName);
}

static DWORD WINABI HookedGetModuleFileNameA(HMODULE hModule, char* lpFilename, DWORD nSize) {
    if (hModule == NULL || hModule == (HMODULE)g_pe_base) {
        return g_origGetModuleFileNameA(NULL, lpFilename, nSize);
    }
    return g_origGetModuleFileNameA(hModule, lpFilename, nSize);
}

static DWORD WINABI HookedGetModuleFileNameW(HMODULE hModule, WCHAR* lpFilename, DWORD nSize) {
    if (hModule == NULL || hModule == (HMODULE)g_pe_base) {
        return g_origGetModuleFileNameW(NULL, lpFilename, nSize);
    }
    return g_origGetModuleFileNameW(hModule, lpFilename, nSize);
}

// --- Main loading logic ---

unsigned char pe_blob[] = {
    0x4D, 0x5A, 0x0A
};
// IMAGE_BASE
ULONG_PTR image_base = 0x0;
// SIZE_OF_IMAGE
SIZE_T size_of_image = 0x0;

void load_pe() {
    HMODULE h_ntdll = get_module_handle_manual("ntdll.dll");
    g_RtlInitAnsiString = (fRtlInitAnsiString)get_export_address_manual(h_ntdll, "RtlInitAnsiString", NULL, NULL, NULL, NULL, NULL);
    g_LdrGetProcedureAddress = (fLdrGetProcedureAddress)get_export_address_manual(h_ntdll, "LdrGetProcedureAddress", g_RtlInitAnsiString, NULL, NULL, NULL, NULL);
    g_LdrLoadDll = (fLdrLoadDll)get_export_address_manual(h_ntdll, "LdrLoadDll", g_RtlInitAnsiString, g_LdrGetProcedureAddress, NULL, NULL, NULL);
    g_RtlAnsiStringToUnicodeString = (fRtlAnsiStringToUnicodeString)get_export_address_manual(h_ntdll, "RtlAnsiStringToUnicodeString", g_RtlInitAnsiString, g_LdrGetProcedureAddress, g_LdrLoadDll, NULL, NULL);
    g_RtlFreeUnicodeString = (fRtlFreeUnicodeString)get_export_address_manual(h_ntdll, "RtlFreeUnicodeString", g_RtlInitAnsiString, g_LdrGetProcedureAddress, g_LdrLoadDll, g_RtlAnsiStringToUnicodeString, NULL);

    HMODULE h_kernel32 = get_module_handle_manual("kernel32.dll");
    g_vAlloc = (fVirtualAlloc)get_export_address_manual(h_kernel32, "VirtualAlloc", g_RtlInitAnsiString, g_LdrGetProcedureAddress, g_LdrLoadDll, g_RtlAnsiStringToUnicodeString, g_RtlFreeUnicodeString);
    g_vFree = (fVirtualFree)get_export_address_manual(h_kernel32, "VirtualFree", g_RtlInitAnsiString, g_LdrGetProcedureAddress, g_LdrLoadDll, g_RtlAnsiStringToUnicodeString, g_RtlFreeUnicodeString);
    fVirtualProtect _VirtualProtect = (fVirtualProtect)get_export_address_manual(h_kernel32, "VirtualProtect", g_RtlInitAnsiString, g_LdrGetProcedureAddress, g_LdrLoadDll, g_RtlAnsiStringToUnicodeString, g_RtlFreeUnicodeString);
    fTlsAlloc _TlsAlloc = (fTlsAlloc)get_export_address_manual(h_kernel32, "TlsAlloc", g_RtlInitAnsiString, g_LdrGetProcedureAddress, g_LdrLoadDll, g_RtlAnsiStringToUnicodeString, g_RtlFreeUnicodeString);
    g_fTlsGetValue = (fTlsGetValue)get_export_address_manual(h_kernel32, "TlsGetValue", g_RtlInitAnsiString, g_LdrGetProcedureAddress, g_LdrLoadDll, g_RtlAnsiStringToUnicodeString, g_RtlFreeUnicodeString);
    g_fTlsSetValue = (fTlsSetValue)get_export_address_manual(h_kernel32, "TlsSetValue", g_RtlInitAnsiString, g_LdrGetProcedureAddress, g_LdrLoadDll, g_RtlAnsiStringToUnicodeString, g_RtlFreeUnicodeString);
    g_fGetProcessHeap = (fGetProcessHeap)get_export_address_manual(h_kernel32, "GetProcessHeap", g_RtlInitAnsiString, g_LdrGetProcedureAddress, g_LdrLoadDll, g_RtlAnsiStringToUnicodeString, g_RtlFreeUnicodeString);
    g_fHeapAlloc = (fHeapAlloc)get_export_address_manual(h_kernel32, "HeapAlloc", g_RtlInitAnsiString, g_LdrGetProcedureAddress, g_LdrLoadDll, g_RtlAnsiStringToUnicodeString, g_RtlFreeUnicodeString);
    g_fHeapFree = (fHeapFree)get_export_address_manual(h_kernel32, "HeapFree", g_RtlInitAnsiString, g_LdrGetProcedureAddress, g_LdrLoadDll, g_RtlAnsiStringToUnicodeString, g_RtlFreeUnicodeString);
    g_origGetProcAddress = (fGetProcAddress)get_export_address_manual(h_kernel32, "GetProcAddress", g_RtlInitAnsiString, g_LdrGetProcedureAddress, g_LdrLoadDll, g_RtlAnsiStringToUnicodeString, g_RtlFreeUnicodeString);
    g_origGetModuleHandleA = (fGetModuleHandleA)get_export_address_manual(h_kernel32, "GetModuleHandleA", g_RtlInitAnsiString, g_LdrGetProcedureAddress, g_LdrLoadDll, g_RtlAnsiStringToUnicodeString, g_RtlFreeUnicodeString);
    g_origGetModuleHandleW = (fGetModuleHandleW)get_export_address_manual(h_kernel32, "GetModuleHandleW", g_RtlInitAnsiString, g_LdrGetProcedureAddress, g_LdrLoadDll, g_RtlAnsiStringToUnicodeString, g_RtlFreeUnicodeString);
    g_origGetModuleFileNameA = (fGetModuleFileNameA)get_export_address_manual(h_kernel32, "GetModuleFileNameA", g_RtlInitAnsiString, g_LdrGetProcedureAddress, g_LdrLoadDll, g_RtlAnsiStringToUnicodeString, g_RtlFreeUnicodeString);
    g_origGetModuleFileNameW = (fGetModuleFileNameW)get_export_address_manual(h_kernel32, "GetModuleFileNameW", g_RtlInitAnsiString, g_LdrGetProcedureAddress, g_LdrLoadDll, g_RtlAnsiStringToUnicodeString, g_RtlFreeUnicodeString);

    PIMAGE_DOS_HEADER dos_header_raw = (PIMAGE_DOS_HEADER)pe_blob;
    PIMAGE_NT_HEADERS nt_headers_raw = (PIMAGE_NT_HEADERS)((char*)pe_blob + dos_header_raw->e_lfanew);
    LPVOID pe_buffer = g_vAlloc(NULL, nt_headers_raw->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!pe_buffer) return;
    g_pe_base = pe_buffer;
    g_is_dll = (nt_headers_raw->FileHeader.Characteristics & IMAGE_FILE_DLL) != 0;
    g_entry_point_rva = nt_headers_raw->OptionalHeader.AddressOfEntryPoint;
    my_memcpy(pe_buffer, pe_blob, nt_headers_raw->OptionalHeader.SizeOfHeaders);
    PIMAGE_SECTION_HEADER sections_raw = IMAGE_FIRST_SECTION(nt_headers_raw);
    for (int i = 0; i < nt_headers_raw->FileHeader.NumberOfSections; i++) {
        if (sections_raw[i].PointerToRawData != 0) {
            my_memcpy((char*)pe_buffer + sections_raw[i].VirtualAddress, (char*)pe_blob + sections_raw[i].PointerToRawData, sections_raw[i].SizeOfRawData);
        }
    }
    PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)((char*)pe_buffer + ((PIMAGE_DOS_HEADER)pe_buffer)->e_lfanew);

    ULONG_PTR delta = (ULONG_PTR)pe_buffer - nt_headers->OptionalHeader.ImageBase;
    if (delta != 0) {
        IMAGE_DATA_DIRECTORY reloc_dir = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (reloc_dir.Size > 0) {
            PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)((char*)pe_buffer + reloc_dir.VirtualAddress);
            while (reloc->VirtualAddress != 0) {
                DWORD count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                WORD* list = (WORD*)((char*)reloc + sizeof(IMAGE_BASE_RELOCATION));
                for (DWORD i = 0; i < count; i++) {
                    WORD type = list[i] >> 12; WORD offset = list[i] & 0xFFF;
                    if (type == IMAGE_REL_BASED_DIR64) *(ULONG_PTR*)((char*)pe_buffer + reloc->VirtualAddress + offset) += delta;
                    else if (type == IMAGE_REL_BASED_HIGHLOW) *(DWORD*)((char*)pe_buffer + reloc->VirtualAddress + offset) += (DWORD)delta;
                }
                reloc = (PIMAGE_BASE_RELOCATION)((char*)reloc + reloc->SizeOfBlock);
            }
        }
    }

    IMAGE_DATA_DIRECTORY tls_dir_info = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (tls_dir_info.Size > 0) {
        g_tls_dir = (PIMAGE_TLS_DIRECTORY)((char*)pe_buffer + tls_dir_info.VirtualAddress);
        g_tls_index = _TlsAlloc();
        if (g_tls_index != 0xFFFFFFFF) {
            if (g_tls_dir->AddressOfIndex) *(DWORD*)(g_tls_dir->AddressOfIndex) = g_tls_index;
        }
    }

    IMAGE_DATA_DIRECTORY import_dir = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (import_dir.Size > 0) {
        PIMAGE_IMPORT_DESCRIPTOR import_desc = (PIMAGE_IMPORT_DESCRIPTOR)((char*)pe_buffer + import_dir.VirtualAddress);
        while (import_desc->Name) {
            const char* dll_name = (char*)pe_buffer + import_desc->Name;
            char resolved_dll[MAX_PATH]; resolve_api_set(dll_name, resolved_dll);
            ANSI_STRING ansi_dll; UNICODE_STRING uni_dll;
            g_RtlInitAnsiString(&ansi_dll, resolved_dll);
            g_RtlAnsiStringToUnicodeString(&uni_dll, &ansi_dll, TRUE);
            HANDLE h_module = NULL; g_LdrLoadDll(NULL, NULL, &uni_dll, &h_module); g_RtlFreeUnicodeString(&uni_dll);
            if (h_module) {
                PIMAGE_THUNK_DATA first_thunk = (PIMAGE_THUNK_DATA)((char*)pe_buffer + import_desc->FirstThunk);
                PIMAGE_THUNK_DATA original_first_thunk = (PIMAGE_THUNK_DATA)((char*)pe_buffer + import_desc->OriginalFirstThunk);
                if (!import_desc->OriginalFirstThunk) original_first_thunk = first_thunk;
                while (original_first_thunk->u1.AddressOfData) {
                    PVOID addr = NULL;
                    if (IMAGE_SNAP_BY_ORDINAL(original_first_thunk->u1.Ordinal)) {
                        addr = get_export_address_manual((HMODULE)h_module, (char*)original_first_thunk->u1.Ordinal, g_RtlInitAnsiString, g_LdrGetProcedureAddress, g_LdrLoadDll, g_RtlAnsiStringToUnicodeString, g_RtlFreeUnicodeString);
                    } else {
                        PIMAGE_IMPORT_BY_NAME import_by_name = (PIMAGE_IMPORT_BY_NAME)((char*)pe_buffer + original_first_thunk->u1.AddressOfData);
                        if (my_strcmp(import_by_name->Name, "CreateThread") == 0) {
                            if (!g_origCreateThread) g_origCreateThread = (fCreateThread)get_export_address_manual((HMODULE)h_module, "CreateThread", g_RtlInitAnsiString, g_LdrGetProcedureAddress, g_LdrLoadDll, g_RtlAnsiStringToUnicodeString, g_RtlFreeUnicodeString);
                            addr = (PVOID)HookedCreateThread;
                        } else if (my_strcmp(import_by_name->Name, "GetProcAddress") == 0) {
                            if (!g_origGetProcAddress) g_origGetProcAddress = (fGetProcAddress)get_export_address_manual((HMODULE)h_module, "GetProcAddress", g_RtlInitAnsiString, g_LdrGetProcedureAddress, g_LdrLoadDll, g_RtlAnsiStringToUnicodeString, g_RtlFreeUnicodeString);
                            addr = (PVOID)HookedGetProcAddress;
                        } else if (my_strcmp(import_by_name->Name, "GetModuleHandleA") == 0) {
                            if (!g_origGetModuleHandleA) g_origGetModuleHandleA = (fGetModuleHandleA)get_export_address_manual((HMODULE)h_module, "GetModuleHandleA", g_RtlInitAnsiString, g_LdrGetProcedureAddress, g_LdrLoadDll, g_RtlAnsiStringToUnicodeString, g_RtlFreeUnicodeString);
                            addr = (PVOID)HookedGetModuleHandleA;
                        } else if (my_strcmp(import_by_name->Name, "GetModuleHandleW") == 0) {
                            if (!g_origGetModuleHandleW) g_origGetModuleHandleW = (fGetModuleHandleW)get_export_address_manual((HMODULE)h_module, "GetModuleHandleW", g_RtlInitAnsiString, g_LdrGetProcedureAddress, g_LdrLoadDll, g_RtlAnsiStringToUnicodeString, g_RtlFreeUnicodeString);
                            addr = (PVOID)HookedGetModuleHandleW;
                        } else if (my_strcmp(import_by_name->Name, "TlsGetValue") == 0) {
                            addr = (PVOID)HookedTlsGetValue;
                        } else if (my_strcmp(import_by_name->Name, "GetModuleFileNameA") == 0) {
                            if (!g_origGetModuleFileNameA) g_origGetModuleFileNameA = (fGetModuleFileNameA)get_export_address_manual((HMODULE)h_module, "GetModuleFileNameA", g_RtlInitAnsiString, g_LdrGetProcedureAddress, g_LdrLoadDll, g_RtlAnsiStringToUnicodeString, g_RtlFreeUnicodeString);
                            addr = (PVOID)HookedGetModuleFileNameA;
                        } else if (my_strcmp(import_by_name->Name, "GetModuleFileNameW") == 0) {
                            if (!g_origGetModuleFileNameW) g_origGetModuleFileNameW = (fGetModuleFileNameW)get_export_address_manual((HMODULE)h_module, "GetModuleFileNameW", g_RtlInitAnsiString, g_LdrGetProcedureAddress, g_LdrLoadDll, g_RtlAnsiStringToUnicodeString, g_RtlFreeUnicodeString);
                            addr = (PVOID)HookedGetModuleFileNameW;
                        } else {
                            addr = get_export_address_manual((HMODULE)h_module, (char*)import_by_name->Name, g_RtlInitAnsiString, g_LdrGetProcedureAddress, g_LdrLoadDll, g_RtlAnsiStringToUnicodeString, g_RtlFreeUnicodeString);
                        }
                    }
                    first_thunk->u1.Function = (ULONG_PTR)addr; first_thunk++; original_first_thunk++;
                }
            }
            import_desc++;
        }
    }

    IMAGE_DATA_DIRECTORY delay_import_dir = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
    if (delay_import_dir.Size > 0) {
        PIMAGE_DELAYLOAD_DESCRIPTOR delay_desc = (PIMAGE_DELAYLOAD_DESCRIPTOR)((char*)pe_buffer + delay_import_dir.VirtualAddress);
        while (delay_desc->DllNameRVA) {
            const char* dll_name = (char*)pe_buffer + delay_desc->DllNameRVA;
            char resolved_dll[MAX_PATH]; resolve_api_set(dll_name, resolved_dll);
            ANSI_STRING ansi_dll; UNICODE_STRING uni_dll;
            g_RtlInitAnsiString(&ansi_dll, resolved_dll);
            g_RtlAnsiStringToUnicodeString(&uni_dll, &ansi_dll, TRUE);
            HANDLE h_module = NULL; g_LdrLoadDll(NULL, NULL, &uni_dll, &h_module); g_RtlFreeUnicodeString(&uni_dll);
            if (h_module) {
                PIMAGE_THUNK_DATA first_thunk = (PIMAGE_THUNK_DATA)((char*)pe_buffer + delay_desc->ImportAddressTableRVA);
                PIMAGE_THUNK_DATA original_first_thunk = (PIMAGE_THUNK_DATA)((char*)pe_buffer + delay_desc->ImportNameTableRVA);
                while (original_first_thunk->u1.AddressOfData) {
                    PVOID addr = NULL;
                    if (IMAGE_SNAP_BY_ORDINAL(original_first_thunk->u1.Ordinal)) {
                        addr = get_export_address_manual((HMODULE)h_module, (char*)original_first_thunk->u1.Ordinal, g_RtlInitAnsiString, g_LdrGetProcedureAddress, g_LdrLoadDll, g_RtlAnsiStringToUnicodeString, g_RtlFreeUnicodeString);
                    } else {
                        PIMAGE_IMPORT_BY_NAME import_by_name = (PIMAGE_IMPORT_BY_NAME)((char*)pe_buffer + original_first_thunk->u1.AddressOfData);
                        if (my_strcmp(import_by_name->Name, "CreateThread") == 0) {
                            if (!g_origCreateThread) g_origCreateThread = (fCreateThread)get_export_address_manual((HMODULE)h_module, "CreateThread", g_RtlInitAnsiString, g_LdrGetProcedureAddress, g_LdrLoadDll, g_RtlAnsiStringToUnicodeString, g_RtlFreeUnicodeString);
                            addr = (PVOID)HookedCreateThread;
                        } else if (my_strcmp(import_by_name->Name, "GetProcAddress") == 0) {
                            if (!g_origGetProcAddress) g_origGetProcAddress = (fGetProcAddress)get_export_address_manual((HMODULE)h_module, "GetProcAddress", g_RtlInitAnsiString, g_LdrGetProcedureAddress, g_LdrLoadDll, g_RtlAnsiStringToUnicodeString, g_RtlFreeUnicodeString);
                            addr = (PVOID)HookedGetProcAddress;
                        } else if (my_strcmp(import_by_name->Name, "GetModuleHandleA") == 0) {
                            if (!g_origGetModuleHandleA) g_origGetModuleHandleA = (fGetModuleHandleA)get_export_address_manual((HMODULE)h_module, "GetModuleHandleA", g_RtlInitAnsiString, g_LdrGetProcedureAddress, g_LdrLoadDll, g_RtlAnsiStringToUnicodeString, g_RtlFreeUnicodeString);
                            addr = (PVOID)HookedGetModuleHandleA;
                        } else if (my_strcmp(import_by_name->Name, "GetModuleHandleW") == 0) {
                            if (!g_origGetModuleHandleW) g_origGetModuleHandleW = (fGetModuleHandleW)get_export_address_manual((HMODULE)h_module, "GetModuleHandleW", g_RtlInitAnsiString, g_LdrGetProcedureAddress, g_LdrLoadDll, g_RtlAnsiStringToUnicodeString, g_RtlFreeUnicodeString);
                            addr = (PVOID)HookedGetModuleHandleW;
                        } else if (my_strcmp(import_by_name->Name, "TlsGetValue") == 0) {
                            addr = (PVOID)HookedTlsGetValue;
                        } else if (my_strcmp(import_by_name->Name, "GetModuleFileNameA") == 0) {
                            if (!g_origGetModuleFileNameA) g_origGetModuleFileNameA = (fGetModuleFileNameA)get_export_address_manual((HMODULE)h_module, "GetModuleFileNameA", g_RtlInitAnsiString, g_LdrGetProcedureAddress, g_LdrLoadDll, g_RtlAnsiStringToUnicodeString, g_RtlFreeUnicodeString);
                            addr = (PVOID)HookedGetModuleFileNameA;
                        } else if (my_strcmp(import_by_name->Name, "GetModuleFileNameW") == 0) {
                            if (!g_origGetModuleFileNameW) g_origGetModuleFileNameW = (fGetModuleFileNameW)get_export_address_manual((HMODULE)h_module, "GetModuleFileNameW", g_RtlInitAnsiString, g_LdrGetProcedureAddress, g_LdrLoadDll, g_RtlAnsiStringToUnicodeString, g_RtlFreeUnicodeString);
                            addr = (PVOID)HookedGetModuleFileNameW;
                        } else {
                            addr = get_export_address_manual((HMODULE)h_module, (char*)import_by_name->Name, g_RtlInitAnsiString, g_LdrGetProcedureAddress, g_LdrLoadDll, g_RtlAnsiStringToUnicodeString, g_RtlFreeUnicodeString);
                        }
                    }
                    first_thunk->u1.Function = (ULONG_PTR)addr; first_thunk++; original_first_thunk++;
                }
            }
            delay_desc++;
        }
    }

#ifdef _WIN64
    IMAGE_DATA_DIRECTORY exception_dir = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (exception_dir.Size > 0) {
        fRtlAddFunctionTable _RtlAddFunctionTable = (fRtlAddFunctionTable)get_export_address_manual(h_ntdll, "RtlAddFunctionTable", g_RtlInitAnsiString, g_LdrGetProcedureAddress, g_LdrLoadDll, g_RtlAnsiStringToUnicodeString, g_RtlFreeUnicodeString);
        if (_RtlAddFunctionTable) _RtlAddFunctionTable((PRUNTIME_FUNCTION)((char*)pe_buffer + exception_dir.VirtualAddress), exception_dir.Size / sizeof(RUNTIME_FUNCTION), (ULONG_PTR)pe_buffer);
    }
#endif

    init_thread_tls();
    run_tls_callbacks(DLL_PROCESS_ATTACH);

    PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(nt_headers);
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
        DWORD old; _VirtualProtect((char*)pe_buffer + sections[i].VirtualAddress, sections[i].Misc.VirtualSize, protection, &old);
    }

    if (g_is_dll) {
        typedef BOOL (WINABI *fDllMain)(HINSTANCE, DWORD, LPVOID);
        fDllMain dll_main = (fDllMain)((char*)pe_buffer + g_entry_point_rva);
#ifdef _WIN64
        call_aligned((PVOID)dll_main, (PVOID)pe_buffer, (PVOID)DLL_PROCESS_ATTACH, NULL, NULL);
#else
        dll_main((HINSTANCE)pe_buffer, DLL_PROCESS_ATTACH, NULL);
#endif
    } else {
        typedef void (*fExeEntry)();
        fExeEntry exe_entry = (fExeEntry)((char*)pe_buffer + g_entry_point_rva);
#ifdef _WIN64
        call_aligned((PVOID)exe_entry, NULL, NULL, NULL, NULL);
#else
        exe_entry();
#endif
    }
}

int main() {
    load_pe();

    HMODULE h_kernel32 = get_module_handle_manual("kernel32.dll");
    HMODULE h_ntdll = get_module_handle_manual("ntdll.dll");
    fRtlInitAnsiString _RtlInitAnsiString = (fRtlInitAnsiString)get_export_address_manual(h_ntdll, "RtlInitAnsiString", NULL, NULL, NULL, NULL, NULL);
    fLdrGetProcedureAddress _LdrGetProcedureAddress = (fLdrGetProcedureAddress)get_export_address_manual(h_ntdll, "LdrGetProcedureAddress", _RtlInitAnsiString, NULL, NULL, NULL, NULL);
    fGetStdHandle _GetStdHandle = (fGetStdHandle)get_export_address_manual(h_kernel32, "GetStdHandle", _RtlInitAnsiString, _LdrGetProcedureAddress, NULL, NULL, NULL);
    fWriteFile _WriteFile = (fWriteFile)get_export_address_manual(h_kernel32, "WriteFile", _RtlInitAnsiString, _LdrGetProcedureAddress, NULL, NULL, NULL);
    fReadFile _ReadFile = (fReadFile)get_export_address_manual(h_kernel32, "ReadFile", _RtlInitAnsiString, _LdrGetProcedureAddress, NULL, NULL, NULL);

    if (_GetStdHandle && _WriteFile && _ReadFile) {
        HANDLE hOut = _GetStdHandle(STD_OUTPUT_HANDLE);
        const char msg[] = "Press Enter to exit...";
        DWORD written;
        _WriteFile(hOut, (LPVOID)msg, (DWORD)sizeof(msg)-1, &written, NULL);

        HANDLE hIn = _GetStdHandle(STD_INPUT_HANDLE);
        char buf[2];
        DWORD read;
        _ReadFile(hIn, buf, 1, &read, NULL);
    }

    return 0;
}
