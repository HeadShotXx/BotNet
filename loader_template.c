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
#define PAGE_READWRITE 0x04
#define PAGE_EXECUTE_READWRITE 0x40
#define PAGE_EXECUTE_READ 0x20
#define PAGE_EXECUTE 0x10
#define PAGE_READONLY 0x02
#define PAGE_NOACCESS 0x01

#define IMAGE_DIRECTORY_ENTRY_EXPORT 0
#define IMAGE_DIRECTORY_ENTRY_IMPORT 1
#define IMAGE_DIRECTORY_ENTRY_BASERELOC 5
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION 3
#define IMAGE_DIRECTORY_ENTRY_TLS 9

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
typedef BOOL (WINABI *fVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef BOOL (WINABI *fRtlAddFunctionTable)(PRUNTIME_FUNCTION, DWORD, DWORD64);
typedef VOID (WINABI *PIMAGE_TLS_CALLBACK)(PVOID, DWORD, PVOID);
typedef DWORD (WINABI *fTlsAlloc)(VOID);
typedef HANDLE (WINABI *fCreateThread)(LPVOID, SIZE_T, LPVOID, LPVOID, DWORD, LPDWORD);
typedef HANDLE (WINABI *fGetStdHandle)(DWORD);
typedef BOOL (WINABI *fWriteFile)(HANDLE, LPVOID, DWORD, LPDWORD, LPVOID);
typedef BOOL (WINABI *fReadFile)(HANDLE, LPVOID, DWORD, LPDWORD, LPVOID);

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
static DWORD g_tls_index = 0;
static fVirtualAlloc g_vAlloc = NULL;
static fCreateThread g_origCreateThread = NULL;
static PVOID g_pe_base = NULL;

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

static void resolve_api_set(const char* dll_name, char* out_name) {
    if (my_strncmp(dll_name, "api-", 4) != 0 && my_strncmp(dll_name, "ext-", 4) != 0) {
        int i = 0; while (dll_name[i]) { out_name[i] = dll_name[i]; i++; } out_name[i] = '\0';
        return;
    }
    PVOID peb = GET_PEB();
    PAPI_SET_NAMESPACE api_set_map = *(PAPI_SET_NAMESPACE*)((char*)peb + (sizeof(PVOID) == 8 ? 0x68 : 0x38));
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

static PVOID get_export_address_manual(HMODULE h_module, const char* func_name, fRtlInitAnsiString _RtlInitAnsiString, fLdrGetProcedureAddress _LdrGetProcedureAddress, fLdrLoadDll _LdrLoadDll, fRtlAnsiStringToUnicodeString _RtlAnsiStringToUnicodeString, fRtlFreeUnicodeString _RtlFreeUnicodeString) {
    if (!h_module) return NULL;
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
            if (h_forward) return get_export_address_manual(h_forward, dot + 1, _RtlInitAnsiString, _LdrGetProcedureAddress, _LdrLoadDll, _RtlAnsiStringToUnicodeString, _RtlFreeUnicodeString);
        }
    }
    return addr;
}

// --- TLS Initialization Helper ---

static VOID init_thread_tls() {
    if (!g_tls_dir) return;
    SIZE_T tls_data_size = (SIZE_T)(g_tls_dir->EndAddressOfRawData - g_tls_dir->StartAddressOfRawData);
    SIZE_T total_tls_size = tls_data_size + g_tls_dir->SizeOfZeroFill;
    LPVOID thread_tls_data = g_vAlloc(NULL, total_tls_size, MEM_COMMIT, PAGE_READWRITE);
    if (thread_tls_data) {
        my_memcpy(thread_tls_data, (const void*)g_tls_dir->StartAddressOfRawData, tls_data_size);
        my_memset((char*)thread_tls_data + tls_data_size, 0, g_tls_dir->SizeOfZeroFill);
        void*** tls_pointer_array_ptr = (void***)((char*)GET_TEB() + (sizeof(PVOID) == 8 ? 0x58 : 0x2C));
        if (*tls_pointer_array_ptr) {
            (*tls_pointer_array_ptr)[g_tls_index] = thread_tls_data;
        }
    }
}

static VOID run_tls_callbacks(DWORD reason) {
    if (!g_tls_dir) return;
    PIMAGE_TLS_CALLBACK* callbacks = (PIMAGE_TLS_CALLBACK*)g_tls_dir->AddressOfCallBacks;
    if (callbacks) {
        while (*callbacks) {
            (*callbacks)(g_pe_base, reason, NULL);
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
    PWRAPPER_ARGS args = (PWRAPPER_ARGS)lpParam;
    LPVOID func = args->func;
    LPVOID param = args->param;

    init_thread_tls();
    run_tls_callbacks(DLL_THREAD_ATTACH);
    DWORD result = ((DWORD(WINABI*)(LPVOID))func)(param);
    run_tls_callbacks(DLL_THREAD_DETACH);
    return result;
}

static HANDLE WINABI HookedCreateThread(LPVOID lpThreadAttributes, SIZE_T dwStackSize, LPVOID lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId) {
    PWRAPPER_ARGS args = (PWRAPPER_ARGS)g_vAlloc(NULL, sizeof(WRAPPER_ARGS), MEM_COMMIT, PAGE_READWRITE);
    args->func = lpStartAddress;
    args->param = lpParameter;
    return g_origCreateThread(lpThreadAttributes, dwStackSize, (LPVOID)ThreadWrapper, args, dwCreationFlags, lpThreadId);
}

// --- Main loading logic ---

// PE_BLOB_ARRAY
unsigned char pe_blob[] = { 0 };
// ENTRY_POINT_RVA
DWORD entry_point_rva = 0;
// IMAGE_BASE
ULONG_PTR image_base = 0;
// SIZE_OF_IMAGE
SIZE_T size_of_image = 0;

void load_pe() {
    HMODULE h_ntdll = get_module_handle_manual("ntdll.dll");
    fRtlInitAnsiString _RtlInitAnsiString = (fRtlInitAnsiString)get_export_address_manual(h_ntdll, "RtlInitAnsiString", NULL, NULL, NULL, NULL, NULL);
    fLdrGetProcedureAddress _LdrGetProcedureAddress = (fLdrGetProcedureAddress)get_export_address_manual(h_ntdll, "LdrGetProcedureAddress", _RtlInitAnsiString, NULL, NULL, NULL, NULL);
    fLdrLoadDll _LdrLoadDll = (fLdrLoadDll)get_export_address_manual(h_ntdll, "LdrLoadDll", _RtlInitAnsiString, _LdrGetProcedureAddress, NULL, NULL, NULL);
    fRtlAnsiStringToUnicodeString _RtlAnsiStringToUnicodeString = (fRtlAnsiStringToUnicodeString)get_export_address_manual(h_ntdll, "RtlAnsiStringToUnicodeString", _RtlInitAnsiString, _LdrGetProcedureAddress, _LdrLoadDll, NULL, NULL);
    fRtlFreeUnicodeString _RtlFreeUnicodeString = (fRtlFreeUnicodeString)get_export_address_manual(h_ntdll, "RtlFreeUnicodeString", _RtlInitAnsiString, _LdrGetProcedureAddress, _LdrLoadDll, _RtlAnsiStringToUnicodeString, NULL);

    HMODULE h_kernel32 = get_module_handle_manual("kernel32.dll");
    g_vAlloc = (fVirtualAlloc)get_export_address_manual(h_kernel32, "VirtualAlloc", _RtlInitAnsiString, _LdrGetProcedureAddress, _LdrLoadDll, _RtlAnsiStringToUnicodeString, _RtlFreeUnicodeString);
    fVirtualProtect _VirtualProtect = (fVirtualProtect)get_export_address_manual(h_kernel32, "VirtualProtect", _RtlInitAnsiString, _LdrGetProcedureAddress, _LdrLoadDll, _RtlAnsiStringToUnicodeString, _RtlFreeUnicodeString);
    fTlsAlloc _TlsAlloc = (fTlsAlloc)get_export_address_manual(h_kernel32, "TlsAlloc", _RtlInitAnsiString, _LdrGetProcedureAddress, _LdrLoadDll, _RtlAnsiStringToUnicodeString, _RtlFreeUnicodeString);

    PIMAGE_DOS_HEADER dos_header_raw = (PIMAGE_DOS_HEADER)pe_blob;
    PIMAGE_NT_HEADERS nt_headers_raw = (PIMAGE_NT_HEADERS)((char*)pe_blob + dos_header_raw->e_lfanew);
    LPVOID pe_buffer = g_vAlloc(NULL, nt_headers_raw->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!pe_buffer) return;
    g_pe_base = pe_buffer;
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
        if (g_tls_dir->AddressOfIndex) *(DWORD*)(g_tls_dir->AddressOfIndex) = g_tls_index;
    }

    IMAGE_DATA_DIRECTORY import_dir = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (import_dir.Size > 0) {
        PIMAGE_IMPORT_DESCRIPTOR import_desc = (PIMAGE_IMPORT_DESCRIPTOR)((char*)pe_buffer + import_dir.VirtualAddress);
        while (import_desc->Name) {
            const char* dll_name = (char*)pe_buffer + import_desc->Name;
            char resolved_dll[MAX_PATH]; resolve_api_set(dll_name, resolved_dll);
            ANSI_STRING ansi_dll; UNICODE_STRING uni_dll;
            _RtlInitAnsiString(&ansi_dll, resolved_dll);
            _RtlAnsiStringToUnicodeString(&uni_dll, &ansi_dll, TRUE);
            HANDLE h_module = NULL; _LdrLoadDll(NULL, NULL, &uni_dll, &h_module); _RtlFreeUnicodeString(&uni_dll);
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
                        if (my_strcmp(import_by_name->Name, "CreateThread") == 0) {
                            g_origCreateThread = (fCreateThread)get_export_address_manual((HMODULE)h_module, "CreateThread", _RtlInitAnsiString, _LdrGetProcedureAddress, _LdrLoadDll, _RtlAnsiStringToUnicodeString, _RtlFreeUnicodeString);
                            addr = (PVOID)HookedCreateThread;
                        } else {
                            addr = get_export_address_manual((HMODULE)h_module, (char*)import_by_name->Name, _RtlInitAnsiString, _LdrGetProcedureAddress, _LdrLoadDll, _RtlAnsiStringToUnicodeString, _RtlFreeUnicodeString);
                        }
                    }
                    first_thunk->u1.Function = (ULONG_PTR)addr; first_thunk++; original_first_thunk++;
                }
            }
            import_desc++;
        }
    }

#ifdef _WIN64
    IMAGE_DATA_DIRECTORY exception_dir = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (exception_dir.Size > 0) {
        fRtlAddFunctionTable _RtlAddFunctionTable = (fRtlAddFunctionTable)get_export_address_manual(h_ntdll, "RtlAddFunctionTable", _RtlInitAnsiString, _LdrGetProcedureAddress, _LdrLoadDll, _RtlAnsiStringToUnicodeString, _RtlFreeUnicodeString);
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
    ((void(*)())((char*)pe_buffer + entry_point_rva))();
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
