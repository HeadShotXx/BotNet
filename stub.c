#include <windows.h>
#include <winternl.h>

// Forward declarations of helpers to be placed AFTER the entry point
static inline ULONG_PTR get_kernel32();
static inline FARPROC get_proc_addr(ULONG_PTR base, const char* name);

// The entry point of the stub MUST be at the top
__attribute__((section(".text.prologue")))
void stub_entry() {
    ULONG_PTR k32 = get_kernel32();

    char sGetProcAddress[] = {'G','e','t','P','r','o','c','A','d','d','r','e','s','s',0};
    char sLoadLibraryA[] = {'L','o','a','d','L','i','b','r','a','r','y','A',0};
    char sVirtualAlloc[] = {'V','i','r','t','u','a','l','A','l','l','o','c',0};

    typedef FARPROC (WINAPI *GPA)(HMODULE, LPCSTR);
    GPA pGPA = (GPA)get_proc_addr(k32, sGetProcAddress);

    typedef HMODULE (WINAPI *LLA)(LPCSTR);
    LLA pLLA = (LLA)pGPA((HMODULE)k32, sLoadLibraryA);

    typedef LPVOID (WINAPI *VA)(LPVOID, SIZE_T, DWORD, DWORD);
    VA pVA = (VA)pGPA((HMODULE)k32, sVirtualAlloc);

    // Find PE blob. It follows the stub.
    // We'll use a unique marker to avoid matching instruction bytes.
    // Marker: 0xDEADBEEFCAFEBABE
    ULONG_PTR current_ptr;
    __asm__ ("lea (%%rip), %0" : "=r" (current_ptr));

    unsigned long long marker = 0xCAFEBABE00000000ULL | 0xDEADBEEF; // Split to avoid immediate match
    char* search = (char*)current_ptr;
    while (1) {
        if (*(unsigned long long*)search == 0xDEADBEEFCAFEBABEULL) {
            search += 8; // Move past marker
            break;
        }
        search++;
    }

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)search;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((char*)search + dos->e_lfanew);

    LPVOID base = pVA(NULL, nt->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    // Copy headers
    for (DWORD i = 0; i < nt->OptionalHeader.SizeOfHeaders; i++) ((char*)base)[i] = ((char*)search)[i];

    // Copy sections
    PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        char* dest = (char*)base + sections[i].VirtualAddress;
        char* src = (char*)search + sections[i].VirtualAddress;
        for (DWORD j = 0; j < sections[i].SizeOfRawData; j++) dest[j] = src[j];
    }

    // Fix imports
    PIMAGE_NT_HEADERS new_nt = (PIMAGE_NT_HEADERS)((char*)base + ((PIMAGE_DOS_HEADER)base)->e_lfanew);
    if (new_nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size > 0) {
        PIMAGE_IMPORT_DESCRIPTOR import_desc = (PIMAGE_IMPORT_DESCRIPTOR)((char*)base + new_nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        while (import_desc->Name) {
            HMODULE hMod = pLLA((char*)base + import_desc->Name);
            PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((char*)base + import_desc->FirstThunk);
            PIMAGE_THUNK_DATA orig_thunk = (PIMAGE_THUNK_DATA)((char*)base + import_desc->OriginalFirstThunk);
            if (!import_desc->OriginalFirstThunk) orig_thunk = thunk;

            while (orig_thunk->u1.AddressOfData) {
                if (IMAGE_SNAP_BY_ORDINAL(orig_thunk->u1.Ordinal)) {
                    thunk->u1.Function = (ULONG_PTR)pGPA(hMod, (LPCSTR)IMAGE_ORDINAL(orig_thunk->u1.Ordinal));
                } else {
                    PIMAGE_IMPORT_BY_NAME ibn = (PIMAGE_IMPORT_BY_NAME)((char*)base + orig_thunk->u1.AddressOfData);
                    thunk->u1.Function = (ULONG_PTR)pGPA(hMod, ibn->Name);
                }
                thunk++; orig_thunk++;
            }
            import_desc++;
        }
    }

    // Relocations
    ULONG_PTR delta = (ULONG_PTR)base - new_nt->OptionalHeader.ImageBase;
    if (delta != 0 && new_nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size > 0) {
        PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)((char*)base + new_nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
        while (reloc->VirtualAddress != 0) {
            DWORD count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            WORD* list = (WORD*)((char*)reloc + sizeof(IMAGE_BASE_RELOCATION));
            for (DWORD i = 0; i < count; i++) {
                if ((list[i] >> 12) == IMAGE_REL_BASED_DIR64) {
                    *(ULONG_PTR*)((char*)base + reloc->VirtualAddress + (list[i] & 0xFFF)) += delta;
                } else if ((list[i] >> 12) == IMAGE_REL_BASED_HIGHLOW) {
                    *(DWORD*)((char*)base + reloc->VirtualAddress + (list[i] & 0xFFF)) += (DWORD)delta;
                }
            }
            reloc = (PIMAGE_BASE_RELOCATION)((char*)reloc + reloc->SizeOfBlock);
        }
    }

    // Jump
    ((void(*)())((char*)base + new_nt->OptionalHeader.AddressOfEntryPoint))();
}

static inline ULONG_PTR get_kernel32() {
    PPEB peb;
#ifdef _WIN64
    __asm__ ("movq %%gs:0x60, %0" : "=r" (peb));
#else
    __asm__ ("movl %%fs:0x30, %0" : "=r" (peb));
#endif
    PLIST_ENTRY list = &peb->Ldr->InMemoryOrderModuleList;
    PLIST_ENTRY entry = list->Flink; // exe
    entry = entry->Flink; // ntdll
    entry = entry->Flink; // kernel32

    LDR_DATA_TABLE_ENTRY* data_entry = (LDR_DATA_TABLE_ENTRY*)((char*)entry - sizeof(LIST_ENTRY));
    return (ULONG_PTR)data_entry->DllBase;
}

static inline FARPROC get_proc_addr(ULONG_PTR base, const char* name) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)(base + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD* names = (DWORD*)(base + exports->AddressOfNames);
    DWORD* funcs = (DWORD*)(base + exports->AddressOfFunctions);
    WORD* ordinals = (WORD*)(base + exports->AddressOfNameOrdinals);

    for (DWORD i = 0; i < exports->NumberOfNames; i++) {
        char* n = (char*)(base + names[i]);
        int match = 1;
        int j = 0;
        for (j = 0; name[j] != 0; j++) {
            if (n[j] != name[j]) { match = 0; break; }
        }
        if (match && n[j] == 0) {
            return (FARPROC)(base + funcs[ordinals[i]]);
        }
    }
    return NULL;
}
