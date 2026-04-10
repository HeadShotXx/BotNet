/**
 * loader_template.c
 *
 * Compilation: x86_64-w64-mingw32-gcc final_loader.c -o final_loader.exe
 */

#include <windows.h>
#include <stdio.h>

// PE_BLOB_ARRAY
unsigned char pe_blob[] = { 0 };

// ENTRY_POINT_RVA
DWORD entry_point_rva = 0;

// IMAGE_BASE
ULONG_PTR image_base = 0;

// SIZE_OF_IMAGE
SIZE_T size_of_image = 0;

void load_pe() {
    PIMAGE_DOS_HEADER dos_header_raw = (PIMAGE_DOS_HEADER)pe_blob;
    PIMAGE_NT_HEADERS nt_headers_raw = (PIMAGE_NT_HEADERS)((char*)pe_blob + dos_header_raw->e_lfanew);

    LPVOID pe_buffer = VirtualAlloc(NULL, nt_headers_raw->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!pe_buffer) {
        printf("VirtualAlloc failed: %lu\n", GetLastError());
        return;
    }

    // Copy Headers
    memcpy(pe_buffer, pe_blob, nt_headers_raw->OptionalHeader.SizeOfHeaders);

    // Copy Sections
    PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(nt_headers_raw);
    for (int i = 0; i < nt_headers_raw->FileHeader.NumberOfSections; i++) {
        if (sections[i].PointerToRawData != 0) {
            memcpy((char*)pe_buffer + sections[i].VirtualAddress,
                   (char*)pe_blob + sections[i].PointerToRawData,
                   sections[i].SizeOfRawData);
        }
    }

    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)pe_buffer;
    PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)((char*)pe_buffer + dos_header->e_lfanew);

    // Fix Import Table
    IMAGE_DATA_DIRECTORY import_dir = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (import_dir.Size > 0) {
        PIMAGE_IMPORT_DESCRIPTOR import_desc = (PIMAGE_IMPORT_DESCRIPTOR)((char*)pe_buffer + import_dir.VirtualAddress);
        while (import_desc->Name) {
            char* lib_name = (char*)pe_buffer + import_desc->Name;
            HMODULE h_module = LoadLibraryA(lib_name);
            if (!h_module) {
                printf("Failed to load library %s\n", lib_name);
                return;
            }

            PIMAGE_THUNK_DATA first_thunk = (PIMAGE_THUNK_DATA)((char*)pe_buffer + import_desc->FirstThunk);
            PIMAGE_THUNK_DATA original_first_thunk = (PIMAGE_THUNK_DATA)((char*)pe_buffer + import_desc->OriginalFirstThunk);

            if (import_desc->OriginalFirstThunk == 0)
                original_first_thunk = first_thunk;

            while (original_first_thunk->u1.AddressOfData) {
                if (IMAGE_SNAP_BY_ORDINAL(original_first_thunk->u1.Ordinal)) {
                    first_thunk->u1.Function = (ULONG_PTR)GetProcAddress(h_module, (LPCSTR)IMAGE_ORDINAL(original_first_thunk->u1.Ordinal));
                } else {
                    PIMAGE_IMPORT_BY_NAME import_by_name = (PIMAGE_IMPORT_BY_NAME)((char*)pe_buffer + original_first_thunk->u1.AddressOfData);
                    first_thunk->u1.Function = (ULONG_PTR)GetProcAddress(h_module, import_by_name->Name);
                }
                first_thunk++;
                original_first_thunk++;
            }
            import_desc++;
        }
    }

    // Perform Base Relocation
    ULONG_PTR delta = (ULONG_PTR)pe_buffer - image_base;
    if (delta != 0) {
        IMAGE_DATA_DIRECTORY reloc_dir = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (reloc_dir.Size > 0) {
            PIMAGE_BASE_RELOCATION relocation = (PIMAGE_BASE_RELOCATION)((char*)pe_buffer + reloc_dir.VirtualAddress);
            while (relocation->VirtualAddress != 0) {
                DWORD size = (relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                PWORD rel_data = (PWORD)((char*)relocation + sizeof(IMAGE_BASE_RELOCATION));
                for (DWORD i = 0; i < size; i++) {
                    WORD type = rel_data[i] >> 12;
                    WORD offset = rel_data[i] & 0xFFF;
                    if (type == IMAGE_REL_BASED_DIR64) {
                        PUINT64 patch = (PUINT64)((char*)pe_buffer + relocation->VirtualAddress + offset);
                        *patch += delta;
                    } else if (type == IMAGE_REL_BASED_HIGHLOW) {
                        PDWORD patch = (PDWORD)((char*)pe_buffer + relocation->VirtualAddress + offset);
                        *patch += (DWORD)delta;
                    }
                }
                relocation = (PIMAGE_BASE_RELOCATION)((char*)relocation + relocation->SizeOfBlock);
            }
        }
    }

    // Set memory protections
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt_headers);
    for (int i = 0; i < nt_headers->FileHeader.NumberOfSections; i++) {
        DWORD protection = 0;
        if (section[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            if (section[i].Characteristics & IMAGE_SCN_MEM_WRITE) protection = PAGE_EXECUTE_READWRITE;
            else if (section[i].Characteristics & IMAGE_SCN_MEM_READ) protection = PAGE_EXECUTE_READ;
            else protection = PAGE_EXECUTE;
        } else {
            if (section[i].Characteristics & IMAGE_SCN_MEM_WRITE) protection = PAGE_READWRITE;
            else if (section[i].Characteristics & IMAGE_SCN_MEM_READ) protection = PAGE_READONLY;
            else protection = PAGE_NOACCESS;
        }
        DWORD old_protection;
        VirtualProtect((char*)pe_buffer + section[i].VirtualAddress, section[i].Misc.VirtualSize, protection, &old_protection);
    }

    // Execute entry point
    ((void(*)())((char*)pe_buffer + entry_point_rva))();
}

int main() {
    load_pe();
    printf("Press Enter to exit...\n");
    getchar();
    return 0;
}
