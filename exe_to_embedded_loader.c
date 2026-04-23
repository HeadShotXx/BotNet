/**
 * exe_to_embedded_loader.c
 *
 * Converts a PE file (x86 or x64) into a memory-ready format and embeds it
 * into a loader template.
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
typedef uint32_t DWORD; typedef uint16_t WORD; typedef uint8_t BYTE; typedef uint64_t ULONG_PTR; typedef uint64_t SIZE_T;
#pragma pack(push, 1)
typedef struct _IMAGE_DOS_HEADER { WORD e_magic; WORD e_cblp; WORD e_cp; WORD e_crlc; WORD e_cparhdr; WORD e_minalloc; WORD e_maxalloc; WORD e_ss; WORD e_sp; WORD e_csum; WORD e_ip; WORD e_cs; WORD e_lfarlc; WORD e_ovno; WORD e_res[4]; WORD e_oemid; WORD e_oeminfo; WORD e_res2[10]; int32_t e_lfanew; } IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;
typedef struct _IMAGE_FILE_HEADER { WORD Machine; WORD NumberOfSections; DWORD TimeDateStamp; DWORD PointerToSymbolTable; DWORD NumberOfSymbols; WORD SizeOfOptionalHeader; WORD Characteristics; } IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;
typedef struct _IMAGE_DATA_DIRECTORY { DWORD VirtualAddress; DWORD Size; } IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;
typedef struct _IMAGE_OPTIONAL_HEADER32 { WORD Magic; BYTE MajorLinkerVersion, MinorLinkerVersion; DWORD SizeOfCode, SizeOfInitializedData, SizeOfUninitializedData, AddressOfEntryPoint, BaseOfCode, BaseOfData, ImageBase, SectionAlignment, FileAlignment; WORD MajorOperatingSystemVersion, MinorOperatingSystemVersion, MajorImageVersion, MinorImageVersion, MajorSubsystemVersion, MinorSubsystemVersion; DWORD Win32VersionValue, SizeOfImage, SizeOfHeaders, CheckSum; WORD Subsystem, DllCharacteristics; DWORD SizeOfStackReserve, SizeOfStackCommit, SizeOfHeapReserve, SizeOfHeapCommit, LoaderFlags, NumberOfRvaAndSizes; IMAGE_DATA_DIRECTORY DataDirectory[16]; } IMAGE_OPTIONAL_HEADER32;
typedef struct _IMAGE_OPTIONAL_HEADER64 { WORD Magic; BYTE MajorLinkerVersion, MinorLinkerVersion; DWORD SizeOfCode, SizeOfInitializedData, SizeOfUninitializedData, AddressOfEntryPoint, BaseOfCode; uint64_t ImageBase; DWORD SectionAlignment, FileAlignment; WORD MajorOperatingSystemVersion, MinorOperatingSystemVersion, MajorImageVersion, MinorImageVersion, MajorSubsystemVersion, MinorSubsystemVersion; DWORD Win32VersionValue, SizeOfImage, SizeOfHeaders, CheckSum; WORD Subsystem, DllCharacteristics; uint64_t SizeOfStackReserve, SizeOfStackCommit, SizeOfHeapReserve, SizeOfHeapCommit; DWORD LoaderFlags, NumberOfRvaAndSizes; IMAGE_DATA_DIRECTORY DataDirectory[16]; } IMAGE_OPTIONAL_HEADER64;
typedef struct _IMAGE_NT_HEADERS32 { DWORD Signature; IMAGE_FILE_HEADER FileHeader; IMAGE_OPTIONAL_HEADER32 OptionalHeader; } IMAGE_NT_HEADERS32;
typedef struct _IMAGE_NT_HEADERS64 { DWORD Signature; IMAGE_FILE_HEADER FileHeader; IMAGE_OPTIONAL_HEADER64 OptionalHeader; } IMAGE_NT_HEADERS64;
#pragma pack(pop)
#endif

const char* builtin_template =
"#include <windows.h>\n"
"#include <stdio.h>\n"
"// PE_BLOB_ARRAY\n"
"unsigned char pe_blob[] = { 0 };\n"
"// ENTRY_POINT_RVA\n"
"DWORD entry_point_rva = 0;\n"
"// IMAGE_BASE\n"
"ULONG_PTR image_base = 0;\n"
"// SIZE_OF_IMAGE\n"
"SIZE_T size_of_image = 0;\n"
"void load_pe() {\n"
"    // Default logic if template is missing\n"
"}\n"
"int main() { load_pe(); return 0; }\n";

void print_hex_array(FILE* out, const uint8_t* data, size_t size) {
    fprintf(out, "unsigned char pe_blob[] = {");
    for (size_t i = 0; i < size; i++) {
        if (i % 12 == 0) fprintf(out, "\n    ");
        fprintf(out, "0x%02X%s", data[i], (i == size - 1) ? "" : ", ");
    }
    fprintf(out, "\n};\n");
}

int main(int argc, char* argv[]) {
    if (argc < 2) { printf("Usage: %s <payload.exe> [loader_template.c]\n", argv[0]); return 1; }
    FILE* fp = fopen(argv[1], "rb");
    if (!fp) { perror("fopen payload"); return 1; }
    fseek(fp, 0, SEEK_END); size_t file_size = ftell(fp); fseek(fp, 0, SEEK_SET);
    uint8_t* file_data = (uint8_t*)malloc(file_size); fread(file_data, 1, file_size, fp); fclose(fp);

    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)file_data;
    if (dos->e_magic != 0x5A4D) { printf("Invalid PE\n"); return 1; }

    DWORD entry_point_rva; uint64_t image_base; DWORD size_of_image;
    WORD magic = *(WORD*)(file_data + dos->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER));
    if (magic == 0x10B) { // PE32
        IMAGE_NT_HEADERS32* nt = (IMAGE_NT_HEADERS32*)(file_data + dos->e_lfanew);
        entry_point_rva = nt->OptionalHeader.AddressOfEntryPoint;
        image_base = nt->OptionalHeader.ImageBase;
        size_of_image = nt->OptionalHeader.SizeOfImage;
    } else { // PE32+
        IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)(file_data + dos->e_lfanew);
        entry_point_rva = nt->OptionalHeader.AddressOfEntryPoint;
        image_base = nt->OptionalHeader.ImageBase;
        size_of_image = nt->OptionalHeader.SizeOfImage;
    }

    char* template_data = NULL;
    FILE* t_fp = fopen((argc > 2) ? argv[2] : "loader_template.c", "r");
    if (t_fp) {
        fseek(t_fp, 0, SEEK_END); size_t t_size = ftell(t_fp); fseek(t_fp, 0, SEEK_SET);
        template_data = (char*)malloc(t_size + 1); fread(template_data, 1, t_size, t_fp);
        template_data[t_size] = '\0'; fclose(t_fp);
    } else {
        template_data = strdup(builtin_template);
    }

    FILE* out_fp = fopen("final_loader.c", "w");
    char* p = template_data;
    while (*p) {
        if (strncmp(p, "// PE_BLOB_ARRAY", 16) == 0) {
            print_hex_array(out_fp, file_data, file_size);
            p = strchr(p, '\n'); if (p) p++; p = strchr(p, '\n'); if (p) p++;
        } else if (strncmp(p, "// ENTRY_POINT_RVA", 18) == 0) {
            fprintf(out_fp, "// ENTRY_POINT_RVA\nDWORD entry_point_rva = 0x%X;\n", entry_point_rva);
            p = strchr(p, '\n'); if (p) p++; p = strchr(p, '\n'); if (p) p++;
        } else if (strncmp(p, "// IMAGE_BASE", 13) == 0) {
            fprintf(out_fp, "// IMAGE_BASE\nULONG_PTR image_base = 0x%llX;\n", (unsigned long long)image_base);
            p = strchr(p, '\n'); if (p) p++; p = strchr(p, '\n'); if (p) p++;
        } else if (strncmp(p, "// SIZE_OF_IMAGE", 16) == 0) {
            fprintf(out_fp, "// SIZE_OF_IMAGE\nSIZE_T size_of_image = 0x%X;\n", size_of_image);
            p = strchr(p, '\n'); if (p) p++; p = strchr(p, '\n'); if (p) p++;
        } else fputc(*p++, out_fp);
    }
    fclose(out_fp); free(file_data); free(template_data);
    printf("Generated final_loader.c successfully.\n");
    return 0;
}
