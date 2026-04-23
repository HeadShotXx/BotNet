/**
 * pe_to_shellcode.c - Architecture Aware
 *
 * Compilation: gcc pe_to_shellcode.c -o pe_to_shellcode
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#else
typedef uint32_t DWORD; typedef uint16_t WORD; typedef uint8_t BYTE; typedef uint64_t ULONG_PTR;
#pragma pack(push, 1)
typedef struct _IMAGE_DOS_HEADER { WORD e_magic; WORD e_cblp; WORD e_cp; WORD e_crlc; WORD e_cparhdr; WORD e_minalloc; WORD e_maxalloc; WORD e_ss; WORD e_sp; WORD e_csum; WORD e_ip; WORD e_cs; WORD e_lfarlc; WORD e_ovno; WORD e_res[4]; WORD e_oemid; WORD e_oeminfo; WORD e_res2[10]; int32_t e_lfanew; } IMAGE_DOS_HEADER;
typedef struct _IMAGE_FILE_HEADER { WORD Machine; WORD NumberOfSections; DWORD TimeDateStamp; DWORD PointerToSymbolTable; DWORD NumberOfSymbols; WORD SizeOfOptionalHeader; WORD Characteristics; } IMAGE_FILE_HEADER;
typedef struct _IMAGE_DATA_DIRECTORY { DWORD VirtualAddress; DWORD Size; } IMAGE_DATA_DIRECTORY;
typedef struct _IMAGE_OPTIONAL_HEADER32 { WORD Magic; BYTE MajorLinkerVersion, MinorLinkerVersion; DWORD SizeOfCode, SizeOfInitializedData, SizeOfUninitializedData, AddressOfEntryPoint, BaseOfCode, BaseOfData, ImageBase, SectionAlignment, FileAlignment; WORD MajorOperatingSystemVersion, MinorOperatingSystemVersion, MajorImageVersion, MinorImageVersion, MajorSubsystemVersion, MinorSubsystemVersion; DWORD Win32VersionValue, SizeOfImage, SizeOfHeaders, CheckSum; WORD Subsystem, DllCharacteristics; DWORD SizeOfStackReserve, SizeOfStackCommit, SizeOfHeapReserve, SizeOfHeapCommit, LoaderFlags, NumberOfRvaAndSizes; IMAGE_DATA_DIRECTORY DataDirectory[16]; } IMAGE_OPTIONAL_HEADER32;
typedef struct _IMAGE_OPTIONAL_HEADER64 { WORD Magic; BYTE MajorLinkerVersion, MinorLinkerVersion; DWORD SizeOfCode, SizeOfInitializedData, SizeOfUninitializedData, AddressOfEntryPoint, BaseOfCode; uint64_t ImageBase; DWORD SectionAlignment, FileAlignment; WORD MajorOperatingSystemVersion, MinorOperatingSystemVersion, MajorImageVersion, MinorImageVersion, MajorSubsystemVersion, MinorSubsystemVersion; DWORD Win32VersionValue, SizeOfImage, SizeOfHeaders, CheckSum; WORD Subsystem, DllCharacteristics; uint64_t SizeOfStackReserve, SizeOfStackCommit, SizeOfHeapReserve, SizeOfHeapCommit; DWORD LoaderFlags, NumberOfRvaAndSizes; IMAGE_DATA_DIRECTORY DataDirectory[16]; } IMAGE_OPTIONAL_HEADER64;
typedef struct _IMAGE_NT_HEADERS32 { DWORD Signature; IMAGE_FILE_HEADER FileHeader; IMAGE_OPTIONAL_HEADER32 OptionalHeader; } IMAGE_NT_HEADERS32;
typedef struct _IMAGE_NT_HEADERS64 { DWORD Signature; IMAGE_FILE_HEADER FileHeader; IMAGE_OPTIONAL_HEADER64 OptionalHeader; } IMAGE_NT_HEADERS64;
typedef struct _IMAGE_SECTION_HEADER { BYTE Name[8]; union { DWORD PhysicalAddress; DWORD VirtualSize; } Misc; DWORD VirtualAddress; DWORD SizeOfRawData; DWORD PointerToRawData; DWORD PointerToRelocations; DWORD PointerToLinenumbers; WORD NumberOfRelocations; WORD NumberOfLinenumbers; DWORD Characteristics; } IMAGE_SECTION_HEADER;
#pragma pack(pop)
#endif

int main(int argc, char* argv[]) {
    if (argc < 2) { printf("Usage: %s <loader.exe> [stub.bin]\n", (argc > 0) ? argv[0] : "pe_to_shellcode"); return 1; }
    FILE* fp = fopen(argv[1], "rb");
    if (!fp) { perror("fopen loader"); return 1; }
    fseek(fp, 0, SEEK_END); size_t file_size = ftell(fp); fseek(fp, 0, SEEK_SET);
    uint8_t* file_data = (uint8_t*)malloc(file_size); fread(file_data, 1, file_size, fp); fclose(fp);

    FILE* s_fp = fopen((argc > 2) ? argv[2] : "stub.bin", "rb");
    uint8_t* stub_data = NULL; size_t stub_size = 0;
    if (s_fp) { fseek(s_fp, 0, SEEK_END); stub_size = ftell(s_fp); fseek(s_fp, 0, SEEK_SET); stub_data = (uint8_t*)malloc(stub_size); fread(stub_data, 1, stub_size, s_fp); fclose(s_fp); }

    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)file_data;
    DWORD size_of_image, size_of_headers, num_sections, opt_size;
    WORD magic = *(WORD*)(file_data + dos->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER));
    if (magic == 0x10B) {
        IMAGE_NT_HEADERS32* nt = (IMAGE_NT_HEADERS32*)(file_data + dos->e_lfanew);
        size_of_image = nt->OptionalHeader.SizeOfImage;
        size_of_headers = nt->OptionalHeader.SizeOfHeaders;
        num_sections = nt->FileHeader.NumberOfSections;
        opt_size = nt->FileHeader.SizeOfOptionalHeader;
    } else {
        IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)(file_data + dos->e_lfanew);
        size_of_image = nt->OptionalHeader.SizeOfImage;
        size_of_headers = nt->OptionalHeader.SizeOfHeaders;
        num_sections = nt->FileHeader.NumberOfSections;
        opt_size = nt->FileHeader.SizeOfOptionalHeader;
    }

    uint8_t* mapped = (uint8_t*)calloc(1, size_of_image);
    memcpy(mapped, file_data, size_of_headers);
    IMAGE_SECTION_HEADER* sections = (IMAGE_SECTION_HEADER*)(file_data + dos->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + opt_size);
    for (int i=0; i<num_sections; i++) {
        if (sections[i].PointerToRawData) memcpy(mapped + sections[i].VirtualAddress, file_data + sections[i].PointerToRawData, sections[i].SizeOfRawData);
    }

    unsigned long long marker = 0xDEADBEEFCAFEBABEULL;
    FILE* bin_fp = fopen("final_shellcode.bin", "wb");
    if (bin_fp) {
        if (stub_data) fwrite(stub_data, 1, stub_size, bin_fp);
        fwrite(&marker, 1, sizeof(marker), bin_fp);
        fwrite(mapped, 1, size_of_image, bin_fp);
        fclose(bin_fp);
    }

    FILE* c_fp = fopen("shellcode.c", "w");
    if (c_fp) {
        fprintf(c_fp, "#include <windows.h>\n\nunsigned char shellcode[] = {\n");
        if (stub_data) { for (size_t i=0; i<stub_size; i++) { fprintf(c_fp, "0x%02X, ", stub_data[i]); if ((i+1)%12==0) fprintf(c_fp, "\n"); } }
        fprintf(c_fp, "\n// --- Marker ---\n");
        uint8_t* m = (uint8_t*)&marker;
        for (int i=0; i<8; i++) fprintf(c_fp, "0x%02X, ", m[i]);
        fprintf(c_fp, "\n// --- PE Blob ---\n");
        for (size_t i=0; i<size_of_image; i++) { fprintf(c_fp, "0x%02X%s", mapped[i], (i==size_of_image-1)?"":", "); if ((i+1)%12==0) fprintf(c_fp, "\n"); }
        fprintf(c_fp, "\n};\n");
        fclose(c_fp);
    }
    printf("Generated final_shellcode.bin and shellcode.c successfully.\n");
    free(file_data); free(mapped); if (stub_data) free(stub_data);
    return 0;
}
