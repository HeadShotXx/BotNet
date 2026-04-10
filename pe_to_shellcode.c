/**
 * pe_to_shellcode.c
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
typedef uint32_t DWORD;
typedef uint16_t WORD;
typedef uint8_t BYTE;
typedef uint64_t ULONG_PTR;

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

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <loader.exe> [stub.bin]\n", (argc > 0) ? argv[0] : "pe_to_shellcode");
        return 1;
    }

    const char* loader_path = argv[1];
    const char* stub_path = (argc > 2) ? argv[2] : "stub.bin";

    FILE* fp = fopen(loader_path, "rb");
    if (!fp) { perror("fopen loader"); return 1; }
    fseek(fp, 0, SEEK_END);
    size_t file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    uint8_t* file_data = (uint8_t*)malloc(file_size);
    fread(file_data, 1, file_size, fp);
    fclose(fp);

    FILE* s_fp = fopen(stub_path, "rb");
    uint8_t* stub_data = NULL;
    size_t stub_size = 0;
    if (s_fp) {
        fseek(s_fp, 0, SEEK_END);
        stub_size = ftell(s_fp);
        fseek(s_fp, 0, SEEK_SET);
        stub_data = (uint8_t*)malloc(stub_size);
        fread(stub_data, 1, stub_size, s_fp);
        fclose(s_fp);
    } else {
        printf("Warning: stub.bin not found. Generated shellcode will have no PIC stub.\n");
    }

    IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)file_data;
    IMAGE_NT_HEADERS64* nt_headers = (IMAGE_NT_HEADERS64*)(file_data + dos_header->e_lfanew);
    DWORD size_of_image = nt_headers->OptionalHeader.SizeOfImage;

    uint8_t* mapped_image = (uint8_t*)calloc(1, size_of_image);
    memcpy(mapped_image, file_data, nt_headers->OptionalHeader.SizeOfHeaders);
    IMAGE_SECTION_HEADER* sections = (IMAGE_SECTION_HEADER*)((uint8_t*)&nt_headers->OptionalHeader + nt_headers->FileHeader.SizeOfOptionalHeader);
    for (int i = 0; i < nt_headers->FileHeader.NumberOfSections; i++) {
        if (sections[i].PointerToRawData != 0) {
            memcpy(mapped_image + sections[i].VirtualAddress,
                   file_data + sections[i].PointerToRawData,
                   sections[i].SizeOfRawData);
        }
    }

    FILE* bin_fp = fopen("final_shellcode.bin", "wb");
    if (bin_fp) {
        if (stub_data) fwrite(stub_data, 1, stub_size, bin_fp);
        fwrite(mapped_image, 1, size_of_image, bin_fp);
        fclose(bin_fp);
    }

    FILE* c_fp = fopen("shellcode.c", "w");
    if (c_fp) {
        fprintf(c_fp, "unsigned char shellcode[] = {\n");
        if (stub_data) {
            for (size_t i = 0; i < stub_size; i++) {
                fprintf(c_fp, "0x%02X, ", stub_data[i]);
                if ((i + 1) % 12 == 0) fprintf(c_fp, "\n");
            }
            fprintf(c_fp, "\n// --- PE Blob ---\n");
        }
        for (size_t i = 0; i < size_of_image; i++) {
            fprintf(c_fp, "0x%02X%s", mapped_image[i], (i == size_of_image - 1) ? "" : ", ");
            if ((i + 1) % 12 == 0) fprintf(c_fp, "\n");
        }
        fprintf(c_fp, "\n};\n");
        fclose(c_fp);
    }

    printf("Generated final_shellcode.bin and shellcode.c successfully.\n");
    free(file_data); free(mapped_image); if (stub_data) free(stub_data);
    return 0;
}
