pub mod bootstrapper;

use std::ffi::c_void;
use std::ptr::{null, null_mut};
use windows_sys::Win32::Foundation::{
    CloseHandle, FALSE, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::System::Diagnostics::Debug::{
    IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Memory::{
    VirtualAllocEx, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
};
use windows_sys::Win32::System::Threading::{
    CreateRemoteThread, OpenProcess, PROCESS_ALL_ACCESS, WaitForSingleObject, INFINITE,
};
use windows_sys::Win32::System::SystemServices::{IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE};
use windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_OPTIONAL_HDR64_MAGIC;
use windows_sys::Win32::System::Diagnostics::Debug::WriteProcessMemory;

use crate::bootstrapper::{realign_pe, realign_pe_end, DllInfo};

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        println!("Usage: injector.exe <path_to_dll> [process_name]");
        println!("       injector.exe --list");
        return;
    }

    if args[1] == "--list" {
        unsafe { list_processes(); }
        return;
    }

    let dll_path = &args[1];
    let process_name = if args.len() > 2 { &args[2] } else { "notepad.exe" };

    let dll_bytes = std::fs::read(dll_path).expect("Failed to read DLL file");

    unsafe {
        let process_id = find_process_id(process_name).expect("Failed to find process");
        println!("[+] Found process {} with ID: {}", process_name, process_id);

        let h_process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process_id);
        if h_process == 0 {
            panic!("Failed to open process");
        }

        inject_dll(h_process, &dll_bytes);

        CloseHandle(h_process);
    }
}

unsafe fn list_processes() {
    let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if snapshot == INVALID_HANDLE_VALUE {
        println!("Failed to create snapshot");
        return;
    }

    let mut entry: PROCESSENTRY32 = std::mem::zeroed();
    entry.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;

    if Process32First(snapshot, &mut entry) != 0 {
        loop {
            let exe_name = std::ffi::CStr::from_ptr(entry.szExeFile.as_ptr() as *const i8)
                .to_string_lossy();
            println!("PID: {}, Name: {}", entry.th32ProcessID, exe_name);

            if Process32Next(snapshot, &mut entry) == 0 {
                break;
            }
        }
    }

    CloseHandle(snapshot);
}

unsafe fn find_process_id(name: &str) -> Option<u32> {
    let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if snapshot == INVALID_HANDLE_VALUE {
        return None;
    }

    let mut entry: PROCESSENTRY32 = std::mem::zeroed();
    entry.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;

    if Process32First(snapshot, &mut entry) != 0 {
        loop {
            let exe_name = std::ffi::CStr::from_ptr(entry.szExeFile.as_ptr() as *const i8)
                .to_string_lossy();
            if exe_name.to_lowercase() == name.to_lowercase() {
                CloseHandle(snapshot);
                return Some(entry.th32ProcessID);
            }

            if Process32Next(snapshot, &mut entry) == 0 {
                break;
            }
        }
    }

    CloseHandle(snapshot);
    None
}

unsafe fn inject_dll(h_process: HANDLE, dll_bytes: &[u8]) {
    let dos_header = dll_bytes.as_ptr() as *const IMAGE_DOS_HEADER;
    if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE {
        panic!("Invalid DOS signature");
    }

    let nt_headers = (dll_bytes.as_ptr() as usize + (*dos_header).e_lfanew as usize)
        as *const IMAGE_NT_HEADERS64;
    if (*nt_headers).OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC {
        panic!("Not a 64-bit DLL");
    }

    let image_size = (*nt_headers).OptionalHeader.SizeOfImage as usize;
    let preferred_base = (*nt_headers).OptionalHeader.ImageBase as *const c_void;

    // 1. Allocate memory for DLL
    let mut remote_base = VirtualAllocEx(
        h_process,
        preferred_base,
        image_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE,
    );

    let mut relocation_required = false;
    if remote_base.is_null() {
        relocation_required = true;
        remote_base = VirtualAllocEx(
            h_process,
            null(),
            image_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        );
    }

    if remote_base.is_null() {
        panic!("Failed to allocate memory in target process");
    }

    println!("[+] Allocated memory at: {:?}", remote_base);

    // 2. Write headers
    WriteProcessMemory(
        h_process,
        remote_base,
        dll_bytes.as_ptr() as *const c_void,
        (*nt_headers).OptionalHeader.SizeOfHeaders as usize,
        null_mut(),
    );

    // 3. Write sections
    let sections_ptr = (nt_headers as usize + std::mem::size_of::<IMAGE_NT_HEADERS64>())
        as *const IMAGE_SECTION_HEADER;
    let num_sections = (*nt_headers).FileHeader.NumberOfSections;

    for i in 0..num_sections {
        let section = &*sections_ptr.add(i as usize);
        let remote_section_addr = (remote_base as usize + section.VirtualAddress as usize) as *mut c_void;
        let local_section_addr = (dll_bytes.as_ptr() as usize + section.PointerToRawData as usize) as *const c_void;

        WriteProcessMemory(
            h_process,
            remote_section_addr,
            local_section_addr,
            section.SizeOfRawData as usize,
            null_mut(),
        );
    }

    // 4. Prepare DllInfo
    let h_kernel32 = windows_sys::Win32::System::LibraryLoader::GetModuleHandleA(
        "kernel32.dll\0".as_ptr() as *const u8,
    );
    let load_library_a_ptr = windows_sys::Win32::System::LibraryLoader::GetProcAddress(
        h_kernel32,
        "LoadLibraryA\0".as_ptr() as *const u8,
    ).expect("Failed to find LoadLibraryA");
    let get_proc_address_ptr = windows_sys::Win32::System::LibraryLoader::GetProcAddress(
        h_kernel32,
        "GetProcAddress\0".as_ptr() as *const u8,
    ).expect("Failed to find GetProcAddress");

    let dll_info = DllInfo {
        base: remote_base,
        load_library_a: std::mem::transmute(load_library_a_ptr),
        get_proc_address: std::mem::transmute(get_proc_address_ptr),
        relocation_required,
    };

    // 5. Allocate memory for bootstrapper
    // NOTE: This assumes realign_pe and realign_pe_end are contiguous and in order.
    // This is fragile but common for position-independent code bootstrapping.
    let start_ptr = realign_pe as *const ();
    let end_ptr = realign_pe_end as *const ();
    let bootstrapper_size = if end_ptr > start_ptr {
        end_ptr as usize - start_ptr as usize
    } else {
        start_ptr as usize - end_ptr as usize // Just in case compiler flipped them
    };
    let total_bootstrap_size = std::mem::size_of::<DllInfo>() + bootstrapper_size;

    let remote_bootstrap_mem = VirtualAllocEx(
        h_process,
        null(),
        total_bootstrap_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE,
    );

    // Write DllInfo
    WriteProcessMemory(
        h_process,
        remote_bootstrap_mem,
        &dll_info as *const DllInfo as *const c_void,
        std::mem::size_of::<DllInfo>(),
        null_mut(),
    );

    // Write realign_pe code
    WriteProcessMemory(
        h_process,
        (remote_bootstrap_mem as usize + std::mem::size_of::<DllInfo>()) as *mut c_void,
        realign_pe as *const c_void,
        bootstrapper_size,
        null_mut(),
    );

    // 6. Execute bootstrapper
    let thread_start_routine_addr = remote_bootstrap_mem as usize + std::mem::size_of::<DllInfo>();
    let h_thread = CreateRemoteThread(
        h_process,
        null(),
        0,
        std::mem::transmute(thread_start_routine_addr),
        remote_bootstrap_mem,
        0,
        null_mut(),
    );

    if h_thread == 0 {
        panic!("Failed to create remote thread");
    }

    println!("[+] Remote thread created: {:?}", h_thread);
    WaitForSingleObject(h_thread, INFINITE);
    CloseHandle(h_thread);
}
