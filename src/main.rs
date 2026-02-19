#![allow(non_upper_case_globals)]

use windows::{
    core::*,
    Win32::Foundation::HANDLE,
    Win32::System::Com::*,
    Win32::UI::Shell::*,
};

// Manually define GUIDs for consistency across crate versions
const FOLDERID_Startup: GUID = GUID::from_u128(0xB97D20BB_F46A_4C97_BA10_5E3608430854);
const CLSID_ShellLink: GUID = GUID::from_u128(0x00021401_0000_0000_C000_000000000046);

fn main() -> Result<()> {
    unsafe {
        // Initialize COM (Single-Threaded Apartment)
        // CoInitializeEx returns Result<()> in this version of the windows crate
        CoInitializeEx(None, COINIT_APARTMENTTHREADED)?;

        // Create an instance of the ShellLink COM object
        let shell_link: IShellLinkW = CoCreateInstance(&CLSID_ShellLink, None, CLSCTX_INPROC_SERVER)?;

        // Set the target path of the shortcut to cmd.exe
        // We use cmd.exe because 'echo' is a shell builtin
        shell_link.SetPath(w!("C:\\Windows\\System32\\cmd.exe"))?;

        // Set the arguments for the command as requested
        shell_link.SetArguments(w!("/c echo \"test\""))?;

        // Set a description for the shortcut
        shell_link.SetDescription(w!("Echo Test Shortcut"))?;

        // Query for the IPersistFile interface
        let persist_file: IPersistFile = shell_link.cast()?;

        // Retrieve the path to the Windows Startup folder
        // SHGetKnownFolderPath returns Result<PWSTR>
        // Use KF_FLAG_DEFAULT (0) and HANDLE(0) for the token
        let path_ptr = SHGetKnownFolderPath(&FOLDERID_Startup, KF_FLAG_DEFAULT, HANDLE(0))?;

        // Convert PWSTR to String, mapping any conversion error to a generic failure
        let startup_path = path_ptr.to_string().map_err(|_| Error::from(HRESULT(0x80004005u32 as i32)))?;

        // Free the memory allocated by SHGetKnownFolderPath
        CoTaskMemFree(Some(path_ptr.0 as _));

        // Construct the full path for the new .lnk file
        let lnk_path = format!("{}\\echo_test.lnk", startup_path);
        let lnk_path_wide: Vec<u16> = lnk_path.encode_utf16().chain(std::iter::once(0)).collect();

        // Save the shortcut file
        persist_file.Save(PCWSTR(lnk_path_wide.as_ptr()), true)?;

        println!("Successfully created shortcut: {}", lnk_path);

        // Uninitialize COM
        CoUninitialize();
    }
    Ok(())
}
