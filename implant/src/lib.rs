use windows_sys::Win32::Foundation::{BOOL, HANDLE, HINSTANCE, TRUE};
use windows_sys::Win32::System::SystemServices::{DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH, DLL_THREAD_ATTACH, DLL_THREAD_DETACH};
use windows_sys::Win32::UI::WindowsAndMessaging::{MessageBoxA, MB_OK};

#[no_mangle]
#[allow(non_snake_case, unused_variables)]
pub extern "system" fn DllMain(
    hinst_dll: HINSTANCE,
    fdw_reason: u32,
    lpv_reserved: *const std::ffi::c_void,
) -> BOOL {
    match fdw_reason {
        DLL_PROCESS_ATTACH => {
            unsafe {
                MessageBoxA(
                    0,
                    "Reflective DLL Injected Successfully!\0".as_ptr() as *const u8,
                    "Success\0".as_ptr() as *const u8,
                    MB_OK,
                );
            }
        }
        DLL_PROCESS_DETACH => {}
        DLL_THREAD_ATTACH => {}
        DLL_THREAD_DETACH => {}
        _ => {}
    }
    TRUE
}
