use std::mem::transmute;
use once_cell::sync::Lazy;
use std::ffi::c_void;
use windows_sys::Win32::System::Threading::PROCESS_INFORMATION_CLASS;
use windows_sys::Win32::System::LibraryLoader::{LoadLibraryA, GetProcAddress};
type NtQueryInformationProcess = extern "system" fn(
    ProcessHandle: *mut c_void,
    ProcessInformationClass: PROCESS_INFORMATION_CLASS,
    ProcessInformation: *mut c_void,
    ProcessInformationLength: u32,
    ReturnLength: *mut u32,
) -> i32;
type NtClose = extern "system" fn(Handle: *mut c_void) -> i32;
type NtReadVirtualMemory = extern "system" fn(
    ProcessHandle: *mut c_void,
    BaseAddress: *mut c_void,
    Buffer: *mut c_void,
    NumberOfBytesToRead: usize,
    NumberOfBytesRead: *mut usize,
) -> i32;
type NtWriteVirtualMemory = extern "system" fn(
    ProcessHandle: *mut c_void,
    BaseAddress: *mut c_void,
    Buffer: *mut c_void,
    NumberOfBytesToWrite: usize,
    NumberOfBytesWritten: *mut usize,
) -> i32;
type NtResumeThread = extern "system" fn(
    ThreadHandle: *mut c_void,
    SuspendCount: *mut u32,
) -> i32;
#[derive(Clone)]
pub struct Syscalls {
    pub NtQueryInformationProcess: NtQueryInformationProcess,
    pub NtClose: NtClose,
    pub NtReadVirtualMemory: NtReadVirtualMemory,
    pub NtWriteVirtualMemory: NtWriteVirtualMemory,
    pub NtResumeThread: NtResumeThread,
}
impl Syscalls {
    fn new() -> Result<Self, &'static str> {
        unsafe {
            let ntdll = LoadLibraryA("ntdll.dll\0".as_ptr());
            if ntdll == 0 {
                return Err("Failed to load ntdll.dll");
            }

            let NtQueryInformationProcess = GetProcAddress(ntdll, "NtQueryInformationProcess\0".as_ptr());
            let NtClose = GetProcAddress(ntdll, "NtClose\0".as_ptr());
            let NtReadVirtualMemory = GetProcAddress(ntdll, "NtReadVirtualMemory\0".as_ptr());
            let NtWriteVirtualMemory = GetProcAddress(ntdll, "NtWriteVirtualMemory\0".as_ptr());
            let NtResumeThread = GetProcAddress(ntdll, "NtResumeThread\0".as_ptr());

            if NtQueryInformationProcess.is_none() || NtClose.is_none() || NtReadVirtualMemory.is_none() || NtWriteVirtualMemory.is_none() || NtResumeThread.is_none() {
                return Err("Failed to get one or more function addresses");
            }

            Ok(Syscalls {
                NtQueryInformationProcess: transmute(NtQueryInformationProcess.unwrap()),
                NtClose: transmute(NtClose.unwrap()),
                NtReadVirtualMemory: transmute(NtReadVirtualMemory.unwrap()),
                NtWriteVirtualMemory: transmute(NtWriteVirtualMemory.unwrap()),
                NtResumeThread: transmute(NtResumeThread.unwrap()),
            })
        }
    }
}
pub static SYSCALLS: Lazy<Syscalls> = Lazy::new(|| {
    Syscalls::new().expect("")
});
