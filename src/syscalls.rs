#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]

use std::arch::asm;
pub use windows_sys::Win32::Foundation::{UNICODE_STRING, NTSTATUS};
pub use windows_sys::Win32::System::SystemServices::{IMAGE_DOS_HEADER, IMAGE_EXPORT_DIRECTORY, IMAGE_DOS_SIGNATURE};

#[repr(C)]
#[derive(Copy, Clone)]
pub struct LIST_ENTRY {
    pub Flink: *mut LIST_ENTRY,
    pub Blink: *mut LIST_ENTRY,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct PEB_LDR_DATA {
    pub Length: u32,
    pub Initialized: u8,
    pub SsHandle: *mut core::ffi::c_void,
    pub InLoadOrderModuleList: LIST_ENTRY,
    pub InMemoryOrderModuleList: LIST_ENTRY,
    pub InInitializationOrderModuleList: LIST_ENTRY,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct LDR_DATA_TABLE_ENTRY {
    pub InLoadOrderLinks: LIST_ENTRY,
    pub InMemoryOrderLinks: LIST_ENTRY,
    pub u1: LIST_ENTRY,
    pub DllBase: *mut core::ffi::c_void,
    pub EntryPoint: *mut core::ffi::c_void,
    pub SizeOfImage: u32,
    pub FullDllName: UNICODE_STRING,
    pub BaseDllName: UNICODE_STRING,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct IMAGE_DATA_DIRECTORY {
    pub VirtualAddress: u32,
    pub Size: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct IMAGE_FILE_HEADER {
    pub Machine: u16,
    pub NumberOfSections: u16,
    pub TimeDateStamp: u32,
    pub PointerToSymbolTable: u32,
    pub NumberOfSymbols: u32,
    pub SizeOfOptionalHeader: u16,
    pub Characteristics: u16,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct IMAGE_OPTIONAL_HEADER64 {
    pub Magic: u16,
    pub MajorLinkerVersion: u8,
    pub MinorLinkerVersion: u8,
    pub SizeOfCode: u32,
    pub SizeOfInitializedData: u32,
    pub SizeOfUninitializedData: u32,
    pub AddressOfEntryPoint: u32,
    pub BaseOfCode: u32,
    pub ImageBase: u64,
    pub SectionAlignment: u32,
    pub FileAlignment: u32,
    pub MajorOperatingSystemVersion: u16,
    pub MinorOperatingSystemVersion: u16,
    pub MajorImageVersion: u16,
    pub MinorImageVersion: u16,
    pub MajorSubsystemVersion: u16,
    pub MinorSubsystemVersion: u16,
    pub Win32VersionValue: u32,
    pub SizeOfImage: u32,
    pub SizeOfHeaders: u32,
    pub CheckSum: u32,
    pub Subsystem: u16,
    pub DllCharacteristics: u16,
    pub SizeOfStackReserve: u64,
    pub SizeOfStackCommit: u64,
    pub SizeOfHeapReserve: u64,
    pub SizeOfHeapCommit: u64,
    pub LoaderFlags: u32,
    pub NumberOfRvaAndSizes: u32,
    pub DataDirectory: [IMAGE_DATA_DIRECTORY; 16],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct IMAGE_NT_HEADERS64 {
    pub Signature: u32,
    pub FileHeader: IMAGE_FILE_HEADER,
    pub OptionalHeader: IMAGE_OPTIONAL_HEADER64,
}

pub unsafe fn get_ntdll_base() -> *mut core::ffi::c_void {
    let peb: *mut u8;
    unsafe {
        asm!("mov {}, gs:[0x60]", out(reg) peb);
    }

    let ldr = unsafe { *(peb.add(0x18) as *const *mut PEB_LDR_DATA) };
    let mut current_entry = unsafe { (*ldr).InLoadOrderModuleList.Flink };

    while current_entry != unsafe { &mut (*ldr).InLoadOrderModuleList } {
        let table_entry = current_entry as *mut LDR_DATA_TABLE_ENTRY;

        let name_slice = unsafe {
            std::slice::from_raw_parts(
                (*table_entry).BaseDllName.Buffer,
                ((*table_entry).BaseDllName.Length / 2) as usize
            )
        };

        let target = ['n' as u16, 't' as u16, 'd' as u16, 'l' as u16, 'l' as u16, '.' as u16, 'd' as u16, 'l' as u16, 'l' as u16];
        let mut match_found = true;
        if name_slice.len() == target.len() {
            for i in 0..target.len() {
                let mut c = name_slice[i];
                if c >= 'A' as u16 && c <= 'Z' as u16 {
                    c += 32;
                }
                if c != target[i] {
                    match_found = false;
                    break;
                }
            }
            if match_found {
                return unsafe { (*table_entry).DllBase };
            }
        }

        current_entry = unsafe { (*current_entry).Flink };
    }

    core::ptr::null_mut()
}

pub unsafe fn get_ssn(ntdll_base: *const u8, function_name: &str) -> Option<u32> {
    let dos_header = ntdll_base as *const IMAGE_DOS_HEADER;
    if unsafe { (*dos_header).e_magic } != IMAGE_DOS_SIGNATURE {
        return None;
    }

    let nt_headers = unsafe { ntdll_base.add((*dos_header).e_lfanew as usize) } as *const IMAGE_NT_HEADERS64;
    let export_dir_entry = unsafe { (*nt_headers).OptionalHeader.DataDirectory[0] };
    let export_dir = unsafe { ntdll_base.add(export_dir_entry.VirtualAddress as usize) } as *const IMAGE_EXPORT_DIRECTORY;

    let names = unsafe {
        std::slice::from_raw_parts(
            ntdll_base.add((*export_dir).AddressOfNames as usize) as *const u32,
            (*export_dir).NumberOfNames as usize
        )
    };
    let functions = unsafe {
        std::slice::from_raw_parts(
            ntdll_base.add((*export_dir).AddressOfFunctions as usize) as *const u32,
            (*export_dir).NumberOfFunctions as usize
        )
    };
    let ordinals = unsafe {
        std::slice::from_raw_parts(
            ntdll_base.add((*export_dir).AddressOfNameOrdinals as usize) as *const u16,
            (*export_dir).NumberOfNames as usize
        )
    };

    for i in 0..unsafe { (*export_dir).NumberOfNames } as usize {
        let name_ptr = unsafe { ntdll_base.add(names[i] as usize) } as *const i8;
        let name = unsafe { std::ffi::CStr::from_ptr(name_ptr).to_str().unwrap_or("") };

        if name == function_name {
            let ordinal = ordinals[i];
            let function_addr = unsafe { ntdll_base.add(functions[ordinal as usize] as usize) };

            if unsafe { *function_addr == 0x4c && *function_addr.add(1) == 0x8b && *function_addr.add(2) == 0xd1 && *function_addr.add(3) == 0xb8 } {
                return Some(unsafe { *(function_addr.add(4) as *const u32) });
            }
            if unsafe { *function_addr == 0xb8 } {
                return Some(unsafe { *(function_addr.add(1) as *const u32) });
            }
        }
    }

    None
}

#[macro_export]
macro_rules! syscall {
    ($ssn:expr, $($arg:expr),*) => {
        {
            let mut result: $crate::syscalls::NTSTATUS;
            let args = [$( $arg as usize ),*];
            let num_args = args.len();

            match num_args {
                    0 => {
                        std::arch::asm!("mov r10, rcx", "syscall", in("rax") $ssn as usize, lateout("rax") result);
                    }
                    1 => {
                        std::arch::asm!("mov r10, rcx", "syscall", in("rax") $ssn as usize, in("rcx") args[0], lateout("rax") result);
                    }
                    2 => {
                        std::arch::asm!("mov r10, rcx", "syscall", in("rax") $ssn as usize, in("rcx") args[0], in("rdx") args[1], lateout("rax") result);
                    }
                    3 => {
                        std::arch::asm!("mov r10, rcx", "syscall", in("rax") $ssn as usize, in("rcx") args[0], in("rdx") args[1], in("r8") args[2], lateout("rax") result);
                    }
                    4 => {
                        std::arch::asm!("mov r10, rcx", "syscall", in("rax") $ssn as usize, in("rcx") args[0], in("rdx") args[1], in("r8") args[2], in("r9") args[3], lateout("rax") result);
                    }
                    5 => {
                        std::arch::asm!("mov r10, rcx", "sub rsp, 0x28", "mov rax, {arg5}", "mov [rsp+0x20], rax", "mov rax, {ssn}", "syscall", "add rsp, 0x28", ssn = in(reg) $ssn as usize, in("rcx") args[0], in("rdx") args[1], in("r8") args[2], in("r9") args[3], arg5 = in(reg) args[4], lateout("rax") result);
                    }
                    6 => {
                        std::arch::asm!("mov r10, rcx", "sub rsp, 0x30", "mov rax, {arg5}", "mov [rsp+0x20], rax", "mov rax, {arg6}", "mov [rsp+0x28], rax", "mov rax, {ssn}", "syscall", "add rsp, 0x30", ssn = in(reg) $ssn as usize, in("rcx") args[0], in("rdx") args[1], in("r8") args[2], in("r9") args[3], arg5 = in(reg) args[4], arg6 = in(reg) args[5], lateout("rax") result);
                    }
                    9 => {
                        std::arch::asm!("mov r10, rcx", "sub rsp, 0x48", "mov rax, {arg5}", "mov [rsp+0x20], rax", "mov rax, {arg6}", "mov [rsp+0x28], rax", "mov rax, {arg7}", "mov [rsp+0x30], rax", "mov rax, {arg8}", "mov [rsp+0x38], rax", "mov rax, {arg9}", "mov [rsp+0x40], rax", "mov rax, {ssn}", "syscall", "add rsp, 0x48", ssn = in(reg) $ssn as usize, in("rcx") args[0], in("rdx") args[1], in("r8") args[2], in("r9") args[3], arg5 = in(reg) args[4], arg6 = in(reg) args[5], arg7 = in(reg) args[6], arg8 = in(reg) args[7], arg9 = in(reg) args[8], lateout("rax") result);
                    }
                    10 => {
                         std::arch::asm!("mov r10, rcx", "sub rsp, 0x50", "mov rax, {arg5}", "mov [rsp+0x20], rax", "mov rax, {arg6}", "mov [rsp+0x28], rax", "mov rax, {arg7}", "mov [rsp+0x30], rax", "mov rax, {arg8}", "mov [rsp+0x38], rax", "mov rax, {arg9}", "mov [rsp+0x40], rax", "mov rax, {arg10}", "mov [rsp+0x48], rax", "mov rax, {ssn}", "syscall", "add rsp, 0x50", ssn = in(reg) $ssn as usize, in("rcx") args[0], in("rdx") args[1], in("r8") args[2], in("r9") args[3], arg5 = in(reg) args[4], arg6 = in(reg) args[5], arg7 = in(reg) args[6], arg8 = in(reg) args[7], arg9 = in(reg) args[8], arg10 = in(reg) args[9], lateout("rax") result);
                    }
                    11 => {
                         std::arch::asm!("mov r10, rcx", "sub rsp, 0x58", "mov rax, {arg5}", "mov [rsp+0x20], rax", "mov rax, {arg6}", "mov [rsp+0x28], rax", "mov rax, {arg7}", "mov [rsp+0x30], rax", "mov rax, {arg8}", "mov [rsp+0x38], rax", "mov rax, {arg9}", "mov [rsp+0x40], rax", "mov rax, {arg10}", "mov [rsp+0x48], rax", "mov rax, {arg11}", "mov [rsp+0x50], rax", "mov rax, {ssn}", "syscall", "add rsp, 0x58", ssn = in(reg) $ssn as usize, in("rcx") args[0], in("rdx") args[1], in("r8") args[2], in("r9") args[3], arg5 = in(reg) args[4], arg6 = in(reg) args[5], arg7 = in(reg) args[6], arg8 = in(reg) args[7], arg9 = in(reg) args[8], arg10 = in(reg) args[9], arg11 = in(reg) args[10], lateout("rax") result);
                    }
                    _ => unimplemented!("Unimplemented syscall arity"),
            }
            result
        }
    };
}
