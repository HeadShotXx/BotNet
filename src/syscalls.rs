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

#[repr(C)]
#[derive(Copy, Clone)]
pub struct IMAGE_SECTION_HEADER {
    pub Name: [u8; 8],
    pub VirtualSize: u32,
    pub VirtualAddress: u32,
    pub SizeOfRawData: u32,
    pub PointerToRawData: u32,
    pub PointerToRelocations: u32,
    pub PointerToLinenumbers: u32,
    pub NumberOfRelocations: u16,
    pub NumberOfLinenumbers: u16,
    pub Characteristics: u32,
}

pub const IMAGE_SCN_MEM_EXECUTE: u32 = 0x20000000;

pub unsafe fn get_module_base(target_name: &[u16]) -> *mut core::ffi::c_void {
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

        let mut match_found = true;
        if name_slice.len() == target_name.len() {
            for i in 0..target_name.len() {
                let mut c = name_slice[i];
                if c >= 'A' as u16 && c <= 'Z' as u16 {
                    c += 32;
                }
                let mut t = target_name[i];
                if t >= 'A' as u16 && t <= 'Z' as u16 {
                    t += 32;
                }
                if c != t {
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

pub unsafe fn find_gadget(module_base: *const u8, patterns: &[&[u8]]) -> Option<*const u8> {
    let dos_header = module_base as *const IMAGE_DOS_HEADER;
    let nt_headers = module_base.add((*dos_header).e_lfanew as usize) as *const IMAGE_NT_HEADERS64;
    let num_sections = (*nt_headers).FileHeader.NumberOfSections;
    let optional_header_ptr = &(*nt_headers).OptionalHeader as *const _ as *const u8;
    let sections = optional_header_ptr.add((*nt_headers).FileHeader.SizeOfOptionalHeader as usize) as *const IMAGE_SECTION_HEADER;

    for i in 0..num_sections {
        let section = *sections.add(i as usize);
        if (section.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0 {
            let section_start = module_base.add(section.VirtualAddress as usize);
            let section_size = section.VirtualSize as usize;

            for j in 0..section_size {
                for pattern in patterns {
                    if j + pattern.len() <= section_size {
                        let ptr = section_start.add(j);
                        if std::slice::from_raw_parts(ptr, pattern.len()) == *pattern {
                            return Some(ptr);
                        }
                    }
                }
            }
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

    let mut stack_args = [0usize; 16];
    for i in 0..num_args {
        stack_args[i] = args[i];
    }

    let num_actual_stack_args = if num_args > 4 { num_args - 4 } else { 0 };
    let mut num_to_push = num_actual_stack_args;
    let mut arg_offset = 24;

    if num_to_push % 2 == 0 {
        num_to_push += 1;
        arg_offset -= 8;
    }

    let actual_stack_ptr = stack_args.as_ptr() as usize + arg_offset;

    asm!(
        "push rsi",
        "push rdi",
        "push rbx",
        "push rbp",
        "mov rbp, rsp",

        "test {num_to_push}, {num_to_push}",
        "jz 3f",

        "mov rcx, {num_to_push}",
        "2:",
        "mov rax, [{actual_stack_ptr} + rcx*8]",
        "push rax",
        "sub rcx, 1",
        "jnz 2b",

        "3:",
        "sub rsp, 0x20",
        "lea rbx, [rip + 4f]",
        "push {jmp_rbx}",

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

        num_to_push = in(reg) num_to_push,
        actual_stack_ptr = in(reg) actual_stack_ptr,
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
