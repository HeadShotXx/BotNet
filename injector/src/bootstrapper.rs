use std::ffi::c_void;
use windows_sys::Win32::Foundation::{BOOL, HINSTANCE};
use windows_sys::Win32::System::Diagnostics::Debug::{
    IMAGE_NT_HEADERS64,
};
use windows_sys::Win32::System::SystemServices::{
    DLL_PROCESS_ATTACH, IMAGE_BASE_RELOCATION, IMAGE_IMPORT_BY_NAME, IMAGE_IMPORT_DESCRIPTOR,
    IMAGE_DOS_HEADER,
};
use windows_sys::Win32::System::WindowsProgramming::IMAGE_THUNK_DATA64;

#[repr(C)]
pub struct DllInfo {
    pub base: *mut c_void,
    pub load_library_a: unsafe extern "system" fn(*const u8) -> HINSTANCE,
    pub get_proc_address: unsafe extern "system" fn(HINSTANCE, *const u8) -> *mut c_void,
    pub relocation_required: bool,
}

/// This function must be position-independent.
/// It cannot use any global variables or strings that aren't passed in or constructed on the stack.
/// It cannot use the Rust standard library in a way that requires relocations.
#[no_mangle]
pub unsafe extern "system" fn realign_pe(dll_info_ptr: *mut DllInfo) {
    let dll_info = &*dll_info_ptr;
    let base = dll_info.base;
    let load_library_a = dll_info.load_library_a;
    let get_proc_address = dll_info.get_proc_address;

    let dos_header = base as *const IMAGE_DOS_HEADER;
    let nt_headers = (base as usize + (*dos_header).e_lfanew as usize) as *const IMAGE_NT_HEADERS64;

    // 1. Relocations
    if dll_info.relocation_required {
        let relocation_dir = (*nt_headers).OptionalHeader.DataDirectory[5]; // IMAGE_DIRECTORY_ENTRY_BASERELOC
        if relocation_dir.VirtualAddress != 0 {
            let mut relocation_block = (base as usize + relocation_dir.VirtualAddress as usize)
                as *const IMAGE_BASE_RELOCATION;
            let delta =
                base as isize - (*nt_headers).OptionalHeader.ImageBase as isize;

            while (*relocation_block).VirtualAddress != 0 {
                let entry_count = ((*relocation_block).SizeOfBlock as usize
                    - std::mem::size_of::<IMAGE_BASE_RELOCATION>())
                    / std::mem::size_of::<u16>();
                let entries_ptr = (relocation_block as usize
                    + std::mem::size_of::<IMAGE_BASE_RELOCATION>())
                    as *const u16;

                for i in 0..entry_count {
                    let entry = *entries_ptr.add(i);
                    let rel_type = entry >> 12;
                    let offset = entry & 0xFFF;

                    if rel_type == 10 {
                        // IMAGE_REL_BASED_DIR64
                        let patch_addr = (base as usize
                            + (*relocation_block).VirtualAddress as usize
                            + offset as usize) as *mut usize;
                        *patch_addr = (*patch_addr as isize + delta) as usize;
                    }
                }

                relocation_block = (relocation_block as usize + (*relocation_block).SizeOfBlock as usize)
                    as *const IMAGE_BASE_RELOCATION;
            }
        }
    }

    // 2. Imports
    let import_dir = (*nt_headers).OptionalHeader.DataDirectory[1]; // IMAGE_DIRECTORY_ENTRY_IMPORT
    if import_dir.VirtualAddress != 0 {
        let mut import_desc = (base as usize + import_dir.VirtualAddress as usize)
            as *const IMAGE_IMPORT_DESCRIPTOR;

        while (*import_desc).Name != 0 {
            let lib_name = (base as usize + (*import_desc).Name as usize) as *const u8;
            let h_module = load_library_a(lib_name);

            let mut original_thunk = if (*import_desc).Anonymous.OriginalFirstThunk != 0 {
                (base as usize + (*import_desc).Anonymous.OriginalFirstThunk as usize)
                    as *mut IMAGE_THUNK_DATA64
            } else {
                (base as usize + (*import_desc).FirstThunk as usize) as *mut IMAGE_THUNK_DATA64
            };

            let mut first_thunk =
                (base as usize + (*import_desc).FirstThunk as usize) as *mut IMAGE_THUNK_DATA64;

            while (*original_thunk).u1.AddressOfData != 0 {
                if (*original_thunk).u1.Ordinal & 0x8000000000000000 != 0 {
                    // Import by ordinal
                    let ordinal = ((*original_thunk).u1.Ordinal & 0xFFFF) as *const u8;
                    (*first_thunk).u1.Function = get_proc_address(h_module, ordinal) as u64;
                } else {
                    // Import by name
                    let import_by_name = (base as usize
                        + (*original_thunk).u1.AddressOfData as usize)
                        as *const IMAGE_IMPORT_BY_NAME;
                    let func_name = (*import_by_name).Name.as_ptr();
                    (*first_thunk).u1.Function = get_proc_address(h_module, func_name) as u64;
                }

                original_thunk = original_thunk.add(1);
                first_thunk = first_thunk.add(1);
            }

            import_desc = import_desc.add(1);
        }
    }

    // 3. Entry Point
    let entry_point_rva = (*nt_headers).OptionalHeader.AddressOfEntryPoint;
    if entry_point_rva != 0 {
        let entry_point_addr = base as usize + entry_point_rva as usize;
        let entry_point: unsafe extern "system" fn(*mut c_void, u32, *mut c_void) -> BOOL = std::mem::transmute(entry_point_addr);
        entry_point(base, DLL_PROCESS_ATTACH, std::ptr::null_mut());
    }
}

/// A dummy function to mark the end of `realign_pe`.
#[no_mangle]
pub extern "system" fn realign_pe_end() {}
