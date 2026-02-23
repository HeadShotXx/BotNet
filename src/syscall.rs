
use windows::{
    core::*,
    Win32::System::LibraryLoader::*,
};

pub fn get_syscall_number(func_name: &str) -> Option<u32> {
    unsafe {
        let ntdll_handle = GetModuleHandleA(s!("ntdll.dll")).expect("Handle not found");
        if ntdll_handle.is_invalid() {
            return None;
        }

        let c_func_name = std::ffi::CString::new(func_name).unwrap();
        let func_addr = GetProcAddress(ntdll_handle, PCSTR(c_func_name.as_ptr() as *const u8));
        if func_addr.is_none() {
            return None;
        }

        let func_bytes = std::slice::from_raw_parts(func_addr.unwrap() as *const u8, 8);

        if func_bytes[0] == 0x4c
            && func_bytes[1] == 0x8b
            && func_bytes[2] == 0xd1
            && func_bytes[3] == 0xb8
            && func_bytes[6] == 0x00
            && func_bytes[7] == 0x00
        {
            let high = u32::from(func_bytes[5]);
            let low = u32::from(func_bytes[4]);
            let syscall_number = (high << 8) | low;
            return Some(syscall_number);
        }

        None
    }
}

pub fn find_gadget(func_name: &str, pattern: &[u8]) -> Option<usize> {
    unsafe {
        let ntdll_handle = GetModuleHandleA(s!("ntdll.dll")).ok()?;
        let c_func_name = std::ffi::CString::new(func_name).ok()?;
        let func_addr = GetProcAddress(ntdll_handle, PCSTR(c_func_name.as_ptr() as *const u8))?;

        // Search within 0x100 bytes of the function start for the pattern
        let search_range = std::slice::from_raw_parts(func_addr as *const u8, 0x100);
        for i in 0..(search_range.len() - pattern.len()) {
            if &search_range[i..i + pattern.len()] == pattern {
                return Some(func_addr as usize + i);
            }
        }
        None
    }
}

pub struct Gadgets {
    pub ret: usize,
    pub syscall_ret: usize,
}

pub fn get_nt_gadgets() -> Option<Gadgets> {
    // C3 = ret
    // 0F 05 C3 = syscall; ret
    let syscall_ret = find_gadget("NtOpenProcess", &[0x0F, 0x05, 0xC3]);
    let ret = syscall_ret.map(|addr| addr + 2);

    if let (Some(ret), Some(syscall_ret)) = (ret, syscall_ret) {
        Some(Gadgets { ret, syscall_ret })
    } else {
        None
    }
}
