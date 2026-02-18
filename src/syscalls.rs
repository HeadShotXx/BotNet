#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]

use core::arch::asm;
use windows_sys::Win32::Foundation::NTSTATUS;

pub struct Arg(pub usize);

impl<T> From<*mut T> for Arg {
    fn from(p: *mut T) -> Self { Arg(p as usize) }
}
impl<T> From<*const T> for Arg {
    fn from(p: *const T) -> Self { Arg(p as usize) }
}
impl From<usize> for Arg {
    fn from(u: usize) -> Self { Arg(u) }
}
impl From<u32> for Arg {
    fn from(u: u32) -> Self { Arg(u as usize) }
}
impl From<i32> for Arg {
    fn from(i: i32) -> Self { Arg(i as usize) }
}
impl From<isize> for Arg {
    fn from(i: isize) -> Self { Arg(i as usize) }
}
impl<'a, T> From<&'a T> for Arg {
    fn from(r: &'a T) -> Self { Arg(r as *const T as usize) }
}
impl<'a, T> From<&'a mut T> for Arg {
    fn from(r: &'a mut T) -> Self { Arg(r as *mut T as usize) }
}

#[macro_export]
macro_rules! syscall {
    ($name:expr) => {
        $crate::syscalls::spoof_syscall($crate::syscalls::get_ssn($name), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    };
    ($name:expr, $a1:expr) => {
        $crate::syscalls::spoof_syscall($crate::syscalls::get_ssn($name), $crate::syscalls::Arg::from($a1).0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    };
    ($name:expr, $a1:expr, $a2:expr) => {
        $crate::syscalls::spoof_syscall($crate::syscalls::get_ssn($name), $crate::syscalls::Arg::from($a1).0, $crate::syscalls::Arg::from($a2).0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    };
    ($name:expr, $a1:expr, $a2:expr, $a3:expr) => {
        $crate::syscalls::spoof_syscall($crate::syscalls::get_ssn($name), $crate::syscalls::Arg::from($a1).0, $crate::syscalls::Arg::from($a2).0, $crate::syscalls::Arg::from($a3).0, 0, 0, 0, 0, 0, 0, 0, 0)
    };
    ($name:expr, $a1:expr, $a2:expr, $a3:expr, $a4:expr) => {
        $crate::syscalls::spoof_syscall($crate::syscalls::get_ssn($name), $crate::syscalls::Arg::from($a1).0, $crate::syscalls::Arg::from($a2).0, $crate::syscalls::Arg::from($a3).0, $crate::syscalls::Arg::from($a4).0, 0, 0, 0, 0, 0, 0, 0)
    };
    ($name:expr, $a1:expr, $a2:expr, $a3:expr, $a4:expr, $a5:expr) => {
        $crate::syscalls::spoof_syscall($crate::syscalls::get_ssn($name), $crate::syscalls::Arg::from($a1).0, $crate::syscalls::Arg::from($a2).0, $crate::syscalls::Arg::from($a3).0, $crate::syscalls::Arg::from($a4).0, $crate::syscalls::Arg::from($a5).0, 0, 0, 0, 0, 0, 0)
    };
    ($name:expr, $a1:expr, $a2:expr, $a3:expr, $a4:expr, $a5:expr, $a6:expr) => {
        $crate::syscalls::spoof_syscall($crate::syscalls::get_ssn($name), $crate::syscalls::Arg::from($a1).0, $crate::syscalls::Arg::from($a2).0, $crate::syscalls::Arg::from($a3).0, $crate::syscalls::Arg::from($a4).0, $crate::syscalls::Arg::from($a5).0, $crate::syscalls::Arg::from($a6).0, 0, 0, 0, 0, 0)
    };
    ($name:expr, $a1:expr, $a2:expr, $a3:expr, $a4:expr, $a5:expr, $a6:expr, $a7:expr) => {
        $crate::syscalls::spoof_syscall($crate::syscalls::get_ssn($name), $crate::syscalls::Arg::from($a1).0, $crate::syscalls::Arg::from($a2).0, $crate::syscalls::Arg::from($a3).0, $crate::syscalls::Arg::from($a4).0, $crate::syscalls::Arg::from($a5).0, $crate::syscalls::Arg::from($a6).0, $crate::syscalls::Arg::from($a7).0, 0, 0, 0, 0)
    };
    ($name:expr, $a1:expr, $a2:expr, $a3:expr, $a4:expr, $a5:expr, $a6:expr, $a7:expr, $a8:expr) => {
        $crate::syscalls::spoof_syscall($crate::syscalls::get_ssn($name), $crate::syscalls::Arg::from($a1).0, $crate::syscalls::Arg::from($a2).0, $crate::syscalls::Arg::from($a3).0, $crate::syscalls::Arg::from($a4).0, $crate::syscalls::Arg::from($a5).0, $crate::syscalls::Arg::from($a6).0, $crate::syscalls::Arg::from($a7).0, $crate::syscalls::Arg::from($a8).0, 0, 0, 0)
    };
    ($name:expr, $a1:expr, $a2:expr, $a3:expr, $a4:expr, $a5:expr, $a6:expr, $a7:expr, $a8:expr, $a9:expr) => {
        $crate::syscalls::spoof_syscall($crate::syscalls::get_ssn($name), $crate::syscalls::Arg::from($a1).0, $crate::syscalls::Arg::from($a2).0, $crate::syscalls::Arg::from($a3).0, $crate::syscalls::Arg::from($a4).0, $crate::syscalls::Arg::from($a5).0, $crate::syscalls::Arg::from($a6).0, $crate::syscalls::Arg::from($a7).0, $crate::syscalls::Arg::from($a8).0, $crate::syscalls::Arg::from($a9).0, 0, 0)
    };
    ($name:expr, $a1:expr, $a2:expr, $a3:expr, $a4:expr, $a5:expr, $a6:expr, $a7:expr, $a8:expr, $a9:expr, $a10:expr) => {
        $crate::syscalls::spoof_syscall($crate::syscalls::get_ssn($name), $crate::syscalls::Arg::from($a1).0, $crate::syscalls::Arg::from($a2).0, $crate::syscalls::Arg::from($a3).0, $crate::syscalls::Arg::from($a4).0, $crate::syscalls::Arg::from($a5).0, $crate::syscalls::Arg::from($a6).0, $crate::syscalls::Arg::from($a7).0, $crate::syscalls::Arg::from($a8).0, $crate::syscalls::Arg::from($a9).0, $crate::syscalls::Arg::from($a10).0, 0)
    };
    ($name:expr, $a1:expr, $a2:expr, $a3:expr, $a4:expr, $a5:expr, $a6:expr, $a7:expr, $a8:expr, $a9:expr, $a10:expr, $a11:expr) => {
        $crate::syscalls::spoof_syscall($crate::syscalls::get_ssn($name), $crate::syscalls::Arg::from($a1).0, $crate::syscalls::Arg::from($a2).0, $crate::syscalls::Arg::from($a3).0, $crate::syscalls::Arg::from($a4).0, $crate::syscalls::Arg::from($a5).0, $crate::syscalls::Arg::from($a6).0, $crate::syscalls::Arg::from($a7).0, $crate::syscalls::Arg::from($a8).0, $crate::syscalls::Arg::from($a9).0, $crate::syscalls::Arg::from($a10).0, $crate::syscalls::Arg::from($a11).0)
    };
}

pub fn get_ssn(function_name: &str) -> u32 {
    use windows_sys::Win32::System::LibraryLoader::GetProcAddress;
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;

    unsafe {
        let ntdll_name: Vec<u16> = "ntdll.dll\0".encode_utf16().collect();
        let ntdll = GetModuleHandleW(ntdll_name.as_ptr());
        if ntdll == 0 {
            return 0;
        }

        let function_name_c = std::ffi::CString::new(function_name).unwrap();
        let address = GetProcAddress(ntdll, function_name_c.as_ptr() as *const u8);
        if address.is_none() {
            return 0;
        }

        let address = address.unwrap() as *const u8;

        for i in 0..32 {
            if *address.add(i) == 0xb8 {
                return *(address.add(i + 1) as *const u32);
            }
        }
    }
    0
}

#[inline(never)]
pub unsafe fn spoof_syscall(
    ssn: u32,
    arg1: usize,
    arg2: usize,
    arg3: usize,
    arg4: usize,
    arg5: usize,
    arg6: usize,
    arg7: usize,
    arg8: usize,
    arg9: usize,
    arg10: usize,
    arg11: usize
) -> NTSTATUS {
    let mut status: i32;

    asm!(
        "mov r10, rcx",
        "sub rsp, 0x60",
        "mov [rsp + 0x20], {arg5}",
        "mov [rsp + 0x28], {arg6}",
        "mov [rsp + 0x30], {arg7}",
        "mov [rsp + 0x38], {arg8}",
        "mov [rsp + 0x40], {arg9}",
        "mov [rsp + 0x48], {arg10}",
        "mov [rsp + 0x50], {arg11}",
        "syscall",
        "add rsp, 0x60",
        in("rax") ssn as usize,
        in("rcx") arg1,
        in("rdx") arg2,
        in("r8") arg3,
        in("r9") arg4,
        arg5 = in(reg) arg5,
        arg6 = in(reg) arg6,
        arg7 = in(reg) arg7,
        arg8 = in(reg) arg8,
        arg9 = in(reg) arg9,
        arg10 = in(reg) arg10,
        arg11 = in(reg) arg11,
        lateout("rax") status,
    );

    status
}
