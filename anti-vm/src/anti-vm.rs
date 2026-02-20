#![cfg(windows)]

use rand::seq::SliceRandom;
use rand::Rng;
use raw_cpuid::CpuId;
use std::ffi::c_void;
use std::thread;
use std::time::{Duration};
use windows::core::{HSTRING, PCWSTR};
use windows::Win32::Foundation::{GENERIC_READ, HANDLE};
use windows::Win32::System::Registry::{
    RegCloseKey, RegGetValueW, RegOpenKeyExW, HKEY, HKEY_LOCAL_MACHINE, KEY_READ, RRF_RT_REG_SZ,
};
use windows::Win32::System::SystemInformation::{
    GlobalMemoryStatusEx, MEMORYSTATUSEX, GetSystemInfo, SYSTEM_INFO,
};
use windows::Win32::System::WindowsProgramming::GetUserNameW;
use windows::Win32::Storage::FileSystem::{
    GetDiskFreeSpaceExW, CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_ATTRIBUTE_NORMAL,
    OPEN_EXISTING,
};
use windows::Win32::UI::WindowsAndMessaging::{GetCursorPos, GetSystemMetrics, SM_CXSCREEN, SM_CYSCREEN};

const XOR_KEY: &[u8] = b"vM_dEtEcTiOn_KeY_2024";

fn xor_obfuscate(data: &mut [u8], key: &[u8]) {
    for i in 0..data.len() {
        data[i] ^= key[i % key.len()];
    }
}

fn deobf(obfuscated_data: &[u8]) -> String {
    let mut data = obfuscated_data.to_vec();
    xor_obfuscate(&mut data, XOR_KEY);
    String::from_utf8_lossy(&data).to_string()
}

/// 1. Advanced RDTSC timing analysis.
/// Measures the relative latency of the CPUID instruction.
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub fn check_rdtsc_advanced() -> bool {
    #[cfg(target_arch = "x86_64")]
    use std::arch::x86_64::{_mm_lfence, _rdtsc};
    #[cfg(target_arch = "x86")]
    use std::arch::x86::{_mm_lfence, _rdtsc};

    let mut cpuid_samples = Vec::new();
    let mut nop_samples = Vec::new();
    let cpuid = CpuId::new();

    for _ in 0..50 {
        unsafe {
            _mm_lfence();
            let t1 = _rdtsc();
            _mm_lfence();

            // Actually execute CPUID via a method call
            let _ = cpuid.get_vendor_info();

            _mm_lfence();
            let t2 = _rdtsc();
            _mm_lfence();
            cpuid_samples.push(t2 - t1);

            _mm_lfence();
            let t3 = _rdtsc();
            _mm_lfence();
            for _ in 0..10 { std::arch::asm!("nop"); }
            _mm_lfence();
            let t4 = _rdtsc();
            _mm_lfence();
            nop_samples.push(t4 - t3);
        }
    }

    let avg_cpuid = cpuid_samples.iter().sum::<u64>() / cpuid_samples.len() as u64;
    let avg_nop = nop_samples.iter().sum::<u64>() / nop_samples.len() as u64;

    // Detection if CPUID is unusually slow compared to local operations.
    avg_cpuid > 1000 || (avg_cpuid / avg_nop.max(1)) > 40
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
pub fn check_rdtsc_advanced() -> bool {
    false
}

/// 2. Mouse movement monitor.
pub fn check_mouse_behavior() -> bool {
    let mut pos1 = windows::Win32::Foundation::POINT::default();
    let mut pos2 = windows::Win32::Foundation::POINT::default();

    unsafe { let _ = GetCursorPos(&mut pos1); }
    thread::sleep(Duration::from_millis(2000));
    unsafe { let _ = GetCursorPos(&mut pos2); }

    pos1.x == pos2.x && pos1.y == pos2.y
}

/// 2. Check for common sandbox usernames and hostnames.
pub fn check_sandbox_environment() -> bool {
    let mut buffer = [0u16; 256];
    let mut size = buffer.len() as u32;
    let username = unsafe {
        if GetUserNameW(windows::core::PWSTR(buffer.as_mut_ptr()), &mut size).is_ok() {
            String::from_utf16_lossy(&buffer[..size as usize - 1]).to_uppercase()
        } else {
            String::new()
        }
    };

    let sandbox_strings = [
        deobf(&[33, 9, 30, 35, 16, 0, 44, 15, 61, 29, 54, 47, 60, 40, 10, 44, 49, 70]), // "WDAGUtilityAccount"
        deobf(&[37, 12, 17, 32, 7, 59, 29]), // "SANDBOX"
    ];

    for s in &sandbox_strings {
        if username.contains(&s.to_uppercase()) {
            return true;
        }
    }
    false
}

/// 2. Check for minimalist environment (file count in System32).
pub fn check_system32_footprint() -> bool {
    let sys32_path = deobf(&[53, 119, 3, 51, 44, 26, 33, 12, 35, 26, 19, 61, 38, 56, 17, 60, 50, 1, 2]); // "C:\Windows\System32"
    if let Ok(entries) = std::fs::read_dir(sys32_path) {
        let count = entries.take(1001).count();
        return count < 800;
    }
    false
}

/// 3. Device file checks for VMs.
pub fn check_device_files() -> bool {
    let devices = [
        deobf(&[42, 17, 113, 56, 19, 54, 42, 27, 19, 28, 42, 29, 43]), // "\\.\VBoxGuest"
        deobf(&[42, 17, 113, 56, 19, 54, 42, 27, 4, 0, 63, 11]), // "\\.\VBoxPipe"
        deobf(&[42, 17, 113, 56, 19, 54, 39, 2, 2, 35]), // "\\.\HGFS"
        deobf(&[42, 17, 113, 56, 19, 54, 43, 29, 18, 51]), // "\\.\vmci"
    ];

    for dev in &devices {
        let h_file: windows::core::Result<HANDLE> = unsafe {
            CreateFileW(
                &HSTRING::from(dev),
                GENERIC_READ.0,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )
        };
        if let Ok(handle) = h_file {
            if !handle.is_invalid() {
                unsafe { let _ = windows::Win32::Foundation::CloseHandle(handle); }
                return true;
            }
        }
    }
    false
}

/// 4. Hardware and environment fingerprinting.
pub fn check_hardware_fingerprint() -> bool {
    let width = unsafe { GetSystemMetrics(SM_CXSCREEN) };
    let height = unsafe { GetSystemMetrics(SM_CYSCREEN) };
    if (width > 0 && width <= 1024 && height > 0 && height <= 768) || (width == 800 && height == 600) {
        return true;
    }

    let mut sys_info = SYSTEM_INFO::default();
    unsafe { GetSystemInfo(&mut sys_info); }
    if sys_info.dwNumberOfProcessors < 2 {
        return true;
    }

    let mut mem_status = MEMORYSTATUSEX::default();
    mem_status.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
    let mut total_disk: u64 = 0;
    let root_path = HSTRING::from(deobf(&[53, 119, 3])); // "C:\"

    unsafe {
        let _ = GlobalMemoryStatusEx(&mut mem_status);
        let _ = GetDiskFreeSpaceExW(&root_path, Some(std::ptr::null_mut()), Some(&mut total_disk), Some(std::ptr::null_mut()));
    }

    if mem_status.ullTotalPhys < (4 * 1024 * 1024 * 1024) && total_disk < (100 * 1024 * 1024 * 1024) {
        return true;
    }

    false
}

/// 4. Enhanced artifact detection (Registry).
pub fn check_registry_artifacts() -> bool {
    let bios_key = HSTRING::from(deobf(&[62, 12, 13, 32, 18, 53, 23, 38, 8, 45, 10, 61, 28, 25, 44, 9, 11, 123, 127, 124, 104, 37, 52, 44, 16, 32, 25, 25, 33, 29, 38, 28]));
    let mut key_handle: HKEY = HKEY(0);
    if unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, &bios_key, 0, KEY_READ, &mut key_handle) }.is_ok() {
        let values = [
            HSTRING::from(deobf(&[52, 4, 16, 55, 19, 17, 43, 7, 59, 27])), // BIOSVendor
            HSTRING::from(deobf(&[37, 52, 44, 16, 32, 25, 8, 2, 58, 28, 41, 15, 60, 63, 16, 43, 58, 64])), // SystemManufacturer
        ];
        for val in &values {
            let mut buffer = [0u16; 1024];
            let mut size = 2048u32;
            if unsafe { RegGetValueW(key_handle, PCWSTR::null(), val, RRF_RT_REG_SZ, Some(std::ptr::null_mut()), Some(buffer.as_mut_ptr() as *mut c_void), Some(&mut size)) }.is_ok() {
                let s = String::from_utf16_lossy(&buffer[..(size/2) as usize]).to_uppercase();
                if s.contains("VMWARE") || s.contains("VBOX") || s.contains("VIRTUAL") || s.contains("QEMU") {
                    unsafe { let _ = RegCloseKey(key_handle); }
                    return true;
                }
            }
        }
        unsafe { let _ = RegCloseKey(key_handle); }
    }
    false
}

/// Central is_virtualized function.
pub fn is_virtualized() -> bool {
    let mut checks: Vec<fn() -> bool> = vec![
        check_rdtsc_advanced,
        check_mouse_behavior,
        check_sandbox_environment,
        check_system32_footprint,
        check_device_files,
        check_hardware_fingerprint,
        check_registry_artifacts,
    ];

    let mut rng = rand::thread_rng();
    checks.shuffle(&mut rng);

    for check in checks {
        if check() {
            return true;
        }
        thread::sleep(Duration::from_millis(rng.gen_range(100..500)));
    }

    false
}
