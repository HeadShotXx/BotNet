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
    GlobalMemoryStatusEx, MEMORYSTATUSEX, GetSystemInfo, SYSTEM_INFO, EnumSystemFirmwareTables, GetSystemFirmwareTable, FIRMWARE_TABLE_PROVIDER,
};
use windows::Win32::System::WindowsProgramming::GetUserNameW;
use windows::Win32::Storage::FileSystem::{
    GetDiskFreeSpaceExW, CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_ATTRIBUTE_NORMAL,
    OPEN_EXISTING,
};
use windows::Win32::UI::WindowsAndMessaging::{GetCursorPos, GetSystemMetrics, SM_CXSCREEN, SM_CYSCREEN};
use windows::Win32::System::Performance::{QueryPerformanceCounter, QueryPerformanceFrequency};
use windows::Win32::System::Diagnostics::Debug::{AddVectoredExceptionHandler, RemoveVectoredExceptionHandler, EXCEPTION_POINTERS};

/// Weights for the scoring system.
const WEIGHT_RDTSC: u32 = 20;
const WEIGHT_TSC_DRIFT: u32 = 25;
const WEIGHT_EXCEPTION_LATENCY: u32 = 20;
const WEIGHT_ACPI: u32 = 30;
const WEIGHT_SMBIOS: u32 = 30;
const WEIGHT_DEVICE_FILES: u32 = 35;
const WEIGHT_SANDBOX_ENV: u32 = 15;
const WEIGHT_HARDWARE_FINGERPRINT: u32 = 10;
const WEIGHT_MOUSE_BEHAVIOR: u32 = 10;
const WEIGHT_SYSTEM32_FOOTPRINT: u32 = 10;

const THRESHOLD_VIRTUALIZED: u32 = 50;

/// 1. Advanced RDTSC timing analysis.
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub fn check_rdtsc_advanced() -> bool {
    #[cfg(target_arch = "x86_64")]
    use std::arch::x86_64::{_mm_lfence, _rdtsc};
    #[cfg(target_arch = "x86")]
    use std::arch::x86::{_mm_lfence, _rdtsc};

    let mut cpuid_samples = [0u64; 50];
    let mut nop_samples = [0u64; 50];
    let cpuid = CpuId::new();

    for i in 0..50 {
        unsafe {
            _mm_lfence();
            let t1 = _rdtsc();
            _mm_lfence();
            let _ = cpuid.get_vendor_info();
            _mm_lfence();
            let t2 = _rdtsc();
            _mm_lfence();
            cpuid_samples[i] = t2 - t1;

            _mm_lfence();
            let t3 = _rdtsc();
            _mm_lfence();
            for _ in 0..10 { std::arch::asm!("nop"); }
            _mm_lfence();
            let t4 = _rdtsc();
            _mm_lfence();
            nop_samples[i] = t4 - t3;
        }
    }

    let avg_cpuid = cpuid_samples.iter().sum::<u64>() / 50;
    let avg_nop = nop_samples.iter().sum::<u64>() / 50;

    avg_cpuid > 1000 || (avg_cpuid / avg_nop.max(1)) > 40
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
pub fn check_rdtsc_advanced() -> bool {
    false
}

/// 4. TSC vs. QPC Drift Analysis.
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub fn check_tsc_drift() -> bool {
    #[cfg(target_arch = "x86_64")]
    use std::arch::x86_64::{_mm_lfence, _rdtsc};
    #[cfg(target_arch = "x86")]
    use std::arch::x86::{_mm_lfence, _rdtsc};

    let mut qpc_freq = 0i64;
    unsafe { let _ = QueryPerformanceFrequency(&mut qpc_freq); }
    if qpc_freq == 0 { return false; }

    let mut qpc1 = 0i64;
    let mut qpc2 = 0i64;
    unsafe {
        _mm_lfence();
        let _ = QueryPerformanceCounter(&mut qpc1);
        let t1 = _rdtsc();
        _mm_lfence();
        thread::sleep(Duration::from_millis(100));
        _mm_lfence();
        let _ = QueryPerformanceCounter(&mut qpc2);
        let t2 = _rdtsc();
        _mm_lfence();
        let tsc_diff = t2 - t1;
        let qpc_diff = (qpc2 - qpc1) as f64 / qpc_freq as f64;
        let tsc_freq = tsc_diff as f64 / qpc_diff;
        tsc_freq < 1.5e9 || tsc_freq > 5.5e9
    }
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
pub fn check_tsc_drift() -> bool {
    false
}

/// 5. Exception Handling Latency Check.
pub fn check_exception_latency() -> bool {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        #[cfg(target_arch = "x86_64")]
        use std::arch::x86_64::{_mm_lfence, _rdtsc};
        #[cfg(target_arch = "x86")]
        use std::arch::x86::{_mm_lfence, _rdtsc};

        unsafe extern "system" fn handler(exception_info: *mut EXCEPTION_POINTERS) -> i32 {
            let context = (*exception_info).ContextRecord;
            #[cfg(target_arch = "x86_64")]
            {
                (*context).Rip += 2;
            }
            #[cfg(target_arch = "x86")]
            {
                (*context).Eip += 2;
            }
            -1
        }

        unsafe {
            let h = AddVectoredExceptionHandler(1, Some(handler));
            if h.is_null() { return false; }

            _mm_lfence();
            let t1 = _rdtsc();
            _mm_lfence();
            std::arch::asm!("ud2");
            _mm_lfence();
            let t2 = _rdtsc();
            _mm_lfence();

            RemoveVectoredExceptionHandler(h);
            (t2 - t1) > 100_000
        }
    }
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    { false }
}

/// 2. ACPI Table Detection.
pub fn check_acpi_tables() -> bool {
    const ACPI_SIGN: FIRMWARE_TABLE_PROVIDER = FIRMWARE_TABLE_PROVIDER(0x41435049); // 'ACPI'
    let mut buffer_size = unsafe { EnumSystemFirmwareTables(ACPI_SIGN, None) };
    if buffer_size == 0 { return false; }
    let mut buffer = vec![0u8; buffer_size as usize];
    buffer_size = unsafe { EnumSystemFirmwareTables(ACPI_SIGN, Some(&mut buffer)) };
    let num_tables = buffer_size as usize / 4;
    for i in 0..num_tables {
        let table_id = u32::from_ne_bytes([buffer[i*4], buffer[i*4+1], buffer[i*4+2], buffer[i*4+3]]);
        let table_size = unsafe { GetSystemFirmwareTable(ACPI_SIGN, table_id, None) };
        if table_size > 0 {
            let mut table_data = vec![0u8; table_size as usize];
            unsafe { GetSystemFirmwareTable(ACPI_SIGN, table_id, Some(&mut table_data)); }
            let table_str = String::from_utf8_lossy(&table_data).to_uppercase();
            if table_str.contains("VMWARE") || table_str.contains("VBOX") || table_str.contains("BOCHS") || table_str.contains("QEMU") {
                return true;
            }
        }
    }
    false
}

/// 3. SMBIOS/DMI Deep Scanning.
pub fn check_smbios_data() -> bool {
    const RSMB_SIGN: FIRMWARE_TABLE_PROVIDER = FIRMWARE_TABLE_PROVIDER(0x52534D42); // 'RSMB'
    let buffer_size = unsafe { GetSystemFirmwareTable(RSMB_SIGN, 0, None) };
    if buffer_size == 0 { return false; }
    let mut buffer = vec![0u8; buffer_size as usize];
    unsafe { GetSystemFirmwareTable(RSMB_SIGN, 0, Some(&mut buffer)); }
    let data_str = String::from_utf8_lossy(&buffer).to_uppercase();
    let vm_indicators = ["VMWARE", "VIRTUALBOX", "VBOX", "QEMU", "XEN", "PARALLELS", "KVM", "HYPER-V"];
    for indicator in &vm_indicators {
        if data_str.contains(indicator) {
            return true;
        }
    }
    false
}

/// 2. Mouse movement monitor.
pub fn check_mouse_behavior() -> bool {
    let mut pos1 = windows::Win32::Foundation::POINT::default();
    let mut pos2 = windows::Win32::Foundation::POINT::default();
    unsafe { let _ = GetCursorPos(&mut pos1); }
    thread::sleep(Duration::from_millis(5000));
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
    let sandbox_strings = ["WDAGUtilityAccount", "SANDBOX", "VXPBOX", "CUCKOO"];
    for s in &sandbox_strings {
        if username.contains(&s.to_uppercase()) {
            return true;
        }
    }
    false
}

/// 2. Check for minimalist environment (file count in System32).
pub fn check_system32_footprint() -> bool {
    let sys32_path = "C:\\Windows\\System32";
    if let Ok(entries) = std::fs::read_dir(sys32_path) {
        let count = entries.take(500).count();
        return count < 300;
    }
    false
}

/// 3. Device file checks for VMs.
pub fn check_device_files() -> bool {
    let devices = ["\\\\.\\VBoxGuest", "\\\\.\\VBoxPipe", "\\\\.\\HGFS", "\\\\.\\vmci"];
    for dev in &devices {
        let h_file: windows::core::Result<HANDLE> = unsafe {
            CreateFileW(
                &HSTRING::from(*dev),
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
    let mut sys_info = SYSTEM_INFO::default();
    unsafe { GetSystemInfo(&mut sys_info); }

    let mut mem_status = MEMORYSTATUSEX::default();
    mem_status.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
    let mut total_disk: u64 = 0;
    let root_path = HSTRING::from("C:\\");

    unsafe {
        let _ = GlobalMemoryStatusEx(&mut mem_status);
        let _ = GetDiskFreeSpaceExW(&root_path, Some(std::ptr::null_mut()), Some(&mut total_disk), Some(std::ptr::null_mut()));
    }

    let mut points = 0;
    if (width > 0 && width <= 1024 && height > 0 && height <= 768) || (width == 800 && height == 600) { points += 1; }
    if sys_info.dwNumberOfProcessors < 2 { points += 1; }
    if mem_status.ullTotalPhys < (2 * 1024 * 1024 * 1024) { points += 1; }
    if total_disk < (60 * 1024 * 1024 * 1024) { points += 1; }

    points >= 2
}

/// 4. Enhanced artifact detection (Registry).
pub fn check_registry_artifacts() -> bool {
    let bios_key = HSTRING::from("HARDWARE\\DESCRIPTION\\System\\BIOS");
    let mut key_handle: HKEY = HKEY(0);
    if unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, &bios_key, 0, KEY_READ, &mut key_handle) }.is_ok() {
        let values = [HSTRING::from("BIOSVendor"), HSTRING::from("SystemManufacturer")];
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

/// Central is_virtualized function using a weighted scoring system.
pub fn is_virtualized() -> bool {
    let mut score = 0;

    let checks: Vec<(&str, fn() -> bool, u32)> = vec![
        ("RDTSC Timing", check_rdtsc_advanced, WEIGHT_RDTSC),
        ("TSC Drift", check_tsc_drift, WEIGHT_TSC_DRIFT),
        ("Exception Latency", check_exception_latency, WEIGHT_EXCEPTION_LATENCY),
        ("ACPI Tables", check_acpi_tables, WEIGHT_ACPI),
        ("SMBIOS Data", check_smbios_data, WEIGHT_SMBIOS),
        ("Mouse Behavior", check_mouse_behavior, WEIGHT_MOUSE_BEHAVIOR),
        ("Sandbox Env", check_sandbox_environment, WEIGHT_SANDBOX_ENV),
        ("System32 Footprint", check_system32_footprint, WEIGHT_SYSTEM32_FOOTPRINT),
        ("Device Files", check_device_files, WEIGHT_DEVICE_FILES),
        ("Hardware Fingerprint", check_hardware_fingerprint, WEIGHT_HARDWARE_FINGERPRINT),
        ("Registry Artifacts", check_registry_artifacts, WEIGHT_SMBIOS),
    ];

    let mut rng = rand::thread_rng();
    let mut indices: Vec<usize> = (0..checks.len()).collect();
    indices.shuffle(&mut rng);

    for i in indices {
        let (_name, check_fn, weight) = checks[i];
        if check_fn() {
            score += weight;
        }
        if score >= THRESHOLD_VIRTUALIZED {
            return true;
        }
        thread::sleep(Duration::from_millis(rng.gen_range(50..200)));
    }

    score >= THRESHOLD_VIRTUALIZED
}
