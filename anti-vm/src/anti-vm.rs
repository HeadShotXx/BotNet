#![cfg(windows)]

use rand::seq::SliceRandom;
use rand::Rng;
use raw_cpuid::CpuId;
use std::ffi::c_void;
use std::thread;
use std::time::{Duration};
use windows::core::{HSTRING, PCWSTR};
use windows::Win32::Foundation::{GENERIC_READ};
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
use windows::Win32::System::IO::DeviceIoControl;
use windows::Win32::System::Ioctl::{
    IOCTL_STORAGE_QUERY_PROPERTY, STORAGE_PROPERTY_QUERY, StorageDeviceProperty,
    PropertyStandardQuery, STORAGE_DEVICE_DESCRIPTOR,
};

/// Weights for the scoring system.
const WEIGHT_RDTSC: u32 = 25;
const WEIGHT_TSC_DRIFT: u32 = 15;
const WEIGHT_EXCEPTION_LATENCY: u32 = 15;
const WEIGHT_ACPI: u32 = 45;
const WEIGHT_SMBIOS: u32 = 45;
const WEIGHT_DEVICE_FILES: u32 = 50;
const WEIGHT_VMWARE_PORT: u32 = 55;
const WEIGHT_DISK_FINGERPRINT: u32 = 40;
const WEIGHT_HYPERVISOR_SIG: u32 = 50;
const WEIGHT_SANDBOX_ENV: u32 = 30;
const WEIGHT_HARDWARE_FINGERPRINT: u32 = 10;
const WEIGHT_MOUSE_BEHAVIOR: u32 = 5;
const WEIGHT_SYSTEM32_FOOTPRINT: u32 = 10;

const THRESHOLD_VIRTUALIZED: u32 = 60;

fn get_median(mut samples: [u64; 50]) -> u64 {
    samples.sort_unstable();
    samples[25]
}

/// 1. Advanced RDTSC timing analysis.
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub fn check_rdtsc_advanced() -> bool {
    #[cfg(target_arch = "x86_64")]
    use std::arch::x86_64::{_mm_lfence, _rdtsc};
    #[cfg(target_arch = "x86")]
    use std::arch::x86::{_mm_lfence, _rdtsc};
    let mut cpuid_samples = [0u64; 50];
    let mut nop_samples = [0u64; 50];
    let cpuid_wrapper = CpuId::new();
    for i in 0..50 {
        unsafe {
            _mm_lfence(); let t1 = _rdtsc(); _mm_lfence();
            let _ = cpuid_wrapper.get_vendor_info();
            _mm_lfence(); let t2 = _rdtsc(); _mm_lfence();
            cpuid_samples[i] = t2 - t1;
            _mm_lfence(); let t3 = _rdtsc(); _mm_lfence();
            for _ in 0..10 { std::arch::asm!("nop"); }
            _mm_lfence(); let t4 = _rdtsc(); _mm_lfence();
            nop_samples[i] = t4 - t3;
        }
    }
    let median_cpuid = get_median(cpuid_samples);
    let median_nop = get_median(nop_samples);
    median_cpuid > 1200 || (median_cpuid / median_nop.max(1)) > 50
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
pub fn check_rdtsc_advanced() -> bool { false }

/// 2. VMware Backdoor Port Check.
pub fn check_vmware_port() -> bool {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        unsafe extern "system" fn handler(exception_info: *mut EXCEPTION_POINTERS) -> i32 {
            let context = (*exception_info).ContextRecord;
            #[cfg(target_arch = "x86_64")] { (*context).Rip += 1; }
            #[cfg(target_arch = "x86")] { (*context).Eip += 1; }
            -1
        }
        let mut is_vmware = false;
        unsafe {
            let h = AddVectoredExceptionHandler(1, Some(handler));
            if h.is_null() { return false; }
            let mut ebx_val: u64 = 0;
            std::arch::asm!(
                "push rbx",
                "mov eax, 0x564D5868",
                "mov ebx, 0x0",
                "mov ecx, 0xA",
                "mov edx, 0x5658",
                "in eax, dx",
                "mov {0}, rbx",
                "pop rbx",
                out(reg) ebx_val,
                out("eax") _,
                out("ecx") _,
                out("edx") _,
            );
            if ebx_val == 0x564D5868 { is_vmware = true; }
            RemoveVectoredExceptionHandler(h);
        }
        is_vmware
    }
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    { false }
}

/// 3. Disk Fingerprinting.
pub fn check_disk_fingerprint() -> bool {
    let h_drive = unsafe {
        CreateFileW(&HSTRING::from("\\\\.\\PhysicalDrive0"), 0, FILE_SHARE_READ | FILE_SHARE_WRITE, None, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, None)
    };
    if let Ok(handle) = h_drive {
        if !handle.is_invalid() {
            let query = STORAGE_PROPERTY_QUERY { PropertyId: StorageDeviceProperty, QueryType: PropertyStandardQuery, AdditionalParameters: [0; 1] };
            let mut descriptor = vec![0u8; 1024];
            let mut bytes_returned = 0u32;
            let success = unsafe {
                DeviceIoControl(handle, IOCTL_STORAGE_QUERY_PROPERTY, Some(&query as *const _ as *const c_void), std::mem::size_of::<STORAGE_PROPERTY_QUERY>() as u32, Some(descriptor.as_mut_ptr() as *mut c_void), descriptor.len() as u32, Some(&mut bytes_returned), None)
            };
            unsafe { let _ = windows::Win32::Foundation::CloseHandle(handle); }
            if success.is_ok() {
                let dev_desc = unsafe { &*(descriptor.as_ptr() as *const STORAGE_DEVICE_DESCRIPTOR) };
                if dev_desc.ProductIdOffset != 0 {
                    let product_id = unsafe { std::ffi::CStr::from_ptr(descriptor.as_ptr().add(dev_desc.ProductIdOffset as usize) as *const i8) }.to_string_lossy().to_uppercase();
                    if product_id.contains("VMWARE") || product_id.contains("VBOX") || product_id.contains("VIRTUAL") || product_id.contains("QEMU") || product_id.contains("VIRTIO") {
                        return true;
                    }
                }
            }
        }
    }
    false
}

/// 4. Hypervisor-specific CPUID Leaf Checks.
pub fn check_hypervisor_signature() -> bool {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        let mut ebx: u32 = 0; let mut ecx: u32 = 0; let mut edx: u32 = 0;
        unsafe {
            std::arch::asm!(
                "push rbx",
                "mov eax, 0x40000000",
                "cpuid",
                "mov {0:e}, ebx",
                "pop rbx",
                out(reg) ebx,
                out("eax") _,
                out("ecx") ecx,
                out("edx") edx,
            );
        }
        let mut signature = [0u8; 12];
        signature[0..4].copy_from_slice(&ebx.to_le_bytes());
        signature[4..8].copy_from_slice(&ecx.to_le_bytes());
        signature[8..12].copy_from_slice(&edx.to_le_bytes());
        let sig_str = String::from_utf8_lossy(&signature).to_uppercase();
        let vm_sigs = ["VMWARE", "MICROSOFT HV", "KVMKVMKVM", "XENVMMXENVMM", "VBOXVBOXVBOX"];
        for sig in &vm_sigs {
            if sig_str.contains(sig) { return true; }
        }
    }
    false
}

/// 5. TSC vs. QPC Drift Analysis.
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub fn check_tsc_drift() -> bool {
    #[cfg(target_arch = "x86_64")]
    use std::arch::x86_64::{_mm_lfence, _rdtsc};
    #[cfg(target_arch = "x86")]
    use std::arch::x86::{_mm_lfence, _rdtsc};
    let mut qpc_freq = 0i64;
    unsafe { let _ = QueryPerformanceFrequency(&mut qpc_freq); }
    if qpc_freq == 0 { return false; }
    let mut qpc1 = 0i64; let mut qpc2 = 0i64;
    unsafe {
        _mm_lfence(); let _ = QueryPerformanceCounter(&mut qpc1); let t1 = _rdtsc(); _mm_lfence();
        thread::sleep(Duration::from_millis(200));
        _mm_lfence(); let _ = QueryPerformanceCounter(&mut qpc2); let t2 = _rdtsc(); _mm_lfence();
        let tsc_diff = t2 - t1;
        let qpc_diff = (qpc2 - qpc1) as f64 / qpc_freq as f64;
        let tsc_freq = tsc_diff as f64 / qpc_diff;
        tsc_freq < 0.4e9 || tsc_freq > 8.0e9
    }
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
pub fn check_tsc_drift() -> bool { false }

/// 6. Exception Handling Latency Check.
pub fn check_exception_latency() -> bool {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        #[cfg(target_arch = "x86_64")]
        use std::arch::x86_64::{_mm_lfence, _rdtsc};
        #[cfg(target_arch = "x86")]
        use std::arch::x86::{_mm_lfence, _rdtsc};
        unsafe extern "system" fn handler(exception_info: *mut EXCEPTION_POINTERS) -> i32 {
            let context = (*exception_info).ContextRecord;
            #[cfg(target_arch = "x86_64")] { (*context).Rip += 2; }
            #[cfg(target_arch = "x86")] { (*context).Eip += 2; }
            -1
        }
        let mut samples = [0u64; 10];
        unsafe {
            let h = AddVectoredExceptionHandler(1, Some(handler));
            if h.is_null() { return false; }
            for i in 0..10 {
                _mm_lfence(); let t1 = _rdtsc(); _mm_lfence();
                std::arch::asm!("ud2");
                _mm_lfence(); let t2 = _rdtsc(); _mm_lfence();
                samples[i] = t2 - t1;
            }
            RemoveVectoredExceptionHandler(h);
        }
        let mut sorted = samples.to_vec();
        sorted.sort_unstable();
        sorted[5] > 150_000
    }
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    { false }
}

/// 2. ACPI Table Detection.
pub fn check_acpi_tables() -> bool {
    const ACPI_SIGN: FIRMWARE_TABLE_PROVIDER = FIRMWARE_TABLE_PROVIDER(u32::from_be_bytes(*b"ACPI"));
    let mut buffer_size = unsafe { EnumSystemFirmwareTables(ACPI_SIGN, None) };
    if buffer_size == 0 { return false; }
    let mut buffer = vec![0u8; buffer_size as usize];
    buffer_size = unsafe { EnumSystemFirmwareTables(ACPI_SIGN, Some(&mut buffer)) };
    let num_tables = buffer_size as usize / 4;
    for i in 0..num_tables {
        let table_id = u32::from_ne_bytes([buffer[i*4], buffer[i*4+1], buffer[i*4+2], buffer[i*4+3]]);
        if table_id == u32::from_be_bytes(*b"WAET") { return true; }
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
    const RSMB_SIGN: FIRMWARE_TABLE_PROVIDER = FIRMWARE_TABLE_PROVIDER(u32::from_be_bytes(*b"RSMB"));
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
        } else { String::new() }
    };
    let sandbox_strings = ["WDAGUtilityAccount", "SANDBOX", "VXPBOX", "CUCKOO"];
    for s in &sandbox_strings {
        if username.contains(&s.to_uppercase()) { return true; }
    }
    false
}

/// 2. Check for minimalist environment.
pub fn check_system32_footprint() -> bool {
    if let Ok(entries) = std::fs::read_dir("C:\\Windows\\System32") {
        let count = entries.take(1000).count();
        return count < 400;
    }
    false
}

/// 3. Device file checks for VMs.
pub fn check_device_files() -> bool {
    let devices = ["\\\\.\\VBoxGuest", "\\\\.\\VBoxPipe", "\\\\.\\HGFS", "\\\\.\\vmci"];
    for dev in &devices {
        let h_file = unsafe {
            CreateFileW(&HSTRING::from(*dev), GENERIC_READ.0, FILE_SHARE_READ | FILE_SHARE_WRITE, None, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, None)
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

/// 4. Hardware fingerprinting.
pub fn check_hardware_fingerprint() -> bool {
    let width = unsafe { GetSystemMetrics(SM_CXSCREEN) };
    let height = unsafe { GetSystemMetrics(SM_CYSCREEN) };
    let mut sys_info = SYSTEM_INFO::default();
    unsafe { GetSystemInfo(&mut sys_info); }
    let mut mem_status = MEMORYSTATUSEX::default();
    mem_status.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
    let mut total_disk: u64 = 0;
    unsafe {
        let _ = GlobalMemoryStatusEx(&mut mem_status);
        let _ = GetDiskFreeSpaceExW(&HSTRING::from("C:\\"), None, Some(&mut total_disk), None);
    }
    let mut points = 0;
    if (width > 0 && width <= 1024 && height > 0 && height <= 768) || (width == 800 && height == 600) { points += 1; }
    if sys_info.dwNumberOfProcessors < 2 { points += 1; }
    if mem_status.ullTotalPhys < (2 * 1024 * 1024 * 1024) { points += 1; }
    if total_disk < (60 * 1024 * 1024 * 1024) { points += 1; }
    points >= 3
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
        ("VMware Port", check_vmware_port, WEIGHT_VMWARE_PORT),
        ("Disk Fingerprint", check_disk_fingerprint, WEIGHT_DISK_FINGERPRINT),
        ("Hypervisor Sig", check_hypervisor_signature, WEIGHT_HYPERVISOR_SIG),
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
        if check_fn() { score += weight; }
        if score >= THRESHOLD_VIRTUALIZED { return true; }
        thread::sleep(Duration::from_millis(rng.gen_range(50..200)));
    }
    score >= THRESHOLD_VIRTUALIZED
}
