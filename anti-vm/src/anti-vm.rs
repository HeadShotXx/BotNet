use rand::seq::SliceRandom;
use rand::Rng;
use raw_cpuid::CpuId;
use std::ffi::c_void;
use std::thread;
use std::time::Duration;
use windows::core::{HSTRING, PCWSTR};
use windows::Win32::Devices::DeviceAndDriverInstallation::{
    SetupDiEnumDeviceInfo, SetupDiGetClassDevsW, SetupDiGetDeviceRegistryPropertyW, DIGCF_ALLCLASSES,
    SPDRP_DEVICEDESC, SP_DEVINFO_DATA,
};
use windows::Win32::Foundation::{ERROR_SUCCESS, HWND};
use windows::Win32::Graphics::Gdi::{EnumDisplayDevicesW, DISPLAY_DEVICEW};
use windows::Win32::NetworkManagement::IpHelper::{
    GetAdaptersAddresses, GAA_FLAG_INCLUDE_PREFIX, IP_ADAPTER_ADDRESSES_LH,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Registry::{
    RegCloseKey, RegGetValueW, RegOpenKeyExW, HKEY, HKEY_LOCAL_MACHINE, KEY_READ, RRF_RT_REG_SZ,
};
use windows::Win32::System::SystemInformation::{
    GlobalMemoryStatusEx, MEMORYSTATUSEX, GetTickCount64,
};
use windows::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;

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

/// 2a. CPUID-based hypervisor detection.
pub fn check_cpuid_hypervisor() -> bool {
    let cpuid = CpuId::new();
    if let Some(hypervisor_info) = cpuid.get_hypervisor_info() {
        match hypervisor_info.identify() {
            raw_cpuid::Hypervisor::VMware
            | raw_cpuid::Hypervisor::KVM
            | raw_cpuid::Hypervisor::HyperV
            | raw_cpuid::Hypervisor::Xen
            | raw_cpuid::Hypervisor::QEMU => true,
            raw_cpuid::Hypervisor::Unknown(ebx, ecx, edx) => {
                let mut vendor_id: [u8; 12] = [0; 12];
                vendor_id[0..4].copy_from_slice(&ebx.to_le_bytes());
                vendor_id[4..8].copy_from_slice(&ecx.to_le_bytes());
                vendor_id[8..12].copy_from_slice(&edx.to_le_bytes());

                let vendor = std::str::from_utf8(&vendor_id).unwrap_or("").trim().to_lowercase();

                // VBoxVBoxVBox
                let vbox_vendor = deobf(&[32, 15, 48, 28, 19, 54, 42, 27, 2, 43, 32, 22]).to_lowercase();
                // prl hyperv
                let prl_vendor = deobf(&[6, 63, 51, 68, 45, 13, 53, 6, 38, 31]).to_lowercase();

                vendor == vbox_vendor || vendor == prl_vendor
            }
            _ => false,
        }
    } else {
        if let Some(features) = cpuid.get_feature_info() {
            features.has_hypervisor()
        } else {
            false
        }
    }
}

/// 2a. Hardware characteristic checks: RAM size.
pub fn check_memory_size() -> bool {
    let mut mem_status = MEMORYSTATUSEX::default();
    mem_status.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
    if unsafe { GlobalMemoryStatusEx(&mut mem_status).is_ok() } {
        mem_status.ullTotalPhys < (4 * 1024 * 1024 * 1024)
    } else {
        false
    }
}

/// 2a. Hardware characteristic checks: MAC addresses.
pub fn check_mac_address() -> bool {
    let vm_mac_prefixes = [
        [0x00, 0x05, 0x69], // VMware
        [0x00, 0x0C, 0x29], // VMware
        [0x00, 0x1C, 0x14], // VMware
        [0x00, 0x50, 0x56], // VMware
        [0x08, 0x00, 0x27], // VirtualBox
        [0x00, 0x1C, 0x42], // Parallels
        [0x52, 0x54, 0x00], // QEMU/KVM
        [0x00, 0x15, 0x5D], // Hyper-V
    ];
    let mut buffer_size: u32 = 0;
    unsafe {
        let _ = GetAdaptersAddresses(
            0,
            GAA_FLAG_INCLUDE_PREFIX,
            Some(std::ptr::null_mut()),
            Some(std::ptr::null_mut()),
            &mut buffer_size,
        );
    }
    if buffer_size == 0 {
        return false;
    }
    let mut buffer: Vec<u8> = vec![0; buffer_size as usize];
    let adapter_addresses = buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH;
    if unsafe {
        GetAdaptersAddresses(
            0,
            GAA_FLAG_INCLUDE_PREFIX,
            Some(std::ptr::null_mut()),
            Some(adapter_addresses),
            &mut buffer_size,
        )
    } == ERROR_SUCCESS.0 as u32
    {
        let mut current_adapter = adapter_addresses;
        while !current_adapter.is_null() {
            let address = unsafe { (*current_adapter).PhysicalAddress };
            let address_length = unsafe { (*current_adapter).PhysicalAddressLength };
            if address_length >= 3 {
                for prefix in &vm_mac_prefixes {
                    if address[0..3] == *prefix {
                        return true;
                    }
                }
            }
            current_adapter = unsafe { (*current_adapter).Next };
        }
    }
    false
}

/// 2a. Hardware characteristic checks: Disk size.
pub fn check_disk_size() -> bool {
    let mut total_bytes: u64 = 0;
    let root_path = HSTRING::from(deobf(&[53, 119, 3])); // "C:\"
    if unsafe {
        GetDiskFreeSpaceExW(
            &root_path,
            Some(std::ptr::null_mut()),
            Some(&mut total_bytes),
            Some(std::ptr::null_mut()),
        )
    }
    .is_ok()
    {
        total_bytes < (100 * 1024 * 1024 * 1024)
    } else {
        false
    }
}

/// 2b. Registry and file-system artifacts: BIOS strings.
pub fn check_bios() -> bool {
    let vm_bios_strings = [
        deobf(&[32, 0, 40, 5, 55, 17]).to_lowercase(), // "VMware"
        deobf(&[32, 36, 45, 16, 48, 21, 41, 33, 59, 17]).to_lowercase(), // "VirtualBox"
        deobf(&[39, 8, 18, 49]).to_lowercase(), // "QEMU"
        deobf(&[62, 52, 47, 1, 55, 89, 19]).to_lowercase(), // "Hyper-V"
        deobf(&[38, 44, 45, 5, 41, 24, 32, 15, 39]).to_lowercase(), // "Parallels"
        deobf(&[46, 40, 49]).to_lowercase(), // "Xen"
    ];

    let bios_key_path = HSTRING::from(deobf(&[62, 12, 13, 32, 18, 53, 23, 38, 8, 45, 10, 61, 28, 25, 44, 9, 11, 123, 127, 124, 104, 37, 52, 44, 16, 32, 25, 25, 33, 29, 38, 28])); // "HARDWARE\DESCRIPTION\System\BIOS"

    let mut key_handle: HKEY = HKEY(0);
    if unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, &bios_key_path, 0, KEY_READ, &mut key_handle) }.is_err() {
        return false;
    }

    let values_to_check = [
        HSTRING::from(deobf(&[52, 4, 16, 55, 19, 17, 43, 7, 59, 27])), // "BIOSVendor"
        HSTRING::from(deobf(&[37, 52, 44, 16, 32, 25, 8, 2, 58, 28, 41, 15, 60, 63, 16, 43, 58, 64])), // "SystemManufacturer"
        HSTRING::from(deobf(&[37, 52, 44, 16, 32, 25, 21, 17, 59, 13, 58, 13, 43, 5, 4, 52, 58])), // "SystemProductName"
    ];

    for value_name in &values_to_check {
        let mut buffer: [u16; 1024] = [0; 1024];
        let mut buffer_size = (buffer.len() * 2) as u32;
        if unsafe {
            RegGetValueW(
                key_handle,
                PCWSTR::null(),
                value_name,
                RRF_RT_REG_SZ,
                Some(std::ptr::null_mut()),
                Some(buffer.as_mut_ptr() as *mut c_void),
                Some(&mut buffer_size),
            )
        } == ERROR_SUCCESS
        {
            let value = String::from_utf16_lossy(&buffer[..(buffer_size / 2) as usize - 1]).to_lowercase();
            for vm_string in &vm_bios_strings {
                if value.contains(vm_string) {
                    unsafe { let _ = RegCloseKey(key_handle); };
                    return true;
                }
            }
        }
    }
    unsafe { let _ = RegCloseKey(key_handle); };
    false
}

/// 2c. Advanced checks: Timing attacks (RDTSC latency).
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub fn check_rdtsc_timing() -> bool {
    use std::arch::x86_64::_rdtsc;
    const SAMPLES: u32 = 10;
    const THRESHOLD: u64 = 1000;
    let mut total_diff: u64 = 0;
    for _ in 0..SAMPLES {
        let t1 = unsafe { _rdtsc() };
        let _ = CpuId::new();
        let t2 = unsafe { _rdtsc() };
        let diff = t2 - t1;
        total_diff += diff;
    }
    let avg_diff = total_diff / SAMPLES as u64;
    avg_diff > THRESHOLD
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
pub fn check_rdtsc_timing() -> bool {
    false
}

/// 2c. Advanced checks: Sandbox-specific artifacts (Processes).
pub fn check_sandbox_processes() -> bool {
    let sandbox_processes = [
        deobf(&[0, 32, 43, 11, 42, 24, 54, 7, 122, 12, 55, 11]).to_lowercase(), // "vmtoolsd.exe"
        deobf(&[0, 47, 48, 28, 54, 17, 55, 21, 61, 10, 42, 64, 58, 51, 0]).to_lowercase(), // "vboxservice.exe"
        deobf(&[28, 34, 58, 6, 42, 12, 54, 6, 38, 31, 42, 28, 113, 46, 29, 60]).to_lowercase(), // "joeboxserver.exe"
        deobf(&[28, 34, 58, 6, 42, 12, 38, 12, 58, 29, 61, 1, 51, 101, 0, 33, 58]).to_lowercase(), // "joeboxcontrol.exe"
        deobf(&[6, 63, 48, 7, 40, 27, 43, 77, 49, 17, 42]).to_lowercase(), // "procmon.exe"
        deobf(&[1, 36, 45, 1, 54, 28, 36, 17, 63, 71, 42, 22, 58]).to_lowercase(), // "wireshark.exe"
    ];

    if let Ok(snapshot) = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) } {
        if snapshot.is_invalid() {
            return false
        }
        let mut process_entry = PROCESSENTRY32W::default();
        process_entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        if unsafe { Process32FirstW(snapshot, &mut process_entry) }.is_ok() {
            loop {
                let process_name = String::from_utf16_lossy(&process_entry.szExeFile);
                let trimmed_name = process_name.trim_end_matches('\0').to_lowercase();
                for sb_process in &sandbox_processes {
                    if trimmed_name == *sb_process {
                        return true;
                    }
                }
                if unsafe { Process32NextW(snapshot, &mut process_entry) }.is_err() {
                    break;
                }
            }
        }
    }
    false
}

/// 2c. Advanced checks: System Uptime.
pub fn check_uptime() -> bool {
    let uptime_ms = unsafe { GetTickCount64() };
    uptime_ms < (10 * 60 * 1000)
}

/// 2c. Advanced checks: Thermal Information.
pub fn check_thermal_info() -> bool {
    let thermal_path = HSTRING::from(deobf(&[37, 20, 12, 48, 0, 57, 25, 32, 33, 27, 61, 11, 49, 63, 38, 54, 49, 70, 66, 93, 88, 37, 40, 43, 56, 6, 27, 43, 23, 38, 6, 35, 50, 11, 35, 0, 43, 50, 83, 92])); // "SYSTEM\CurrentControlSet\Control\Thermal"

    let mut key_handle: HKEY = HKEY(0);
    let result = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            &thermal_path,
            0,
            KEY_READ,
            &mut key_handle,
        )
    };
    if result.is_err() {
        return true;
    }
    unsafe { let _ = RegCloseKey(key_handle); };
    false
}

/// Advanced check: Display adapter.
pub fn check_display_adapter() -> bool {
    let vm_adapters = [
        deobf(&[32, 0, 40, 5, 55, 17]).to_lowercase(), // "VMware"
        deobf(&[32, 36, 45, 16, 48, 21, 41, 33, 59, 17]).to_lowercase(), // "VirtualBox"
    ];

    let mut device = DISPLAY_DEVICEW::default();
    device.cb = std::mem::size_of::<DISPLAY_DEVICEW>() as u32;
    let mut i = 0;
    while unsafe { EnumDisplayDevicesW(PCWSTR::null(), i, &mut device, 0) }.as_bool() {
        let device_string = String::from_utf16_lossy(&device.DeviceString).to_lowercase();
        for vm_adapter in &vm_adapters {
            if device_string.contains(vm_adapter) {
                return true;
            }
        }
        i += 1;
    }
    false
}

/// Advanced check: PCI Devices.
pub fn check_pci_devices() -> bool {
    let vm_pci_devices = [
        deobf(&[32, 0, 40, 5, 55, 17]).to_lowercase(), // "VMware"
        deobf(&[32, 36, 45, 16, 48, 21, 41, 33, 59, 17]).to_lowercase(), // "VirtualBox"
    ];

    if let Ok(device_info_set) = unsafe { SetupDiGetClassDevsW(None, PCWSTR::null(), HWND::default(), DIGCF_ALLCLASSES) }{
        if device_info_set.is_invalid() {
            return false;
        }
        let mut device_info_data = SP_DEVINFO_DATA::default();
        device_info_data.cbSize = std::mem::size_of::<SP_DEVINFO_DATA>() as u32;
        let mut i = 0;
        while unsafe { SetupDiEnumDeviceInfo(device_info_set, i, &mut device_info_data) }.is_ok() {
            let mut buffer: [u16; 1024] = [0; 1024];
            let mut required_size = 0;
            let byte_buffer: &mut [u8] = unsafe { std::slice::from_raw_parts_mut(buffer.as_mut_ptr() as *mut u8, buffer.len() * 2) };

            if unsafe { SetupDiGetDeviceRegistryPropertyW(
                device_info_set,
                &device_info_data,
                SPDRP_DEVICEDESC,
                None,
                Some(byte_buffer),
                Some(&mut required_size)
            ) }.is_ok() {
                let desc = String::from_utf16_lossy(&buffer[..(required_size / 2) as usize -1]).to_lowercase();
                for vm_device in &vm_pci_devices {
                    if desc.contains(vm_device) {
                        return true;
                    }
                }
            }
            i += 1;
        }
    }
    false
}

/// 2e. Central is_virtualized() function.
pub fn is_virtualized() -> bool {
    let mut checks: Vec<fn() -> bool> = vec![
        check_cpuid_hypervisor,
        check_mac_address,
        check_bios,
        check_memory_size,
        check_disk_size,
        check_rdtsc_timing,
        check_sandbox_processes,
        check_uptime,
        check_thermal_info,
        check_display_adapter,
        check_pci_devices,
    ];

    let mut rng = rand::thread_rng();
    checks.shuffle(&mut rng);

    for check in checks {
        if check() {
            return true;
        }
        let delay = rng.gen_range(100..=500);
        thread::sleep(Duration::from_millis(delay));
    }

    false
}
