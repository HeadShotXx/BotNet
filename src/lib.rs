
mod utils;

use rand::seq::SliceRandom;
use rand::Rng;
use raw_cpuid::CpuId;
use std::ffi::c_void;
use std::path::Path;
use std::thread;
use std::time::Duration;
use windows::core::{HSTRING, PCWSTR};
use windows::Win32::Devices::DeviceAndDriverInstallation::{
    SetupDiEnumDeviceInfo, SetupDiGetClassDevsW, SetupDiGetDeviceRegistryPropertyW, DIGCF_ALLCLASSES,
    SPDRP_DEVICEDESC, SP_DEVINFO_DATA,
};
use windows::Win32::Foundation::{ERROR_SUCCESS, HWND, MAX_PATH};
use windows::Win32::Graphics::Gdi::{EnumDisplayDevicesW, DISPLAY_DEVICEW};
use windows::Win32::NetworkManagement::IpHelper::{
    GetAdaptersAddresses, GAA_FLAG_INCLUDE_PREFIX, IP_ADAPTER_ADDRESSES_LH,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::ProcessStatus::{EnumDeviceDrivers, GetDeviceDriverBaseNameW};
use windows::Win32::System::Registry::{
    RegCloseKey, RegGetValueW, RegOpenKeyExW, HKEY, HKEY_LOCAL_MACHINE, KEY_READ, RRF_RT_REG_SZ,
};
use windows::Win32::System::SystemInformation::{
    GetSystemInfo, GlobalMemoryStatusEx, MEMORYSTATUSEX, SYSTEM_INFO,
};
use windows::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;

const XOR_KEY: &[u8] = b"secretkey";

fn deobfuscate_string(obfuscated_data: &mut [u8]) -> String {
    utils::xor_obfuscate(obfuscated_data, XOR_KEY);
    String::from_utf8_lossy(obfuscated_data).to_string()
}

/// Checks for the presence of a hypervisor using the CPUID instruction.
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

                let mut vbox_vendor_id_obf = b"VBoxVBoxVBox".to_vec();
                utils::xor_obfuscate(&mut vbox_vendor_id_obf, XOR_KEY);
                let mut prl_vendor_id_obf = b"prl hyperv".to_vec();
                utils::xor_obfuscate(&mut prl_vendor_id_obf, XOR_KEY);

                let vendor = std::str::from_utf8(&vendor_id).unwrap_or("").trim();

                let deobfuscated_vbox = deobfuscate_string(&mut vbox_vendor_id_obf);
                let deobfuscated_prl = deobfuscate_string(&mut prl_vendor_id_obf);

                vendor == deobfuscated_vbox || vendor == deobfuscated_prl
            }
            _ => false,
        }
    } else {
        false
    }
}

/// Checks the total physical memory size.
pub fn check_memory_size() -> bool {
    let mut mem_status = MEMORYSTATUSEX::default();
    mem_status.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
    if unsafe { GlobalMemoryStatusEx(&mut mem_status).is_ok() } {
        let common_vm_sizes = [
            1 * 1024 * 1024 * 1024,
            2 * 1024 * 1024 * 1024,
            4 * 1024 * 1024 * 1024,
        ];
        common_vm_sizes.contains(&mem_status.ullTotalPhys)
    } else {
        false
    }
}

/// Checks for MAC addresses associated with virtual machines.
pub fn check_mac_address() -> bool {
    let vm_mac_prefixes = [
        [0x00, 0x05, 0x69], // VMware
        [0x00, 0x0C, 0x29], // VMware
        [0x00, 0x1C, 0x14], // VMware
        [0x00, 0x50, 0x56], // VMware
        [0x08, 0x00, 0x27], // VirtualBox
        [0x00, 0x1C, 0x42], // Parallels
        [0x52, 0x54, 0x00], // QEMU/KVM
    ];
    let mut buffer_size: u32 = 0;
    unsafe {
        GetAdaptersAddresses(
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

/// Checks the BIOS for strings commonly found in virtual machines.
pub fn check_bios() -> bool {
    let mut vm_bios_strings_obf: Vec<Vec<u8>> = vec![
        b"VMware".to_vec(), b"VirtualBox".to_vec(), b"QEMU".to_vec(),
        b"Hyper-V".to_vec(), b"Parallels".to_vec(), b"Xen".to_vec(),
    ];
    vm_bios_strings_obf.iter_mut().for_each(|s| utils::xor_obfuscate(s, XOR_KEY));

    let mut bios_key_path_obf = b"HARDWARE\\DESCRIPTION\\System\\BIOS".to_vec();
    utils::xor_obfuscate(&mut bios_key_path_obf, XOR_KEY);
    let bios_key_path = HSTRING::from(deobfuscate_string(&mut bios_key_path_obf));

    let mut key_handle: HKEY = HKEY(0);
    if unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, &bios_key_path, 0, KEY_READ, &mut key_handle) }.is_err() {
        return false;
    }

    let mut bios_vendor_obf = b"BIOSVendor".to_vec();
    utils::xor_obfuscate(&mut bios_vendor_obf, XOR_KEY);
    let bios_vendor_value = HSTRING::from(deobfuscate_string(&mut bios_vendor_obf));

    let mut system_manufacturer_obf = b"SystemManufacturer".to_vec();
    utils::xor_obfuscate(&mut system_manufacturer_obf, XOR_KEY);
    let system_manufacturer_value = HSTRING::from(deobfuscate_string(&mut system_manufacturer_obf));

    let mut system_product_name_obf = b"SystemProductName".to_vec();
    utils::xor_obfuscate(&mut system_product_name_obf, XOR_KEY);
    let system_product_name_value = HSTRING::from(deobfuscate_string(&mut system_product_name_obf));

    let values_to_check = [
        bios_vendor_value,
        system_manufacturer_value,
        system_product_name_value,
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
            let value = String::from_utf16_lossy(&buffer[..(buffer_size / 2) as usize - 1]);
            for vm_string_obf in &vm_bios_strings_obf {
                let mut temp_deobf = vm_string_obf.clone();
                let vm_string = deobfuscate_string(&mut temp_deobf);
                if value.contains(&vm_string) {
                    unsafe { let _ = RegCloseKey(key_handle); };
                    return true;
                }
            }
        }
    }
    unsafe { let _ = RegCloseKey(key_handle); };
    false
}

/// Checks the number of CPU cores.
pub fn check_cpu_cores() -> bool {
    let mut system_info = SYSTEM_INFO::default();
    unsafe { GetSystemInfo(&mut system_info) };
    matches!(system_info.dwNumberOfProcessors, 1 | 2)
}

/// Checks the disk drive size.
pub fn check_disk_size() -> bool {
    let mut total_bytes: u64 = 0;
    let mut root_path_obf = b"C:\\".to_vec();
    utils::xor_obfuscate(&mut root_path_obf, XOR_KEY);
    let root_path = HSTRING::from(deobfuscate_string(&mut root_path_obf));
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
        let common_vm_sizes = [
            60 * 1024 * 1024 * 1024,
            80 * 1024 * 1024 * 1024,
            100 * 1024 * 1024 * 1024,
        ];
        common_vm_sizes.contains(&total_bytes)
    } else {
        false
    }
}

/// Checks the display adapter name.
pub fn check_display_adapter() -> bool {
    let mut vm_adapters_obf: Vec<Vec<u8>> = vec![
        b"VMware SVGA".to_vec(), b"VirtualBox Graphics Adapter".to_vec(), b"Hyper-V Video".to_vec(),
        b"QEMU Standard VGA".to_vec(), b"Parallels Display Adapter".to_vec(),
    ];
    vm_adapters_obf.iter_mut().for_each(|s| utils::xor_obfuscate(s, XOR_KEY));

    let mut device = DISPLAY_DEVICEW::default();
    device.cb = std::mem::size_of::<DISPLAY_DEVICEW>() as u32;
    let mut i = 0;
    while unsafe { EnumDisplayDevicesW(PCWSTR::null(), i, &mut device, 0) }.as_bool() {
        let device_string = String::from_utf16_lossy(&device.DeviceString);
        for vm_adapter_obf in &vm_adapters_obf {
            let mut temp_deobf = vm_adapter_obf.clone();
            let vm_adapter = deobfuscate_string(&mut temp_deobf);
            if device_string.contains(&vm_adapter) {
                return true;
            }
        }
        i += 1;
    }
    false
}

/// Checks for virtual PCI devices.
pub fn check_pci_devices() -> bool {
    let mut vm_pci_devices_obf: Vec<Vec<u8>> = vec![
        b"VMware VMCI".to_vec(), b"VirtualBox Guest Service".to_vec(), b"Red Hat VirtIO".to_vec(),
    ];
    vm_pci_devices_obf.iter_mut().for_each(|s| utils::xor_obfuscate(s, XOR_KEY));
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
                let desc = String::from_utf16_lossy(&buffer[..(required_size / 2) as usize -1]);
                for vm_device_obf in &vm_pci_devices_obf {
                    let mut temp_deobf = vm_device_obf.clone();
                    let vm_device = deobfuscate_string(&mut temp_deobf);
                    if desc.contains(&vm_device) {
                        return true;
                    }
                }
            }
            i += 1;
        }
    }
    false
}

/// Checks for known virtual machine drivers.
pub fn check_drivers() -> bool {
    let mut vm_drivers_obf: Vec<Vec<u8>> = vec![
        b"virtio".to_vec(), b"vmxnet".to_vec(), b"pvscsi".to_vec(), b"vboxguest".to_vec(),
        b"vmware".to_vec(), b"vmusb".to_vec(), b"vmx86".to_vec(),
    ];
    vm_drivers_obf.iter_mut().for_each(|s| utils::xor_obfuscate(s, XOR_KEY));
    let mut drivers: [isize; 1024] = [0; 1024];
    let mut needed: u32 = 0;
    if unsafe { EnumDeviceDrivers(drivers.as_mut_ptr() as *mut *mut c_void, std::mem::size_of_val(&drivers) as u32, &mut needed) }.is_ok() {
        let num_drivers = needed as usize / std::mem::size_of::<isize>();
        for i in 0..num_drivers {
            let mut driver_name: [u16; MAX_PATH as usize] = [0; MAX_PATH as usize];
            let driver_name_len = unsafe { GetDeviceDriverBaseNameW(drivers[i] as *mut c_void, &mut driver_name) };
            if driver_name_len > 0 {
                let name = String::from_utf16_lossy(&driver_name[..driver_name_len as usize]);
                for vm_driver_obf in &vm_drivers_obf {
                    let mut temp_deobf = vm_driver_obf.clone();
                    let vm_driver = deobfuscate_string(&mut temp_deobf);
                    if name.to_lowercase().contains(&vm_driver) {
                        return true;
                    }
                }
            }
        }
    }
    false
}

/// Checks for registry keys associated with virtual machines.
pub fn check_vm_registry_keys() -> bool {
    let mut vm_keys_obf: Vec<Vec<u8>> = vec![
        b"SOFTWARE\\VMware, Inc.\\VMware Tools".to_vec(),
        b"SYSTEM\\CurrentControlSet\\Services\\VBoxGuest".to_vec(),
        b"SYSTEM\\CurrentControlSet\\Services\\VBoxMouse".to_vec(),
        b"SYSTEM\\CurrentControlSet\\Services\\VBoxSF".to_vec(),
        b"SYSTEM\\CurrentControlSet\\Services\\VBoxVideo".to_vec(),
    ];
    vm_keys_obf.iter_mut().for_each(|s| utils::xor_obfuscate(s, XOR_KEY));

    for key_path_obf in &vm_keys_obf {
        let mut temp_deobf = key_path_obf.clone();
        let subkey_hstring = HSTRING::from(deobfuscate_string(&mut temp_deobf));
        let mut key_handle: HKEY = HKEY(0);
        let result = unsafe {
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                &subkey_hstring,
                0,
                KEY_READ,
                &mut key_handle,
            )
        };
        if result.is_ok() {
            unsafe { let _ = RegCloseKey(key_handle); };
            return true;
        }
    }
    false
}

/// Checks for running processes associated with virtual machines.
pub fn check_vm_processes() -> bool {
    let mut vm_processes_obf: Vec<Vec<u8>> = vec![
        b"vmtoolsd.exe".to_vec(), b"VMwareService.exe".to_vec(), b"VMwareTray.exe".to_vec(),
        b"VBoxService.exe".to_vec(), b"VBoxTray.exe".to_vec(), b"qemu-ga.exe".to_vec(),
        b"prl_tools_service.exe".to_vec(),
    ];
    vm_processes_obf.iter_mut().for_each(|s| utils::xor_obfuscate(s, XOR_KEY));

    if let Ok(snapshot) = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) } {
        if snapshot.is_invalid() {
            return false
        }
        let mut process_entry = PROCESSENTRY32W::default();
        process_entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        if unsafe { Process32FirstW(snapshot, &mut process_entry) }.is_ok() {
            loop {
                let process_name = String::from_utf16_lossy(&process_entry.szExeFile);
                for vm_process_obf in &vm_processes_obf {
                    let mut temp_deobf = vm_process_obf.clone();
                    let vm_process = deobfuscate_string(&mut temp_deobf);
                    if process_name.trim_end_matches('\0').eq_ignore_ascii_case(&vm_process) {
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

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
/// Checks for VM overhead by measuring the execution time of the RDTSC instruction.
pub fn check_rdtsc_timing() -> bool {
    use std::arch::x86_64::_rdtsc;
    const SAMPLES: u32 = 10;
    const THRESHOLD: u64 = 1000;
    let mut total_diff: u64 = 0;
    for _ in 0..SAMPLES {
        let t1 = unsafe { _rdtsc() };
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

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
/// Checks for VM overhead by measuring the execution time of the CPUID instruction.
pub fn check_cpuid_timing() -> bool {
    use std::arch::x86_64::_rdtsc;
    const SAMPLES: u32 = 10;
    const THRESHOLD: u64 = 400;
    let mut total_diff: u64 = 0;
    for _ in 0..SAMPLES {
        let t1 = unsafe { _rdtsc() };
        let _cpuid = CpuId::new();
        let t2 = unsafe { _rdtsc() };
        let diff = t2 - t1;
        total_diff += diff;
    }
    let avg_diff = total_diff / SAMPLES as u64;
    avg_diff > THRESHOLD
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
pub fn check_cpuid_timing() -> bool {
    false
}

/// Checks for the presence of VM-related directories in Program Files.
pub fn check_filesystem_artifacts() -> bool {
    let mut vm_dirs_obf: Vec<Vec<u8>> = vec![
        b"C:\\Program Files\\VMware".to_vec(), b"C:\\Program Files\\Oracle".to_vec(),
        b"C:\\Program Files\\VirtualBox".to_vec(), b"C:\\Program Files\\Parallels".to_vec(),
        b"C:\\Program Files\\QEMU".to_vec(),
    ];
    vm_dirs_obf.iter_mut().for_each(|s| utils::xor_obfuscate(s, XOR_KEY));

    for dir_obf in &vm_dirs_obf {
        let mut temp_deobf = dir_obf.clone();
        let dir = deobfuscate_string(&mut temp_deobf);
        if Path::new(&dir).exists() {
            return true;
        }
    }
    false
}

/// Runs all anti-VM checks.
pub fn is_virtualized() -> bool {
    let mut checks: Vec<fn() -> bool> = vec![
        check_cpuid_hypervisor,
        check_mac_address,
        check_bios,
        check_cpu_cores,
        check_memory_size,
        check_disk_size,
        check_display_adapter,
        check_pci_devices,
        check_drivers,
        check_vm_registry_keys,
        check_vm_processes,
        check_rdtsc_timing,
        check_cpuid_timing,
        check_filesystem_artifacts,
    ];

    let mut rng = rand::thread_rng();
    checks.shuffle(&mut rng);

    for check in checks {
        if check() {
            return true;
        }
        let delay = rng.gen_range(50..=200);
        thread::sleep(Duration::from_millis(delay));
    }

    false
}
