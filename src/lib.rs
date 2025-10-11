
use raw_cpuid::CpuId;
use serde::Deserialize;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use wmi::{COMLibrary, WMIConnection};
use windows::core::PCWSTR;
use windows::Win32::System::Registry::{RegCloseKey, RegOpenKeyExW, HKEY, HKEY_LOCAL_MACHINE, KEY_READ};

/// Checks for the presence of a hypervisor using the CPUID instruction.
///
/// It first checks for the presence of a hypervisor and then queries the hypervisor name.
///
/// Returns `true` if a known hypervisor is detected, `false` otherwise.
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
                let vendor = std::str::from_utf8(&vendor_id).unwrap_or("");
                matches!(vendor, "VBoxVBoxVBox" | "prl hyperv")
            }
            _ => false,
        }
    } else {
        false
    }
}

#[derive(Deserialize, Debug)]
#[serde(rename = "Win32_ComputerSystem")]
#[serde(rename_all = "PascalCase")]
struct Win32ComputerSystem {
    total_physical_memory: u64,
}

/// Checks the total physical memory size.
///
/// Returns `true` if the memory size is a common VM allocation (e.g., 1GB, 2GB, 4GB).
pub fn check_memory_size() -> bool {
    let com_lib = match COMLibrary::new() {
        Ok(lib) => lib,
        Err(_) => return false,
    };
    let wmi_con = match WMIConnection::new(com_lib.into()) {
        Ok(con) => con,
        Err(_) => return false,
    };

    let results: Vec<Win32ComputerSystem> = match wmi_con.query() {
        Ok(res) => res,
        Err(_) => return false,
    };

    if let Some(system) = results.first() {
        // Common VM RAM sizes in bytes (1GB, 2GB, 4GB)
        let common_vm_sizes = [
            1 * 1024 * 1024 * 1024,
            2 * 1024 * 1024 * 1024,
            4 * 1024 * 1024 * 1024,
        ];
        common_vm_sizes.contains(&system.total_physical_memory)
    } else {
        false
    }
}

#[derive(Deserialize, Debug)]
#[serde(rename = "Win32_NetworkAdapterConfiguration")]
#[serde(rename_all = "PascalCase")]
struct Win32NetworkAdapterConfiguration {
    #[serde(rename = "MACAddress")]
    mac_address: Option<String>,
}

/// Checks for MAC addresses associated with virtual machines.
///
/// Returns `true` if a known VM MAC address prefix is found, `false` otherwise.
pub fn check_mac_address() -> bool {
    let com_lib = match COMLibrary::new() {
        Ok(lib) => lib,
        Err(_) => return false,
    };
    let wmi_con = match WMIConnection::new(com_lib.into()) {
        Ok(con) => con,
        Err(_) => return false,
    };

    let results: Vec<Win32NetworkAdapterConfiguration> = match wmi_con.query() {
        Ok(res) => res,
        Err(_) => return false,
    };

    let vm_mac_prefixes = [
        "00:05:69", // VMware
        "00:0C:29", // VMware
        "00:1C:14", // VMware
        "00:50:56", // VMware
        "08:00:27", // VirtualBox
        "00:1C:42", // Parallels
        "52:54:00", // QEMU/KVM
    ];

    for item in results {
        if let Some(mac) = &item.mac_address {
            for &prefix in &vm_mac_prefixes {
                if mac.starts_with(prefix) {
                    return true;
                }
            }
        }
    }

    false
}

#[derive(Deserialize, Debug)]
#[serde(rename = "Win32_BIOS")]
#[serde(rename_all = "PascalCase")]
struct Win32Bios {
    #[serde(rename = "SerialNumber")]
    serial_number: Option<String>,
    #[serde(rename = "Version")]
    version: Option<String>,
}

/// Checks the BIOS for strings commonly found in virtual machines.
///
/// Returns `true` if a VM-related string is found in the BIOS information, `false` otherwise.
pub fn check_bios() -> bool {
    let com_lib = match COMLibrary::new() {
        Ok(lib) => lib,
        Err(_) => return false,
    };
    let wmi_con = match WMIConnection::new(com_lib.into()) {
        Ok(con) => con,
        Err(_) => return false,
    };

    let results: Vec<Win32Bios> = match wmi_con.query() {
        Ok(res) => res,
        Err(_) => return false,
    };

    let vm_bios_strings = [
        "VMware",
        "VirtualBox",
        "QEMU",
        "Hyper-V",
        "Parallels",
        "Xen",
    ];

    for bios in results {
        if let Some(serial) = &bios.serial_number {
            for &vm_string in &vm_bios_strings {
                if serial.contains(vm_string) {
                    return true;
                }
            }
        }
        if let Some(version) = &bios.version {
            for &vm_string in &vm_bios_strings {
                if version.contains(vm_string) {
                    return true;
                }
            }
        }
    }

    false
}

#[derive(Deserialize, Debug)]
#[serde(rename = "Win32_Processor")]
#[serde(rename_all = "PascalCase")]
struct Win32Processor {
    number_of_cores: u32,
}

/// Checks the number of CPU cores.
///
/// Returns `true` if the number of cores is 1 or 2, which is common for VMs.
pub fn check_cpu_cores() -> bool {
    let com_lib = match COMLibrary::new() {
        Ok(lib) => lib,
        Err(_) => return false,
    };
    let wmi_con = match WMIConnection::new(com_lib.into()) {
        Ok(con) => con,
        Err(_) => return false,
    };

    let results: Vec<Win32Processor> = match wmi_con.query() {
        Ok(res) => res,
        Err(_) => return false,
    };

    if let Some(processor) = results.first() {
        // VMs often have 1 or 2 cores
        matches!(processor.number_of_cores, 1 | 2)
    } else {
        false
    }
}

#[derive(Deserialize, Debug)]
#[serde(rename = "Win32_DiskDrive")]
#[serde(rename_all = "PascalCase")]
struct Win32DiskDrive {
    size: u64,
}

/// Checks the disk drive size.
///
/// Returns `true` if the disk size is a common VM allocation (e.g., 64GB, 128GB).
pub fn check_disk_size() -> bool {
    let com_lib = match COMLibrary::new() {
        Ok(lib) => lib,
        Err(_) => return false,
    };
    let wmi_con = match WMIConnection::new(com_lib.into()) {
        Ok(con) => con,
        Err(_) => return false,
    };

    let results: Vec<Win32DiskDrive> = match wmi_con.query() {
        Ok(res) => res,
        Err(_) => return false,
    };

    if let Some(disk) = results.first() {
        // Common VM disk sizes in bytes (e.g., 60GB, 80GB, 100GB)
        let common_vm_sizes = [
            60 * 1024 * 1024 * 1024,
            80 * 1024 * 1024 * 1024,
            100 * 1024 * 1024 * 1024,
        ];
        common_vm_sizes.contains(&disk.size)
    } else {
        false
    }
}

#[derive(Deserialize, Debug)]
#[serde(rename = "Win32_VideoController")]
#[serde(rename_all = "PascalCase")]
struct Win32VideoController {
    name: String,
}

/// Checks the display adapter name.
///
/// Returns `true` if the display adapter is a known virtual adapter.
pub fn check_display_adapter() -> bool {
    let com_lib = match COMLibrary::new() {
        Ok(lib) => lib,
        Err(_) => return false,
    };
    let wmi_con = match WMIConnection::new(com_lib.into()) {
        Ok(con) => con,
        Err(_) => return false,
    };

    let results: Vec<Win32VideoController> = match wmi_con.query() {
        Ok(res) => res,
        Err(_) => return false,
    };

    let vm_adapters = [
        "VMware SVGA",
        "VirtualBox Graphics Adapter",
        "Hyper-V Video",
        "QEMU Standard VGA",
        "Parallels Display Adapter",
    ];

    for adapter in results {
        for &vm_adapter in &vm_adapters {
            if adapter.name.contains(vm_adapter) {
                return true;
            }
        }
    }
    false
}

#[derive(Deserialize, Debug)]
#[serde(rename = "Win32_PnPEntity")]
#[serde(rename_all = "PascalCase")]
struct Win32PnPEntity {
    description: String,
}

/// Checks for virtual PCI devices.
///
/// Returns `true` if a known virtual PCI device is found.
pub fn check_pci_devices() -> bool {
    let com_lib = match COMLibrary::new() {
        Ok(lib) => lib,
        Err(_) => return false,
    };
    let wmi_con = match WMIConnection::new(com_lib.into()) {
        Ok(con) => con,
        Err(_) => return false,
    };

    let results: Vec<Win32PnPEntity> = match wmi_con.query() {
        Ok(res) => res,
        Err(_) => return false,
    };

    let vm_pci_devices = ["VMware VMCI", "VirtualBox Guest Service", "Red Hat VirtIO"];

    for device in results {
        for &vm_device in &vm_pci_devices {
            if device.description.contains(vm_device) {
                return true;
            }
        }
    }
    false
}

#[derive(Deserialize, Debug)]
#[serde(rename = "Win32_SystemDriver")]
#[serde(rename_all = "PascalCase")]
struct Win32SystemDriver {
    name: String,
}

/// Checks for known virtual machine drivers.
///
/// Returns `true` if a known VM driver is found.
pub fn check_drivers() -> bool {
    let com_lib = match COMLibrary::new() {
        Ok(lib) => lib,
        Err(_) => return false,
    };
    let wmi_con = match WMIConnection::new(com_lib.into()) {
        Ok(con) => con,
        Err(_) => return false,
    };

    let results: Vec<Win32SystemDriver> = match wmi_con.query() {
        Ok(res) => res,
        Err(_) => return false,
    };

    let vm_drivers = [
        "virtio", "vmxnet", "pvscsi", "vboxguest", "vmware", "vmusb", "vmx86",
    ];

    for driver in results {
        for &vm_driver in &vm_drivers {
            if driver.name.contains(vm_driver) {
                return true;
            }
        }
    }
    false
}

fn to_pcwstr(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}

/// Checks for registry keys associated with virtual machines.
pub fn check_vm_registry_keys() -> bool {
    let vm_keys = [
        "SOFTWARE\\VMware, Inc.\\VMware Tools",
        "SYSTEM\\CurrentControlSet\\Services\\VBoxGuest",
        "SYSTEM\\CurrentControlSet\\Services\\VBoxMouse",
        "SYSTEM\\CurrentControlSet\\Services\\VBoxSF",
        "SYSTEM\\CurrentControlSet\\Services\\VBoxVideo",
    ];

    for key_path in vm_keys {
        let subkey_pcwstr = to_pcwstr(key_path);
        let mut key_handle: HKEY = HKEY(0);
        let result = unsafe {
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                PCWSTR(subkey_pcwstr.as_ptr()),
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

#[derive(Deserialize, Debug)]
#[serde(rename = "Win32_Process")]
#[serde(rename_all = "PascalCase")]
struct Win32Process {
    name: String,
}

/// Checks for running processes associated with virtual machines.
pub fn check_vm_processes() -> bool {
    let com_lib = match COMLibrary::new() {
        Ok(lib) => lib,
        Err(_) => return false,
    };
    let wmi_con = match WMIConnection::new(com_lib.into()) {
        Ok(con) => con,
        Err(_) => return false,
    };

    let results: Vec<Win32Process> = match wmi_con.query() {
        Ok(res) => res,
        Err(_) => return false,
    };

    let vm_processes = [
        "vmtoolsd.exe",
        "VMwareService.exe",
        "VMwareTray.exe",
        "VBoxService.exe",
        "VBoxTray.exe",
        "qemu-ga.exe",
        "prl_tools_service.exe",
    ];

    for process in results {
        for &vm_process in &vm_processes {
            if process.name.eq_ignore_ascii_case(vm_process) {
                return true;
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
    const THRESHOLD: u64 = 1000; // A high number of cycles between consecutive calls is suspicious.
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
    use raw_cpuid::CpuId;
    const SAMPLES: u32 = 10;
    const THRESHOLD: u64 = 400; // A common threshold for CPUID timing.
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
    let vm_dirs = [
        "C:\\Program Files\\VMware",
        "C:\\Program Files\\Oracle",
        "C:\\Program Files\\VirtualBox",
        "C:\\Program Files\\Parallels",
        "C:\\Program Files\\QEMU",
    ];

    for dir in vm_dirs {
        if Path::new(dir).exists() {
            return true;
        }
    }

    false
}


/// Runs all anti-VM checks.
///
/// Returns `true` if any of the checks detect a virtualized environment, `false` otherwise.
pub fn is_virtualized() -> bool {
    check_cpuid_hypervisor()
        || check_mac_address()
        || check_bios()
        || check_cpu_cores()
        || check_memory_size()
        || check_disk_size()
        || check_display_adapter()
        || check_pci_devices()
        || check_drivers()
        || check_vm_registry_keys()
        || check_vm_processes()
        || check_rdtsc_timing()
}
