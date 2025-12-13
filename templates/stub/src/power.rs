// src/lib.rs

use anti_debug_rust;
use anti_vm;
use anti_sandbox;

// --- Import functions and modules from the new files (use crate::... to ensure internal modules are used) ---

// From anti_debug
use crate::anti_debug_rust::run_debug_checks;
use crate::anti_debug_rust::{
    debugger_detection,
    parent_anti_debug,
    bad_processes,
    blacklisted_windows,
    hooks_detection,
};

// From anti_vm
use crate::anti_vm::run_vm_checks;
use crate::anti_vm::{
    shadow_defender_detection,
    anyrun_detection,
    comodo_antivirus_detection,
    deep_freeze_detection,
    hyperv_check,
    kvm_check,
    monitor_metrics,
    parallels_check,
    qemu_check,
    sandboxie_detection,
    triage_detection,
    virtualbox_detection,
    vm_artifacts,
    vm_platform_check,
    vmware_detection,
};

// From anti_sandbox
use crate::anti_sandbox::run_environment_checks;
use crate::anti_sandbox::{
    admin_check,
    all_tokens,
    clean_environment_detection,
    critical_process,
    internet_check,
    pc_uptime,
    recent_file_activity,
    repetitive_process,
    running_processes,
    runtime_detector,
    usb_check,
    username_check,
};

// ============================================================================
// TOP-LEVEL PUBLIC API
// ============================================================================

/// Run comprehensive checks with admin privilege escalation.
/// This will attempt to elevate the process if not already running as an administrator.
pub fn run_all_checks_with_admin() -> bool {
    // Only run on Windows
    if !runtime_detector::is_windows() {
        return false;
    }

    // Check if we're admin, try to elevate if not
    if !admin_check::is_admin() {
        if let Err(_) = admin_check::elevate_process() {
            // Continue without admin privileges if elevation fails
        }
    }

    // Enable all available tokens if we have admin privileges
    if admin_check::is_admin() {
        let _ = all_tokens::enable();
        
        // Note: Setting process as critical is commented out as it can cause BSOD
        // if the process is terminated. Use with extreme caution.
        // let _ = critical_process::set_process_critical();
    }

    // Run all standard checks
    run_all_checks()
}

/// Windows-specific comprehensive anti-analysis check.
/// Runs checks in logical categories.
pub fn run_windows_specific_checks() -> bool {
    if !runtime_detector::is_windows() {
        return false;
    }

    // Core debugging detection
    if run_debug_checks() {
        return true;
    }

    // VM/Sandbox detection
    if run_vm_checks() {
        return true;
    }

    // Environment analysis
    if run_environment_checks() {
        return true;
    }

    // Process detection
    if run_process_checks() {
        return true;
    }

    false
}

/// The main detection function that runs a comprehensive suite of checks.
/// Returns `true` if a debugger, VM, sandbox, or other analysis tool is detected.
pub fn run_all_checks() -> bool {
    // Core anti-debug checks
    if debugger_detection::is_debugger_present() {
        println!("[anti_debug_rust] debugger_detection::is_debugger_present");
        return true;
    }
    if debugger_detection::check_remote_debugger().unwrap_or(false) {
        println!("[anti_debug_rust] debugger_detection::check_remote_debugger");
        return true;
    }
    if parent_anti_debug::parent_anti_debug() {
        println!("[anti_debug_rust] parent_anti_debug::parent_anti_debug");
        return true;
    }
    if pc_uptime::check_uptime(600).unwrap_or(false) {
        println!("[anti_sandbox] pc_uptime::check_uptime");
        return true;
    }
    if bad_processes::detect().unwrap_or(false) {
        println!("[anti_debug_rust] bad_processes::detect");
        return true;
    }
    if running_processes::check_running_processes_count(50).unwrap_or(false) {
        println!("[anti_sandbox] running_processes::check_running_processes_count");
        return true;
    }
    if blacklisted_windows::check_blacklisted_windows() {
        println!("[anti_debug_rust] blacklisted_windows::check_blacklisted_windows");
        return true;
    }
    if hooks_detection::detect_hooks_on_common_winapi_functions(None, None) {
        println!("[anti_debug_rust] hooks_detection::detect_hooks_on_common_winapi_functions");
        return true;
    }

    // Sandbox/VM detection checks
    if shadow_defender_detection::detect_shadow_defender() {
        println!("[anti_vm] shadow_defender_detection::detect_shadow_defender");
        return true;
    }
    if anyrun_detection::anyrun_detection().unwrap_or(false) {
        println!("[anti_sandbox] anyrun_detection::anyrun_detection");
        return true;
    }
    if !clean_environment_detection::detect_clean_environment() {
        println!("[anti_sandbox] clean_environment_detection::detect_clean_environment (too clean)");
        return true;
    }
    if comodo_antivirus_detection::detect_comodo_antivirus() {
        println!("[anti_sandbox] comodo_antivirus_detection::detect_comodo_antivirus");
        return true;
    }
    if deep_freeze_detection::detect_deep_freeze() {
        println!("[anti_vm] deep_freeze_detection::detect_deep_freeze");
        return true;
    }
    if hyperv_check::detect_hyperv().unwrap_or(false) {
        println!("[anti_vm] hyperv_check::detect_hyperv");
        return true;
    }
    if kvm_check::check_for_kvm().unwrap_or(false) {
        println!("[anti_vm] kvm_check::check_for_kvm");
        return true;
    }
    if monitor_metrics::is_screen_small().unwrap_or(false) {
        println!("[anti_sandbox] monitor_metrics::is_screen_small");
        return true;
    }
    if parallels_check::check_for_parallels().unwrap_or(false) {
        println!("[anti_vm] parallels_check::check_for_parallels");
        return true;
    }
    if qemu_check::check_for_qemu().unwrap_or(false) {
        println!("[anti_vm] qemu_check::check_for_qemu");
        return true;
    }
    if recent_file_activity::recent_file_activity_check().unwrap_or(false) {
        println!("[anti_sandbox] recent_file_activity::recent_file_activity_check");
        return true;
    }
    if repetitive_process::check().unwrap_or(false) {
        println!("[anti_sandbox] repetitive_process::check");
        return true;
    }
    if sandboxie_detection::detect_sandboxie() {
        println!("[anti_sandbox] sandboxie_detection::detect_sandboxie");
        return true;
    }
    if triage_detection::triage_check().unwrap_or(false) {
        println!("[anti_sandbox] triage_detection::triage_check");
        return true;
    }
    if usb_check::plugged_in().unwrap_or(true) == false {
        println!("[anti_sandbox] usb_check::plugged_in (no USB devices)");
        return true;
    }
    if username_check::check_for_blacklisted_names() {
        println!("[anti_sandbox] username_check::check_for_blacklisted_names");
        return true;
    }
    if virtualbox_detection::graphics_card_check().unwrap_or(false) {
        println!("[anti_vm] virtualbox_detection::graphics_card_check");
        return true;
    }
    if vm_artifacts::vm_artifacts_detect() {
        println!("[anti_vm] vm_artifacts::vm_artifacts_detect");
        return true;
    }
    if vm_platform_check::detect_vm_platform().unwrap_or(false) {
        println!("[anti_vm] vm_platform_check::detect_vm_platform");
        return true;
    }
    if vmware_detection::graphics_card_check().unwrap_or(false) {
        println!("[anti_vm] vmware_detection::graphics_card_check");
        return true;
    }
    if internet_check::check_connection().unwrap_or(true) == false {
        println!("[anti_sandbox] internet_check::check_connection");
        return true;
    }

    false
}

/// Run only process/service detection checks.
pub fn run_process_checks() -> bool {
    bad_processes::detect().unwrap_or(false) ||
    blacklisted_windows::check_blacklisted_windows()
}

// ============================================================================
// CONFIGURATION AND CUSTOMIZATION
// ============================================================================

pub struct AntiAnalysisConfig {
    pub enable_debug_checks: bool,
    pub enable_vm_checks: bool,
    pub enable_environment_checks: bool,
    pub enable_process_checks: bool,
    pub min_uptime_seconds: u32,
    pub min_process_count: usize,
    pub min_installed_programs: usize,
    pub enable_internet_check: bool,
    pub enable_usb_check: bool,
    pub enable_admin_escalation: bool,
    pub enable_privilege_escalation: bool,
    pub enable_critical_process: bool,
}

impl Default for AntiAnalysisConfig {
    fn default() -> Self {
        Self {
            enable_debug_checks: true,
            enable_vm_checks: true,
            enable_environment_checks: true,
            enable_process_checks: true,
            min_uptime_seconds: 600,    // 10 minutes
            min_process_count: 50,
            min_installed_programs: 10,
            enable_internet_check: true,
            enable_usb_check: true,
            enable_admin_escalation: true,
            enable_privilege_escalation: true,
            enable_critical_process: true,
        }
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {

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
    fn test_debugger_detection() {
        println!("Debugger present: {}", debugger_detection::is_debugger_present());
    }

    #[test]
    fn test_remote_debugger() {
        if let Ok(result) = debugger_detection::check_remote_debugger() {
            println!("Remote debugger present: {}", result);
        }
    }

    #[test]
    fn test_parent_process() {
        println!("Suspicious parent process: {}", parent_anti_debug::parent_anti_debug());
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
    fn test_bad_processes() {
        if let Ok(result) = bad_processes::detect() {
            println!("Bad processes detected: {}", result);
        }
    }

    #[test]
    fn test_vm_detection() {
        println!("VM environment detected: {}", run_vm_checks());
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
    fn test_screen_size() {
        if let Ok(small_screen) = monitor_metrics::is_screen_small() {
            println!("Small screen detected: {}", small_screen);
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

    #[test]
    fn test_all_checks() {
        let detected = run_all_checks();
        println!("Anti-analysis measures detected: {}", detected);
        println!("Debug checks: {}", run_debug_checks());
        println!("VM checks: {}", run_vm_checks());
        println!("Environment checks: {}", run_environment_checks());
        println!("Process checks: {}", run_process_checks());
    }

    #[test]
    fn test_windows_specific() {
        if runtime_detector::is_windows() {
            let detected = run_windows_specific_checks();
            println!("Windows-specific checks detected threats: {}", detected);
        } else {
            println!("Not running on Windows, skipping Windows-specific tests");
        }
    }
}
