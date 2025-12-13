use std::ffi::CString;
use std::mem;
use std::path::Path;
use std::process::Command;
use windows::{
    core::*,
    Win32::{
        Foundation::*,
        System::{
            Diagnostics::Debug::*,
            ProcessStatus::*,
            Threading::*,
            LibraryLoader::*,
        },
        UI::WindowsAndMessaging::*,
    },
};
use windows::Win32::System::Threading::PROCESS_NAME_FORMAT;

// ============================================================================
// ANTI-DEBUG MODULE
// Contains all debugging and reverse engineering detection mechanisms
// ============================================================================

/// Main anti-debug detection function
pub fn run_debug_checks() -> bool {
    debugger_detection::is_debugger_present() ||
    debugger_detection::check_remote_debugger().unwrap_or(false) ||
    parent_anti_debug::parent_anti_debug() ||
    hooks_detection::detect_hooks_on_common_winapi_functions(None, None)
}

pub mod debugger_detection {
    use super::*;

    pub fn is_debugger_present() -> bool {
        unsafe { IsDebuggerPresent().as_bool() }
    }

    pub fn check_remote_debugger() -> std::result::Result<bool, String> {
        unsafe {
            let mut is_remote_debug_present = FALSE;
            CheckRemoteDebuggerPresent(
                GetCurrentProcess(),
                &mut is_remote_debug_present
            ).map(|_| is_remote_debug_present.as_bool()).map_err(|e| e.to_string())
        }
    }
}

pub mod parent_anti_debug {
    use super::*;
    use std::path::Path;

    #[repr(C)]
    struct ProcessBasicInformation {
        _exit_status: *mut std::ffi::c_void,
        _peb_base_address: *mut std::ffi::c_void,
        _affinity_mask: usize,
        _base_priority: i32,
        _unique_process_id: usize,
        inherited_from_unique_process_id: usize,
    }

    pub fn parent_anti_debug() -> bool {
        unsafe {
            let current_process = GetCurrentProcess();
            let mut pbi: ProcessBasicInformation = mem::zeroed();
            let mut return_length = 0u32;

            let ntdll = match GetModuleHandleA(s!("ntdll.dll")) {
                Ok(handle) => handle,
                Err(_) => return false,
            };

            let nt_query_proc = match GetProcAddress(ntdll, s!("NtQueryInformationProcess")) {
                Some(proc_addr) => proc_addr,
                None => return false,
            };

            type NtQueryInformationProcessFn = unsafe extern "system" fn(
                HANDLE,
                u32,
                *mut std::ffi::c_void,
                u32,
                *mut u32,
            ) -> i32;

            let nt_query: NtQueryInformationProcessFn = mem::transmute(nt_query_proc);
            
            if nt_query(
                current_process,
                0, // ProcessBasicInformation
                &mut pbi as *mut _ as *mut std::ffi::c_void,
                mem::size_of::<ProcessBasicInformation>() as u32,
                &mut return_length,
            ) != 0 {
                return false;
            }

            let parent_pid = pbi.inherited_from_unique_process_id as u32;
            if parent_pid == 0 {
                return false;
            }

            let parent_handle = match OpenProcess(
                PROCESS_QUERY_INFORMATION,
                false,
                parent_pid,
            ) {
                Ok(handle) => handle,
                Err(_) => return false,
            };

            let mut buffer = [0u16; 260]; // MAX_PATH
            let mut size = buffer.len() as u32;
            
            let result = match QueryFullProcessImageNameW(parent_handle, PROCESS_NAME_FORMAT(0), PWSTR(buffer.as_mut_ptr()), &mut size) {
                Ok(_) => {
                    let parent_name = String::from_utf16_lossy(&buffer[..size as usize]);
                    let parent_exe = Path::new(&parent_name)
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .to_lowercase();
                    
                    parent_exe != "explorer.exe" && parent_exe != "cmd.exe"
                }
                Err(_) => false,
            };
            
            let _ = CloseHandle(parent_handle);
            result
        }
    }
}

pub mod bad_processes {
    use super::*;

    const BANNED_PROCESSES: &[&str] = &[
        // Analysis & Debugging Tools
        "taskmgr.exe", "process.exe", "processhacker.exe", "procexp.exe", "procexp64.exe",
        "procmon.exe", "procmon64.exe", "processmonitor.exe", "systemexplorer.exe",
        "ksdumper.exe", "ksdumperclient.exe", "fiddler.exe", "httpdebuggerui.exe",
        "wireshark.exe", "httpanalyzerv7.exe", "decoder.exe", "regedit.exe", "dnspy.exe",
        "burpsuite.exe", "DbgX.Shell.exe", "ILSpy.exe", "ollydbg.exe", "x32dbg.exe",
        "x64dbg.exe", "x96dbg.exe", "gdb.exe", "idaq.exe", "idag.exe", "idaw.exe",
        "ida64.exe", "idag64.exe", "idaw64.exe", "idaq64.exe", "windbg.exe",
        "immunitydebugger.exe", "windasm.exe", "HTTP Toolkit.exe", "pestudio.exe",
        "pe-bear.exe", "detectiteasy.exe", "die.exe", "hex.exe", "hxd.exe",
        "010editor.exe", "binaryninja.exe", "radare2.exe", "r2.exe", "cutter.exe",
        "ghidra.exe", "cheatengine.exe", "cheatengine-x86_64.exe", "apimonitor.exe",
        "apimonitor-x64.exe", "apispypp.exe", "regshot.exe", "regshot-x64-ansi.exe",
        "regshot-x64-unicode.exe", "perfview.exe", "vmmap.exe", "rammap.exe",
        "pslist.exe", "pskill.exe", "psexec.exe", "autoruns.exe", "autoruns64.exe",
        "tcpview.exe", "strings.exe", "strings64.exe", "handle.exe", "handle64.exe",
        "listdlls.exe", "listdlls64.exe", "portmon.exe", "filemon.exe", "regmon.exe",
        "sysmon.exe", "sysmon64.exe",
        
        // VM/Sandbox Specific Processes
        "vboxservice.exe", "vboxtray.exe", "vmtoolsd.exe", "vgauthservice.exe",
        "vmacthlp.exe", "vmsrvc.exe", "vmusrvc.exe", "prl_cc.exe", "prl_tools.exe",
        "xenservice.exe", "qemu-ga.exe", "joeboxcontrol.exe", "joeboxserver.exe",
        "df5serv.exe", // Deep Freeze
    ];

    pub fn detect() -> std::result::Result<bool, String> {
        unsafe {
            let mut processes = [0u32; 1024];
            let mut bytes_returned = 0u32;

            if !K32EnumProcesses(
                processes.as_mut_ptr(),
                (processes.len() * mem::size_of::<u32>()) as u32,
                &mut bytes_returned,
            ).as_bool() {
                return Err(format!("Failed to enumerate processes: {:?}", GetLastError()));
            }

            let process_count = bytes_returned as usize / mem::size_of::<u32>();
            
            for &pid in &processes[..process_count] {
                if let Ok(handle) = OpenProcess(
                    PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                    false,
                    pid,
                ) {
                    let mut buffer = [0u16; 260];
                    let mut size = buffer.len() as u32;
                    if QueryFullProcessImageNameW(handle, PROCESS_NAME_FORMAT(0), PWSTR(buffer.as_mut_ptr()), &mut size).is_ok() {
                        let process_name = String::from_utf16_lossy(&buffer);
                        let exe_name = std::path::Path::new(process_name.trim_end_matches('\0'))
                            .file_name()
                            .unwrap_or_default()
                            .to_string_lossy()
                            .to_lowercase();

                        if BANNED_PROCESSES.contains(&exe_name.as_str()) {
                            let _ = CloseHandle(handle);
                            return Ok(true);
                        }
                    }
                    let _ = CloseHandle(handle);
                }
            }
            Ok(false)
        }
    }
}

pub mod blacklisted_windows {
    use super::*;
    
    const BANNED_UUIDS: &[&str] = &[ "7AB5C494-39F5-4941-9163-47F54D6D5016", "032E02B4-0499-05C3-0806-3C0700080009", "03DE0294-0480-05DE-1A06-350700080009", "11111111-2222-3333-4444-555555555555", "6F3CA5EC-BEC9-4A4D-8274-11168F640058", "4C4C4544-0050-3710-8058-CAC04F59344A", "00000000-0000-0000-0000-AC1F6BD04972", "00000000-0000-0000-0000-000000000000", "5BD24D56-789F-8468-7CDC-CAA7222CC121", "49434D53-0200-9065-2500-65902500E439", "49434D53-0200-9036-2500-36902500F022", "777D84B3-88D1-451C-93E4-D235177420A7", "49434D53-0200-9036-2500-369025000C65", "B1112042-52E8-E25B-3655-6A4F54155DBF", "00000000-0000-0000-0000-AC1F6BD048FE", "EB16924B-FB6D-4FA1-8666-17B91F62FB37", "A15A930C-8251-9645-AF63-E45AD728C20C", "67E595EB-54AC-4FF0-B5E3-3DA7C7B547E3", "C7D23342-A5D4-68A1-59AC-CF40F735B363", "63203342-0EB0-AA1A-4DF5-3FB37DBB0670", "44B94D56-65AB-DC02-86A0-98143A7423BF", "6608003F-ECE4-494E-B07E-1C4615D1D93C", "D9142042-8F51-5EFF-D5F8-EE9AE3D1602A", "49434D53-0200-9036-2500-369025003AF0", "8B4E8278-525C-7343-B825-280AEBCD3BCB", "4D4DDC94-E06C-44F4-95FE-33A1ADA5AC27", "79AF5279-16CF-4094-9758-F88A616D81B4", ];
    const BANNED_COMPUTER_NAMES: &[&str] = &[ "WDAGUtilityAccount", "Abby", "Peter Wilson", "hmarc", "patex", "JOHN-PC", "RDhJ0CNFevzX", "kEecfMwgj", "Frank", "8Nl0ColNQ5bq", "Lisa", "John", "george", "PxmdUOpVyx", "8VizSM", "w0fjuOVmCcP5A", "lmVwjj9b", "PqONjHVwexsS", "3u2v9m8", "Julia", "HEUeRzl", "BEE7370C-8C0C-4", "DESKTOP-NAKFFMT", "WIN-5E07COS9ALR", "B30F0242-1C6A-4", "DESKTOP-VRSQLAG", "Q9IATRKPRH", "XC64ZB", "DESKTOP-D019GDM", "DESKTOP-WI8CLET", "SERVER1", "LISA-PC", "DESKTOP-B0T93D6", "DESKTOP-1PYKP29", "DESKTOP-1Y2433R", "COMPNAME_4491", "WILEYPC", "WORK", "KATHLROGE", "DESKTOP-TKGQ6GH", "6C4E733F-C2D9-4", "RALPHS-PC", "DESKTOP-WG3MYJS", "DESKTOP-7XC6GEZ", "DESKTOP-5OV9S0O", "QarZhrdBpj", "ORELEEPC", "ARCHIBALDPC", "DESKTOP-NNSJYNR", "JULIA-PC", "DESKTOP-BQISITB", "d1bnJkfVlH", ];
    const BLACKLISTED_WINDOW_TITLES: &[&str] = &[ "proxifier", "graywolf", "extremedumper", "zed", "exeinfope", "dnspy", "titanHide", "ilspy", "x32dbg", "codecracker", "simpleassembly", "process hacker", "pc-ret", "http debugger", "Centos", "process monitor", "debug", "reverse", "de4dot", "fiddler", "die", "crack", "strongod", "ida -", "brute", "dump", "StringDecryptor", "wireshark", "debugger", "gdb", "kdb", "x64_dbg", "windbg", "x64netdumper", "petools", "scyllahide", "megadumper", "reversal", "ksdumper", "dbgclr", "HxD", "ollydbg", "http", "wpe pro", "dbg", "httpanalyzer", "httpdebug", "PhantOm", "kgdb", "x32_dbg", "proxy", "phantom", "mdbg", "system explorer", "protection_id", "charles", "pepper", "hxd", "procmon", "MegaDumper", "ghidra", "0harmony", "hacker", "SAE", "mdb", "cheat engine", ];

    unsafe extern "system" fn enum_windows_proc(hwnd: HWND, lparam: LPARAM) -> BOOL {
        unsafe {
            let found_blacklisted = &mut *(lparam.0 as *mut bool);
            let mut buffer = [0u16; 256];
            let length = GetWindowTextW(hwnd, &mut buffer);
            
            if length > 0 {
                let window_title = String::from_utf16_lossy(&buffer[..length as usize]).to_lowercase();
                if BLACKLISTED_WINDOW_TITLES.iter().any(|&blacklisted| window_title.contains(blacklisted)) {
                    *found_blacklisted = true;
                    return FALSE; // Stop enumeration
                }
            }
        }
        TRUE // Continue enumeration
    }
    fn enum_windows_and_check() -> bool {
        let mut found_blacklisted = false;
        unsafe {
            let _ = EnumWindows(Some(enum_windows_proc), LPARAM(&mut found_blacklisted as *mut _ as isize));
        }
        found_blacklisted
    }

    fn check_banned_uuid() -> bool {
        if let Ok(output) = Command::new("wmic").args(&["csproduct", "get", "uuid"]).output() {
            let uuid = String::from_utf8_lossy(&output.stdout).trim().to_uppercase();
            BANNED_UUIDS.iter().any(|&banned| uuid.contains(banned))
        } else { false }
    }

    pub fn check_blacklisted_windows() -> bool {
        if let Ok(hostname) = std::env::var("COMPUTERNAME") {
            if BANNED_COMPUTER_NAMES.iter().any(|&name| hostname.eq_ignore_ascii_case(name)) { return true; }
        }
        if check_banned_uuid() { return true; }
        if enum_windows_and_check() { return true; }
        // Process check is now handled by bad_processes::detect() in run_all_checks
        false
    }
}

pub mod hooks_detection {
    use super::*;

    const KERNEL_FUNCTIONS: &[&str] = &[ "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "GetThreadContext", "CloseHandle", "OutputDebugStringA", "GetTickCount", "SetHandleInformation" ];
    const NTDLL_FUNCTIONS: &[&str] = &[ "NtQueryInformationProcess", "NtSetInformationThread", "NtClose", "NtGetContextThread", "NtQuerySystemInformation", "NtCreateFile", "NtCreateProcess", "NtCreateSection", "NtCreateThread", "NtYieldExecution", "NtCreateUserProcess" ];
    const USER32_FUNCTIONS: &[&str] = &[ "FindWindowW", "FindWindowA", "FindWindowExW", "FindWindowExA", "GetForegroundWindow", "GetWindowTextLengthA", "GetWindowTextA", "BlockInput", "CreateWindowExW", "CreateWindowExA" ];
    const WIN32U_FUNCTIONS: &[&str] = &[ "NtUserBlockInput", "NtUserFindWindowEx", "NtUserQueryWindow", "NtUserGetForegroundWindow" ];

    fn check_function_hooks(module_name: &str, functions: &[&str]) -> bool {
        unsafe {
            if let Ok(module_handle) = GetModuleHandleA(PCSTR(CString::new(module_name).unwrap().as_ptr() as *const u8)) {
                for &function_name in functions {
                    if let Some(proc_addr) = GetProcAddress(module_handle, PCSTR(CString::new(function_name).unwrap().as_ptr() as *const u8)) {
                        let first_byte = *(proc_addr as *const u8);
                        if first_byte == 0x90 || first_byte == 0xE9 { return true; } // NOP or JMP
                    }
                }
            }
        }
        false
    }

    pub fn detect_hooks_on_common_winapi_functions(module_name: Option<&str>, functions: Option<&[&str]>) -> bool {
        if check_function_hooks("kernel32.dll", KERNEL_FUNCTIONS) ||
           check_function_hooks("kernelbase.dll", KERNEL_FUNCTIONS) ||
           check_function_hooks("ntdll.dll", NTDLL_FUNCTIONS) ||
           check_function_hooks("user32.dll", USER32_FUNCTIONS) ||
           check_function_hooks("win32u.dll", WIN32U_FUNCTIONS) {
            return true;
        }
        if let (Some(module), Some(funcs)) = (module_name, functions) {
            if check_function_hooks(module, funcs) { return true; }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_bad_processes() {
        if let Ok(result) = bad_processes::detect() {
            println!("Bad processes detected: {}", result);
        }
    }

    #[test]
    fn test_all_debug_checks() {
        println!("Debug checks result: {}", run_debug_checks());
    }
}
