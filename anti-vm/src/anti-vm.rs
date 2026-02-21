#![cfg(windows)]

use rand::seq::SliceRandom;
use rand::Rng;
use raw_cpuid::CpuId;
use std::ffi::c_void;
use std::thread;
use std::time::{Duration};
use windows::core::{HSTRING, PCWSTR};
use windows::Win32::Foundation::{GENERIC_READ, BOOL, HANDLE, CloseHandle, SetLastError, GetLastError};
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
use windows::Win32::System::Diagnostics::Debug::{AddVectoredExceptionHandler, RemoveVectoredExceptionHandler, EXCEPTION_POINTERS, IsDebuggerPresent, CheckRemoteDebuggerPresent, GetThreadContext, CONTEXT, OutputDebugStringW};
#[cfg(target_arch = "x86_64")]
use windows::Win32::System::Diagnostics::Debug::CONTEXT_DEBUG_REGISTERS_AMD64 as DEBUG_REG_FLAG;
#[cfg(target_arch = "x86")]
use windows::Win32::System::Diagnostics::Debug::CONTEXT_DEBUG_REGISTERS_X86 as DEBUG_REG_FLAG;

use windows::Win32::System::IO::DeviceIoControl;
use windows::Win32::System::Ioctl::{
    IOCTL_STORAGE_QUERY_PROPERTY, STORAGE_PROPERTY_QUERY, StorageDeviceProperty,
    PropertyStandardQuery, STORAGE_DEVICE_DESCRIPTOR,
};
use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};

/// Weights for the scoring system (Recalibrated for False Positive reduction).
const WEIGHT_RDTSC: u32 = 25;
const WEIGHT_TSC_DRIFT: u32 = 15;
const WEIGHT_EXCEPTION_LATENCY: u32 = 15;
const WEIGHT_INTERRUPT_LATENCY: u32 = 20;
const WEIGHT_ACPI: u32 = 45;
const WEIGHT_SMBIOS: u32 = 45;
const WEIGHT_DEVICE_FILES: u32 = 50;
const WEIGHT_VMWARE_PORT: u32 = 55;
const WEIGHT_DISK_FINGERPRINT: u32 = 40;
const WEIGHT_HYPERVISOR_SIG: u32 = 50;
const WEIGHT_DESCRIPTOR_TABLES: u32 = 35;
const WEIGHT_DEBUGGER: u32 = 20;
const WEIGHT_HW_BREAKPOINTS: u32 = 30;
const WEIGHT_LOADED_MODULES: u32 = 50;
const WEIGHT_ENV_PURITY: u32 = 20;
const WEIGHT_SANDBOX_ENV: u32 = 30;
const WEIGHT_MOUSE_BEHAVIOR: u32 = 5;
const WEIGHT_SYSTEM32_FOOTPRINT: u32 = 10;
const WEIGHT_REGISTRY_ARTIFACTS: u32 = 45;
const WEIGHT_TLB_LATENCY: u32 = 40;
const WEIGHT_PEB_DEBUG: u32 = 35;
const WEIGHT_NT_QUERY_INFO: u32 = 40;
const WEIGHT_INVALID_HANDLE: u32 = 30;
const WEIGHT_OUTPUT_DEBUG: u32 = 15;
const WEIGHT_TRAP_FLAG: u32 = 25;
const WEIGHT_CODE_INTEGRITY: u32 = 40;

const THRESHOLD_VIRTUALIZED: u32 = 60;

static mut EXCEPTION_HIT: bool = false;

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
    let first = cpuid_samples[0];
    let all_same = cpuid_samples.iter().all(|&x| x == first && x != 0);
    all_same || median_cpuid > 1200 || (median_cpuid / median_nop.max(1)) > 50
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
            #[cfg(target_arch = "x86_64")]
            std::arch::asm!(
                "mov {1}, rbx",
                "mov eax, 0x564D5868",
                "xor ebx, ebx",
                "mov ecx, 0xA",
                "mov edx, 0x5658",
                "in eax, dx",
                "mov {0}, rbx",
                "mov rbx, {1}",
                out(reg) ebx_val,
                out(reg) _,
                out("eax") _,
                out("ecx") _,
                out("edx") _,
            );
            #[cfg(target_arch = "x86")]
            std::arch::asm!(
                "mov {1}, ebx",
                "mov eax, 0x564D5868",
                "xor ebx, ebx",
                "mov ecx, 0xA",
                "mov edx, 0x5658",
                "in eax, dx",
                "mov {0}, ebx",
                "mov ebx, {1}",
                out(reg) ebx_val,
                out(reg) _,
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

/// 3. Descriptor Table Analysis.
pub fn check_descriptor_tables() -> bool {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        let mut gdt = [0u8; 10];
        let mut idt = [0u8; 10];
        let mut ldt: u16 = 0;
        unsafe {
            std::arch::asm!("sgdt [{0}]", in(reg) &mut gdt);
            std::arch::asm!("sidt [{0}]", in(reg) &mut idt);
            std::arch::asm!("sldt {0:e}", out(reg) ldt);
        }
        #[cfg(target_arch = "x86_64")]
        {
            let gdt_base = u64::from_le_bytes(gdt[2..10].try_into().unwrap());
            let idt_base = u64::from_le_bytes(idt[2..10].try_into().unwrap());
            if gdt_base > 0xFFFFFFFFFFFF0000 || idt_base > 0xFFFFFFFFFFFF0000 || ldt != 0 {
                return true;
            }
        }
        #[cfg(target_arch = "x86")]
        {
            let gdt_base = u32::from_le_bytes(gdt[2..6].try_into().unwrap());
            let idt_base = u32::from_le_bytes(idt[2..6].try_into().unwrap());
            if gdt_base > 0xFF000000 || idt_base > 0xFF000000 || ldt != 0 {
                return true;
            }
        }
    }
    false
}

/// 4. Disk Fingerprinting.
pub fn check_disk_fingerprint() -> bool {
    let drive_path = "\\\\.\\PhysicalDrive0";
    let h_drive = unsafe {
        CreateFileW(&HSTRING::from(drive_path), 0, FILE_SHARE_READ | FILE_SHARE_WRITE, None, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, None)
    };
    if let Ok(handle) = h_drive {
        if !handle.is_invalid() {
            let query = STORAGE_PROPERTY_QUERY { PropertyId: StorageDeviceProperty, QueryType: PropertyStandardQuery, AdditionalParameters: [0; 1] };
            let mut descriptor = vec![0u8; 1024];
            let mut bytes_returned = 0u32;
            let success = unsafe {
                DeviceIoControl(handle, IOCTL_STORAGE_QUERY_PROPERTY, Some(&query as *const _ as *const c_void), std::mem::size_of::<STORAGE_PROPERTY_QUERY>() as u32, Some(descriptor.as_mut_ptr() as *mut c_void), descriptor.len() as u32, Some(&mut bytes_returned), None)
            };
            unsafe { let _ = CloseHandle(handle); }
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

/// 5. Hypervisor-specific CPUID Leaf Checks.
pub fn check_hypervisor_signature() -> bool {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        let mut ebx: u32 = 0; let mut ecx: u32 = 0; let mut edx: u32 = 0;
        let mut eax_val: u32 = 0x40000000;
        unsafe {
            std::arch::asm!(
                "push rbx",
                "cpuid",
                "mov {0:e}, ebx",
                "pop rbx",
                out(reg) ebx,
                inout("eax") eax_val,
                out("ecx") ecx,
                out("edx") edx,
            );
        }
        let _ = eax_val;
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

/// 6. TSC vs. QPC Drift Analysis.
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub fn check_tsc_drift() -> bool {
    #[cfg(target_arch = "x86_64")]
    use std::arch::x86_64::{_mm_lfence, _rdtsc};
    #[cfg(target_arch = "x86")]
    use std::arch::x86::{_mm_lfence, _rdtsc};
    let mut qpc_freq = 0i64;
    unsafe { let _ = QueryPerformanceFrequency(&mut qpc_freq); }
    if qpc_freq == 0 { return false; }

    let mut drift_detected = false;
    for _ in 0..3 {
        let mut qpc1 = 0i64; let mut qpc2 = 0i64;
        unsafe {
            _mm_lfence(); let _ = QueryPerformanceCounter(&mut qpc1); let t1 = _rdtsc(); _mm_lfence();
            thread::sleep(Duration::from_millis(300));
            _mm_lfence(); let _ = QueryPerformanceCounter(&mut qpc2); let t2 = _rdtsc(); _mm_lfence();
            let tsc_diff = t2 - t1;
            let qpc_diff = (qpc2 - qpc1) as f64 / qpc_freq as f64;
            let tsc_freq = tsc_diff as f64 / qpc_diff;
            if tsc_freq < 0.4e9 || tsc_freq > 8.0e9 { drift_detected = true; break; }
        }
    }
    drift_detected
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
pub fn check_tsc_drift() -> bool { false }

/// 7. Software Interrupt Latency Analysis.
pub fn check_interrupt_latency() -> bool {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        #[cfg(target_arch = "x86_64")]
        use std::arch::x86_64::{_mm_lfence, _rdtsc};
        #[cfg(target_arch = "x86")]
        use std::arch::x86::{_mm_lfence, _rdtsc};

        unsafe extern "system" fn handler(exception_info: *mut EXCEPTION_POINTERS) -> i32 {
            let record = (*exception_info).ExceptionRecord;
            if (*record).ExceptionCode.0 == 0x80000003u32 as i32 {
                let context = (*exception_info).ContextRecord;
                #[cfg(target_arch = "x86_64")] { (*context).Rip += 1; }
                #[cfg(target_arch = "x86")] { (*context).Eip += 1; }
                return -1; // EXCEPTION_CONTINUE_EXECUTION
            }
            0 // EXCEPTION_CONTINUE_SEARCH
        }
        let mut samples = [0u64; 10];
        unsafe {
            let h = AddVectoredExceptionHandler(1, Some(handler));
            if h.is_null() { return false; }
            for i in 0..10 {
                _mm_lfence(); let t1 = _rdtsc(); _mm_lfence();
                std::arch::asm!("int 3");
                _mm_lfence(); let t2 = _rdtsc(); _mm_lfence();
                samples[i] = t2 - t1;
            }
            RemoveVectoredExceptionHandler(h);
        }
        let mut sorted = samples.to_vec();
        sorted.sort_unstable();
        sorted[5] > 200_000
    }
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    { false }
}

/// 8. Exception Handling Latency Check.
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

/// 9. Loaded Modules Check.
pub fn check_loaded_modules() -> bool {
    let modules = ["snxhk.dll", "cmdvrt64.dll", "SbieDll.dll", "dbghelp.dll", "api_log.dll", "dir_log.dll", "pstorec.dll", "vmcheck.dll", "w03_res.dll"];
    for m in &modules {
        let mut name: Vec<u16> = m.encode_utf16().collect();
        name.push(0);
        unsafe {
            if !GetModuleHandleW(PCWSTR(name.as_ptr())).is_err() { return true; }
        }
    }
    false
}

/// 10. Environment Purity (Empty Folders, Specific files).
pub fn check_environment_purity() -> bool {
    let mut purity_points = 0;
    if std::path::Path::new("C:\\file.exe").exists() { purity_points += 2; }
    let user_profile = std::env::var("USERPROFILE").unwrap_or_default();
    if !user_profile.is_empty() {
        let docs = format!("{}\\{}", user_profile, "Documents");
        if let Ok(entries) = std::fs::read_dir(docs) {
            if entries.count() < 1 { purity_points += 1; }
        }
    }
    purity_points >= 2
}

/// 11. Debugger Detection.
pub fn check_debugger() -> bool {
    let mut remote_debugger = BOOL(0);
    unsafe {
        if IsDebuggerPresent().as_bool() { return true; }
        let _ = CheckRemoteDebuggerPresent(windows::Win32::System::Threading::GetCurrentProcess(), &mut remote_debugger);
    }
    remote_debugger.as_bool()
}

/// 12. Hardware Breakpoint Detection.
/// Inspects DR0-DR3 (addresses), DR6 (status), and DR7 (control).
pub fn check_hw_breakpoints() -> bool {
    let mut ctx = CONTEXT::default();
    ctx.ContextFlags = DEBUG_REG_FLAG;
    unsafe {
        if GetThreadContext(windows::Win32::System::Threading::GetCurrentThread(), &mut ctx).is_ok() {
            // DR0-DR3 are breakpoint addresses.
            // DR6 is status, DR7 is control.
            // In a normal system, these should typically be 0.
            if ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0 || ctx.Dr6 != 0 || (ctx.Dr7 != 0 && ctx.Dr7 != 0x400) {
                return true;
            }
        }
    }
    false
}

/// 13. PEB-based Debugger Detection (BeingDebugged & NtGlobalFlag).
pub fn check_peb_debugger() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        let mut being_debugged: u8 = 0;
        let mut nt_global_flag: u32 = 0;
        unsafe {
            std::arch::asm!(
                "mov rax, gs:[0x60]",
                "mov {0}, byte ptr [rax + 0x02]",
                "mov {1:e}, dword ptr [rax + 0xBC]",
                out(reg_byte) being_debugged,
                out(reg) nt_global_flag,
                out("rax") _,
            );
        }
        if being_debugged != 0 { return true; }
        // FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS
        if (nt_global_flag & 0x70) != 0 { return true; }
    }
    #[cfg(target_arch = "x86")]
    {
        let mut being_debugged: u8 = 0;
        let mut nt_global_flag: u32 = 0;
        unsafe {
            std::arch::asm!(
                "mov eax, fs:[0x30]",
                "mov {0}, byte ptr [eax + 0x02]",
                "mov {1:e}, dword ptr [eax + 0x68]",
                out(reg_byte) being_debugged,
                out(reg) nt_global_flag,
                out("eax") _,
            );
        }
        if being_debugged != 0 { return true; }
        if (nt_global_flag & 0x70) != 0 { return true; }
    }
    false
}

/// 14. NtQueryInformationProcess checks.
pub fn check_nt_query_info_process() -> bool {
    type NtQueryInformationProcessFn = unsafe extern "system" fn(
        HANDLE, u32, *mut c_void, u32, *mut u32
    ) -> i32;

    let ntdll = unsafe { GetModuleHandleW(PCWSTR("ntdll.dll\0".encode_utf16().collect::<Vec<u16>>().as_ptr())).unwrap_or_default() };
    if ntdll.is_invalid() { return false; }

    let nt_query_info_ptr = unsafe { GetProcAddress(ntdll, windows::core::PCSTR("NtQueryInformationProcess\0".as_ptr())) };
    if let Some(nt_query_info_addr) = nt_query_info_ptr {
        let nt_query_info: NtQueryInformationProcessFn = unsafe { std::mem::transmute(nt_query_info_addr) };

        let mut debug_port: usize = 0;
        let mut status = unsafe { nt_query_info(windows::Win32::System::Threading::GetCurrentProcess(), 7, &mut debug_port as *mut _ as *mut c_void, std::mem::size_of::<usize>() as u32, std::ptr::null_mut()) };
        if status == 0 && debug_port != 0 { return true; }

        let mut debug_object: HANDLE = HANDLE(0);
        status = unsafe { nt_query_info(windows::Win32::System::Threading::GetCurrentProcess(), 30, &mut debug_object as *mut _ as *mut c_void, std::mem::size_of::<HANDLE>() as u32, std::ptr::null_mut()) };
        if status == 0 && !debug_object.is_invalid() { return true; }

        let mut debug_flags: u32 = 0;
        status = unsafe { nt_query_info(windows::Win32::System::Threading::GetCurrentProcess(), 31, &mut debug_flags as *mut _ as *mut c_void, 4, std::ptr::null_mut()) };
        if status == 0 && debug_flags == 0 { return true; }
    }
    false
}

/// 15. ThreadHideFromDebugger check.
pub fn check_thread_hide_from_debugger() -> bool {
    type NtSetInformationThreadFn = unsafe extern "system" fn(
        HANDLE, u32, *mut c_void, u32
    ) -> i32;

    let ntdll = unsafe { GetModuleHandleW(PCWSTR("ntdll.dll\0".encode_utf16().collect::<Vec<u16>>().as_ptr())).unwrap_or_default() };
    if ntdll.is_invalid() { return false; }

    let nt_set_info_ptr = unsafe { GetProcAddress(ntdll, windows::core::PCSTR("NtSetInformationThread\0".as_ptr())) };
    if let Some(nt_set_info_addr) = nt_set_info_ptr {
        let nt_set_info: NtSetInformationThreadFn = unsafe { std::mem::transmute(nt_set_info_addr) };
        // ThreadHideFromDebugger = 0x11
        let status = unsafe { nt_set_info(windows::Win32::System::Threading::GetCurrentThread(), 0x11, std::ptr::null_mut(), 0) };
        return status >= 0;
    }
    false
}

/// 16. Invalid Handle check.
pub fn check_invalid_handle() -> bool {
    unsafe extern "system" fn handler(exception_info: *mut EXCEPTION_POINTERS) -> i32 {
        if (*(*exception_info).ExceptionRecord).ExceptionCode.0 == 0xC0000008u32 as i32 {
            unsafe { EXCEPTION_HIT = true; }
            return -1; // EXCEPTION_CONTINUE_EXECUTION
        }
        0 // EXCEPTION_CONTINUE_SEARCH
    }

    unsafe {
        EXCEPTION_HIT = false;
        let h = AddVectoredExceptionHandler(1, Some(handler));
        if !h.is_null() {
            let _ = CloseHandle(HANDLE(0xBAADF00D));
            RemoveVectoredExceptionHandler(h);
        }
        EXCEPTION_HIT
    }
}

/// 17. OutputDebugString check.
pub fn check_output_debug_string() -> bool {
    unsafe {
        SetLastError(windows::Win32::Foundation::WIN32_ERROR(0xDEADBEEF));
        OutputDebugStringW(PCWSTR("Anti-Debug\0".encode_utf16().collect::<Vec<u16>>().as_ptr()));
        GetLastError().0 != 0xDEADBEEF
    }
}

/// 18. Trap Flag Detection.
/// Uses the CPU Trap Flag (TF) to detect single-step debugging.
pub fn check_trap_flag() -> bool {
    unsafe extern "system" fn handler(exception_info: *mut EXCEPTION_POINTERS) -> i32 {
        if (*(*exception_info).ExceptionRecord).ExceptionCode.0 == 0x80000004u32 as i32 {
            unsafe { EXCEPTION_HIT = true; }
            return -1; // EXCEPTION_CONTINUE_EXECUTION
        }
        0 // EXCEPTION_CONTINUE_SEARCH
    }

    unsafe {
        EXCEPTION_HIT = false;
        let h = AddVectoredExceptionHandler(1, Some(handler));
        if !h.is_null() {
            #[cfg(target_arch = "x86_64")]
            std::arch::asm!(
                "pushfq",
                "or qword ptr [rsp], 0x100",
                "popfq",
                "nop",
            );
            #[cfg(target_arch = "x86")]
            std::arch::asm!(
                "pushfd",
                "or dword ptr [esp], 0x100",
                "popfd",
                "nop",
            );
            RemoveVectoredExceptionHandler(h);
        }
        // If EXCEPTION_HIT is true, it means our VEH caught the single-step.
        // If a debugger intercepted it, EXCEPTION_HIT might be false.
        !EXCEPTION_HIT
    }
}

/// 19. Code Integrity Self-Check.
/// Detects if a debugger has patched the .text section with software breakpoints (0xCC).
#[allow(non_snake_case)]
#[allow(dead_code)]
pub fn check_code_integrity() -> bool {
    #[repr(C)]
    struct IMAGE_DOS_HEADER {
        e_magic: u16, e_cblp: u16, e_cp: u16, e_crlc: u16, e_cparhdr: u16, e_minalloc: u16, e_maxalloc: u16,
        e_ss: u16, e_sp: u16, e_csum: u16, e_ip: u16, e_cs: u16, e_lfarlc: u16, e_ovno: u16,
        e_res: [u16; 4], e_oemid: u16, e_oeminfo: u16, e_res2: [u16; 10], e_lfanew: i32,
    }

    #[repr(C)]
    struct IMAGE_FILE_HEADER {
        Machine: u16, NumberOfSections: u16, TimeDateStamp: u32, PointerToSymbolTable: u32,
        NumberOfSymbols: u32, SizeOfOptionalHeader: u16, Characteristics: u16,
    }

    #[repr(C)]
    struct IMAGE_DATA_DIRECTORY { VirtualAddress: u32, Size: u32 }

    #[repr(C)]
    struct IMAGE_OPTIONAL_HEADER64 {
        Magic: u16, MajorLinkerVersion: u8, MinorLinkerVersion: u8, SizeOfCode: u32,
        SizeOfInitializedData: u32, SizeOfUninitializedData: u32, AddressOfEntryPoint: u32,
        BaseOfCode: u32, ImageBase: u64, SectionAlignment: u32, FileAlignment: u32,
        MajorOperatingSystemVersion: u16, MinorOperatingSystemVersion: u16,
        MajorImageVersion: u16, MinorImageVersion: u16, MajorSubsystemVersion: u16,
        MinorSubsystemVersion: u16, Win32VersionValue: u32, SizeOfImage: u32,
        SizeOfHeaders: u32, CheckSum: u32, Subsystem: u16, DllCharacteristics: u16,
        SizeOfStackReserve: u64, SizeOfStackCommit: u64, SizeOfHeapReserve: u64,
        SizeOfHeapCommit: u64, LoaderFlags: u32, NumberOfRvaAndSizes: u32,
        DataDirectory: [IMAGE_DATA_DIRECTORY; 16],
    }

    #[repr(C)]
    struct IMAGE_NT_HEADERS64 { Signature: u32, FileHeader: IMAGE_FILE_HEADER, OptionalHeader: IMAGE_OPTIONAL_HEADER64 }

    #[repr(C)]
    struct IMAGE_SECTION_HEADER {
        Name: [u8; 8], VirtualSize: u32, VirtualAddress: u32, SizeOfRawData: u32,
        PointerToRawData: u32, PointerToRelocations: u32, PointerToLinenumbers: u32,
        NumberOfRelocations: u16, NumberOfLinenumbers: u16, Characteristics: u32,
    }

    unsafe {
        let h_module = GetModuleHandleW(None).unwrap_or_default();
        if h_module.is_invalid() { return false; }

        let base_addr = h_module.0 as *const u8;
        let dos_header = &*(base_addr as *const IMAGE_DOS_HEADER);
        if dos_header.e_magic != 0x5A4D { return false; }

        let nt_headers = &*(base_addr.add(dos_header.e_lfanew as usize) as *const IMAGE_NT_HEADERS64);
        if nt_headers.Signature != 0x4550 { return false; }

        let section_header_ptr = base_addr.add(dos_header.e_lfanew as usize + 4 + std::mem::size_of::<IMAGE_FILE_HEADER>() + nt_headers.FileHeader.SizeOfOptionalHeader as usize) as *const IMAGE_SECTION_HEADER;
        let num_sections = nt_headers.FileHeader.NumberOfSections;

        for i in 0..num_sections {
            let section = &*(section_header_ptr.add(i as usize));
            let name = String::from_utf8_lossy(&section.Name).to_string();
            if name.starts_with(".text") {
                let start = base_addr.add(section.VirtualAddress as usize);
                let size = section.VirtualSize as usize;

                let mut int3_count = 0;
                for j in 0..size {
                    if *start.add(j) == 0xCC {
                        int3_count += 1;
                    }
                }
                if int3_count > 0 { return true; }
            }
        }
    }
    false
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
            if table_str.contains("VMWARE") || table_str.contains("VBOX") || table_str.contains("BOCHS") || table_str.contains("QEMU") { return true; }
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
        if data_str.contains(indicator) { return true; }
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
    let sandbox_strings = ["WDAGUtilityAccount", "SANDBOX", "VIRUSTOTAL"];
    for s in &sandbox_strings {
        if username.contains(&s.to_uppercase()) { return true; }
    }
    false
}

/// 2. Check for minimalist environment.
pub fn check_system32_footprint() -> bool {
    if let Ok(entries) = std::fs::read_dir("C:\\Windows\\System32") {
        let count = entries.take(500).count();
        return count < 250;
    }
    false
}

/// 1. TLB Timing Test (Translation Lookaside Buffer).
/// Measures memory translation latency which is significantly higher in virtualized environments.
pub fn check_tlb_latency() -> bool {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        #[cfg(target_arch = "x86_64")]
        use std::arch::x86_64::{_mm_lfence, _rdtsc};
        #[cfg(target_arch = "x86")]
        use std::arch::x86::{_mm_lfence, _rdtsc};

        use windows::Win32::System::Memory::{VirtualAlloc, VirtualFree, MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE, MEM_RELEASE};

        let page_size = 4096;
        let num_pages = 1024; // 4MB to ensure spread
        let buffer_size = num_pages * page_size;

        unsafe {
            let buffer_ptr = VirtualAlloc(None, buffer_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if buffer_ptr.is_null() { return false; }

            // Warm up / Ensure mapped
            for i in 0..num_pages {
                std::ptr::write_volatile(buffer_ptr.cast::<u8>().add(i * page_size), 0);
            }

            let mut samples = [0u64; 100];
            let mut rng = rand::thread_rng();

            for i in 0..100 {
                let page_idx = rng.gen_range(0..num_pages);
                let offset = page_idx * page_size;
                _mm_lfence();
                let t1 = _rdtsc();
                _mm_lfence();
                let _val = std::ptr::read_volatile(buffer_ptr.cast::<u8>().add(offset));
                _mm_lfence();
                let t2 = _rdtsc();
                _mm_lfence();
                samples[i] = t2 - t1;
            }

            let _ = VirtualFree(buffer_ptr, 0, MEM_RELEASE);

            let mut sorted = samples.to_vec();
            sorted.sort_unstable();
            let median = sorted[50];

            // Real PC: ~50-200 cycles, VM: ~500-2000 cycles
            median > 450
        }
    }
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    { false }
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
                unsafe { let _ = CloseHandle(handle); }
                return true;
            }
        }
    }
    false
}

/// 4. Hardware fingerprinting with negative scoring.
pub fn get_hardware_score() -> i32 {
    let mut score = 0;
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
    if (width > 0 && width <= 1024 && height > 0 && height <= 768) || (width == 800 && height == 600) { score += 10; }
    if sys_info.dwNumberOfProcessors < 2 { score += 10; }
    if mem_status.ullTotalPhys < (2 * 1024 * 1024 * 1024) { score += 10; }
    if total_disk < (60 * 1024 * 1024 * 1024) { score += 10; }
    if sys_info.dwNumberOfProcessors >= 8 { score -= 30; }
    if mem_status.ullTotalPhys >= (16 * 1024 * 1024 * 1024) { score -= 30; }
    if width > 1920 || height > 1080 { score -= 20; }
    score
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
    let mut score: i32 = get_hardware_score();
    let checks: Vec<(&str, fn() -> bool, u32)> = vec![
        ("RDTSC Timing", check_rdtsc_advanced, WEIGHT_RDTSC),
        ("VMware Port", check_vmware_port, WEIGHT_VMWARE_PORT),
        ("Descriptor Tables", check_descriptor_tables, WEIGHT_DESCRIPTOR_TABLES),
        ("Debugger", check_debugger, WEIGHT_DEBUGGER),
        ("HW Breakpoints", check_hw_breakpoints, WEIGHT_HW_BREAKPOINTS),
        ("PEB Debugger", check_peb_debugger, WEIGHT_PEB_DEBUG),
        ("NtQueryInfo", check_nt_query_info_process, WEIGHT_NT_QUERY_INFO),
        ("Invalid Handle", check_invalid_handle, WEIGHT_INVALID_HANDLE),
        ("OutputDebugString", check_output_debug_string, WEIGHT_OUTPUT_DEBUG),
        ("Hide Thread", check_thread_hide_from_debugger, 5),
        ("Trap Flag", check_trap_flag, WEIGHT_TRAP_FLAG),
        ("Code Integrity", check_code_integrity, WEIGHT_CODE_INTEGRITY),
        ("Loaded Modules", check_loaded_modules, WEIGHT_LOADED_MODULES),
        ("Disk Fingerprint", check_disk_fingerprint, WEIGHT_DISK_FINGERPRINT),
        ("Hypervisor Sig", check_hypervisor_signature, WEIGHT_HYPERVISOR_SIG),
        ("TSC Drift", check_tsc_drift, WEIGHT_TSC_DRIFT),
        ("Interrupt Latency", check_interrupt_latency, WEIGHT_INTERRUPT_LATENCY),
        ("Exception Latency", check_exception_latency, WEIGHT_EXCEPTION_LATENCY),
        ("ACPI Tables", check_acpi_tables, WEIGHT_ACPI),
        ("SMBIOS Data", check_smbios_data, WEIGHT_SMBIOS),
        ("Mouse Behavior", check_mouse_behavior, WEIGHT_MOUSE_BEHAVIOR),
        ("Sandbox Env", check_sandbox_environment, WEIGHT_SANDBOX_ENV),
        ("Env Purity", check_environment_purity, WEIGHT_ENV_PURITY),
        ("System32 Footprint", check_system32_footprint, WEIGHT_SYSTEM32_FOOTPRINT),
        ("Device Files", check_device_files, WEIGHT_DEVICE_FILES),
        ("Registry Artifacts", check_registry_artifacts, WEIGHT_REGISTRY_ARTIFACTS),
        ("TLB Latency", check_tlb_latency, WEIGHT_TLB_LATENCY),
    ];
    let mut rng = rand::thread_rng();
    let mut indices: Vec<usize> = (0..checks.len()).collect();
    indices.shuffle(&mut rng);
    for i in indices {
        let (_name, check_fn, weight) = checks[i];
        if check_fn() { score += weight as i32; }
        if score >= THRESHOLD_VIRTUALIZED as i32 { return true; }
        thread::sleep(Duration::from_millis(rng.gen_range(50..150)));
    }
    score >= THRESHOLD_VIRTUALIZED as i32
}
