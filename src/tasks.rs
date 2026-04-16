// Task manager — pure Rust via Windows API (no PowerShell)

use windows::{
    Win32::System::Diagnostics::ToolHelp::*,
    Win32::System::Threading::*,
    Win32::Foundation::*,
};
use serde_json::{json, Value};
use crate::Sock;
use crate::send;

pub fn handle_tasklist(sock: &Sock) {
    let procs = list_processes();
    let json  = serde_json::to_string(&procs).unwrap_or_else(|_| "[]".to_string());
    send(sock, &format!("[tasklist_result]{}", json));
}

fn list_processes() -> Vec<Value> {
    let mut result = Vec::new();
    unsafe {
        let snap = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
            Ok(h) => h,
            Err(_) => return result,
        };

        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };

        if Process32FirstW(snap, &mut entry).is_err() {
            let _ = CloseHandle(snap);
            return result;
        }

        loop {
            let pid  = entry.th32ProcessID;
            let name = String::from_utf16_lossy(
                entry.szExeFile.split(|&c| c == 0).next().unwrap_or(&[])
            );

            // Get memory (WorkingSetSize) via OpenProcess
            let mem_mb = open_process_mem(pid);

            result.push(json!({
                "pid":  pid.to_string(),
                "name": name,
                "cpu":  "0",         // ToolHelp32 doesn't expose CPU %; omit
                "mem":  format!("{:.1}", mem_mb),
            }));

            if Process32NextW(snap, &mut entry).is_err() {
                break;
            }
        }

        let _ = CloseHandle(snap);
    }
    result
}

fn open_process_mem(pid: u32) -> f64 {
    use windows::Win32::System::ProcessStatus::GetProcessMemoryInfo;
    use windows::Win32::System::ProcessStatus::PROCESS_MEMORY_COUNTERS;
    unsafe {
        let handle = OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION,
            false,
            pid,
        );
        let handle = match handle {
            Ok(h) => h,
            Err(_) => return 0.0,
        };
        let mut pmc = PROCESS_MEMORY_COUNTERS::default();
        pmc.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
        let ok = GetProcessMemoryInfo(handle, &mut pmc, pmc.cb);
        let _ = CloseHandle(handle);
        if ok.is_ok() {
            pmc.WorkingSetSize as f64 / 1024.0 / 1024.0
        } else {
            0.0
        }
    }
}

pub fn handle_taskkill(sock: &Sock, pid_str: &str) {
    let pid: u32 = match pid_str.parse() {
        Ok(p) => p,
        Err(_) => {
            send(sock, "[taskkill_result]error:invalid pid");
            return;
        }
    };

    unsafe {
        match OpenProcess(PROCESS_TERMINATE, false, pid) {
            Err(e) => {
                send(sock, &format!("[taskkill_result]error:{}", e.message()));
            }
            Ok(handle) => {
                match TerminateProcess(handle, 1) {
                    Ok(_) => send(sock, &format!("[taskkill_result]ok:PID {} terminated", pid)),
                    Err(e) => send(sock, &format!("[taskkill_result]error:{}", e.message())),
                }
                let _ = CloseHandle(handle);
            }
        }
    }
}