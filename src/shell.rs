// PowerShell and CMD execution — Windows only

use std::process::Command;
#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;

pub fn run_powershell(cmd: &str) -> String {
    let mut cmd_obj = Command::new("powershell");
    cmd_obj.args(["-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", cmd]);

    #[cfg(target_os = "windows")]
    cmd_obj.creation_flags(0x08000000); // CREATE_NO_WINDOW

    let result = cmd_obj.output();

    match result {
        Ok(o) => {
            let mut out = String::from_utf8_lossy(&o.stdout).to_string();
            out.push_str(&String::from_utf8_lossy(&o.stderr));
            if out.trim().is_empty() {
                "(no output)\n".to_string()
            } else {
                out
            }
        }
        Err(e) => format!("(error: {})\n", e),
    }
}

pub fn run_cmd(cmd: &str) -> String {
    let mut cmd_obj = Command::new("cmd");
    cmd_obj.args(["/c", cmd]);

    #[cfg(target_os = "windows")]
    cmd_obj.creation_flags(0x08000000); // CREATE_NO_WINDOW

    let result = cmd_obj.output();

    match result {
        Ok(o) => {
            // cmd output is typically cp1252/cp1254; attempt UTF-8, fall back to lossy
            let stdout = decode_cp1252(&o.stdout);
            let stderr = decode_cp1252(&o.stderr);
            let combined = format!("{}{}", stdout, stderr);
            if combined.trim().is_empty() {
                "(no output)\n".to_string()
            } else {
                combined
            }
        }
        Err(e) => format!("(error: {})\n", e),
    }
}

/// Best-effort decode: try UTF-8, fall back to lossy latin-1 approximation.
fn decode_cp1252(bytes: &[u8]) -> String {
    match std::str::from_utf8(bytes) {
        Ok(s) => s.to_string(),
        Err(_) => bytes.iter().map(|&b| b as char).collect(),
    }
}
