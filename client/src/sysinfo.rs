// Windows system info — pure Rust via windows crate (no PowerShell)

use windows::{
    core::PCWSTR,
    Win32::{
        Foundation::ERROR_SUCCESS,
        System::Registry::*,
    },
};
use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;

pub fn collect() -> String {
    let win_version  = get_win_version();
    let desktop_name = get_desktop_name();
    let antivirus    = get_antivirus();
    let country      = get_country();
    format!("{}|{}|{}|{}", win_version, desktop_name, antivirus, country)
}

// ── Windows version from registry ────────────────────────────────────────────

fn reg_read_sz(key: HKEY, subkey: &str, value: &str) -> Option<String> {
    unsafe {
        let subkey_w: Vec<u16> = subkey.encode_utf16().chain(Some(0)).collect();
        let value_w:  Vec<u16> = value.encode_utf16().chain(Some(0)).collect();

        let mut hkey = HKEY::default();
        let res = RegOpenKeyExW(key, PCWSTR(subkey_w.as_ptr()), 0, KEY_READ, &mut hkey);
        if res != ERROR_SUCCESS { return None; }

        let mut data_type = REG_VALUE_TYPE::default();
        let mut size = 0u32;
        // First call: get size
        RegQueryValueExW(hkey, PCWSTR(value_w.as_ptr()), None, Some(&mut data_type), None, Some(&mut size));

        let mut buf: Vec<u8> = vec![0u8; size as usize];
        let res2 = RegQueryValueExW(
            hkey,
            PCWSTR(value_w.as_ptr()),
            None,
            Some(&mut data_type),
            Some(buf.as_mut_ptr()),
            Some(&mut size),
        );
        RegCloseKey(hkey);

        if res2 != ERROR_SUCCESS { return None; }

        // REG_SZ is UTF-16LE; convert to Rust String
        let words: Vec<u16> = buf
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .take_while(|&w| w != 0)
            .collect();
        Some(OsString::from_wide(&words).to_string_lossy().to_string())
    }
}

fn get_win_version() -> String {
    const KEY: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
    let product = reg_read_sz(HKEY_LOCAL_MACHINE, KEY, "ProductName")
        .unwrap_or_else(|| "Windows".to_string());
    let build   = reg_read_sz(HKEY_LOCAL_MACHINE, KEY, "CurrentBuild")
        .unwrap_or_default();
    let display = reg_read_sz(HKEY_LOCAL_MACHINE, KEY, "DisplayVersion")
        .or_else(|| reg_read_sz(HKEY_LOCAL_MACHINE, KEY, "ReleaseId"))
        .unwrap_or_default();

    if build.is_empty() {
        product
    } else {
        format!("{} {} (Build {})", product, display, build)
    }
}

// ── Computer name from environment ───────────────────────────────────────────

fn get_desktop_name() -> String {
    std::env::var("COMPUTERNAME").unwrap_or_else(|_| "Unknown".to_string())
}

// ── Antivirus detection ───────────────────────────────────────────────────────

fn reg_key_exists(key: HKEY, subkey: &str) -> bool {
    let subkey_w: Vec<u16> = subkey.encode_utf16().chain(Some(0)).collect();
    unsafe {
        let mut hkey = HKEY::default();
        let res = RegOpenKeyExW(key, PCWSTR(subkey_w.as_ptr()), 0, KEY_READ, &mut hkey);
        if res == ERROR_SUCCESS {
            RegCloseKey(hkey);
            true
        } else {
            false
        }
    }
}

fn get_antivirus() -> String {
    // ── 1. Önce üçüncü parti AV'leri kontrol et ──────────────────────────────
    // Üçüncü parti AV kuruluysa Windows Defender genellikle pasifleşir.
    // Bu yüzden önce bunları kontrol etmek daha doğru sonuç verir.
    let av_paths: &[(&str, &str)] = &[
        (r"SOFTWARE\AVAST Software\Avast",          "Avast"),
        (r"SOFTWARE\AVAST Software",                "Avast"),
        (r"SOFTWARE\AVG\Antivirus",                 "AVG"),
        (r"SOFTWARE\AVG",                           "AVG"),
        (r"SOFTWARE\Bitdefender",                   "Bitdefender"),
        (r"SOFTWARE\Bitdefender Agent",             "Bitdefender"),
        (r"SOFTWARE\KasperskyLab",                  "Kaspersky"),
        (r"SOFTWARE\McAfee\Agent",                  "McAfee"),
        (r"SOFTWARE\McAfee",                        "McAfee"),
        (r"SOFTWARE\Norton\{0C55C096-0F1D-4F28-AAA2-85EF591126E7}", "Norton"),
        (r"SOFTWARE\Norton",                        "Norton"),
        (r"SOFTWARE\Symantec\Symantec Endpoint Protection", "Symantec"),
        (r"SOFTWARE\Symantec",                      "Symantec"),
        (r"SOFTWARE\ESET\ESET Security",            "ESET"),
        (r"SOFTWARE\ESET",                          "ESET"),
        (r"SOFTWARE\Trend Micro",                   "Trend Micro"),
        (r"SOFTWARE\Malwarebytes",                  "Malwarebytes"),
        (r"SOFTWARE\Sophos",                        "Sophos"),
        (r"SOFTWARE\Panda Security",                "Panda"),
        (r"SOFTWARE\Comodo\Comodo Internet Security","Comodo"),
        (r"SOFTWARE\Comodo",                        "Comodo"),
        (r"SOFTWARE\F-Secure",                      "F-Secure"),
        (r"SOFTWARE\G Data",                        "G Data"),
        (r"SOFTWARE\360Safe",                       "360 Total Security"),
    ];

    for (path, name) in av_paths.iter() {
        if reg_key_exists(HKEY_LOCAL_MACHINE, path) {
            return name.to_string();
        }
    }

    // ── 2. Windows Defender kontrolü ─────────────────────────────────────────
    // Modern Windows 10/11'de "DisableAntiSpyware" key'i varsayılan olarak
    // registry'de BULUNMAZ — bu durumda Defender aktif demektir (None = açık).
    // Key varsa ve değeri "1" ise Defender devre dışı bırakılmış demektir.
    let defender_disabled = reg_read_sz(
        HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows Defender",
        "DisableAntiSpyware",
    );

    let defender_off = matches!(defender_disabled.as_deref(), Some("1"));

    if !defender_off {
        // Real-Time Protection da kapalı mı kontrol et
        let rt_disabled = reg_read_sz(
            HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection",
            "DisableRealtimeMonitoring",
        );
        // Key yoksa (None) veya "0" ise real-time protection aktif
        if !matches!(rt_disabled.as_deref(), Some("1")) {
            return "Windows Defender".to_string();
        }
    }

    "Unknown".to_string()
}

// ── Country via HTTP (pure Rust / windows WinHTTP) ───────────────────────────

fn get_country() -> String {
    use windows::{
        core::PCWSTR,
        Win32::Networking::WinHttp::*,
    };
    unsafe {
        let agent:  Vec<u16> = "client\0".encode_utf16().collect();
        let server: Vec<u16> = "ipinfo.io\0".encode_utf16().collect();
        let path:   Vec<u16> = "/country\0".encode_utf16().collect();

        let session = WinHttpOpen(
            PCWSTR(agent.as_ptr()),
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            PCWSTR::null(),
            PCWSTR::null(),
            0,
        );
        if session.is_null() { return "??".to_string(); }

        let connect = WinHttpConnect(session, PCWSTR(server.as_ptr()), 80, 0);
        if connect.is_null() { WinHttpCloseHandle(session); return "??".to_string(); }

        let verb:    Vec<u16> = "GET\0".encode_utf16().collect();
        let request = WinHttpOpenRequest(
            connect,
            PCWSTR(verb.as_ptr()),
            PCWSTR(path.as_ptr()),
            PCWSTR::null(),
            PCWSTR::null(),
            std::ptr::null_mut(),
            WINHTTP_OPEN_REQUEST_FLAGS(0),
        );
        if request.is_null() {
            WinHttpCloseHandle(connect);
            WinHttpCloseHandle(session);
            return "??".to_string();
        }

        let headers: Vec<u16> = Vec::new();
        if WinHttpSendRequest(
            request,
            if headers.is_empty() { None } else { Some(&headers) },
            None,
            0,
            0,
            0,
        ).is_err() || WinHttpReceiveResponse(request, std::ptr::null_mut()).is_err() {
            WinHttpCloseHandle(request);
            WinHttpCloseHandle(connect);
            WinHttpCloseHandle(session);
            return "??".to_string();
        }

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

        let s = String::from_utf8_lossy(&body).trim().to_string();
        if s.is_empty() { "??".to_string() } else { s }
    }
}