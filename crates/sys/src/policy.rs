//! "Eşzamanlı bağlantıları en aza indir" politikası.
//!
//! Windows varsayılan olarak, internete zaten bağlıyken ikinci bir bağlantıyı
//! kendiliğinden düşürebilir. Uygulamanın çalışması için bu davranış kapatılmalıdır:
//! `HKLM\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy\fMinimizeConnections = 0`

use std::ffi::c_void;
use std::io;
use std::ptr;

use windows_sys::Win32::Foundation::ERROR_SUCCESS;
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegGetValueW, RegSetValueExW, HKEY, HKEY_LOCAL_MACHINE,
    KEY_SET_VALUE, REG_DWORD, REG_OPTION_NON_VOLATILE, RRF_RT_REG_DWORD,
};

use crate::util::{to_wide, win32_err};

const KEY: &str = r"SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy";
const VALUE: &str = "fMinimizeConnections";

/// Politikanın mevcut değeri. `None`: hiç ayarlanmamış (Windows varsayılanı = 1, yani açık).
pub fn minimize_connections() -> Option<u32> {
    let key = to_wide(KEY);
    let name = to_wide(VALUE);
    let mut data = 0u32;
    let mut size = std::mem::size_of::<u32>() as u32;
    let ret = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            key.as_ptr(),
            name.as_ptr(),
            RRF_RT_REG_DWORD,
            ptr::null_mut(),
            &mut data as *mut u32 as *mut c_void,
            &mut size,
        )
    };
    (ret == ERROR_SUCCESS).then_some(data)
}

/// Birden fazla bağlantının aynı anda açık kalmasına izin verir. Yönetici yetkisi gerekir.
pub fn allow_simultaneous_connections() -> io::Result<()> {
    let key = to_wide(KEY);
    let name = to_wide(VALUE);
    let mut hkey: HKEY = ptr::null_mut();
    let ret = unsafe {
        RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            key.as_ptr(),
            0,
            ptr::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE,
            ptr::null(),
            &mut hkey,
            ptr::null_mut(),
        )
    };
    if ret != ERROR_SUCCESS {
        return Err(win32_err(ret));
    }
    let value = 0u32;
    let ret = unsafe {
        RegSetValueExW(
            hkey,
            name.as_ptr(),
            0,
            REG_DWORD,
            &value as *const u32 as *const u8,
            std::mem::size_of::<u32>() as u32,
        )
    };
    unsafe { RegCloseKey(hkey) };
    if ret != ERROR_SUCCESS {
        return Err(win32_err(ret));
    }
    Ok(())
}
