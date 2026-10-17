use std::ffi::c_void;
use std::ptr;

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// Süreç yönetici yetkisiyle (UAC onaylı) mı çalışıyor?
pub fn is_elevated() -> bool {
    let mut token: HANDLE = ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return false;
    }
    let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut len = 0u32;
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            &mut elevation as *mut _ as *mut c_void,
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut len,
        )
    };
    unsafe { CloseHandle(token) };
    ok != 0 && elevation.TokenIsElevated != 0
}
