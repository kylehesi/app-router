use std::io;
use std::iter;

/// Null ile biten UTF-16 dizgesi.
pub fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(iter::once(0)).collect()
}

/// Null ile biten bir UTF-16 işaretçisini okur.
///
/// # Safety
/// `p` null olabilir; değilse null ile biten geçerli bir dizgeyi göstermelidir.
pub(crate) unsafe fn from_wide_ptr(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut len = 0;
    while *p.add(len) != 0 {
        len += 1;
    }
    String::from_utf16_lossy(std::slice::from_raw_parts(p, len))
}

/// Sabit boyutlu bir UTF-16 tamponunu ilk null karakterine kadar okur.
pub(crate) fn from_wide_buf(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

pub(crate) fn win32_err(code: u32) -> io::Error {
    io::Error::from_raw_os_error(code as i32)
}
