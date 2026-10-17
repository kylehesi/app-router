use std::io;
use std::iter;

/// Null-terminated UTF-16 string.
pub fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(iter::once(0)).collect()
}

/// Reads a null-terminated UTF-16 pointer.
///
/// # Safety
/// `p` may be null; otherwise it must point to a valid null-terminated string.
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

/// Reads a fixed-size UTF-16 buffer up to the first null character.
pub(crate) fn from_wide_buf(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

pub(crate) fn win32_err(code: u32) -> io::Error {
    io::Error::from_raw_os_error(code as i32)
}
