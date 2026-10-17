use windows_sys::Win32::System::Console::{
    GetConsoleMode, GetStdHandle, SetConsoleMode, ENABLE_VIRTUAL_TERMINAL_PROCESSING,
    STD_OUTPUT_HANDLE,
};

/// Enables ANSI color codes in the console. Older consoles (Windows PowerShell 5.1)
/// have them off by default; returns `false` if they can't be enabled, in which
/// case the caller should print without colors.
pub fn enable_ansi() -> bool {
    unsafe {
        let out = GetStdHandle(STD_OUTPUT_HANDLE);
        let mut mode = 0;
        if GetConsoleMode(out, &mut mode) == 0 {
            return false; // not a console (redirected to a file/pipe)
        }
        mode & ENABLE_VIRTUAL_TERMINAL_PROCESSING != 0
            || SetConsoleMode(out, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0
    }
}
