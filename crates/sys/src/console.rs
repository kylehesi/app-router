use windows_sys::Win32::System::Console::{
    GetConsoleMode, GetStdHandle, SetConsoleMode, ENABLE_VIRTUAL_TERMINAL_PROCESSING,
    STD_OUTPUT_HANDLE,
};

/// Konsolda ANSI renk kodlarını açar. Eski konsollarda (Windows PowerShell 5.1)
/// kapalı gelir; açılamazsa `false` döner ve çağıran renksiz çıktı vermelidir.
pub fn enable_ansi() -> bool {
    unsafe {
        let out = GetStdHandle(STD_OUTPUT_HANDLE);
        let mut mode = 0;
        if GetConsoleMode(out, &mut mode) == 0 {
            return false; // konsol değil (dosyaya/boruya yönlendirilmiş)
        }
        mode & ENABLE_VIRTUAL_TERMINAL_PROCESSING != 0
            || SetConsoleMode(out, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0
    }
}
