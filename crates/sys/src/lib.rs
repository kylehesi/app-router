//! Windows API sarmalayıcıları: adaptörler, Wi-Fi, süreçler, soket tabloları,
//! yetki ve sistem politikası. `unsafe` kodun tamamı bu crate'te toplanır.

pub mod adapters;
pub mod firewall;
pub mod netcfg;
pub mod policy;
pub mod processes;
pub mod security;
mod util;
pub mod wlan;

pub use util::to_wide;
