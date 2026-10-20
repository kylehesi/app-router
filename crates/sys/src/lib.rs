//! Windows API wrappers: adapters, Wi-Fi, processes, socket tables,
//! elevation and system policy. All `unsafe` code lives in this crate.

pub mod adapters;
pub mod console;
pub mod firewall;
pub mod netcfg;
pub mod notify;
pub mod policy;
pub mod processes;
pub mod security;
mod util;
pub mod wlan;

pub use util::to_wide;
