//! Wintun virtual network adapter.
//!
//! wintun.dll is signed by the WireGuard project; it ships with the app
//! (next to the exe), so no separate driver signing is needed.

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};

pub const ADAPTER_NAME: &str = "Router TUN";
const TUNNEL_TYPE: &str = "Router";

pub struct Tun {
    adapter: Arc<wintun::Adapter>,
    session: Arc<wintun::Session>,
}

impl Tun {
    /// Opens the adapter (creating it if missing) and starts a session. Requires admin rights.
    pub fn open(dll_path: &Path) -> Result<Self> {
        // SAFETY: loads the official wintun.dll release; the crate's ABI matches it.
        let wintun = unsafe { wintun::load_from_path(dll_path) }
            .with_context(|| format!("failed to load {}", dll_path.display()))?;
        let adapter = match wintun::Adapter::open(&wintun, ADAPTER_NAME) {
            Ok(adapter) => adapter,
            Err(_) => wintun::Adapter::create(&wintun, ADAPTER_NAME, TUNNEL_TYPE, None)
                .context("failed to create Wintun adapter (run as administrator)")?,
        };
        let session = Arc::new(
            adapter
                .start_session(wintun::MAX_RING_CAPACITY)
                .context("failed to start Wintun session")?,
        );
        Ok(Self { adapter, session })
    }

    pub fn if_index(&self) -> Result<u32> {
        Ok(self.adapter.get_adapter_index()?)
    }

    pub fn session(&self) -> Arc<wintun::Session> {
        self.session.clone()
    }

    /// Unblocks pending `receive_blocking` calls.
    pub fn shutdown(&self) {
        let _ = self.session.shutdown();
    }
}

impl Drop for Tun {
    fn drop(&mut self) {
        self.shutdown();
    }
}
