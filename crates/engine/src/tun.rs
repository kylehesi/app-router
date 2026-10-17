//! Wintun sanal ağ adaptörü.
//!
//! wintun.dll WireGuard projesi tarafından imzalanmıştır; uygulamayla birlikte
//! (exe'nin yanında) dağıtılır, ayrıca sürücü imzalama gerekmez.

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
    /// Adaptörü açar, yoksa oluşturur ve bir oturum başlatır. Yönetici yetkisi gerekir.
    pub fn open(dll_path: &Path) -> Result<Self> {
        // SAFETY: wintun.dll'nin resmi sürümü yükleniyor; crate ABI'yi bununla eşleştirir.
        let wintun = unsafe { wintun::load_from_path(dll_path) }
            .with_context(|| format!("{} yüklenemedi", dll_path.display()))?;
        let adapter = match wintun::Adapter::open(&wintun, ADAPTER_NAME) {
            Ok(adapter) => adapter,
            Err(_) => wintun::Adapter::create(&wintun, ADAPTER_NAME, TUNNEL_TYPE, None)
                .context("Wintun adaptörü oluşturulamadı (yönetici olarak çalıştırın)")?,
        };
        let session = Arc::new(
            adapter
                .start_session(wintun::MAX_RING_CAPACITY)
                .context("Wintun oturumu başlatılamadı")?,
        );
        Ok(Self { adapter, session })
    }

    pub fn if_index(&self) -> Result<u32> {
        Ok(self.adapter.get_adapter_index()?)
    }

    pub fn session(&self) -> Arc<wintun::Session> {
        self.session.clone()
    }

    /// Bekleyen `receive_blocking` çağrılarını sonlandırır.
    pub fn shutdown(&self) {
        let _ = self.session.shutdown();
    }
}

impl Drop for Tun {
    fn drop(&mut self) {
        self.shutdown();
    }
}
