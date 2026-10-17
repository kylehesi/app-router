//! Servis ile arayüz arasında paylaşılan veri tipleri ve IPC protokolü.
//!
//! Protokol: named pipe üzerinden satır başına bir JSON mesajı.
//! İstemci bir [`Request`] yazar, servis tek bir [`Response`] ile cevap verir.

use serde::{Deserialize, Serialize};

/// Servisin dinlediği named pipe.
pub const PIPE_NAME: &str = r"\\.\pipe\router-service";

/// Windows servis adı (sc.exe / services.msc'de görünen kısa ad).
pub const SERVICE_NAME: &str = "RouterService";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdapterKind {
    Wifi,
    Ethernet,
    Cellular,
    Other,
}

/// Bilgisayardaki bir ağ adaptörü (Wi-Fi kartı, USB Wi-Fi, USB tethering, Ethernet...).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AdapterInfo {
    /// Kalıcı kimlik, örn. "{4F6A...}". Kurallar bu değerle saklanır;
    /// adaptör adı veya index'i değişse bile sabit kalır.
    pub guid: String,
    pub if_index: u32,
    pub luid: u64,
    /// Windows'taki adı, örn. "Wi-Fi 2".
    pub friendly_name: String,
    /// Donanım açıklaması, örn. "Intel(R) Wi-Fi 6E AX211 160MHz".
    pub description: String,
    pub kind: AdapterKind,
    /// Fiziksel (veya USB) bir donanım mı? Sanal adaptörleri ayırt etmek için.
    pub hardware: bool,
    pub connected: bool,
    /// Bağlı olunan Wi-Fi ağının adı.
    pub ssid: Option<String>,
    /// Wi-Fi sinyal kalitesi, 0-100.
    pub signal_quality: Option<u32>,
    pub ipv4: Vec<String>,
    pub ipv6: Vec<String>,
    pub gateways: Vec<String>,
    pub ipv4_metric: u32,
    pub link_speed_bps: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

impl AdapterInfo {
    /// Varsayılan ağ geçidi varsa bu adaptör üzerinden internete çıkılabilir.
    pub fn has_internet_route(&self) -> bool {
        !self.gateways.is_empty()
    }

    /// İlk IPv4 ağ geçidi. Yönlendirme motoru şimdilik yalnızca IPv4 taşır.
    pub fn ipv4_gateway(&self) -> Option<&str> {
        self.gateways
            .iter()
            .map(String::as_str)
            .find(|g| g.parse::<std::net::Ipv4Addr>().is_ok())
    }

    /// Kullanıcıya gösterilecek ad: "Wi-Fi 2 · TurkTelekom_5G".
    pub fn display_name(&self) -> String {
        match &self.ssid {
            Some(ssid) => format!("{} · {}", self.friendly_name, ssid),
            None => self.friendly_name.clone(),
        }
    }
}

/// Ağ kullanan bir uygulama (aynı exe'nin tüm süreçleri tek kayıtta toplanır).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppInfo {
    /// Küçük harfli exe adı, örn. "chrome.exe". Kural anahtarıdır.
    pub exe: String,
    pub path: Option<String>,
    pub pids: Vec<u32>,
    pub tcp_connections: u32,
    pub udp_endpoints: u32,
}

/// Seçilen adaptör takılı değilse veya bağlantısı koptuysa ne yapılacağı.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum Fallback {
    /// Windows'un varsayılan internetini kullan.
    #[default]
    UseDefault,
    /// Uygulamanın internetini kes.
    Block,
}

/// "Bu uygulama şu adaptörden çıksın" kuralı.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    pub exe: String,
    pub adapter_guid: String,
    #[serde(default)]
    pub on_unavailable: Fallback,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Request {
    Ping,
    ListAdapters,
    ListApps,
    GetRules,
    /// `adapter_guid: None` kuralı siler (uygulama varsayılan internete döner).
    SetRule {
        exe: String,
        adapter_guid: Option<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum Response {
    Pong { version: String },
    Adapters(Vec<AdapterInfo>),
    Apps(Vec<AppInfo>),
    Rules(Vec<Rule>),
    Ok,
    Error(String),
}

/// Kural anahtarı olarak kullanılan exe adını normalleştirir.
pub fn normalize_exe(name: &str) -> String {
    name.trim().to_lowercase()
}
