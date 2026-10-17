//! Data types and IPC protocol shared between the service and the UI.
//!
//! Protocol: one JSON message per line over a named pipe.
//! The client writes a [`Request`]; the service answers with a single [`Response`].

use serde::{Deserialize, Serialize};

/// Named pipe the service listens on.
pub const PIPE_NAME: &str = r"\\.\pipe\router-service";

/// Windows service name (the short name shown in sc.exe / services.msc).
pub const SERVICE_NAME: &str = "RouterService";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdapterKind {
    Wifi,
    Ethernet,
    Cellular,
    Other,
}

/// A network adapter on this machine (Wi-Fi card, USB Wi-Fi, USB tethering, Ethernet...).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AdapterInfo {
    /// Persistent ID, e.g. "{4F6A...}". Rules are stored by this value;
    /// it stays the same even if the adapter's name or index changes.
    pub guid: String,
    pub if_index: u32,
    pub luid: u64,
    /// Name in Windows, e.g. "Wi-Fi 2".
    pub friendly_name: String,
    /// Hardware description, e.g. "Intel(R) Wi-Fi 6E AX211 160MHz".
    pub description: String,
    pub kind: AdapterKind,
    /// Physical (or USB) hardware? Used to tell virtual adapters apart.
    pub hardware: bool,
    pub connected: bool,
    /// Name of the connected Wi-Fi network.
    pub ssid: Option<String>,
    /// Wi-Fi signal quality, 0-100.
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
    /// With a default gateway, this adapter can reach the internet.
    pub fn has_internet_route(&self) -> bool {
        !self.gateways.is_empty()
    }

    /// First IPv4 gateway. The routing engine only carries IPv4 for now.
    pub fn ipv4_gateway(&self) -> Option<&str> {
        self.gateways
            .iter()
            .map(String::as_str)
            .find(|g| g.parse::<std::net::Ipv4Addr>().is_ok())
    }

    /// User-facing name: the friendly name, followed by the SSID (separated by a
    /// middle dot) when connected to Wi-Fi.
    pub fn display_name(&self) -> String {
        match &self.ssid {
            Some(ssid) => format!("{} · {}", self.friendly_name, ssid),
            None => self.friendly_name.clone(),
        }
    }
}

/// An app using the network (all processes of the same exe are merged into one entry).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppInfo {
    /// Lowercase exe name, e.g. "chrome.exe". This is the rule key.
    pub exe: String,
    pub path: Option<String>,
    pub pids: Vec<u32>,
    pub tcp_connections: u32,
    pub udp_endpoints: u32,
}

/// What to do when the chosen adapter is unplugged or disconnected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum Fallback {
    /// Use Windows' default internet connection.
    #[default]
    UseDefault,
    /// Cut the app off from the internet.
    Block,
}

/// A "send this app's traffic through this adapter" rule.
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
    /// `adapter_guid: None` deletes the rule (the app goes back to the default internet).
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

/// Normalizes an exe name for use as a rule key.
pub fn normalize_exe(name: &str) -> String {
    name.trim().to_lowercase()
}
