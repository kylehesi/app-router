//! Yönlendirme motoru.
//!
//! ```text
//! uygulama ──► Wintun TUN (0.0.0.0/1 + 128.0.0.0/1) ──► tun-reader iş parçacığı
//!                                                          │
//!   TCP: "system stack" NAT. Paket yerinde yeniden yazılıp Windows'un kendi
//!        TCP yığınındaki yerel dinleyiciye verilir; TCP'yi Windows sonlandırır.
//!   UDP: uygulama portu başına bir oturum.
//!                                                          │
//!   Policy::route(flow) → hangi adaptör? (servis: soket → PID → exe → kural)
//!                                                          │
//!   giden soket: bind::connect_tcp / bind::bind_udp (IP_UNICAST_IF)
//!                → seçilen fiziksel adaptör. Bu soketler TUN'a geri dönmez.
//! ```

pub mod bind;
pub mod checksum;
pub mod nat;
pub mod packet;
pub mod policy;
mod stack;
pub mod tun;

pub use policy::{Flow, Policy, Proto, Route};
pub use stack::{Engine, EngineConfig, FULL_TUNNEL, PEER_IP, TUN_IP, TUN_MTU, TUN_PREFIX_LEN};
