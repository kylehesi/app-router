//! Yönlendirme motoru.
//!
//! Hedef veri yolu (Faz 2'de tamamlanacak):
//!
//! ```text
//! uygulama ──► Wintun TUN (varsayılan rota) ──► paket okuyucu
//!                                                  │
//!     TCP: "system stack" NAT — paket TUN adresindeki yerel dinleyiciye
//!          yönlendirilir, TCP'yi Windows'un kendi yığını sonlandırır
//!          (pencereleme, tıkanıklık kontrolü vb. Windows'ta kalır).
//!     UDP: oturum tablosu üzerinden doğrudan aktarma.
//!                                                  │
//!     sahip süreç: router_sys::processes ile 5'li → PID → exe → kural
//!                                                  │
//!     giden soket: bind::connect_tcp / bind::bind_udp (IP_UNICAST_IF)
//!                  → seçilen fiziksel adaptör. Bu soketler TUN'a geri dönmez.
//! ```

pub mod bind;
pub mod packet;
pub mod tun;
