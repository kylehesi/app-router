//! Motorun "bu bağlantı hangi adaptörden çıksın?" sorusunu sorduğu arayüz.
//! Kuralların ve adaptör listesinin ayrıntısını servis bilir; motor bilmez.

use std::net::SocketAddrV4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proto {
    Tcp,
    Udp,
}

/// Uygulamanın açtığı bağlantı. `app` her zaman TUN adresindeki yerel uçtur.
#[derive(Debug, Clone, Copy)]
pub struct Flow {
    pub proto: Proto,
    pub app: SocketAddrV4,
    pub dst: SocketAddrV4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    /// Bu index'teki arayüzden çık.
    Interface(u32),
    /// Bağlantıyı reddet.
    Block,
}

pub trait Policy: Send + Sync + 'static {
    /// Engelleyen çağrılar yapabilir (süreç tablosu vb.); motor bunu ayrı bir iş
    /// parçacığında çağırır.
    fn route(&self, flow: &Flow) -> Route;
}
