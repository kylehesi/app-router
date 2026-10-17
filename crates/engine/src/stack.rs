//! Veri yolu: TUN okuyucu, TCP NAT aktarma ve UDP oturumları.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use anyhow::{Context, Result};
use router_sys::netcfg::{self, Ipv4Prefix, RouteGuard};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::sync::mpsc::{self, error::TrySendError};
use tracing::{debug, info, warn};

use crate::bind;
use crate::nat::{NatEntry, TcpNat};
use crate::packet::{self, IPV4_HEADER_LEN, PROTO_TCP, PROTO_UDP, TCP_ACK, TCP_SYN, UDP_HEADER_LEN};
use crate::policy::{Flow, Policy, Proto, Route};
use crate::tun::Tun;

/// TUN'un kendi adresi. 198.18.0.0/15 kıyaslama testleri için ayrılmıştır (RFC 2544);
/// ev ve iş ağlarıyla çakışmaz.
pub const TUN_IP: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 1);
/// NAT'ta yerel dinleyiciye bağlanan "karşı taraf" adresi.
pub const PEER_IP: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 2);
pub const TUN_PREFIX_LEN: u8 = 30;
/// Büyük MTU: uygulama tarafında daha az ve daha büyük paket, daha az işlemci yükü.
/// Bu paketler TUN'dan dışarı çıkmaz; dış bağlantılar adaptörün kendi MTU'sunu kullanır.
pub const TUN_MTU: u32 = 9000;

/// Tüm IPv4 trafiğini TUN'a alan iki rota. Varsayılan rotadan (0.0.0.0/0) daha
/// özel oldukları için onu silmeden önce gelirler.
pub const FULL_TUNNEL: [Ipv4Prefix; 2] = [
    Ipv4Prefix::new(Ipv4Addr::new(0, 0, 0, 0), 1),
    Ipv4Prefix::new(Ipv4Addr::new(128, 0, 0, 0), 1),
];

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const RELAY_BUF: usize = 64 * 1024;
/// Aktarma bittikten sonra kapanış paketleri için NAT kaydının tutulduğu süre.
const NAT_LINGER: Duration = Duration::from_secs(5);
/// Kabul edilmeden bekleyen (cevapsız) NAT kayıtlarının ömrü.
const NAT_PENDING_TTL: Duration = Duration::from_secs(30);
const UDP_IDLE: Duration = Duration::from_secs(60);
const DNS_IDLE: Duration = Duration::from_secs(15);
const UDP_QUEUE: usize = 4096;
const UDP_SESSION_QUEUE: usize = 256;

pub struct EngineConfig {
    pub wintun_dll: PathBuf,
    /// TUN'a yönlendirilecek ön ekler; normal kullanımda [`FULL_TUNNEL`].
    pub routes: Vec<Ipv4Prefix>,
}

/// Çalışan motor. Düşürüldüğünde (drop) rotaları kaldırır ve TUN'u kapatır.
pub struct Engine {
    routes: Option<RouteGuard>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    reader: Option<JoinHandle<()>>,
    tun: Tun,
    if_index: u32,
}

impl Engine {
    /// TUN'u açar ve yapılandırır, aktarma görevlerini başlatır, en son da rotaları
    /// ekler: rota eklendiği anda trafiği karşılayacak her şey hazırdır.
    pub async fn start(config: EngineConfig, policy: Arc<dyn Policy>) -> Result<Self> {
        let tun = Tun::open(&config.wintun_dll)?;
        let if_index = tun.if_index()?;
        netcfg::set_ipv4_address(if_index, TUN_IP, TUN_PREFIX_LEN)
            .context("TUN adresi atanamadı")?;
        if let Err(e) = netcfg::set_ipv4_mtu(if_index, TUN_MTU) {
            warn!("TUN MTU ayarlanamadı, varsayılan kullanılacak: {e}");
        }

        let listener = bind_listener().await?;
        let listener_port = listener.local_addr()?.port();
        let (udp_tx, udp_rx) = mpsc::channel(UDP_QUEUE);
        let shared = Arc::new(Shared {
            session: tun.session(),
            nat: TcpNat::default(),
            listener_port,
            udp_tx,
            ip_id: AtomicU16::new(1),
        });

        let reader = std::thread::Builder::new().name("tun-reader".into()).spawn({
            let shared = shared.clone();
            move || shared.reader_loop()
        })?;
        let tasks = vec![
            tokio::spawn(tcp_accept_loop(shared.clone(), policy.clone(), listener)),
            tokio::spawn(udp_dispatch(shared.clone(), policy, udp_rx)),
            tokio::spawn(nat_sweeper(shared)),
        ];

        let mut engine = Self { routes: None, tasks, reader: Some(reader), tun, if_index };
        engine.routes = Some(netcfg::add_routes(if_index, &config.routes).context("rotalar eklenemedi")?);
        info!(if_index, %TUN_IP, listener_port, routes = ?config.routes, "motor başladı");
        Ok(engine)
    }

    /// TUN arayüzünün index'i (varsayılan adaptör seçiminde hariç tutmak için).
    pub fn if_index(&self) -> u32 {
        self.if_index
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        // Önce rotalar: trafik hemen normal adaptörlere döner.
        drop(self.routes.take());
        for task in &self.tasks {
            task.abort();
        }
        self.tun.shutdown();
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
        info!("motor durdu");
    }
}

async fn bind_listener() -> Result<TcpListener> {
    let addr = SocketAddr::V4(SocketAddrV4::new(TUN_IP, 0));
    // Adres yeni atandıysa kullanılabilir olması kısa sürebilir.
    let mut attempt = 0;
    loop {
        let sock = TcpSocket::new_v4()?;
        match sock.bind(addr) {
            Ok(()) => return Ok(sock.listen(4096)?),
            Err(e) if attempt < 30 => {
                debug!("dinleyici henüz bağlanamadı: {e}");
                attempt += 1;
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(e) => return Err(e).context("TUN dinleyicisi açılamadı"),
        }
    }
}

struct UdpDatagram {
    app_port: u16,
    dst: SocketAddrV4,
    payload: Vec<u8>,
}

struct Shared {
    session: Arc<wintun::Session>,
    nat: TcpNat,
    listener_port: u16,
    udp_tx: mpsc::Sender<UdpDatagram>,
    ip_id: AtomicU16,
}

impl Shared {
    /// TUN'dan paket okur. TCP burada, kopyalamadan önce yerinde yeniden yazılır;
    /// UDP, oturum görevlerine aktarılır. `shutdown` çağrılınca biter.
    fn reader_loop(&self) {
        while let Ok(pkt) = self.session.receive_blocking() {
            let data = pkt.bytes();
            // Faz 2: yalnızca IPv4. IPv6 trafiği TUN'a yönlendirilmez.
            if data.len() < IPV4_HEADER_LEN || data[0] >> 4 != 4 || packet::is_v4_fragment(data) {
                continue;
            }
            let Some(info) = packet::parse(data) else { continue };
            let (IpAddr::V4(src_ip), IpAddr::V4(dst_ip)) = (info.src, info.dst) else { continue };
            let (Some(src_port), Some(dst_port)) = (info.src_port, info.dst_port) else { continue };
            let src = SocketAddrV4::new(src_ip, src_port);
            let dst = SocketAddrV4::new(dst_ip, dst_port);
            match info.protocol {
                PROTO_TCP => self.handle_tcp(data, info.header_len, src, dst),
                PROTO_UDP => self.handle_udp(data, info.header_len, src, dst),
                _ => {}
            }
        }
    }

    fn handle_tcp(&self, data: &[u8], ihl: usize, src: SocketAddrV4, dst: SocketAddrV4) {
        if data.len() < ihl + 20 {
            return;
        }
        let (new_src, new_dst) = if *src.ip() == TUN_IP
            && src.port() == self.listener_port
            && *dst.ip() == PEER_IP
        {
            // Dinleyiciden uygulamaya: uzak sunucudan geliyormuş gibi göster.
            let Some(entry) = self.nat.inbound(dst.port()) else { return };
            (entry.dst, SocketAddrV4::new(TUN_IP, entry.app_port))
        } else if *src.ip() == TUN_IP {
            // Uygulamadan dışarı: yerel dinleyiciye çevir.
            let flags = data[ihl + 13];
            let syn = flags & TCP_SYN != 0 && flags & TCP_ACK == 0;
            let Some(nat_port) = self.nat.outbound(src.port(), dst, syn) else { return };
            (SocketAddrV4::new(PEER_IP, nat_port), SocketAddrV4::new(TUN_IP, self.listener_port))
        } else {
            return;
        };
        self.inject(data.len(), |out| {
            out.copy_from_slice(data);
            packet::rewrite_v4_tcp(out, ihl, new_src, new_dst);
        });
    }

    fn handle_udp(&self, data: &[u8], ihl: usize, src: SocketAddrV4, dst: SocketAddrV4) {
        if *src.ip() != TUN_IP || dst.ip().is_multicast() || dst.ip().is_broadcast() {
            return;
        }
        if data.len() < ihl + UDP_HEADER_LEN {
            return;
        }
        let udp_len = usize::from(u16::from_be_bytes([data[ihl + 4], data[ihl + 5]]));
        let end = (ihl + udp_len).min(data.len());
        if end < ihl + UDP_HEADER_LEN {
            return;
        }
        let datagram = UdpDatagram {
            app_port: src.port(),
            dst,
            payload: data[ihl + UDP_HEADER_LEN..end].to_vec(),
        };
        // Kuyruk doluysa düşür: UDP zaten kayıplı bir protokoldür, okuyucu asla beklememeli.
        let _ = self.udp_tx.try_send(datagram);
    }

    /// Uzak `from` adresinden gelen UDP verisini uygulamaya teslim eder.
    fn write_udp(&self, from: SocketAddrV4, app_port: u16, payload: &[u8]) {
        let len = IPV4_HEADER_LEN + UDP_HEADER_LEN + payload.len();
        if len > TUN_MTU as usize {
            return;
        }
        let id = self.ip_id.fetch_add(1, Ordering::Relaxed);
        let to = SocketAddrV4::new(TUN_IP, app_port);
        self.inject(len, |out| packet::write_v4_udp(out, id, from, to, payload));
    }

    /// Windows'a TUN'dan "gelen" bir paket teslim eder.
    fn inject(&self, len: usize, fill: impl FnOnce(&mut [u8])) {
        let Ok(len) = u16::try_from(len) else { return };
        // Gönderme halkası doluysa paket düşer; TCP yeniden gönderir.
        if let Ok(mut out) = self.session.allocate_send_packet(len) {
            fill(out.bytes_mut());
            self.session.send_packet(out);
        }
    }
}

async fn decide(policy: &Arc<dyn Policy>, flow: Flow) -> Route {
    let policy = policy.clone();
    tokio::task::spawn_blocking(move || policy.route(&flow))
        .await
        .unwrap_or(Route::Block)
}

async fn tcp_accept_loop(shared: Arc<Shared>, policy: Arc<dyn Policy>, listener: TcpListener) {
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                warn!("TUN dinleyicisi hata verdi: {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let SocketAddr::V4(peer) = peer else { continue };
        if *peer.ip() != PEER_IP {
            continue; // NAT dışından gelen bağlantı
        }
        let Some(entry) = shared.nat.activate(peer.port()) else { continue };
        let (shared, policy) = (shared.clone(), policy.clone());
        tokio::spawn(async move {
            relay_tcp(&policy, stream, entry).await;
            tokio::time::sleep(NAT_LINGER).await;
            shared.nat.remove(peer.port());
        });
    }
}

async fn relay_tcp(policy: &Arc<dyn Policy>, mut inbound: TcpStream, entry: NatEntry) {
    let flow = Flow {
        proto: Proto::Tcp,
        app: SocketAddrV4::new(TUN_IP, entry.app_port),
        dst: entry.dst,
    };
    let Route::Interface(if_index) = decide(policy, flow).await else {
        debug!(dst = %entry.dst, "TCP engellendi");
        return;
    };
    let connect = tokio::time::timeout(CONNECT_TIMEOUT, bind::connect_tcp(entry.dst.into(), if_index));
    let mut outbound = match connect.await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            debug!(dst = %entry.dst, if_index, "bağlanılamadı: {e}");
            return;
        }
        Err(_) => {
            debug!(dst = %entry.dst, if_index, "bağlantı zaman aşımı");
            return;
        }
    };
    let _ = inbound.set_nodelay(true);
    match tokio::io::copy_bidirectional_with_sizes(&mut inbound, &mut outbound, RELAY_BUF, RELAY_BUF)
        .await
    {
        Ok((up, down)) => debug!(dst = %entry.dst, if_index, up, down, "TCP kapandı"),
        Err(e) => debug!(dst = %entry.dst, if_index, "TCP aktarma bitti: {e}"),
    }
}

/// UDP paketlerini uygulama portuna göre oturumlara dağıtır.
async fn udp_dispatch(shared: Arc<Shared>, policy: Arc<dyn Policy>, mut rx: mpsc::Receiver<UdpDatagram>) {
    let mut sessions: HashMap<u16, mpsc::Sender<UdpDatagram>> = HashMap::new();
    while let Some(datagram) = rx.recv().await {
        let port = datagram.app_port;
        let datagram = match sessions.get(&port) {
            Some(tx) => match tx.try_send(datagram) {
                Ok(()) | Err(TrySendError::Full(_)) => continue,
                Err(TrySendError::Closed(d)) => d, // oturum boşta kalıp bitmiş; yenisini aç
            },
            None => datagram,
        };
        let (tx, session_rx) = mpsc::channel(UDP_SESSION_QUEUE);
        let _ = tx.try_send(datagram);
        if sessions.len() >= 1024 {
            sessions.retain(|_, tx| !tx.is_closed());
        }
        sessions.insert(port, tx);
        tokio::spawn(udp_session(shared.clone(), policy.clone(), port, session_rx));
    }
}

/// Bir uygulama portunun UDP oturumu. Port başına tek giden soket kullanılır
/// ("full cone"): uygulama aynı porttan farklı hedeflere gönderebilir, her yerden
/// gelen cevabı alır. Oyunlar, QUIC ve STUN bunu bekler.
async fn udp_session(
    shared: Arc<Shared>,
    policy: Arc<dyn Policy>,
    app_port: u16,
    mut rx: mpsc::Receiver<UdpDatagram>,
) {
    let Some(first) = rx.recv().await else { return };
    let idle = if first.dst.port() == 53 { DNS_IDLE } else { UDP_IDLE };
    let flow = Flow {
        proto: Proto::Udp,
        app: SocketAddrV4::new(TUN_IP, app_port),
        dst: first.dst,
    };
    let sock = match decide(&policy, flow).await {
        Route::Interface(if_index) => match bind::bind_udp(false, if_index).await {
            Ok(sock) => Some(sock),
            Err(e) => {
                debug!(app_port, if_index, "UDP soketi açılamadı: {e}");
                None
            }
        },
        Route::Block => None,
    };
    let Some(sock) = sock else {
        // Engellenen oturum: paketleri yut, her pakette yeniden karar verilmesin.
        while let Ok(Some(_)) = tokio::time::timeout(idle, rx.recv()).await {}
        return;
    };

    let _ = sock.send_to(&first.payload, first.dst).await;
    let mut buf = vec![0u8; 65_535];
    loop {
        tokio::select! {
            datagram = rx.recv() => match datagram {
                Some(d) => { let _ = sock.send_to(&d.payload, d.dst).await; }
                None => return,
            },
            received = sock.recv_from(&mut buf) => {
                // Hata (örn. ICMP "port kapalı" → WSAECONNRESET) oturumu bitirmez.
                if let Ok((n, SocketAddr::V4(from))) = received {
                    shared.write_udp(from, app_port, &buf[..n]);
                }
            }
            _ = tokio::time::sleep(idle) => return,
        }
    }
}

async fn nat_sweeper(shared: Arc<Shared>) {
    let mut tick = tokio::time::interval(Duration::from_secs(10));
    loop {
        tick.tick().await;
        let removed = shared.nat.expire(NAT_PENDING_TTL);
        if removed > 0 {
            debug!(removed, active = shared.nat.len(), "cevapsız NAT kayıtları silindi");
        }
    }
}
