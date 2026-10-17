//! Data path: TUN reader, TCP NAT relay and UDP sessions.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use anyhow::{Context, Result};
use router_sys::netcfg::{self, IpPrefix, RouteGuard};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::sync::mpsc::{self, error::TrySendError};
use tracing::{debug, info, warn};

use crate::bind;
use crate::nat::{NatEntry, TcpNat};
use crate::packet::{self, IPV4_HEADER_LEN, PROTO_TCP, PROTO_UDP, TCP_ACK, TCP_SYN, UDP_HEADER_LEN};
use crate::policy::{Flow, Policy, Proto, Route};
use crate::tun::Tun;

/// The TUN's own address. 198.18.0.0/15 is reserved for benchmarking (RFC 2544),
/// so it does not clash with home or office networks.
pub const TUN_IP: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 1);
/// The "peer" address that connects to the local listener in the NAT.
pub const PEER_IP: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 2);
pub const TUN_PREFIX_LEN: u8 = 30;
/// Large MTU: fewer, bigger packets on the app side means less CPU load.
/// These packets never leave the TUN; outbound connections use the adapter's own MTU.
pub const TUN_MTU: u32 = 9000;

/// The TUN's IPv6 address (ULA, RFC 4193). For IPv6 traffic to go out via the TUN,
/// Windows needs a source address on this interface.
pub const TUN_IP6: Ipv6Addr = Ipv6Addr::new(0xfd52, 0x6f75, 0x7465, 0, 0, 0, 0, 1);
const TUN_IP6_PREFIX_LEN: u8 = 64;

/// Routes that pull all traffic into the TUN. The two IPv4 /1 routes are more specific
/// than the default route (0.0.0.0/0), so they take precedence without deleting it. For
/// IPv6 the whole internet (2000::/3) is sent to the TUN and rejected: apps fall back to
/// IPv4, so no connection can bypass the rules over IPv6.
pub const FULL_TUNNEL: [IpPrefix; 3] = [
    IpPrefix::v4(Ipv4Addr::new(0, 0, 0, 0), 1),
    IpPrefix::v4(Ipv4Addr::new(128, 0, 0, 0), 1),
    IpPrefix::v6(Ipv6Addr::new(0x2000, 0, 0, 0, 0, 0, 0, 0), 3),
];

/// Is the destination in the TUN's own subnet (network/broadcast included)? Those never go to the internet.
fn in_tun_net(ip: &Ipv4Addr) -> bool {
    let mask = u32::MAX << (32 - TUN_PREFIX_LEN);
    u32::from(*ip) & mask == u32::from(TUN_IP) & mask
}

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const RELAY_BUF: usize = 64 * 1024;
/// How long a NAT entry is kept after the relay ends, for closing packets.
const NAT_LINGER: Duration = Duration::from_secs(5);
/// Lifetime of NAT entries still waiting to be accepted (unanswered).
const NAT_PENDING_TTL: Duration = Duration::from_secs(30);
const UDP_IDLE: Duration = Duration::from_secs(60);
const DNS_IDLE: Duration = Duration::from_secs(15);
const UDP_QUEUE: usize = 4096;
const UDP_SESSION_QUEUE: usize = 256;

pub struct EngineConfig {
    pub wintun_dll: PathBuf,
    /// Prefixes to route into the TUN; normally [`FULL_TUNNEL`].
    pub routes: Vec<IpPrefix>,
}

/// The running engine. On drop it removes the routes and closes the TUN.
pub struct Engine {
    routes: Option<RouteGuard>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    reader: Option<JoinHandle<()>>,
    tun: Tun,
    if_index: u32,
}

impl Engine {
    /// Opens and configures the TUN, starts the relay tasks, and adds the routes last:
    /// by the time a route exists, everything needed to handle the traffic is ready.
    pub async fn start(config: EngineConfig, policy: Arc<dyn Policy>) -> Result<Self> {
        let tun = Tun::open(&config.wintun_dll)?;
        let if_index = tun.if_index()?;
        netcfg::set_address(if_index, IpAddr::V4(TUN_IP), TUN_PREFIX_LEN)
            .context("failed to assign TUN address")?;
        netcfg::set_address(if_index, IpAddr::V6(TUN_IP6), TUN_IP6_PREFIX_LEN)
            .context("failed to assign TUN IPv6 address")?;
        if let Err(e) = netcfg::set_ipv4_mtu(if_index, TUN_MTU) {
            warn!("failed to set TUN MTU, using default: {e}");
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
        engine.routes = Some(netcfg::add_routes(if_index, &config.routes).context("failed to add routes")?);
        info!(if_index, %TUN_IP, listener_port, routes = ?config.routes, "engine started");
        Ok(engine)
    }

    /// Index of the TUN interface (to exclude it when picking the default adapter).
    pub fn if_index(&self) -> u32 {
        self.if_index
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        // Routes first: traffic immediately falls back to the regular adapters.
        drop(self.routes.take());
        for task in &self.tasks {
            task.abort();
        }
        self.tun.shutdown();
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
        info!("engine stopped");
    }
}

async fn bind_listener() -> Result<TcpListener> {
    let addr = SocketAddr::V4(SocketAddrV4::new(TUN_IP, 0));
    // A freshly assigned address may take a moment to become usable.
    let mut attempt = 0;
    loop {
        let sock = TcpSocket::new_v4()?;
        match sock.bind(addr) {
            Ok(()) => return Ok(sock.listen(4096)?),
            Err(e) if attempt < 30 => {
                debug!("listener could not bind yet: {e}");
                attempt += 1;
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(e) => return Err(e).context("failed to open TUN listener"),
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
    /// Reads packets from the TUN. TCP is rewritten in place here, before copying;
    /// UDP is handed off to the session tasks. Returns once `shutdown` is called.
    fn reader_loop(&self) {
        while let Ok(pkt) = self.session.receive_blocking() {
            let data = pkt.bytes();
            if data.first().is_some_and(|b| b >> 4 == 6) {
                // IPv6 is not carried yet: reject TCP immediately (the app falls back to
                // IPv4) and drop the rest (UDP/QUIC); browsers fall back to TCP.
                if let Some(rst) = packet::v6_tcp_rst(data) {
                    self.inject(rst.len(), |out| out.copy_from_slice(&rst));
                }
                continue;
            }
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
            // Listener to app: make it look like it came from the remote server.
            let Some(entry) = self.nat.inbound(dst.port()) else { return };
            (entry.dst, SocketAddrV4::new(TUN_IP, entry.app_port))
        } else if *src.ip() == TUN_IP && !in_tun_net(dst.ip()) {
            // App to outside: redirect to the local listener.
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
        if *src.ip() != TUN_IP
            || in_tun_net(dst.ip())
            || dst.ip().is_multicast()
            || dst.ip().is_broadcast()
        {
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
        // Drop if the queue is full: UDP is lossy anyway, and the reader must never block.
        let _ = self.udp_tx.try_send(datagram);
    }

    /// Delivers UDP data from the remote `from` address to the app.
    fn write_udp(&self, from: SocketAddrV4, app_port: u16, payload: &[u8]) {
        let len = IPV4_HEADER_LEN + UDP_HEADER_LEN + payload.len();
        if len > TUN_MTU as usize {
            return;
        }
        let id = self.ip_id.fetch_add(1, Ordering::Relaxed);
        let to = SocketAddrV4::new(TUN_IP, app_port);
        self.inject(len, |out| packet::write_v4_udp(out, id, from, to, payload));
    }

    /// Hands Windows a packet as if it "arrived" from the TUN.
    fn inject(&self, len: usize, fill: impl FnOnce(&mut [u8])) {
        let Ok(len) = u16::try_from(len) else { return };
        // If the send ring is full the packet is dropped; TCP retransmits.
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
                warn!("TUN listener error: {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let SocketAddr::V4(peer) = peer else { continue };
        if *peer.ip() != PEER_IP {
            continue; // connection that did not come through the NAT
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
        debug!(dst = %entry.dst, "TCP blocked");
        return;
    };
    let connect = tokio::time::timeout(CONNECT_TIMEOUT, bind::connect_tcp(entry.dst.into(), if_index));
    let mut outbound = match connect.await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            debug!(dst = %entry.dst, if_index, "connect failed: {e}");
            return;
        }
        Err(_) => {
            debug!(dst = %entry.dst, if_index, "connect timeout");
            return;
        }
    };
    let _ = inbound.set_nodelay(true);
    match tokio::io::copy_bidirectional_with_sizes(&mut inbound, &mut outbound, RELAY_BUF, RELAY_BUF)
        .await
    {
        Ok((up, down)) => debug!(dst = %entry.dst, if_index, up, down, "TCP closed"),
        Err(e) => debug!(dst = %entry.dst, if_index, "TCP relay ended: {e}"),
    }
}

/// Dispatches UDP packets to sessions by app port.
async fn udp_dispatch(shared: Arc<Shared>, policy: Arc<dyn Policy>, mut rx: mpsc::Receiver<UdpDatagram>) {
    let mut sessions: HashMap<u16, mpsc::Sender<UdpDatagram>> = HashMap::new();
    while let Some(datagram) = rx.recv().await {
        let port = datagram.app_port;
        let datagram = match sessions.get(&port) {
            Some(tx) => match tx.try_send(datagram) {
                Ok(()) | Err(TrySendError::Full(_)) => continue,
                Err(TrySendError::Closed(d)) => d, // session ended after idling; open a new one
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

/// UDP session for one app port. A single outbound socket is used per port
/// ("full cone"): the app can send to different destinations from the same port and
/// receives replies from anywhere. Games, QUIC and STUN expect this.
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
                debug!(app_port, if_index, "failed to open UDP socket: {e}");
                None
            }
        },
        Route::Block => None,
    };
    let Some(sock) = sock else {
        // Blocked session: swallow packets so we don't re-decide on every packet.
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
                // Errors (e.g. ICMP "port unreachable" -> WSAECONNRESET) don't end the session.
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
            debug!(removed, active = shared.nat.len(), "removed unanswered NAT entries");
        }
    }
}
