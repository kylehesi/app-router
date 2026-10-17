//! TCP NAT tablosu ("system stack").
//!
//! An app's `TUN_IP:app_port -> destination` connection is redirected to a local
//! listener on Windows' own TCP stack as `PEER_IP:nat_port -> TUN_IP:listener`.
//! When the listener accepts it, `nat_port` maps back to the original destination;
//! the listener's replies are translated back through the same table.

use std::collections::HashMap;
use std::net::SocketAddrV4;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const PORT_FIRST: u16 = 10_000;
const PORT_LAST: u16 = 65_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NatEntry {
    pub app_port: u16,
    pub dst: SocketAddrV4,
}

struct Slot {
    entry: NatEntry,
    /// The listener accepted the connection and the relay is running; never expired.
    active: bool,
    last_seen: Instant,
}

#[derive(Default)]
struct Inner {
    by_app: HashMap<(u16, SocketAddrV4), u16>,
    by_nat: HashMap<u16, Slot>,
    next: u16,
}

#[derive(Default)]
pub struct TcpNat {
    inner: Mutex<Inner>,
}

impl TcpNat {
    /// Returns the NAT port for a packet leaving the app. An entry is created only
    /// when a new connection opens (`syn`); other packets of an unknown connection
    /// get `None`.
    pub fn outbound(&self, app_port: u16, dst: SocketAddrV4, syn: bool) -> Option<u16> {
        let mut g = self.inner.lock().unwrap();
        let inner = &mut *g;
        if let Some(&port) = inner.by_app.get(&(app_port, dst)) {
            if let Some(slot) = inner.by_nat.get_mut(&port) {
                slot.last_seen = Instant::now();
            }
            return Some(port);
        }
        if !syn {
            return None;
        }
        let port = inner.allocate()?;
        inner.by_app.insert((app_port, dst), port);
        inner.by_nat.insert(
            port,
            Slot {
                entry: NatEntry { app_port, dst },
                active: false,
                last_seen: Instant::now(),
            },
        );
        Some(port)
    }

    /// Looks up the original connection for a packet going from the listener back to the app.
    pub fn inbound(&self, nat_port: u16) -> Option<NatEntry> {
        let mut g = self.inner.lock().unwrap();
        let slot = g.by_nat.get_mut(&nat_port)?;
        slot.last_seen = Instant::now();
        Some(slot.entry)
    }

    /// Called when the listener accepts the connection; marks the entry active.
    pub fn activate(&self, nat_port: u16) -> Option<NatEntry> {
        let mut g = self.inner.lock().unwrap();
        let slot = g.by_nat.get_mut(&nat_port)?;
        slot.active = true;
        Some(slot.entry)
    }

    pub fn remove(&self, nat_port: u16) {
        let mut g = self.inner.lock().unwrap();
        if let Some(slot) = g.by_nat.remove(&nat_port) {
            g.by_app.remove(&(slot.entry.app_port, slot.entry.dst));
        }
    }

    /// Removes entries that waited `idle` without being accepted (unanswered SYNs).
    pub fn expire(&self, idle: Duration) -> usize {
        let mut g = self.inner.lock().unwrap();
        let now = Instant::now();
        let stale: Vec<u16> = g
            .by_nat
            .iter()
            .filter(|(_, s)| !s.active && now.duration_since(s.last_seen) > idle)
            .map(|(&p, _)| p)
            .collect();
        for port in &stale {
            if let Some(slot) = g.by_nat.remove(port) {
                g.by_app.remove(&(slot.entry.app_port, slot.entry.dst));
            }
        }
        stale.len()
    }

    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().by_nat.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Inner {
    /// Next free NAT port; `None` if the range is exhausted.
    fn allocate(&mut self) -> Option<u16> {
        let span = u32::from(PORT_LAST - PORT_FIRST) + 1;
        for _ in 0..span {
            if self.next < PORT_FIRST || self.next > PORT_LAST {
                self.next = PORT_FIRST;
            }
            let port = self.next;
            self.next = self.next.wrapping_add(1);
            if !self.by_nat.contains_key(&port) {
                return Some(port);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dst() -> SocketAddrV4 {
        "93.184.216.34:443".parse().unwrap()
    }

    #[test]
    fn syn_creates_entry_and_lookups_agree() {
        let nat = TcpNat::default();
        assert_eq!(nat.outbound(50000, dst(), false), None, "a packet without SYN must not create an entry");
        let port = nat.outbound(50000, dst(), true).unwrap();
        assert_eq!(nat.outbound(50000, dst(), false), Some(port));
        assert_eq!(nat.inbound(port), Some(NatEntry { app_port: 50000, dst: dst() }));
        assert_eq!(nat.activate(port).unwrap().app_port, 50000);
        nat.remove(port);
        assert!(nat.is_empty());
        assert_eq!(nat.outbound(50000, dst(), false), None);
    }

    #[test]
    fn distinct_connections_get_distinct_ports() {
        let nat = TcpNat::default();
        let a = nat.outbound(50000, dst(), true).unwrap();
        let b = nat.outbound(50001, dst(), true).unwrap();
        let c = nat.outbound(50000, "1.1.1.1:443".parse().unwrap(), true).unwrap();
        assert!(a != b && b != c && a != c);
    }

    #[test]
    fn expire_keeps_active_connections() {
        let nat = TcpNat::default();
        let pending = nat.outbound(1, dst(), true).unwrap();
        let active = nat.outbound(2, dst(), true).unwrap();
        nat.activate(active);
        assert_eq!(nat.expire(Duration::ZERO), 1);
        assert_eq!(nat.inbound(pending), None);
        assert!(nat.inbound(active).is_some());
    }
}
