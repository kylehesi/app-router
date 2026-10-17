//! TUN'dan okunan ham IP paketlerinin başlıklarını ayrıştırma.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;

#[derive(Debug, Clone, Copy)]
pub struct PacketInfo {
    pub protocol: u8,
    pub src: IpAddr,
    pub dst: IpAddr,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    /// IP başlığının bayt cinsinden uzunluğu (taşıma katmanının başladığı ofset).
    pub header_len: usize,
    pub total_len: usize,
}

/// IPv4 veya IPv6 paketini ayrıştırır. Bozuk/kısa paketlerde `None` döner.
/// IPv6 uzantı başlıkları atlanmaz; `protocol` ilk Next Header değeridir.
pub fn parse(p: &[u8]) -> Option<PacketInfo> {
    let (protocol, src, dst, header_len) = match p.first()? >> 4 {
        4 => {
            let ihl = usize::from(p[0] & 0x0f) * 4;
            if ihl < 20 || p.len() < ihl {
                return None;
            }
            let src = Ipv4Addr::new(p[12], p[13], p[14], p[15]);
            let dst = Ipv4Addr::new(p[16], p[17], p[18], p[19]);
            (p[9], IpAddr::V4(src), IpAddr::V4(dst), ihl)
        }
        6 => {
            if p.len() < 40 {
                return None;
            }
            let src: [u8; 16] = p[8..24].try_into().ok()?;
            let dst: [u8; 16] = p[24..40].try_into().ok()?;
            (p[6], IpAddr::V6(Ipv6Addr::from(src)), IpAddr::V6(Ipv6Addr::from(dst)), 40)
        }
        _ => return None,
    };

    let ports = matches!(protocol, PROTO_TCP | PROTO_UDP) && p.len() >= header_len + 4;
    let port_at = |off: usize| u16::from_be_bytes([p[header_len + off], p[header_len + off + 1]]);
    Some(PacketInfo {
        protocol,
        src,
        dst,
        src_port: ports.then(|| port_at(0)),
        dst_port: ports.then(|| port_at(2)),
        header_len,
        total_len: p.len(),
    })
}

impl fmt::Display for PacketInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let proto = match self.protocol {
            PROTO_TCP => "TCP".to_string(),
            PROTO_UDP => "UDP".to_string(),
            1 => "ICMP".to_string(),
            58 => "ICMPv6".to_string(),
            n => format!("proto={n}"),
        };
        match (self.src_port, self.dst_port) {
            (Some(sp), Some(dp)) => {
                write!(f, "{proto} {}:{sp} -> {}:{dp} ({} B)", self.src, self.dst, self.total_len)
            }
            _ => write!(f, "{proto} {} -> {} ({} B)", self.src, self.dst, self.total_len),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ipv4_udp() {
        let mut p = vec![0u8; 28];
        p[0] = 0x45;
        p[9] = PROTO_UDP;
        p[12..16].copy_from_slice(&[10, 0, 0, 1]);
        p[16..20].copy_from_slice(&[1, 1, 1, 1]);
        p[20..22].copy_from_slice(&5353u16.to_be_bytes());
        p[22..24].copy_from_slice(&53u16.to_be_bytes());
        let info = parse(&p).unwrap();
        assert_eq!(info.protocol, PROTO_UDP);
        assert_eq!(info.dst, IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));
        assert_eq!(info.src_port, Some(5353));
        assert_eq!(info.dst_port, Some(53));
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse(&[]).is_none());
        assert!(parse(&[0x45, 0, 0]).is_none());
        assert!(parse(&[0x60; 10]).is_none());
    }
}
