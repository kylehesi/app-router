//! TUN'dan okunan ham IP paketlerinin başlıklarını ayrıştırma.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddrV4};

use crate::checksum;

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

pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_ACK: u8 = 0x10;

pub const IPV4_HEADER_LEN: usize = 20;
pub const UDP_HEADER_LEN: usize = 8;

/// Paket bir IPv4 parçası mı (fragment)? Parçalar yeniden birleştirilmeden işlenemez.
pub fn is_v4_fragment(p: &[u8]) -> bool {
    // bayrak/ofset alanı: MF biti (0x2000) veya sıfır olmayan ofset (alt 13 bit)
    p.len() >= 8 && (u16::from_be_bytes([p[6], p[7]]) & 0x3fff) != 0
}

/// IPv4 TCP paketinin kaynak/hedef adres ve portlarını değiştirir; IP ve TCP
/// sağlama toplamlarını artımlı olarak günceller. `ihl`: IP başlığı uzunluğu.
/// Çağıran, `pkt.len() >= ihl + 20` olduğunu garanti etmelidir.
pub fn rewrite_v4_tcp(pkt: &mut [u8], ihl: usize, src: SocketAddrV4, dst: SocketAddrV4) {
    let mut old_addrs = [0u8; 8];
    old_addrs.copy_from_slice(&pkt[12..20]);
    let mut new_addrs = [0u8; 8];
    new_addrs[..4].copy_from_slice(&src.ip().octets());
    new_addrs[4..].copy_from_slice(&dst.ip().octets());

    let t = ihl;
    let mut old_ports = [0u8; 4];
    old_ports.copy_from_slice(&pkt[t..t + 4]);
    let mut new_ports = [0u8; 4];
    new_ports[..2].copy_from_slice(&src.port().to_be_bytes());
    new_ports[2..].copy_from_slice(&dst.port().to_be_bytes());

    let ip_check = u16::from_be_bytes([pkt[10], pkt[11]]);
    let ip_check = checksum::update(ip_check, &old_addrs, &new_addrs);

    // TCP sağlama toplamı sözde başlıktaki adresleri de kapsar.
    let tcp_check = u16::from_be_bytes([pkt[t + 16], pkt[t + 17]]);
    let tcp_check = checksum::update(tcp_check, &old_addrs, &new_addrs);
    let tcp_check = checksum::update(tcp_check, &old_ports, &new_ports);

    pkt[10..12].copy_from_slice(&ip_check.to_be_bytes());
    pkt[12..20].copy_from_slice(&new_addrs);
    pkt[t..t + 4].copy_from_slice(&new_ports);
    pkt[t + 16..t + 18].copy_from_slice(&tcp_check.to_be_bytes());
}

/// `out` içine eksiksiz bir IPv4/UDP paketi yazar. `out.len()`,
/// `IPV4_HEADER_LEN + UDP_HEADER_LEN + payload.len()` olmalıdır.
pub fn write_v4_udp(out: &mut [u8], id: u16, src: SocketAddrV4, dst: SocketAddrV4, payload: &[u8]) {
    let total = out.len();
    debug_assert_eq!(total, IPV4_HEADER_LEN + UDP_HEADER_LEN + payload.len());
    let udp_len = (UDP_HEADER_LEN + payload.len()) as u16;
    let (ip, rest) = out.split_at_mut(IPV4_HEADER_LEN);
    let (udp, data) = rest.split_at_mut(UDP_HEADER_LEN);

    ip[0] = 0x45; // IPv4, 20 baytlık başlık
    ip[1] = 0;
    ip[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    ip[4..6].copy_from_slice(&id.to_be_bytes());
    ip[6..8].copy_from_slice(&[0x40, 0]); // DF
    ip[8] = 64; // TTL
    ip[9] = PROTO_UDP;
    ip[10..12].fill(0);
    ip[12..16].copy_from_slice(&src.ip().octets());
    ip[16..20].copy_from_slice(&dst.ip().octets());
    let ip_check = checksum::finish(checksum::add(0, ip));
    ip[10..12].copy_from_slice(&ip_check.to_be_bytes());

    udp[0..2].copy_from_slice(&src.port().to_be_bytes());
    udp[2..4].copy_from_slice(&dst.port().to_be_bytes());
    udp[4..6].copy_from_slice(&udp_len.to_be_bytes());
    udp[6..8].fill(0);
    data.copy_from_slice(payload);

    let acc = checksum::pseudo_v4(src.ip().octets(), dst.ip().octets(), PROTO_UDP, udp_len);
    let acc = checksum::add(checksum::add(acc, udp), data);
    // UDP'de 0 "sağlama toplamı yok" demektir; hesaplanan 0 değeri 0xffff olarak yazılır.
    let udp_check = match checksum::finish(acc) {
        0 => 0xffff,
        c => c,
    };
    udp[6..8].copy_from_slice(&udp_check.to_be_bytes());
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

    /// Sağlama toplamları doğru olan örnek bir IPv4 TCP SYN paketi.
    fn tcp_syn(src: SocketAddrV4, dst: SocketAddrV4) -> Vec<u8> {
        let mut p = vec![0u8; 40];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&40u16.to_be_bytes());
        p[8] = 128;
        p[9] = PROTO_TCP;
        p[12..16].copy_from_slice(&src.ip().octets());
        p[16..20].copy_from_slice(&dst.ip().octets());
        let ip_check = checksum::finish(checksum::add(0, &p[..20]));
        p[10..12].copy_from_slice(&ip_check.to_be_bytes());
        p[20..22].copy_from_slice(&src.port().to_be_bytes());
        p[22..24].copy_from_slice(&dst.port().to_be_bytes());
        p[24..28].copy_from_slice(&0x1234_5678u32.to_be_bytes());
        p[32] = 0x50; // veri ofseti: 5 kelime
        p[33] = TCP_SYN;
        p[34..36].copy_from_slice(&64240u16.to_be_bytes());
        fix_tcp_checksum(&mut p);
        p
    }

    fn fix_tcp_checksum(p: &mut [u8]) {
        p[36..38].fill(0);
        let c = full_tcp_checksum(p);
        p[36..38].copy_from_slice(&c.to_be_bytes());
    }

    fn full_tcp_checksum(p: &[u8]) -> u16 {
        let src: [u8; 4] = p[12..16].try_into().unwrap();
        let dst: [u8; 4] = p[16..20].try_into().unwrap();
        let mut tcp = p[20..].to_vec();
        tcp[16..18].fill(0);
        let acc = checksum::pseudo_v4(src, dst, PROTO_TCP, tcp.len() as u16);
        checksum::finish(checksum::add(acc, &tcp))
    }

    fn addr(s: &str) -> SocketAddrV4 {
        s.parse().unwrap()
    }

    #[test]
    fn tcp_rewrite_keeps_checksums_valid() {
        let mut p = tcp_syn(addr("198.18.0.1:50000"), addr("142.250.187.14:443"));
        rewrite_v4_tcp(&mut p, 20, addr("198.18.0.2:10000"), addr("198.18.0.1:61234"));

        let info = parse(&p).unwrap();
        assert_eq!(info.src, IpAddr::V4(Ipv4Addr::new(198, 18, 0, 2)));
        assert_eq!(info.dst_port, Some(61234));
        // IP başlığının toplamı (sağlama toplamı dahil) geçerliyse 0 çıkar.
        assert_eq!(checksum::finish(checksum::add(0, &p[..20])), 0);
        assert_eq!(u16::from_be_bytes([p[36], p[37]]), full_tcp_checksum(&p));
        // Sıra numarası ve bayraklar korunur.
        assert_eq!(&p[24..28], &0x1234_5678u32.to_be_bytes());
        assert_eq!(p[33], TCP_SYN);
    }

    #[test]
    fn udp_builder_produces_valid_packet() {
        let payload = b"merhaba";
        let mut out = vec![0u8; IPV4_HEADER_LEN + UDP_HEADER_LEN + payload.len()];
        write_v4_udp(&mut out, 7, addr("1.1.1.1:53"), addr("198.18.0.1:5353"), payload);

        let info = parse(&out).unwrap();
        assert_eq!(info.protocol, PROTO_UDP);
        assert_eq!(info.src_port, Some(53));
        assert_eq!(checksum::finish(checksum::add(0, &out[..20])), 0);
        let acc = checksum::pseudo_v4([1, 1, 1, 1], [198, 18, 0, 1], PROTO_UDP, 15);
        assert_eq!(checksum::finish(checksum::add(acc, &out[20..])), 0);
        assert_eq!(&out[28..], payload);
    }

    #[test]
    fn detects_fragments() {
        let mut p = tcp_syn(addr("198.18.0.1:1"), addr("1.1.1.1:2"));
        assert!(!is_v4_fragment(&p));
        p[6] = 0x20; // MF
        assert!(is_v4_fragment(&p));
        p[6] = 0x40; // yalnızca DF
        assert!(!is_v4_fragment(&p));
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse(&[]).is_none());
        assert!(parse(&[0x45, 0, 0]).is_none());
        assert!(parse(&[0x60; 10]).is_none());
    }
}
