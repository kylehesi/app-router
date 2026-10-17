//! Giden soketleri belirli bir ağ adaptörüne bağlama.
//!
//! `IP_UNICAST_IF` / `IPV6_UNICAST_IF`, soketin hangi arayüzden çıkacağını
//! rota tablosundan bağımsız olarak belirler. Windows'un "strong host" modeli
//! sayesinde kaynak IP de o adaptörün IP'si olur.

use std::io;
use std::net::SocketAddr;
use std::os::windows::io::{AsRawSocket, RawSocket};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream, UdpSocket};
use windows_sys::Win32::Networking::WinSock::{
    setsockopt, WSAGetLastError, IPPROTO_IP, IPPROTO_IPV6, IPV6_UNICAST_IF, IP_UNICAST_IF,
    SOCKET, SOCKET_ERROR,
};

/// Soketin trafiğini `if_index` numaralı arayüzden çıkmaya zorlar.
pub fn set_unicast_interface(sock: RawSocket, ipv6: bool, if_index: u32) -> io::Result<()> {
    // IPv4'te index ağ bayt sırasında, IPv6'da makine sırasında verilir (MS dokümantasyonu).
    let (level, name, value) = if ipv6 {
        (IPPROTO_IPV6, IPV6_UNICAST_IF, if_index)
    } else {
        (IPPROTO_IP, IP_UNICAST_IF, if_index.to_be())
    };
    let ret = unsafe {
        setsockopt(
            sock as SOCKET,
            level,
            name,
            &value as *const u32 as *const u8,
            std::mem::size_of::<u32>() as i32,
        )
    };
    if ret == SOCKET_ERROR {
        return Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }));
    }
    Ok(())
}

/// `dst`'ye, yalnızca `if_index` adaptörü üzerinden TCP bağlantısı açar.
pub async fn connect_tcp(dst: SocketAddr, if_index: u32) -> io::Result<TcpStream> {
    let sock = if dst.is_ipv4() { TcpSocket::new_v4()? } else { TcpSocket::new_v6()? };
    set_unicast_interface(sock.as_raw_socket(), dst.is_ipv6(), if_index)?;
    let stream = sock.connect(dst).await?;
    stream.set_nodelay(true)?;
    Ok(stream)
}

/// `if_index` adaptöründen çıkan bir UDP soketi açar.
pub async fn bind_udp(ipv6: bool, if_index: u32) -> io::Result<UdpSocket> {
    let local: SocketAddr = if ipv6 { "[::]:0" } else { "0.0.0.0:0" }.parse().unwrap();
    let sock = UdpSocket::bind(local).await?;
    set_unicast_interface(sock.as_raw_socket(), ipv6, if_index)?;
    Ok(sock)
}

/// Seçilen adaptör üzerinden internete çıkıp dış (public) IPv4 adresini öğrenir.
/// Adaptör bağlamasının çalıştığını doğrulamak için kullanılır.
pub async fn public_ipv4_via(if_index: u32) -> io::Result<String> {
    const HOST: &str = "api.ipify.org";
    let fut = async {
        let dst = tokio::net::lookup_host((HOST, 80))
            .await?
            .find(SocketAddr::is_ipv4)
            .ok_or_else(|| io::Error::other("api.ipify.org için IPv4 adresi bulunamadı"))?;
        let mut s = connect_tcp(dst, if_index).await?;
        s.write_all(format!("GET / HTTP/1.1\r\nHost: {HOST}\r\nConnection: close\r\n\r\n").as_bytes())
            .await?;
        let mut resp = Vec::new();
        s.read_to_end(&mut resp).await?;
        let resp = String::from_utf8_lossy(&resp);
        let body = resp.split("\r\n\r\n").nth(1).unwrap_or_default().trim();
        if body.is_empty() {
            return Err(io::Error::other("boş yanıt"));
        }
        Ok(body.to_string())
    };
    tokio::time::timeout(Duration::from_secs(8), fut)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "zaman aşımı (8 sn)"))?
}
