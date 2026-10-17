//! Arayüz yapılandırması: IPv4 adresi, MTU ve rotalar (IP Helper API).
//! Hepsi yönetici yetkisi gerektirir.

use std::io;
use std::net::Ipv4Addr;

use windows_sys::Win32::Foundation::{ERROR_NOT_FOUND, ERROR_OBJECT_ALREADY_EXISTS, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    ConvertInterfaceIndexToLuid, CreateIpForwardEntry2, CreateUnicastIpAddressEntry,
    DeleteIpForwardEntry2, GetIpInterfaceEntry, InitializeIpForwardEntry,
    InitializeIpInterfaceEntry, InitializeUnicastIpAddressEntry, SetIpInterfaceEntry,
    MIB_IPFORWARD_ROW2, MIB_IPINTERFACE_ROW, MIB_UNICASTIPADDRESS_ROW,
};
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::Win32::Networking::WinSock::{AF_INET, SOCKADDR_IN};

use crate::util::win32_err;

const IP_DAD_STATE_PREFERRED: i32 = 4;
const MIB_IPPROTO_NETMGMT: i32 = 3;

/// IPv4 ön eki, örn. 0.0.0.0/1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Prefix {
    pub addr: Ipv4Addr,
    pub len: u8,
}

impl Ipv4Prefix {
    pub const fn new(addr: Ipv4Addr, len: u8) -> Self {
        Self { addr, len }
    }
}

impl std::fmt::Display for Ipv4Prefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.len)
    }
}

fn luid_of(if_index: u32) -> io::Result<NET_LUID_LH> {
    let mut luid: NET_LUID_LH = unsafe { std::mem::zeroed() };
    match unsafe { ConvertInterfaceIndexToLuid(if_index, &mut luid) } {
        NO_ERROR => Ok(luid),
        e => Err(win32_err(e)),
    }
}

fn sockaddr_in(ip: Ipv4Addr) -> SOCKADDR_IN {
    let mut s: SOCKADDR_IN = unsafe { std::mem::zeroed() };
    s.sin_family = AF_INET;
    s.sin_addr.S_un.S_addr = u32::from_ne_bytes(ip.octets());
    s
}

/// Arayüze IPv4 adresi atar (zaten varsa dokunmaz). DAD beklenmez: adres hemen kullanılabilir.
pub fn set_ipv4_address(if_index: u32, ip: Ipv4Addr, prefix_len: u8) -> io::Result<()> {
    let mut row: MIB_UNICASTIPADDRESS_ROW = unsafe { std::mem::zeroed() };
    unsafe { InitializeUnicastIpAddressEntry(&mut row) };
    row.InterfaceLuid = luid_of(if_index)?;
    row.Address.Ipv4 = sockaddr_in(ip);
    row.OnLinkPrefixLength = prefix_len;
    row.DadState = IP_DAD_STATE_PREFERRED;
    match unsafe { CreateUnicastIpAddressEntry(&row) } {
        NO_ERROR | ERROR_OBJECT_ALREADY_EXISTS => Ok(()),
        e => Err(win32_err(e)),
    }
}

/// Arayüzün IPv4 MTU değerini ayarlar.
pub fn set_ipv4_mtu(if_index: u32, mtu: u32) -> io::Result<()> {
    let mut row: MIB_IPINTERFACE_ROW = unsafe { std::mem::zeroed() };
    unsafe { InitializeIpInterfaceEntry(&mut row) };
    row.Family = AF_INET;
    row.InterfaceLuid = luid_of(if_index)?;
    match unsafe { GetIpInterfaceEntry(&mut row) } {
        NO_ERROR => {}
        e => return Err(win32_err(e)),
    }
    row.NlMtu = mtu;
    // IPv4'te SitePrefixLength 0 olmalı, yoksa SetIpInterfaceEntry ERROR_INVALID_PARAMETER döner.
    row.SitePrefixLength = 0;
    match unsafe { SetIpInterfaceEntry(&mut row) } {
        NO_ERROR => Ok(()),
        e => Err(win32_err(e)),
    }
}

fn route_row(luid: NET_LUID_LH, prefix: Ipv4Prefix) -> MIB_IPFORWARD_ROW2 {
    let mut row: MIB_IPFORWARD_ROW2 = unsafe { std::mem::zeroed() };
    unsafe { InitializeIpForwardEntry(&mut row) };
    row.InterfaceLuid = luid;
    row.DestinationPrefix.Prefix.Ipv4 = sockaddr_in(prefix.addr);
    row.DestinationPrefix.PrefixLength = prefix.len;
    row.NextHop.Ipv4 = sockaddr_in(Ipv4Addr::UNSPECIFIED); // bağlantı üzerinde (on-link)
    row.Metric = 0;
    row.Protocol = MIB_IPPROTO_NETMGMT;
    row
}

/// Eklenen rotaları tutar; düşürüldüğünde (drop) hepsini siler.
pub struct RouteGuard {
    luid: NET_LUID_LH,
    routes: Vec<Ipv4Prefix>,
}

impl RouteGuard {
    pub fn routes(&self) -> &[Ipv4Prefix] {
        &self.routes
    }
}

/// Ön ekleri bu arayüze yönlendiren rotaları ekler. Biri başarısız olursa
/// o ana kadar eklenenler geri alınır.
pub fn add_routes(if_index: u32, prefixes: &[Ipv4Prefix]) -> io::Result<RouteGuard> {
    let mut guard = RouteGuard { luid: luid_of(if_index)?, routes: Vec::new() };
    for &prefix in prefixes {
        let row = route_row(guard.luid, prefix);
        match unsafe { CreateIpForwardEntry2(&row) } {
            NO_ERROR | ERROR_OBJECT_ALREADY_EXISTS => guard.routes.push(prefix),
            e => return Err(win32_err(e)), // guard düşer, eklenenler silinir
        }
    }
    Ok(guard)
}

impl Drop for RouteGuard {
    fn drop(&mut self) {
        for &prefix in &self.routes {
            let row = route_row(self.luid, prefix);
            let ret = unsafe { DeleteIpForwardEntry2(&row) };
            debug_assert!(ret == NO_ERROR || ret == ERROR_NOT_FOUND, "rota silinemedi: {ret}");
        }
    }
}
