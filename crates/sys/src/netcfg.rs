//! Interface configuration: IPv4 address, MTU and routes (IP Helper API).
//! All of it requires administrator rights.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use windows_sys::Win32::Foundation::{ERROR_NOT_FOUND, ERROR_OBJECT_ALREADY_EXISTS, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    ConvertInterfaceIndexToLuid, CreateIpForwardEntry2, CreateUnicastIpAddressEntry,
    DeleteIpForwardEntry2, GetIpInterfaceEntry, InitializeIpForwardEntry,
    InitializeIpInterfaceEntry, InitializeUnicastIpAddressEntry, SetIpInterfaceEntry,
    MIB_IPFORWARD_ROW2, MIB_IPINTERFACE_ROW, MIB_UNICASTIPADDRESS_ROW,
};
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, SOCKADDR_IN, SOCKADDR_IN6, SOCKADDR_INET,
};

use crate::util::win32_err;

const IP_DAD_STATE_PREFERRED: i32 = 4;
const MIB_IPPROTO_NETMGMT: i32 = 3;

/// IP prefix, e.g. 0.0.0.0/1 or 2000::/3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpPrefix {
    pub addr: IpAddr,
    pub len: u8,
}

impl IpPrefix {
    pub const fn v4(addr: Ipv4Addr, len: u8) -> Self {
        Self { addr: IpAddr::V4(addr), len }
    }

    pub const fn v6(addr: Ipv6Addr, len: u8) -> Self {
        Self { addr: IpAddr::V6(addr), len }
    }
}

impl std::fmt::Display for IpPrefix {
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

fn sockaddr_inet(ip: IpAddr) -> SOCKADDR_INET {
    let mut s: SOCKADDR_INET = unsafe { std::mem::zeroed() };
    match ip {
        IpAddr::V4(v4) => s.Ipv4 = sockaddr_in(v4),
        IpAddr::V6(v6) => {
            let mut s6: SOCKADDR_IN6 = unsafe { std::mem::zeroed() };
            s6.sin6_family = AF_INET6;
            s6.sin6_addr.u.Byte = v6.octets();
            s.Ipv6 = s6;
        }
    }
    s
}

/// Assigns an IP address to the interface (no-op if it already exists). Skips DAD so the address is usable immediately.
pub fn set_address(if_index: u32, ip: IpAddr, prefix_len: u8) -> io::Result<()> {
    let mut row: MIB_UNICASTIPADDRESS_ROW = unsafe { std::mem::zeroed() };
    unsafe { InitializeUnicastIpAddressEntry(&mut row) };
    row.InterfaceLuid = luid_of(if_index)?;
    row.Address = sockaddr_inet(ip);
    row.OnLinkPrefixLength = prefix_len;
    row.DadState = IP_DAD_STATE_PREFERRED;
    match unsafe { CreateUnicastIpAddressEntry(&row) } {
        NO_ERROR | ERROR_OBJECT_ALREADY_EXISTS => Ok(()),
        e => Err(win32_err(e)),
    }
}

/// Sets the interface's IPv4 MTU.
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
    // SitePrefixLength must be 0 for IPv4, or SetIpInterfaceEntry returns ERROR_INVALID_PARAMETER.
    row.SitePrefixLength = 0;
    match unsafe { SetIpInterfaceEntry(&mut row) } {
        NO_ERROR => Ok(()),
        e => Err(win32_err(e)),
    }
}

fn route_row(luid: NET_LUID_LH, prefix: IpPrefix) -> MIB_IPFORWARD_ROW2 {
    let mut row: MIB_IPFORWARD_ROW2 = unsafe { std::mem::zeroed() };
    unsafe { InitializeIpForwardEntry(&mut row) };
    row.InterfaceLuid = luid;
    row.DestinationPrefix.Prefix = sockaddr_inet(prefix.addr);
    row.DestinationPrefix.PrefixLength = prefix.len;
    // On-link: the next hop is the family's unspecified address.
    row.NextHop = sockaddr_inet(match prefix.addr {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    });
    row.Metric = 0;
    row.Protocol = MIB_IPPROTO_NETMGMT;
    row
}

/// Holds the added routes; deletes them all on drop.
pub struct RouteGuard {
    luid: NET_LUID_LH,
    routes: Vec<IpPrefix>,
}

impl RouteGuard {
    pub fn routes(&self) -> &[IpPrefix] {
        &self.routes
    }
}

/// Adds routes sending the prefixes to this interface. If one fails, the ones
/// added so far are rolled back.
pub fn add_routes(if_index: u32, prefixes: &[IpPrefix]) -> io::Result<RouteGuard> {
    let mut guard = RouteGuard { luid: luid_of(if_index)?, routes: Vec::new() };
    for &prefix in prefixes {
        let row = route_row(guard.luid, prefix);
        match unsafe { CreateIpForwardEntry2(&row) } {
            NO_ERROR | ERROR_OBJECT_ALREADY_EXISTS => guard.routes.push(prefix),
            e => return Err(win32_err(e)), // guard drops, removing the added routes
        }
    }
    Ok(guard)
}

impl Drop for RouteGuard {
    fn drop(&mut self) {
        for &prefix in &self.routes {
            let row = route_row(self.luid, prefix);
            let ret = unsafe { DeleteIpForwardEntry2(&row) };
            debug_assert!(ret == NO_ERROR || ret == ERROR_NOT_FOUND, "failed to delete route: {ret}");
        }
    }
}
