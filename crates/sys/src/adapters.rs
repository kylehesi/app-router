//! Network adapter enumeration (IP Helper API + WLAN API).

use std::ffi::{c_char, CStr};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ptr;

use router_common::{AdapterInfo, AdapterKind};
use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetAdaptersAddresses, GetIfEntry2, GAA_FLAG_INCLUDE_GATEWAYS, GAA_FLAG_SKIP_ANYCAST,
    GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST, IP_ADAPTER_ADDRESSES_LH, MIB_IF_ROW2,
};
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_IN, SOCKADDR_IN6, SOCKET_ADDRESS,
};

use crate::util::{from_wide_ptr, win32_err};
use crate::wlan;

// ipifcons.h
const IF_TYPE_ETHERNET_CSMACD: u32 = 6;
const IF_TYPE_SOFTWARE_LOOPBACK: u32 = 24;
const IF_TYPE_IEEE80211: u32 = 71;
const IF_TYPE_TUNNEL: u32 = 131;
const IF_TYPE_WWANPP: u32 = 243;
const IF_TYPE_WWANPP2: u32 = 244;
const IF_OPER_STATUS_UP: i32 = 1;
/// HardwareInterface bit in MIB_IF_ROW2.InterfaceAndOperStatusFlags.
const FLAG_HARDWARE_INTERFACE: u8 = 0x01;

/// Returns all adapters except loopback and tunnel interfaces.
pub fn list_adapters() -> io::Result<Vec<AdapterInfo>> {
    let buf = adapter_addresses()?;
    let wifi = wlan::current_connections();
    let mut out = Vec::new();

    let mut cur = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
    while !cur.is_null() {
        // SAFETY: linked list filled by GetAdaptersAddresses; valid as long as `buf` lives.
        let a = unsafe { &*cur };
        cur = a.Next;

        if a.IfType == IF_TYPE_SOFTWARE_LOOPBACK || a.IfType == IF_TYPE_TUNNEL {
            continue;
        }

        let guid = unsafe { CStr::from_ptr(a.AdapterName as *const c_char) }
            .to_string_lossy()
            .into_owned();
        let luid = unsafe { a.Luid.Value };
        let row = if_row(luid);
        let link = wifi.get(&guid.to_uppercase());

        let mut ipv4 = Vec::new();
        let mut ipv6 = Vec::new();
        let mut u = a.FirstUnicastAddress;
        while !u.is_null() {
            let ua = unsafe { &*u };
            match unsafe { sockaddr_to_ip(&ua.Address) } {
                Some(IpAddr::V4(ip)) => ipv4.push(ip.to_string()),
                Some(IpAddr::V6(ip)) if !is_link_local(&ip) => ipv6.push(ip.to_string()),
                _ => {}
            }
            u = ua.Next;
        }

        let mut gateways = Vec::new();
        let mut g = a.FirstGatewayAddress;
        while !g.is_null() {
            let ga = unsafe { &*g };
            if let Some(ip) = unsafe { sockaddr_to_ip(&ga.Address) } {
                gateways.push(ip.to_string());
            }
            g = ga.Next;
        }

        out.push(AdapterInfo {
            guid,
            if_index: unsafe { a.Anonymous1.Anonymous.IfIndex },
            luid,
            friendly_name: unsafe { from_wide_ptr(a.FriendlyName) },
            description: unsafe { from_wide_ptr(a.Description) },
            kind: kind_of(a.IfType),
            hardware: row.as_ref().is_some_and(|r| {
                r.InterfaceAndOperStatusFlags._bitfield & FLAG_HARDWARE_INTERFACE != 0
            }),
            connected: a.OperStatus as i32 == IF_OPER_STATUS_UP,
            ssid: link.map(|l| l.ssid.clone()),
            signal_quality: link.map(|l| l.signal_quality),
            ipv4,
            ipv6,
            gateways,
            ipv4_metric: a.Ipv4Metric,
            link_speed_bps: a.ReceiveLinkSpeed,
            rx_bytes: row.as_ref().map_or(0, |r| r.InOctets),
            tx_bytes: row.as_ref().map_or(0, |r| r.OutOctets),
        });
    }
    Ok(out)
}

/// Allocates the buffer for GetAdaptersAddresses; retries if the table grows.
fn adapter_addresses() -> io::Result<Vec<u64>> {
    let flags = GAA_FLAG_INCLUDE_GATEWAYS
        | GAA_FLAG_SKIP_ANYCAST
        | GAA_FLAG_SKIP_MULTICAST
        | GAA_FLAG_SKIP_DNS_SERVER;
    let mut size: u32 = 16 * 1024;
    for _ in 0..4 {
        // u64 buffer: guarantees 8-byte alignment for the structs.
        let mut buf = vec![0u64; (size as usize).div_ceil(8)];
        let ret = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC as u32,
                flags,
                ptr::null(),
                buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH,
                &mut size,
            )
        };
        match ret {
            NO_ERROR => return Ok(buf),
            ERROR_BUFFER_OVERFLOW => continue,
            e => return Err(win32_err(e)),
        }
    }
    Err(io::Error::other(
        "failed to get adapter list (buffer size kept changing)",
    ))
}

fn if_row(luid: u64) -> Option<MIB_IF_ROW2> {
    let mut row: MIB_IF_ROW2 = unsafe { std::mem::zeroed() };
    row.InterfaceLuid.Value = luid;
    (unsafe { GetIfEntry2(&mut row) } == NO_ERROR).then_some(row)
}

fn kind_of(if_type: u32) -> AdapterKind {
    match if_type {
        IF_TYPE_IEEE80211 => AdapterKind::Wifi,
        IF_TYPE_ETHERNET_CSMACD => AdapterKind::Ethernet,
        IF_TYPE_WWANPP | IF_TYPE_WWANPP2 => AdapterKind::Cellular,
        _ => AdapterKind::Other,
    }
}

fn is_link_local(ip: &Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xffc0) == 0xfe80
}

/// # Safety
/// `sa.lpSockaddr` must be null or point to a valid SOCKADDR.
unsafe fn sockaddr_to_ip(sa: &SOCKET_ADDRESS) -> Option<IpAddr> {
    if sa.lpSockaddr.is_null() {
        return None;
    }
    match (*sa.lpSockaddr).sa_family {
        AF_INET => {
            let sin = &*(sa.lpSockaddr as *const SOCKADDR_IN);
            Some(IpAddr::V4(Ipv4Addr::from(
                sin.sin_addr.S_un.S_addr.to_ne_bytes(),
            )))
        }
        AF_INET6 => {
            let sin6 = &*(sa.lpSockaddr as *const SOCKADDR_IN6);
            Some(IpAddr::V6(Ipv6Addr::from(sin6.sin6_addr.u.Byte)))
        }
        _ => None,
    }
}
