//! Process list, exe paths and "which socket belongs to which process" tables.

use std::collections::{BTreeMap, HashMap};
use std::ffi::c_void;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4};

use router_common::{normalize_exe, AppInfo};
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_INSUFFICIENT_BUFFER, INVALID_HANDLE_VALUE, NO_ERROR,
};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID,
    MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID, MIB_UDP6ROW_OWNER_PID, MIB_UDP6TABLE_OWNER_PID,
    MIB_UDPROW_OWNER_PID, MIB_UDPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
    TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
    PROCESS_QUERY_LIMITED_INFORMATION,
};

use crate::util::{from_wide_buf, win32_err};

const MIB_TCP_STATE_LISTEN: u32 = 2;
const PID_IDLE: u32 = 0;
const PID_SYSTEM: u32 = 4;

#[derive(Debug, Clone)]
pub struct ProcessEntry {
    pub pid: u32,
    pub parent_pid: u32,
    pub exe_name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proto {
    Tcp,
    Udp,
}

#[derive(Debug, Clone)]
pub struct SocketEntry {
    pub proto: Proto,
    pub local: SocketAddr,
    /// Absent for listening TCP sockets and for UDP.
    pub remote: Option<SocketAddr>,
    pub pid: u32,
}

/// All running processes (no administrator rights needed).
pub fn list_processes() -> io::Result<Vec<ProcessEntry>> {
    let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snap == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    let mut out = Vec::new();
    let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
    let mut ok = unsafe { Process32FirstW(snap, &mut entry) };
    while ok != 0 {
        out.push(ProcessEntry {
            pid: entry.th32ProcessID,
            parent_pid: entry.th32ParentProcessID,
            exe_name: from_wide_buf(&entry.szExeFile),
        });
        ok = unsafe { Process32NextW(snap, &mut entry) };
    }
    unsafe { CloseHandle(snap) };
    Ok(out)
}

/// Full exe path of the process. May return `None` for protected system processes.
pub fn process_path(pid: u32) -> Option<String> {
    let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if h.is_null() {
        return None;
    }
    let mut buf = [0u16; 1024];
    let mut len = buf.len() as u32;
    let ok = unsafe { QueryFullProcessImageNameW(h, PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut len) };
    unsafe { CloseHandle(h) };
    (ok != 0).then(|| String::from_utf16_lossy(&buf[..len as usize]))
}

/// All TCP and UDP sockets on the system, with their owning PID.
pub fn socket_table() -> io::Result<Vec<SocketEntry>> {
    let mut out = tcp4_sockets()?;
    out.extend(tcp6_sockets()?);
    out.extend(udp4_sockets()?);
    out.extend(udp6_sockets()?);
    Ok(out)
}

/// Process owning the IPv4 TCP connection `local -> remote`.
pub fn tcp4_owner(local: SocketAddrV4, remote: SocketAddrV4) -> io::Result<Option<u32>> {
    let (local, remote) = (SocketAddr::V4(local), Some(SocketAddr::V4(remote)));
    Ok(tcp4_sockets()?
        .into_iter()
        .find(|s| s.local == local && s.remote == remote)
        .map(|s| s.pid))
}

/// Process owning the IPv4 UDP socket at `local`. If the socket is bound to
/// 0.0.0.0, only the port is matched.
pub fn udp4_owner(local: SocketAddrV4) -> io::Result<Option<u32>> {
    let sockets = udp4_sockets()?;
    let exact = SocketAddr::V4(local);
    let any = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, local.port()));
    Ok(sockets
        .iter()
        .find(|s| s.local == exact)
        .or_else(|| sockets.iter().find(|s| s.local == any))
        .map(|s| s.pid))
}

/// Lowercase exe name of the process ("chrome.exe"); same format as the rule key.
pub fn exe_name(pid: u32) -> Option<String> {
    let path = process_path(pid)?;
    let name = path.rsplit(['\\', '/']).next()?;
    Some(normalize_exe(name))
}

fn tcp4_sockets() -> io::Result<Vec<SocketEntry>> {
    let buf = fetch_table(|p, s| unsafe {
        GetExtendedTcpTable(p, s, 0, AF_INET as u32, TCP_TABLE_OWNER_PID_ALL, 0)
    })?;
    let rows = unsafe { rows::<MIB_TCPTABLE_OWNER_PID, MIB_TCPROW_OWNER_PID>(&buf) };
    Ok(rows
        .iter()
        .map(|r| SocketEntry {
            proto: Proto::Tcp,
            local: v4(r.dwLocalAddr, r.dwLocalPort),
            remote: (r.dwState != MIB_TCP_STATE_LISTEN).then(|| v4(r.dwRemoteAddr, r.dwRemotePort)),
            pid: r.dwOwningPid,
        })
        .collect())
}

fn tcp6_sockets() -> io::Result<Vec<SocketEntry>> {
    let buf = fetch_table(|p, s| unsafe {
        GetExtendedTcpTable(p, s, 0, AF_INET6 as u32, TCP_TABLE_OWNER_PID_ALL, 0)
    })?;
    let rows = unsafe { rows::<MIB_TCP6TABLE_OWNER_PID, MIB_TCP6ROW_OWNER_PID>(&buf) };
    Ok(rows
        .iter()
        .map(|r| SocketEntry {
            proto: Proto::Tcp,
            local: v6(r.ucLocalAddr, r.dwLocalPort),
            remote: (r.dwState != MIB_TCP_STATE_LISTEN).then(|| v6(r.ucRemoteAddr, r.dwRemotePort)),
            pid: r.dwOwningPid,
        })
        .collect())
}

fn udp4_sockets() -> io::Result<Vec<SocketEntry>> {
    let buf = fetch_table(|p, s| unsafe {
        GetExtendedUdpTable(p, s, 0, AF_INET as u32, UDP_TABLE_OWNER_PID, 0)
    })?;
    let rows = unsafe { rows::<MIB_UDPTABLE_OWNER_PID, MIB_UDPROW_OWNER_PID>(&buf) };
    Ok(rows
        .iter()
        .map(|r| SocketEntry {
            proto: Proto::Udp,
            local: v4(r.dwLocalAddr, r.dwLocalPort),
            remote: None,
            pid: r.dwOwningPid,
        })
        .collect())
}

fn udp6_sockets() -> io::Result<Vec<SocketEntry>> {
    let buf = fetch_table(|p, s| unsafe {
        GetExtendedUdpTable(p, s, 0, AF_INET6 as u32, UDP_TABLE_OWNER_PID, 0)
    })?;
    let rows = unsafe { rows::<MIB_UDP6TABLE_OWNER_PID, MIB_UDP6ROW_OWNER_PID>(&buf) };
    Ok(rows
        .iter()
        .map(|r| SocketEntry {
            proto: Proto::Udp,
            local: v6(r.ucLocalAddr, r.dwLocalPort),
            remote: None,
            pid: r.dwOwningPid,
        })
        .collect())
}

/// Apps that have sockets, grouped and sorted by exe name.
pub fn network_apps() -> io::Result<Vec<AppInfo>> {
    let names: HashMap<u32, String> = list_processes()?
        .into_iter()
        .map(|p| (p.pid, normalize_exe(&p.exe_name)))
        .collect();

    let mut apps: BTreeMap<String, AppInfo> = BTreeMap::new();
    for s in socket_table()? {
        if s.pid == PID_IDLE || s.pid == PID_SYSTEM {
            continue;
        }
        let Some(exe) = names.get(&s.pid) else { continue };
        let app = apps.entry(exe.clone()).or_insert_with(|| AppInfo {
            exe: exe.clone(),
            path: None,
            pids: Vec::new(),
            tcp_connections: 0,
            udp_endpoints: 0,
        });
        if !app.pids.contains(&s.pid) {
            app.pids.push(s.pid);
        }
        match s.proto {
            Proto::Tcp if s.remote.is_some() => app.tcp_connections += 1,
            Proto::Tcp => {}
            Proto::Udp => app.udp_endpoints += 1,
        }
    }

    Ok(apps
        .into_values()
        .map(|mut app| {
            app.pids.sort_unstable();
            app.path = app.pids.iter().find_map(|&pid| process_path(pid));
            app
        })
        .collect())
}

/// Repeats the GetExtended*Table call until the buffer is large enough.
fn fetch_table(f: impl Fn(*mut c_void, *mut u32) -> u32) -> io::Result<Vec<u64>> {
    let mut size = 0u32;
    for _ in 0..8 {
        let mut buf = vec![0u64; (size as usize).div_ceil(8).max(1)];
        match f(buf.as_mut_ptr().cast(), &mut size) {
            NO_ERROR => return Ok(buf),
            ERROR_INSUFFICIENT_BUFFER => continue,
            e => return Err(win32_err(e)),
        }
    }
    Err(io::Error::other("failed to get socket table (size kept changing)"))
}

/// All MIB_*TABLE structs have the shape `{ dwNumEntries: u32, table: [ROW; 1] }`.
///
/// # Safety
/// `buf` must contain a valid table of type `T`.
unsafe fn rows<T, R>(buf: &[u64]) -> &[R] {
    let count = *(buf.as_ptr() as *const u32) as usize;
    let offset = std::mem::size_of::<T>() - std::mem::size_of::<R>();
    let first = (buf.as_ptr() as *const u8).add(offset) as *const R;
    std::slice::from_raw_parts(first, count)
}

/// The port is stored in the low 16 bits of the DWORD, in network byte order.
fn port(raw: u32) -> u16 {
    u16::from_be(raw as u16)
}

fn v4(addr: u32, raw_port: u32) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::from(addr.to_ne_bytes())), port(raw_port))
}

fn v6(addr: [u8; 16], raw_port: u32) -> SocketAddr {
    SocketAddr::new(IpAddr::V6(Ipv6Addr::from(addr)), port(raw_port))
}

// Compile-time check of the `rows` offset assumption (table = u32 count + one row).
const _: () = {
    use std::mem::size_of;
    assert!(size_of::<MIB_TCPTABLE_OWNER_PID>() == 4 + size_of::<MIB_TCPROW_OWNER_PID>());
    assert!(size_of::<MIB_TCP6TABLE_OWNER_PID>() == 4 + size_of::<MIB_TCP6ROW_OWNER_PID>());
    assert!(size_of::<MIB_UDPTABLE_OWNER_PID>() == 4 + size_of::<MIB_UDPROW_OWNER_PID>());
    assert!(size_of::<MIB_UDP6TABLE_OWNER_PID>() == 4 + size_of::<MIB_UDP6ROW_OWNER_PID>());
};
