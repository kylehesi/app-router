//! Socket -> owning process lookup for new connections.
//!
//! Reading a socket table costs O(sockets): about 5 ms with ~2000 sockets. Doing
//! that once per new connection doesn't scale, because connections arrive in
//! bursts (a browser opening a page, a torrent client) and every lookup would
//! rescan the table.
//!
//! Lookups therefore share scans. The socket being looked up already exists when
//! the lookup starts, so any scan that *started* after that moment is guaranteed
//! to contain it. Only one scan runs at a time; lookups that arrive while it runs
//! wait for the next one, which answers all of them at once. A burst of N lookups
//! costs about two scans instead of N, and every answer is still exact.

use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Instant;

use crate::processes;

/// `(local, remote) -> pid` for IPv4 TCP connections.
type TcpTable = HashMap<(SocketAddrV4, SocketAddrV4), u32>;
/// `local -> pid` for IPv4 UDP sockets.
type UdpTable = HashMap<SocketAddrV4, u32>;

/// Cached exe names are dropped wholesale beyond this many processes.
const EXE_CACHE_LIMIT: usize = 4096;

/// Snapshots of one socket table, shared between concurrent lookups.
struct SharedScan<T> {
    state: Mutex<ScanState<T>>,
    done: Condvar,
    scan: fn() -> io::Result<T>,
}

struct ScanState<T> {
    /// Latest snapshot and the moment its scan started.
    latest: Option<(Instant, Arc<T>)>,
    scanning: bool,
}

impl<T> SharedScan<T> {
    fn new(scan: fn() -> io::Result<T>) -> Self {
        Self {
            state: Mutex::new(ScanState {
                latest: None,
                scanning: false,
            }),
            done: Condvar::new(),
            scan,
        }
    }

    /// A snapshot whose scan started at or after `since`.
    fn get(&self, since: Instant) -> io::Result<Arc<T>> {
        let mut state = self.state.lock().unwrap();
        loop {
            if let Some((started, snapshot)) = &state.latest {
                if *started >= since {
                    return Ok(snapshot.clone());
                }
            }
            if state.scanning {
                // The running scan may have started too early for us; wait for
                // it and check again (the next scan will be late enough).
                state = self.done.wait(state).unwrap();
                continue;
            }
            state.scanning = true;
            drop(state);

            let started = Instant::now();
            let result = (self.scan)().map(Arc::new);

            state = self.state.lock().unwrap();
            state.scanning = false;
            if let Ok(snapshot) = &result {
                state.latest = Some((started, snapshot.clone()));
            }
            self.done.notify_all();
            return result;
        }
    }
}

pub struct OwnerResolver {
    tcp: SharedScan<TcpTable>,
    udp: SharedScan<UdpTable>,
    /// pid -> (process start time, exe). The start time detects reused PIDs.
    exes: Mutex<HashMap<u32, (u64, Option<String>)>>,
}

impl Default for OwnerResolver {
    fn default() -> Self {
        Self::with_scans(processes::tcp4_connection_owners, processes::udp4_owners)
    }
}

impl OwnerResolver {
    fn with_scans(tcp: fn() -> io::Result<TcpTable>, udp: fn() -> io::Result<UdpTable>) -> Self {
        Self {
            tcp: SharedScan::new(tcp),
            udp: SharedScan::new(udp),
            exes: Mutex::new(HashMap::new()),
        }
    }

    /// Owner of the IPv4 TCP connection `local -> remote`.
    pub fn tcp4(&self, local: SocketAddrV4, remote: SocketAddrV4) -> Option<u32> {
        let table = self.tcp.get(Instant::now()).ok()?;
        table.get(&(local, remote)).copied()
    }

    /// Owner of the IPv4 UDP socket at `local` (or bound to 0.0.0.0 on that port).
    pub fn udp4(&self, local: SocketAddrV4) -> Option<u32> {
        let table = self.udp.get(Instant::now()).ok()?;
        table
            .get(&local)
            .or_else(|| table.get(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, local.port())))
            .copied()
    }

    /// Lowercase exe name of `pid` ("chrome.exe"), cached per process instance.
    pub fn exe(&self, pid: u32) -> Option<String> {
        let started = processes::process_start_time(pid)?;
        if let Some((cached_start, exe)) = self.exes.lock().unwrap().get(&pid) {
            if *cached_start == started {
                return exe.clone();
            }
        }
        let exe = processes::exe_name(pid);
        let mut exes = self.exes.lock().unwrap();
        if exes.len() >= EXE_CACHE_LIMIT {
            exes.clear();
        }
        exes.insert(pid, (started, exe.clone()));
        exe
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Barrier;
    use std::time::Duration;

    static SCANS: AtomicUsize = AtomicUsize::new(0);

    fn slow_scan() -> io::Result<HashMap<SocketAddrV4, u32>> {
        SCANS.fetch_add(1, Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(30));
        Ok(HashMap::from([("10.0.0.1:5000".parse().unwrap(), 42)]))
    }

    #[test]
    fn concurrent_lookups_share_scans() {
        let scan = Arc::new(SharedScan::new(slow_scan));
        let barrier = Arc::new(Barrier::new(32));
        let threads: Vec<_> = (0..32)
            .map(|_| {
                let (scan, barrier) = (scan.clone(), barrier.clone());
                std::thread::spawn(move || {
                    barrier.wait();
                    let since = Instant::now();
                    let table = scan.get(since).unwrap();
                    assert_eq!(table.len(), 1);
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        // One scan for whoever came first, one for everyone who arrived during it.
        let scans = SCANS.load(Ordering::SeqCst);
        assert!(scans <= 3, "32 concurrent lookups needed {scans} scans");
    }

    #[test]
    fn stale_snapshot_is_never_returned() {
        fn counting_scan() -> io::Result<u32> {
            static N: AtomicUsize = AtomicUsize::new(0);
            Ok(N.fetch_add(1, Ordering::SeqCst) as u32)
        }
        let scan = SharedScan::new(counting_scan);
        let first = scan.get(Instant::now()).unwrap();
        let again = scan.get(Instant::now()).unwrap();
        assert_ne!(
            first, again,
            "a lookup must not reuse a scan that started before it"
        );
    }

    #[test]
    fn udp_falls_back_to_wildcard_bind() {
        fn tcp() -> io::Result<TcpTable> {
            Ok(HashMap::new())
        }
        fn udp() -> io::Result<UdpTable> {
            Ok(HashMap::from([
                ("0.0.0.0:53000".parse().unwrap(), 7),
                ("198.18.0.1:53001".parse().unwrap(), 8),
            ]))
        }
        let resolver = OwnerResolver::with_scans(tcp, udp);
        assert_eq!(resolver.udp4("198.18.0.1:53000".parse().unwrap()), Some(7));
        assert_eq!(resolver.udp4("198.18.0.1:53001".parse().unwrap()), Some(8));
        assert_eq!(resolver.udp4("198.18.0.1:53002".parse().unwrap()), None);
    }

    #[test]
    fn exe_of_this_process() {
        let resolver = OwnerResolver::default();
        let me = std::process::id();
        let first = resolver.exe(me);
        assert!(first.as_deref().is_some_and(|e| e.ends_with(".exe")));
        assert_eq!(resolver.exe(me), first, "cached lookup must match");
    }
}
