//! Command-line diagnostic tools.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use router_common::{AdapterInfo, AdapterKind};
use router_engine::flows::FlowTable;
use router_engine::{bind, packet, tun, Engine, EngineConfig, Proto};
use router_sys::netcfg::IpPrefix;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub fn adapters() -> Result<()> {
    let list = router_sys::adapters::list_adapters()?;
    println!(
        "{:>4}  {:<22} {:<9} {:<10} {:<22} {:<16} {:<16} {:>6}",
        "Idx", "Name", "Type", "Status", "SSID", "IPv4", "Gateway", "Metric"
    );
    for a in &list {
        println!(
            "{:>4}  {:<22} {:<9} {:<10} {:<22} {:<16} {:<16} {:>6}",
            a.if_index,
            truncate(&a.friendly_name, 22),
            kind_label(a.kind),
            if a.connected { "Up" } else { "Down" },
            truncate(a.ssid.as_deref().unwrap_or("-"), 22),
            a.ipv4.first().map_or("-", String::as_str),
            a.ipv4_gateway().or(a.gateways.first().map(String::as_str)).unwrap_or("-"),
            a.ipv4_metric,
        );
        println!("        {}{}", a.description, if a.hardware { "" } else { "  [virtual]" });
    }
    Ok(())
}

pub fn apps() -> Result<()> {
    let apps = router_sys::processes::network_apps()?;
    println!("{:<32} {:>5} {:>5}  PID", "Application", "TCP", "UDP");
    for app in &apps {
        let pids: Vec<String> = app.pids.iter().map(u32::to_string).collect();
        println!(
            "{:<32} {:>5} {:>5}  {}",
            truncate(&app.exe, 32),
            app.tcp_connections,
            app.udp_endpoints,
            pids.join(",")
        );
    }
    println!("\n{} applications in total.", apps.len());
    Ok(())
}

pub fn probe(name: Option<&str>) -> Result<()> {
    let Some(name) = name else {
        bail!("adapter name required, e.g. router-service probe \"Wi-Fi\"");
    };
    let adapter = find_adapter(name)?;
    println!("Trying via {} (index {})...", adapter.display_name(), adapter.if_index);
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    let ip = rt
        .block_on(bind::public_ipv4_via(adapter.if_index))
        .with_context(|| format!("could not reach the internet via {}", adapter.friendly_name))?;
    println!("Public IP: {ip}");
    Ok(())
}

pub fn tun_test() -> Result<()> {
    if !router_sys::security::is_elevated() {
        bail!("run as administrator");
    }
    let tun = tun::Tun::open(&crate::wintun_path()?)?;
    println!("Opened '{}' (index {}). Capturing packets for 10 s...", tun::ADAPTER_NAME, tun.if_index()?);

    let session = tun.session();
    let reader = std::thread::spawn(move || {
        let mut count = 0usize;
        // Once shutdown() is called, receive_blocking returns an error and the loop ends.
        while let Ok(pkt) = session.receive_blocking() {
            count += 1;
            match packet::parse(pkt.bytes()) {
                Some(info) => println!("  {info}"),
                None => println!("  unparseable packet ({} B)", pkt.bytes().len()),
            }
        }
        count
    });

    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(10) && !reader.is_finished() {
        std::thread::sleep(Duration::from_millis(100));
    }
    tun.shutdown();
    let count = reader.join().unwrap_or(0);
    println!("Done: received {count} packets. Wintun is working.");
    Ok(())
}

pub fn firewall() -> Result<()> {
    if !router_sys::security::is_elevated() {
        bail!("run as administrator");
    }
    router_sys::firewall::ensure_rule(router_engine::TUN_IP, router_engine::PEER_IP)?;
    println!(
        "Firewall rule added: '{}' (inbound TCP, {} -> {}).",
        router_sys::firewall::RULE_NAME,
        router_engine::PEER_IP,
        router_engine::TUN_IP
    );
    Ok(())
}

/// Starts the engine with routes for a few test addresses only and exercises TCP
/// and UDP end to end using this process's own (not adapter-bound) sockets.
/// All other traffic keeps taking its normal path.
pub fn engine_test(adapter: Option<&str>) -> Result<()> {
    if !router_sys::security::is_elevated() {
        bail!("run as administrator");
    }
    let dll = crate::wintun_path()?;
    if !dll.exists() {
        bail!("{} not found; run scripts\\fetch-wintun.ps1", dll.display());
    }
    if !router_sys::firewall::rule_exists() {
        println!("Warning: firewall rule missing, the TCP test may fail ('router-service firewall').");
    }
    let force = adapter.map(find_adapter).transpose()?;
    if let Some(a) = &force {
        println!("All test connections will go out via {}.", a.display_name());
    }

    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(
            "warn,wintun=off,router_engine=debug,router_service=debug",
        ))
        .with_ansi(router_sys::console::enable_ansi())
        .init();

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        // Resolve the test targets the normal way, before the routes are added.
        let ipify = tokio::net::lookup_host(("api.ipify.org", 80))
            .await?
            .find_map(|a| match a {
                std::net::SocketAddr::V4(v4) => Some(*v4.ip()),
                _ => None,
            })
            .context("could not resolve api.ipify.org")?;
        let dns = Ipv4Addr::new(1, 1, 1, 1);
        // An IPv6-only server: the connection must be rejected on the TUN.
        let ipv6 = tokio::net::lookup_host(("api6.ipify.org", 80)).await.ok().and_then(|mut it| {
            it.find_map(|a| match a {
                std::net::SocketAddr::V6(v6) => Some(*v6.ip()),
                _ => None,
            })
        });
        let mut routes = vec![IpPrefix::v4(ipify, 32), IpPrefix::v4(dns, 32)];
        routes.extend(ipv6.map(|ip| IpPrefix::v6(ip, 128)));
        let targets: Vec<String> = routes.iter().map(|r| r.addr.to_string()).collect();

        let rules = Arc::new(crate::rules::RuleStore::load(
            crate::rules::data_dir().join("rules.json"),
        )?);
        let policy = Arc::new(crate::policy::RulePolicy::new(rules, force.map(|a| a.if_index)));
        let engine = Engine::start(EngineConfig { wintun_dll: dll, routes }, policy.clone()).await?;
        policy.set_tun_if_index(engine.if_index());
        println!("Engine running; only {} routed to the TUN.\n", targets.join(", "));

        let tcp = tokio::time::timeout(Duration::from_secs(10), http_public_ip(ipify)).await;
        let tcp = tcp.unwrap_or_else(|_| Err(anyhow::anyhow!("timed out (10 s)")));
        match &tcp {
            Ok(ip) => println!("[ OK ] TCP: api.ipify.org answered via the TUN, public IP {ip}"),
            Err(e) => println!("[ !! ] TCP: {e:#}"),
        }

        let udp = tokio::time::timeout(Duration::from_secs(5), dns_lookup(dns, "example.com")).await;
        let udp = udp.unwrap_or_else(|_| Err(anyhow::anyhow!("timed out (5 s)")));
        match &udp {
            Ok(ips) => println!("[ OK ] UDP: DNS query to 1.1.1.1 answered via the TUN: example.com = {ips}"),
            Err(e) => println!("[ !! ] UDP: {e:#}"),
        }

        let v6_ok = match ipv6 {
            None => {
                println!("[ -- ] IPv6: could not resolve api6.ipify.org, test skipped");
                true
            }
            Some(ip) => {
                let start = Instant::now();
                let attempt = tokio::time::timeout(
                    Duration::from_secs(3),
                    tokio::net::TcpStream::connect((ip, 80)),
                )
                .await;
                let ms = start.elapsed().as_millis();
                match attempt {
                    Ok(Err(_)) => {
                        println!("[ OK ] IPv6: connection rejected within {ms} ms; applications fall back to IPv4");
                        true
                    }
                    Ok(Ok(_)) => {
                        println!("[ !! ] IPv6: connection established; IPv6 traffic may bypass the rules");
                        false
                    }
                    Err(_) => {
                        println!("[ !! ] IPv6: connection not rejected, waited 3 s (applications will stall)");
                        false
                    }
                }
            }
        };

        let failover = tokio::time::timeout(Duration::from_secs(10), failover_reset(ipify, engine.flows())).await;
        let failover = failover.unwrap_or_else(|_| Err(anyhow::anyhow!("timed out (10 s)")));
        match &failover {
            Ok(ms) => println!(
                "[ OK ] Failover: open connection reset {ms} ms after its adapter was marked unavailable"
            ),
            Err(e) => println!("[ !! ] Failover: {e:#}"),
        }

        drop(engine);
        if tcp.is_err() || udp.is_err() || !v6_ok || failover.is_err() {
            bail!("engine test failed");
        }
        println!("\nEngine test passed; routes removed.");
        Ok(())
    })
}

/// Opens a connection through the TUN and makes sure data is flowing (a full HTTP
/// round trip on a keep-alive connection), then does what the network monitor
/// does when an adapter drops: resets every flow on that adapter. The app side
/// must see a connection reset (RST) right away, not a hang or a clean close.
async fn failover_reset(ip: Ipv4Addr, flows: Arc<FlowTable>) -> Result<u128> {
    let mut stream = tokio::net::TcpStream::connect((ip, 80)).await.context("connect failed")?;
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: api.ipify.org\r\nConnection: keep-alive\r\n\r\n")
        .await?;
    let mut response = [0u8; 4096];
    let n = stream.read(&mut response).await.context("no response before the reset")?;
    if !response[..n].starts_with(b"HTTP/1.1 200") {
        bail!("unexpected response before the reset");
    }
    let if_index = flows
        .active()
        .into_iter()
        .find(|(_, p)| *p == Proto::Tcp)
        .map(|(if_index, _)| if_index)
        .context("the relayed connection is not registered")?;
    let start = Instant::now();
    if flows.reset_interface(if_index) == 0 {
        bail!("no connection was registered on interface {if_index}");
    }
    let mut buf = [0u8; 1];
    match stream.read(&mut buf).await {
        Err(e) if matches!(e.kind(), std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted) => {
            Ok(start.elapsed().as_millis())
        }
        Ok(0) => bail!("connection was closed normally (FIN) instead of reset; apps may not retry"),
        Ok(_) => bail!("connection is still open"),
        Err(e) => bail!("unexpected error: {e}"),
    }
}

/// Prints adapters becoming available/unavailable as it happens.
pub fn watch() -> Result<()> {
    let rules = Arc::new(crate::rules::RuleStore::load(crate::rules::data_dir().join("rules.json"))?);
    let policy = crate::policy::RulePolicy::new(rules, None);
    let snapshot = || {
        let adapters = policy.refresh();
        let usable = policy.usable_interfaces(&adapters);
        adapters
            .iter()
            .filter(|a| a.hardware || a.has_internet_route())
            .map(|a| (a.if_index, a.display_name(), usable.contains(&a.if_index)))
            .collect::<Vec<_>>()
    };

    let (tx, rx) = std::sync::mpsc::channel();
    let _watcher = router_sys::notify::watch_changes(move || {
        let _ = tx.send(());
    })?;
    let start = Instant::now();
    let mut prev = snapshot();
    println!("Watching network changes (Ctrl+C to stop). Usable adapters now:");
    for (if_index, name, usable) in &prev {
        println!("  {} {name} (index {if_index})", if *usable { "[ OK ]" } else { "[ -- ]" });
    }
    loop {
        rx.recv()?;
        std::thread::sleep(Duration::from_millis(500));
        while rx.try_recv().is_ok() {}
        let now = snapshot();
        let secs = start.elapsed().as_secs_f32();
        for (if_index, name, usable) in &now {
            let before = prev.iter().find(|(i, _, _)| i == if_index).map(|(_, _, u)| *u);
            match (before, *usable) {
                (Some(false) | None, true) => println!("[{secs:7.1}s] + {name} is available (index {if_index})"),
                (Some(true), false) => println!("[{secs:7.1}s] - {name} is unavailable (index {if_index})"),
                _ => {}
            }
        }
        for (if_index, name, usable) in &prev {
            if *usable && !now.iter().any(|(i, _, _)| i == if_index) {
                println!("[{secs:7.1}s] - {name} was removed (index {if_index})");
            }
        }
        prev = now;
    }
}

/// Uses a plain socket not bound to any adapter: it goes wherever the route table says.
async fn http_public_ip(ip: Ipv4Addr) -> Result<String> {
    let mut s = tokio::net::TcpStream::connect((ip, 80)).await.context("connect failed")?;
    s.write_all(b"GET / HTTP/1.1\r\nHost: api.ipify.org\r\nConnection: close\r\n\r\n").await?;
    let mut resp = Vec::new();
    s.read_to_end(&mut resp).await?;
    let resp = String::from_utf8_lossy(&resp);
    let body = resp.split("\r\n\r\n").nth(1).unwrap_or_default().trim();
    if body.is_empty() {
        bail!("empty response");
    }
    Ok(body.to_string())
}

/// Minimal DNS A query; returns the IPv4 addresses from the answer.
async fn dns_lookup(server: Ipv4Addr, name: &str) -> Result<String> {
    let mut query = vec![0x52, 0x54, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in name.split('.') {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.extend_from_slice(&[0, 0, 1, 0, 1]); // root, type A, class IN

    let sock = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
    sock.send_to(&query, (server, 53)).await?;
    let mut buf = [0u8; 512];
    let (n, _) = sock.recv_from(&mut buf).await?;
    let resp = &buf[..n];
    if n < 12 || resp[..2] != query[..2] {
        bail!("invalid DNS response");
    }
    // Collect the 4-byte A records from the answers (skip the question section).
    let answers = u16::from_be_bytes([resp[6], resp[7]]);
    let mut pos = query.len();
    let mut ips = Vec::new();
    for _ in 0..answers {
        // name: compression pointer (2 bytes) or label sequence
        if resp.get(pos).is_some_and(|b| b & 0xc0 == 0xc0) {
            pos += 2;
        } else {
            while let Some(&len) = resp.get(pos) {
                pos += 1 + len as usize;
                if len == 0 {
                    break;
                }
            }
        }
        let Some(hdr) = resp.get(pos..pos + 10) else { break };
        let (rtype, rdlen) = (u16::from_be_bytes([hdr[0], hdr[1]]), u16::from_be_bytes([hdr[8], hdr[9]]));
        pos += 10;
        if rtype == 1 && rdlen == 4 {
            if let Some(r) = resp.get(pos..pos + 4) {
                ips.push(Ipv4Addr::new(r[0], r[1], r[2], r[3]).to_string());
            }
        }
        pos += rdlen as usize;
    }
    if ips.is_empty() {
        bail!("no A record in the response ({answers} answers)");
    }
    Ok(ips.join(", "))
}

pub fn doctor() -> Result<()> {
    let mut ok = true;
    let mut check = |pass: bool, msg: &str, hint: &str| {
        if pass {
            println!("[ OK ] {msg}");
        } else {
            ok = false;
            println!("[ !! ] {msg}\n       -> {hint}");
        }
    };

    check(
        router_sys::security::is_elevated(),
        "Administrator privileges",
        "Open the terminal as administrator to create the TUN and install the service.",
    );

    let dll = crate::wintun_path()?;
    check(
        is_x64_dll(&dll),
        &format!("wintun.dll ({})", dll.display()),
        "File missing or corrupt; run scripts\\fetch-wintun.ps1.",
    );

    check(
        router_sys::firewall::rule_exists(),
        &format!("Firewall rule ('{}')", router_sys::firewall::RULE_NAME),
        "Run 'router-service firewall' (or 'install') in an administrator terminal.",
    );

    let policy = router_sys::policy::minimize_connections();
    check(
        policy == Some(0),
        &format!(
            "Simultaneous connections policy (fMinimizeConnections = {})",
            policy.map_or("not set".to_string(), |v| v.to_string())
        ),
        "Windows may drop the second connection; 'router-service install' fixes this.",
    );

    let adapters = router_sys::adapters::list_adapters()?;
    let online: Vec<&AdapterInfo> = adapters
        .iter()
        .filter(|a| a.connected && a.has_internet_route())
        .collect();
    let names: Vec<String> = online.iter().map(|a| a.display_name()).collect();
    check(
        online.len() >= 2,
        &format!("Adapters connected to the internet: {} ({})", online.len(), names.join(", ")),
        "At least two connections are needed to use the app (e.g. a second USB Wi-Fi adapter or USB tethering from a phone).",
    );

    println!();
    println!("{}", if ok { "System is ready." } else { "Fix the issues above." });
    Ok(())
}

fn find_adapter(name: &str) -> Result<AdapterInfo> {
    let list = router_sys::adapters::list_adapters()?;
    let wanted = name.to_lowercase();
    list.into_iter()
        .find(|a| {
            a.friendly_name.to_lowercase() == wanted
                || a.if_index.to_string() == wanted
                || a.ssid.as_deref().is_some_and(|s| s.to_lowercase() == wanted)
        })
        .with_context(|| format!("no adapter named '{name}' (list them with the 'adapters' command)"))
}

/// Is the file a valid x64 PE (DLL/EXE)? Catches half-finished copies.
fn is_x64_dll(path: &std::path::Path) -> bool {
    const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
    let Ok(bytes) = std::fs::read(path) else { return false };
    let u32_at = |i: usize| bytes.get(i..i + 4).map(|b| u32::from_le_bytes(b.try_into().unwrap()));
    let u16_at = |i: usize| bytes.get(i..i + 2).map(|b| u16::from_le_bytes(b.try_into().unwrap()));
    let Some(pe) = u32_at(0x3c).map(|v| v as usize) else { return false };
    bytes.starts_with(b"MZ")
        && bytes.get(pe..pe + 4) == Some(b"PE\0\0")
        && u16_at(pe + 4) == Some(IMAGE_FILE_MACHINE_AMD64)
}

fn kind_label(kind: AdapterKind) -> &'static str {
    match kind {
        AdapterKind::Wifi => "Wi-Fi",
        AdapterKind::Ethernet => "Ethernet",
        AdapterKind::Cellular => "Cellular",
        AdapterKind::Other => "Other",
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        // ASCII ellipsis; still `max` chars wide so table columns line up.
        let mut t: String = s.chars().take(max - 3).collect();
        t.push_str("...");
        t
    }
}
