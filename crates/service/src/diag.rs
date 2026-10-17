//! Komut satırı tanılama araçları.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use router_common::{AdapterInfo, AdapterKind};
use router_engine::{bind, packet, tun, Engine, EngineConfig};
use router_sys::netcfg::Ipv4Prefix;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub fn adapters() -> Result<()> {
    let list = router_sys::adapters::list_adapters()?;
    println!(
        "{:>4}  {:<22} {:<9} {:<10} {:<22} {:<16} {:<16} {:>6}",
        "Idx", "Ad", "Tür", "Durum", "SSID", "IPv4", "Ağ geçidi", "Metric"
    );
    for a in &list {
        println!(
            "{:>4}  {:<22} {:<9} {:<10} {:<22} {:<16} {:<16} {:>6}",
            a.if_index,
            truncate(&a.friendly_name, 22),
            kind_label(a.kind),
            if a.connected { "Bağlı" } else { "Kapalı" },
            truncate(a.ssid.as_deref().unwrap_or("-"), 22),
            a.ipv4.first().map_or("-", String::as_str),
            a.gateways.first().map_or("-", String::as_str),
            a.ipv4_metric,
        );
        println!("        {}{}", a.description, if a.hardware { "" } else { "  [sanal]" });
    }
    Ok(())
}

pub fn apps() -> Result<()> {
    let apps = router_sys::processes::network_apps()?;
    println!("{:<32} {:>5} {:>5}  PID", "Uygulama", "TCP", "UDP");
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
    println!("\nToplam {} uygulama.", apps.len());
    Ok(())
}

pub fn probe(name: Option<&str>) -> Result<()> {
    let Some(name) = name else {
        bail!("adaptör adı gerekli, örn: router-service probe \"Wi-Fi\"");
    };
    let adapter = find_adapter(name)?;
    println!("{} (index {}) üzerinden deneniyor...", adapter.display_name(), adapter.if_index);
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    let ip = rt
        .block_on(bind::public_ipv4_via(adapter.if_index))
        .with_context(|| format!("{} üzerinden internete çıkılamadı", adapter.friendly_name))?;
    println!("Dış IP: {ip}");
    Ok(())
}

pub fn tun_test() -> Result<()> {
    if !router_sys::security::is_elevated() {
        bail!("yönetici olarak çalıştırın");
    }
    let tun = tun::Tun::open(&crate::wintun_path()?)?;
    println!("'{}' açıldı (index {}). 10 sn paket dinleniyor...", tun::ADAPTER_NAME, tun.if_index()?);

    let session = tun.session();
    let reader = std::thread::spawn(move || {
        let mut count = 0usize;
        // shutdown() çağrılınca receive_blocking hata döner ve döngü biter.
        while let Ok(pkt) = session.receive_blocking() {
            count += 1;
            match packet::parse(pkt.bytes()) {
                Some(info) => println!("  {info}"),
                None => println!("  ayrıştırılamayan paket ({} B)", pkt.bytes().len()),
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
    println!("Bitti: {count} paket alındı. Wintun çalışıyor.");
    Ok(())
}

pub fn firewall() -> Result<()> {
    if !router_sys::security::is_elevated() {
        bail!("yönetici olarak çalıştırın");
    }
    router_sys::firewall::ensure_rule(router_engine::TUN_IP, router_engine::PEER_IP)?;
    println!(
        "Güvenlik duvarı kuralı eklendi: '{}' (gelen TCP, {} → {}).",
        router_sys::firewall::RULE_NAME,
        router_engine::PEER_IP,
        router_engine::TUN_IP
    );
    Ok(())
}

/// Motoru yalnızca birkaç test adresine yönelik rotalarla başlatır ve bu sürecin
/// kendi (adaptöre bağlanmamış) soketleriyle TCP ve UDP'yi uçtan uca dener.
/// Diğer tüm trafik normal yolundan gitmeye devam eder.
pub fn engine_test(adapter: Option<&str>) -> Result<()> {
    if !router_sys::security::is_elevated() {
        bail!("yönetici olarak çalıştırın");
    }
    let dll = crate::wintun_path()?;
    if !dll.exists() {
        bail!("{} bulunamadı; scripts\\fetch-wintun.ps1 betiğini çalıştırın", dll.display());
    }
    if !router_sys::firewall::rule_exists() {
        println!("Uyarı: güvenlik duvarı kuralı yok, TCP testi başarısız olabilir ('router-service firewall').");
    }
    let force = adapter.map(find_adapter).transpose()?;
    if let Some(a) = &force {
        println!("Tüm test bağlantıları {} üzerinden çıkacak.", a.display_name());
    }

    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(
            "warn,router_engine=debug,router_service=debug",
        ))
        .init();

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        // Test hedefleri rotalar eklenmeden önce, normal yoldan çözülür.
        let ipify = tokio::net::lookup_host(("api.ipify.org", 80))
            .await?
            .find_map(|a| match a {
                std::net::SocketAddr::V4(v4) => Some(*v4.ip()),
                _ => None,
            })
            .context("api.ipify.org çözülemedi")?;
        let dns = Ipv4Addr::new(1, 1, 1, 1);
        let routes = vec![Ipv4Prefix::new(ipify, 32), Ipv4Prefix::new(dns, 32)];

        let rules = Arc::new(crate::rules::RuleStore::load(
            crate::rules::data_dir().join("rules.json"),
        )?);
        let policy = Arc::new(crate::policy::RulePolicy::new(rules, force.map(|a| a.if_index)));
        let engine = Engine::start(EngineConfig { wintun_dll: dll, routes }, policy.clone()).await?;
        policy.set_tun_if_index(engine.if_index());
        println!("Motor çalışıyor; yalnızca {ipify} ve {dns} TUN'a yönlendirildi.\n");

        let tcp = tokio::time::timeout(Duration::from_secs(10), http_public_ip(ipify)).await;
        let tcp = tcp.unwrap_or_else(|_| Err(anyhow::anyhow!("zaman aşımı (10 sn)")));
        match &tcp {
            Ok(ip) => println!("[ OK ] TCP: api.ipify.org TUN üzerinden cevap verdi, dış IP {ip}"),
            Err(e) => println!("[ !! ] TCP: {e:#}"),
        }

        let udp = tokio::time::timeout(Duration::from_secs(5), dns_lookup(dns, "example.com")).await;
        let udp = udp.unwrap_or_else(|_| Err(anyhow::anyhow!("zaman aşımı (5 sn)")));
        match &udp {
            Ok(ips) => println!("[ OK ] UDP: 1.1.1.1 DNS sorgusu TUN üzerinden cevaplandı: example.com = {ips}"),
            Err(e) => println!("[ !! ] UDP: {e:#}"),
        }

        drop(engine);
        if tcp.is_err() || udp.is_err() {
            bail!("motor testi başarısız");
        }
        println!("\nMotor testi başarılı; rotalar kaldırıldı.");
        Ok(())
    })
}

/// Adaptöre bağlanmamış sıradan bir soketle: rota tablosu ne derse oradan gider.
async fn http_public_ip(ip: Ipv4Addr) -> Result<String> {
    let mut s = tokio::net::TcpStream::connect((ip, 80)).await.context("bağlanılamadı")?;
    s.write_all(b"GET / HTTP/1.1\r\nHost: api.ipify.org\r\nConnection: close\r\n\r\n").await?;
    let mut resp = Vec::new();
    s.read_to_end(&mut resp).await?;
    let resp = String::from_utf8_lossy(&resp);
    let body = resp.split("\r\n\r\n").nth(1).unwrap_or_default().trim();
    if body.is_empty() {
        bail!("boş yanıt");
    }
    Ok(body.to_string())
}

/// En basit DNS A sorgusu; cevaptaki IPv4 adreslerini döndürür.
async fn dns_lookup(server: Ipv4Addr, name: &str) -> Result<String> {
    let mut query = vec![0x52, 0x54, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in name.split('.') {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.extend_from_slice(&[0, 0, 1, 0, 1]); // kök, tip A, sınıf IN

    let sock = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
    sock.send_to(&query, (server, 53)).await?;
    let mut buf = [0u8; 512];
    let (n, _) = sock.recv_from(&mut buf).await?;
    let resp = &buf[..n];
    if n < 12 || resp[..2] != query[..2] {
        bail!("geçersiz DNS cevabı");
    }
    // Cevaplardaki 4 baytlık A kayıtlarını topla (soru bölümünü atla).
    let answers = u16::from_be_bytes([resp[6], resp[7]]);
    let mut pos = query.len();
    let mut ips = Vec::new();
    for _ in 0..answers {
        // ad: sıkıştırılmış işaretçi (2 bayt) veya etiket dizisi
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
        bail!("cevapta A kaydı yok ({answers} cevap)");
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
            println!("[ !! ] {msg}\n       → {hint}");
        }
    };

    check(
        router_sys::security::is_elevated(),
        "Yönetici yetkisi",
        "TUN oluşturmak ve servisi kurmak için terminali yönetici olarak açın.",
    );

    let dll = crate::wintun_path()?;
    check(
        is_x64_dll(&dll),
        &format!("wintun.dll ({})", dll.display()),
        "Dosya yok veya bozuk; scripts\\fetch-wintun.ps1 betiğini çalıştırın.",
    );

    check(
        router_sys::firewall::rule_exists(),
        &format!("Güvenlik duvarı kuralı ('{}')", router_sys::firewall::RULE_NAME),
        "Yönetici terminalinde 'router-service firewall' (veya 'install') çalıştırın.",
    );

    let policy = router_sys::policy::minimize_connections();
    check(
        policy == Some(0),
        &format!(
            "Eşzamanlı bağlantı politikası (fMinimizeConnections = {})",
            policy.map_or("ayarlanmamış".to_string(), |v| v.to_string())
        ),
        "Windows ikinci bağlantıyı düşürebilir; 'router-service install' bunu düzeltir.",
    );

    let adapters = router_sys::adapters::list_adapters()?;
    let online: Vec<&AdapterInfo> = adapters
        .iter()
        .filter(|a| a.connected && a.has_internet_route())
        .collect();
    let names: Vec<String> = online.iter().map(|a| a.display_name()).collect();
    check(
        online.len() >= 2,
        &format!("İnternete bağlı adaptör sayısı: {} ({})", online.len(), names.join(", ")),
        "Uygulamayı kullanmak için en az iki bağlantı gerekir (örn. ikinci bir USB Wi-Fi veya telefondan USB tethering).",
    );

    println!();
    println!("{}", if ok { "Sistem hazır." } else { "Yukarıdaki sorunları giderin." });
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
        .with_context(|| format!("'{name}' adında adaptör bulunamadı ('adapters' komutuyla listeleyin)"))
}

/// Dosya geçerli bir x64 PE (DLL/EXE) mi? Yarım kalmış kopyaları yakalar.
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
        AdapterKind::Cellular => "Hücresel",
        AdapterKind::Other => "Diğer",
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut t: String = s.chars().take(max - 1).collect();
        t.push('…');
        t
    }
}
