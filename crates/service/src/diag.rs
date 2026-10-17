//! Komut satırı tanılama araçları.

use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use router_common::{AdapterInfo, AdapterKind};
use router_engine::{bind, packet, tun};

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
    let dll = exe_dir()?.join("wintun.dll");
    let tun = tun::Tun::open(&dll)?;
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

    let dll = exe_dir()?.join("wintun.dll");
    check(
        dll.exists(),
        &format!("wintun.dll ({})", dll.display()),
        "scripts\\fetch-wintun.ps1 betiğini çalıştırın.",
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

fn exe_dir() -> Result<std::path::PathBuf> {
    let exe = std::env::current_exe()?;
    Ok(exe.parent().context("exe klasörü bulunamadı")?.to_path_buf())
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
