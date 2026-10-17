//! Router arka plan servisi ve tanılama komutları.

mod diag;
mod ipc;
mod policy;
mod rules;
mod winsvc;

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{Context, Result};
use router_engine::{Engine, EngineConfig, FULL_TUNNEL};
use tokio::sync::watch;
use tracing::{error, info};

const HELP: &str = "\
Router servisi

Kullanım: router-service <komut>

  run [--engine]  Konsolda çalıştır (geliştirme; Ctrl+C ile durur).
                  --engine: yönlendirmeyi de başlat (tüm IPv4 trafiği; yönetici)
  install         Windows servisi olarak kur ve başlat (yönetici)
  uninstall       Servisi durdur ve kaldır (yönetici)
  firewall        TUN için güvenlik duvarı kuralını ekle (yönetici)

Tanılama:
  adapters        Ağ adaptörlerini SSID'leriyle listele
  apps            Ağ kullanan uygulamaları listele
  probe <ad>      Belirtilen adaptör üzerinden dış IP'yi göster (örn. probe \"Wi-Fi 2\")
  tun-test        Wintun adaptörünü oluşturup 10 sn paket dinle (yönetici)
  engine-test [ad]
                  Motoru yalnızca birkaç test adresi için çalıştırıp TCP ve UDP
                  aktarmayı uçtan uca dener; diğer trafiğe dokunmaz (yönetici)
  doctor          Sistemin hazır olup olmadığını kontrol et
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("run") => run_console(args.iter().any(|a| a == "--engine")),
        Some("service") => winsvc::run_dispatcher(),
        Some("install") => winsvc::install(),
        Some("uninstall") => winsvc::uninstall(),
        Some("firewall") => diag::firewall(),
        Some("adapters") => diag::adapters(),
        Some("apps") => diag::apps(),
        Some("probe") => diag::probe(args.get(1).map(String::as_str)),
        Some("tun-test") => diag::tun_test(),
        Some("engine-test") => diag::engine_test(args.get(1).map(String::as_str)),
        Some("doctor") => diag::doctor(),
        _ => {
            print!("{HELP}");
            Ok(())
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Hata: {e:#}");
            ExitCode::FAILURE
        }
    }
}

/// Servisin asıl işi; hem konsol modunda hem Windows servisi olarak bunu çalıştırır.
pub async fn run_core(shutdown: watch::Receiver<bool>, with_engine: bool) -> Result<()> {
    let rules = Arc::new(rules::RuleStore::load(rules::data_dir().join("rules.json"))?);
    info!(count = rules.list().len(), "kurallar yüklendi");

    // Motor başlatılamazsa servis yine de ayakta kalır: arayüz durumu görebilir,
    // kurallar düzenlenebilir.
    let _engine = if with_engine {
        match start_engine(rules.clone()).await {
            Ok(engine) => Some(engine),
            Err(e) => {
                error!("motor başlatılamadı: {e:#}");
                None
            }
        }
    } else {
        None
    };

    let state = Arc::new(ipc::State { rules });
    ipc::serve(state, shutdown).await
    // `_engine` burada düşer: rotalar kaldırılır, trafik normale döner.
}

async fn start_engine(rules: Arc<rules::RuleStore>) -> Result<Engine> {
    let policy = Arc::new(policy::RulePolicy::new(rules, None));
    let config = EngineConfig { wintun_dll: wintun_path()?, routes: FULL_TUNNEL.to_vec() };
    let engine = Engine::start(config, policy.clone()).await?;
    policy.set_tun_if_index(engine.if_index());
    Ok(engine)
}

/// wintun.dll exe'nin yanında dağıtılır.
pub fn wintun_path() -> Result<PathBuf> {
    let exe = std::env::current_exe()?;
    Ok(exe.parent().context("exe klasörü bulunamadı")?.join("wintun.dll"))
}

fn run_console(with_engine: bool) -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(env_filter())
        .with_ansi(router_sys::console::enable_ansi())
        .init();
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        let (tx, rx) = watch::channel(false);
        tokio::spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            info!("durduruluyor");
            let _ = tx.send(true);
        });
        run_core(rx, with_engine).await
    })
}

/// `wintun=off`: Wintun, adaptör henüz yokken "adaptör bulunamadı" diye hata
/// günlüğü yazar; bu beklenen bir durumdur (adaptör hemen oluşturulur). Gerçek
/// Wintun hataları zaten `Result` olarak bize döner.
pub fn env_filter() -> tracing_subscriber::EnvFilter {
    tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info,wintun=off"))
}
