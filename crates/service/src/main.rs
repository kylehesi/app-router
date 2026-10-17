//! Router arka plan servisi ve tanılama komutları.

mod diag;
mod ipc;
mod rules;
mod winsvc;

use std::process::ExitCode;
use std::sync::Arc;

use anyhow::Result;
use tokio::sync::watch;
use tracing::info;

const HELP: &str = "\
Router servisi

Kullanım: router-service <komut>

  run          Konsolda çalıştır (geliştirme; Ctrl+C ile durur)
  install      Windows servisi olarak kur ve başlat (yönetici)
  uninstall    Servisi durdur ve kaldır (yönetici)

Tanılama:
  adapters     Ağ adaptörlerini SSID'leriyle listele
  apps         Ağ kullanan uygulamaları listele
  probe <ad>   Belirtilen adaptör üzerinden dış IP'yi göster (örn. probe \"Wi-Fi 2\")
  tun-test     Wintun adaptörünü oluşturup 10 sn paket dinle (yönetici + wintun.dll)
  doctor       Sistemin hazır olup olmadığını kontrol et
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("run") => run_console(),
        Some("service") => winsvc::run_dispatcher(),
        Some("install") => winsvc::install(),
        Some("uninstall") => winsvc::uninstall(),
        Some("adapters") => diag::adapters(),
        Some("apps") => diag::apps(),
        Some("probe") => diag::probe(args.get(1).map(String::as_str)),
        Some("tun-test") => diag::tun_test(),
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
pub async fn run_core(shutdown: watch::Receiver<bool>) -> Result<()> {
    let rules = rules::RuleStore::load(rules::data_dir().join("rules.json"))?;
    info!(count = rules.list().len(), "kurallar yüklendi");
    let state = Arc::new(ipc::State { rules });
    // Faz 2: router_engine burada başlatılacak (TUN + yönlendirme).
    ipc::serve(state, shutdown).await
}

fn run_console() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(env_filter())
        .init();
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        let (tx, rx) = watch::channel(false);
        tokio::spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            info!("durduruluyor");
            let _ = tx.send(true);
        });
        run_core(rx).await
    })
}

pub fn env_filter() -> tracing_subscriber::EnvFilter {
    tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"))
}
