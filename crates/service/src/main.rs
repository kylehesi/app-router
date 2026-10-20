//! Router background service and diagnostic commands.

mod diag;
mod ipc;
mod monitor;
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

const HELP: &str = "Router service

Usage: router-service <command>

  run [--engine]  Run in the console (development; stop with Ctrl+C).
                  --engine: also start routing (all traffic; administrator)
  install         Install and start as a Windows service (administrator)
  uninstall       Stop and remove the service (administrator)
  firewall        Add the firewall rule for the TUN adapter (administrator)

Diagnostics:
  adapters        List network adapters with their SSIDs
  apps            List applications using the network
  probe <name>    Show the public IP via the given adapter (e.g. probe \"Wi-Fi 2\")
  tun-test        Create the Wintun adapter and capture packets for 10 s (administrator)
  engine-test [name]
                  Run the engine for a few test addresses only and check TCP and
                  UDP relaying end to end; other traffic is untouched (administrator)
  watch           Show adapters becoming available/unavailable live (Ctrl+C to stop)
  doctor          Check whether the system is ready
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
        Some("watch") => diag::watch(),
        Some("doctor") => diag::doctor(),
        _ => {
            print!("{HELP}");
            Ok(())
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

/// The service's actual work; both console mode and the Windows service run this.
pub async fn run_core(shutdown: watch::Receiver<bool>, with_engine: bool) -> Result<()> {
    let rules = Arc::new(rules::RuleStore::load(
        rules::data_dir().join("rules.json"),
    )?);
    info!(count = rules.list().len(), "rules loaded");

    // If the engine fails to start, the service stays up anyway: the UI can still
    // see the status and rules can still be edited.
    let _engine = if with_engine {
        match start_engine(rules.clone()).await {
            Ok((engine, policy)) => {
                tokio::spawn(monitor::run(policy, engine.flows(), shutdown.clone()));
                Some(engine)
            }
            Err(e) => {
                error!("failed to start engine: {e:#}");
                None
            }
        }
    } else {
        None
    };

    let state = Arc::new(ipc::State { rules });
    ipc::serve(state, shutdown).await
    // `_engine` is dropped here: routes are removed and traffic goes back to normal.
}

async fn start_engine(rules: Arc<rules::RuleStore>) -> Result<(Engine, Arc<policy::RulePolicy>)> {
    let policy = Arc::new(policy::RulePolicy::new(rules, None));
    let config = EngineConfig {
        wintun_dll: wintun_path()?,
        routes: FULL_TUNNEL.to_vec(),
    };
    let engine = Engine::start(config, policy.clone()).await?;
    policy.set_tun_if_index(engine.if_index());
    Ok((engine, policy))
}

/// wintun.dll ships next to the exe.
pub fn wintun_path() -> Result<PathBuf> {
    let exe = std::env::current_exe()?;
    Ok(exe
        .parent()
        .context("could not determine the exe directory")?
        .join("wintun.dll"))
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
            info!("stopping");
            let _ = tx.send(true);
        });
        run_core(rx, with_engine).await
    })
}

/// `wintun=off`: Wintun logs an "adapter not found" error when the adapter does
/// not exist yet; that is expected (we create it right away). Real Wintun errors
/// are returned to us as `Result` anyway.
pub fn env_filter() -> tracing_subscriber::EnvFilter {
    tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info,wintun=off"))
}
