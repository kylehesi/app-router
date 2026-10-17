//! Windows service lifecycle: install, uninstall and startup from the SCM.

use std::ffi::OsString;
use std::sync::Mutex;
use std::time::Duration;

use anyhow::{Context, Result};
use router_common::SERVICE_NAME;
use tokio::sync::watch;
use tracing::{error, info, warn};
use windows_service::service::{
    ServiceAccess, ServiceAction, ServiceActionType, ServiceControl, ServiceControlAccept,
    ServiceErrorControl, ServiceExitCode, ServiceFailureActions, ServiceFailureResetPeriod,
    ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};

use crate::rules::data_dir;

const DISPLAY_NAME: &str = "Router - Per-App Internet";
const DESCRIPTION: &str =
    "Lets you choose which internet connection (Wi-Fi, hotspot, Ethernet) each application uses.";

define_windows_service!(ffi_service_main, service_main);

/// Called when the SCM starts us as `router-service.exe service`.
pub fn run_dispatcher() -> Result<()> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
        .context("failed to start the service dispatcher (this command is only meant to be invoked by Windows)")
}

fn service_main(_args: Vec<OsString>) {
    init_file_logging();
    if let Err(e) = run_service() {
        error!("service stopped with an error: {e:#}");
    }
}

fn run_service() -> Result<()> {
    let (tx, rx) = watch::channel(false);
    let handler = move |event| match event {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            let _ = tx.send(true);
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let status = service_control_handler::register(SERVICE_NAME, handler)?;
    let set_state = |state: ServiceState, accept: ServiceControlAccept, code: u32| {
        status.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: accept,
            exit_code: ServiceExitCode::Win32(code),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })
    };

    set_state(
        ServiceState::Running,
        ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        0,
    )?;
    info!("service started");

    let result = tokio::runtime::Runtime::new()
        .context("failed to start tokio")
        .and_then(|rt| rt.block_on(crate::run_core(rx, true)));

    // Non-zero code on error: the SCM counts it as a crash and restarts us per the recovery settings.
    let code = if result.is_ok() { 0 } else { 1 };
    set_state(ServiceState::Stopped, ServiceControlAccept::empty(), code)?;
    info!("service stopped");
    result
}

fn init_file_logging() {
    let dir = data_dir();
    let _ = std::fs::create_dir_all(&dir);
    if let Ok(file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join("service.log"))
    {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(crate::env_filter())
            .with_ansi(false)
            .with_writer(Mutex::new(file))
            .try_init();
    }
}

pub fn install() -> Result<()> {
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )
    .context("cannot access the Service Control Manager (run as administrator)")?;

    let info = ServiceInfo {
        name: SERVICE_NAME.into(),
        display_name: DISPLAY_NAME.into(),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: std::env::current_exe()?,
        launch_arguments: vec!["service".into()],
        dependencies: vec![],
        account_name: None, // LocalSystem
        account_password: None,
    };
    let service = manager
        .create_service(&info, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START)
        .context("failed to create the service (it may already be installed)")?;
    service.set_description(DESCRIPTION)?;

    // Restart automatically 5 s after a crash.
    let restart = ServiceAction {
        action_type: ServiceActionType::Restart,
        delay: Duration::from_secs(5),
    };
    service.update_failure_actions(ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(24 * 60 * 60)),
        reboot_msg: None,
        command: None,
        actions: Some(vec![restart.clone(), restart.clone(), restart]),
    })?;
    service.set_failure_actions_on_non_crash_failures(true)?;

    // Stops Windows from dropping the second connection on its own.
    match router_sys::policy::allow_simultaneous_connections() {
        Ok(()) => println!("Simultaneous connections policy set (fMinimizeConnections = 0)."),
        Err(e) => warn!("failed to set the simultaneous connections policy: {e}"),
    }
    router_sys::firewall::ensure_rule(router_engine::TUN_IP, router_engine::PEER_IP)
        .context("failed to add the firewall rule")?;
    println!("Firewall rule added ('{}').", router_sys::firewall::RULE_NAME);

    service.start::<&str>(&[]).context("failed to start the service")?;
    println!("'{SERVICE_NAME}' installed and started.");
    Ok(())
}

pub fn uninstall() -> Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .context("cannot access the Service Control Manager (run as administrator)")?;
    let service = manager
        .open_service(
            SERVICE_NAME,
            ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
        )
        .context("service not found")?;

    if service.query_status()?.current_state != ServiceState::Stopped {
        service.stop()?;
        for _ in 0..50 {
            if service.query_status()?.current_state == ServiceState::Stopped {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
    service.delete()?;
    if router_sys::firewall::rule_exists() {
        router_sys::firewall::remove_rule()?;
    }
    println!("'{SERVICE_NAME}' removed.");
    Ok(())
}
