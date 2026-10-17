//! Windows servis yaşam döngüsü: kurma, kaldırma ve SCM'den başlatılma.

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

const DISPLAY_NAME: &str = "Router - Uygulama Bazlı İnternet";
const DESCRIPTION: &str =
    "Uygulamaların hangi internet bağlantısını (Wi-Fi, hotspot, Ethernet) kullanacağını yönetir.";

define_windows_service!(ffi_service_main, service_main);

/// SCM tarafından `router-service.exe service` ile başlatıldığında çağrılır.
pub fn run_dispatcher() -> Result<()> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
        .context("servis dağıtıcısı başlatılamadı (bu komut yalnızca Windows tarafından çağrılır)")
}

fn service_main(_args: Vec<OsString>) {
    init_file_logging();
    if let Err(e) = run_service() {
        error!("servis hatayla durdu: {e:#}");
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
    info!("servis başladı");

    let result = tokio::runtime::Runtime::new()
        .context("tokio başlatılamadı")
        .and_then(|rt| rt.block_on(crate::run_core(rx, true)));

    // Hata durumunda sıfır olmayan kod: SCM bunu çökme sayar ve kurtarma ayarına göre yeniden başlatır.
    let code = if result.is_ok() { 0 } else { 1 };
    set_state(ServiceState::Stopped, ServiceControlAccept::empty(), code)?;
    info!("servis durdu");
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
    .context("Servis yöneticisine erişilemedi (yönetici olarak çalıştırın)")?;

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
        .context("servis oluşturulamadı (zaten kurulu olabilir)")?;
    service.set_description(DESCRIPTION)?;

    // Çökerse 5 sn sonra kendini yeniden başlatır.
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

    // Windows'un ikinci bağlantıyı kendiliğinden düşürmesini engeller.
    match router_sys::policy::allow_simultaneous_connections() {
        Ok(()) => println!("Eşzamanlı bağlantı politikası ayarlandı (fMinimizeConnections = 0)."),
        Err(e) => warn!("eşzamanlı bağlantı politikası ayarlanamadı: {e}"),
    }
    router_sys::firewall::ensure_rule(router_engine::TUN_IP, router_engine::PEER_IP)
        .context("güvenlik duvarı kuralı eklenemedi")?;
    println!("Güvenlik duvarı kuralı eklendi ('{}').", router_sys::firewall::RULE_NAME);

    service.start::<&str>(&[]).context("servis başlatılamadı")?;
    println!("'{SERVICE_NAME}' kuruldu ve başlatıldı.");
    Ok(())
}

pub fn uninstall() -> Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .context("Servis yöneticisine erişilemedi (yönetici olarak çalıştırın)")?;
    let service = manager
        .open_service(
            SERVICE_NAME,
            ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
        )
        .context("servis bulunamadı")?;

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
    println!("'{SERVICE_NAME}' kaldırıldı.");
    Ok(())
}
