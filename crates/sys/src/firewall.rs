//! Windows Güvenlik Duvarı kuralı.
//!
//! TCP aktarımı, Windows'un TCP yığınındaki yerel dinleyiciye TUN üzerinden
//! gelen bağlantılara dayanır. Güvenlik duvarı TUN'u "genel ağ" sayıp bu
//! bağlantıları engelleyebileceğinden, yalnızca TUN içindeki iki sabit adres
//! arasındaki TCP trafiğine izin veren dar bir kural eklenir.

use std::io;
use std::net::Ipv4Addr;
use std::os::windows::process::CommandExt;
use std::process::{Command, Stdio};

pub const RULE_NAME: &str = "Router TUN";

fn netsh() -> Command {
    let mut cmd = Command::new("netsh");
    cmd.stdout(Stdio::null()).stderr(Stdio::null());
    cmd
}

/// Kural tanımlı mı?
pub fn rule_exists() -> bool {
    netsh()
        .args(["advfirewall", "firewall", "show", "rule"])
        .raw_arg(format!("name=\"{RULE_NAME}\""))
        .status()
        .is_ok_and(|s| s.success())
}

/// `peer → local` yönündeki gelen TCP bağlantılarına izin veren kuralı ekler
/// (varsa önce eskisini siler). Yönetici yetkisi gerekir.
pub fn ensure_rule(local: Ipv4Addr, peer: Ipv4Addr) -> io::Result<()> {
    if rule_exists() {
        remove_rule()?;
    }
    let status = netsh()
        .args(["advfirewall", "firewall", "add", "rule"])
        .raw_arg(format!("name=\"{RULE_NAME}\""))
        .args([
            "dir=in",
            "action=allow",
            "protocol=TCP",
            "profile=any",
            "enable=yes",
            &format!("localip={local}"),
            &format!("remoteip={peer}"),
        ])
        .status()?;
    if !status.success() {
        return Err(io::Error::other(format!(
            "güvenlik duvarı kuralı eklenemedi (netsh çıkış kodu {:?}); yönetici olarak çalıştırın",
            status.code()
        )));
    }
    Ok(())
}

pub fn remove_rule() -> io::Result<()> {
    let status = netsh()
        .args(["advfirewall", "firewall", "delete", "rule"])
        .raw_arg(format!("name=\"{RULE_NAME}\""))
        .status()?;
    if !status.success() {
        return Err(io::Error::other("güvenlik duvarı kuralı silinemedi"));
    }
    Ok(())
}
