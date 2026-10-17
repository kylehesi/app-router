//! Windows Firewall rule.
//!
//! The TCP relay relies on connections arriving over the TUN at a local
//! listener in the Windows TCP stack. The firewall may treat the TUN as a
//! "public network" and block them, so we add a narrow rule that only allows
//! TCP traffic between two fixed addresses inside the TUN.

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

/// Does the rule exist?
pub fn rule_exists() -> bool {
    netsh()
        .args(["advfirewall", "firewall", "show", "rule"])
        .raw_arg(format!("name=\"{RULE_NAME}\""))
        .status()
        .is_ok_and(|s| s.success())
}

/// Adds the rule allowing inbound TCP connections `peer -> local`
/// (deleting any existing one first). Requires administrator rights.
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
            "failed to add firewall rule (netsh exit code {:?}); run as administrator",
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
        return Err(io::Error::other("failed to delete firewall rule"));
    }
    Ok(())
}
