//! OS-specific helpers for configuring TUN devices and routes.

use crate::error::{Error, Result};
use std::net::Ipv4Addr;
use std::process::Command;

pub fn configure_tun_macos(name: &str, local_ip: &str, peer_ip: &str) -> Result<()> {
    let status = Command::new("ifconfig")
        .args([name, local_ip, peer_ip])
        .status()?;
    if !status.success() {
        return Err(Error::Server(format!(
            "ifconfig {} {} {} failed",
            name, local_ip, peer_ip
        )));
    }
    Ok(())
}

pub fn configure_tun_linux(name: &str, local_ip: &str) -> Result<()> {
    let cidr = format!("{}/32", local_ip);
    let status = Command::new("ip")
        .args(["addr", "add", &cidr, "dev", name])
        .status()?;
    if !status.success() {
        return Err(Error::Server(format!("ip addr add failed for {}", name)));
    }
    let status = Command::new("ip")
        .args(["link", "set", name, "up"])
        .status()?;
    if !status.success() {
        return Err(Error::Server(format!("ip link set up failed for {}", name)));
    }
    Ok(())
}

pub fn configure_tun(name: &str, local_ip: &str, peer_ip: &str) -> Result<()> {
    if cfg!(target_os = "macos") {
        configure_tun_macos(name, local_ip, peer_ip)
    } else if cfg!(target_os = "linux") {
        configure_tun_linux(name, local_ip)
    } else {
        Err(Error::Server(
            "TUN auto-configuration not implemented for this OS".to_string(),
        ))
    }
}

pub fn add_route_macos(dest: &str, tun_name: &str) -> Result<()> {
    let status = Command::new("route")
        .args(["-n", "add", "-net", dest, "-interface", tun_name])
        .status()?;
    if !status.success() {
        return Err(Error::Server(format!(
            "route add -net {} -interface {} failed",
            dest, tun_name
        )));
    }
    Ok(())
}

pub fn add_route_linux(dest: &str, tun_name: &str) -> Result<()> {
    let status = Command::new("ip")
        .args(["route", "replace", dest, "dev", tun_name])
        .status()?;
    if !status.success() {
        return Err(Error::Server(format!(
            "ip route replace {} dev {} failed",
            dest, tun_name
        )));
    }
    Ok(())
}

pub fn add_route(dest: &str, tun_name: &str) -> Result<()> {
    if cfg!(target_os = "macos") {
        add_route_macos(dest, tun_name)
    } else if cfg!(target_os = "linux") {
        add_route_linux(dest, tun_name)
    } else {
        Err(Error::Server(
            "route management not implemented for this OS".to_string(),
        ))
    }
}

pub fn parse_ipv4(s: &str) -> Result<Ipv4Addr> {
    s.parse::<Ipv4Addr>()
        .map_err(|_| Error::Server(format!("invalid IPv4: {s}")))
}
