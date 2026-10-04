use std::fmt;
use std::net::Ipv4Addr;
use std::process::{Command, Stdio};
use std::str::FromStr;
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use clap::ValueEnum;

use crate::network::scan_port;
use crate::report::{PortInfo, ScanResult};

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum ScanProtocol {
    Tcp,
    Udp,
}

impl fmt::Display for ScanProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScanProtocol::Tcp => write!(f, "tcp"),
            ScanProtocol::Udp => write!(f, "udp"),
        }
    }
}

impl FromStr for ScanProtocol {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "tcp" => Ok(Self::Tcp),
            "udp" => Ok(Self::Udp),
            _ => Err(format!("unsupported protocol: {s}")),
        }
    }
}

pub fn ping_host(host: &str, timeout: Duration) -> bool {
    let timeout_secs = (timeout.as_millis().max(1000) / 1000).max(1).to_string();
    let command = if cfg!(windows) {
        Command::new("ping")
            .args(["-n", "1", "-w", &timeout_secs, host])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
    } else {
        Command::new("ping")
            .args(["-c", "1", "-W", &timeout_secs, host])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
    };

    match command {
        Ok(status) => status.success(),
        Err(_) => false,
    }
}

pub fn discover_alive_hosts(hosts: &[String], timeout: Duration) -> Vec<String> {
    hosts
        .iter()
        .filter(|host| ping_host(host, timeout))
        .cloned()
        .collect()
}

pub fn expand_targets(target: &str) -> Vec<String> {
    if let Some((network, prefix)) = target.split_once('/') {
        let Ok(ip) = Ipv4Addr::from_str(network) else {
            return Vec::new();
        };
        let Ok(prefix_len) = prefix.parse::<u8>() else {
            return Vec::new();
        };
        if prefix_len > 32 {
            return Vec::new();
        }

        let ip_u32 = u32::from(ip);
        let prefix_len = prefix_len as u32;
        let mask = if prefix_len == 0 {
            0
        } else {
            u32::MAX << (32 - prefix_len)
        };
        let network_u32 = ip_u32 & mask;
        let broadcast_u32 = if prefix_len == 0 {
            u32::MAX
        } else {
            network_u32 | (!mask & u32::MAX)
        };

        if prefix_len >= 32 {
            return vec![ip.to_string()];
        }

        let mut hosts = Vec::new();
        for host_u32 in (network_u32 + 1)..broadcast_u32 {
            let host = Ipv4Addr::from(host_u32);
            hosts.push(host.to_string());
        }
        return hosts;
    }

    vec![target.to_string()]
}

pub fn scan_target(
    host: &str,
    start_port: u16,
    end_port: u16,
    timeout: Duration,
    threads: usize,
    protocol: ScanProtocol,
) -> Vec<PortInfo> {
    let total_ports = (end_port - start_port + 1) as usize;
    let workers = threads.clamp(1, total_ports);

    println!(
        "\nScanning {} from {} to {} with {} worker(s) over {}...",
        host, start_port, end_port, workers, protocol
    );

    let start_time = Instant::now();
    let (port_sender, port_receiver) = mpsc::channel::<u16>();
    let port_receiver = Arc::new(Mutex::new(port_receiver));
    let (result_sender, result_receiver) = mpsc::channel::<ScanResult>();

    for _ in 0..workers {
        let host = host.to_string();
        let port_receiver = Arc::clone(&port_receiver);
        let result_sender = result_sender.clone();

        thread::spawn(move || {
            loop {
                let port = {
                    let receiver_guard = port_receiver.lock().unwrap();
                    receiver_guard.recv()
                };

                match port {
                    Ok(port) => {
                        let open = scan_port(&host, port, timeout, protocol);
                        let _ = result_sender.send(ScanResult { port, open });
                    }
                    Err(_) => break,
                }
            }
        });
    }

    drop(result_sender);

    for port in start_port..=end_port {
        if port_sender.send(port).is_err() {
            break;
        }
    }
    drop(port_sender);

    let mut open_ports = Vec::new();
    for result in result_receiver.iter() {
        if result.open {
            let (service_name, service_type) = service_info(result.port);
            open_ports.push(PortInfo {
                port: result.port,
                name: service_name.to_string(),
                protocol: service_type.to_string(),
            });
        }
    }

    let elapsed = start_time.elapsed();
    println!("Elapsed: {:.2}s", elapsed.as_secs_f64());
    open_ports
}

pub fn service_info(port: u16) -> (&'static str, &'static str) {
    match port {
        20 | 21 => ("ftp", "TCP"),
        22 => ("ssh", "TCP"),
        23 => ("telnet", "TCP"),
        25 => ("smtp", "TCP"),
        53 => ("dns", "UDP"),
        80 => ("http", "TCP"),
        110 => ("pop3", "TCP"),
        123 => ("ntp", "UDP"),
        143 => ("imap", "TCP"),
        161 | 162 => ("snmp", "UDP"),
        194 => ("irc", "TCP"),
        443 => ("https", "TCP"),
        445 => ("microsoft-ds", "TCP"),
        554 => ("rtsp", "TCP"),
        465 => ("smtps", "TCP"),
        587 => ("smtp", "TCP"),
        631 => ("ipp", "TCP"),
        993 => ("imaps", "TCP"),
        995 => ("pop3s", "TCP"),
        3306 => ("mysql", "TCP"),
        3389 => ("ms-wbt-server", "TCP"),
        5900 => ("vnc", "TCP"),
        8080 => ("http-alt", "TCP"),
        _ => ("unknown", "TCP"),
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use std::time::Duration;

    use super::{ScanProtocol, expand_targets};

    #[test]
    fn parses_udp_protocol() {
        assert_eq!(ScanProtocol::from_str("udp").unwrap(), ScanProtocol::Udp);
        assert_eq!(ScanProtocol::from_str("TCP").unwrap(), ScanProtocol::Tcp);
    }

    #[test]
    fn detects_loopback_with_ping() {
        assert!(super::ping_host("127.0.0.1", Duration::from_millis(500)));
    }

    #[test]
    fn expands_single_host_without_cidr() {
        assert_eq!(expand_targets("localhost"), vec!["localhost".to_string()]);
    }

    #[test]
    fn expands_ipv4_cidr_to_hosts() {
        let hosts = expand_targets("192.168.1.0/24");
        assert_eq!(hosts.first(), Some(&"192.168.1.1".to_string()));
        assert_eq!(hosts.last(), Some(&"192.168.1.254".to_string()));
    }

    #[test]
    fn rejects_invalid_cidr() {
        assert!(expand_targets("192.168.1.0/33").is_empty());
    }
}
