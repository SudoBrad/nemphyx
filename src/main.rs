use clap::Parser;
use std::net::{Ipv4Addr, TcpStream, ToSocketAddrs};
use std::str::FromStr;
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Parser, Debug)]
#[command(author, version, about = "Simple threaded TCP port scanner", long_about = None)]
struct Args {
    /// Host to scan (IP address or hostname)
    host: String,

    /// Start port in the inclusive range
    start_port: u16,

    /// End port in the inclusive range
    end_port: u16,

    /// Timeout per connection attempt in milliseconds
    #[arg(short, long, default_value_t = 500)]
    timeout: u64,

    /// Number of worker threads to use
    #[arg(short = 'j', long, default_value_t = 50)]
    threads: usize,
}

struct ScanResult {
    port: u16,
    open: bool,
}

struct PortInfo {
    port: u16,
    name: String,
    protocol: String,
}

fn main() {
    let args = Args::parse();

    if args.start_port > args.end_port {
        eprintln!("Error: start_port must be less than or equal to end_port.");
        std::process::exit(1);
    }

    let timeout = Duration::from_millis(args.timeout);
    let targets = expand_targets(&args.host);
    if targets.is_empty() {
        eprintln!("Error: unable to expand target range {}.", args.host);
        std::process::exit(1);
    }

    println!(
        "Scanning {} host(s) in {} from {} to {} with {}ms timeout...",
        targets.len(),
        args.host,
        args.start_port,
        args.end_port,
        args.timeout
    );

    let mut host_reports = Vec::new();
    for host in &targets {
        let host_open_ports = scan_target(host, args.start_port, args.end_port, timeout, args.threads);
        host_reports.push((host.clone(), host_open_ports));
    }

    println!("\nScan complete.");
    println!("{}", format_report(&host_reports));
    let total_open_ports = host_reports.iter().map(|(_, ports)| ports.len()).sum::<usize>();
    let hosts_with_open_ports = host_reports.iter().filter(|(_, ports)| !ports.is_empty()).count();
    println!("Hosts scanned: {}", targets.len());
    println!("Hosts with open ports: {}", hosts_with_open_ports);
    println!("Total open ports found: {}", total_open_ports);
}

fn scan_target(host: &str, start_port: u16, end_port: u16, timeout: Duration, threads: usize) -> Vec<PortInfo> {
    let total_ports = (end_port - start_port + 1) as usize;
    let workers = threads.clamp(1, total_ports);

    println!("\nScanning {} from {} to {} with {} worker(s)...", host, start_port, end_port, workers);

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
                        let open = scan_port(&host, port, timeout);
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

fn format_report(host_reports: &[(String, Vec<PortInfo>)]) -> String {
    let mut lines = vec!["=== Host Scan Report ===".to_string()];

    for (host, ports) in host_reports {
        if ports.is_empty() {
            lines.push(format!("- {}: no open ports", host));
        } else {
            let formatted_ports = ports
                .iter()
                .map(|info| format!("{} ({})", info.name, info.port))
                .collect::<Vec<_>>()
                .join(", ");
            lines.push(format!("- {}: {}", host, formatted_ports));
        }
    }

    lines.join("\n")
}

fn expand_targets(target: &str) -> Vec<String> {
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

fn scan_port(host: &str, port: u16, timeout: Duration) -> bool {
    let address = format!("{}:{}", host, port);
    if let Ok(mut addresses) = address.to_socket_addrs() {
        if let Some(socket_addr) = addresses.next() {
            return TcpStream::connect_timeout(&socket_addr, timeout).is_ok();
        }
    }
    false
}

fn service_info(port: u16) -> (&'static str, &'static str) {
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
    use super::expand_targets;

    #[test]
    fn expands_single_host_without_cidr() {
        assert_eq!(expand_targets("localhost"), vec!["localhost".to_string()]);
    }

    #[test]
    fn expands_ipv4_cidr_to_hosts() {
        let hosts = expand_targets("192.168.1.0/24");
        assert_eq!(hosts.first(), Some(&"192.168.1.1".to_string()));
        assert_eq!(hosts.last(), Some(&"192.168.1.254".to_string()));
        assert_eq!(hosts.len(), 254);
    }

    #[test]
    fn rejects_invalid_prefix() {
        assert!(expand_targets("192.168.1.0/33").is_empty());
    }

    #[test]
    fn formats_host_report() {
        let report = super::format_report(&[
            (
                "192.168.1.1".to_string(),
                vec![
                    super::PortInfo {
                        port: 22,
                        name: "ssh".to_string(),
                        protocol: "TCP".to_string(),
                    },
                    super::PortInfo {
                        port: 80,
                        name: "http".to_string(),
                        protocol: "TCP".to_string(),
                    },
                ],
            ),
            ("192.168.1.2".to_string(), vec![]),
        ]);

        assert!(report.contains("192.168.1.1"));
        assert!(report.contains("ssh (22)"));
        assert!(report.contains("http (80)"));
        assert!(report.contains("no open ports"));
    }
}
