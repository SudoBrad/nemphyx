use crate::audit::audit_target;
use crate::cli::Args;
use crate::config::ScanConfig;
use crate::report::format_report;
use crate::scan::{discover_alive_hosts, expand_targets, scan_target};

pub fn run(args: Args) -> Result<(), String> {
    if args.start_port > args.end_port {
        return Err("start_port must be less than or equal to end_port".to_string());
    }

    let config = ScanConfig::from(args);
    if config.service_audit && (config.host.contains('/') || config.ping_sweep) {
        return Err("--service-audit requires one explicitly specified host; CIDR ranges and --ping-sweep are not supported".to_string());
    }
    if config.service_audit && config.protocol != crate::scan::ScanProtocol::Tcp {
        return Err("--service-audit requires TCP scanning".to_string());
    }

    let targets = expand_targets(&config.host);
    if targets.is_empty() {
        return Err(format!("unable to expand target range {}", config.host));
    }

    let targets = if config.ping_sweep {
        let alive = discover_alive_hosts(&targets, config.timeout);
        println!(
            "Ping sweep found {} host(s) responding to ICMP.",
            alive.len()
        );
        alive
    } else {
        targets
    };

    if targets.is_empty() {
        return Err("no hosts responded to the ping sweep".to_string());
    }

    println!(
        "Scanning {} host(s) in {} from {} to {} with {}ms timeout using {}...",
        targets.len(),
        config.host,
        config.start_port,
        config.end_port,
        config.timeout.as_millis(),
        config.protocol
    );

    let mut host_reports = Vec::new();
    for host in &targets {
        let ports = scan_target(
            host,
            config.start_port,
            config.end_port,
            config.timeout,
            config.threads,
            config.protocol,
        );
        host_reports.push((host.clone(), ports));
    }

    println!("\nScan complete.");
    println!("{}", format_report(&host_reports));

    let total_open_ports = host_reports
        .iter()
        .map(|(_, ports)| ports.len())
        .sum::<usize>();
    let hosts_with_open_ports = host_reports
        .iter()
        .filter(|(_, ports)| !ports.is_empty())
        .count();

    println!("Hosts scanned: {}", targets.len());
    println!("Hosts with open ports: {}", hosts_with_open_ports);
    println!("Total open ports found: {}", total_open_ports);

    if config.service_audit {
        audit_target(&config.host, config.timeout, config.insecure_tls)?;
    }

    Ok(())
}
