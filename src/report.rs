#[derive(Debug, Clone)]
pub struct PortInfo {
    pub port: u16,
    pub name: String,
    pub protocol: String,
}

pub struct ScanResult {
    pub port: u16,
    pub open: bool,
}

pub fn format_report(host_reports: &[(String, Vec<PortInfo>)]) -> String {
    let mut lines = vec!["=== Host Scan Report ===".to_string()];

    for (host, ports) in host_reports {
        if ports.is_empty() {
            lines.push(format!("- {}: no open ports", host));
        } else {
            let formatted_ports = ports
                .iter()
                .map(|info| format!("{} ({}/{})", info.name, info.port, info.protocol))
                .collect::<Vec<_>>()
                .join(", ");
            lines.push(format!("- {}: {}", host, formatted_ports));
        }
    }

    lines.join("\n")
}
