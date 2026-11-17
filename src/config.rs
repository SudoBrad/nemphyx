use std::time::Duration;

use crate::cli::Args;
use crate::scan::ScanProtocol;

#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub host: String,
    pub start_port: u16,
    pub end_port: u16,
    pub timeout: Duration,
    pub threads: usize,
    pub protocol: ScanProtocol,
    pub ping_sweep: bool,
    pub service_audit: bool,
    pub insecure_tls: bool,
}

impl From<Args> for ScanConfig {
    fn from(args: Args) -> Self {
        Self {
            host: args.host,
            start_port: args.start_port,
            end_port: args.end_port,
            timeout: Duration::from_millis(args.timeout),
            threads: args.threads,
            protocol: args.protocol,
            ping_sweep: args.ping_sweep,
            service_audit: args.service_audit,
            insecure_tls: args.insecure_tls,
        }
    }
}
