use clap::Parser;

use crate::scan::ScanProtocol;

#[derive(Parser, Debug)]
#[command(author, version, about = "Simple threaded TCP/UDP port scanner", long_about = None)]
pub struct Args {
    /// Host to scan (IP address or hostname)
    pub host: String,

    /// Start port in the inclusive range
    pub start_port: u16,

    /// End port in the inclusive range
    pub end_port: u16,

    /// Timeout per connection attempt in milliseconds
    #[arg(short, long, default_value_t = 500)]
    pub timeout: u64,

    /// Number of worker threads to use
    #[arg(short = 'j', long, default_value_t = 50)]
    pub threads: usize,

    /// Protocol to scan for
    #[arg(short, long, value_enum, default_value_t = ScanProtocol::Tcp)]
    pub protocol: ScanProtocol,

    /// Perform an ICMP ping sweep and scan only hosts that respond
    #[arg(long)]
    pub ping_sweep: bool,
}
