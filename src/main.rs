use clap::Parser;
use std::net::{TcpStream, ToSocketAddrs};
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

fn main() {
    let args = Args::parse();

    if args.start_port > args.end_port {
        eprintln!("Error: start_port must be less than or equal to end_port.");
        std::process::exit(1);
    }

    let total_ports = (args.end_port - args.start_port + 1) as usize;
    let workers = args.threads.clamp(1, total_ports);
    let timeout = Duration::from_millis(args.timeout);

    println!(
        "Scanning {} from {} to {} with {} worker(s) and {}ms timeout...\n",
        args.host, args.start_port, args.end_port, workers, args.timeout
    );

    let start_time = Instant::now();
    let (port_sender, port_receiver) = mpsc::channel::<u16>();
    let port_receiver = Arc::new(Mutex::new(port_receiver));
    let (result_sender, result_receiver) = mpsc::channel::<ScanResult>();

    for _ in 0..workers {
        let host = args.host.clone();
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

    for port in args.start_port..=args.end_port {
        if port_sender.send(port).is_err() {
            break;
        }
    }
    drop(port_sender);

    let mut open_ports = Vec::new();
    for result in result_receiver.iter() {
        if result.open {
            open_ports.push(result.port);
            let (service_name, service_type) = service_info(result.port);
            println!(
                "Port {} is OPEN ({}/{})",
                result.port,
                service_name,
                service_type
            );
        }
    }

    let elapsed = start_time.elapsed();
    println!("\nScan complete.");
    println!("Open ports: {}", open_ports.len());
    if !open_ports.is_empty() {
        open_ports.sort_unstable();
        println!("{}", open_ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", "));
    }
    println!("Elapsed: {:.2}s", elapsed.as_secs_f64());
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
