use std::env;
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() == 2 && (args[1] == "-h" || args[1] == "--help") {
        print_help(&args[0]);
        return;
    }

    if args.len() != 4 {
        println!(
            "Usage: {} <host> <start_port> <end_port>",
            args[0]
        );
        println!("Try '{} -h' for more information.", args[0]);
        return;
    }

    let host = &args[1];

    let start_port: u16 = args[2]
        .parse()
        .expect("Invalid start port");

    let end_port: u16 = args[3]
        .parse()
        .expect("Invalid end port");

    println!(
        "Scanning {} from {} to {}...\n",
        host,
        start_port,
        end_port
    );

    for port in start_port..=end_port {
        let address = format!("{}:{}", host, port);

        if let Ok(mut addresses) = address.to_socket_addrs() {
            if let Some(socket_addr) = addresses.next() {
                let timeout = Duration::from_millis(500);

                if TcpStream::connect_timeout(&socket_addr, timeout).is_ok() {
                    println!("Port {} is OPEN", port);
                }
            }
        }
    }

    println!("\nScan complete.");
}

fn print_help(program_name: &str) {
    println!("Usage: {} <host> <start_port> <end_port>", program_name);
    println!("");
    println!("Scans the specified host for open TCP ports in the given inclusive range.");
    println!("");
    println!("Flags:");
    println!("  -h, --help    Show this help message");
    println!("");
    println!("Examples:");
    println!("  {} example.com 1 1024", program_name);
    println!("  {} 127.0.0.1 80 80", program_name);
}