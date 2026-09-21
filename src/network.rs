use std::net::{SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::time::Duration;

use crate::scan::ScanProtocol;

pub fn scan_port(host: &str, port: u16, timeout: Duration, protocol: ScanProtocol) -> bool {
    let address = format!("{}:{}", host, port);
    if let Ok(mut addresses) = address.to_socket_addrs() {
        if let Some(socket_addr) = addresses.next() {
            return match protocol {
                ScanProtocol::Tcp => TcpStream::connect_timeout(&socket_addr, timeout).is_ok(),
                #[cfg(feature = "udp-scan")]
                ScanProtocol::Udp => probe_udp_socket(&socket_addr, timeout),
                #[cfg(not(feature = "udp-scan"))]
                ScanProtocol::Udp => {
                    eprintln!("UDP scanning is disabled in this build.");
                    false
                }
            };
        }
    }
    false
}

pub fn probe_udp_socket(socket_addr: &SocketAddr, timeout: Duration) -> bool {
    match UdpSocket::bind("0.0.0.0:0") {
        Ok(socket) => {
            if socket.set_read_timeout(Some(timeout)).is_ok() {
                if socket.send_to(b"", socket_addr).is_ok() {
                    return socket.recv_from(&mut [0u8; 1]).is_ok();
                }
            }
        }
        Err(_) => {}
    }
    false
}
