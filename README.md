# nemphyx

A simple threaded TCP port scanner written in Rust.

## Features

- Scan a single host or a CIDR network range such as 192.168.1.0/24
- Scan a configurable port range
- Use multiple worker threads for faster scanning
- Report open ports with service names in a consolidated summary

## Build

```bash
cargo build
```

## Usage

Scan a single host:

```bash
cargo run -- 192.168.1.3 1 1024
```

Scan a whole network range:

```bash
cargo run -- 192.168.1.0/24 1 1024
```

Options:

- `--timeout` sets the connection timeout in milliseconds (default: 500)
- `-j, --threads` sets the number of worker threads (default: 50)

Example with custom values:

```bash
cargo run -- 192.168.1.0/24 20 100 --timeout 1000 -j 100
```

## Notes

- This tool performs TCP connection attempts and may be blocked by firewalls or network policies.
- Use it only on networks and systems you are authorized to scan.
