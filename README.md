# nemphyx

A threaded network scanner written in Rust for checking open ports across a host or CIDR range.

## Features

- Scan a single host or a CIDR network range such as `192.168.1.0/24`
- Validate and scan a configurable inclusive port range
- Perform a quick ICMP ping sweep before scanning selected hosts
- Use multiple worker threads for faster scans
- Report open ports with basic service names in a consolidated summary
- Keep the scan logic separated into reusable modules for easier extension

## Project structure

```text
src/
├── app.rs         # orchestration and end-to-end scan flow
├── cli.rs         # clap CLI arguments
├── config.rs      # scan configuration values
├── lib.rs         # crate exports
├── main.rs        # binary entry point
├── network.rs     # TCP/UDP probing helpers
├── report.rs      # result rendering
└── scan.rs        # protocol definitions, pinging, CIDR expansion, port scanning
```

## Build

```bash
cargo build
```

## Run

Scan a single host:

```bash
cargo run -- 192.168.1.3 1 1024
```

Scan a network block:

```bash
cargo run -- 192.168.1.0/24 1 1024
```

Ping sweep before scanning:

```bash
cargo run -- 192.168.1.0/24 1 1024 --ping-sweep
```

Custom timeout and thread count:

```bash
cargo run -- 192.168.1.0/24 20 100 --timeout 1000 -j 100
```

## CLI options

- `--timeout`: connection timeout in milliseconds (default: `500`)
- `-j, --threads`: worker thread count (default: `50`)
- `-p, --protocol`: scan protocol (`tcp` or `udp`, default: `tcp`)
- `--ping-sweep`: only scan hosts that respond to ICMP echo requests

## UDP support

UDP scanning is available behind an optional feature flag:

```bash
cargo run --features udp-scan -- 192.168.1.0/24 53 53 -p udp
```

## Notes

- This tool performs network connection attempts and may be blocked by firewalls or host policies.
- Use it only on networks and systems you are authorized to test.
- The project is designed to be extended with more scan types, results, and output formats.
