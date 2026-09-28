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

The positional arguments are:

- `host`: an IP address, hostname, or IPv4 CIDR range
- `start_port`: first port in the inclusive scan range
- `end_port`: last port in the inclusive scan range

Optional settings are:

| Option | Default | Description |
| --- | ---: | --- |
| `--timeout <milliseconds>` | `500` | Maximum time allowed for each connection attempt |
| `-j, --threads <count>` | `50` | Number of worker threads used for port scanning |
| `-p, --protocol <tcp\|udp>` | `tcp` | Protocol to scan; UDP requires the `udp-scan` feature |
| `--ping-sweep` | disabled | Scan only hosts that respond to an ICMP echo request |

Run `cargo run -- --help` to display the generated command-line help.

## Configuration

Configuration is supplied through command-line arguments and is converted into a `ScanConfig` value before scanning begins. The configuration contains the target host, port range, timeout, worker count, selected protocol, and ping-sweep setting.

Port ranges are inclusive. For example, `20 100` scans ports 20 through 100. The application rejects a range where `start_port` is greater than `end_port`.

Timeouts are specified in milliseconds and apply to each connection attempt. Increasing the timeout can improve results on slower networks but may make scans take longer. The worker count controls concurrency; the scanner limits the effective worker count to the number of ports being scanned.

## UDP support

TCP scanning is enabled by default. UDP scanning is optional and is disabled unless the `udp-scan` Cargo feature is enabled:

```bash
cargo run --features udp-scan -- 192.168.1.0/24 53 53 --protocol udp
```

You can also build the feature-enabled binary first:

```bash
cargo build --features udp-scan
```

Without this feature, selecting `--protocol udp` does not perform UDP probing. Enable the feature when UDP scanning is required.

## Notes

- This tool performs network connection attempts and may be blocked by firewalls or host policies.
- Use it only on networks and systems you are authorized to test.
- The project is designed to be extended with more scan types, results, and output formats.
