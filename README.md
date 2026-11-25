# RustSweeper

An agentless, Lansweeper-style network asset inventory written in Rust. One self-contained
binary scans your network, keeps an inventory in SQLite, tracks changes over time, and serves a
web dashboard plus a JSON API.

## What it discovers

| Technique | What you get |
|---|---|
| TCP connect probe (27 common ports by default) | Open ports, and liveness (even a "closed" RST proves the host is up) |
| ICMP ping (via the OS `ping` tool, no admin rights needed) | Liveness + TTL (OS hint) |
| NetBIOS node status (UDP 137) | Windows computer name, domain/workgroup, MAC — works across routed subnets |
| SNMP v2c (UDP 161) | sysName, sysDescr, sysLocation, sysContact, sysObjectID |
| ARP cache | MAC addresses on local subnets, and hosts that block everything else |
| Reverse DNS | DNS hostname |
| Banners | SSH/FTP/SMTP/Telnet banners, HTTP `Server` header and page `<title>` |
| OUI lookup | Hardware vendor from MAC (built-in table, or load the full IEEE list) |

Results are fingerprinted into device types: Windows Workstation / Server / Domain Controller,
Linux/Unix Server, Printer, Network Device, VoIP Phone, Camera, UPS, NAS, Hypervisor,
Medical (HL7 2575 / DICOM 104), Apple Device, Raspberry Pi, and virtual machines.

## Features

- **Dashboard** with totals, online/offline, new assets, breakdown by type and vendor
- **Asset list** with search (IP, name, MAC, vendor, OS, port number, service, notes), filters, sorting, CSV export
- **Asset detail** with identity, open ports + banners, SNMP and web info, editable notes, full change history
- **Change tracking**: discovered, IP/MAC/hostname/OS/type changes, ports opened/closed, online→offline
- **Scheduled scans** (hourly / daily / weekly …) that run while the server is up
- **REST API** for scripting and integrations
- Optional **HTTP basic auth**; listens on localhost only by default

## Build

Requires Rust 1.80+ (`https://rustup.rs`). On Windows, install the MSVC build tools when rustup asks.

```sh
cargo build --release
# binary: target/release/rustsweeper(.exe)
```

## Usage

```sh
# Web dashboard (http://127.0.0.1:8080)
rustsweeper serve

# Make it reachable from other machines — use auth!
rustsweeper serve --bind 0.0.0.0:8080 --auth admin:S3cret!

# One-off scan from the command line
rustsweeper scan 10.10.0.0/24 10.10.5.10-60 printer01

# Query the inventory
rustsweeper assets --search printer
rustsweeper assets --csv > inventory.csv
rustsweeper show 10.10.0.25
rustsweeper scans

# Schedules (executed by `serve`)
rustsweeper schedule add "Main clinic LAN" 10.10.0.0/22 --every 1440
rustsweeper schedule list
```

Useful scan flags (work with both `serve` and `scan`):

```
--ports 22,80,443,3389        custom port list
--snmp-community public,clinicRO
--concurrency 64              hosts probed in parallel
--timeout-ms 800              per-connection timeout
--no-ping                     skip ICMP
--db path/to/rustsweeper.db   database location (or RUSTSWEEPER_DB)
--oui-file oui.csv            full vendor list (or RUSTSWEEPER_OUI)
```

For full MAC-vendor coverage, download `https://standards-oui.ieee.org/oui/oui.csv` and pass
`--oui-file oui.csv`.

## REST API

| Method | Path | Notes |
|---|---|---|
| GET | `/api/stats` | Totals and breakdowns |
| GET | `/api/assets?q=&type=&status=&sort=&desc=1` | Asset list |
| GET | `/api/assets/{id}` | Asset + ports + change history |
| GET | `/api/scans` | Scan history |
| POST | `/api/scans` | Body `{"targets":"10.0.0.0/24"}` → `{"id": n}` |
| GET | `/api/scans/{id}` | Scan status + live progress |

CSV export: `GET /export.csv` (takes the same filters as the asset list).

## Running as a Windows service

Easiest is [NSSM](https://nssm.cc/):

```
nssm install RustSweeper C:\RustSweeper\rustsweeper.exe serve --db C:\RustSweeper\rustsweeper.db --bind 0.0.0.0:8080 --auth admin:CHANGE_ME
nssm start RustSweeper
```

## Notes and limits

- Only scan networks you're authorized to scan. The scanner uses normal TCP connects and a
  few UDP queries; it's light, but IDS tools may still flag it.
- MAC addresses come from the ARP cache (same subnet) or NetBIOS (any subnet, Windows/Samba).
- Per-scan limit is 65,536 addresses (a /16).
- Basic auth sends credentials in clear text; put it behind HTTPS (IIS/nginx reverse proxy)
  if it's reachable beyond the IT VLAN.
- This version is agentless and unauthenticated. Credentialed inventory (installed software,
  hardware specs via WMI/WinRM, SSH) or an endpoint agent are natural next steps.

## Project layout

```
src/
  main.rs              CLI (clap)
  db.rs                SQLite schema, upserts, change tracking
  web.rs               axum dashboard, REST API, CSV export, scheduler
  scanner/
    mod.rs             scan orchestration
    targets.rs         CIDR / range / hostname parsing
    probe.rs           TCP probe, ping, reverse DNS, banners, HTTP
    netbios.rs         NBSTAT query
    snmp.rs            SNMP v2c GET (hand-rolled BER)
    arp.rs             ARP cache parsing (Windows, Linux, macOS)
    oui.rs             MAC vendor lookup
    classify.rs        device-type / OS fingerprinting
```

`cargo test` runs the unit tests (target parsing, NetBIOS/SNMP encoding and parsing, ARP
formats, classification, escaping).
