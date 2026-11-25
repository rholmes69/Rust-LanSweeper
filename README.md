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

# MCP access tokens and audit log
rustsweeper token create "claude-desktop"
rustsweeper audit

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

## AI assistants (MCP server)

RustSweeper includes a read-only [Model Context Protocol](https://modelcontextprotocol.io) server, so
assistants like Claude Desktop, Claude Code and Cursor can answer questions such as *"which devices
expose RDP?"*, *"what's new on the network this week?"* or *"summarise our printers"* straight from
the inventory. It follows the same design as Lansweeper's MCP server: discover sites and fields, pick a
pre-built query or build a structured one, get capped, pageable results. No SQL is ever accepted.

```sh
rustsweeper --db C:\RustSweeper\rustsweeper.db mcp            # read-only
rustsweeper --db C:\RustSweeper\rustsweeper.db mcp --allow-scans   # also expose start_scan
```

**Tools**

| Tool | Purpose |
|---|---|
| `list_sites` | Start here: sites, subnets, asset counts, last scan |
| `search_datasets` | Discover datasets (`assets`, `ports`, `changes`, `scans`), fields and operators |
| `search_query_catalog` | 20 pre-built queries (remote access exposure, clear-text protocols, HL7/DICOM, new/offline/stale devices, counts by type/OS/vendor, port changes…); `run_id` executes one |
| `execute_query` | Structured query: dataset, fields, filters (`eq`, `contains`, `in`, `gte` …, relative times like `now-7d`), sort, `group_by`, limit 1–20 (default 10), offset |
| `get_asset` | One device by id, IP or name: details, ports, recent changes |
| `asset_history` | Change log for one device |
| `scan_status` | Status/progress of a scan |
| `docs` | Searches this documentation |
| `start_scan` | Only with `--allow-scans` |

**Prompts:** `security-exposure-review`, `new-device-review`, `weekly-inventory-summary`,
`offline-device-check`, `asset-lookup`.

**Claude Desktop** (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "rustsweeper": {
      "command": "C:\\RustSweeper\\rustsweeper.exe",
      "args": ["--db", "C:\\RustSweeper\\rustsweeper.db", "mcp"]
    }
  }
}
```

**Claude Code:**

```sh
claude mcp add rustsweeper -- C:\RustSweeper\rustsweeper.exe --db C:\RustSweeper\rustsweeper.db mcp
```

**Cursor** (`.cursor/mcp.json`): same `command`/`args` block as Claude Desktop.

**Remote access over HTTP.** `rustsweeper serve` also exposes the MCP server at `/mcp`
(Streamable HTTP), for assistants that can't launch a local process or for a shared server:

```sh
rustsweeper token create "claude-desktop"     # prints rsw_… once — store it in the client config
rustsweeper token list
rustsweeper token revoke claude-desktop       # live sessions stop immediately
rustsweeper serve --bind 0.0.0.0:8080 --auth admin:CHANGE_ME
```

Clients send `Authorization: Bearer rsw_…` to `http://<server>:8080/mcp`. For example, Claude Code:

```sh
claude mcp add --transport http rustsweeper http://inventory01:8080/mcp --header "Authorization: Bearer rsw_…"
```

- Tokens are random 256-bit values; only a SHA-256 hash is stored.
- Sessions are tied to the token that opened them and expire after 60 minutes idle.
- Browser requests from foreign origins are rejected (DNS-rebinding protection).
- Every MCP call (stdio and HTTP) is written to an audit log: who, from where, which tool, the
  arguments, rows returned and duration. See the **AI access** page or `rustsweeper audit`.
- `--mcp-allow-scans` exposes `start_scan`; `--no-mcp` turns the endpoint off; `--mcp-no-auth`
  skips tokens but is only allowed when bound to 127.0.0.1.

The MCP server reads the same database as `serve`, so you can run both at once. Before connecting a
third-party AI assistant, check that it's allowed under your organization's AI-use policy — asset data
(names, IPs, notes) is sent to the assistant when it answers.

## REST API

| Method | Path | Notes |
|---|---|---|
| GET | `/api/stats` | Totals and breakdowns |
| GET | `/api/assets?q=&type=&status=&sort=&desc=1` | Asset list |
| GET | `/api/assets/{id}` | Asset + ports + change history |
| GET | `/api/scans` | Scan history |
| POST | `/api/scans` | Body `{"targets":"10.0.0.0/24"}` → `{"id": n}` |
| GET | `/api/scans/{id}` | Scan status + live progress |
| GET | `/api/datasets` | Queryable datasets, fields and operators |
| POST | `/api/query` | Structured query (same format as the MCP `execute_query` tool; up to 1000 rows) |

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
- This version is agentless and doesn't log in to devices. Credentialed inventory (installed software,
  hardware specs via WMI/WinRM, SSH) or an endpoint agent are natural next steps.

## Project layout

```
src/
  main.rs              CLI (clap)
  db.rs                SQLite schema, upserts, change tracking
  web.rs               axum dashboard, REST API, CSV export, scheduler
  query.rs             structured, injection-safe query engine (datasets/fields/filters)
  mcp/
    mod.rs             MCP JSON-RPC dispatch, tools, docs search
    catalog.rs         pre-built query templates
    prompts.rs         MCP prompts (IT workflows)
    stdio.rs           stdio transport
    http.rs            Streamable HTTP transport (/mcp), sessions, Origin checks
  auth.rs              API tokens for /mcp
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
