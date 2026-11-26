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
- **Sites**: group assets by location (e.g. each clinic) using the subnets each site owns; scan,
  schedule, filter, export and query per site, and limit AI/API tokens to specific sites
- **Asset details** the network can't tell you — name, asset tag, serial, manufacturer, model, owner,
  department, cost center, location, purchase date, PO, supplier, warranty end — plus your own
  **custom fields**; edit on the asset page, via CLI/API, or in bulk with **CSV import**
- **Manual assets** for devices the scanner can't reach (off-site laptops, spare stock)
- **Scan visibility**: where each record came from and how the scanner last detected it
- **Windows inventory** (when running on Windows): logs in over WMI to collect manufacturer, model,
  serial, BIOS, CPU, RAM, disks, network adapters, OS edition/build, install date, last boot and the
  logged-on user, **installed software** and **Windows services**; stored credentials are
  DPAPI-encrypted; failures are listed as inventory problems
- **Software** page: every product across the fleet with device and version counts
- **Security posture** for Windows devices — antivirus/Defender, BitLocker, firewall, last
  installed update, pending restart — summarised on the dashboard
- **Scheduled scans** (hourly / daily / weekly …) that run while the server is up
- **REST API** for scripting and integrations
- Optional **HTTP basic auth**; listens on localhost only by default

## Build

Requires Rust 1.80+ (`https://rustup.rs`). On Windows, install the MSVC build tools when rustup asks.

```sh
cargo build --release
# binary: target/release/rustsweeper(.exe)
```

## Sites

A site is a location — typically one clinic or building — defined by the subnets it owns. Assets
are placed automatically: the site whose subnet most specifically contains the asset's IP wins (so
`10.10.5.0/24` beats `10.10.0.0/16`). Assets outside every site are **Unassigned**. You can pin an
individual device to a site from its asset page or with `rustsweeper site assign`; pinned devices
stay put when subnets change. Each site has a **Scan now** button, and schedules can target a site
so they always scan its current subnets. Existing databases are upgraded automatically.

## Asset details, custom fields and CSV import

Scanning finds what's on the wire; IT knows who owns it, where it lives and when its warranty
ends. Each asset page has an **Asset details** form for that, and every edit is recorded in the
asset's history. Define extra fields (e.g. *Room*, *Clinical use*) under **Custom fields**.

For bulk updates, **Export CSV** from the Assets page, fill in columns in Excel, and **Import CSV**
it back — the export is import-ready. Rows match existing assets by the first identifier present:
`id`, `asset_tag`, `serial_number`, `mac`, `ip`, `name`. Empty cells leave a field alone, `-` clears
it, read-only columns are ignored, and a **preview** (dry run) shows every change before saving.
Tick *create missing* to add devices from a purchasing or MDM list.

```sh
rustsweeper field add "Room"
rustsweeper set 10.10.0.25 owner="Jane Doe" department=Billing warranty_end=2027-06-30 custom:Room=12B
rustsweeper add --name LAPTOP-0142 --mac AA-BB-CC-00-11-22
rustsweeper import inventory.csv --dry-run
rustsweeper import inventory.csv --create
```

## Windows inventory (credentialed)

When RustSweeper runs **on Windows**, every scan is followed by a credentialed inventory of the
Windows devices it found, the way Lansweeper does it: a WMI/CIM session over DCOM (or WinRM with
`--inventory-protocol wsman`) reads hardware, OS and the logged-on user. Results appear in a
**Windows inventory** card on each asset, feed the asset's manufacturer/model/serial when those are
blank (never overwriting what you entered), set an exact OS and Server/Workstation type, and are
queryable by AI assistants (Windows 10 end-of-support, low disk, low RAM, not rebooted, who's logged
on where…). Hardware and OS changes are recorded in the asset's history.

**Software and services.** Installed programs are read from each device's registry *Uninstall*
keys (64- and 32-bit) through WMI's `StdRegProv` — not `Win32_Product`, which makes Windows Installer
re-check every MSI package. Names are normalised (versions and `(x64 en-US)`-style tags removed) so
the **Software** page can show how many devices run each product and how many versions are in use.
Windows services are recorded with state, start mode and the account they run as, flagging
unquoted executable paths and services running under user accounts. Installs, removals, upgrades,
new/removed services and start-mode changes go into the asset's history. AI assistants get the
`software` and `services` datasets plus catalog queries such as *remote-access tools installed*,
*end-of-life software*, *automatic services that aren't running* and *unquoted service paths*.

**Security posture and patches.** Each inventory also records antivirus status (Security Center,
or Microsoft Defender on servers), Defender signature age, BitLocker protection of C:, Windows
Firewall profiles, installed updates (KB numbers, with the most recent date), whether a restart is
pending, and the exact release/build (e.g. 24H2 / 26100.2314). The dashboard counts devices failing
each check; changes in antivirus, BitLocker or firewall state are logged. AI assistants get a
`hotfixes` dataset and queries such as *BitLocker off*, *no working antivirus*, *no update in 45+
days*, *restart pending* and *Windows builds in use*. Checks that need features a device doesn't
have (e.g. BitLocker on Windows Home, Security Center on Server) show as unknown rather than failing.

**Credentials.** Use an account that is a local administrator on your PCs — usually a dedicated
domain account (e.g. `DELTA\svc-rustsweeper`) added to local Administrators by Group Policy. Add it
on the **Credentials** page or:

```sh
rustsweeper credential add "Domain scanning" --user DELTA\svc-rustsweeper     # prompts for the password
rustsweeper credential add "Dental local admin" --user .\Administrator --site Dental
rustsweeper inventory 10.10.0.25        # one device now; or --site Dental / --all
```

Passwords are encrypted with Windows DPAPI (machine scope) on the RustSweeper server and are
only passed to the PowerShell collector through its environment — never on a command line or in
logs. RustSweeper tries the credential that worked last time, then site-specific ones, then global
ones, then the account the service runs as (`--no-integrated-auth` to skip that). Devices that fail
show up under **Inventory problems** with the reason.

**Target requirements.** WMI must be reachable: allow the *Windows Management Instrumentation
(WMI-In / DCOM-In)* firewall rule group (TCP 135 + dynamic RPC) for the RustSweeper server's
address, e.g. via GPO. Use `--no-inventory` to turn it off.

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

# Sites (one per clinic/location)
rustsweeper site add "Main Clinic" 10.10.0.0/22 --description "1200 Delta Ave"
rustsweeper site add "Dental" 10.20.0.0/24
rustsweeper site list
rustsweeper scan --site "Dental"
rustsweeper assets --site "Main Clinic"
rustsweeper site assign 10.10.3.40 Dental      # pin one device; --auto to undo

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
| `list_sites` | Start here: sites with subnets and asset counts, plus unassigned assets grouped by subnet |
| `search_datasets` | Discover datasets (`assets`, `ports`, `changes`, `custom_fields`, `scans`), fields and operators |
| `search_query_catalog` | 26 pre-built queries (remote access exposure, clear-text protocols, HL7/DICOM, new/offline/stale devices, warranties expiring/expired, workstations without an owner, counts by type/OS/vendor/department, port changes…); `run_id` executes one |
| `execute_query` | Structured query: dataset, optional `site`, fields, filters (`eq`, `contains`, `in`, `gte` …, relative times like `now-7d`), sort, `group_by`, limit 1–20 (default 10), offset |
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
- **Site-scoped tokens**: `rustsweeper token create dental-ai --sites Dental` can only see assets,
  ports, changes and scans for that site — enforced server-side on every tool, whatever the assistant
  asks for. Scoped tokens can't start scans.
- `--mcp-allow-scans` exposes `start_scan`; `--no-mcp` turns the endpoint off; `--mcp-no-auth`
  skips tokens but is only allowed when bound to 127.0.0.1.

The MCP server reads the same database as `serve`, so you can run both at once. Before connecting a
third-party AI assistant, check that it's allowed under your organization's AI-use policy — asset data
(names, IPs, notes) is sent to the assistant when it answers.

## REST API

| Method | Path | Notes |
|---|---|---|
| GET | `/api/stats` | Totals and breakdowns |
| GET | `/api/assets?q=&type=&status=&site=&sort=&desc=1` | Asset list (`site=0` = unassigned) |
| GET | `/api/assets/{id}` | Asset + ports + change history |
| GET | `/api/scans` | Scan history |
| POST | `/api/scans` | Body `{"targets":"10.0.0.0/24"}` → `{"id": n}` |
| GET | `/api/scans/{id}` | Scan status + live progress |
| GET | `/api/sites` | Sites with subnets and asset counts |
| GET | `/api/datasets` | Queryable datasets, fields and operators |
| POST | `/api/assets` | Add a manual asset: `{"name":"LAPTOP-0142","mac":"…"}` |
| PATCH | `/api/assets/{id}` | Edit details: `{"owner":"Jane","warranty_end":"2027-06-30","custom":{"Room":"12B"},"site":"Dental"}` |
| POST | `/api/import?dry_run=true&create_missing=true` | CSV body; returns a per-row report |
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
- Credentialed inventory covers Windows hardware, OS, user, software, services, security posture
  and installed updates; Linux (SSH) comes next.
- Devices identified only by their ping TTL are labelled conservatively (Unidentified/Mobile/
  Linux-based device) — a TTL of 64 alone doesn't mean "server". Credentialed inventory (installed software,
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
  auth.rs              API tokens for /mcp (optionally site-scoped)
  sites.rs             site subnets and longest-prefix assignment
  import.rs            CSV import (matching, preview, custom fields)
  inventory/
    mod.rs             credentialed Windows inventory (credential order, storage)
    collect.ps1        PowerShell/CIM collector run on the RustSweeper host
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
