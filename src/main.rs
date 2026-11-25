//! RustSweeper — an agentless, Lansweeper-style network asset inventory written in Rust.

mod auth;
mod db;
mod import;
mod mcp;
mod query;
mod scanner;
mod sites;
mod web;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand};

use db::{AssetFilter, Db};
use scanner::{Progress, ScanOptions};

#[derive(Parser)]
#[command(name = "rustsweeper", version, about = "Agentless network asset discovery & inventory")]
struct Cli {
    /// SQLite database file.
    #[arg(long, global = true, default_value = "rustsweeper.db", env = "RUSTSWEEPER_DB")]
    db: String,

    /// Optional IEEE oui.csv / oui.txt or Wireshark manuf file for full MAC vendor lookup.
    #[arg(long, global = true, env = "RUSTSWEEPER_OUI")]
    oui_file: Option<String>,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Args, Clone)]
struct ScanArgs {
    /// Comma-separated TCP ports to probe (default: built-in list of 27 common ports).
    #[arg(long, value_delimiter = ',')]
    ports: Option<Vec<u16>>,
    /// Hosts scanned in parallel.
    #[arg(long, default_value_t = 64)]
    concurrency: usize,
    /// Per-connection timeout in milliseconds.
    #[arg(long, default_value_t = 800)]
    timeout_ms: u64,
    /// SNMP v2c community strings to try (comma-separated).
    #[arg(long, value_delimiter = ',', default_value = "public")]
    snmp_community: Vec<String>,
    /// Skip ICMP ping (use TCP/UDP probes only).
    #[arg(long)]
    no_ping: bool,
}

impl ScanArgs {
    fn options(&self) -> ScanOptions {
        let mut o = ScanOptions {
            concurrency: self.concurrency,
            timeout: Duration::from_millis(self.timeout_ms),
            snmp_communities: self.snmp_community.clone(),
            ping: !self.no_ping,
            ..Default::default()
        };
        if let Some(p) = &self.ports {
            o.ports = p.clone();
        }
        o
    }
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the web dashboard, REST API and scan scheduler.
    Serve {
        /// Address to listen on. Use 0.0.0.0:8080 to allow other machines.
        #[arg(long, default_value = "127.0.0.1:8080", env = "RUSTSWEEPER_BIND")]
        bind: SocketAddr,
        /// Require HTTP basic auth for the dashboard and REST API, as user:password.
        #[arg(long, env = "RUSTSWEEPER_AUTH")]
        auth: Option<String>,
        /// Disable the MCP endpoint at /mcp.
        #[arg(long)]
        no_mcp: bool,
        /// Expose the start_scan tool on /mcp.
        #[arg(long)]
        mcp_allow_scans: bool,
        /// Allow /mcp without a bearer token (only permitted when bound to localhost).
        #[arg(long)]
        mcp_no_auth: bool,
        #[command(flatten)]
        scan: ScanArgs,
    },
    /// Run an MCP (Model Context Protocol) server on stdio for AI assistants
    /// (Claude Desktop, Claude Code, Cursor…). Read-only unless --allow-scans.
    Mcp {
        /// Expose the start_scan tool so the assistant can launch discovery scans.
        #[arg(long)]
        allow_scans: bool,
        #[command(flatten)]
        scan: ScanArgs,
    },
    /// Scan targets from the command line and store results.
    Scan {
        /// Targets: CIDR, ranges, IPs or hostnames (e.g. 10.0.0.0/24 10.0.1.5-40).
        #[arg(required_unless_present = "site")]
        targets: Vec<String>,
        /// Scan all subnets of this site (id or name) instead of explicit targets.
        #[arg(long)]
        site: Option<String>,
        #[command(flatten)]
        scan: ScanArgs,
    },
    /// List inventoried assets.
    Assets {
        /// Free-text search (IP, name, MAC, vendor, OS, port...).
        #[arg(short, long)]
        search: Option<String>,
        /// Only assets in this site (id or name; "unassigned" for none).
        #[arg(long)]
        site: Option<String>,
        /// Output CSV instead of a table.
        #[arg(long)]
        csv: bool,
        /// Output JSON instead of a table.
        #[arg(long)]
        json: bool,
    },
    /// Set asset details, e.g. `set 10.0.0.25 owner="Jane Doe" department=Billing warranty_end=2027-06-30`.
    /// Use `custom:Field=value` for custom fields, an empty value to clear.
    Set {
        /// Asset id, IP, MAC or name.
        asset: String,
        /// field=value pairs.
        #[arg(required = true)]
        values: Vec<String>,
    },
    /// Add a device the scanner can't see (laptop off-site, spare stock…).
    Add {
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        ip: Option<String>,
        #[arg(long)]
        mac: Option<String>,
    },
    /// Import asset details from CSV (match by id, asset_tag, serial_number, mac, ip or name).
    Import {
        file: std::path::PathBuf,
        /// Create assets for rows that match nothing.
        #[arg(long)]
        create: bool,
        /// Show what would change without saving.
        #[arg(long)]
        dry_run: bool,
    },
    /// Manage custom asset fields.
    Field {
        #[command(subcommand)]
        action: FieldCmd,
    },
    /// Show full details for one asset (by id or IP).
    Show { asset: String },
    /// List recent scans.
    Scans,
    /// Manage API tokens for the /mcp HTTP endpoint.
    Token {
        #[command(subcommand)]
        action: TokenCmd,
    },
    /// Show the most recent MCP (AI assistant) calls.
    Audit {
        #[arg(long, default_value_t = 50)]
        limit: i64,
    },
    /// Manage sites (locations such as clinics, defined by their subnets).
    Site {
        #[command(subcommand)]
        action: SiteCmd,
    },
    /// Manage scheduled scans.
    Schedule {
        #[command(subcommand)]
        action: ScheduleCmd,
    },
}

#[derive(Subcommand)]
enum TokenCmd {
    /// Create a token (shown once — store it in your MCP client config).
    Create {
        name: String,
        /// Limit the token to these sites (comma-separated names or ids). Default: all sites.
        #[arg(long, value_delimiter = ',')]
        sites: Option<Vec<String>>,
    },
    List,
    /// Revoke by id or name. Active sessions using it stop working immediately.
    Revoke { id_or_name: String },
}

#[derive(Subcommand)]
enum FieldCmd {
    Add { name: String },
    List,
    /// Delete a custom field and its values on every asset.
    Remove { name: String },
}

#[derive(Subcommand)]
enum SiteCmd {
    /// Add a site, e.g. `site add "Main Clinic" 10.10.0.0/24,10.10.1.0/24`.
    Add {
        name: String,
        subnets: String,
        #[arg(long, default_value = "")]
        description: String,
    },
    List,
    /// Change a site's name, subnets or description.
    Update {
        site: String,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        subnets: Option<String>,
        #[arg(long)]
        description: Option<String>,
    },
    /// Delete a site (its assets become unassigned).
    Remove { site: String },
    /// Pin an asset (id or IP) to a site, or `--auto` to return it to subnet-based assignment.
    Assign {
        asset: String,
        site: Option<String>,
        #[arg(long)]
        auto: bool,
    },
}

#[derive(Subcommand)]
enum ScheduleCmd {
    /// Add a recurring scan.
    Add {
        name: String,
        targets: String,
        /// Interval in minutes.
        #[arg(long, default_value_t = 1440)]
        every: i64,
    },
    List,
    Remove { id: i64 },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "rustsweeper=info".into()),
        )
        .with_writer(std::io::stderr) // stdout is reserved for data (and the MCP stdio transport)
        .init();
    let cli = Cli::parse();
    if let Some(f) = &cli.oui_file {
        let n = scanner::oui::load_file(f).with_context(|| format!("loading OUI file {f}"))?;
        tracing::info!("loaded {n} OUI vendor prefixes from {f}");
    }
    let db = Db::open(&cli.db).with_context(|| format!("opening database {}", cli.db))?;

    match cli.cmd {
        Cmd::Serve { bind, auth, no_mcp, mcp_allow_scans, mcp_no_auth, scan } => {
            let auth = match auth {
                Some(s) => match s.split_once(':') {
                    Some((u, p)) if !u.is_empty() && !p.is_empty() => Some((u.to_string(), p.to_string())),
                    _ => bail!("--auth must be user:password"),
                },
                None => None,
            };
            if auth.is_none() && !bind.ip().is_loopback() {
                tracing::warn!("listening on {bind} without --auth: anyone on the network can view the inventory");
            }
            if mcp_no_auth && !bind.ip().is_loopback() {
                bail!("--mcp-no-auth is only allowed when --bind is a loopback address (127.0.0.1)");
            }
            let state = web::AppState::new(db.clone(), scan.options(), auth);
            tokio::spawn(web::scheduler(state.clone()));
            let mut app = web::router(state.clone());
            if !no_mcp {
                let server = mcp::McpServer::new(state, mcp_allow_scans);
                app = app.merge(mcp::http::router(mcp::http::HttpMcp::new(server, !mcp_no_auth)));
                if !mcp_no_auth && db.active_token_count()? == 0 {
                    tracing::warn!("MCP endpoint /mcp has no API tokens yet; create one with `rustsweeper token create <name>`");
                }
            }
            let listener = tokio::net::TcpListener::bind(bind).await.with_context(|| format!("binding {bind}"))?;
            println!("RustSweeper dashboard: http://{bind}/");
            if !no_mcp {
                println!("MCP endpoint:          http://{bind}/mcp{}", if mcp_no_auth { " (no auth)" } else { " (bearer token)" });
            }
            axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await?;
        }
        Cmd::Mcp { allow_scans, scan } => {
            let state = web::AppState::new(db, scan.options(), None);
            mcp::stdio::serve(mcp::McpServer::new(state, allow_scans)).await?;
        }
        Cmd::Scan { targets, site, scan } => {
            let (spec, site_id) = match &site {
                Some(s) => {
                    let site = db.find_site(s)?.with_context(|| format!("no site '{s}'"))?;
                    (sites::scan_targets(&sites::parse_subnets(&site.subnets)?), Some(site.id))
                }
                None => (targets.join(","), None),
            };
            let (id, ips) = scanner::prepare_site_scan(&db, &spec, "cli", site_id)?;
            println!("Scan #{id}: probing {} host(s)…", ips.len());
            let progress = Arc::new(Progress::default());
            let p2 = progress.clone();
            let ticker = tokio::spawn(async move {
                use std::sync::atomic::Ordering::Relaxed;
                loop {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    eprintln!("  {}/{} probed, {} up", p2.done.load(Relaxed), p2.total.load(Relaxed), p2.up.load(Relaxed));
                }
            });
            let res = scanner::execute_scan(db.clone(), id, ips, scan.options(), progress).await;
            ticker.abort();
            if let Err(e) = res {
                db.finish_scan(id, "failed", 0, 0, 0, Some(&format!("{e:#}")))?;
                return Err(e);
            }
            let s = db.get_scan(id)?.context("scan vanished")?;
            println!("Done: {} up, {} new asset(s).\n", s.hosts_up, s.new_assets);
            print_assets(&db.list_assets(&AssetFilter { scan_id: Some(id), ..Default::default() })?);
        }
        Cmd::Assets { search, site, csv, json } => {
            let site_id = match site.as_deref() {
                None => None,
                Some(s) if s.eq_ignore_ascii_case("unassigned") => Some(0),
                Some(s) => Some(db.find_site(s)?.with_context(|| format!("no site '{s}'"))?.id),
            };
            let assets = db.list_assets(&AssetFilter { q: search, site_id, ..Default::default() })?;
            if csv {
                print!("{}", web::assets_csv(&db, &assets)?);
            } else if json {
                println!("{}", serde_json::to_string_pretty(&assets)?);
            } else {
                print_assets(&assets);
            }
        }
        Cmd::Set { asset, values } => {
            let a = find_asset(&db, &asset)?;
            let mut edits = Vec::new();
            let mut custom = Vec::new();
            for kv in &values {
                let (k, v) = kv.split_once('=').with_context(|| format!("'{kv}' should be field=value"))?;
                let k = k.trim();
                if let Some(name) = k.strip_prefix("custom:") {
                    custom.push((name.to_string(), Some(v.trim().to_string()).filter(|s| !s.is_empty())));
                } else if db::EDITABLE_FIELDS.iter().any(|(c, _)| *c == k) {
                    edits.push((k.to_string(), db::normalize_field(k, v).with_context(|| k.to_string())?));
                } else {
                    bail!("'{k}' is not editable. Fields: {}", db::EDITABLE_FIELDS.iter().map(|(c, _)| *c).collect::<Vec<_>>().join(", "));
                }
            }
            let mut n = db.update_asset_fields(a.id, &edits)?;
            for (name, v) in custom {
                n += db.set_custom_value(a.id, &name, v.as_deref())? as usize;
            }
            println!("Asset #{} '{}': {n} field(s) changed", a.id, a.display_name());
        }
        Cmd::Add { name, ip, mac } => {
            let id = db.create_manual_asset(ip.as_deref(), mac.as_deref(), name.as_deref(), "manual")?;
            println!("Added asset #{id}. Fill in details with: rustsweeper set {id} owner=... serial_number=...");
        }
        Cmd::Import { file, create, dry_run } => {
            let data = std::fs::read(&file).with_context(|| format!("reading {}", file.display()))?;
            let data = String::from_utf8_lossy(&data);
            let opts = import::ImportOptions { create_missing: create, dry_run, source: "import".into() };
            let r = import::import_csv(&db, &data, &opts)?;
            println!(
                "{}{} rows: {} matched, {} created, {} assets updated ({} field changes), {} skipped",
                if dry_run { "DRY RUN — nothing saved. " } else { "" },
                r.rows, r.matched, r.created, r.updated_assets, r.fields_changed, r.skipped
            );
            if !r.ignored_columns.is_empty() {
                println!("Ignored columns: {}", r.ignored_columns.join(", "));
            }
            for x in r.results.iter().filter(|x| x.action != "unchanged" || !x.errors.is_empty()) {
                println!(
                    "  row {:>4}  {:<9} {:<24} {}{}",
                    x.row, x.action, trunc(x.asset.as_deref().unwrap_or("-"), 24), x.changes.join("; "),
                    if x.errors.is_empty() { String::new() } else { format!("  !! {}", x.errors.join("; ")) }
                );
            }
        }
        Cmd::Field { action } => match action {
            FieldCmd::Add { name } => {
                let id = db.add_custom_field(&name)?;
                println!("Custom field #{id} '{}' added", name.trim());
            }
            FieldCmd::List => {
                for f in db.custom_fields()? {
                    println!("#{:<4} {:<40} {} asset(s)", f.id, f.name, f.in_use);
                }
            }
            FieldCmd::Remove { name } => {
                let f = db.custom_fields()?.into_iter().find(|f| f.name.eq_ignore_ascii_case(&name) || f.id.to_string() == name)
                    .with_context(|| format!("no custom field '{name}'"))?;
                db.delete_custom_field(f.id)?;
                println!("Removed custom field '{}' ({} value(s) deleted)", f.name, f.in_use);
            }
        },
        Cmd::Show { asset } => {
            let a = match asset.parse::<i64>() {
                Ok(id) => db.get_asset(id)?,
                Err(_) => db
                    .list_assets(&AssetFilter::default())?
                    .into_iter()
                    .find(|a| a.ip == asset || a.display_name().eq_ignore_ascii_case(&asset)),
            };
            let Some(a) = a else { bail!("no asset '{asset}'") };
            let ports = db.asset_ports(a.id)?;
            let changes = db.changes(Some(a.id), 20)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({"asset": a, "ports": ports, "recent_changes": changes}))?
            );
        }
        Cmd::Scans => {
            println!("{:<6} {:<10} {:<6} {:<6} {:<20} TARGETS", "ID", "STATUS", "UP", "NEW", "STARTED");
            for s in db.list_scans(50)? {
                println!("{:<6} {:<10} {:<6} {:<6} {:<20} {}", s.id, s.status, s.hosts_up, s.new_assets, s.started_at, s.targets);
            }
        }
        Cmd::Token { action } => match action {
            TokenCmd::Create { name, sites: site_names } => {
                let ids = match &site_names {
                    None => None,
                    Some(list) => Some(
                        list.iter()
                            .map(|s| db.find_site(s)?.map(|x| x.id).with_context(|| format!("no site '{s}'")))
                            .collect::<Result<Vec<i64>>>()?,
                    ),
                };
                let (id, token) = auth::create(&db, &name, ids.as_deref())?;
                if let Some(list) = &site_names {
                    println!("Scoped to sites: {}", list.join(", "));
                }
                println!("Token #{id} '{name}' created. Copy it now — it will not be shown again:\n\n  {token}\n");
                println!("Use it as an HTTP header in your MCP client:  Authorization: Bearer {token}");
            }
            TokenCmd::List => {
                let all_sites = db.list_sites()?;
                println!("{:<5} {:<24} {:<12} {:<20} {:<20} {:<8} SITES", "ID", "NAME", "PREFIX", "CREATED", "LAST USED", "STATE");
                for t in db.list_tokens()? {
                    let scope = match &t.sites {
                        None => "all".to_string(),
                        Some(ids) => ids
                            .iter()
                            .map(|i| all_sites.iter().find(|s| s.id == *i).map(|s| s.name.clone()).unwrap_or_else(|| format!("#{i} (deleted)")))
                            .collect::<Vec<_>>()
                            .join(", "),
                    };
                    println!(
                        "{:<5} {:<24} {:<12} {:<20} {:<20} {:<8} {}",
                        t.id, t.name, format!("{}…", t.prefix), t.created_at,
                        t.last_used.as_deref().unwrap_or("never"), if t.revoked { "revoked" } else { "active" }, scope
                    );
                }
            }
            TokenCmd::Revoke { id_or_name } => {
                if db.revoke_token(&id_or_name)? {
                    println!("Revoked {id_or_name}");
                } else {
                    bail!("no active token '{id_or_name}'");
                }
            }
        },
        Cmd::Audit { limit } => {
            println!("{:<20} {:<6} {:<16} {:<15} {:<22} {:<4} {:>6} ARGUMENTS", "WHEN", "VIA", "CLIENT", "FROM", "TOOL", "OK", "ROWS");
            for a in db.list_audit(limit)? {
                println!(
                    "{:<20} {:<6} {:<16} {:<15} {:<22} {:<4} {:>6} {}",
                    a.at, a.transport, trunc(a.client.as_deref().unwrap_or("-"), 16), a.remote_addr.as_deref().unwrap_or("-"),
                    a.tool.as_deref().unwrap_or(&a.method), if a.ok { "yes" } else { "NO" },
                    a.rows.map(|r| r.to_string()).unwrap_or_default(), trunc(a.arguments.as_deref().unwrap_or(""), 80)
                );
            }
        }
        Cmd::Site { action } => match action {
            SiteCmd::Add { name, subnets, description } => {
                let nets = sites::parse_subnets(&subnets)?;
                let id = db.add_site(&name, &sites::format_subnets(&nets), &description)?;
                let s = db.get_site(id)?.context("site vanished")?;
                println!("Site #{id} '{}' added: {} ({} existing assets placed)", s.name, s.subnets, s.asset_count);
            }
            SiteCmd::List => {
                println!("{:<5} {:<24} {:>7} {:>7}  SUBNETS", "ID", "NAME", "ASSETS", "ONLINE");
                for s in db.list_sites()? {
                    println!("{:<5} {:<24} {:>7} {:>7}  {}", s.id, trunc(&s.name, 24), s.asset_count, s.online, s.subnets);
                }
                println!("{:<5} {:<24} {:>7}", "-", "(unassigned)", db.unassigned_count()?);
            }
            SiteCmd::Update { site, name, subnets, description } => {
                let s = db.find_site(&site)?.with_context(|| format!("no site '{site}'"))?;
                let subnets = match subnets {
                    Some(x) => sites::format_subnets(&sites::parse_subnets(&x)?),
                    None => s.subnets.clone(),
                };
                db.update_site(s.id, name.as_deref().unwrap_or(&s.name), &subnets, description.as_deref().unwrap_or(&s.description))?;
                println!("Updated site #{}", s.id);
            }
            SiteCmd::Remove { site } => {
                let s = db.find_site(&site)?.with_context(|| format!("no site '{site}'"))?;
                db.delete_site(s.id)?;
                println!("Removed site '{}'; its assets are now unassigned unless another site's subnets cover them.", s.name);
            }
            SiteCmd::Assign { asset, site, auto } => {
                let a = match asset.parse::<i64>() {
                    Ok(id) => db.get_asset(id)?,
                    Err(_) => db.list_assets(&AssetFilter::default())?.into_iter().find(|a| a.ip == asset),
                }
                .with_context(|| format!("no asset '{asset}'"))?;
                match (site, auto) {
                    (_, true) => {
                        db.set_asset_site(a.id, None)?;
                        println!("Asset #{} returned to automatic site assignment", a.id);
                    }
                    (Some(s), false) => {
                        let s = db.find_site(&s)?.with_context(|| format!("no site '{s}'"))?;
                        db.set_asset_site(a.id, Some(s.id))?;
                        println!("Asset #{} pinned to '{}'", a.id, s.name);
                    }
                    (None, false) => bail!("give a site name, or --auto"),
                }
            }
        },
        Cmd::Schedule { action } => match action {
            ScheduleCmd::Add { name, targets, every } => {
                scanner::targets::parse_targets(&targets)?;
                let id = db.add_schedule(&name, &targets, every.max(5))?;
                println!("Schedule #{id} added (runs while `rustsweeper serve` is running).");
            }
            ScheduleCmd::List => {
                for s in db.list_schedules()? {
                    println!(
                        "#{:<4} {:<24} every {:>5} min  {:<8} last run: {}  [{}]",
                        s.id, s.name, s.interval_minutes, if s.enabled { "enabled" } else { "paused" },
                        s.last_run.as_deref().unwrap_or("never"), s.targets
                    );
                }
            }
            ScheduleCmd::Remove { id } => {
                db.delete_schedule(id)?;
                println!("Removed schedule #{id}");
            }
        },
    }
    Ok(())
}

fn trunc(s: &str, n: usize) -> String {
    if s.chars().count() <= n { s.to_string() } else { format!("{}…", s.chars().take(n - 1).collect::<String>()) }
}

fn print_assets(assets: &[db::Asset]) {
    println!(
        "{:<5} {:<15} {:<22} {:<16} {:<17} {:<16} {:<26} {:<18} {:>5} {:<7}",
        "ID", "IP", "NAME", "SITE", "MAC", "VENDOR", "TYPE", "OS", "PORTS", "STATUS"
    );
    for a in assets {
        let o = |v: &Option<String>, n| trunc(v.as_deref().unwrap_or("-"), n);
        println!(
            "{:<5} {:<15} {:<22} {:<16} {:<17} {:<16} {:<26} {:<18} {:>5} {:<7}",
            a.id, a.ip, trunc(&a.display_name(), 22), o(&a.site, 16), o(&a.mac, 17), o(&a.vendor, 16),
            o(&a.device_type, 26), o(&a.os_guess, 18), a.open_ports, a.status
        );
    }
    println!("\n{} asset(s)", assets.len());
}

/// Find one asset by id, IP, MAC or exact name.
fn find_asset(db: &Db, key: &str) -> Result<db::Asset> {
    if let Ok(id) = key.parse::<i64>() {
        return db.get_asset(id)?.with_context(|| format!("no asset #{id}"));
    }
    let all = db.list_assets(&AssetFilter::default())?;
    let mac = scanner::arp::normalize_mac(key);
    let hits: Vec<_> = all
        .into_iter()
        .filter(|a| a.ip == key || a.display_name().eq_ignore_ascii_case(key) || (mac.is_some() && a.mac == mac))
        .collect();
    match hits.len() {
        1 => Ok(hits.into_iter().next().unwrap()),
        0 => bail!("no asset '{key}'"),
        n => bail!("'{key}' matches {n} assets; use the asset id"),
    }
}
