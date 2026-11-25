//! RustSweeper — an agentless, Lansweeper-style network asset inventory written in Rust.

mod auth;
mod db;
mod mcp;
mod query;
mod scanner;
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
        #[arg(required = true)]
        targets: Vec<String>,
        #[command(flatten)]
        scan: ScanArgs,
    },
    /// List inventoried assets.
    Assets {
        /// Free-text search (IP, name, MAC, vendor, OS, port...).
        #[arg(short, long)]
        search: Option<String>,
        /// Output CSV instead of a table.
        #[arg(long)]
        csv: bool,
        /// Output JSON instead of a table.
        #[arg(long)]
        json: bool,
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
    /// Manage scheduled scans.
    Schedule {
        #[command(subcommand)]
        action: ScheduleCmd,
    },
}

#[derive(Subcommand)]
enum TokenCmd {
    /// Create a token (shown once — store it in your MCP client config).
    Create { name: String },
    List,
    /// Revoke by id or name. Active sessions using it stop working immediately.
    Revoke { id_or_name: String },
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
        Cmd::Scan { targets, scan } => {
            let spec = targets.join(",");
            let (id, ips) = scanner::prepare_scan(&db, &spec, "cli")?;
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
        Cmd::Assets { search, csv, json } => {
            let assets = db.list_assets(&AssetFilter { q: search, ..Default::default() })?;
            if csv {
                print!("{}", web::assets_csv(&assets));
            } else if json {
                println!("{}", serde_json::to_string_pretty(&assets)?);
            } else {
                print_assets(&assets);
            }
        }
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
            TokenCmd::Create { name } => {
                let (id, token) = auth::create(&db, &name)?;
                println!("Token #{id} '{name}' created. Copy it now — it will not be shown again:\n\n  {token}\n");
                println!("Use it as an HTTP header in your MCP client:  Authorization: Bearer {token}");
            }
            TokenCmd::List => {
                println!("{:<5} {:<24} {:<12} {:<20} {:<20} STATE", "ID", "NAME", "PREFIX", "CREATED", "LAST USED");
                for t in db.list_tokens()? {
                    println!(
                        "{:<5} {:<24} {:<12} {:<20} {:<20} {}",
                        t.id, t.name, format!("{}…", t.prefix), t.created_at,
                        t.last_used.as_deref().unwrap_or("never"), if t.revoked { "revoked" } else { "active" }
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
        "{:<5} {:<15} {:<22} {:<17} {:<16} {:<26} {:<18} {:>5} {:<7}",
        "ID", "IP", "NAME", "MAC", "VENDOR", "TYPE", "OS", "PORTS", "STATUS"
    );
    for a in assets {
        let o = |v: &Option<String>, n| trunc(v.as_deref().unwrap_or("-"), n);
        println!(
            "{:<5} {:<15} {:<22} {:<17} {:<16} {:<26} {:<18} {:>5} {:<7}",
            a.id, a.ip, trunc(&a.display_name(), 22), o(&a.mac, 17), o(&a.vendor, 16),
            o(&a.device_type, 26), o(&a.os_guess, 18), a.open_ports, a.status
        );
    }
    println!("\n{} asset(s)", assets.len());
}
