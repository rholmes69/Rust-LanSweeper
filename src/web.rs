//! Web dashboard (server-rendered HTML) and JSON REST API.

use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use anyhow::Result;
use axum::extract::{Form, Path, Query, Request, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;

use crate::db::{Asset, AssetFilter, Db};
use crate::scanner::{self, Progress, ScanOptions};

#[derive(Clone)]
pub struct AppState {
    pub db: Db,
    pub opts: ScanOptions,
    pub running: Arc<Mutex<HashMap<i64, Arc<Progress>>>>,
    /// Expected `Authorization` header value when basic auth is enabled.
    pub auth: Option<String>,
}

impl AppState {
    pub fn new(db: Db, opts: ScanOptions, auth: Option<(String, String)>) -> Self {
        use base64::Engine;
        let auth = auth.map(|(u, p)| {
            format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(format!("{u}:{p}")))
        });
        Self { db, opts, running: Arc::new(Mutex::new(HashMap::new())), auth }
    }

    pub fn progress_of(&self, id: i64) -> Option<Arc<Progress>> {
        self.running.lock().unwrap().get(&id).cloned()
    }
}

/// Validate targets, then run the scan in the background. Returns the new scan id.
pub fn launch_scan(state: &AppState, spec: &str, trigger: &str) -> Result<i64> {
    launch_scan_for_site(state, spec, trigger, None)
}

/// Launch a scan recorded against a site (used for "scan this site" and site schedules).
pub fn launch_scan_for_site(state: &AppState, spec: &str, trigger: &str, site_id: Option<i64>) -> Result<i64> {
    let (id, ips) = scanner::prepare_site_scan(&state.db, spec, trigger, site_id)?;
    let progress = Arc::new(Progress::default());
    state.running.lock().unwrap().insert(id, progress.clone());
    let st = state.clone();
    tokio::spawn(async move {
        tracing::info!(scan = id, hosts = ips.len(), "scan started");
        let res = scanner::execute_scan(st.db.clone(), id, ips, st.opts.clone(), progress.clone()).await;
        match res {
            Ok(()) => tracing::info!(scan = id, up = progress.up.load(Ordering::Relaxed), "scan completed"),
            Err(e) => {
                tracing::error!(scan = id, "scan failed: {e:#}");
                let _ = st.db.finish_scan(
                    id,
                    "failed",
                    progress.done.load(Ordering::Relaxed),
                    progress.up.load(Ordering::Relaxed),
                    0,
                    Some(&format!("{e:#}")),
                );
            }
        }
        st.running.lock().unwrap().remove(&id);
    });
    Ok(id)
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(dashboard))
        .route("/assets", get(assets_page))
        .route("/assets/{id}", get(asset_page))
        .route("/assets/{id}/details", post(save_details))
        .route("/assets/new", get(new_asset_page).post(create_asset))
        .route("/import", get(import_page).post(import_upload))
        .route("/custom-fields", get(custom_fields_page).post(add_custom_field))
        .route("/custom-fields/{id}/delete", post(delete_custom_field))
        .route("/api/import", post(api_import))
        .route("/assets/{id}/delete", post(delete_asset))
        .route("/assets/{id}/site", post(set_asset_site))
        .route("/sites", get(sites_page).post(add_site))
        .route("/sites/{id}", get(site_page).post(update_site))
        .route("/sites/{id}/delete", post(delete_site))
        .route("/sites/{id}/scan", post(scan_site))
        .route("/api/sites", get(api_sites))
        .route("/scans", get(scans_page).post(start_scan_form))
        .route("/scans/{id}", get(scan_page))
        .route("/schedules", get(schedules_page).post(add_schedule))
        .route("/schedules/{id}/toggle", post(toggle_schedule))
        .route("/schedules/{id}/delete", post(delete_schedule))
        .route("/changes", get(changes_page))
        .route("/ai-access", get(ai_access_page))
        .route("/export.csv", get(export_csv))
        .route("/api/stats", get(api_stats))
        .route("/api/assets", get(api_assets).post(api_create_asset))
        .route("/api/assets/{id}", get(api_asset).patch(api_update_asset))
        .route("/api/scans", get(api_scans).post(api_start_scan))
        .route("/api/scans/{id}", get(api_scan))
        .route("/api/query", post(api_query))
        .route("/api/datasets", get(api_datasets))
        .layer(middleware::from_fn_with_state(state.clone(), basic_auth))
        .with_state(state)
}

async fn basic_auth(State(st): State<AppState>, req: Request, next: Next) -> Response {
    if let Some(expected) = &st.auth {
        let ok = req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| constant_time_eq(v.as_bytes(), expected.as_bytes()));
        if !ok {
            let mut r = (StatusCode::UNAUTHORIZED, "Authentication required").into_response();
            r.headers_mut()
                .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Basic realm=\"RustSweeper\""));
            return r;
        }
    }
    next.run(req).await
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

// ---------------------------------------------------------------- errors

pub struct AppError(anyhow::Error);

impl<E: Into<anyhow::Error>> From<E> for AppError {
    fn from(e: E) -> Self {
        Self(e.into())
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        tracing::error!("{:#}", self.0);
        (StatusCode::INTERNAL_SERVER_ERROR, format!("Error: {:#}", self.0)).into_response()
    }
}

type WebResult<T> = std::result::Result<T, AppError>;

fn not_found() -> Response {
    (StatusCode::NOT_FOUND, page("Not found", "", "<div class=card><h2>Not found</h2></div>".into())).into_response()
}

// ---------------------------------------------------------------- HTML helpers

fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&#39;"),
            _ => o.push(c),
        }
    }
    o
}

fn opt(s: &Option<String>) -> String {
    s.as_deref().map(esc).unwrap_or_else(|| "<span class=muted>—</span>".into())
}

fn url_enc(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

fn status_pill(s: &str) -> String {
    let cls = match s {
        "online" | "completed" => "ok",
        "offline" | "failed" | "interrupted" => "bad",
        "unknown" => "",
        "running" => "run",
        _ => "",
    };
    format!("<span class='pill {cls}'>{}</span>", esc(s))
}

const CSS: &str = r#"
:root{--bg:#f5f6f8;--card:#fff;--ink:#1d2330;--muted:#6b7385;--line:#e3e6ec;--accent:#2563eb;--ok:#15803d;--bad:#b91c1c;--run:#b45309;--nav:#111827}
*{box-sizing:border-box}body{margin:0;font:14px/1.45 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--ink)}
a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}
header{background:var(--nav);color:#fff;display:flex;align-items:center;gap:28px;padding:0 24px;height:54px}
header .brand{font-weight:700;font-size:17px;letter-spacing:.2px}header .brand span{color:#60a5fa}
header nav a{color:#cbd5e1;margin-right:18px;font-weight:500}header nav a.active,header nav a:hover{color:#fff;text-decoration:none}
header form{margin-left:auto}header input{background:#1f2937;border:1px solid #374151;color:#fff;border-radius:6px;padding:6px 10px;width:240px}
main{max-width:1320px;margin:0 auto;padding:24px}
h1{font-size:22px;margin:0 0 18px}h2{font-size:15px;margin:0 0 12px;color:var(--ink)}
.grid{display:grid;gap:16px}.g4{grid-template-columns:repeat(4,1fr)}.g2{grid-template-columns:1fr 1fr}.g3{grid-template-columns:2fr 1fr}
@media(max-width:900px){.g4,.g2,.g3{grid-template-columns:1fr}}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:18px;margin-bottom:16px}
.stat .n{font-size:30px;font-weight:700}.stat .l{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.5px}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.4px;font-weight:600;white-space:nowrap}
tr:hover td{background:#fafbfc}td.mono,.mono{font-family:ui-monospace,Consolas,monospace;font-size:12.5px}
.muted{color:var(--muted)}.pill{display:inline-block;padding:1px 8px;border-radius:99px;font-size:12px;background:#eef2f7;color:var(--muted)}
.pill.ok{background:#dcfce7;color:var(--ok)}.pill.bad{background:#fee2e2;color:var(--bad)}.pill.run{background:#fef3c7;color:var(--run)}
.bar{display:flex;align-items:center;gap:10px;margin:6px 0}.bar .lbl{width:190px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.bar .trk{flex:1;background:#eef2f7;border-radius:4px;height:10px}.bar .fill{background:var(--accent);height:10px;border-radius:4px}.bar .v{width:36px;text-align:right;color:var(--muted)}
form.inline{display:inline}input[type=text],input[type=number],select,textarea{border:1px solid var(--line);border-radius:6px;padding:7px 10px;font:inherit;background:#fff}
textarea{width:100%;min-height:90px}button,.btn{background:var(--accent);color:#fff;border:0;border-radius:6px;padding:7px 14px;font:inherit;font-weight:600;cursor:pointer}
button.ghost{background:#fff;color:var(--ink);border:1px solid var(--line)}button.danger{background:#fff;color:var(--bad);border:1px solid #fecaca}
.row{display:flex;gap:8px;align-items:center;flex-wrap:wrap}.spacer{flex:1}
dl{display:grid;grid-template-columns:150px 1fr;gap:6px 12px;margin:0}dt{color:var(--muted)}dd{margin:0;word-break:break-word}
.progress{background:#eef2f7;border-radius:6px;height:14px;overflow:hidden}.progress div{background:var(--accent);height:14px}
.hint{color:var(--muted);font-size:12.5px;margin-top:6px}
"#;

fn page(title: &str, active: &str, body: String) -> Html<String> {
    page_ext(title, active, body, "")
}

fn page_ext(title: &str, active: &str, body: String, head_extra: &str) -> Html<String> {
    let nav = [("dashboard", "/", "Dashboard"), ("assets", "/assets", "Assets"), ("sites", "/sites", "Sites"), ("scans", "/scans", "Scans"),
        ("schedules", "/schedules", "Schedules"), ("changes", "/changes", "Changes"), ("ai", "/ai-access", "AI access")]
        .iter()
        .map(|(k, href, label)| {
            format!("<a href='{href}' class='{}'>{label}</a>", if *k == active { "active" } else { "" })
        })
        .collect::<String>();
    Html(format!(
        "<!DOCTYPE html><html lang=en><head><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>\
         <title>{} · RustSweeper</title>{head_extra}<style>{CSS}</style></head><body>\
         <header><div class=brand>Rust<span>Sweeper</span></div><nav>{nav}</nav>\
         <form action=/assets><input type=text name=q placeholder='Search IP, name, MAC, vendor, port…'></form></header>\
         <main>{body}</main></body></html>",
        esc(title)
    ))
}

fn suggested_subnet() -> String {
    // Learn our primary IPv4 without sending traffic (UDP connect only sets the route).
    std::net::UdpSocket::bind("0.0.0.0:0")
        .and_then(|s| s.connect("8.8.8.8:80").map(|_| s))
        .and_then(|s| s.local_addr())
        .ok()
        .and_then(|a| match a.ip() {
            std::net::IpAddr::V4(v4) if !v4.is_loopback() => {
                let o = v4.octets();
                Some(format!("{}.{}.{}.0/24", o[0], o[1], o[2]))
            }
            _ => None,
        })
        .unwrap_or_else(|| "192.168.1.0/24".into())
}

fn scan_form(prefill: &str) -> String {
    format!(
        "<form method=post action=/scans class=row><input type=text name=targets value='{}' style='flex:1;min-width:260px' \
         placeholder='e.g. 10.0.0.0/24, 10.0.1.10-50, printer01'><button>Scan now</button></form>\
         <div class=hint>CIDR, ranges (10.0.0.5-40), single IPs or hostnames — comma separated. Max 65,536 hosts per scan.</div>",
        esc(prefill)
    )
}

fn asset_name_link(a: &Asset) -> String {
    format!("<a href='/assets/{}'>{}</a>", a.id, esc(&a.display_name()))
}

// ---------------------------------------------------------------- dashboard

async fn dashboard(State(st): State<AppState>) -> WebResult<Html<String>> {
    let s = st.db.stats()?;
    let scans = st.db.list_scans(6)?;
    let changes = st.db.changes(None, 12)?;
    let max_t = s.by_type.iter().map(|x| x.1).max().unwrap_or(1).max(1);
    let max_v = s.by_vendor.iter().map(|x| x.1).max().unwrap_or(1).max(1);
    let bars = |rows: &[(String, i64)], max: i64, link: bool| -> String {
        if rows.is_empty() {
            return "<p class=muted>No assets yet — run a scan.</p>".into();
        }
        rows.iter()
            .map(|(k, v)| {
                let label = if link && k != "Unknown" {
                    format!("<a href='/assets?type={}'>{}</a>", url_enc(k), esc(k))
                } else {
                    esc(k)
                };
                format!(
                    "<div class=bar><div class=lbl title='{}'>{label}</div><div class=trk><div class=fill style='width:{}%'></div></div><div class=v>{v}</div></div>",
                    esc(k),
                    (v * 100 / max).max(2)
                )
            })
            .collect()
    };
    let max_s = s.by_site.iter().map(|x| x.1).max().unwrap_or(1).max(1);
    let site_ids: std::collections::HashMap<String, i64> = st.db.list_sites()?.into_iter().map(|x| (x.name, x.id)).collect();
    let site_bars = if s.by_site.is_empty() {
        "<p class=muted>No assets yet.</p>".to_string()
    } else {
        let mut html: String = s
            .by_site
            .iter()
            .map(|(k, v)| {
                let id = site_ids.get(k).copied().unwrap_or(0);
                format!(
                    "<div class=bar><div class=lbl><a href='/assets?site={id}'>{}</a></div><div class=trk><div class=fill style='width:{}%'></div></div><div class=v>{v}</div></div>",
                    esc(k), (v * 100 / max_s).max(2)
                )
            })
            .collect();
        if site_ids.is_empty() {
            html.push_str("<p class=hint><a href=/sites>Define sites</a> (e.g. one per clinic) to group assets by location.</p>");
        }
        html
    };
    let scan_rows: String = scans
        .iter()
        .map(|sc| {
            format!(
                "<tr><td><a href='/scans/{0}'>#{0}</a></td><td class=mono>{1}</td><td>{2}</td><td>{3}</td><td class=muted>{4}</td></tr>",
                sc.id, esc(&sc.targets), status_pill(&sc.status), sc.hosts_up, esc(&sc.started_at)
            )
        })
        .collect();
    let body = format!(
        "<h1>Dashboard</h1>\
         <div class='grid g4'>\
           <div class='card stat'><div class=l>Total assets</div><div class=n><a href=/assets>{}</a></div></div>\
           <div class='card stat'><div class=l>Online</div><div class=n style='color:var(--ok)'><a style='color:inherit' href='/assets?status=online'>{}</a></div></div>\
           <div class='card stat'><div class=l>Offline</div><div class=n style='color:var(--bad)'><a style='color:inherit' href='/assets?status=offline'>{}</a></div></div>\
           <div class='card stat'><div class=l>New (7 days)</div><div class=n>{}</div></div>\
         </div>\
         <div class=card><h2>Quick scan</h2>{}</div>\
         <div class='grid g2'><div class=card><h2>Assets by type</h2>{}</div><div class=card><h2>Assets by site</h2>{}</div></div>\
         <div class='grid g2'><div class=card><h2>Top vendors</h2>{}</div><div></div></div>\
         <div class='grid g2'>\
           <div class=card><h2>Recent scans</h2><table><tr><th>Scan</th><th>Targets</th><th>Status</th><th>Up</th><th>Started</th></tr>{}</table></div>\
           <div class=card><h2>Recent changes</h2>{}</div>\
         </div>",
        s.total, s.online, s.offline, s.new_7d,
        scan_form(&suggested_subnet()),
        bars(&s.by_type, max_t, true),
        site_bars,
        bars(&s.by_vendor, max_v, false),
        if scan_rows.is_empty() { "<tr><td colspan=5 class=muted>No scans yet</td></tr>".into() } else { scan_rows },
        changes_table(&changes, true),
    );
    Ok(page("Dashboard", "dashboard", body))
}

fn changes_table(changes: &[crate::db::Change], with_asset: bool) -> String {
    if changes.is_empty() {
        return "<p class=muted>No changes recorded.</p>".into();
    }
    let rows: String = changes
        .iter()
        .map(|c| {
            let asset = if with_asset {
                format!("<td><a href='/assets/{}'>{}</a></td>", c.asset_id, esc(&c.asset_name))
            } else {
                String::new()
            };
            format!(
                "<tr><td class=muted style='white-space:nowrap'>{}</td>{asset}<td>{}</td><td class=mono>{}</td><td class=mono>{}</td></tr>",
                esc(&c.at), esc(&c.field), opt(&c.old_value), opt(&c.new_value)
            )
        })
        .collect();
    format!(
        "<table><tr><th>When</th>{}<th>Change</th><th>Old</th><th>New</th></tr>{rows}</table>",
        if with_asset { "<th>Asset</th>" } else { "" }
    )
}

// ---------------------------------------------------------------- assets

#[derive(Deserialize, Default)]
struct AssetQuery {
    q: Option<String>,
    #[serde(rename = "type")]
    device_type: Option<String>,
    status: Option<String>,
    sort: Option<String>,
    desc: Option<String>,
    /// Site id; "0" = unassigned.
    site: Option<String>,
}

impl AssetQuery {
    fn filter(&self) -> AssetFilter {
        AssetFilter {
            q: self.q.clone(),
            device_type: self.device_type.clone(),
            status: self.status.clone(),
            sort: self.sort.clone(),
            desc: self.desc.as_deref() == Some("1"),
            scan_id: None,
            site_id: self.site.as_deref().and_then(|s| s.parse().ok()),
            allowed_sites: None,
        }
    }
}

fn assets_table(assets: &[Asset], sort_base: Option<(&AssetQuery, String)>) -> String {
    let th = |key: &str, label: &str| -> String {
        match &sort_base {
            Some((q, base)) => {
                let cur = q.sort.as_deref().unwrap_or("ip");
                let desc = q.desc.as_deref() == Some("1");
                let next_desc = if cur == key && !desc { "1" } else { "0" };
                let arrow = if cur == key { if desc { " ↓" } else { " ↑" } } else { "" };
                format!("<th><a href='/assets?{base}&sort={key}&desc={next_desc}'>{label}{arrow}</a></th>")
            }
            None => format!("<th>{label}</th>"),
        }
    };
    let rows: String = assets
        .iter()
        .map(|a| {
            format!(
                "<tr><td class=mono>{}</td><td>{}</td><td>{}</td><td class=mono>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td class=muted style='white-space:nowrap'>{}</td></tr>",
                esc(&a.ip), asset_name_link(a), opt(&a.site), opt(&a.mac), opt(&a.vendor), opt(&a.device_type),
                opt(&a.os_guess), a.open_ports, status_pill(&a.status), esc(&a.last_seen)
            )
        })
        .collect();
    format!(
        "<table><tr>{}{}{}{}{}{}{}{}{}{}</tr>{}</table>",
        th("ip", "IP"), th("name", "Name"), th("site", "Site"), th("mac", "MAC"), th("vendor", "Vendor"), th("type", "Type"),
        th("os", "OS"), th("ports", "Ports"), th("status", "Status"), th("last_seen", "Last seen"),
        if rows.is_empty() { "<tr><td colspan=10 class=muted>No matching assets</td></tr>".into() } else { rows }
    )
}

async fn assets_page(State(st): State<AppState>, Query(q): Query<AssetQuery>) -> WebResult<Html<String>> {
    let assets = st.db.list_assets(&q.filter())?;
    let types = st.db.device_types()?;
    let sel = |v: &str, cur: &Option<String>| if cur.as_deref() == Some(v) { " selected" } else { "" };
    let type_opts: String = types
        .iter()
        .map(|t| format!("<option value='{}'{}>{}</option>", esc(t), sel(t, &q.device_type), esc(t)))
        .collect();
    let base = format!(
        "q={}&type={}&status={}&site={}",
        url_enc(q.q.as_deref().unwrap_or("")),
        url_enc(q.device_type.as_deref().unwrap_or("")),
        url_enc(q.status.as_deref().unwrap_or("")),
        url_enc(q.site.as_deref().unwrap_or(""))
    );
    let site_opts: String = std::iter::once((0i64, "Unassigned".to_string()))
        .chain(st.db.list_sites()?.into_iter().map(|x| (x.id, x.name)))
        .map(|(id, n)| format!("<option value='{id}'{}>{}</option>", sel(&id.to_string(), &q.site), esc(&n)))
        .collect();
    let body = format!(
        "<div class=row><h1>Assets <span class=muted style='font-weight:400'>({})</span></h1><div class=spacer></div>\
         <a class=btn href='/assets/new' style='background:#fff;color:var(--ink);border:1px solid var(--line)'>Add asset</a>&nbsp;\
         <a class=btn href='/import' style='background:#fff;color:var(--ink);border:1px solid var(--line)'>Import CSV</a>&nbsp;\
         <a class=btn href='/export.csv?{base}'>Export CSV</a></div>\
         <div class=card><form class=row action=/assets>\
           <input type=text name=q value='{}' placeholder='Search…' style='flex:1;min-width:220px'>\
           <select name=site><option value=''>All sites</option>{site_opts}</select>\
           <select name=type><option value=''>All types</option>{type_opts}</select>\
           <select name=status><option value=''>Any status</option><option{}>online</option><option{}>offline</option></select>\
           <button>Filter</button><a href=/assets class=muted>Reset</a></form></div>\
         <div class=card style='padding:0;overflow-x:auto'>{}</div>",
        assets.len(),
        esc(q.q.as_deref().unwrap_or("")),
        sel("online", &q.status),
        sel("offline", &q.status),
        assets_table(&assets, Some((&q, base.clone()))),
    );
    Ok(page("Assets", "assets", body))
}

async fn asset_page(State(st): State<AppState>, Path(id): Path<i64>) -> WebResult<Response> {
    let Some(a) = st.db.get_asset(id)? else { return Ok(not_found()) };
    let ports = st.db.asset_ports(id)?;
    let changes = st.db.changes(Some(id), 200)?;
    let port_rows: String = ports
        .iter()
        .map(|p| {
            let link = match p.port {
                80 | 8000 | 8080 => format!(" <a href='http://{}:{}/' target=_blank rel=noopener>open ↗</a>", esc(&a.ip), p.port),
                443 | 8443 => format!(" <a href='https://{}:{}/' target=_blank rel=noopener>open ↗</a>", esc(&a.ip), p.port),
                _ => String::new(),
            };
            format!(
                "<tr><td class=mono>{}/{}</td><td>{}{link}</td><td class=mono>{}</td></tr>",
                p.port, esc(&p.proto), opt(&p.service), opt(&p.banner)
            )
        })
        .collect();
    let row = |k: &str, v: String| format!("<dt>{k}</dt><dd>{v}</dd>");
    let body = format!(
        "<div class=row><h1>{name}</h1>&nbsp;{status}<div class=spacer></div>\
           <form class=inline method=post action='/scans'><input type=hidden name=targets value='{ip}'><button class=ghost>Rescan</button></form>\
           <form class=inline method=post action='/assets/{id}/delete' onsubmit=\"return confirm('Delete this asset and its history?')\"><button class=danger>Delete</button></form></div>\
         <div class='grid g3'>\
          <div>\
           <div class=card><h2>Identity</h2><dl>{identity}</dl></div>\
           <div class=card><h2>Open ports ({nports})</h2><table><tr><th>Port</th><th>Service</th><th>Banner</th></tr>{port_rows}</table></div>\
           <div class=card><h2>History</h2>{history}</div>\
          </div>\
          <div>\
           <div class=card><h2>SNMP</h2><dl>{snmp}</dl></div>\
           <div class=card><h2>Web</h2><dl>{web}</dl></div>\
           <div class=card><h2>Site</h2><form method=post action='/assets/{id}/site' class=row><select name=site_id>{site_opts}</select><button class=ghost>Set</button></form>\
             <div class=hint>&ldquo;Automatic&rdquo; places the asset by its IP and your site subnets.</div></div>\
           <div class=card><h2>Asset details</h2><form method=post action='/assets/{id}/details'>{details_form}\
             <div style='margin-top:10px' class=row><button>Save details</button><span class=hint><a href=/custom-fields>Manage custom fields</a></span></div></form></div>\
          </div>\
         </div>",
        name = esc(&a.display_name()),
        status = status_pill(&a.status),
        ip = esc(&a.ip),
        id = a.id,
        identity = [
            row("IP address", format!("<span class=mono>{}</span>", esc(&a.ip))),
            row("MAC address", format!("<span class=mono>{}</span>", opt(&a.mac))),
            row("Vendor", opt(&a.vendor)),
            row("DNS name", opt(&a.hostname)),
            row("NetBIOS name", opt(&a.netbios_name)),
            row("Domain / workgroup", opt(&a.netbios_domain)),
            row("Site", format!("{} <span class=muted>{}</span>",
                a.site_id.map(|sid| format!("<a href='/sites/{sid}'>{}</a>", opt(&a.site))).unwrap_or_else(|| "<span class=muted>Unassigned</span>".into()),
                if a.site_manual { "(set manually)" } else { "(by subnet)" })),
            row("Device type", opt(&a.device_type)),
            row("OS (guess)", opt(&a.os_guess)),
            row("TTL", a.ttl.map(|t| t.to_string()).unwrap_or_else(|| "—".into())),
            row("SSH banner", format!("<span class=mono>{}</span>", opt(&a.ssh_banner))),
            row("Source", format!("{}{}", esc(&a.source), if a.scan_count > 0 { format!(" <span class=muted>· seen by {} scan(s)</span>", a.scan_count) } else { String::new() })),
            row("Detected via", opt(&a.detected_by)),
            row("First seen", esc(&a.first_seen)),
            row("Last seen", esc(&a.last_seen)),
        ]
        .concat(),
        nports = ports.len(),
        port_rows = if port_rows.is_empty() { "<tr><td colspan=3 class=muted>None detected</td></tr>".into() } else { port_rows },
        history = changes_table(&changes, false),
        snmp = [
            row("sysName", opt(&a.snmp_name)),
            row("sysDescr", opt(&a.snmp_descr)),
            row("sysLocation", opt(&a.snmp_location)),
            row("sysContact", opt(&a.snmp_contact)),
        ]
        .concat(),
        web = [row("Server", opt(&a.http_server)), row("Title", opt(&a.http_title))].concat(),
        details_form = details_form(&a, &st.db.custom_fields()?, &st.db.asset_custom_values(a.id)?),
        site_opts = std::iter::once(format!("<option value=''{}>Automatic (by subnet)</option>", if a.site_manual { "" } else { " selected" }))
            .chain(st.db.list_sites()?.iter().map(|x| format!(
                "<option value='{}'{}>{}</option>", x.id,
                if a.site_manual && a.site_id == Some(x.id) { " selected" } else { "" }, esc(&x.name))))
            .collect::<String>(),
    );
    Ok(page(&a.display_name(), "assets", body).into_response())
}

fn details_form(a: &Asset, custom: &[crate::db::CustomField], values: &[(String, String)]) -> String {
    let input = |name: &str, label: &str, value: &str, kind: &str| {
        format!(
            "<label style='display:block'><span class=muted style='font-size:12px'>{label}</span><br>\
             <input type={kind} name='{name}' value='{}' style='width:100%'></label>",
            esc(value)
        )
    };
    let mut html = String::from("<div style='display:grid;grid-template-columns:1fr 1fr;gap:8px 10px'>");
    for (col, label) in crate::db::EDITABLE_FIELDS.iter().filter(|(c, _)| *c != "notes") {
        let kind = if crate::db::DATE_FIELDS.contains(col) { "date" } else { "text" };
        html.push_str(&input(col, label, a.editable(col).as_deref().unwrap_or(""), kind));
    }
    for f in custom {
        let v = values.iter().find(|(k, _)| k == &f.name).map(|(_, v)| v.as_str()).unwrap_or("");
        html.push_str(&input(&format!("custom:{}", f.name), &esc(&f.name), v, "text"));
    }
    html.push_str("</div>");
    html.push_str(&format!(
        "<label style='display:block;margin-top:8px'><span class=muted style='font-size:12px'>Notes</span>\
         <textarea name=notes>{}</textarea></label>",
        esc(&a.notes)
    ));
    html
}

/// Split a submitted details form into built-in field edits and custom field edits.
fn parse_details(form: &HashMap<String, String>) -> Result<(Vec<(String, Option<String>)>, Vec<(String, Option<String>)>)> {
    let mut edits = Vec::new();
    let mut custom = Vec::new();
    for (k, v) in form {
        if let Some(name) = k.strip_prefix("custom:") {
            custom.push((name.to_string(), Some(v.trim().to_string()).filter(|s| !s.is_empty())));
        } else if crate::db::EDITABLE_FIELDS.iter().any(|(c, _)| c == k) {
            let v = crate::db::normalize_field(k, v).map_err(|e| anyhow::anyhow!("{k}: {e}"))?;
            edits.push((k.clone(), v));
        }
    }
    Ok((edits, custom))
}

async fn save_details(State(st): State<AppState>, Path(id): Path<i64>, Form(form): Form<HashMap<String, String>>) -> WebResult<Response> {
    let (edits, custom) = match parse_details(&form) {
        Ok(x) => x,
        Err(e) => return Ok(form_error("Could not save", "assets", &e, &format!("/assets/{id}"))),
    };
    st.db.update_asset_fields(id, &edits)?;
    for (name, v) in custom {
        st.db.set_custom_value(id, &name, v.as_deref())?;
    }
    Ok(Redirect::to(&format!("/assets/{id}")).into_response())
}

async fn new_asset_page() -> Html<String> {
    page("Add asset", "assets", "<h1>Add asset</h1><div class=card>\
        <p class=muted>For devices the scanner can't reach (off-network laptops, spare stock, peripherals). If the scanner later finds a device with the same MAC or IP, it updates this record instead of creating a new one.</p>\
        <form method=post action=/assets/new class=row>\
          <input type=text name=name placeholder='Name (e.g. LAPTOP-0142)' style='min-width:220px'>\
          <input type=text name=ip placeholder='IP (optional)'>\
          <input type=text name=mac placeholder='MAC (optional)'>\
          <button>Add</button></form><div class=hint>Give at least one of name, IP or MAC. You can fill in owner, serial, warranty and other details on the next page.</div></div>".into())
}

#[derive(Deserialize)]
struct NewAssetForm {
    #[serde(default)]
    name: String,
    #[serde(default)]
    ip: String,
    #[serde(default)]
    mac: String,
}

async fn create_asset(State(st): State<AppState>, Form(f): Form<NewAssetForm>) -> WebResult<Response> {
    let opt_s = |s: &str| Some(s.trim()).filter(|s| !s.is_empty()).map(str::to_string);
    Ok(match st.db.create_manual_asset(opt_s(&f.ip).as_deref(), opt_s(&f.mac).as_deref(), opt_s(&f.name).as_deref(), "manual") {
        Ok(id) => Redirect::to(&format!("/assets/{id}")).into_response(),
        Err(e) => form_error("Could not add asset", "assets", &e, "/assets/new"),
    })
}

// ---------------------------------------------------------------- import & custom fields

fn import_form() -> String {
    "<form method=post action=/import enctype=multipart/form-data>\
       <div class=row style='margin-bottom:8px'><input type=file name=file accept='.csv,text/csv'>\
       <label><input type=checkbox name=create_missing value=1> Create assets for rows that match nothing</label>\
       <label><input type=checkbox name=dry_run value=1 checked> Preview only (dry run)</label></div>\
       <textarea name=text placeholder='…or paste CSV here'></textarea>\
       <div style='margin-top:8px'><button>Import</button></div></form>".into()
}

async fn import_page(State(st): State<AppState>) -> WebResult<Html<String>> {
    let custom = st.db.custom_fields()?;
    let cols: Vec<String> = crate::db::EDITABLE_FIELDS.iter().map(|(c, _)| format!("<code>{c}</code>")).collect();
    Ok(page("Import", "assets", format!(
        "<h1>Import asset details</h1>\
         <div class=card>{}</div>\
         <div class=card><h2>How matching works</h2>\
         <p>Each row is matched to an existing asset by the first identifier column present: <code>id</code>, <code>asset_tag</code>, \
         <code>serial_number</code>, <code>mac</code>, <code>ip</code>, <code>name</code>. The easiest workflow is \
         <a href=/export.csv>export the asset list</a>, fill in columns in Excel, and import it back.</p>\
         <p>Updatable columns: {}, <code>site</code> (pins the asset; <code>auto</code> to unpin){}.</p>\
         <p class=hint>Empty cells leave a field unchanged; a cell containing just <code>-</code> clears it. Dates accept YYYY-MM-DD or MM/DD/YYYY. \
         Other columns (vendor, device_type, …) are ignored. Every change is recorded in the asset's history.</p></div>",
        import_form(),
        cols.join(", "),
        if custom.is_empty() { String::new() } else {
            format!(", and custom fields: {}", custom.iter().map(|f| format!("<code>{}</code>", esc(&f.name))).collect::<Vec<_>>().join(", "))
        }
    )))
}

fn import_report_html(r: &crate::import::ImportReport) -> String {
    let rows: String = r
        .results
        .iter()
        .filter(|x| x.action != "unchanged" || !x.errors.is_empty())
        .take(500)
        .map(|x| {
            let pill = match x.action.as_str() {
                "created" => "<span class='pill ok'>created</span>".to_string(),
                "updated" => "<span class='pill run'>updated</span>".to_string(),
                "skipped" => "<span class='pill bad'>skipped</span>".to_string(),
                other => status_pill(other),
            };
            format!(
                "<tr><td>{}</td><td>{}</td><td>{pill}</td><td>{}</td><td style='color:var(--bad)'>{}</td></tr>",
                x.row,
                match (x.asset_id, &x.asset) {
                    (Some(id), Some(n)) => format!("<a href='/assets/{id}'>{}</a>", esc(n)),
                    (_, Some(n)) => esc(n),
                    _ => "—".into(),
                },
                x.changes.iter().map(|c| esc(c)).collect::<Vec<_>>().join("<br>"),
                x.errors.iter().map(|c| esc(c)).collect::<Vec<_>>().join("<br>")
            )
        })
        .collect();
    format!(
        "<div class=card><h2>{}</h2><p>{} rows · {} matched · {} created · {} assets updated ({} field changes) · {} skipped</p>\
         <p class=hint>Identifier columns: {} · updated: {} · ignored: {}</p>\
         <table><tr><th>Row</th><th>Asset</th><th>Result</th><th>Changes</th><th>Problems</th></tr>{}</table></div>",
        if r.dry_run { "Preview — nothing was saved" } else { "Import complete" },
        r.rows, r.matched, r.created, r.updated_assets, r.fields_changed, r.skipped,
        esc(&r.key_columns.join(", ")), esc(&r.update_columns.join(", ")),
        if r.ignored_columns.is_empty() { "none".into() } else { esc(&r.ignored_columns.join(", ")) },
        if rows.is_empty() { "<tr><td colspan=5 class=muted>No changes</td></tr>".into() } else { rows }
    )
}

async fn import_upload(State(st): State<AppState>, mut mp: axum::extract::Multipart) -> WebResult<Response> {
    let mut data = String::new();
    let mut opts = crate::import::ImportOptions { source: "import".into(), ..Default::default() };
    while let Some(field) = mp.next_field().await.map_err(|e| anyhow::anyhow!("upload failed: {e}"))? {
        let name = field.name().unwrap_or("").to_string();
        let bytes = field.bytes().await.map_err(|e| anyhow::anyhow!("upload failed: {e}"))?;
        match name.as_str() {
            "file" if !bytes.is_empty() => data = String::from_utf8_lossy(&bytes).into_owned(),
            "text" if data.is_empty() => data = String::from_utf8_lossy(&bytes).into_owned(),
            "create_missing" => opts.create_missing = true,
            "dry_run" => opts.dry_run = true,
            _ => {}
        }
    }
    if data.trim().is_empty() {
        return Ok(form_error("Nothing to import", "assets", &anyhow::anyhow!("choose a CSV file or paste CSV text"), "/import"));
    }
    Ok(match crate::import::import_csv(&st.db, &data, &opts) {
        Ok(r) => page("Import", "assets", format!(
            "<h1>Import asset details</h1>{}<div class=card><h2>Import another file</h2>{}</div>",
            import_report_html(&r), import_form()
        )).into_response(),
        Err(e) => form_error("Import failed", "assets", &e, "/import"),
    })
}

async fn custom_fields_page(State(st): State<AppState>) -> WebResult<Html<String>> {
    let rows: String = st
        .db
        .custom_fields()?
        .iter()
        .map(|f| format!(
            "<tr><td>{}</td><td>{}</td><td class=muted>{}</td><td><form class=inline method=post action='/custom-fields/{}/delete' \
             onsubmit=\"return confirm('Delete this field and its values on every asset?')\"><button class=danger>Delete</button></form></td></tr>",
            esc(&f.name), f.in_use, esc(&f.created_at), f.id
        ))
        .collect();
    Ok(page("Custom fields", "assets", format!(
        "<h1>Custom fields</h1><div class=card><h2>Add field</h2><form method=post action=/custom-fields class=row>\
         <input type=text name=name placeholder='e.g. Room, Insurance Plan, Clinical use' required><button>Add</button></form>\
         <div class=hint>Custom fields appear on every asset's details form, in CSV export/import, and to AI assistants (custom_fields dataset).</div></div>\
         <div class=card style='padding:0'><table><tr><th>Field</th><th>Assets with a value</th><th>Created</th><th></th></tr>{}</table></div>",
        if rows.is_empty() { "<tr><td colspan=4 class=muted>No custom fields yet</td></tr>".into() } else { rows }
    )))
}

#[derive(Deserialize)]
struct CustomFieldForm {
    name: String,
}

async fn add_custom_field(State(st): State<AppState>, Form(f): Form<CustomFieldForm>) -> WebResult<Response> {
    Ok(match st.db.add_custom_field(&f.name) {
        Ok(_) => Redirect::to("/custom-fields").into_response(),
        Err(e) => form_error("Could not add field", "assets", &e, "/custom-fields"),
    })
}

async fn delete_custom_field(State(st): State<AppState>, Path(id): Path<i64>) -> WebResult<Redirect> {
    st.db.delete_custom_field(id)?;
    Ok(Redirect::to("/custom-fields"))
}

async fn delete_asset(State(st): State<AppState>, Path(id): Path<i64>) -> WebResult<Redirect> {
    st.db.delete_asset(id)?;
    Ok(Redirect::to("/assets"))
}

// ---------------------------------------------------------------- scans

#[derive(Deserialize)]
struct ScanForm {
    targets: String,
}

async fn start_scan_form(State(st): State<AppState>, Form(f): Form<ScanForm>) -> Response {
    match launch_scan(&st, &f.targets, "manual") {
        Ok(id) => Redirect::to(&format!("/scans/{id}")).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            page(
                "Scan error",
                "scans",
                format!(
                    "<h1>Could not start scan</h1><div class=card><p style='color:var(--bad)'>{}</p>{}</div>",
                    esc(&format!("{e:#}")),
                    scan_form(&f.targets)
                ),
            ),
        )
            .into_response(),
    }
}

async fn scans_page(State(st): State<AppState>) -> WebResult<Html<String>> {
    let scans = st.db.list_scans(200)?;
    let rows: String = scans
        .iter()
        .map(|s| {
            format!(
                "<tr><td><a href='/scans/{0}'>#{0}</a></td><td class=mono>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td><td>{5}</td><td>{6}</td><td class=muted>{7}</td><td class=muted>{8}</td></tr>",
                s.id, esc(&s.targets), esc(&s.trigger), status_pill(&s.status), s.hosts_scanned, s.hosts_up,
                s.new_assets, esc(&s.started_at), opt(&s.finished_at)
            )
        })
        .collect();
    let body = format!(
        "<h1>Scans</h1><div class=card><h2>New scan</h2>{}</div>\
         <div class=card style='padding:0;overflow-x:auto'><table><tr><th>Scan</th><th>Targets</th><th>Trigger</th><th>Status</th><th>Scanned</th><th>Up</th><th>New</th><th>Started</th><th>Finished</th></tr>{}</table></div>",
        scan_form(&suggested_subnet()),
        if rows.is_empty() { "<tr><td colspan=9 class=muted>No scans yet</td></tr>".into() } else { rows }
    );
    Ok(page("Scans", "scans", body))
}

async fn scan_page(State(st): State<AppState>, Path(id): Path<i64>) -> WebResult<Response> {
    let Some(s) = st.db.get_scan(id)? else { return Ok(not_found()) };
    let prog = st.progress_of(id);
    let (progress_html, head) = match &prog {
        Some(p) => {
            let total = p.total.load(Ordering::Relaxed).max(1);
            let done = p.done.load(Ordering::Relaxed);
            (
                format!(
                    "<div class=card><h2>Progress</h2><div class=progress><div style='width:{}%'></div></div>\
                     <p>{done} / {total} hosts probed · <b>{}</b> up so far</p><p class=hint>This page refreshes automatically.</p></div>",
                    done * 100 / total,
                    p.up.load(Ordering::Relaxed)
                ),
                "<meta http-equiv=refresh content=2>",
            )
        }
        None => (String::new(), ""),
    };
    let assets = if prog.is_none() {
        st.db.list_assets(&AssetFilter { scan_id: Some(id), ..Default::default() })?
    } else {
        vec![]
    };
    let body = format!(
        "<div class=row><h1>Scan #{}</h1>&nbsp;{}</div>\
         <div class=card><dl><dt>Targets</dt><dd class=mono>{}</dd><dt>Trigger</dt><dd>{}</dd><dt>Started</dt><dd>{}</dd><dt>Finished</dt><dd>{}</dd>\
         <dt>Hosts scanned</dt><dd>{}</dd><dt>Hosts up</dt><dd>{}</dd><dt>New assets</dt><dd>{}</dd>{}</dl></div>{}\
         {}",
        s.id, status_pill(&s.status), esc(&s.targets), esc(&s.trigger), esc(&s.started_at), opt(&s.finished_at),
        s.hosts_scanned, s.hosts_up, s.new_assets,
        s.error.as_ref().map(|e| format!("<dt>Error</dt><dd style='color:var(--bad)'>{}</dd>", esc(e))).unwrap_or_default(),
        progress_html,
        if prog.is_none() {
            format!("<div class=card style='padding:0;overflow-x:auto'><h2 style='padding:16px 16px 0'>Assets seen in this scan</h2>{}</div>", assets_table(&assets, None))
        } else {
            String::new()
        }
    );
    Ok(page_ext(&format!("Scan #{id}"), "scans", body, head).into_response())
}

// ---------------------------------------------------------------- schedules

#[derive(Deserialize)]
struct ScheduleForm {
    name: String,
    #[serde(default)]
    targets: String,
    interval_minutes: i64,
    /// Site id; when set the schedule scans that site's subnets.
    #[serde(default)]
    site_id: String,
}

async fn schedules_page(State(st): State<AppState>) -> WebResult<Html<String>> {
    let sites = st.db.list_sites()?;
    let site_name = |id: Option<i64>| id.and_then(|i| sites.iter().find(|s| s.id == i)).map(|s| s.name.clone());
    let rows: String = st
        .db
        .list_schedules()?
        .iter()
        .map(|s| {
            format!(
                "<tr><td>{}</td><td class=mono>{}</td><td>every {}</td><td>{}</td><td class=muted>{}</td>\
                 <td><form class=inline method=post action='/schedules/{id}/toggle'><button class=ghost>{}</button></form> \
                 <form class=inline method=post action='/schedules/{id}/delete'><button class=danger>Delete</button></form></td></tr>",
                esc(&s.name),
                match site_name(s.site_id) { Some(n) => format!("Site: {} <span class=muted>(its subnets)</span>", esc(&n)), None => esc(&s.targets) },
                human_minutes(s.interval_minutes),
                if s.enabled { status_pill("online").replace("online", "enabled") } else { status_pill("offline").replace("offline", "paused") },
                opt(&s.last_run),
                if s.enabled { "Pause" } else { "Resume" },
                id = s.id,
            )
        })
        .collect();
    let body = format!(
        "<h1>Scheduled scans</h1>\
         <div class=card><h2>Add schedule</h2><form method=post action=/schedules class=row>\
           <input type=text name=name placeholder='Name (e.g. Main clinic LAN)' required>\
           <select name=site_id><option value=''>Custom targets →</option>{}</select>\
           <input type=text name=targets placeholder='10.0.0.0/24' value='{}' style='flex:1;min-width:200px'>\
           <select name=interval_minutes><option value=60>Hourly</option><option value=240>Every 4 hours</option>\
             <option value=720>Every 12 hours</option><option value=1440 selected>Daily</option><option value=10080>Weekly</option></select>\
           <button>Add</button></form><div class=hint>Schedules run while <code>rustsweeper serve</code> is running.</div></div>\
         <div class=card style='padding:0'><table><tr><th>Name</th><th>Targets</th><th>Interval</th><th>State</th><th>Last run</th><th></th></tr>{}</table></div>",
        sites.iter().map(|x| format!("<option value='{}'>Site: {}</option>", x.id, esc(&x.name))).collect::<String>(),
        esc(&suggested_subnet()),
        if rows.is_empty() { "<tr><td colspan=6 class=muted>No schedules</td></tr>".into() } else { rows }
    );
    Ok(page("Schedules", "schedules", body))
}

fn human_minutes(m: i64) -> String {
    match m {
        m if m % 10080 == 0 => format!("{} week(s)", m / 10080),
        m if m % 1440 == 0 => format!("{} day(s)", m / 1440),
        m if m % 60 == 0 => format!("{} hour(s)", m / 60),
        m => format!("{m} min"),
    }
}

async fn add_schedule(State(st): State<AppState>, Form(f): Form<ScheduleForm>) -> WebResult<Response> {
    if let Ok(site_id) = f.site_id.trim().parse::<i64>() {
        let Some(site) = st.db.get_site(site_id)? else { return Ok(not_found()) };
        st.db.add_schedule_for_site(f.name.trim(), &site.subnets, f.interval_minutes.max(5), Some(site_id))?;
        return Ok(Redirect::to("/schedules").into_response());
    }
    if let Err(e) = scanner::targets::parse_targets(&f.targets) {
        return Ok((StatusCode::BAD_REQUEST, page("Schedule error", "schedules",
            format!("<h1>Invalid targets</h1><div class=card><p style='color:var(--bad)'>{}</p><a href=/schedules>Back</a></div>", esc(&format!("{e:#}"))))).into_response());
    }
    st.db.add_schedule(f.name.trim(), f.targets.trim(), f.interval_minutes.max(5))?;
    Ok(Redirect::to("/schedules").into_response())
}

async fn toggle_schedule(State(st): State<AppState>, Path(id): Path<i64>) -> WebResult<Redirect> {
    st.db.toggle_schedule(id)?;
    Ok(Redirect::to("/schedules"))
}

async fn delete_schedule(State(st): State<AppState>, Path(id): Path<i64>) -> WebResult<Redirect> {
    st.db.delete_schedule(id)?;
    Ok(Redirect::to("/schedules"))
}

async fn changes_page(State(st): State<AppState>) -> WebResult<Html<String>> {
    let changes = st.db.changes(None, 500)?;
    Ok(page(
        "Changes",
        "changes",
        format!("<h1>Change log</h1><div class=card style='overflow-x:auto'>{}</div>", changes_table(&changes, true)),
    ))
}

async fn ai_access_page(State(st): State<AppState>) -> WebResult<Html<String>> {
    let tokens: String = st
        .db
        .list_tokens()?
        .iter()
        .map(|t| {
            format!(
                "<tr><td>{}</td><td>{}</td><td class=mono>{}…</td><td class=muted>{}</td><td class=muted>{}</td><td>{}</td></tr>",
                t.id, esc(&t.name), esc(&t.prefix), esc(&t.created_at), opt(&t.last_used),
                if t.revoked { status_pill("offline").replace("offline", "revoked") } else { status_pill("online").replace("online", "active") }
            )
        })
        .collect();
    let audit: String = st
        .db
        .list_audit(300)?
        .iter()
        .map(|a| {
            let args = a.arguments.as_deref().unwrap_or("");
            let short: String = args.chars().take(160).collect();
            format!(
                "<tr><td class=muted style='white-space:nowrap'>{}</td><td>{}</td><td>{}</td><td class=mono>{}</td><td>{}</td><td class=mono title='{}'>{}{}</td><td>{}</td><td>{}</td><td class=muted>{} ms</td></tr>",
                esc(&a.at), esc(&a.transport), opt(&a.client), opt(&a.remote_addr),
                esc(a.tool.as_deref().unwrap_or(&a.method)), esc(args), esc(&short), if args.chars().count() > 160 { "…" } else { "" },
                if a.ok { status_pill("online").replace("online", "ok") } else { format!("<span class='pill bad' title='{}'>error</span>", esc(a.error.as_deref().unwrap_or(""))) },
                a.rows.map(|r| r.to_string()).unwrap_or_default(), a.duration_ms
            )
        })
        .collect();
    let body = format!(
        "<h1>AI access (MCP)</h1>\
         <div class=card><h2>How to connect</h2>\
         <p>Local assistants (Claude Desktop, Claude Code, Cursor) can launch <code>rustsweeper mcp</code> over stdio. \
         Remote clients connect to <code>/mcp</code> on this server with an API token:</p>\
         <pre class=mono style='background:#f3f4f6;padding:10px;border-radius:6px'>rustsweeper token create \"claude-desktop\"\nAuthorization: Bearer rsw_…</pre>\
         <p class=hint>The MCP server is read-only unless started with --allow-scans / --mcp-allow-scans. Every call is logged below. \
         Check your organization's AI-use policy before connecting third-party assistants.</p></div>\
         <div class=card style='padding:0;overflow-x:auto'><h2 style='padding:16px 16px 0'>API tokens</h2>\
         <table><tr><th>ID</th><th>Name</th><th>Prefix</th><th>Created</th><th>Last used</th><th>State</th></tr>{}</table>\
         <p class=hint style='padding:0 16px 12px'>Create and revoke tokens with <code>rustsweeper token create|revoke</code>.</p></div>\
         <div class=card style='padding:0;overflow-x:auto'><h2 style='padding:16px 16px 0'>Audit log</h2>\
         <table><tr><th>When</th><th>Via</th><th>Client</th><th>From</th><th>Tool</th><th>Arguments</th><th>Result</th><th>Rows</th><th>Time</th></tr>{}</table></div>",
        if tokens.is_empty() { "<tr><td colspan=6 class=muted>No tokens</td></tr>".into() } else { tokens },
        if audit.is_empty() { "<tr><td colspan=9 class=muted>No MCP calls yet</td></tr>".into() } else { audit },
    );
    Ok(page("AI access", "ai", body))
}

// ---------------------------------------------------------------- sites

#[derive(Deserialize)]
struct SiteForm {
    name: String,
    subnets: String,
    #[serde(default)]
    description: String,
}

fn site_form(action: &str, name: &str, subnets: &str, description: &str, button: &str) -> String {
    format!(
        "<form method=post action='{action}'>\
           <div class=row style='margin-bottom:8px'><input type=text name=name value='{}' placeholder='Name (e.g. Main Clinic)' required style='min-width:220px'>\
           <input type=text name=subnets value='{}' placeholder='10.10.0.0/24, 10.10.1.0/24' required style='flex:1;min-width:260px'></div>\
           <div class=row><input type=text name=description value='{}' placeholder='Description / address (optional)' style='flex:1'><button>{button}</button></div>\
         </form><div class=hint>Subnets in CIDR form, comma separated. Assets are placed in the site whose subnet most specifically contains their IP; you can also pin individual assets by hand.</div>",
        esc(name), esc(subnets), esc(description)
    )
}

fn form_error(title: &str, active: &str, e: &anyhow::Error, back: &str) -> Response {
    (StatusCode::BAD_REQUEST, page(title, active, format!(
        "<h1>{}</h1><div class=card><p style='color:var(--bad)'>{}</p><a href='{back}'>Back</a></div>", esc(title), esc(&format!("{e:#}"))
    ))).into_response()
}

async fn sites_page(State(st): State<AppState>) -> WebResult<Html<String>> {
    let sites = st.db.list_sites()?;
    let unassigned = st.db.unassigned_count()?;
    let rows: String = sites
        .iter()
        .map(|x| format!(
            "<tr><td><a href='/sites/{0}'>{1}</a></td><td class=mono>{2}</td><td class=muted>{3}</td><td><a href='/assets?site={0}'>{4}</a></td><td>{5}</td>\
             <td><form class=inline method=post action='/sites/{0}/scan'><button class=ghost>Scan now</button></form></td></tr>",
            x.id, esc(&x.name), esc(&x.subnets), esc(&x.description), x.asset_count, x.online
        ))
        .collect();
    let body = format!(
        "<h1>Sites</h1>\
         <div class=card><h2>Add site</h2>{}</div>\
         <div class=card style='padding:0;overflow-x:auto'><table><tr><th>Site</th><th>Subnets</th><th>Description</th><th>Assets</th><th>Online</th><th></th></tr>{}\
           <tr><td class=muted>Unassigned</td><td class=muted>—</td><td class=muted>IPs outside every site</td><td><a href='/assets?site=0'>{unassigned}</a></td><td></td><td></td></tr></table></div>",
        site_form("/sites", "", "", "", "Add site"),
        rows
    );
    Ok(page("Sites", "sites", body))
}

async fn add_site(State(st): State<AppState>, Form(f): Form<SiteForm>) -> WebResult<Response> {
    let res = crate::sites::parse_subnets(&f.subnets)
        .and_then(|n| st.db.add_site(&f.name, &crate::sites::format_subnets(&n), &f.description));
    Ok(match res {
        Ok(id) => Redirect::to(&format!("/sites/{id}")).into_response(),
        Err(e) => form_error("Could not add site", "sites", &e, "/sites"),
    })
}

async fn site_page(State(st): State<AppState>, Path(id): Path<i64>) -> WebResult<Response> {
    let Some(site) = st.db.get_site(id)? else { return Ok(not_found()) };
    let assets = st.db.list_assets(&AssetFilter { site_id: Some(id), ..Default::default() })?;
    let body = format!(
        "<div class=row><h1>{}</h1><span class=muted>&nbsp;{} assets · {} online</span><div class=spacer></div>\
           <form class=inline method=post action='/sites/{id}/scan'><button>Scan this site</button></form>\
           <form class=inline method=post action='/sites/{id}/delete' onsubmit=\"return confirm('Delete this site? Its assets become unassigned.')\"><button class=danger>Delete</button></form></div>\
         <div class=card><h2>Edit</h2>{}</div>\
         <div class=card style='padding:0;overflow-x:auto'>{}</div>",
        esc(&site.name), site.asset_count, site.online,
        site_form(&format!("/sites/{id}"), &site.name, &site.subnets, &site.description, "Save"),
        assets_table(&assets, None)
    );
    Ok(page(&site.name, "sites", body).into_response())
}

async fn update_site(State(st): State<AppState>, Path(id): Path<i64>, Form(f): Form<SiteForm>) -> WebResult<Response> {
    let res = crate::sites::parse_subnets(&f.subnets)
        .and_then(|n| st.db.update_site(id, &f.name, &crate::sites::format_subnets(&n), &f.description));
    Ok(match res {
        Ok(()) => Redirect::to(&format!("/sites/{id}")).into_response(),
        Err(e) => form_error("Could not update site", "sites", &e, &format!("/sites/{id}")),
    })
}

async fn delete_site(State(st): State<AppState>, Path(id): Path<i64>) -> WebResult<Redirect> {
    st.db.delete_site(id)?;
    Ok(Redirect::to("/sites"))
}

async fn scan_site(State(st): State<AppState>, Path(id): Path<i64>) -> WebResult<Response> {
    let Some(site) = st.db.get_site(id)? else { return Ok(not_found()) };
    let targets = crate::sites::scan_targets(&crate::sites::parse_subnets(&site.subnets)?);
    Ok(match launch_scan_for_site(&st, &targets, &format!("site: {}", site.name), Some(id)) {
        Ok(scan) => Redirect::to(&format!("/scans/{scan}")).into_response(),
        Err(e) => form_error("Could not start scan", "sites", &e, &format!("/sites/{id}")),
    })
}

#[derive(Deserialize)]
struct AssetSiteForm {
    #[serde(default)]
    site_id: String,
}

async fn set_asset_site(State(st): State<AppState>, Path(id): Path<i64>, Form(f): Form<AssetSiteForm>) -> WebResult<Redirect> {
    st.db.set_asset_site(id, f.site_id.trim().parse().ok())?;
    Ok(Redirect::to(&format!("/assets/{id}")))
}

async fn api_sites(State(st): State<AppState>) -> WebResult<Json<serde_json::Value>> {
    Ok(Json(json!(st.db.list_sites()?)))
}

// ---------------------------------------------------------------- CSV export

fn csv_field(s: &str) -> String {
    // Quote always; neutralise spreadsheet formula injection.
    let s = if s.starts_with(['=', '+', '-', '@']) { format!("'{s}") } else { s.to_string() };
    format!("\"{}\"", s.replace('"', "\"\""))
}

/// CSV export. Columns are import-compatible: edit in Excel and import back.
pub fn assets_csv(db: &Db, assets: &[Asset]) -> Result<String> {
    let custom_names: Vec<String> = db.custom_fields()?.into_iter().map(|f| f.name).collect();
    let custom = db.all_custom_values()?;
    let mut header: Vec<String> = ["id", "ip", "name", "site", "mac", "vendor", "dns_name", "netbios_name", "domain", "device_type",
        "os_guess", "open_ports", "status", "source", "detected_by", "snmp_descr", "snmp_location", "first_seen", "last_seen"]
        .iter().map(|s| s.to_string()).collect();
    header.extend(crate::db::EDITABLE_FIELDS.iter().filter(|(c, _)| *c != "notes").map(|(c, _)| c.to_string()));
    header.extend(custom_names.iter().map(|n| csv_field(n)));
    header.push("notes".into());
    let mut out = header.join(",");
    out.push_str("\r\n");
    for a in assets {
        let o = |v: &Option<String>| csv_field(v.as_deref().unwrap_or(""));
        let mut row = vec![
            a.id.to_string(), csv_field(&a.ip), csv_field(&a.display_name()), o(&a.site), o(&a.mac), o(&a.vendor), o(&a.hostname),
            o(&a.netbios_name), o(&a.netbios_domain), o(&a.device_type), o(&a.os_guess), a.open_ports.to_string(), csv_field(&a.status),
            csv_field(&a.source), o(&a.detected_by), o(&a.snmp_descr), o(&a.snmp_location), csv_field(&a.first_seen), csv_field(&a.last_seen),
        ];
        row.extend(crate::db::EDITABLE_FIELDS.iter().filter(|(c, _)| *c != "notes").map(|(c, _)| o(&a.editable(c))));
        let mine = custom.get(&a.id);
        row.extend(custom_names.iter().map(|n| csv_field(mine.and_then(|m| m.get(n)).map(String::as_str).unwrap_or(""))));
        row.push(csv_field(&a.notes));
        out.push_str(&row.join(","));
        out.push_str("\r\n");
    }
    Ok(out)
}

async fn export_csv(State(st): State<AppState>, Query(q): Query<AssetQuery>) -> WebResult<Response> {
    let csv = assets_csv(&st.db, &st.db.list_assets(&q.filter())?)?;
    Ok((
        [
            (header::CONTENT_TYPE, "text/csv; charset=utf-8"),
            (header::CONTENT_DISPOSITION, "attachment; filename=\"assets.csv\""),
        ],
        csv,
    )
        .into_response())
}

// ---------------------------------------------------------------- JSON API

async fn api_stats(State(st): State<AppState>) -> WebResult<Json<serde_json::Value>> {
    Ok(Json(json!(st.db.stats()?)))
}

async fn api_assets(State(st): State<AppState>, Query(q): Query<AssetQuery>) -> WebResult<Json<serde_json::Value>> {
    Ok(Json(json!(st.db.list_assets(&q.filter())?)))
}

async fn api_asset(State(st): State<AppState>, Path(id): Path<i64>) -> WebResult<Response> {
    let Some(a) = st.db.get_asset(id)? else { return Ok((StatusCode::NOT_FOUND, Json(json!({"error":"not found"}))).into_response()) };
    Ok(Json(json!({
        "asset": a,
        "custom_fields": st.db.asset_custom_values(id)?.into_iter().collect::<std::collections::BTreeMap<_, _>>(),
        "ports": st.db.asset_ports(id)?,
        "changes": st.db.changes(Some(id), 200)?,
    })).into_response())
}

/// PATCH /api/assets/{id}: {"owner":"Jane","warranty_end":"2027-06-30","custom":{"Room":"12B"},"site":"Dental"|"auto"}
/// A null or "" value clears a field.
async fn api_update_asset(State(st): State<AppState>, Path(id): Path<i64>, Json(body): Json<serde_json::Value>) -> WebResult<Response> {
    let bad = |m: String| Ok((StatusCode::BAD_REQUEST, Json(json!({ "error": m }))).into_response());
    if st.db.get_asset(id)?.is_none() {
        return Ok((StatusCode::NOT_FOUND, Json(json!({"error":"not found"}))).into_response());
    }
    let Some(obj) = body.as_object() else { return bad("expected a JSON object".into()) };
    let mut edits = Vec::new();
    for (k, v) in obj {
        match k.as_str() {
            "custom" | "site" => {}
            col if crate::db::EDITABLE_FIELDS.iter().any(|(c, _)| *c == col) => {
                let raw = v.as_str().map(str::to_string).unwrap_or_else(|| if v.is_null() { String::new() } else { v.to_string() });
                match crate::db::normalize_field(col, &raw) {
                    Ok(val) => edits.push((col.to_string(), val)),
                    Err(e) => return bad(format!("{col}: {e}")),
                }
            }
            other => return bad(format!("'{other}' is not editable")),
        }
    }
    let site = match obj.get("site") {
        None => None,
        Some(v) if v.as_str().is_some_and(|s| s.eq_ignore_ascii_case("auto")) || v.is_null() => Some(None),
        Some(v) => match crate::query::resolve_site(&st.db, v) {
            Ok(id) => Some(id),
            Err(e) => return bad(format!("{e:#}")),
        },
    };
    let changed = st.db.update_asset_fields(id, &edits)?;
    let mut custom_changed = 0;
    if let Some(c) = obj.get("custom").and_then(|c| c.as_object()) {
        for (name, v) in c {
            if let Err(e) = st.db.set_custom_value(id, name, v.as_str()).map(|ch| custom_changed += ch as usize) {
                return bad(format!("{e:#}"));
            }
        }
    }
    if let Some(s) = site {
        st.db.set_asset_site(id, s)?;
    }
    Ok(Json(json!({ "id": id, "fields_changed": changed + custom_changed, "asset": st.db.get_asset(id)? })).into_response())
}

/// POST /api/assets: {"name":"LAPTOP-0142","ip":null,"mac":"..."} → creates a manual asset.
async fn api_create_asset(State(st): State<AppState>, Json(body): Json<serde_json::Value>) -> Response {
    let g = |k: &str| body.get(k).and_then(|v| v.as_str()).map(str::to_string);
    match st.db.create_manual_asset(g("ip").as_deref(), g("mac").as_deref(), g("name").as_deref(), "api") {
        Ok(id) => (StatusCode::CREATED, Json(json!({ "id": id }))).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": format!("{e:#}") }))).into_response(),
    }
}

#[derive(Deserialize)]
struct ImportQuery {
    #[serde(default)]
    create_missing: bool,
    #[serde(default)]
    dry_run: bool,
}

/// POST /api/import?dry_run=true&create_missing=true with a CSV body.
async fn api_import(State(st): State<AppState>, Query(q): Query<ImportQuery>, body: String) -> Response {
    let opts = crate::import::ImportOptions { create_missing: q.create_missing, dry_run: q.dry_run, source: "import".into() };
    match crate::import::import_csv(&st.db, &body, &opts) {
        Ok(r) => Json(r).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": format!("{e:#}") }))).into_response(),
    }
}

async fn api_scans(State(st): State<AppState>) -> WebResult<Json<serde_json::Value>> {
    Ok(Json(json!(st.db.list_scans(200)?)))
}

async fn api_scan(State(st): State<AppState>, Path(id): Path<i64>) -> WebResult<Response> {
    let Some(s) = st.db.get_scan(id)? else { return Ok((StatusCode::NOT_FOUND, Json(json!({"error":"not found"}))).into_response()) };
    Ok(Json(json!({ "scan": s, "progress": st.progress_of(id).as_deref() })).into_response())
}

#[derive(Deserialize)]
struct ApiScanReq {
    targets: String,
}

async fn api_start_scan(State(st): State<AppState>, Json(r): Json<ApiScanReq>) -> Response {
    match launch_scan(&st, &r.targets, "api") {
        Ok(id) => (StatusCode::ACCEPTED, Json(json!({ "id": id }))).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": format!("{e:#}") }))).into_response(),
    }
}

/// Structured query (same engine as the MCP `execute_query` tool, larger page size).
async fn api_query(State(st): State<AppState>, Json(v): Json<serde_json::Value>) -> Response {
    let res = crate::query::parse(v).and_then(|q| crate::query::execute(&st.db, &q, crate::query::API_LIMITS, &crate::query::Scope::all()));
    match res {
        Ok(r) => Json(r).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": format!("{e:#}") }))).into_response(),
    }
}

async fn api_datasets() -> Json<serde_json::Value> {
    Json(crate::query::describe(None))
}

// ---------------------------------------------------------------- scheduler

/// Background loop that launches due scheduled scans.
pub async fn scheduler(state: AppState) {
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(30));
    loop {
        tick.tick().await;
        let Ok(schedules) = state.db.list_schedules() else { continue };
        let now = chrono::Local::now().naive_local();
        for s in schedules.into_iter().filter(|s| s.enabled) {
            let due = match &s.last_run {
                None => true,
                Some(t) => chrono::NaiveDateTime::parse_from_str(t, "%Y-%m-%d %H:%M:%S")
                    .map(|last| now - last >= chrono::Duration::minutes(s.interval_minutes))
                    .unwrap_or(true),
            };
            if !due {
                continue;
            }
            let _ = state.db.touch_schedule(s.id);
            let targets = match s.site_id {
                Some(sid) => match state.db.get_site(sid) {
                    Ok(Some(site)) => crate::sites::scan_targets(&crate::sites::parse_subnets(&site.subnets).unwrap_or_default()),
                    _ => continue,
                },
                None => s.targets.clone(),
            };
            match launch_scan_for_site(&state, &targets, &format!("schedule: {}", s.name), s.site_id) {
                Ok(id) => tracing::info!(schedule = s.id, scan = id, "scheduled scan launched"),
                Err(e) => tracing::warn!(schedule = s.id, "scheduled scan failed to start: {e:#}"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escaping() {
        assert_eq!(esc("<a href='x'>&"), "&lt;a href=&#39;x&#39;&gt;&amp;");
        assert_eq!(csv_field("=cmd()"), "\"'=cmd()\"");
        assert_eq!(csv_field("a\"b"), "\"a\"\"b\"");
    }
}
