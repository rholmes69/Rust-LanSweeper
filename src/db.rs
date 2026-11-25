//! SQLite persistence layer: assets, open ports, scans, change history and scan schedules.

use std::collections::{BTreeSet, HashSet};
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};

use anyhow::Result;
use rusqlite::{params, Connection, OptionalExtension, Row};
use serde::Serialize;

use crate::scanner::HostResult;

const SCHEMA: &str = r#"
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS assets (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ip              TEXT NOT NULL,
    ip_num          INTEGER NOT NULL DEFAULT 0,
    mac             TEXT,
    vendor          TEXT,
    hostname        TEXT,
    netbios_name    TEXT,
    netbios_domain  TEXT,
    os_guess        TEXT,
    device_type     TEXT,
    snmp_descr      TEXT,
    snmp_name       TEXT,
    snmp_location   TEXT,
    snmp_contact    TEXT,
    http_title      TEXT,
    http_server     TEXT,
    ssh_banner      TEXT,
    ttl             INTEGER,
    status          TEXT NOT NULL DEFAULT 'online',
    notes           TEXT NOT NULL DEFAULT '',
    first_seen      TEXT NOT NULL,
    last_seen       TEXT NOT NULL,
    last_scan_id    INTEGER
);
CREATE INDEX IF NOT EXISTS idx_assets_ip  ON assets(ip);
CREATE INDEX IF NOT EXISTS idx_assets_mac ON assets(mac);

CREATE TABLE IF NOT EXISTS ports (
    asset_id   INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    port       INTEGER NOT NULL,
    proto      TEXT NOT NULL DEFAULT 'tcp',
    service    TEXT,
    banner     TEXT,
    last_seen  TEXT NOT NULL,
    PRIMARY KEY (asset_id, port, proto)
);

CREATE TABLE IF NOT EXISTS scans (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    targets        TEXT NOT NULL,
    trigger        TEXT NOT NULL DEFAULT 'manual',
    started_at     TEXT NOT NULL,
    finished_at    TEXT,
    status         TEXT NOT NULL DEFAULT 'running',
    hosts_scanned  INTEGER NOT NULL DEFAULT 0,
    hosts_up       INTEGER NOT NULL DEFAULT 0,
    new_assets     INTEGER NOT NULL DEFAULT 0,
    error          TEXT
);

CREATE TABLE IF NOT EXISTS changes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id   INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    scan_id    INTEGER,
    at         TEXT NOT NULL,
    field      TEXT NOT NULL,
    old_value  TEXT,
    new_value  TEXT
);
CREATE INDEX IF NOT EXISTS idx_changes_asset ON changes(asset_id);

CREATE TABLE IF NOT EXISTS api_tokens (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL UNIQUE,
    token_hash  TEXT NOT NULL UNIQUE,
    prefix      TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    last_used   TEXT,
    revoked     INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS mcp_audit (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    at           TEXT NOT NULL,
    transport    TEXT NOT NULL,
    client       TEXT,
    remote_addr  TEXT,
    method       TEXT NOT NULL,
    tool         TEXT,
    arguments    TEXT,
    ok           INTEGER NOT NULL,
    error        TEXT,
    rows         INTEGER,
    duration_ms  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_mcp_audit_at ON mcp_audit(at);

CREATE TABLE IF NOT EXISTS sites (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    name         TEXT NOT NULL UNIQUE COLLATE NOCASE,
    description  TEXT NOT NULL DEFAULT '',
    subnets      TEXT NOT NULL,
    created_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS schedules (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    name              TEXT NOT NULL,
    targets           TEXT NOT NULL,
    interval_minutes  INTEGER NOT NULL,
    enabled           INTEGER NOT NULL DEFAULT 1,
    last_run          TEXT,
    created_at        TEXT NOT NULL
);
"#;

pub fn now() -> String {
    chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string()
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct Asset {
    pub id: i64,
    pub ip: String,
    pub mac: Option<String>,
    pub vendor: Option<String>,
    pub hostname: Option<String>,
    pub netbios_name: Option<String>,
    pub netbios_domain: Option<String>,
    pub os_guess: Option<String>,
    pub device_type: Option<String>,
    pub snmp_descr: Option<String>,
    pub snmp_name: Option<String>,
    pub snmp_location: Option<String>,
    pub snmp_contact: Option<String>,
    pub http_title: Option<String>,
    pub http_server: Option<String>,
    pub ssh_banner: Option<String>,
    pub ttl: Option<i64>,
    pub status: String,
    pub notes: String,
    pub first_seen: String,
    pub last_seen: String,
    pub open_ports: i64,
    pub site_id: Option<i64>,
    pub site: Option<String>,
    /// True when IT pinned the asset to its site by hand (auto-assignment won't move it).
    pub site_manual: bool,
}

impl Asset {
    /// Best human-friendly name for the asset.
    pub fn display_name(&self) -> String {
        self.netbios_name
            .clone()
            .or_else(|| self.hostname.clone())
            .or_else(|| self.snmp_name.clone())
            .unwrap_or_else(|| self.ip.clone())
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Port {
    pub port: i64,
    pub proto: String,
    pub service: Option<String>,
    pub banner: Option<String>,
    pub last_seen: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Scan {
    pub id: i64,
    pub targets: String,
    pub trigger: String,
    pub started_at: String,
    pub finished_at: Option<String>,
    pub status: String,
    pub hosts_scanned: i64,
    pub hosts_up: i64,
    pub new_assets: i64,
    pub error: Option<String>,
    pub site_id: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Change {
    pub id: i64,
    pub asset_id: i64,
    pub asset_name: String,
    pub scan_id: Option<i64>,
    pub at: String,
    pub field: String,
    pub old_value: Option<String>,
    pub new_value: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Schedule {
    pub id: i64,
    pub name: String,
    pub targets: String,
    pub interval_minutes: i64,
    pub enabled: bool,
    pub last_run: Option<String>,
    pub created_at: String,
    /// When set, the schedule scans this site's current subnets (targets is informational).
    pub site_id: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct Stats {
    pub total: i64,
    pub online: i64,
    pub offline: i64,
    pub new_7d: i64,
    pub by_type: Vec<(String, i64)>,
    pub by_vendor: Vec<(String, i64)>,
    pub by_site: Vec<(String, i64)>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ApiToken {
    pub id: i64,
    pub name: String,
    /// First characters of the token, for identification only.
    pub prefix: String,
    pub created_at: String,
    pub last_used: Option<String>,
    pub revoked: bool,
    /// None = all sites; Some(ids) = only these sites.
    pub sites: Option<Vec<i64>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditEntry {
    pub id: i64,
    pub at: String,
    pub transport: String,
    pub client: Option<String>,
    pub remote_addr: Option<String>,
    pub method: String,
    pub tool: Option<String>,
    pub arguments: Option<String>,
    pub ok: bool,
    pub error: Option<String>,
    pub rows: Option<i64>,
    pub duration_ms: i64,
}

#[derive(Debug, Clone, Default)]
pub struct NewAudit<'a> {
    pub transport: &'a str,
    pub client: Option<&'a str>,
    pub remote_addr: Option<&'a str>,
    pub method: &'a str,
    pub tool: Option<&'a str>,
    pub arguments: Option<String>,
    pub ok: bool,
    pub error: Option<String>,
    pub rows: Option<i64>,
    pub duration_ms: i64,
}

#[derive(Debug, Default, Clone)]
pub struct AssetFilter {
    pub q: Option<String>,
    pub device_type: Option<String>,
    pub status: Option<String>,
    pub sort: Option<String>,
    pub desc: bool,
    pub scan_id: Option<i64>,
    /// Some(0) = unassigned assets only.
    pub site_id: Option<i64>,
    /// Restrict to these sites (site-scoped API tokens). Empty = nothing.
    pub allowed_sites: Option<Vec<i64>>,
}

#[derive(Clone)]
pub struct Db {
    conn: Arc<Mutex<Connection>>,
}

const ASSET_COLS: &str = "a.id, a.ip, a.mac, a.vendor, a.hostname, a.netbios_name, a.netbios_domain, \
    a.os_guess, a.device_type, a.snmp_descr, a.snmp_name, a.snmp_location, a.snmp_contact, \
    a.http_title, a.http_server, a.ssh_banner, a.ttl, a.status, a.notes, a.first_seen, a.last_seen, \
    (SELECT COUNT(*) FROM ports p WHERE p.asset_id = a.id) AS open_ports, \
    a.site_id, (SELECT st.name FROM sites st WHERE st.id = a.site_id), a.site_manual";

fn asset_from_row(r: &Row) -> rusqlite::Result<Asset> {
    Ok(Asset {
        id: r.get(0)?,
        ip: r.get(1)?,
        mac: r.get(2)?,
        vendor: r.get(3)?,
        hostname: r.get(4)?,
        netbios_name: r.get(5)?,
        netbios_domain: r.get(6)?,
        os_guess: r.get(7)?,
        device_type: r.get(8)?,
        snmp_descr: r.get(9)?,
        snmp_name: r.get(10)?,
        snmp_location: r.get(11)?,
        snmp_contact: r.get(12)?,
        http_title: r.get(13)?,
        http_server: r.get(14)?,
        ssh_banner: r.get(15)?,
        ttl: r.get(16)?,
        status: r.get(17)?,
        notes: r.get(18)?,
        first_seen: r.get(19)?,
        last_seen: r.get(20)?,
        open_ports: r.get(21)?,
        site_id: r.get(22)?,
        site: r.get(23)?,
        site_manual: r.get::<_, i64>(24)? != 0,
    })
}

fn scan_from_row(r: &Row) -> rusqlite::Result<Scan> {
    Ok(Scan {
        id: r.get(0)?,
        targets: r.get(1)?,
        trigger: r.get(2)?,
        started_at: r.get(3)?,
        finished_at: r.get(4)?,
        status: r.get(5)?,
        hosts_scanned: r.get(6)?,
        hosts_up: r.get(7)?,
        new_assets: r.get(8)?,
        error: r.get(9)?,
        site_id: r.get(10)?,
    })
}

const SCAN_COLS: &str =
    "id, targets, trigger, started_at, finished_at, status, hosts_scanned, hosts_up, new_assets, error, site_id";

/// Columns added after v0.1. `CREATE TABLE IF NOT EXISTS` doesn't alter existing tables,
/// so older databases get them added here.
const MIGRATIONS: &[(&str, &str, &str)] = &[
    ("assets", "site_id", "INTEGER REFERENCES sites(id) ON DELETE SET NULL"),
    ("assets", "site_manual", "INTEGER NOT NULL DEFAULT 0"),
    ("scans", "site_id", "INTEGER"),
    ("schedules", "site_id", "INTEGER REFERENCES sites(id) ON DELETE CASCADE"),
    ("api_tokens", "sites", "TEXT"),
];

fn migrate(conn: &Connection) -> Result<()> {
    for (table, col, decl) in MIGRATIONS {
        let exists: bool = conn
            .prepare(&format!("SELECT 1 FROM pragma_table_info('{table}') WHERE name=?1"))?
            .exists([col])?;
        if !exists {
            conn.execute_batch(&format!("ALTER TABLE {table} ADD COLUMN {col} {decl}"))?;
        }
    }
    conn.execute_batch("CREATE INDEX IF NOT EXISTS idx_assets_site ON assets(site_id);")?;
    Ok(())
}

fn ids_to_text(ids: &[i64]) -> String {
    ids.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(",")
}

fn text_to_ids(s: Option<String>) -> Option<Vec<i64>> {
    s.map(|s| s.split(',').filter_map(|x| x.trim().parse().ok()).collect())
}

impl Db {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch(SCHEMA)?;
        migrate(&conn)?;
        // Any scan left "running" from a previous process was interrupted.
        conn.execute(
            "UPDATE scans SET status='interrupted', finished_at=?1 WHERE status='running'",
            params![now()],
        )?;
        Ok(Self { conn: Arc::new(Mutex::new(conn)) })
    }

    fn lock(&self) -> MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Run a closure with the raw connection (used by the structured query engine).
    pub fn with_conn<T>(&self, f: impl FnOnce(&Connection) -> Result<T>) -> Result<T> {
        f(&self.lock())
    }

    // ---------------------------------------------------------------- assets

    pub fn list_assets(&self, f: &AssetFilter) -> Result<Vec<Asset>> {
        let mut sql = format!("SELECT {ASSET_COLS} FROM assets a WHERE 1=1");
        let mut args: Vec<String> = Vec::new();
        if let Some(q) = f.q.as_ref().filter(|s| !s.trim().is_empty()) {
            let like = format!("%{}%", q.trim());
            let n = args.len();
            sql.push_str(&format!(
                " AND (a.ip LIKE ?{0} OR a.mac LIKE ?{0} OR a.hostname LIKE ?{0} OR a.netbios_name LIKE ?{0} \
                 OR a.vendor LIKE ?{0} OR a.os_guess LIKE ?{0} OR a.device_type LIKE ?{0} OR a.snmp_descr LIKE ?{0} \
                 OR a.notes LIKE ?{0} OR a.http_title LIKE ?{0} \
                 OR EXISTS (SELECT 1 FROM ports p WHERE p.asset_id=a.id AND (CAST(p.port AS TEXT)=?{1} OR p.service LIKE ?{0})))",
                n + 1,
                n + 2
            ));
            args.push(like);
            args.push(q.trim().to_string());
        }
        if let Some(t) = f.device_type.as_ref().filter(|s| !s.is_empty()) {
            args.push(t.clone());
            sql.push_str(&format!(" AND a.device_type = ?{}", args.len()));
        }
        if let Some(s) = f.status.as_ref().filter(|s| !s.is_empty()) {
            args.push(s.clone());
            sql.push_str(&format!(" AND a.status = ?{}", args.len()));
        }
        if let Some(sid) = f.scan_id {
            args.push(sid.to_string());
            sql.push_str(&format!(" AND a.last_scan_id = CAST(?{} AS INTEGER)", args.len()));
        }
        match f.site_id {
            Some(0) => sql.push_str(" AND a.site_id IS NULL"),
            Some(id) => sql.push_str(&format!(" AND a.site_id = {id}")),
            None => {}
        }
        if let Some(allowed) = &f.allowed_sites {
            sql.push_str(&format!(" AND a.site_id IN ({})", if allowed.is_empty() { "NULL".into() } else { ids_to_text(allowed) }));
        }
        // Whitelisted sort columns only (never interpolate user input directly).
        let order = match f.sort.as_deref() {
            Some("name") => "COALESCE(a.netbios_name, a.hostname, a.ip) COLLATE NOCASE",
            Some("mac") => "a.mac",
            Some("vendor") => "a.vendor COLLATE NOCASE",
            Some("type") => "a.device_type",
            Some("os") => "a.os_guess",
            Some("ports") => "open_ports",
            Some("last_seen") => "a.last_seen",
            Some("status") => "a.status",
            Some("site") => "(SELECT st.name FROM sites st WHERE st.id = a.site_id) COLLATE NOCASE",
            _ => "a.ip_num",
        };
        let dir = if f.desc { "DESC" } else { "ASC" };
        sql.push_str(&format!(" ORDER BY {order} {dir}, a.ip_num"));
        let conn = self.lock();
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(args.iter()), asset_from_row)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn get_asset(&self, id: i64) -> Result<Option<Asset>> {
        let conn = self.lock();
        Ok(conn
            .query_row(&format!("SELECT {ASSET_COLS} FROM assets a WHERE a.id=?1"), [id], asset_from_row)
            .optional()?)
    }

    pub fn asset_ports(&self, id: i64) -> Result<Vec<Port>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT port, proto, service, banner, last_seen FROM ports WHERE asset_id=?1 ORDER BY port",
        )?;
        let rows = stmt.query_map([id], |r| {
            Ok(Port {
                port: r.get(0)?,
                proto: r.get(1)?,
                service: r.get(2)?,
                banner: r.get(3)?,
                last_seen: r.get(4)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn set_notes(&self, id: i64, notes: &str) -> Result<()> {
        self.lock().execute("UPDATE assets SET notes=?1 WHERE id=?2", params![notes, id])?;
        Ok(())
    }

    pub fn delete_asset(&self, id: i64) -> Result<()> {
        self.lock().execute("DELETE FROM assets WHERE id=?1", [id])?;
        Ok(())
    }

    pub fn device_types(&self) -> Result<Vec<String>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT DISTINCT device_type FROM assets WHERE device_type IS NOT NULL ORDER BY device_type",
        )?;
        let rows = stmt.query_map([], |r| r.get(0))?;
        Ok(rows.collect::<rusqlite::Result<Vec<String>>>()?)
    }

    pub fn stats(&self) -> Result<Stats> {
        let conn = self.lock();
        let count = |sql: &str| -> rusqlite::Result<i64> { conn.query_row(sql, [], |r| r.get(0)) };
        let mut s = Stats {
            total: count("SELECT COUNT(*) FROM assets")?,
            online: count("SELECT COUNT(*) FROM assets WHERE status='online'")?,
            offline: count("SELECT COUNT(*) FROM assets WHERE status='offline'")?,
            ..Default::default()
        };
        let week_ago = (chrono::Local::now() - chrono::Duration::days(7))
            .format("%Y-%m-%d %H:%M:%S")
            .to_string();
        s.new_7d = conn.query_row(
            "SELECT COUNT(*) FROM assets WHERE first_seen >= ?1",
            [week_ago],
            |r| r.get(0),
        )?;
        let group = |sql: &str| -> rusqlite::Result<Vec<(String, i64)>> {
            let mut st = conn.prepare(sql)?;
            let rows = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
            rows.collect()
        };
        s.by_type = group(
            "SELECT COALESCE(device_type,'Unknown'), COUNT(*) c FROM assets GROUP BY 1 ORDER BY c DESC",
        )?;
        s.by_site = group(
            "SELECT COALESCE((SELECT st.name FROM sites st WHERE st.id = a.site_id),'Unassigned'), COUNT(*) c FROM assets a GROUP BY 1 ORDER BY c DESC",
        )?;
        s.by_vendor = group(
            "SELECT COALESCE(vendor,'Unknown'), COUNT(*) c FROM assets GROUP BY 1 ORDER BY c DESC LIMIT 10",
        )?;
        Ok(s)
    }

    /// Insert or update an asset from a scan result. Returns (asset_id, was_new).
    pub fn record_host(&self, scan_id: i64, h: &HostResult) -> Result<(i64, bool)> {
        let mut conn = self.lock();
        let tx = conn.transaction()?;
        let ts = now();
        let ip = h.ip.to_string();

        // Identify the asset: MAC is the strongest identity, then IP.
        let mut existing: Option<i64>;
        if let Some(mac) = &h.mac {
            existing = tx
                .query_row("SELECT id FROM assets WHERE mac=?1 ORDER BY last_seen DESC LIMIT 1", [mac], |r| r.get(0))
                .optional()?;
            if existing.is_none() {
                existing = tx
                    .query_row(
                        "SELECT id FROM assets WHERE ip=?1 AND mac IS NULL ORDER BY last_seen DESC LIMIT 1",
                        [&ip],
                        |r| r.get(0),
                    )
                    .optional()?;
            }
        } else {
            existing = tx
                .query_row("SELECT id FROM assets WHERE ip=?1 ORDER BY last_seen DESC LIMIT 1", [&ip], |r| r.get(0))
                .optional()?;
        }

        let fields: [(&str, Option<String>); 16] = [
            ("ip", Some(ip.clone())),
            ("mac", h.mac.clone()),
            ("vendor", h.vendor.clone()),
            ("hostname", h.hostname.clone()),
            ("netbios_name", h.netbios_name.clone()),
            ("netbios_domain", h.netbios_domain.clone()),
            ("os_guess", h.os_guess.clone()),
            ("device_type", h.device_type.clone()),
            ("snmp_descr", h.snmp.as_ref().and_then(|s| s.descr.clone())),
            ("snmp_name", h.snmp.as_ref().and_then(|s| s.name.clone())),
            ("snmp_location", h.snmp.as_ref().and_then(|s| s.location.clone())),
            ("snmp_contact", h.snmp.as_ref().and_then(|s| s.contact.clone())),
            ("http_title", h.http_title.clone()),
            ("http_server", h.http_server.clone()),
            ("ssh_banner", h.ssh_banner.clone()),
            ("status", Some("online".to_string())),
        ];
        // Fields whose changes are worth recording in history.
        const TRACKED: &[&str] =
            &["ip", "mac", "hostname", "netbios_name", "os_guess", "device_type", "snmp_descr", "status"];

        let (asset_id, is_new) = match existing {
            None => {
                tx.execute(
                    "INSERT INTO assets (ip, first_seen, last_seen, last_scan_id) VALUES (?1, ?2, ?2, ?3)",
                    params![ip, ts, scan_id],
                )?;
                let id = tx.last_insert_rowid();
                for (col, val) in &fields {
                    if val.is_some() {
                        tx.execute(&format!("UPDATE assets SET {col}=?1 WHERE id=?2"), params![val, id])?;
                    }
                }
                tx.execute(
                    "INSERT INTO changes (asset_id, scan_id, at, field, old_value, new_value) VALUES (?1,?2,?3,'discovered',NULL,?4)",
                    params![id, scan_id, ts, ip],
                )?;
                (id, true)
            }
            Some(id) => {
                for (col, val) in &fields {
                    let Some(new) = val else { continue }; // never erase data we failed to re-collect
                    let old: Option<String> =
                        tx.query_row(&format!("SELECT {col} FROM assets WHERE id=?1"), [id], |r| r.get(0))?;
                    if old.as_deref() != Some(new.as_str()) {
                        tx.execute(&format!("UPDATE assets SET {col}=?1 WHERE id=?2"), params![new, id])?;
                        if TRACKED.contains(col) {
                            tx.execute(
                                "INSERT INTO changes (asset_id, scan_id, at, field, old_value, new_value) VALUES (?1,?2,?3,?4,?5,?6)",
                                params![id, scan_id, ts, col, old, new],
                            )?;
                        }
                    }
                }
                tx.execute(
                    "UPDATE assets SET last_seen=?1, last_scan_id=?2 WHERE id=?3",
                    params![ts, scan_id, id],
                )?;
                (id, false)
            }
        };
        let ip_num: i64 = match h.ip {
            std::net::IpAddr::V4(v4) => u32::from(v4) as i64,
            std::net::IpAddr::V6(_) => 0,
        };
        tx.execute("UPDATE assets SET ip_num=?1 WHERE id=?2", params![ip_num, asset_id])?;
        if let Some(ttl) = h.ttl {
            tx.execute("UPDATE assets SET ttl=?1 WHERE id=?2", params![ttl as i64, asset_id])?;
        }

        // Port diff.
        let old_ports: BTreeSet<u16> = {
            let mut st = tx.prepare("SELECT port FROM ports WHERE asset_id=?1 AND proto='tcp'")?;
            let rows = st.query_map([asset_id], |r| r.get::<_, i64>(0))?;
            rows.filter_map(|r| r.ok()).map(|p| p as u16).collect()
        };
        let new_ports: BTreeSet<u16> = h.ports.iter().map(|p| p.port).collect();
        if !is_new {
            for p in new_ports.difference(&old_ports) {
                tx.execute(
                    "INSERT INTO changes (asset_id, scan_id, at, field, old_value, new_value) VALUES (?1,?2,?3,'port opened',NULL,?4)",
                    params![asset_id, scan_id, ts, p.to_string()],
                )?;
            }
            for p in old_ports.difference(&new_ports) {
                tx.execute(
                    "INSERT INTO changes (asset_id, scan_id, at, field, old_value, new_value) VALUES (?1,?2,?3,'port closed',?4,NULL)",
                    params![asset_id, scan_id, ts, p.to_string()],
                )?;
            }
        }
        tx.execute("DELETE FROM ports WHERE asset_id=?1 AND proto='tcp'", [asset_id])?;
        for p in &h.ports {
            tx.execute(
                "INSERT INTO ports (asset_id, port, proto, service, banner, last_seen) VALUES (?1,?2,'tcp',?3,?4,?5)",
                params![asset_id, p.port as i64, p.service, p.banner, ts],
            )?;
        }
        tx.commit()?;
        Ok((asset_id, is_new))
    }

    /// Mark assets whose IP was scanned but not found (and not matched this scan) as offline.
    pub fn mark_offline(&self, scan_id: i64, scanned_ips: &HashSet<String>, seen_ids: &HashSet<i64>) -> Result<usize> {
        let mut conn = self.lock();
        let tx = conn.transaction()?;
        let ts = now();
        let candidates: Vec<(i64, String)> = {
            let mut st = tx.prepare("SELECT id, ip FROM assets WHERE status='online'")?;
            let rows = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
            rows.filter_map(|r| r.ok()).collect()
        };
        let mut n = 0;
        for (id, ip) in candidates {
            if scanned_ips.contains(&ip) && !seen_ids.contains(&id) {
                tx.execute("UPDATE assets SET status='offline' WHERE id=?1", [id])?;
                tx.execute(
                    "INSERT INTO changes (asset_id, scan_id, at, field, old_value, new_value) VALUES (?1,?2,?3,'status','online','offline')",
                    params![id, scan_id, ts],
                )?;
                n += 1;
            }
        }
        tx.commit()?;
        Ok(n)
    }

    // ---------------------------------------------------------------- changes

    pub fn changes(&self, asset_id: Option<i64>, limit: i64) -> Result<Vec<Change>> {
        let conn = self.lock();
        let sql = "SELECT c.id, c.asset_id, COALESCE(a.netbios_name, a.hostname, a.ip), c.scan_id, c.at, c.field, c.old_value, c.new_value \
                   FROM changes c JOIN assets a ON a.id=c.asset_id \
                   WHERE (?1 IS NULL OR c.asset_id=?1) ORDER BY c.id DESC LIMIT ?2";
        let mut st = conn.prepare(sql)?;
        let rows = st.query_map(params![asset_id, limit], |r| {
            Ok(Change {
                id: r.get(0)?,
                asset_id: r.get(1)?,
                asset_name: r.get(2)?,
                scan_id: r.get(3)?,
                at: r.get(4)?,
                field: r.get(5)?,
                old_value: r.get(6)?,
                new_value: r.get(7)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    // ---------------------------------------------------------------- scans

    pub fn create_scan_for_site(&self, targets: &str, trigger: &str, site_id: Option<i64>) -> Result<i64> {
        let conn = self.lock();
        conn.execute(
            "INSERT INTO scans (targets, trigger, started_at, site_id) VALUES (?1, ?2, ?3, ?4)",
            params![targets, trigger, now(), site_id],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn finish_scan(
        &self,
        id: i64,
        status: &str,
        hosts_scanned: usize,
        hosts_up: usize,
        new_assets: usize,
        error: Option<&str>,
    ) -> Result<()> {
        self.lock().execute(
            "UPDATE scans SET status=?1, finished_at=?2, hosts_scanned=?3, hosts_up=?4, new_assets=?5, error=?6 WHERE id=?7",
            params![status, now(), hosts_scanned as i64, hosts_up as i64, new_assets as i64, error, id],
        )?;
        Ok(())
    }

    pub fn list_scans(&self, limit: i64) -> Result<Vec<Scan>> {
        let conn = self.lock();
        let mut st = conn.prepare(&format!("SELECT {SCAN_COLS} FROM scans ORDER BY id DESC LIMIT ?1"))?;
        let rows = st.query_map([limit], scan_from_row)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn get_scan(&self, id: i64) -> Result<Option<Scan>> {
        let conn = self.lock();
        Ok(conn
            .query_row(&format!("SELECT {SCAN_COLS} FROM scans WHERE id=?1"), [id], scan_from_row)
            .optional()?)
    }

    // ---------------------------------------------------------------- schedules

    pub fn list_schedules(&self) -> Result<Vec<Schedule>> {
        let conn = self.lock();
        let mut st = conn.prepare(
            "SELECT id, name, targets, interval_minutes, enabled, last_run, created_at, site_id FROM schedules ORDER BY id",
        )?;
        let rows = st.query_map([], |r| {
            Ok(Schedule {
                id: r.get(0)?,
                name: r.get(1)?,
                targets: r.get(2)?,
                interval_minutes: r.get(3)?,
                enabled: r.get::<_, i64>(4)? != 0,
                last_run: r.get(5)?,
                created_at: r.get(6)?,
                site_id: r.get(7)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn add_schedule(&self, name: &str, targets: &str, interval_minutes: i64) -> Result<i64> {
        self.add_schedule_for_site(name, targets, interval_minutes, None)
    }

    pub fn add_schedule_for_site(&self, name: &str, targets: &str, interval_minutes: i64, site_id: Option<i64>) -> Result<i64> {
        let conn = self.lock();
        conn.execute(
            "INSERT INTO schedules (name, targets, interval_minutes, created_at, site_id) VALUES (?1,?2,?3,?4,?5)",
            params![name, targets, interval_minutes, now(), site_id],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn delete_schedule(&self, id: i64) -> Result<()> {
        self.lock().execute("DELETE FROM schedules WHERE id=?1", [id])?;
        Ok(())
    }

    pub fn toggle_schedule(&self, id: i64) -> Result<()> {
        self.lock()
            .execute("UPDATE schedules SET enabled = 1 - enabled WHERE id=?1", [id])?;
        Ok(())
    }

    pub fn touch_schedule(&self, id: i64) -> Result<()> {
        self.lock()
            .execute("UPDATE schedules SET last_run=?1 WHERE id=?2", params![now(), id])?;
        Ok(())
    }

    // ---------------------------------------------------------------- API tokens

    pub fn create_token(&self, name: &str, token_hash: &str, prefix: &str, sites: Option<&[i64]>) -> Result<i64> {
        let conn = self.lock();
        conn.execute(
            "INSERT INTO api_tokens (name, token_hash, prefix, created_at, sites) VALUES (?1,?2,?3,?4,?5)",
            params![name, token_hash, prefix, now(), sites.map(ids_to_text)],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn list_tokens(&self) -> Result<Vec<ApiToken>> {
        let conn = self.lock();
        let mut st = conn.prepare("SELECT id, name, prefix, created_at, last_used, revoked, sites FROM api_tokens ORDER BY id")?;
        let rows = st.query_map([], |r| {
            Ok(ApiToken {
                id: r.get(0)?,
                name: r.get(1)?,
                prefix: r.get(2)?,
                created_at: r.get(3)?,
                last_used: r.get(4)?,
                revoked: r.get::<_, i64>(5)? != 0,
                sites: text_to_ids(r.get(6)?),
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Look up an active token by hash; records last use. Returns (id, name, site scope).
    pub fn token_by_hash(&self, token_hash: &str) -> Result<Option<(i64, String, Option<Vec<i64>>)>> {
        let conn = self.lock();
        let found: Option<(i64, String, Option<Vec<i64>>)> = conn
            .query_row(
                "SELECT id, name, sites FROM api_tokens WHERE token_hash=?1 AND revoked=0",
                [token_hash],
                |r| Ok((r.get(0)?, r.get(1)?, text_to_ids(r.get(2)?))),
            )
            .optional()?;
        if let Some((id, _, _)) = &found {
            conn.execute("UPDATE api_tokens SET last_used=?1 WHERE id=?2", params![now(), id])?;
        }
        Ok(found)
    }

    pub fn active_token_count(&self) -> Result<i64> {
        Ok(self.lock().query_row("SELECT COUNT(*) FROM api_tokens WHERE revoked=0", [], |r| r.get(0))?)
    }

    /// Revoke by id or name. Returns true if a token was revoked.
    pub fn revoke_token(&self, id_or_name: &str) -> Result<bool> {
        let n = self.lock().execute(
            "UPDATE api_tokens SET revoked=1 WHERE revoked=0 AND (CAST(id AS TEXT)=?1 OR name=?1)",
            [id_or_name],
        )?;
        Ok(n > 0)
    }

    // ---------------------------------------------------------------- MCP audit log

    pub fn add_audit(&self, a: &NewAudit) -> Result<()> {
        self.lock().execute(
            "INSERT INTO mcp_audit (at, transport, client, remote_addr, method, tool, arguments, ok, error, rows, duration_ms) \
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
            params![now(), a.transport, a.client, a.remote_addr, a.method, a.tool, a.arguments, a.ok as i64, a.error, a.rows, a.duration_ms],
        )?;
        Ok(())
    }

    pub fn list_audit(&self, limit: i64) -> Result<Vec<AuditEntry>> {
        let conn = self.lock();
        let mut st = conn.prepare(
            "SELECT id, at, transport, client, remote_addr, method, tool, arguments, ok, error, rows, duration_ms \
             FROM mcp_audit ORDER BY id DESC LIMIT ?1",
        )?;
        let rows = st.query_map([limit], |r| {
            Ok(AuditEntry {
                id: r.get(0)?,
                at: r.get(1)?,
                transport: r.get(2)?,
                client: r.get(3)?,
                remote_addr: r.get(4)?,
                method: r.get(5)?,
                tool: r.get(6)?,
                arguments: r.get(7)?,
                ok: r.get::<_, i64>(8)? != 0,
                error: r.get(9)?,
                rows: r.get(10)?,
                duration_ms: r.get(11)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    // ---------------------------------------------------------------- sites

    pub fn list_sites(&self) -> Result<Vec<Site>> {
        let conn = self.lock();
        let mut st = conn.prepare(
            "SELECT s.id, s.name, s.description, s.subnets, s.created_at, \
               (SELECT COUNT(*) FROM assets a WHERE a.site_id = s.id), \
               (SELECT COUNT(*) FROM assets a WHERE a.site_id = s.id AND a.status = 'online') \
             FROM sites s ORDER BY s.name COLLATE NOCASE",
        )?;
        let rows = st.query_map([], |r| {
            Ok(Site {
                id: r.get(0)?,
                name: r.get(1)?,
                description: r.get(2)?,
                subnets: r.get(3)?,
                created_at: r.get(4)?,
                asset_count: r.get(5)?,
                online: r.get(6)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn get_site(&self, id: i64) -> Result<Option<Site>> {
        Ok(self.list_sites()?.into_iter().find(|s| s.id == id))
    }

    /// Find a site by numeric id or (case-insensitive) name.
    pub fn find_site(&self, id_or_name: &str) -> Result<Option<Site>> {
        let key = id_or_name.trim();
        Ok(self
            .list_sites()?
            .into_iter()
            .find(|s| s.id.to_string() == key || s.name.eq_ignore_ascii_case(key)))
    }

    pub fn unassigned_count(&self) -> Result<i64> {
        Ok(self.lock().query_row("SELECT COUNT(*) FROM assets WHERE site_id IS NULL", [], |r| r.get(0))?)
    }

    /// Create a site; subnets must already be validated/normalised. Re-assigns assets.
    pub fn add_site(&self, name: &str, subnets: &str, description: &str) -> Result<i64> {
        let id = {
            let conn = self.lock();
            conn.execute(
                "INSERT INTO sites (name, subnets, description, created_at) VALUES (?1,?2,?3,?4)",
                params![name.trim(), subnets, description.trim(), now()],
            )
            .map_err(|e| if e.to_string().contains("UNIQUE") { anyhow::anyhow!("a site named '{}' already exists", name.trim()) } else { e.into() })?;
            conn.last_insert_rowid()
        };
        self.reassign_sites()?;
        Ok(id)
    }

    pub fn update_site(&self, id: i64, name: &str, subnets: &str, description: &str) -> Result<()> {
        self.lock()
            .execute(
                "UPDATE sites SET name=?1, subnets=?2, description=?3 WHERE id=?4",
                params![name.trim(), subnets, description.trim(), id],
            )
            .map_err(|e| if e.to_string().contains("UNIQUE") { anyhow::anyhow!("a site named '{}' already exists", name.trim()) } else { anyhow::Error::from(e) })?;
        self.reassign_sites()?;
        Ok(())
    }

    pub fn delete_site(&self, id: i64) -> Result<()> {
        {
            let conn = self.lock();
            conn.execute("UPDATE assets SET site_id = NULL, site_manual = 0 WHERE site_id = ?1", [id])?;
            conn.execute("DELETE FROM sites WHERE id = ?1", [id])?;
        }
        self.reassign_sites()?;
        Ok(())
    }

    /// Recompute automatic site membership for every asset not pinned by hand.
    /// Returns how many assets changed site.
    pub fn reassign_sites(&self) -> Result<usize> {
        let sites: Vec<(i64, Vec<ipnet::Ipv4Net>)> = self
            .list_sites()?
            .into_iter()
            .filter_map(|s| crate::sites::parse_subnets(&s.subnets).ok().map(|n| (s.id, n)))
            .collect();
        let mut conn = self.lock();
        let tx = conn.transaction()?;
        let assets: Vec<(i64, String, Option<i64>)> = {
            let mut st = tx.prepare("SELECT id, ip, site_id FROM assets WHERE site_manual = 0")?;
            let rows = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
            rows.filter_map(|r| r.ok()).collect()
        };
        let mut changed = 0;
        for (id, ip, cur) in assets {
            let want = crate::sites::site_for_ip(&sites, &ip);
            if want != cur {
                tx.execute("UPDATE assets SET site_id=?1 WHERE id=?2", params![want, id])?;
                changed += 1;
            }
        }
        tx.commit()?;
        Ok(changed)
    }

    /// Pin an asset to a site (Some) or return it to automatic assignment (None).
    pub fn set_asset_site(&self, asset_id: i64, site_id: Option<i64>) -> Result<()> {
        match site_id {
            Some(sid) => {
                self.lock().execute("UPDATE assets SET site_id=?1, site_manual=1 WHERE id=?2", params![sid, asset_id])?;
            }
            None => {
                self.lock().execute("UPDATE assets SET site_manual=0 WHERE id=?1", [asset_id])?;
                self.reassign_sites()?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Site {
    pub id: i64,
    pub name: String,
    pub description: String,
    /// Normalised, comma-separated CIDRs.
    pub subnets: String,
    pub created_at: String,
    pub asset_count: i64,
    pub online: i64,
}
