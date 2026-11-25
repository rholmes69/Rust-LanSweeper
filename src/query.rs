//! Structured, injection-safe query engine over the inventory.
//!
//! Callers (MCP tools, REST API) never send SQL. They name a dataset, pick whitelisted fields,
//! and add filters; this module turns that into parameterised SQL.

use anyhow::{anyhow, bail, Result};
use rusqlite::types::{Value as SqlValue, ValueRef};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::db::Db;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Text,
    Int,
    /// Timestamp stored as "YYYY-MM-DD HH:MM:SS" (local time). Accepts relative values like "now-7d".
    Time,
    /// Filter-only pseudo field on assets: "asset has this TCP port open".
    HasPort,
}

#[derive(Debug, Clone, Serialize)]
pub struct Field {
    pub name: &'static str,
    #[serde(skip)]
    pub sql: &'static str,
    pub kind: Kind,
    pub description: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct Dataset {
    pub name: &'static str,
    pub description: &'static str,
    #[serde(skip)]
    pub from: &'static str,
    pub default_fields: &'static [&'static str],
    #[serde(skip)]
    pub default_sort: &'static str,
    pub fields: &'static [Field],
}

macro_rules! f {
    ($n:expr, $sql:expr, $k:ident, $d:expr) => {
        Field { name: $n, sql: $sql, kind: Kind::$k, description: $d }
    };
}

const ASSET_NAME: &str = "COALESCE(a.netbios_name, a.hostname, a.snmp_name, a.ip)";

pub static DATASETS: &[Dataset] = &[
    Dataset {
        name: "assets",
        description: "One row per discovered device: identity, network names, vendor, fingerprint, SNMP/web info, status and timestamps.",
        from: "assets a",
        default_fields: &["id", "ip", "name", "mac", "vendor", "device_type", "os_guess", "open_ports", "status", "last_seen"],
        default_sort: "a.ip_num",
        fields: &[
            f!("id", "a.id", Int, "Asset id"),
            f!("ip", "a.ip", Text, "IPv4 address (sorts numerically)"),
            f!("name", "COALESCE(a.netbios_name, a.hostname, a.snmp_name, a.ip)", Text, "Best display name: NetBIOS, then DNS, then SNMP sysName, then IP"),
            f!("mac", "a.mac", Text, "MAC address AA:BB:CC:DD:EE:FF"),
            f!("vendor", "a.vendor", Text, "Hardware vendor from MAC OUI"),
            f!("hostname", "a.hostname", Text, "Reverse-DNS name"),
            f!("netbios_name", "a.netbios_name", Text, "Windows/NetBIOS computer name"),
            f!("domain", "a.netbios_domain", Text, "NetBIOS domain or workgroup"),
            f!("device_type", "a.device_type", Text, "Fingerprinted type, e.g. 'Windows Workstation', 'Printer', 'Network Device'"),
            f!("os_guess", "a.os_guess", Text, "Fingerprinted operating system"),
            f!("ttl", "a.ttl", Int, "ICMP TTL observed (128≈Windows, 64≈Linux, 255≈network gear)"),
            f!("snmp_name", "a.snmp_name", Text, "SNMP sysName"),
            f!("snmp_descr", "a.snmp_descr", Text, "SNMP sysDescr (model / firmware string)"),
            f!("snmp_location", "a.snmp_location", Text, "SNMP sysLocation"),
            f!("snmp_contact", "a.snmp_contact", Text, "SNMP sysContact"),
            f!("http_title", "a.http_title", Text, "Web page <title> on port 80/8000/8080"),
            f!("http_server", "a.http_server", Text, "HTTP Server header"),
            f!("ssh_banner", "a.ssh_banner", Text, "SSH server banner"),
            f!("status", "a.status", Text, "'online' or 'offline' (as of the last scan covering this IP)"),
            f!("notes", "a.notes", Text, "Free-text notes entered by IT"),
            f!("first_seen", "a.first_seen", Time, "When the asset was first discovered"),
            f!("last_seen", "a.last_seen", Time, "When the asset last responded"),
            f!("open_ports", "(SELECT COUNT(*) FROM ports p WHERE p.asset_id = a.id)", Int, "Number of open TCP ports"),
            f!("port_list", "(SELECT group_concat(port, ',') FROM (SELECT port FROM ports p WHERE p.asset_id = a.id ORDER BY port))", Text, "Comma-separated open TCP ports"),
            f!("has_port", "", HasPort, "Filter only: asset has this TCP port open (use eq or in, e.g. {\"field\":\"has_port\",\"op\":\"in\",\"value\":[3389,5900]})"),
        ],
    },
    Dataset {
        name: "ports",
        description: "One row per open TCP port per asset, with service name and banner.",
        from: "ports p JOIN assets a ON a.id = p.asset_id",
        default_fields: &["asset_id", "asset_name", "ip", "port", "service", "banner"],
        default_sort: "a.ip_num, p.port",
        fields: &[
            f!("asset_id", "p.asset_id", Int, "Asset id"),
            f!("asset_name", ASSET_NAME, Text, "Asset display name"),
            f!("ip", "a.ip", Text, "Asset IP"),
            f!("port", "p.port", Int, "TCP port number"),
            f!("service", "p.service", Text, "Service name guessed from the port (rdp, smb, http, jetdirect, hl7…)"),
            f!("banner", "p.banner", Text, "Banner or HTTP Server header"),
            f!("device_type", "a.device_type", Text, "Asset device type"),
            f!("status", "a.status", Text, "Asset status"),
            f!("last_seen", "p.last_seen", Time, "When the port was last seen open"),
        ],
    },
    Dataset {
        name: "changes",
        description: "Change history: discoveries, field changes (ip, mac, hostname, os, type), ports opened/closed, online/offline.",
        from: "changes c JOIN assets a ON a.id = c.asset_id",
        default_fields: &["at", "asset_id", "asset_name", "change", "old_value", "new_value"],
        default_sort: "c.id DESC",
        fields: &[
            f!("id", "c.id", Int, "Change id"),
            f!("asset_id", "c.asset_id", Int, "Asset id"),
            f!("asset_name", ASSET_NAME, Text, "Asset display name"),
            f!("ip", "a.ip", Text, "Asset current IP"),
            f!("at", "c.at", Time, "When the change was recorded"),
            f!("change", "c.field", Text, "'discovered', 'port opened', 'port closed', 'status', 'ip', 'mac', 'hostname', 'netbios_name', 'os_guess', 'device_type', 'snmp_descr'"),
            f!("old_value", "c.old_value", Text, "Previous value"),
            f!("new_value", "c.new_value", Text, "New value"),
            f!("scan_id", "c.scan_id", Int, "Scan that detected the change"),
        ],
    },
    Dataset {
        name: "scans",
        description: "Scan runs: targets, trigger (manual, cli, api, schedule, mcp), status and counts.",
        from: "scans s",
        default_fields: &["id", "targets", "trigger", "status", "hosts_scanned", "hosts_up", "new_assets", "started_at", "finished_at"],
        default_sort: "s.id DESC",
        fields: &[
            f!("id", "s.id", Int, "Scan id"),
            f!("targets", "s.targets", Text, "Target specification"),
            f!("trigger", "s.trigger", Text, "What started the scan"),
            f!("status", "s.status", Text, "running, completed, failed, interrupted"),
            f!("hosts_scanned", "s.hosts_scanned", Int, "Addresses probed"),
            f!("hosts_up", "s.hosts_up", Int, "Hosts that responded"),
            f!("new_assets", "s.new_assets", Int, "Assets first discovered by this scan"),
            f!("started_at", "s.started_at", Time, "Start time"),
            f!("finished_at", "s.finished_at", Time, "End time"),
            f!("error", "s.error", Text, "Error message if failed"),
        ],
    },
];

pub fn dataset(name: &str) -> Result<&'static Dataset> {
    DATASETS
        .iter()
        .find(|d| d.name.eq_ignore_ascii_case(name))
        .ok_or_else(|| anyhow!("unknown dataset '{name}'. Available: {}", DATASETS.iter().map(|d| d.name).collect::<Vec<_>>().join(", ")))
}

impl Dataset {
    fn field(&self, name: &str) -> Result<&Field> {
        self.fields.iter().find(|f| f.name.eq_ignore_ascii_case(name)).ok_or_else(|| {
            anyhow!(
                "unknown field '{name}' in dataset '{}'. Fields: {}",
                self.name,
                self.fields.iter().map(|f| f.name).collect::<Vec<_>>().join(", ")
            )
        })
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Filter {
    pub field: String,
    /// eq, ne, contains, not_contains, starts_with, gt, gte, lt, lte, in, not_in, is_null, not_null
    #[serde(default = "default_op")]
    pub op: String,
    #[serde(default)]
    pub value: Value,
}

fn default_op() -> String {
    "eq".into()
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Sort {
    pub field: String,
    #[serde(default)]
    pub desc: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Query {
    pub dataset: String,
    #[serde(default)]
    pub fields: Vec<String>,
    #[serde(default)]
    pub filters: Vec<Filter>,
    /// Combine filters with "and" (default) or "or".
    #[serde(default)]
    pub match_any: bool,
    #[serde(default)]
    pub sort: Option<Sort>,
    #[serde(default)]
    pub limit: Option<i64>,
    #[serde(default)]
    pub offset: Option<i64>,
    /// Return counts grouped by this field instead of rows.
    #[serde(default)]
    pub group_by: Option<String>,
}

#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub default: i64,
    pub max: i64,
}

/// Same limits as Lansweeper's MCP server: 1–20 rows per call, default 10.
pub const MCP_LIMITS: Limits = Limits { default: 10, max: 20 };
pub const API_LIMITS: Limits = Limits { default: 100, max: 1000 };

/// Resolve "now-7d" / "now-12h" / "now-30m" / "now" into a stored-format timestamp.
fn resolve_time(v: &str) -> Result<String> {
    let s = v.trim().to_ascii_lowercase();
    if s == "now" {
        return Ok(crate::db::now());
    }
    if let Some(rest) = s.strip_prefix("now-") {
        let (num, unit) = rest.split_at(rest.len().saturating_sub(1));
        let n: i64 = num.parse().map_err(|_| anyhow!("bad relative time '{v}' (use e.g. now-7d, now-12h, now-30m)"))?;
        let d = match unit {
            "d" => chrono::Duration::days(n),
            "h" => chrono::Duration::hours(n),
            "m" => chrono::Duration::minutes(n),
            "w" => chrono::Duration::weeks(n),
            _ => bail!("bad relative time unit in '{v}' (use d, h, m or w)"),
        };
        return Ok((chrono::Local::now() - d).format("%Y-%m-%d %H:%M:%S").to_string());
    }
    Ok(v.to_string()) // absolute date/time; lexical comparison works for "YYYY-MM-DD[ HH:MM:SS]"
}

fn to_sql(field: &Field, v: &Value) -> Result<SqlValue> {
    Ok(match v {
        Value::Null => SqlValue::Null,
        Value::Bool(b) => SqlValue::Integer(*b as i64),
        Value::Number(n) => match n.as_i64() {
            Some(i) => SqlValue::Integer(i),
            None => SqlValue::Real(n.as_f64().unwrap_or(0.0)),
        },
        Value::String(s) => match field.kind {
            Kind::Time => SqlValue::Text(resolve_time(s)?),
            Kind::Int | Kind::HasPort => match s.trim().parse::<i64>() {
                Ok(i) => SqlValue::Integer(i),
                Err(_) => bail!("field '{}' expects a number, got '{s}'", field.name),
            },
            Kind::Text => SqlValue::Text(s.clone()),
        },
        other => bail!("unsupported value for '{}': {other}", field.name),
    })
}

fn like_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_")
}

fn build_filter(field: &Field, f: &Filter, params: &mut Vec<SqlValue>) -> Result<String> {
    let op = f.op.to_ascii_lowercase();
    let list = |params: &mut Vec<SqlValue>| -> Result<String> {
        let arr = match &f.value {
            Value::Array(a) if !a.is_empty() && a.len() <= 200 => a.clone(),
            Value::Array(_) => bail!("'{}' needs 1–200 values", op),
            v => vec![v.clone()],
        };
        let mut ph = Vec::new();
        for v in &arr {
            params.push(to_sql(field, v)?);
            ph.push(format!("?{}", params.len()));
        }
        Ok(ph.join(","))
    };

    if field.kind == Kind::HasPort {
        let (neg, sql_op) = match op.as_str() {
            "eq" | "in" => ("", "IN"),
            "ne" | "not_in" => ("NOT ", "IN"),
            _ => bail!("has_port supports eq, in, ne, not_in"),
        };
        let ph = list(params)?;
        return Ok(format!("{neg}EXISTS (SELECT 1 FROM ports hp WHERE hp.asset_id = a.id AND hp.port {sql_op} ({ph}))"));
    }

    let col = field.sql;
    let one = |params: &mut Vec<SqlValue>| -> Result<String> {
        if f.value.is_null() {
            bail!("operator '{op}' on '{}' needs a value", field.name);
        }
        params.push(to_sql(field, &f.value)?);
        Ok(format!("?{}", params.len()))
    };
    Ok(match op.as_str() {
        "eq" | "=" => format!("{col} = {}", one(params)?),
        "ne" | "!=" => format!("({col} IS NULL OR {col} != {})", one(params)?),
        "gt" | ">" => format!("{col} > {}", one(params)?),
        "gte" | ">=" => format!("{col} >= {}", one(params)?),
        "lt" | "<" => format!("{col} < {}", one(params)?),
        "lte" | "<=" => format!("{col} <= {}", one(params)?),
        "contains" | "not_contains" | "starts_with" => {
            let s = match &f.value {
                Value::String(s) => s.clone(),
                Value::Null => bail!("operator '{op}' needs a value"),
                v => v.to_string(),
            };
            let pat = if op == "starts_with" { format!("{}%", like_escape(&s)) } else { format!("%{}%", like_escape(&s)) };
            params.push(SqlValue::Text(pat));
            let n = params.len();
            if op == "not_contains" {
                format!("({col} IS NULL OR CAST({col} AS TEXT) NOT LIKE ?{n} ESCAPE '\\')")
            } else {
                format!("CAST({col} AS TEXT) LIKE ?{n} ESCAPE '\\'")
            }
        }
        "in" => format!("{col} IN ({})", list(params)?),
        "not_in" => format!("({col} IS NULL OR {col} NOT IN ({}))", list(params)?),
        "is_null" => format!("({col} IS NULL OR {col} = '')"),
        "not_null" => format!("({col} IS NOT NULL AND {col} != '')"),
        other => bail!(
            "unknown operator '{other}'. Use eq, ne, contains, not_contains, starts_with, gt, gte, lt, lte, in, not_in, is_null, not_null"
        ),
    })
}

fn json_of(v: ValueRef) -> Value {
    match v {
        ValueRef::Null => Value::Null,
        ValueRef::Integer(i) => json!(i),
        ValueRef::Real(f) => json!(f),
        ValueRef::Text(t) => json!(String::from_utf8_lossy(t)),
        ValueRef::Blob(_) => Value::Null,
    }
}

/// Execute a structured query and return a JSON result envelope.
pub fn execute(db: &Db, q: &Query, limits: Limits) -> Result<Value> {
    let ds = dataset(&q.dataset)?;
    let mut params: Vec<SqlValue> = Vec::new();
    let mut clauses = Vec::new();
    for f in &q.filters {
        let field = ds.field(&f.field)?;
        clauses.push(build_filter(field, f, &mut params)?);
    }
    let where_sql = if clauses.is_empty() {
        String::new()
    } else {
        format!(" WHERE {}", clauses.join(if q.match_any { " OR " } else { " AND " }))
    };
    let limit = q.limit.unwrap_or(limits.default).clamp(1, limits.max);
    let offset = q.offset.unwrap_or(0).max(0);

    db.with_conn(|conn| {
        let total: i64 = conn.query_row(
            &format!("SELECT COUNT(*) FROM {}{where_sql}", ds.from),
            rusqlite::params_from_iter(params.iter()),
            |r| r.get(0),
        )?;

        if let Some(g) = &q.group_by {
            let field = ds.field(g)?;
            if field.kind == Kind::HasPort {
                bail!("cannot group by has_port; query the 'ports' dataset grouped by 'port' instead");
            }
            let sql = format!(
                "SELECT COALESCE(CAST({} AS TEXT), '(none)') AS v, COUNT(*) AS c FROM {}{where_sql} GROUP BY 1 ORDER BY c DESC, v LIMIT {limit} OFFSET {offset}",
                field.sql, ds.from
            );
            let groups_total: i64 = conn.query_row(
                &format!("SELECT COUNT(DISTINCT COALESCE(CAST({} AS TEXT), '(none)')) FROM {}{where_sql}", field.sql, ds.from),
                rusqlite::params_from_iter(params.iter()),
                |r| r.get(0),
            )?;
            let mut st = conn.prepare(&sql)?;
            let rows = st
                .query_map(rusqlite::params_from_iter(params.iter()), |r| {
                    Ok(json!({ field.name: r.get::<_, String>(0)?, "count": r.get::<_, i64>(1)? }))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            return Ok(json!({
                "dataset": ds.name, "group_by": field.name, "matching_rows": total,
                "total_groups": groups_total, "returned": rows.len(), "offset": offset, "groups": rows,
                "has_more": offset + (rows.len() as i64) < groups_total,
            }));
        }

        let names: Vec<&str> = if q.fields.is_empty() {
            ds.default_fields.to_vec()
        } else {
            let mut v = Vec::new();
            for n in &q.fields {
                let f = ds.field(n)?;
                if f.kind == Kind::HasPort {
                    bail!("has_port is filter-only; select 'port_list' or 'open_ports' instead");
                }
                v.push(f.name);
            }
            v
        };
        let select: Vec<String> = names
            .iter()
            .map(|n| ds.field(n).map(|f| format!("{} AS \"{}\"", f.sql, f.name)))
            .collect::<Result<_>>()?;
        let order = match &q.sort {
            Some(s) => {
                let f = ds.field(&s.field)?;
                let expr = if ds.name == "assets" && f.name == "ip" { "a.ip_num" } else { f.sql };
                format!("{expr} {}", if s.desc { "DESC" } else { "ASC" })
            }
            None => ds.default_sort.to_string(),
        };
        let sql = format!(
            "SELECT {} FROM {}{where_sql} ORDER BY {order} LIMIT {limit} OFFSET {offset}",
            select.join(", "),
            ds.from
        );
        let mut st = conn.prepare(&sql)?;
        let rows = st
            .query_map(rusqlite::params_from_iter(params.iter()), |r| {
                let mut m = Map::new();
                for (i, n) in names.iter().enumerate() {
                    m.insert((*n).to_string(), json_of(r.get_ref(i)?));
                }
                Ok(Value::Object(m))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(json!({
            "dataset": ds.name, "total": total, "returned": rows.len(), "offset": offset,
            "has_more": offset + (rows.len() as i64) < total, "rows": rows,
        }))
    })
}

/// Dataset/field discovery, optionally filtered by keyword.
pub fn describe(keyword: Option<&str>) -> Value {
    let kw = keyword.map(|k| k.to_lowercase()).filter(|k| !k.trim().is_empty());
    let out: Vec<Value> = DATASETS
        .iter()
        .filter_map(|d| {
            let fields: Vec<&Field> = match &kw {
                None => d.fields.iter().collect(),
                Some(k) => {
                    if d.name.contains(k.as_str()) || d.description.to_lowercase().contains(k.as_str()) {
                        d.fields.iter().collect()
                    } else {
                        d.fields
                            .iter()
                            .filter(|f| f.name.contains(k.as_str()) || f.description.to_lowercase().contains(k.as_str()))
                            .collect()
                    }
                }
            };
            (!fields.is_empty()).then(|| {
                json!({ "dataset": d.name, "description": d.description, "default_fields": d.default_fields, "fields": fields })
            })
        })
        .collect();
    json!({
        "datasets": out,
        "operators": ["eq","ne","contains","not_contains","starts_with","gt","gte","lt","lte","in","not_in","is_null","not_null"],
        "relative_time": "Time fields accept 'now', 'now-30m', 'now-12h', 'now-7d', 'now-4w' or 'YYYY-MM-DD'.",
        "limits": { "default": MCP_LIMITS.default, "max": MCP_LIMITS.max, "paging": "use offset" },
    })
}

/// Convenience used by tests and the catalog.
pub fn parse(v: Value) -> Result<Query> {
    serde_json::from_value(v).map_err(|e| anyhow!("invalid query: {e}"))
}
