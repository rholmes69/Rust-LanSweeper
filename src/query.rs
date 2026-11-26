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
    /// Column holding the site id, used for site filters and site-scoped tokens.
    #[serde(skip)]
    pub site_col: &'static str,
    pub fields: &'static [Field],
}

macro_rules! f {
    ($n:expr, $sql:expr, $k:ident, $d:expr) => {
        Field { name: $n, sql: $sql, kind: Kind::$k, description: $d }
    };
}

const ASSET_NAME: &str = crate::db::NAME_SQL;
const ASSET_SITE: &str = "(SELECT st.name FROM sites st WHERE st.id = a.site_id)";

pub static DATASETS: &[Dataset] = &[
    Dataset {
        name: "assets",
        description: "One row per discovered device: identity, network names, vendor, fingerprint, SNMP/web info, status and timestamps.",
        from: "assets a LEFT JOIN windows_inventory w ON w.asset_id = a.id",
        default_fields: &["id", "ip", "name", "mac", "vendor", "device_type", "os_guess", "open_ports", "status", "last_seen"],
        default_sort: "a.ip_num",
        site_col: "a.site_id",
        fields: &[
            f!("id", "a.id", Int, "Asset id"),
            f!("ip", "a.ip", Text, "IPv4 address (sorts numerically)"),
            f!("name", ASSET_NAME, Text, "Display name: IT-assigned name, then NetBIOS, DNS, SNMP sysName, IP"),
            f!("site", "(SELECT st.name FROM sites st WHERE st.id = a.site_id)", Text, "Site (location) name; empty if unassigned"),
            f!("site_id", "a.site_id", Int, "Site id"),
            f!("mac", "a.mac", Text, "MAC address AA:BB:CC:DD:EE:FF"),
            f!("vendor", "a.vendor", Text, "Hardware vendor from MAC OUI"),
            f!("hostname", "a.hostname", Text, "Reverse-DNS name"),
            f!("netbios_name", "a.netbios_name", Text, "Windows/NetBIOS computer name"),
            f!("domain", "a.netbios_domain", Text, "NetBIOS domain or workgroup"),
            f!("device_type", "a.device_type", Text, "Fingerprinted type, e.g. 'Windows Workstation', 'Printer', 'Network Device'"),
            f!("os_guess", "a.os_guess", Text, "Operating system (from Windows inventory when available, else fingerprinted)"),
            f!("os", "COALESCE(w.os_name, a.os_guess)", Text, "Best-known OS name, e.g. 'Microsoft Windows 11 Pro'"),
            f!("os_version", "w.os_version", Text, "Windows version, e.g. 10.0.22631 (inventory)"),
            f!("os_build", "w.os_build", Text, "Windows build number, e.g. 19045 (inventory)"),
            f!("last_user", "w.last_user", Text, "User logged on at last inventory, DOMAIN\\user (inventory)"),
            f!("win_domain", "w.domain", Text, "AD domain or workgroup (inventory)"),
            f!("cpu", "w.cpu", Text, "Processor model (inventory)"),
            f!("cores", "w.cores", Int, "Physical CPU cores (inventory)"),
            f!("memory_mb", "w.memory_mb", Int, "Installed RAM in MB as reported by Windows (8 GB ≈ 7,900–8,192)"),
            f!("min_disk_free_pct", "w.min_free_pct", Int, "Lowest free-space % across fixed disks (inventory)"),
            f!("last_boot", "w.last_boot", Time, "Last boot time (inventory)"),
            f!("os_install_date", "w.os_install_date", Time, "When Windows was installed (inventory)"),
            f!("bios_version", "w.bios_version", Text, "BIOS/UEFI version (inventory)"),
            f!("platform", "w.platform", Text, "Credentialed inventory platform: 'windows' (WMI) or 'linux' (SSH); empty if never inventoried"),
            f!("software_count", "w.software_count", Int, "Installed programs/packages found by credentialed inventory"),
            f!("display_version", "w.display_version", Text, "Windows feature release, e.g. 23H2, 24H2 (inventory)"),
            f!("full_build", "w.os_build || '.' || w.ubr", Text, "Build including monthly update revision, e.g. 26100.2314 (inventory)"),
            f!("av_ok", "w.av_ok", Int, "1 = an antivirus is enabled and up to date; 0 = not; empty = unknown (inventory)"),
            f!("av_products", "w.av_products", Text, "Antivirus products registered with Security Center (JSON)"),
            f!("defender_sig_updated", "w.defender_sig_updated", Time, "When Microsoft Defender signatures last updated"),
            f!("bitlocker_os", "w.bitlocker_os", Int, "1 = BitLocker protection on for C:, 0 = off, empty = unknown/not supported"),
            f!("firewall_off", "w.firewall_off", Int, "1 = at least one Windows Firewall profile is disabled"),
            f!("reboot_pending", "w.reboot_pending", Int, "1 = Windows is waiting for a restart to finish updates"),
            f!("last_patch_date", "w.last_patch_date", Time, "Most recent installed update (Win32_QuickFixEngineering)"),
            f!("hotfix_count", "w.hotfix_count", Int, "Installed updates listed by Windows"),
            f!("inventory_status", "a.inventory_status", Text, "'ok' or 'error' for the last credentialed inventory attempt; empty if never tried"),
            f!("inventory_error", "a.inventory_error", Text, "Why the last inventory attempt failed"),
            f!("inventory_at", "a.inventory_at", Time, "When credentialed inventory last ran"),
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
            f!("asset_tag", "a.asset_tag", Text, "IT asset tag"),
            f!("serial_number", "a.serial_number", Text, "Serial number"),
            f!("manufacturer", "a.manufacturer", Text, "Manufacturer (entered/imported; see vendor for the MAC-derived maker)"),
            f!("model", "a.model", Text, "Model"),
            f!("owner", "a.owner", Text, "Owner / assigned user"),
            f!("department", "a.department", Text, "Department"),
            f!("cost_center", "a.cost_center", Text, "Cost center"),
            f!("location", "a.location", Text, "Room / physical location (finer than site)"),
            f!("purchase_date", "a.purchase_date", Time, "Purchase date (YYYY-MM-DD)"),
            f!("po_number", "a.po_number", Text, "Purchase order number"),
            f!("supplier", "a.supplier", Text, "Supplier / reseller"),
            f!("warranty_end", "a.warranty_end", Time, "Warranty end date (YYYY-MM-DD); compare with now+90d etc."),
            f!("source", "a.source", Text, "Where the record came from: scanner, manual, import, api"),
            f!("detected_by", "a.detected_by", Text, "How the last scan saw the device: tcp, ping, netbios, snmp, arp"),
            f!("scan_count", "a.scan_count", Int, "Number of scans that have seen the device"),
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
        site_col: "a.site_id",
        fields: &[
            f!("asset_id", "p.asset_id", Int, "Asset id"),
            f!("asset_name", ASSET_NAME, Text, "Asset display name"),
            f!("ip", "a.ip", Text, "Asset IP"),
            f!("site", ASSET_SITE, Text, "Asset's site name"),
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
        site_col: "a.site_id",
        fields: &[
            f!("id", "c.id", Int, "Change id"),
            f!("asset_id", "c.asset_id", Int, "Asset id"),
            f!("asset_name", ASSET_NAME, Text, "Asset display name"),
            f!("ip", "a.ip", Text, "Asset current IP"),
            f!("site", ASSET_SITE, Text, "Asset's site name"),
            f!("at", "c.at", Time, "When the change was recorded"),
            f!("change", "c.field", Text, "'discovered', 'port opened', 'port closed', 'status', 'ip', 'mac', 'hostname', 'netbios_name', 'os_guess', 'device_type', 'snmp_descr'"),
            f!("old_value", "c.old_value", Text, "Previous value"),
            f!("new_value", "c.new_value", Text, "New value"),
            f!("scan_id", "c.scan_id", Int, "Scan that detected the change"),
        ],
    },
    Dataset {
        name: "custom_fields",
        description: "Organisation-defined custom field values, one row per asset per field (e.g. 'Insurance Plan', 'Room').",
        from: "asset_custom_values cv JOIN custom_fields cf ON cf.id = cv.field_id JOIN assets a ON a.id = cv.asset_id",
        default_fields: &["asset_id", "asset_name", "ip", "field", "value"],
        default_sort: "cf.name, a.ip_num",
        site_col: "a.site_id",
        fields: &[
            f!("asset_id", "cv.asset_id", Int, "Asset id"),
            f!("asset_name", ASSET_NAME, Text, "Asset display name"),
            f!("ip", "a.ip", Text, "Asset IP"),
            f!("site", ASSET_SITE, Text, "Asset's site name"),
            f!("field", "cf.name", Text, "Custom field name"),
            f!("value", "cv.value", Text, "Value"),
        ],
    },
    Dataset {
        name: "software",
        description: "Installed programs on Windows devices (from credentialed inventory), one row per program per device. 'product' is the name without version/arch tags — group by it for fleet counts.",
        from: "software sw JOIN assets a ON a.id = sw.asset_id",
        default_fields: &["asset_id", "asset_name", "product", "version", "publisher"],
        default_sort: "sw.product COLLATE NOCASE, a.ip_num",
        site_col: "a.site_id",
        fields: &[
            f!("asset_id", "sw.asset_id", Int, "Asset id"),
            f!("asset_name", ASSET_NAME, Text, "Asset display name"),
            f!("ip", "a.ip", Text, "Asset IP"),
            f!("site", ASSET_SITE, Text, "Asset's site name"),
            f!("name", "sw.name", Text, "Program name exactly as registered, e.g. 'Mozilla Firefox (x64 en-US)'"),
            f!("product", "sw.product", Text, "Normalised product name, e.g. 'Mozilla Firefox'"),
            f!("version", "sw.version", Text, "Version string"),
            f!("publisher", "sw.publisher", Text, "Publisher (normalised, e.g. 'Microsoft')"),
            f!("install_date", "sw.install_date", Time, "Install date (YYYY-MM-DD) when the installer recorded one"),
            f!("arch", "sw.arch", Text, "x64 or x86 (registry view)"),
        ],
    },
    Dataset {
        name: "services",
        description: "Windows services per device (from credentialed inventory): state, start mode, the account they run as, and risk flags.",
        from: "services sv JOIN assets a ON a.id = sv.asset_id",
        default_fields: &["asset_id", "asset_name", "name", "display_name", "state", "start_mode", "start_name"],
        default_sort: "a.ip_num, sv.display_name COLLATE NOCASE",
        site_col: "a.site_id",
        fields: &[
            f!("asset_id", "sv.asset_id", Int, "Asset id"),
            f!("asset_name", ASSET_NAME, Text, "Asset display name"),
            f!("ip", "a.ip", Text, "Asset IP"),
            f!("site", ASSET_SITE, Text, "Asset's site name"),
            f!("name", "sv.name", Text, "Service short name, e.g. Spooler"),
            f!("display_name", "sv.display_name", Text, "Display name, e.g. Print Spooler"),
            f!("state", "sv.state", Text, "Running, Stopped, …"),
            f!("start_mode", "sv.start_mode", Text, "Auto, Manual or Disabled"),
            f!("start_name", "sv.start_name", Text, "Account the service runs as"),
            f!("path", "sv.path", Text, "Executable path and arguments"),
            f!("unquoted_path", "sv.unquoted_path", Int, "1 if the executable path has spaces and no quotes (privilege-escalation risk)"),
            f!("custom_account", "sv.custom_account", Int, "1 if it runs as a user/domain account instead of a built-in service identity"),
        ],
    },
    Dataset {
        name: "hotfixes",
        description: "Installed Windows updates (KB numbers) per device, from Win32_QuickFixEngineering. Use to find devices missing a specific KB.",
        from: "hotfixes hf JOIN assets a ON a.id = hf.asset_id",
        default_fields: &["asset_id", "asset_name", "hotfix_id", "description", "installed_on"],
        default_sort: "hf.installed_on DESC, a.ip_num",
        site_col: "a.site_id",
        fields: &[
            f!("asset_id", "hf.asset_id", Int, "Asset id"),
            f!("asset_name", ASSET_NAME, Text, "Asset display name"),
            f!("ip", "a.ip", Text, "Asset IP"),
            f!("site", ASSET_SITE, Text, "Asset's site name"),
            f!("hotfix_id", "hf.hotfix_id", Text, "KB number, e.g. KB5044284"),
            f!("description", "hf.description", Text, "Update, Security Update, …"),
            f!("installed_on", "hf.installed_on", Time, "Install date (YYYY-MM-DD) when Windows recorded one"),
        ],
    },
    Dataset {
        name: "scans",
        description: "Scan runs: targets, trigger (manual, cli, api, schedule, mcp), status and counts.",
        from: "scans s",
        default_fields: &["id", "targets", "trigger", "status", "hosts_scanned", "hosts_up", "new_assets", "started_at", "finished_at"],
        default_sort: "s.id DESC",
        site_col: "s.site_id",
        fields: &[
            f!("id", "s.id", Int, "Scan id"),
            f!("targets", "s.targets", Text, "Target specification"),
            f!("site", "(SELECT st.name FROM sites st WHERE st.id = s.site_id)", Text, "Site scanned, when the scan was started for a site"),
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
    /// Limit to one site: id, name, or "unassigned".
    #[serde(default)]
    pub site: Option<Value>,
}

/// What the caller may see. Site-scoped API tokens get `Some(ids)`.
#[derive(Debug, Clone, Default)]
pub struct Scope {
    pub sites: Option<Vec<i64>>,
}

impl Scope {
    pub fn all() -> Self {
        Self { sites: None }
    }

    pub fn is_restricted(&self) -> bool {
        self.sites.is_some()
    }

    pub fn allows(&self, site_id: Option<i64>) -> bool {
        match &self.sites {
            None => true,
            Some(ids) => site_id.is_some_and(|s| ids.contains(&s)),
        }
    }
}

/// Resolve a site reference (id, name or "unassigned") to Some(id) / None (= unassigned).
pub fn resolve_site(db: &Db, v: &Value) -> Result<Option<i64>> {
    let key = match v {
        Value::Number(n) => n.to_string(),
        Value::String(s) => s.trim().to_string(),
        other => bail!("site must be an id or name, got {other}"),
    };
    if key == "0" || key.eq_ignore_ascii_case("unassigned") {
        return Ok(None);
    }
    db.find_site(&key)?
        .map(|s| Some(s.id))
        .ok_or_else(|| anyhow!("unknown site '{key}' (use list_sites to see site names)"))
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
    let (rest, sign) = match (s.strip_prefix("now-"), s.strip_prefix("now+")) {
        (Some(r), _) => (Some(r), -1),
        (_, Some(r)) => (Some(r), 1),
        _ => (None, 1),
    };
    if let Some(rest) = rest {
        let (num, unit) = rest.split_at(rest.len().saturating_sub(1));
        let n: i64 = num.parse::<i64>().map_err(|_| anyhow!("bad relative time '{v}' (use e.g. now-7d, now+90d, now-12h)"))? * -sign;
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
pub fn execute(db: &Db, q: &Query, limits: Limits, scope: &Scope) -> Result<Value> {
    let ds = dataset(&q.dataset)?;
    let mut params: Vec<SqlValue> = Vec::new();
    let mut clauses = Vec::new();
    for f in &q.filters {
        let field = ds.field(&f.field)?;
        clauses.push(build_filter(field, f, &mut params)?);
    }
    let mut where_parts = Vec::new();
    if !clauses.is_empty() {
        where_parts.push(format!("({})", clauses.join(if q.match_any { " OR " } else { " AND " })));
    }
    if let Some(site) = &q.site {
        match resolve_site(db, site)? {
            Some(id) => {
                if !scope.allows(Some(id)) {
                    bail!("this token does not have access to that site");
                }
                where_parts.push(format!("{} = {id}", ds.site_col));
            }
            None => {
                if scope.is_restricted() {
                    bail!("this token does not have access to unassigned assets");
                }
                where_parts.push(format!("{} IS NULL", ds.site_col));
            }
        }
    }
    // Site-scoped tokens: enforced server-side on every query (ids are integers from the DB).
    if let Some(ids) = &scope.sites {
        let list = if ids.is_empty() { "NULL".to_string() } else { ids.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(",") };
        where_parts.push(format!("{} IN ({list})", ds.site_col));
    }
    let where_sql = if where_parts.is_empty() { String::new() } else { format!(" WHERE {}", where_parts.join(" AND ")) };
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
        "relative_time": "Time/date fields accept 'now', 'now-30m', 'now-12h', 'now-7d', 'now+90d', 'now-4w' or 'YYYY-MM-DD'.",
        "limits": { "default": MCP_LIMITS.default, "max": MCP_LIMITS.max, "paging": "use offset" },
    })
}

/// Convenience used by tests and the catalog.
pub fn parse(v: Value) -> Result<Query> {
    serde_json::from_value(v).map_err(|e| anyhow!("invalid query: {e}"))
}
