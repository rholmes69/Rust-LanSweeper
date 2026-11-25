//! Model Context Protocol (MCP) server: lets AI assistants (Claude, Cursor, …) query the
//! RustSweeper inventory in natural language. Read-only by default, modelled on Lansweeper's
//! MCP server (list sites → find a template or dataset → run a structured query).
//!
//! JSON-RPC 2.0 is implemented directly; transports live in `stdio.rs` (and `http.rs`).

pub mod catalog;
pub mod http;
pub mod prompts;
pub mod stdio;

use std::collections::BTreeMap;
use std::sync::atomic::Ordering;

use anyhow::{anyhow, bail, Result};
use serde_json::{json, Value};

use crate::db::AssetFilter;
use crate::query::{self, MCP_LIMITS};
use crate::web::{self, AppState};

pub const SERVER_NAME: &str = "rustsweeper";
const SUPPORTED_VERSIONS: &[&str] = &["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];
const FALLBACK_VERSION: &str = "2025-06-18";

const INSTRUCTIONS: &str = "RustSweeper is an agentless network asset inventory (devices, open ports, \
names, vendors, change history, scans). Suggested workflow: (1) list_sites to see what is inventoried; \
(2) search_query_catalog for a ready-made query matching the question; (3) otherwise search_datasets to \
find fields, then execute_query with filters. Results are capped at 20 rows per call (default 10) — page \
with offset when has_more is true, or use group_by for counts. Use get_asset / asset_history for a single \
device and docs for how RustSweeper works. Only report what the tools return.";

#[derive(Clone)]
pub struct McpServer {
    pub state: AppState,
    /// Expose the `start_scan` tool (off by default: the server is read-only).
    pub allow_scans: bool,
}

/// Who is calling — used for auditing by transports that know the caller.
#[derive(Debug, Clone, Default)]
pub struct CallContext {
    pub transport: &'static str,
    /// Authenticated caller: token name (HTTP) or OS user (stdio).
    pub client: Option<String>,
    pub remote_addr: Option<String>,
}

fn rpc_result(id: &Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

fn rpc_error(id: &Value, code: i64, message: impl Into<String>) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message.into() } })
}

pub const PARSE_ERROR: i64 = -32700;
pub const INVALID_REQUEST: i64 = -32600;
pub const METHOD_NOT_FOUND: i64 = -32601;
pub const INVALID_PARAMS: i64 = -32602;

impl McpServer {
    pub fn new(state: AppState, allow_scans: bool) -> Self {
        Self { state, allow_scans }
    }

    /// Handle one parsed JSON-RPC message (or batch). Returns `None` for notifications.
    pub async fn handle(&self, msg: Value, ctx: &CallContext) -> Option<Value> {
        if let Value::Array(items) = msg {
            if items.is_empty() {
                return Some(rpc_error(&Value::Null, INVALID_REQUEST, "empty batch"));
            }
            let mut out = Vec::new();
            for m in items {
                if let Some(r) = Box::pin(self.handle(m, ctx)).await {
                    out.push(r);
                }
            }
            return (!out.is_empty()).then_some(Value::Array(out));
        }
        let Some(obj) = msg.as_object() else {
            return Some(rpc_error(&Value::Null, INVALID_REQUEST, "expected a JSON-RPC object"));
        };
        let method = obj.get("method").and_then(|m| m.as_str());
        let id = obj.get("id").cloned();
        let params = obj.get("params").cloned().unwrap_or(Value::Null);

        let (Some(method), Some(id)) = (method, id) else {
            // Notifications (no id) and stray responses get no reply.
            return None;
        };
        Some(match self.dispatch(method, &params, ctx).await {
            Ok(r) => rpc_result(&id, r),
            Err(RpcError(code, msg)) => rpc_error(&id, code, msg),
        })
    }

    async fn dispatch(&self, method: &str, params: &Value, ctx: &CallContext) -> Result<Value, RpcError> {
        match method {
            "initialize" => {
                let client_info = params.get("clientInfo").cloned().unwrap_or(Value::Null);
                self.audit(ctx, "initialize", None, Some(&client_info), &Ok(Value::Null), std::time::Instant::now());
                let requested = params.get("protocolVersion").and_then(|v| v.as_str()).unwrap_or(FALLBACK_VERSION);
                let version = if SUPPORTED_VERSIONS.contains(&requested) { requested } else { FALLBACK_VERSION };
                Ok(json!({
                    "protocolVersion": version,
                    "capabilities": { "tools": { "listChanged": false }, "prompts": { "listChanged": false } },
                    "serverInfo": { "name": SERVER_NAME, "title": "RustSweeper", "version": env!("CARGO_PKG_VERSION") },
                    "instructions": INSTRUCTIONS,
                }))
            }
            "ping" => Ok(json!({})),
            "tools/list" => Ok(json!({ "tools": self.tool_defs() })),
            "tools/call" => {
                let name = params
                    .get("name")
                    .and_then(|n| n.as_str())
                    .ok_or_else(|| RpcError(INVALID_PARAMS, "missing tool name".into()))?;
                let args = params.get("arguments").cloned().unwrap_or_else(|| json!({}));
                if !self.tool_defs().iter().any(|t| t["name"] == name) {
                    return Err(RpcError(INVALID_PARAMS, format!("unknown tool '{name}'")));
                }
                let started = std::time::Instant::now();
                let res = self.call_tool(name, &args).await;
                self.audit(ctx, "tools/call", Some(name), Some(&args), &res, started);
                Ok(match res {
                    Ok(v) => json!({
                        "content": [{ "type": "text", "text": serde_json::to_string_pretty(&v).unwrap_or_default() }],
                        "structuredContent": v,
                        "isError": false,
                    }),
                    // Tool failures are reported in-band so the model can correct its arguments.
                    Err(e) => json!({ "content": [{ "type": "text", "text": format!("Error: {e:#}") }], "isError": true }),
                })
            }
            "prompts/list" => Ok(prompts::list()),
            "prompts/get" => {
                let name = params.get("name").and_then(|n| n.as_str()).unwrap_or("");
                let args = params.get("arguments").cloned().unwrap_or_else(|| json!({}));
                prompts::get(name, &args)
                    .ok_or_else(|| RpcError(INVALID_PARAMS, format!("unknown prompt '{name}' or missing required argument")))
            }
            "resources/list" => Ok(json!({ "resources": [] })),
            "resources/templates/list" => Ok(json!({ "resourceTemplates": [] })),
            other => Err(RpcError(METHOD_NOT_FOUND, format!("method '{other}' not found"))),
        }
    }

    pub fn tool_defs(&self) -> Vec<Value> {
        let ro = json!({ "readOnlyHint": true, "openWorldHint": false });
        let query_schema = json!({
            "type": "object",
            "properties": {
                "dataset": { "type": "string", "enum": query::DATASETS.iter().map(|d| d.name).collect::<Vec<_>>() },
                "fields": { "type": "array", "items": { "type": "string" }, "description": "Fields to return (default: dataset's default fields)" },
                "filters": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "field": { "type": "string" },
                            "op": { "type": "string", "enum": ["eq","ne","contains","not_contains","starts_with","gt","gte","lt","lte","in","not_in","is_null","not_null"] },
                            "value": { "description": "String, number, or array for in/not_in. Time fields accept now-7d, now-12h, YYYY-MM-DD." }
                        },
                        "required": ["field"]
                    }
                },
                "match_any": { "type": "boolean", "description": "OR the filters instead of AND" },
                "sort": { "type": "object", "properties": { "field": {"type":"string"}, "desc": {"type":"boolean"} }, "required": ["field"] },
                "group_by": { "type": "string", "description": "Return counts per value of this field instead of rows" },
                "limit": { "type": "integer", "minimum": 1, "maximum": MCP_LIMITS.max, "default": MCP_LIMITS.default },
                "offset": { "type": "integer", "minimum": 0, "default": 0 }
            },
            "required": ["dataset"]
        });
        let mut tools = vec![
            json!({
                "name": "list_sites",
                "title": "List sites",
                "description": "Start here. Lists the inventoried sites and the subnets/asset counts in each, plus database totals.",
                "inputSchema": { "type": "object", "properties": {} },
                "annotations": ro,
            }),
            json!({
                "name": "search_datasets",
                "title": "Search datasets and fields",
                "description": "Discover queryable datasets (assets, ports, changes, scans), their fields, operators and limits. Optionally filter by keyword (e.g. 'snmp', 'port', 'time').",
                "inputSchema": { "type": "object", "properties": { "keyword": { "type": "string" } } },
                "annotations": ro,
            }),
            json!({
                "name": "search_query_catalog",
                "title": "Search query catalog",
                "description": "Find pre-built queries for common IT/security questions (remote access exposure, new devices, offline printers, counts by type/OS/vendor, port changes, HL7/DICOM…). Returns ready-to-run execute_query arguments. Pass run_id to execute one directly.",
                "inputSchema": { "type": "object", "properties": {
                    "query": { "type": "string", "description": "Keywords describing the question" },
                    "run_id": { "type": "string", "description": "Template id to execute immediately" },
                    "offset": { "type": "integer", "minimum": 0, "description": "Paging offset when using run_id" }
                } },
                "annotations": ro,
            }),
            json!({
                "name": "execute_query",
                "title": "Execute structured query",
                "description": "Run a structured, read-only query against a dataset. Max 20 rows per call (default 10); page with offset; use group_by for counts. Assets can be filtered by open port with the has_port pseudo-field.",
                "inputSchema": query_schema,
                "annotations": ro,
            }),
            json!({
                "name": "get_asset",
                "title": "Get asset",
                "description": "Full detail for one device — identity, fingerprint, SNMP/web info, notes, open ports and recent changes. Look up by id, IP or name.",
                "inputSchema": { "type": "object", "properties": {
                    "id": { "type": "integer" }, "ip": { "type": "string" }, "name": { "type": "string" }
                } },
                "annotations": ro,
            }),
            json!({
                "name": "asset_history",
                "title": "Asset change history",
                "description": "Chronological change log for one asset (discovered, IP/MAC/name/OS/type changes, ports opened/closed, online/offline).",
                "inputSchema": { "type": "object", "properties": {
                    "asset_id": { "type": "integer" }, "limit": { "type": "integer", "minimum": 1, "maximum": 100, "default": 25 }
                }, "required": ["asset_id"] },
                "annotations": ro,
            }),
            json!({
                "name": "scan_status",
                "title": "Scan status",
                "description": "Status and live progress of a scan (latest scan if scan_id is omitted).",
                "inputSchema": { "type": "object", "properties": { "scan_id": { "type": "integer" } } },
                "annotations": ro,
            }),
            json!({
                "name": "docs",
                "title": "RustSweeper documentation",
                "description": "Search RustSweeper's documentation: how discovery works, fingerprinting, CLI/API usage, limits.",
                "inputSchema": { "type": "object", "properties": { "query": { "type": "string" } } },
                "annotations": ro,
            }),
        ];
        if self.allow_scans {
            tools.push(json!({
                "name": "start_scan",
                "title": "Start a network scan",
                "description": "Start a discovery scan (runs in the background; poll scan_status). Targets: CIDR, ranges like 10.0.0.5-40, IPs or hostnames. Max 65,536 addresses. Only scan networks you are authorised to scan.",
                "inputSchema": { "type": "object", "properties": { "targets": { "type": "string" } }, "required": ["targets"] },
                "annotations": { "readOnlyHint": false, "destructiveHint": false, "idempotentHint": false, "openWorldHint": true },
            }));
        }
        tools
    }

    pub async fn call_tool(&self, name: &str, args: &Value) -> Result<Value> {
        let db = &self.state.db;
        match name {
            "list_sites" => list_sites(&self.state),
            "search_datasets" => Ok(query::describe(args.get("keyword").and_then(|v| v.as_str()))),
            "search_query_catalog" => {
                if let Some(id) = args.get("run_id").and_then(|v| v.as_str()) {
                    let t = catalog::get(id).ok_or_else(|| anyhow!("no template '{id}'"))?;
                    let mut q = query::parse(t.query.clone())?;
                    if let Some(o) = args.get("offset").and_then(|v| v.as_i64()) {
                        q.offset = Some(o);
                    }
                    let result = query::execute(db, &q, MCP_LIMITS)?;
                    return Ok(json!({ "template": t.id, "title": t.title, "result": result }));
                }
                let hits = catalog::search(args.get("query").and_then(|v| v.as_str()));
                Ok(json!({
                    "count": hits.len(),
                    "templates": hits,
                    "hint": "Run one with search_query_catalog {run_id}, or pass its 'query' (adjusted as needed) to execute_query.",
                }))
            }
            "execute_query" => {
                let q = query::parse(args.clone())?;
                query::execute(db, &q, MCP_LIMITS)
            }
            "get_asset" => get_asset(&self.state, args),
            "asset_history" => {
                let id = args.get("asset_id").and_then(|v| v.as_i64()).ok_or_else(|| anyhow!("asset_id is required"))?;
                let limit = args.get("limit").and_then(|v| v.as_i64()).unwrap_or(25).clamp(1, 100);
                let a = db.get_asset(id)?.ok_or_else(|| anyhow!("no asset {id}"))?;
                Ok(json!({ "asset_id": id, "name": a.display_name(), "changes": db.changes(Some(id), limit)? }))
            }
            "scan_status" => {
                let scan = match args.get("scan_id").and_then(|v| v.as_i64()) {
                    Some(id) => db.get_scan(id)?,
                    None => db.list_scans(1)?.into_iter().next(),
                };
                let scan = scan.ok_or_else(|| anyhow!("no such scan (no scans have run yet?)"))?;
                let progress = self.state.progress_of(scan.id).map(|p| {
                    json!({
                        "total": p.total.load(Ordering::Relaxed),
                        "done": p.done.load(Ordering::Relaxed),
                        "up": p.up.load(Ordering::Relaxed),
                    })
                });
                Ok(json!({ "scan": scan, "progress": progress }))
            }
            "docs" => Ok(docs(args.get("query").and_then(|v| v.as_str()))),
            "start_scan" if self.allow_scans => {
                let targets = args.get("targets").and_then(|v| v.as_str()).ok_or_else(|| anyhow!("targets is required"))?;
                let id = web::launch_scan(&self.state, targets, "mcp")?;
                Ok(json!({ "scan_id": id, "status": "running", "hint": "Poll scan_status with this scan_id." }))
            }
            other => bail!("unknown tool '{other}'"),
        }
    }
}

impl McpServer {
    /// Record an MCP call in the audit log (never fails the request).
    fn audit(&self, ctx: &CallContext, method: &str, tool: Option<&str>, args: Option<&Value>, res: &Result<Value>, started: std::time::Instant) {
        let mut arguments = args.map(|a| a.to_string());
        if let Some(a) = &mut arguments {
            if a.len() > 2000 {
                let mut cut = 2000;
                while !a.is_char_boundary(cut) {
                    cut -= 1;
                }
                a.truncate(cut);
                a.push('…');
            }
        }
        let rows = res.as_ref().ok().and_then(|v| {
            v.get("returned").or_else(|| v.get("result").and_then(|r| r.get("returned"))).and_then(|n| n.as_i64())
        });
        let entry = crate::db::NewAudit {
            transport: ctx.transport,
            client: ctx.client.as_deref(),
            remote_addr: ctx.remote_addr.as_deref(),
            method,
            tool,
            arguments,
            ok: res.is_ok(),
            error: res.as_ref().err().map(|e| format!("{e:#}")),
            rows,
            duration_ms: started.elapsed().as_millis() as i64,
        };
        if let Err(e) = self.state.db.add_audit(&entry) {
            tracing::warn!("could not write MCP audit entry: {e:#}");
        }
        tracing::info!(transport = ctx.transport, client = ?ctx.client, method, tool, ok = res.is_ok(), "mcp call");
    }
}

pub struct RpcError(pub i64, pub String);

fn list_sites(state: &AppState) -> Result<Value> {
    let assets = state.db.list_assets(&AssetFilter::default())?;
    let mut subnets: BTreeMap<u32, (usize, usize)> = BTreeMap::new();
    for a in &assets {
        if let Ok(std::net::IpAddr::V4(v4)) = a.ip.parse::<std::net::IpAddr>() {
            let net = u32::from(v4) & 0xFFFF_FF00;
            let e = subnets.entry(net).or_default();
            e.0 += 1;
            if a.status == "online" {
                e.1 += 1;
            }
        }
    }
    let stats = state.db.stats()?;
    let last_scan = state.db.list_scans(1)?.into_iter().next();
    Ok(json!({
        "sites": [{
            "id": "default",
            "name": "Default site",
            "asset_count": stats.total,
            "online": stats.online,
            "offline": stats.offline,
            "subnets": subnets.iter().map(|(n, (c, on))| json!({
                "subnet": format!("{}/24", std::net::Ipv4Addr::from(*n)), "assets": c, "online": on
            })).collect::<Vec<_>>(),
        }],
        "last_scan": last_scan,
        "note": "Multi-site support (clinic locations) is planned; all assets currently belong to the default site.",
    }))
}

fn get_asset(state: &AppState, args: &Value) -> Result<Value> {
    let db = &state.db;
    let asset = if let Some(id) = args.get("id").and_then(|v| v.as_i64()) {
        db.get_asset(id)?
    } else {
        let needle = args
            .get("ip")
            .or_else(|| args.get("name"))
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| anyhow!("provide id, ip or name"))?;
        let all = db.list_assets(&AssetFilter { q: Some(needle.clone()), ..Default::default() })?;
        let exact: Vec<_> = all
            .iter()
            .filter(|a| {
                a.ip == needle
                    || a.display_name().eq_ignore_ascii_case(&needle)
                    || a.hostname.as_deref().is_some_and(|h| h.eq_ignore_ascii_case(&needle) || h.split('.').next().is_some_and(|s| s.eq_ignore_ascii_case(&needle)))
                    || a.mac.as_deref().is_some_and(|m| m.eq_ignore_ascii_case(&needle))
            })
            .cloned()
            .collect();
        match (exact.len(), all.len()) {
            (1, _) => exact.into_iter().next(),
            (0, 1) => all.into_iter().next(),
            (0, 0) => None,
            _ => {
                let c = if exact.is_empty() { &all } else { &exact };
                return Ok(json!({
                    "ambiguous": true,
                    "candidates": c.iter().take(20).map(|a| json!({"id": a.id, "ip": a.ip, "name": a.display_name(), "device_type": a.device_type})).collect::<Vec<_>>(),
                    "hint": "Call get_asset again with one of these ids.",
                }));
            }
        }
    };
    let a = asset.ok_or_else(|| anyhow!("asset not found"))?;
    Ok(json!({
        "asset": a,
        "ports": db.asset_ports(a.id)?,
        "recent_changes": db.changes(Some(a.id), 20)?,
    }))
}

const README: &str = include_str!("../../README.md");

const DATA_MODEL_DOC: &str = "## How RustSweeper collects data\n\
Agentless discovery per IP: TCP connect probe of common ports (a refused connection still proves the host is up), \
ICMP ping via the OS (TTL hints the OS), NetBIOS node status on UDP 137 (Windows name, domain, MAC), SNMP v2c GET of \
the MIB-II system group (sysName/sysDescr/sysLocation/sysContact), the local ARP cache (MACs on the same subnet, plus \
hosts that block everything else), reverse DNS, and banners (SSH/FTP/SMTP/Telnet, HTTP Server header and <title>). \
MAC prefixes map to vendors. A heuristic classifier assigns device_type and os_guess. Assets are matched across scans \
by MAC first, then IP; changes are recorded in the 'changes' dataset. A device is marked offline when a scan covering \
its IP gets no response. RustSweeper does not log in to devices, so it has no installed-software, user or patch data yet.";

fn docs(q: Option<&str>) -> Value {
    let mut sections: Vec<(String, String)> = vec![("How RustSweeper collects data".into(), DATA_MODEL_DOC.into())];
    let mut cur_title = String::from("Overview");
    let mut cur = String::new();
    for line in README.lines() {
        if let Some(t) = line.strip_prefix("## ") {
            if !cur.trim().is_empty() {
                sections.push((cur_title.clone(), cur.trim().to_string()));
            }
            cur_title = t.trim().to_string();
            cur.clear();
        } else {
            cur.push_str(line);
            cur.push('\n');
        }
    }
    if !cur.trim().is_empty() {
        sections.push((cur_title, cur.trim().to_string()));
    }
    let words: Vec<String> = q
        .unwrap_or("")
        .to_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| w.len() > 2)
        .map(String::from)
        .collect();
    let mut hits: Vec<(usize, &(String, String))> = sections
        .iter()
        .map(|s| {
            let hay = format!("{} {}", s.0, s.1).to_lowercase();
            (words.iter().filter(|w| hay.contains(w.as_str())).count(), s)
        })
        .filter(|(n, _)| words.is_empty() || *n > 0)
        .collect();
    hits.sort_by_key(|x| std::cmp::Reverse(x.0));
    let take = if words.is_empty() { usize::MAX } else { 3 };
    json!({
        "results": hits.iter().take(take).map(|(_, (t, body))| json!({ "section": t, "text": body })).collect::<Vec<_>>()
    })
}

#[cfg(test)]
mod tests;
