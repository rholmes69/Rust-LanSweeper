//! Streamable HTTP transport for MCP at `/mcp` (served by `rustsweeper serve`).
//!
//! * POST /mcp   — JSON-RPC request(s); replies are `application/json` (no SSE needed: the
//!   server never pushes notifications).
//! * DELETE /mcp — end the session.
//! * GET /mcp    — 405 (no server-initiated stream).
//!
//! Security: bearer API tokens (`rustsweeper token create`), sessions bound to the token that
//! created them with a 60-minute idle timeout, and Origin validation against DNS rebinding.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::body::Bytes;
use axum::extract::{ConnectInfo, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use serde_json::{json, Value};

use super::{rpc_error, CallContext, McpServer, INVALID_REQUEST, PARSE_ERROR};

pub const SESSION_HEADER: &str = "mcp-session-id";
/// Same idle timeout as Lansweeper's MCP server.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(60 * 60);
const MAX_SESSIONS: usize = 1000;
const MAX_BODY: usize = 1024 * 1024;

struct Session {
    client: Option<String>,
    last_seen: Instant,
}

pub struct HttpMcp {
    server: McpServer,
    require_auth: bool,
    idle: Duration,
    sessions: Mutex<HashMap<String, Session>>,
}

impl HttpMcp {
    pub fn new(server: McpServer, require_auth: bool) -> Arc<Self> {
        Self::with_timeout(server, require_auth, IDLE_TIMEOUT)
    }

    pub fn with_timeout(server: McpServer, require_auth: bool, idle: Duration) -> Arc<Self> {
        Arc::new(Self { server, require_auth, idle, sessions: Mutex::new(HashMap::new()) })
    }
}

pub fn router(mcp: Arc<HttpMcp>) -> Router {
    Router::new()
        .route("/mcp", post(post_mcp).delete(delete_mcp).get(get_mcp))
        .with_state(mcp)
}

fn json_error(status: StatusCode, code: i64, msg: &str) -> Response {
    (status, Json(rpc_error(&Value::Null, code, msg))).into_response()
}

/// Reject browser requests from foreign origins (DNS-rebinding protection).
fn origin_ok(headers: &HeaderMap) -> bool {
    let Some(origin) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) else {
        return true; // non-browser clients don't send Origin
    };
    let host_of = |s: &str| -> String {
        let s = s.split("://").nth(1).unwrap_or(s);
        let s = s.split('/').next().unwrap_or(s);
        // strip port (handle [::1]:8080)
        if let Some(end) = s.strip_prefix('[').and_then(|r| r.find(']')) {
            s[..end + 2].to_ascii_lowercase()
        } else {
            s.split(':').next().unwrap_or(s).to_ascii_lowercase()
        }
    };
    let o = host_of(origin);
    if matches!(o.as_str(), "localhost" | "127.0.0.1" | "[::1]") {
        return true;
    }
    headers.get(header::HOST).and_then(|v| v.to_str().ok()).is_some_and(|h| host_of(h) == o)
}

/// Returns Ok(client name) or an error response.
fn authenticate(mcp: &HttpMcp, headers: &HeaderMap) -> Result<Option<String>, Response> {
    if !mcp.require_auth {
        return Ok(Some("unauthenticated (localhost)".into()));
    }
    let presented = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer ").or_else(|| v.strip_prefix("bearer ")));
    let unauthorized = |msg: &str| {
        let mut r = json_error(StatusCode::UNAUTHORIZED, INVALID_REQUEST, msg);
        r.headers_mut().insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer realm=\"RustSweeper MCP\""));
        r
    };
    let Some(tok) = presented else {
        return Err(unauthorized("missing bearer token (create one with `rustsweeper token create <name>`)"));
    };
    match crate::auth::verify(&mcp.server.state.db, tok) {
        Ok(Some(name)) => Ok(Some(name)),
        Ok(None) => Err(unauthorized("invalid or revoked token")),
        Err(e) => {
            tracing::error!("token check failed: {e:#}");
            Err(json_error(StatusCode::INTERNAL_SERVER_ERROR, INVALID_REQUEST, "internal error"))
        }
    }
}

fn is_initialize(msg: &Value) -> bool {
    match msg {
        Value::Object(o) => o.get("method").and_then(|m| m.as_str()) == Some("initialize"),
        Value::Array(a) => a.iter().any(is_initialize),
        _ => false,
    }
}

async fn post_mcp(
    State(mcp): State<Arc<HttpMcp>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !origin_ok(&headers) {
        return json_error(StatusCode::FORBIDDEN, INVALID_REQUEST, "origin not allowed");
    }
    let client = match authenticate(&mcp, &headers) {
        Ok(c) => c,
        Err(r) => return r,
    };
    if body.len() > MAX_BODY {
        return json_error(StatusCode::PAYLOAD_TOO_LARGE, INVALID_REQUEST, "request too large");
    }
    let msg: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return json_error(StatusCode::BAD_REQUEST, PARSE_ERROR, &format!("parse error: {e}")),
    };

    let init = is_initialize(&msg);
    let session_id = headers.get(SESSION_HEADER).and_then(|v| v.to_str().ok()).map(str::to_string);
    {
        let mut sessions = mcp.sessions.lock().unwrap();
        let idle = mcp.idle;
        sessions.retain(|_, s| s.last_seen.elapsed() < idle);
        if !init {
            let Some(sid) = &session_id else {
                return json_error(StatusCode::BAD_REQUEST, INVALID_REQUEST, "missing Mcp-Session-Id header; send initialize first");
            };
            match sessions.get_mut(sid) {
                // A session can only be used with the token that created it.
                Some(s) if s.client == client => s.last_seen = Instant::now(),
                _ => return json_error(StatusCode::NOT_FOUND, INVALID_REQUEST, "session not found or expired; re-initialize"),
            }
        }
    }

    let ctx = CallContext { transport: "http", client: client.clone(), remote_addr: Some(addr.ip().to_string()) };
    let reply = mcp.server.handle(msg, &ctx).await;

    let mut new_session = None;
    if init && reply.as_ref().is_some_and(|r| r.get("error").is_none()) {
        let sid = match crate::auth::random_hex(16) {
            Ok(s) => s,
            Err(e) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, INVALID_REQUEST, &format!("{e:#}")),
        };
        let mut sessions = mcp.sessions.lock().unwrap();
        if sessions.len() >= MAX_SESSIONS {
            // Evict the least recently used session.
            if let Some(oldest) = sessions.iter().min_by_key(|(_, s)| s.last_seen).map(|(k, _)| k.clone()) {
                sessions.remove(&oldest);
            }
        }
        sessions.insert(sid.clone(), Session { client, last_seen: Instant::now() });
        new_session = Some(sid);
    }

    let mut resp = match reply {
        None => StatusCode::ACCEPTED.into_response(),
        Some(r) => (StatusCode::OK, Json(r)).into_response(),
    };
    if let Some(sid) = new_session {
        if let Ok(v) = HeaderValue::from_str(&sid) {
            resp.headers_mut().insert(SESSION_HEADER, v);
        }
    }
    resp
}

async fn delete_mcp(State(mcp): State<Arc<HttpMcp>>, headers: HeaderMap) -> Response {
    if !origin_ok(&headers) {
        return json_error(StatusCode::FORBIDDEN, INVALID_REQUEST, "origin not allowed");
    }
    let client = match authenticate(&mcp, &headers) {
        Ok(c) => c,
        Err(r) => return r,
    };
    let Some(sid) = headers.get(SESSION_HEADER).and_then(|v| v.to_str().ok()) else {
        return json_error(StatusCode::BAD_REQUEST, INVALID_REQUEST, "missing Mcp-Session-Id");
    };
    let mut sessions = mcp.sessions.lock().unwrap();
    match sessions.get(sid) {
        Some(s) if s.client == client => {
            sessions.remove(sid);
            StatusCode::NO_CONTENT.into_response()
        }
        _ => json_error(StatusCode::NOT_FOUND, INVALID_REQUEST, "session not found"),
    }
}

async fn get_mcp() -> Response {
    let mut r = (StatusCode::METHOD_NOT_ALLOWED, Json(json!({"error": "this server does not offer an SSE stream; use POST"}))).into_response();
    r.headers_mut().insert(header::ALLOW, HeaderValue::from_static("POST, DELETE"));
    r
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;
    use crate::scanner::ScanOptions;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    fn app(require_auth: bool, idle: Duration) -> (Router, Db) {
        let db = Db::open(":memory:").unwrap();
        let state = crate::web::AppState::new(db.clone(), ScanOptions::default(), None);
        let mcp = HttpMcp::with_timeout(McpServer::new(state, false), require_auth, idle);
        (router(mcp), db)
    }

    async fn call(app: &Router, token: Option<&str>, session: Option<&str>, origin: Option<&str>, body: Value) -> (StatusCode, HeaderMap, Value) {
        let mut req = Request::post("/mcp").header("content-type", "application/json").header("host", "inventory.local:8080");
        if let Some(t) = token {
            req = req.header("authorization", format!("Bearer {t}"));
        }
        if let Some(s) = session {
            req = req.header(SESSION_HEADER, s);
        }
        if let Some(o) = origin {
            req = req.header("origin", o);
        }
        let mut req = req.body(Body::from(body.to_string())).unwrap();
        req.extensions_mut().insert(ConnectInfo(SocketAddr::from(([10, 0, 0, 9], 5555))));
        let resp = app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let headers = resp.headers().clone();
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        (status, headers, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
    }

    fn init() -> Value {
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","clientInfo":{"name":"t","version":"1"}}})
    }
    fn list() -> Value {
        json!({"jsonrpc":"2.0","id":2,"method":"tools/list"})
    }

    #[tokio::test]
    async fn auth_sessions_audit() {
        let (app, db) = app(true, IDLE_TIMEOUT);
        let (_, tok) = crate::auth::create(&db, "claude").unwrap();
        let (_, tok2) = crate::auth::create(&db, "cursor").unwrap();

        // No / bad token.
        assert_eq!(call(&app, None, None, None, init()).await.0, StatusCode::UNAUTHORIZED);
        assert_eq!(call(&app, Some("rsw_bad"), None, None, init()).await.0, StatusCode::UNAUTHORIZED);

        // Initialize → session id.
        let (st, h, body) = call(&app, Some(&tok), None, None, init()).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(body["result"]["serverInfo"]["name"], "rustsweeper");
        let sid = h.get(SESSION_HEADER).unwrap().to_str().unwrap().to_string();

        // Requests need the session, and only work with the same token.
        assert_eq!(call(&app, Some(&tok), None, None, list()).await.0, StatusCode::BAD_REQUEST);
        assert_eq!(call(&app, Some(&tok), Some("nope"), None, list()).await.0, StatusCode::NOT_FOUND);
        assert_eq!(call(&app, Some(&tok2), Some(&sid), None, list()).await.0, StatusCode::NOT_FOUND);
        let (st, _, body) = call(&app, Some(&tok), Some(&sid), None, list()).await;
        assert_eq!(st, StatusCode::OK);
        assert!(body["result"]["tools"].as_array().unwrap().len() >= 8);

        // Notifications → 202.
        let (st, _, _) = call(&app, Some(&tok), Some(&sid), None, json!({"jsonrpc":"2.0","method":"notifications/initialized"})).await;
        assert_eq!(st, StatusCode::ACCEPTED);

        // Tool call is audited with the token name and client IP.
        call(&app, Some(&tok), Some(&sid), None, json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"execute_query","arguments":{"dataset":"assets"}}})).await;
        let audit = db.list_audit(10).unwrap();
        let entry = audit.iter().find(|a| a.tool.as_deref() == Some("execute_query")).unwrap();
        assert_eq!(entry.client.as_deref(), Some("claude"));
        assert_eq!(entry.remote_addr.as_deref(), Some("10.0.0.9"));
        assert!(entry.ok);

        // Foreign Origin rejected; same-host and localhost origins allowed.
        assert_eq!(call(&app, Some(&tok), Some(&sid), Some("https://evil.example"), list()).await.0, StatusCode::FORBIDDEN);
        assert_eq!(call(&app, Some(&tok), Some(&sid), Some("http://inventory.local:8080"), list()).await.0, StatusCode::OK);
        assert_eq!(call(&app, Some(&tok), Some(&sid), Some("http://localhost:6274"), list()).await.0, StatusCode::OK);

        // Revoking the token cuts off the live session.
        db.revoke_token("claude").unwrap();
        assert_eq!(call(&app, Some(&tok), Some(&sid), None, list()).await.0, StatusCode::UNAUTHORIZED);

        // Malformed JSON.
        let mut req = Request::post("/mcp").header("authorization", format!("Bearer {tok2}")).body(Body::from("{oops")).unwrap();
        req.extensions_mut().insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 1))));
        assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn idle_timeout_and_delete() {
        let (app, db) = app(true, Duration::from_millis(50));
        let (_, tok) = crate::auth::create(&db, "t").unwrap();
        let (_, h, _) = call(&app, Some(&tok), None, None, init()).await;
        let sid = h.get(SESSION_HEADER).unwrap().to_str().unwrap().to_string();
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert_eq!(call(&app, Some(&tok), Some(&sid), None, list()).await.0, StatusCode::NOT_FOUND);

        let (_, h, _) = call(&app, Some(&tok), None, None, init()).await;
        let sid = h.get(SESSION_HEADER).unwrap().to_str().unwrap().to_string();
        let mut req = Request::delete("/mcp").header("authorization", format!("Bearer {tok}")).header(SESSION_HEADER, &sid).body(Body::empty()).unwrap();
        req.extensions_mut().insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 1))));
        assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::NO_CONTENT);
        assert_eq!(call(&app, Some(&tok), Some(&sid), None, list()).await.0, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn no_auth_mode() {
        let (app, _) = app(false, IDLE_TIMEOUT);
        let (st, h, _) = call(&app, None, None, None, init()).await;
        assert_eq!(st, StatusCode::OK);
        assert!(h.get(SESSION_HEADER).is_some());
    }
}
