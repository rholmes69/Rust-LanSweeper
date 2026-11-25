//! stdio transport: newline-delimited JSON-RPC on stdin/stdout (logs go to stderr).
//! This is how desktop clients such as Claude Desktop, Claude Code and Cursor launch local servers.

use anyhow::Result;
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use super::{rpc_error, CallContext, McpServer, PARSE_ERROR};

pub async fn serve(server: McpServer) -> Result<()> {
    let user = std::env::var("USERNAME").or_else(|_| std::env::var("USER")).ok();
    let ctx = CallContext { transport: "stdio", client: user, remote_addr: None };
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    let mut out = tokio::io::stdout();
    tracing::info!("MCP server ready on stdio (read-only{})", if server.allow_scans { ", scans enabled" } else { "" });
    while let Some(line) = lines.next_line().await? {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let reply = match serde_json::from_str::<Value>(line) {
            Ok(msg) => server.handle(msg, &ctx).await,
            Err(e) => Some(rpc_error(&Value::Null, PARSE_ERROR, format!("parse error: {e}"))),
        };
        if let Some(r) = reply {
            let mut s = serde_json::to_string(&r)?;
            s.push('\n');
            out.write_all(s.as_bytes()).await?;
            out.flush().await?;
        }
    }
    Ok(())
}
