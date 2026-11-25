//! End-to-end tests of the MCP JSON-RPC surface against an in-memory inventory.

use serde_json::{json, Value};

use super::*;
use crate::db::Db;
use crate::scanner::{HostResult, OpenPort, ScanOptions};

fn host(ip: &str, name: &str, mac: &str, dtype: &str, os: &str, ports: &[u16]) -> HostResult {
    HostResult {
        ip: ip.parse().unwrap(),
        alive: true,
        netbios_name: Some(name.into()),
        mac: Some(mac.into()),
        vendor: crate::scanner::oui::lookup(mac),
        device_type: Some(dtype.into()),
        os_guess: Some(os.into()),
        ports: ports.iter().map(|&p| OpenPort { port: p, service: Some(crate::scanner::probe::service_name(p).into()), banner: None }).collect(),
        ..Default::default()
    }
}

fn server(allow_scans: bool) -> McpServer {
    let db = Db::open(":memory:").unwrap();
    let scan = db.create_scan_for_site("10.0.0.0/24", "test", None).unwrap();
    for h in [
        host("10.0.0.10", "FRONTDESK-01", "00:14:22:00:00:01", "Windows Workstation", "Windows", &[135, 445, 3389]),
        host("10.0.0.11", "FRONTDESK-02", "00:14:22:00:00:02", "Windows Workstation", "Windows", &[135, 445]),
        host("10.0.0.2", "DC01", "00:50:56:00:00:03", "Windows Domain Controller (VM)", "Windows", &[53, 88, 389, 445]),
        host("10.0.0.50", "NPI-LOBBY", "00:17:A4:00:00:04", "Printer", "Network OS (TTL)", &[80, 9100, 23]),
        host("10.0.0.60", "PACS", "00:25:90:00:00:05", "Medical / HL7-DICOM", "Linux/Unix", &[22, 104]),
    ] {
        db.record_host(scan, &h).unwrap();
    }
    db.finish_scan(scan, "completed", 254, 5, 5, None).unwrap();
    McpServer::new(crate::web::AppState::new(db, ScanOptions::default(), None), allow_scans)
}

async fn rpc(s: &McpServer, method: &str, params: Value) -> Value {
    let ctx = CallContext { transport: "test", client: Some("tester".into()), remote_addr: None, scope: crate::query::Scope::all() };
    s.handle(json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}), &ctx).await.unwrap()
}

async fn tool(s: &McpServer, name: &str, args: Value) -> Value {
    let r = rpc(s, "tools/call", json!({"name": name, "arguments": args})).await;
    assert_eq!(r["result"]["isError"], false, "{name} failed: {r}");
    r["result"]["structuredContent"].clone()
}

#[tokio::test]
async fn initialize_and_list() {
    let s = server(false);
    let r = rpc(&s, "initialize", json!({"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}})).await;
    assert_eq!(r["result"]["protocolVersion"], "2025-06-18");
    assert_eq!(r["result"]["serverInfo"]["name"], "rustsweeper");
    let r = rpc(&s, "initialize", json!({"protocolVersion":"1999-01-01"})).await;
    assert_eq!(r["result"]["protocolVersion"], FALLBACK_VERSION);

    let tools = rpc(&s, "tools/list", json!({})).await;
    let names: Vec<&str> = tools["result"]["tools"].as_array().unwrap().iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert!(names.contains(&"execute_query") && names.contains(&"list_sites"));
    assert!(!names.contains(&"start_scan"), "read-only by default");
    let with_scans = server(true);
    let tools = rpc(&with_scans, "tools/list", json!({})).await;
    assert!(tools["result"]["tools"].as_array().unwrap().iter().any(|t| t["name"] == "start_scan"));

    // Notifications get no reply; unknown methods get -32601.
    let ctx = CallContext::default();
    assert!(s.handle(json!({"jsonrpc":"2.0","method":"notifications/initialized"}), &ctx).await.is_none());
    assert_eq!(rpc(&s, "nope", json!({})).await["error"]["code"], METHOD_NOT_FOUND);
    // start_scan is not callable when disabled.
    let r = rpc(&s, "tools/call", json!({"name":"start_scan","arguments":{"targets":"10.0.0.1"}})).await;
    assert_eq!(r["error"]["code"], INVALID_PARAMS);
}

#[tokio::test]
async fn sites_and_datasets() {
    let s = server(false);
    // No sites defined yet: everything is "Unassigned", grouped by observed subnet.
    let r = tool(&s, "list_sites", json!({})).await;
    assert_eq!(r["sites"][0]["name"], "Unassigned");
    assert_eq!(r["sites"][0]["asset_count"], 5);
    assert_eq!(r["sites"][0]["observed_subnets"][0]["subnet"], "10.0.0.0/24");
    let r = tool(&s, "search_datasets", json!({"keyword":"snmp"})).await;
    assert_eq!(r["datasets"][0]["dataset"], "assets");
}

#[tokio::test]
async fn structured_queries() {
    let s = server(false);
    // Cross-domain: assets with RDP or Telnet open.
    let r = tool(&s, "execute_query", json!({"dataset":"assets","filters":[{"field":"has_port","op":"in","value":[3389,23]}],"fields":["name","port_list"]})).await;
    assert_eq!(r["total"], 2);
    assert_eq!(r["rows"][0]["name"], "FRONTDESK-01");
    assert_eq!(r["rows"][0]["port_list"], "135,445,3389");

    // Numeric IP sort: 10.0.0.2 before 10.0.0.10.
    let r = tool(&s, "execute_query", json!({"dataset":"assets","fields":["ip"],"sort":{"field":"ip"}})).await;
    assert_eq!(r["rows"][0]["ip"], "10.0.0.2");

    // Limit capping and paging.
    let r = tool(&s, "execute_query", json!({"dataset":"ports","limit":500})).await;
    assert_eq!(r["returned"], 14); // all 14 ports (under the 20 cap)
    let r = tool(&s, "execute_query", json!({"dataset":"ports","limit":500,"filters":[{"field":"port","op":"gte","value":1}]})).await;
    assert!(r["returned"].as_i64().unwrap() <= MCP_LIMITS.max);
    let r = tool(&s, "execute_query", json!({"dataset":"ports","limit":5,"offset":5})).await;
    assert_eq!(r["returned"], 5);
    assert_eq!(r["has_more"], true);

    // group_by
    let r = tool(&s, "execute_query", json!({"dataset":"assets","group_by":"device_type"})).await;
    assert_eq!(r["groups"][0]["device_type"], "Windows Workstation");
    assert_eq!(r["groups"][0]["count"], 2);

    // contains + relative time + OR
    let r = tool(&s, "execute_query", json!({"dataset":"assets","match_any":true,"filters":[
        {"field":"name","op":"contains","value":"desk"},{"field":"vendor","op":"eq","value":"VMware"}]})).await;
    assert_eq!(r["total"], 3);
    let r = tool(&s, "execute_query", json!({"dataset":"assets","filters":[{"field":"first_seen","op":"gte","value":"now-1h"}]})).await;
    assert_eq!(r["total"], 5);

    // Injection attempts are rejected as unknown fields/operators, never executed.
    let ctx = CallContext::default();
    for bad in [
        json!({"dataset":"assets","fields":["ip; DROP TABLE assets"]}),
        json!({"dataset":"assets","filters":[{"field":"ip","op":"= 1 OR 1=1 --","value":"x"}]}),
        json!({"dataset":"assets","sort":{"field":"ip DESC; --"}}),
        json!({"dataset":"sqlite_master"}),
    ] {
        let r = s.handle(json!({"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"execute_query","arguments":bad}}), &ctx).await.unwrap();
        assert_eq!(r["result"]["isError"], true, "{r}");
    }
    // LIKE wildcards are literal.
    let r = tool(&s, "execute_query", json!({"dataset":"assets","filters":[{"field":"name","op":"contains","value":"%"}]})).await;
    assert_eq!(r["total"], 0);
}

#[tokio::test]
async fn catalog_assets_docs_prompts() {
    let s = server(false);
    let r = tool(&s, "search_query_catalog", json!({"query":"hl7 dicom medical"})).await;
    assert_eq!(r["templates"][0]["id"], "medical-interfaces");
    let r = tool(&s, "search_query_catalog", json!({"run_id":"medical-interfaces"})).await;
    assert_eq!(r["result"]["rows"][0]["asset_name"], "PACS");
    let r = tool(&s, "search_query_catalog", json!({"run_id":"telnet-ftp-cleartext"})).await;
    assert_eq!(r["result"]["total"], 1);

    let r = tool(&s, "get_asset", json!({"name":"dc01"})).await;
    assert_eq!(r["asset"]["ip"], "10.0.0.2");
    assert_eq!(r["ports"].as_array().unwrap().len(), 4);
    let r = tool(&s, "get_asset", json!({"name":"frontdesk"})).await;
    assert_eq!(r["ambiguous"], true);
    let id = tool(&s, "get_asset", json!({"ip":"10.0.0.50"})).await["asset"]["id"].as_i64().unwrap();
    let r = tool(&s, "asset_history", json!({"asset_id": id})).await;
    assert_eq!(r["changes"][0]["field"], "discovered");
    let r = tool(&s, "scan_status", json!({})).await;
    assert_eq!(r["scan"]["status"], "completed");
    let r = tool(&s, "docs", json!({"query":"netbios snmp"})).await;
    assert!(!r["results"].as_array().unwrap().is_empty());

    let r = rpc(&s, "prompts/list", json!({})).await;
    assert!(r["result"]["prompts"].as_array().unwrap().len() >= 5);
    let r = rpc(&s, "prompts/get", json!({"name":"asset-lookup","arguments":{"asset":"DC01"}})).await;
    assert!(r["result"]["messages"][0]["content"]["text"].as_str().unwrap().contains("DC01"));
    let r = rpc(&s, "prompts/get", json!({"name":"asset-lookup","arguments":{}})).await;
    assert_eq!(r["error"]["code"], INVALID_PARAMS);
    let r = rpc(&s, "prompts/get", json!({"name":"new-device-review"})).await;
    assert!(r["result"]["messages"][0]["content"]["text"].as_str().unwrap().contains("now-7d"));
}

/// Two sites: Main Clinic 10.0.0.0/26 (.2 .10 .11 .50, and .60 if nothing more specific) and Imaging 10.0.0.60/32 (PACS).
fn with_sites(s: &McpServer) -> (i64, i64) {
    let db = &s.state.db;
    let main = db.add_site("Main Clinic", "10.0.0.0/26", "").unwrap();
    let imaging = db.add_site("Imaging", "10.0.0.60/32", "").unwrap();
    (main, imaging)
}

fn scoped(sites: Option<Vec<i64>>) -> CallContext {
    CallContext { transport: "test", client: Some("scoped".into()), remote_addr: None, scope: crate::query::Scope { sites } }
}

async fn tool_as(s: &McpServer, ctx: &CallContext, name: &str, args: Value) -> Value {
    s.handle(json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":name,"arguments":args}}), ctx).await.unwrap()["result"].clone()
}

#[tokio::test]
async fn sites_assignment_and_site_filter() {
    let s = server(false);
    let (main, imaging) = with_sites(&s);
    let r = tool(&s, "list_sites", json!({})).await;
    let names: Vec<&str> = r["sites"].as_array().unwrap().iter().map(|x| x["name"].as_str().unwrap()).collect();
    assert_eq!(names, vec!["Imaging", "Main Clinic"], "no Unassigned entry when everything is placed");
    assert_eq!(r["sites"][1]["asset_count"], 4);

    let r = tool(&s, "execute_query", json!({"dataset":"assets","site":"main clinic","fields":["name","site"]})).await;
    assert_eq!(r["total"], 4);
    assert_eq!(r["rows"][0]["site"], "Main Clinic");
    let r = tool(&s, "execute_query", json!({"dataset":"ports","site": imaging})).await;
    assert_eq!(r["total"], 2);
    let r = tool(&s, "search_query_catalog", json!({"run_id":"assets-by-type","site":"Imaging"})).await;
    assert_eq!(r["result"]["groups"][0]["device_type"], "Medical / HL7-DICOM");
    let r = tool(&s, "execute_query", json!({"dataset":"assets","group_by":"site"})).await;
    assert_eq!(r["groups"][0]["site"], "Main Clinic");

    // Manual pin survives re-assignment; deleting a site unassigns its assets.
    let pacs = s.state.db.list_assets(&crate::db::AssetFilter { q: Some("PACS".into()), ..Default::default() }).unwrap()[0].id;
    s.state.db.set_asset_site(pacs, Some(main)).unwrap();
    s.state.db.reassign_sites().unwrap();
    assert_eq!(s.state.db.get_asset(pacs).unwrap().unwrap().site_id, Some(main));
    s.state.db.set_asset_site(pacs, None).unwrap();
    assert_eq!(s.state.db.get_asset(pacs).unwrap().unwrap().site_id, Some(imaging));
    // Deleting the more specific site falls back to the broader one (10.0.0.0/26 covers .60)…
    s.state.db.delete_site(imaging).unwrap();
    assert_eq!(s.state.db.get_asset(pacs).unwrap().unwrap().site_id, Some(main));
    // …and deleting that leaves everything unassigned.
    s.state.db.delete_site(main).unwrap();
    assert_eq!(s.state.db.get_asset(pacs).unwrap().unwrap().site_id, None);
    let r = tool(&s, "execute_query", json!({"dataset":"assets","site":"unassigned"})).await;
    assert_eq!(r["total"], 5);
}

#[tokio::test]
async fn site_scoped_tokens_are_enforced() {
    let s = server(true);
    let (main, imaging) = with_sites(&s);
    let ctx = scoped(Some(vec![imaging]));

    let r = tool_as(&s, &ctx, "list_sites", json!({})).await;
    assert_eq!(r["structuredContent"]["sites"].as_array().unwrap().len(), 1);
    assert_eq!(r["structuredContent"]["sites"][0]["name"], "Imaging");

    // Every dataset is filtered to the token's sites, even without a site argument.
    let r = tool_as(&s, &ctx, "execute_query", json!({"dataset":"assets"})).await;
    assert_eq!(r["structuredContent"]["total"], 1);
    let r = tool_as(&s, &ctx, "execute_query", json!({"dataset":"ports","match_any":true,
        "filters":[{"field":"port","op":"eq","value":3389},{"field":"port","op":"eq","value":104}]})).await;
    assert_eq!(r["structuredContent"]["total"], 1, "OR filters can't escape the scope");
    let r = tool_as(&s, &ctx, "execute_query", json!({"dataset":"changes","group_by":"asset_name"})).await;
    assert_eq!(r["structuredContent"]["total_groups"], 1);
    let r = tool_as(&s, &ctx, "execute_query", json!({"dataset":"scans"})).await;
    assert_eq!(r["structuredContent"]["total"], 0, "unscoped scans are hidden");

    // Asking for another site, unassigned assets, or another site's device is refused.
    assert_eq!(tool_as(&s, &ctx, "execute_query", json!({"dataset":"assets","site": main})).await["isError"], true);
    assert_eq!(tool_as(&s, &ctx, "execute_query", json!({"dataset":"assets","site":"unassigned"})).await["isError"], true);
    assert_eq!(tool_as(&s, &ctx, "get_asset", json!({"name":"DC01"})).await["isError"], true);
    let dc = s.state.db.list_assets(&crate::db::AssetFilter { q: Some("DC01".into()), ..Default::default() }).unwrap()[0].id;
    assert_eq!(tool_as(&s, &ctx, "get_asset", json!({"id": dc})).await["isError"], true);
    assert_eq!(tool_as(&s, &ctx, "asset_history", json!({"asset_id": dc})).await["isError"], true);
    assert_eq!(tool_as(&s, &ctx, "get_asset", json!({"name":"PACS"})).await["isError"], false);
    assert_eq!(tool_as(&s, &ctx, "scan_status", json!({})).await["isError"], true);
    assert_eq!(tool_as(&s, &ctx, "start_scan", json!({"targets":"10.0.0.60"})).await["isError"], true);

    // A token whose sites were all deleted sees nothing.
    let none = scoped(Some(vec![]));
    assert_eq!(tool_as(&s, &none, "execute_query", json!({"dataset":"assets"})).await["structuredContent"]["total"], 0);
}
