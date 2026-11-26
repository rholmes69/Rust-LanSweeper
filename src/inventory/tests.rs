use super::*;
use crate::db::AssetFilter;
use crate::scanner::{HostResult, OpenPort};

/// Shaped like real Windows PowerShell 5.1 `ConvertTo-Json -Compress` output of collect.ps1,
/// including a single-object `disks` (PS 5.1 quirk) and a warning line before the JSON.
const SAMPLE: &str = r#"WARNING: The names of some imported commands include unapproved verbs.
{"ok":true,"computer_name":"FRONTDESK-01","domain":"delta.local","part_of_domain":true,"manufacturer":"Dell Inc.","model":"OptiPlex 7090","system_type":"x64-based PC","last_user":"DELTA\\jdoe","memory_bytes":17007370240,"logical_processors":12,"serial_number":"7XK2QF3","bios_version":"1.21.0","bios_date":"2023-08-14 00:00:00","os_name":"Microsoft Windows 10 Pro","os_version":"10.0.19045","os_build":"19045","os_arch":"64-bit","os_install_date":"2021-03-02 09:15:44","last_boot":"2026-10-01 07:58:12","cpu":"Intel(R) Core(TM) i5-10505 CPU @ 3.20GHz","cpu_count":1,"cores":6,"disks":{"drive":"C:","filesystem":"NTFS","size_bytes":255369482240,"free_bytes":18200000000},"nics":[{"description":"Intel(R) Ethernet Connection (17) I219-LM","mac":"00:14:22:00:00:01","ips":["10.0.0.10","fe80::1"]}]}
"#;

#[test]
fn parses_collector_output() {
    let inv = parse_output(SAMPLE).unwrap();
    assert_eq!(inv.computer_name.as_deref(), Some("FRONTDESK-01"));
    assert_eq!(inv.last_user.as_deref(), Some("DELTA\\jdoe"));
    assert_eq!(inv.memory_mb(), Some(16219));
    assert_eq!(inv.disks.len(), 1, "single object accepted as a one-element list");
    assert_eq!(inv.min_free_pct(), Some(7.1));
    assert_eq!(inv.nics[0].ips, vec!["10.0.0.10", "fe80::1"]);
    assert!(!inv.is_server() && !inv.is_virtual());
    assert_eq!(inv.real_serial().as_deref(), Some("7XK2QF3"));

    // A NIC whose IPAddress came back as a bare string.
    let one = r#"{"ok":true,"nics":{"description":"x","mac":"AA","ips":"10.1.1.1"},"disks":null}"#;
    let inv = parse_output(one).unwrap();
    assert_eq!(inv.nics[0].ips, vec!["10.1.1.1"]);
    assert!(inv.disks.is_empty());
}

#[test]
fn categorises_failures() {
    let denied = r#"{"ok":false,"stage":"connect","error":"Access is denied. "}"#;
    assert!(matches!(parse_output(denied), Err(CollectError::AccessDenied(_))));
    let rpc = r#"{"ok":false,"stage":"connect","error":"WinRM cannot complete the operation. The RPC server is unavailable. (0x800706BA)"}"#;
    assert!(matches!(parse_output(rpc), Err(CollectError::Unreachable(_))));
    let other = r#"{"ok":false,"stage":"query","error":"Invalid class"}"#;
    assert!(matches!(parse_output(other), Err(CollectError::Other(m)) if m.contains("query")));
    assert!(matches!(parse_output("garbage"), Err(CollectError::Other(m)) if m.contains("no JSON")));
}

#[test]
fn placeholders_and_vm_detection() {
    let inv = WinInventory {
        serial_number: Some("To be filled by O.E.M.".into()),
        manufacturer: Some("VMware, Inc.".into()),
        model: Some("VMware7,1".into()),
        os_name: Some("Microsoft Windows Server 2022 Standard".into()),
        ..Default::default()
    };
    assert!(inv.real_serial().is_none());
    assert!(inv.is_virtual() && inv.is_server());
}

#[test]
fn encoded_command_is_utf16le_base64() {
    let enc = encode_command("Get-Date");
    let raw = base64::engine::general_purpose::STANDARD.decode(enc).unwrap();
    let units: Vec<u16> = raw.chunks(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    assert_eq!(String::from_utf16(&units).unwrap(), "Get-Date");
    // The collector script must fit comfortably within Windows' command-line limit (32,767 chars).
    assert!(encode_command(COLLECT_PS).len() < 24_000);
}

#[test]
fn collector_script_contract() {
    // The Rust side depends on these names; keep script and struct in sync.
    for key in ["ok", "stage", "error", "computer_name", "last_user", "memory_bytes", "serial_number", "os_name", "os_build",
        "last_boot", "disks", "nics", "RSW_TARGET", "RSW_USER", "RSW_SECRET", "RSW_PROTOCOL", "LocalMachine", "'RustSweeper'"] {
        assert!(COLLECT_PS.contains(key), "collect.ps1 is missing {key}");
    }
    assert!(PROTECT_PS.contains("LocalMachine") && PROTECT_PS.contains("'RustSweeper'"), "same DPAPI scope/entropy both ways");
    // Balanced braces/parens — a cheap guard against a broken edit (no PowerShell in CI).
    for (o, c) in [('{', '}'), ('(', ')')] {
        assert_eq!(COLLECT_PS.matches(o).count(), COLLECT_PS.matches(c).count(), "unbalanced {o}{c} in collect.ps1");
    }
}

fn cred(id: i64, site: Option<i64>) -> Credential {
    Credential { id, name: format!("c{id}"), kind: "windows".into(), username: "u".into(), secret: "s".into(), site_id: site, site: None, created_at: String::new(), last_success: None }
}

#[test]
fn credential_order_prefers_last_success_then_site_then_global() {
    let creds = vec![cred(1, None), cred(2, Some(7)), cred(3, Some(8)), cred(4, None)];
    let a = Asset { site_id: Some(7), ..Default::default() };
    let ids = |v: Vec<Option<Credential>>| v.into_iter().map(|c| c.map(|c| c.id)).collect::<Vec<_>>();
    assert_eq!(ids(credential_order(&creds, &a, None, true)), vec![Some(2), Some(1), Some(4), None]);
    assert_eq!(ids(credential_order(&creds, &a, Some(4), false)), vec![Some(4), Some(2), Some(1)]);
    // A remembered credential scoped to another site is not used.
    assert_eq!(ids(credential_order(&creds, &a, Some(3), false)), vec![Some(2), Some(1), Some(4)]);
}

fn seeded() -> (Db, i64) {
    let db = Db::open(":memory:").unwrap();
    let scan = db.create_scan_for_site("10.0.0.0/24", "test", None).unwrap();
    let h = HostResult {
        ip: "10.0.0.10".parse().unwrap(),
        alive: true,
        netbios_name: Some("FRONTDESK-01".into()),
        mac: Some("00:14:22:00:00:01".into()),
        os_guess: Some("Windows".into()),
        device_type: Some("Windows Workstation".into()),
        ports: vec![OpenPort { port: 445, service: None, banner: None }],
        ..Default::default()
    };
    let (id, _) = db.record_host(scan, &h).unwrap();
    (db, id)
}

#[test]
fn saving_inventory_updates_asset_and_history() {
    let (db, id) = seeded();
    assert!(is_candidate(&db.get_asset(id).unwrap().unwrap()));
    // IT already entered a model; inventory must not overwrite it, but fills the blank serial.
    db.update_asset_fields(id, &[("model".into(), Some("OptiPlex (front desk)".into()))]).unwrap();
    let inv = parse_output(SAMPLE).unwrap();
    db.save_windows_inventory(id, &inv, None, "service account").unwrap();
    let a = db.get_asset(id).unwrap().unwrap();
    assert_eq!(a.model.as_deref(), Some("OptiPlex (front desk)"));
    assert_eq!(a.serial_number.as_deref(), Some("7XK2QF3"));
    assert_eq!(a.manufacturer.as_deref(), Some("Dell Inc."));
    assert_eq!(a.os_guess.as_deref(), Some("Microsoft Windows 10 Pro"));
    assert_eq!(a.inventory_status.as_deref(), Some("ok"));
    let w = db.windows_inventory(id).unwrap().unwrap();
    assert_eq!(w["last_user"], "DELTA\\jdoe");
    assert_eq!(w["disks"][0]["drive"], "C:");

    // A later scan's fingerprint doesn't clobber the inventoried OS/type.
    let scan = db.create_scan_for_site("x", "test", None).unwrap();
    let h = HostResult { ip: "10.0.0.10".parse().unwrap(), alive: true, mac: Some("00:14:22:00:00:01".into()),
        os_guess: Some("Windows (TTL)".into()), device_type: Some("Windows Server".into()), ..Default::default() };
    db.record_host(scan, &h).unwrap();
    let a = db.get_asset(id).unwrap().unwrap();
    assert_eq!(a.os_guess.as_deref(), Some("Microsoft Windows 10 Pro"));
    assert_eq!(a.device_type.as_deref(), Some("Windows Workstation"));

    // Re-inventory after an upgrade logs the change.
    let mut upgraded = inv.clone();
    upgraded.os_name = Some("Microsoft Windows 11 Pro".into());
    upgraded.os_build = Some("26100".into());
    db.save_windows_inventory(id, &upgraded, None, "service account").unwrap();
    let changes = db.changes(Some(id), 50).unwrap();
    assert!(changes.iter().any(|c| c.field == "windows: os" && c.new_value.as_deref() == Some("Microsoft Windows 11 Pro")));
    assert!(changes.iter().any(|c| c.field == "windows: build" && c.old_value.as_deref() == Some("19045")));

    // Errors are tracked as "inventory problems".
    db.record_inventory_error(id, "access denied: Access is denied.").unwrap();
    let issues = db.inventory_issues(10).unwrap();
    assert_eq!(issues[0].asset_id, id);
    assert_eq!(db.get_asset(id).unwrap().unwrap().inventory_status.as_deref(), Some("error"));
}

#[tokio::test]
async fn non_windows_hosts_report_clearly() {
    if supported() {
        return;
    }
    let (db, id) = seeded();
    let a = db.get_asset(id).unwrap().unwrap();
    let o = inventory_asset(&db, &a, &InventoryOptions::default()).await.unwrap();
    assert!(!o.ok);
    assert!(o.message.contains("needs RustSweeper running on Windows"), "{}", o.message);
    assert!(db.list_assets(&AssetFilter::default()).unwrap()[0].inventory_error.is_some());
    assert!(protect_secret("x").await.is_err());
}

#[tokio::test]
async fn inventory_queries_via_mcp() {
    let (db, id) = seeded();
    db.save_windows_inventory(id, &parse_output(SAMPLE).unwrap(), None, "service account").unwrap();
    let state = crate::web::AppState::new(db, crate::scanner::ScanOptions::default(), None);
    let mcp = crate::mcp::McpServer::new(state, false);
    let scope = crate::query::Scope::all();
    for (tpl, expect) in [("windows-10-end-of-support", 1), ("low-disk-space", 1), ("not-rebooted-30d", 1), ("low-memory", 0), ("logged-on-users", 1)] {
        let r = mcp.call_tool("search_query_catalog", &serde_json::json!({"run_id": tpl}), &scope).await.unwrap();
        assert_eq!(r["result"]["total"], expect, "{tpl}: {r}");
    }
    let r = mcp.call_tool("get_asset", &serde_json::json!({"id": id}), &scope).await.unwrap();
    assert_eq!(r["windows_inventory"]["cpu"], "Intel(R) Core(TM) i5-10505 CPU @ 3.20GHz");
}
