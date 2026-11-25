//! MCP prompts: ready-made IT workflows an assistant can run against RustSweeper.

use serde_json::{json, Value};

struct Prompt {
    name: &'static str,
    title: &'static str,
    description: &'static str,
    args: &'static [(&'static str, &'static str, bool)],
    text: &'static str,
}

const PROMPTS: &[Prompt] = &[
    Prompt {
        name: "security-exposure-review",
        title: "Security exposure review",
        description: "Find risky services (remote access, clear-text protocols, SMB, databases, medical interfaces) and summarise what to fix first.",
        args: &[],
        text: "Run a network security exposure review using RustSweeper.\n\
1. Run the catalog queries remote-access-exposed, telnet-ftp-cleartext, smb-exposed, database-ports and medical-interfaces (page with offset if has_more is true).\n\
2. Group findings by risk: clear-text admin protocols first, then remote access on workstations, then anything unexpected on printers/IoT.\n\
3. For each finding list the asset name, IP, device type and port, and say why it matters.\n\
4. Finish with a short prioritised remediation list. Do not invent assets that the tools did not return.",
    },
    Prompt {
        name: "new-device-review",
        title: "New & unidentified device review",
        description: "Review devices discovered recently and anything unidentified, to spot rogue or shadow-IT hardware.",
        args: &[("days", "Look-back window in days (default 7)", false)],
        text: "Review new and unidentified devices with RustSweeper.\n\
1. Query assets with first_seen >= now-{days}d (sorted newest first) and run the unknown-devices and randomized-macs catalog queries.\n\
2. For each device, use vendor, open ports, names and banners to suggest what it probably is.\n\
3. Flag anything that looks out of place for a health-center network and recommend next steps (identify owner, move VLAN, block).",
    },
    Prompt {
        name: "weekly-inventory-summary",
        title: "Weekly inventory summary",
        description: "A management-ready summary: totals, breakdowns, changes, offline devices.",
        args: &[],
        text: "Write a weekly IT inventory summary from RustSweeper.\n\
Use: assets-by-type, assets-by-os, assets-by-vendor, new-assets-7d, offline-assets, port-changes-7d and recent-scans.\n\
Report total assets and online/offline counts, the top device types and OSes, what changed this week, and any devices that need attention. Keep it to one page with a short table or two.",
    },
    Prompt {
        name: "offline-device-check",
        title: "Offline device triage",
        description: "Triage devices that went offline, starting with infrastructure and printers.",
        args: &[],
        text: "Triage offline devices with RustSweeper. Run offline-assets, then use asset_history on the most important ones (network devices, servers, printers) to see when they went offline and what else changed. Separate likely-retired devices (not seen in 30+ days) from recent outages, and suggest who should check each.",
    },
    Prompt {
        name: "asset-lookup",
        title: "Asset deep-dive",
        description: "Everything RustSweeper knows about one device.",
        args: &[("asset", "Asset id, IP address or name", true)],
        text: "Look up the device \"{asset}\" with RustSweeper's get_asset tool (by id, IP or name). Summarise its identity, type and OS, open ports and what they imply, SNMP/web details, notes, and its change history. Point out anything risky or unusual.",
    },
];

pub fn list() -> Value {
    json!({
        "prompts": PROMPTS.iter().map(|p| json!({
            "name": p.name,
            "title": p.title,
            "description": p.description,
            "arguments": p.args.iter().map(|(n, d, r)| json!({"name": n, "description": d, "required": r})).collect::<Vec<_>>(),
        })).collect::<Vec<_>>()
    })
}

pub fn get(name: &str, args: &Value) -> Option<Value> {
    let p = PROMPTS.iter().find(|p| p.name == name)?;
    let mut text = p.text.to_string();
    for (arg, _, required) in p.args {
        let v = args.get(*arg).and_then(|v| v.as_str()).map(str::to_string);
        let v = match (v, *required, *arg) {
            (Some(v), _, _) if !v.trim().is_empty() => v,
            (_, false, "days") => "7".into(),
            (_, true, _) => return None,
            _ => String::new(),
        };
        text = text.replace(&format!("{{{arg}}}"), &v);
    }
    Some(json!({
        "description": p.description,
        "messages": [{ "role": "user", "content": { "type": "text", "text": text } }]
    }))
}
