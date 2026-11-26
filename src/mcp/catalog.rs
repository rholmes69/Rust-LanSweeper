//! Pre-built query templates (the equivalent of Lansweeper's query catalog).

use serde::Serialize;
use serde_json::{json, Value};

#[derive(Debug, Clone, Serialize)]
pub struct Template {
    pub id: &'static str,
    pub title: &'static str,
    pub description: &'static str,
    pub tags: &'static [&'static str],
    /// Ready-to-run argument for `execute_query`.
    pub query: Value,
}

pub fn templates() -> Vec<Template> {
    vec![
        Template {
            id: "remote-access-exposed",
            title: "Devices exposing remote access (RDP, VNC, Telnet)",
            description: "Assets with TCP 3389, 5900 or 23 open — review that each is expected and restricted.",
            tags: &["security", "rdp", "vnc", "telnet", "remote", "exposure"],
            query: json!({"dataset":"assets","filters":[{"field":"has_port","op":"in","value":[3389,5900,23]}],
                          "fields":["id","ip","name","device_type","os_guess","port_list","status"]}),
        },
        Template {
            id: "telnet-ftp-cleartext",
            title: "Clear-text management protocols (Telnet, FTP)",
            description: "Assets with Telnet (23) or FTP (21) open; credentials cross the network unencrypted.",
            tags: &["security", "telnet", "ftp", "cleartext", "compliance", "hipaa"],
            query: json!({"dataset":"ports","filters":[{"field":"port","op":"in","value":[21,23]}],
                          "fields":["asset_id","asset_name","ip","port","service","banner"]}),
        },
        Template {
            id: "smb-exposed",
            title: "Devices with SMB file sharing (445)",
            description: "SMB on non-Windows devices or unexpected hosts is worth checking.",
            tags: &["security", "smb", "file sharing", "445"],
            query: json!({"dataset":"assets","filters":[{"field":"has_port","op":"eq","value":445}],
                          "fields":["id","ip","name","device_type","os_guess","domain"]}),
        },
        Template {
            id: "database-ports",
            title: "Database servers (SQL Server, MySQL, PostgreSQL)",
            description: "Assets listening on 1433, 3306 or 5432.",
            tags: &["database", "sql", "mssql", "mysql", "postgres", "servers"],
            query: json!({"dataset":"ports","filters":[{"field":"port","op":"in","value":[1433,3306,5432]}],
                          "fields":["asset_id","asset_name","ip","port","service"]}),
        },
        Template {
            id: "medical-interfaces",
            title: "Medical interfaces (HL7 2575, DICOM 104)",
            description: "Systems speaking HL7 or DICOM — EHR interfaces, PACS, modalities.",
            tags: &["medical", "hl7", "dicom", "ehr", "pacs", "clinical"],
            query: json!({"dataset":"ports","filters":[{"field":"port","op":"in","value":[104,2575]}],
                          "fields":["asset_id","asset_name","ip","port","service","device_type"]}),
        },
        Template {
            id: "new-assets-7d",
            title: "New devices in the last 7 days",
            description: "Assets first discovered within the past week.",
            tags: &["new", "recent", "discovered", "rogue", "week"],
            query: json!({"dataset":"assets","filters":[{"field":"first_seen","op":"gte","value":"now-7d"}],
                          "sort":{"field":"first_seen","desc":true},
                          "fields":["id","ip","name","mac","vendor","device_type","first_seen"]}),
        },
        Template {
            id: "offline-assets",
            title: "Offline devices",
            description: "Assets that did not respond to the most recent scan covering their IP.",
            tags: &["offline", "down", "missing", "status"],
            query: json!({"dataset":"assets","filters":[{"field":"status","op":"eq","value":"offline"}],
                          "sort":{"field":"last_seen","desc":true},
                          "fields":["id","ip","name","device_type","last_seen"]}),
        },
        Template {
            id: "offline-printers",
            title: "Offline printers",
            description: "Printers that stopped responding.",
            tags: &["printer", "offline", "helpdesk"],
            query: json!({"dataset":"assets","filters":[{"field":"device_type","op":"eq","value":"Printer"},
                                                        {"field":"status","op":"eq","value":"offline"}],
                          "fields":["id","ip","name","vendor","snmp_location","last_seen"]}),
        },
        Template {
            id: "stale-30d",
            title: "Not seen in 30 days",
            description: "Candidates for retirement or inventory cleanup.",
            tags: &["stale", "lifecycle", "cleanup", "retire", "old"],
            query: json!({"dataset":"assets","filters":[{"field":"last_seen","op":"lt","value":"now-30d"}],
                          "sort":{"field":"last_seen"},
                          "fields":["id","ip","name","device_type","last_seen"]}),
        },
        Template {
            id: "unknown-devices",
            title: "Unidentified devices",
            description: "Assets with no device type or no vendor — investigate what they are.",
            tags: &["unknown", "unidentified", "rogue", "vendor", "shadow it"],
            query: json!({"dataset":"assets","match_any":true,
                          "filters":[{"field":"device_type","op":"is_null"},{"field":"vendor","op":"is_null"}],
                          "fields":["id","ip","name","mac","vendor","device_type","port_list"]}),
        },
        Template {
            id: "randomized-macs",
            title: "Devices with randomized/private MACs",
            description: "Usually phones or laptops with MAC privacy on; can't be tracked reliably by MAC.",
            tags: &["mac", "random", "private", "byod", "phones"],
            query: json!({"dataset":"assets","filters":[{"field":"vendor","op":"eq","value":"Private/randomized MAC"}],
                          "fields":["id","ip","name","mac","last_seen"]}),
        },
        Template {
            id: "port-changes-7d",
            title: "Ports opened or closed in the last 7 days",
            description: "Service changes detected between scans.",
            tags: &["changes", "ports", "drift", "security", "week"],
            query: json!({"dataset":"changes","filters":[{"field":"change","op":"in","value":["port opened","port closed"]},
                                                         {"field":"at","op":"gte","value":"now-7d"}]}),
        },
        Template {
            id: "changes-24h",
            title: "All changes in the last 24 hours",
            description: "Everything the scanner noticed changing since yesterday.",
            tags: &["changes", "today", "recent", "audit"],
            query: json!({"dataset":"changes","filters":[{"field":"at","op":"gte","value":"now-24h"}]}),
        },
        Template {
            id: "assets-by-type",
            title: "Asset count by device type",
            description: "Inventory breakdown.",
            tags: &["summary", "count", "type", "breakdown", "inventory"],
            query: json!({"dataset":"assets","group_by":"device_type","limit":20}),
        },
        Template {
            id: "assets-by-vendor",
            title: "Asset count by vendor",
            description: "Which hardware vendors are most common.",
            tags: &["summary", "count", "vendor", "manufacturer"],
            query: json!({"dataset":"assets","group_by":"vendor","limit":20}),
        },
        Template {
            id: "assets-by-os",
            title: "Asset count by operating system",
            description: "OS distribution from fingerprinting.",
            tags: &["summary", "os", "operating system", "windows", "linux"],
            query: json!({"dataset":"assets","group_by":"os_guess","limit":20}),
        },
        Template {
            id: "most-common-ports",
            title: "Most common open ports",
            description: "Which services are most widely exposed across the network.",
            tags: &["ports", "services", "summary", "exposure"],
            query: json!({"dataset":"ports","group_by":"port","limit":20}),
        },
        Template {
            id: "windows-servers",
            title: "Windows servers and domain controllers",
            description: "Windows hosts with server roles (DNS, Kerberos, LDAP, SQL, SMTP).",
            tags: &["windows", "server", "domain controller", "ad"],
            query: json!({"dataset":"assets","filters":[{"field":"device_type","op":"in","value":["Windows Server","Windows Domain Controller","Windows Server (VM)","Windows Domain Controller (VM)"]}],
                          "fields":["id","ip","name","domain","device_type","port_list"]}),
        },
        Template {
            id: "network-devices",
            title: "Network infrastructure",
            description: "Switches, routers, firewalls and access points.",
            tags: &["network", "switch", "router", "firewall", "infrastructure"],
            query: json!({"dataset":"assets","filters":[{"field":"device_type","op":"eq","value":"Network Device"}],
                          "fields":["id","ip","name","vendor","snmp_descr","snmp_location"]}),
        },
        Template {
            id: "warranty-expiring-90d",
            title: "Warranties expiring in the next 90 days",
            description: "Assets whose warranty end date falls within 90 days — plan renewals or replacements.",
            tags: &["warranty", "lifecycle", "expiring", "renewal", "replacement", "budget"],
            query: json!({"dataset":"assets","filters":[{"field":"warranty_end","op":"gte","value":"now"},
                                                        {"field":"warranty_end","op":"lte","value":"now+90d"}],
                          "sort":{"field":"warranty_end"},
                          "fields":["id","name","site","model","serial_number","owner","warranty_end"]}),
        },
        Template {
            id: "warranty-expired",
            title: "Out-of-warranty assets",
            description: "Assets whose recorded warranty end date has passed.",
            tags: &["warranty", "expired", "lifecycle", "out of warranty", "risk"],
            query: json!({"dataset":"assets","filters":[{"field":"warranty_end","op":"lt","value":"now"}],
                          "sort":{"field":"warranty_end"},
                          "fields":["id","name","site","model","owner","warranty_end"]}),
        },
        Template {
            id: "workstations-without-owner",
            title: "Workstations with no owner recorded",
            description: "Windows workstations and Apple devices missing an owner — fill in for accountability.",
            tags: &["owner", "unassigned", "accountability", "workstation", "missing", "data quality"],
            query: json!({"dataset":"assets","filters":[{"field":"owner","op":"is_null"},
                                                        {"field":"device_type","op":"in","value":["Windows Workstation","Windows Workstation (VM)","Apple Device"]}],
                          "fields":["id","ip","name","site","device_type","last_seen"]}),
        },
        Template {
            id: "assets-by-department",
            title: "Asset count by department",
            description: "How many devices each department has (from entered/imported data).",
            tags: &["department", "summary", "count", "owner", "cost"],
            query: json!({"dataset":"assets","group_by":"department","limit":20}),
        },
        Template {
            id: "manual-assets",
            title: "Manually added or imported assets",
            description: "Records not created by the scanner (added by hand, via CSV import or the API).",
            tags: &["manual", "import", "imported", "added", "source"],
            query: json!({"dataset":"assets","filters":[{"field":"source","op":"ne","value":"scanner"}],
                          "fields":["id","name","ip","mac","site","source","owner","status"]}),
        },
        Template {
            id: "arp-only-devices",
            title: "Devices visible only via ARP",
            description: "Hosts that answered ARP but blocked every probe — typical of locked-down endpoints or unknown devices.",
            tags: &["arp", "firewall", "stealth", "hidden", "locked down", "unknown"],
            query: json!({"dataset":"assets","filters":[{"field":"detected_by","op":"eq","value":"arp"}],
                          "fields":["id","ip","name","mac","vendor","site","last_seen"]}),
        },
        Template {
            id: "windows-10-end-of-support",
            title: "Windows 10 devices (out of support since Oct 14, 2025)",
            description: "Windows 10 reached end of support on October 14, 2025 — no more security updates without ESU. Plan upgrades or ESU enrolment.",
            tags: &["windows 10", "end of support", "eol", "lifecycle", "upgrade", "windows 11", "security", "compliance"],
            query: json!({"dataset":"assets","filters":[{"field":"os","op":"contains","value":"Windows 10"}],
                          "fields":["id","name","site","os","os_build","model","owner","last_user"]}),
        },
        Template {
            id: "legacy-windows",
            title: "Legacy Windows (7, 8.1, Server 2008/2012)",
            description: "Long-unsupported Windows versions that no longer receive security fixes.",
            tags: &["legacy", "windows 7", "server 2008", "server 2012", "eol", "unsupported", "risk"],
            query: json!({"dataset":"assets","match_any":true,"filters":[
                {"field":"os","op":"contains","value":"Windows 7"},{"field":"os","op":"contains","value":"Windows 8"},
                {"field":"os","op":"contains","value":"Server 2008"},{"field":"os","op":"contains","value":"Server 2012"},
                {"field":"os","op":"contains","value":"Windows XP"}],
                "fields":["id","name","site","os","device_type","owner"]}),
        },
        Template {
            id: "windows-versions",
            title: "Windows versions in use",
            description: "Count of devices per Windows edition (from credentialed inventory).",
            tags: &["windows", "versions", "os", "summary", "build"],
            query: json!({"dataset":"assets","filters":[{"field":"os_build","op":"not_null"}],"group_by":"os","limit":20}),
        },
        Template {
            id: "low-disk-space",
            title: "Low disk space (under 10% free)",
            description: "Windows devices with a fixed disk under 10% free.",
            tags: &["disk", "storage", "space", "full", "helpdesk", "performance"],
            query: json!({"dataset":"assets","filters":[{"field":"min_disk_free_pct","op":"lt","value":10}],
                          "sort":{"field":"min_disk_free_pct"},
                          "fields":["id","name","site","min_disk_free_pct","last_user"]}),
        },
        Template {
            id: "low-memory",
            title: "Devices with less than 8 GB RAM",
            description: "Upgrade or replacement candidates (Windows 11 needs 4 GB minimum; 8 GB+ recommended for clinical apps).",
            tags: &["memory", "ram", "upgrade", "performance", "hardware", "replacement"],
            query: json!({"dataset":"assets","filters":[{"field":"memory_mb","op":"lt","value":7500}],
                          "fields":["id","name","site","model","memory_mb","os"]}),
        },
        Template {
            id: "not-rebooted-30d",
            title: "Not rebooted in 30+ days",
            description: "Devices whose last boot is more than 30 days ago — updates may be pending.",
            tags: &["reboot", "uptime", "patching", "updates", "restart"],
            query: json!({"dataset":"assets","filters":[{"field":"last_boot","op":"lt","value":"now-30d"}],
                          "sort":{"field":"last_boot"},
                          "fields":["id","name","site","os","last_boot","last_user"]}),
        },
        Template {
            id: "inventory-failures",
            title: "Windows inventory failures",
            description: "Devices where credentialed inventory failed, with the reason (access denied, RPC unavailable…).",
            tags: &["errors", "scan errors", "inventory", "credentials", "access denied", "wmi", "troubleshooting"],
            query: json!({"dataset":"assets","filters":[{"field":"inventory_status","op":"eq","value":"error"}],
                          "sort":{"field":"inventory_at","desc":true},
                          "fields":["id","name","ip","site","inventory_at","inventory_error"]}),
        },
        Template {
            id: "logged-on-users",
            title: "Who is logged on where",
            description: "The user logged on to each Windows device at its last inventory.",
            tags: &["users", "logged on", "who", "last user", "workstation"],
            query: json!({"dataset":"assets","filters":[{"field":"last_user","op":"not_null"}],
                          "sort":{"field":"last_user"},
                          "fields":["id","name","site","last_user","inventory_at"]}),
        },
        Template {
            id: "most-installed-software",
            title: "Most widely installed software",
            description: "Programs on the most Windows devices (by normalised product name).",
            tags: &["software", "installed", "applications", "programs", "popular", "summary", "licensing"],
            query: json!({"dataset":"software","group_by":"product","limit":20}),
        },
        Template {
            id: "remote-access-software",
            title: "Remote-access tools installed",
            description: "TeamViewer, AnyDesk, ScreenConnect, LogMeIn, Splashtop, RustDesk, VNC and similar — confirm each is sanctioned (common ransomware entry point).",
            tags: &["remote access", "teamviewer", "anydesk", "screenconnect", "vnc", "security", "shadow it", "ransomware"],
            query: json!({"dataset":"software","match_any":true,"filters":[
                {"field":"product","op":"contains","value":"TeamViewer"},{"field":"product","op":"contains","value":"AnyDesk"},
                {"field":"product","op":"contains","value":"ScreenConnect"},{"field":"product","op":"contains","value":"ConnectWise Control"},
                {"field":"product","op":"contains","value":"LogMeIn"},{"field":"product","op":"contains","value":"Splashtop"},
                {"field":"product","op":"contains","value":"RustDesk"},{"field":"product","op":"contains","value":"VNC"},
                {"field":"product","op":"contains","value":"Chrome Remote Desktop"},{"field":"product","op":"contains","value":"GoTo"}],
                "fields":["asset_id","asset_name","site","product","version"]}),
        },
        Template {
            id: "end-of-life-software",
            title: "End-of-life software still installed",
            description: "Adobe Flash Player (EOL Dec 2020), Microsoft Silverlight (EOL Oct 2021), Internet Explorer add-ons and similar unsupported runtimes.",
            tags: &["eol", "end of life", "flash", "silverlight", "unsupported", "security", "lifecycle"],
            query: json!({"dataset":"software","match_any":true,"filters":[
                {"field":"product","op":"contains","value":"Flash Player"},{"field":"product","op":"contains","value":"Silverlight"},
                {"field":"product","op":"contains","value":"Shockwave"},{"field":"product","op":"contains","value":"QuickTime"}],
                "fields":["asset_id","asset_name","site","product","version"]}),
        },
        Template {
            id: "software-installed-7d",
            title: "Software installed, removed or updated in the last 7 days",
            description: "Software changes detected between inventories.",
            tags: &["software", "changes", "installed", "removed", "updated", "week", "drift"],
            query: json!({"dataset":"changes","filters":[{"field":"change","op":"starts_with","value":"software"},
                                                         {"field":"at","op":"gte","value":"now-7d"}]}),
        },
        Template {
            id: "stopped-auto-services",
            title: "Automatic services that aren't running",
            description: "Services set to start automatically but currently stopped — often a sign of a failing app or agent (AV, backup, EHR client).",
            tags: &["services", "stopped", "failed", "automatic", "health", "troubleshooting", "monitoring"],
            query: json!({"dataset":"services","filters":[{"field":"start_mode","op":"eq","value":"Auto"},
                {"field":"state","op":"ne","value":"Running"},
                {"field":"name","op":"not_in","value":["gupdate","edgeupdate","sppsvc","RemoteRegistry","MapsBroker","TrustedInstaller","WbioSrvc","clr_optimization_v4.0.30319_32","clr_optimization_v4.0.30319_64","GoogleUpdaterService","MozillaMaintenance","tiledatamodelsvc","sedsvc","ShellHWDetection","BITS","wuauserv","UsoSvc","CDPSvc","WinDefend"]}],
                "fields":["asset_id","asset_name","site","name","display_name","state"]}),
        },
        Template {
            id: "unquoted-service-paths",
            title: "Services with unquoted paths",
            description: "Executable paths with spaces and no quotes let a local user plant a program that runs as the service account — a common audit finding.",
            tags: &["services", "unquoted", "privilege escalation", "security", "audit", "vulnerability"],
            query: json!({"dataset":"services","filters":[{"field":"unquoted_path","op":"eq","value":1}],
                          "fields":["asset_id","asset_name","name","start_name","path"]}),
        },
        Template {
            id: "services-with-user-accounts",
            title: "Services running as user/domain accounts",
            description: "Services that log on with a real account — their passwords sit in LSA secrets and are worth tracking and rotating.",
            tags: &["services", "service accounts", "credentials", "security", "passwords", "audit"],
            query: json!({"dataset":"services","filters":[{"field":"custom_account","op":"eq","value":1}],
                          "fields":["asset_id","asset_name","name","display_name","start_name","state"]}),
        },
        Template {
            id: "recent-scans",
            title: "Recent scans",
            description: "Latest scan runs and their results.",
            tags: &["scans", "history", "status"],
            query: json!({"dataset":"scans"}),
        },
    ]
}

/// Keyword search across ids, titles, descriptions and tags. Empty query returns everything.
pub fn search(q: Option<&str>) -> Vec<Template> {
    let all = templates();
    let words: Vec<String> = q
        .unwrap_or("")
        .to_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| w.len() > 1)
        .map(String::from)
        .collect();
    if words.is_empty() {
        return all;
    }
    let mut scored: Vec<(usize, Template)> = all
        .into_iter()
        .filter_map(|t| {
            let hay = format!("{} {} {} {}", t.id, t.title, t.description, t.tags.join(" ")).to_lowercase();
            let score = words.iter().filter(|w| hay.contains(w.as_str())).count();
            (score > 0).then_some((score, t))
        })
        .collect();
    scored.sort_by_key(|x| std::cmp::Reverse(x.0));
    scored.into_iter().map(|(_, t)| t).collect()
}

pub fn get(id: &str) -> Option<Template> {
    templates().into_iter().find(|t| t.id == id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_template_parses() {
        for t in templates() {
            crate::query::parse(t.query.clone()).unwrap_or_else(|e| panic!("{}: {e}", t.id));
        }
    }

    #[test]
    fn search_ranks() {
        let r = search(Some("printers offline"));
        assert_eq!(r[0].id, "offline-printers");
        assert!(search(Some("zzzz")).is_empty());
    }
}
