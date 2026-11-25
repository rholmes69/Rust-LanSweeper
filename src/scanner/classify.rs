//! Heuristic device-type and OS fingerprinting from everything the scanner collected.

use super::HostResult;

pub fn classify(h: &HostResult) -> (Option<String>, Option<String>) {
    let ports: Vec<u16> = h.ports.iter().map(|p| p.port).collect();
    let has = |p: u16| ports.contains(&p);
    let vendor = h.vendor.as_deref().unwrap_or("").to_lowercase();
    let snmp = h.snmp.as_ref().and_then(|s| s.descr.as_deref()).unwrap_or("").to_lowercase();
    let ssh = h.ssh_banner.as_deref().unwrap_or("").to_lowercase();
    let http = format!(
        "{} {}",
        h.http_server.as_deref().unwrap_or(""),
        h.http_title.as_deref().unwrap_or("")
    )
    .to_lowercase();
    let any = |hay: &str, needles: &[&str]| needles.iter().any(|n| hay.contains(n));

    let mut os: Option<String> = None;
    let mut dtype: Option<String> = None;

    // ---- OS, strongest evidence first
    if !snmp.is_empty() {
        os = Some(if snmp.contains("windows") {
            "Windows".into()
        } else if snmp.contains("cisco ios") || snmp.contains("cisco nx-os") {
            "Cisco IOS".into()
        } else if snmp.contains("junos") {
            "Junos".into()
        } else if snmp.contains("fortigate") || snmp.contains("fortios") {
            "FortiOS".into()
        } else if snmp.contains("routeros") {
            "RouterOS".into()
        } else if snmp.contains("vmware esxi") {
            "VMware ESXi".into()
        } else if snmp.contains("linux") {
            "Linux".into()
        } else if snmp.contains("darwin") {
            "macOS".into()
        } else {
            h.snmp.as_ref().and_then(|s| s.descr.clone()).unwrap_or_default().chars().take(40).collect()
        });
    }
    if os.is_none() && !ssh.is_empty() {
        os = Some(if ssh.contains("ubuntu") {
            "Linux (Ubuntu)".into()
        } else if ssh.contains("debian") || ssh.contains("raspbian") {
            "Linux (Debian)".into()
        } else if ssh.contains("freebsd") {
            "FreeBSD".into()
        } else if ssh.contains("cisco") {
            "Cisco IOS".into()
        } else if ssh.contains("for_windows") || ssh.contains("windows") {
            "Windows".into()
        } else if ssh.contains("dropbear") {
            "Embedded Linux".into()
        } else {
            "Linux/Unix".into()
        });
    }
    if os.is_none() && h.netbios_name.is_some() && (has(445) || has(135) || has(3389)) {
        os = Some("Windows".into());
    }
    if os.is_none() && (has(3389) || (has(135) && has(445)) || has(5985)) {
        os = Some("Windows".into());
    }
    if os.is_none() && vendor.contains("apple") {
        os = Some("macOS/iOS".into());
    }
    if os.is_none() {
        if let Some(ttl) = h.ttl {
            os = Some(
                match ttl {
                    65..=128 => "Windows (TTL)",
                    129..=255 => "Network OS (TTL)",
                    _ => "Linux/Unix (TTL)",
                }
                .into(),
            );
        }
    }

    // ---- Device type
    let printer_words = ["jetdirect", "laserjet", "printer", "officejet", "brother", "lexmark", "xerox", "ricoh", "canon", "kyocera", "zebra", "konica", "sharp mx"];
    let netgear_words = ["cisco", "aruba", "juniper", "ubiquiti", "netgear", "tp-link", "fortinet", "palo alto", "meraki", "mikrotik"];

    if any(&snmp, &printer_words) || any(&http, &printer_words) || has(9100) || (has(515) && !has(445)) {
        dtype = Some("Printer".into());
    } else if any(&vendor, &["polycom", "yealink"]) || (has(5060) && !has(445) && !has(22)) {
        dtype = Some("VoIP Phone".into());
    } else if any(&vendor, &["axis", "hikvision"]) || any(&http, &["network camera", "ip camera", "nvr"]) {
        dtype = Some("Camera".into());
    } else if vendor.contains("apc") || any(&snmp, &["smart-ups", "network management card", "ups network"]) {
        dtype = Some("UPS".into());
    } else if vendor.contains("synology") || any(&http, &["synology", "qnap", "diskstation"]) {
        dtype = Some("NAS".into());
    } else if has(104) || has(2575) {
        dtype = Some("Medical / HL7-DICOM".into());
    } else if any(&snmp, &["cisco ios", "junos", "fortigate", "routeros", "switch", "router", "firewall", "procurve", "aruba"])
        || (any(&vendor, &netgear_words) && !has(445))
        || os.as_deref().is_some_and(|o| o.contains("Network OS") || o.contains("Cisco") || o == "Junos" || o == "FortiOS")
    {
        dtype = Some("Network Device".into());
    } else if snmp.contains("esxi") || http.contains("vmware esxi") {
        dtype = Some("Hypervisor".into());
    } else if os.as_deref().is_some_and(|o| o.starts_with("Windows")) {
        let server_roles = has(88) || has(389) || has(53) || has(1433) || has(25);
        dtype = Some(if has(88) && has(389) {
            "Windows Domain Controller".into()
        } else if server_roles {
            "Windows Server".into()
        } else {
            "Windows Workstation".into()
        });
    } else if os.as_deref().is_some_and(|o| o.contains("macOS")) {
        dtype = Some("Apple Device".into());
    } else if os.as_deref().is_some_and(|o| o.contains("Linux") || o.contains("BSD") || o.contains("Unix")) {
        dtype = Some(if vendor.contains("raspberry") { "Raspberry Pi".into() } else { "Linux/Unix Server".into() });
    } else if has(80) || has(443) || has(8080) {
        dtype = Some("Web Device".into());
    }

    if any(&vendor, &["vmware", "virtualbox", "hyper-v", "qemu"]) {
        dtype = Some(format!("{} (VM)", dtype.unwrap_or_else(|| "Virtual Machine".into())));
    }
    (dtype, os)
}

#[cfg(test)]
mod tests {
    use super::super::{HostResult, OpenPort};
    use super::*;

    fn host(ports: &[u16]) -> HostResult {
        HostResult {
            ip: "10.0.0.5".parse().unwrap(),
            ports: ports.iter().map(|&p| OpenPort { port: p, service: None, banner: None }).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn domain_controller() {
        let h = host(&[53, 88, 135, 389, 445, 3389]);
        assert_eq!(classify(&h), (Some("Windows Domain Controller".into()), Some("Windows".into())));
    }

    #[test]
    fn printer() {
        let h = host(&[80, 443, 9100]);
        assert_eq!(classify(&h).0.as_deref(), Some("Printer"));
    }

    #[test]
    fn linux_vm() {
        let mut h = host(&[22]);
        h.ssh_banner = Some("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13".into());
        h.vendor = Some("VMware".into());
        assert_eq!(classify(&h), (Some("Linux/Unix Server (VM)".into()), Some("Linux (Ubuntu)".into())));
    }
}
