//! Read the OS ARP/neighbor cache to map IPs to MAC addresses (local subnets only).

use std::collections::HashMap;
use std::net::IpAddr;

/// Normalise any MAC notation (`00-11-22-..`, `0:11:22:..`, `0011.2233.4455`) to `00:11:22:33:44:55`.
pub fn normalize_mac(s: &str) -> Option<String> {
    let s = s.trim();
    let parts: Vec<&str> = s.split([':', '-']).collect();
    let hex: String = if parts.len() == 6 {
        parts.iter().map(|p| format!("{:0>2}", p)).collect()
    } else if s.len() == 14 && s.matches('.').count() == 2 {
        s.replace('.', "")
    } else {
        return None;
    };
    if hex.len() != 12 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let hex = hex.to_uppercase();
    let mac = (0..6).map(|i| &hex[i * 2..i * 2 + 2]).collect::<Vec<_>>().join(":");
    // Skip broadcast, all-zero and IPv4 multicast entries.
    if mac == "FF:FF:FF:FF:FF:FF" || mac == "00:00:00:00:00:00" || mac.starts_with("01:00:5E") {
        return None;
    }
    Some(mac)
}

/// Parse `/proc/net/arp`, Windows `arp -a`, or BSD/macOS `arp -an` output.
pub fn parse_arp_output(text: &str) -> HashMap<IpAddr, String> {
    let mut map = HashMap::new();
    for line in text.lines() {
        let toks: Vec<&str> = line
            .split(|c: char| c.is_whitespace() || c == '(' || c == ')')
            .filter(|t| !t.is_empty())
            .collect();
        // /proc/net/arp: flags column 0x0 means incomplete.
        if toks.len() >= 4 && toks[2] == "0x0" {
            continue;
        }
        let ip = toks.iter().find_map(|t| t.parse::<IpAddr>().ok());
        let mac = toks.iter().find_map(|t| normalize_mac(t));
        if let (Some(ip), Some(mac)) = (ip, mac) {
            map.insert(ip, mac);
        }
    }
    map
}

pub async fn read_arp_table() -> HashMap<IpAddr, String> {
    #[cfg(target_os = "linux")]
    if let Ok(text) = tokio::fs::read_to_string("/proc/net/arp").await {
        return parse_arp_output(&text);
    }
    let mut cmd = tokio::process::Command::new("arp");
    cmd.arg(if cfg!(windows) { "-a" } else { "-an" });
    #[cfg(windows)]
    cmd.creation_flags(0x0800_0000);
    match cmd.output().await {
        Ok(o) => parse_arp_output(&String::from_utf8_lossy(&o.stdout)),
        Err(_) => HashMap::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_format() {
        let t = "Interface: 10.1.1.20 --- 0xb\n  Internet Address      Physical Address      Type\n  10.1.1.1              00-1b-17-aa-bb-cc     dynamic\n  10.1.1.255            ff-ff-ff-ff-ff-ff     static\n";
        let m = parse_arp_output(t);
        assert_eq!(m.len(), 1);
        assert_eq!(m[&"10.1.1.1".parse().unwrap()], "00:1B:17:AA:BB:CC");
    }

    #[test]
    fn linux_format() {
        let t = "IP address       HW type     Flags       HW address            Mask     Device\n192.168.0.1      0x1         0x2         b8:27:eb:01:02:03     *        eth0\n192.168.0.9      0x1         0x0         00:00:00:00:00:00     *        eth0\n";
        let m = parse_arp_output(t);
        assert_eq!(m.len(), 1);
        assert_eq!(m[&"192.168.0.1".parse().unwrap()], "B8:27:EB:01:02:03");
    }

    #[test]
    fn mac_formats() {
        assert_eq!(normalize_mac("0:c:29:a:b:c").as_deref(), Some("00:0C:29:0A:0B:0C"));
        assert_eq!(normalize_mac("0050.56ab.cdef").as_deref(), Some("00:50:56:AB:CD:EF"));
        assert!(normalize_mac("10.1.1.1").is_none());
    }
}
