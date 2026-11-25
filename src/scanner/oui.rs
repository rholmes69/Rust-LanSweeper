//! MAC address → hardware vendor lookup.
//!
//! A small built-in table covers the vendors most common on business networks. For full
//! coverage, download the IEEE registry (https://standards-oui.ieee.org/oui/oui.csv) and pass
//! it with `--oui-file oui.csv` (the Wireshark `manuf` file is accepted too).

use std::collections::HashMap;
use std::sync::OnceLock;

static BUILTIN: &[(&str, &str)] = &[
    // Virtualisation
    ("000C29", "VMware"), ("005056", "VMware"), ("000569", "VMware"), ("001C14", "VMware"),
    ("080027", "Oracle VirtualBox"), ("00155D", "Microsoft Hyper-V"), ("525400", "QEMU/KVM"),
    // Single-board / embedded
    ("B827EB", "Raspberry Pi"), ("DCA632", "Raspberry Pi"), ("E45F01", "Raspberry Pi"), ("28CDC1", "Raspberry Pi"),
    // PCs & servers
    ("001422", "Dell"), ("B8CA3A", "Dell"), ("D4BED9", "Dell"), ("F8B156", "Dell"), ("180373", "Dell"),
    ("0017A4", "HP"), ("3CD92B", "HP"), ("9C8E99", "HP"), ("10604B", "HP"), ("001E0B", "HP"),
    ("002590", "Supermicro"), ("AC1F6B", "Supermicro"),
    ("001B21", "Intel"), ("001E67", "Intel"), ("A0369F", "Intel"),
    ("000393", "Apple"), ("001CB3", "Apple"), ("A45E60", "Apple"), ("F01898", "Apple"), ("ACBC32", "Apple"), ("3C0754", "Apple"),
    // Network infrastructure
    ("00000C", "Cisco"), ("001AA1", "Cisco"), ("00180A", "Cisco Meraki"),
    ("000B86", "Aruba"), ("24DEC6", "Aruba"),
    ("000585", "Juniper"), ("00090F", "Fortinet"), ("001B17", "Palo Alto Networks"),
    ("24A43C", "Ubiquiti"), ("0418D6", "Ubiquiti"), ("802AA8", "Ubiquiti"), ("F09FC2", "Ubiquiti"),
    ("788A20", "Ubiquiti"), ("FCECDA", "Ubiquiti"),
    ("00146C", "Netgear"), ("50C7BF", "TP-Link"), ("14CC20", "TP-Link"),
    // Printers & imaging
    ("008077", "Brother"), ("30055C", "Brother"), ("0000AA", "Xerox"), ("000400", "Lexmark"),
    ("002000", "Lexmark"), ("002673", "Ricoh"), ("001E8F", "Canon"), ("000085", "Canon"),
    ("00074D", "Zebra"),
    // Phones, cameras, power, storage
    ("0004F2", "Polycom"), ("001565", "Yealink"), ("00408C", "Axis"), ("ACCC8E", "Axis"),
    ("00C0B7", "APC"), ("001132", "Synology"),
];

static TABLE: OnceLock<HashMap<String, String>> = OnceLock::new();

fn clean_vendor(v: &str) -> String {
    let v = v.trim().trim_matches('"').trim();
    v.chars().take(60).collect()
}

/// Load an IEEE `oui.csv`, `oui.txt`, or Wireshark `manuf` file to extend the built-in table.
/// Must be called before the first lookup.
pub fn load_file(path: &str) -> anyhow::Result<usize> {
    let text = std::fs::read_to_string(path)?;
    let mut map: HashMap<String, String> =
        BUILTIN.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
    let mut n = 0;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // IEEE CSV: MA-L,005056,"VMware, Inc.",address
        if let Some(rest) = line.strip_prefix("MA-L,") {
            if let Some((hex, vendor)) = rest.split_once(',') {
                let vendor = if let Some(v) = vendor.strip_prefix('"') {
                    v.split('"').next().unwrap_or("")
                } else {
                    vendor.split(',').next().unwrap_or("")
                };
                map.insert(hex.to_uppercase(), clean_vendor(vendor));
                n += 1;
            }
            continue;
        }
        // IEEE TXT: 00-50-56   (hex)\t\tVMware, Inc.
        if let Some((pre, vendor)) = line.split_once("(hex)") {
            let hex = pre.trim().replace('-', "").to_uppercase();
            if hex.len() == 6 {
                map.insert(hex, clean_vendor(vendor));
                n += 1;
            }
            continue;
        }
        // Wireshark manuf: 00:50:56\tVMware\tVMware, Inc.
        let mut cols = line.split('\t');
        if let (Some(pfx), Some(short)) = (cols.next(), cols.next()) {
            let hex = pfx.replace([':', '-'], "").to_uppercase();
            if hex.len() == 6 && hex.chars().all(|c| c.is_ascii_hexdigit()) {
                let long = cols.next().unwrap_or(short);
                map.insert(hex, clean_vendor(long));
                n += 1;
            }
        }
    }
    let _ = TABLE.set(map);
    Ok(n)
}

pub fn lookup(mac: &str) -> Option<String> {
    let table = TABLE.get_or_init(|| BUILTIN.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect());
    let hex: String = mac.chars().filter(|c| c.is_ascii_hexdigit()).collect::<String>().to_uppercase();
    if hex.len() < 6 {
        return None;
    }
    if let Some(v) = table.get(&hex[..6]) {
        return Some(v.clone());
    }
    // Locally-administered bit set → randomised (phones, Windows "random hardware address") or virtual.
    let first = u8::from_str_radix(&hex[..2], 16).ok()?;
    if first & 0x02 != 0 {
        return Some("Private/randomized MAC".to_string());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_lookup() {
        assert_eq!(lookup("00:50:56:12:34:56").as_deref(), Some("VMware"));
        assert_eq!(lookup("DA:11:22:33:44:55").as_deref(), Some("Private/randomized MAC"));
        assert_eq!(lookup("00:00:01:00:00:00"), None);
    }
}
