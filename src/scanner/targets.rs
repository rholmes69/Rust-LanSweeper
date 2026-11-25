//! Target parsing: CIDR blocks, ranges, single IPs and hostnames.

use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs};

use anyhow::{bail, Context, Result};
use ipnet::Ipv4Net;

/// Hard ceiling so a typo like `10.0.0.0/8` doesn't launch a 16M-host scan.
pub const MAX_HOSTS: usize = 65_536;

/// Parse a comma/whitespace separated list of targets.
///
/// Supported forms:
/// * `192.168.1.0/24`           – CIDR (network/broadcast excluded for /0-/30)
/// * `192.168.1.10-50`          – last-octet range
/// * `192.168.1.10-192.168.2.5` – full range
/// * `192.168.1.7`              – single address
/// * `printer01.corp.local`     – hostname (resolved via DNS)
pub fn parse_targets(spec: &str) -> Result<Vec<IpAddr>> {
    let mut out: Vec<IpAddr> = Vec::new();
    for tok in spec.split(|c: char| c == ',' || c.is_whitespace()).filter(|t| !t.is_empty()) {
        if tok.contains('/') {
            let net: Ipv4Net = tok.parse().with_context(|| format!("invalid CIDR '{tok}'"))?;
            let size = 1u64 << (32 - net.prefix_len());
            if size as usize > MAX_HOSTS {
                bail!("'{tok}' is {size} addresses; the limit is {MAX_HOSTS} per scan (use /16 or smaller)");
            }
            if net.prefix_len() >= 31 {
                out.extend(net.network().to_string().parse::<IpAddr>());
                if net.prefix_len() == 31 {
                    out.push(IpAddr::V4(net.broadcast()));
                }
            } else {
                out.extend(net.hosts().map(IpAddr::V4));
            }
        } else if let Some((a, b)) = tok.split_once('-') {
            let start: Ipv4Addr = a.trim().parse().with_context(|| format!("invalid range start '{a}'"))?;
            let end: Ipv4Addr = if b.contains('.') {
                b.trim().parse().with_context(|| format!("invalid range end '{b}'"))?
            } else {
                let last: u8 = b.trim().parse().with_context(|| format!("invalid range end '{b}'"))?;
                let o = start.octets();
                Ipv4Addr::new(o[0], o[1], o[2], last)
            };
            let (s, e) = (u32::from(start), u32::from(end));
            if e < s {
                bail!("range '{tok}' ends before it starts");
            }
            if (e - s) as usize + 1 > MAX_HOSTS {
                bail!("range '{tok}' exceeds {MAX_HOSTS} hosts");
            }
            out.extend((s..=e).map(|n| IpAddr::V4(Ipv4Addr::from(n))));
        } else if let Ok(ip) = tok.parse::<IpAddr>() {
            out.push(ip);
        } else {
            let addrs = (tok, 0u16)
                .to_socket_addrs()
                .with_context(|| format!("could not resolve '{tok}'"))?;
            match addrs.map(|a| a.ip()).find(|ip| ip.is_ipv4()) {
                Some(ip) => out.push(ip),
                None => bail!("'{tok}' has no IPv4 address"),
            }
        }
        if out.len() > MAX_HOSTS {
            bail!("too many targets (limit {MAX_HOSTS})");
        }
    }
    out.sort();
    out.dedup();
    if out.is_empty() {
        bail!("no targets given");
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_excludes_network_and_broadcast() {
        let t = parse_targets("10.0.0.0/30").unwrap();
        assert_eq!(t, vec!["10.0.0.1".parse::<IpAddr>().unwrap(), "10.0.0.2".parse().unwrap()]);
    }

    #[test]
    fn short_range_and_list() {
        let t = parse_targets("192.168.1.10-12, 192.168.1.11 192.168.1.50").unwrap();
        assert_eq!(t.len(), 4);
    }

    #[test]
    fn full_range() {
        let t = parse_targets("10.0.0.250-10.0.1.5").unwrap();
        assert_eq!(t.len(), 12);
    }

    #[test]
    fn rejects_huge() {
        assert!(parse_targets("10.0.0.0/8").is_err());
        assert!(parse_targets("10.0.0.9-3").is_err());
    }
}
