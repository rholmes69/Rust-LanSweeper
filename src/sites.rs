//! Sites: named locations (e.g. clinics) defined by the subnets they own.
//!
//! Assets are assigned to the site whose subnet most specifically contains their IP
//! (longest prefix wins), unless IT has pinned the asset to a site by hand.

use std::net::IpAddr;

use anyhow::{bail, Context, Result};
use ipnet::{IpNet, Ipv4Net};

/// Parse a comma/space separated list of CIDRs or single IPv4 addresses.
pub fn parse_subnets(spec: &str) -> Result<Vec<Ipv4Net>> {
    let mut out = Vec::new();
    for tok in spec.split(|c: char| c == ',' || c.is_whitespace()).filter(|t| !t.is_empty()) {
        let net: Ipv4Net = if tok.contains('/') {
            tok.parse::<Ipv4Net>().with_context(|| format!("invalid subnet '{tok}' (use CIDR like 10.20.0.0/24)"))?.trunc()
        } else {
            let ip: std::net::Ipv4Addr = tok.parse().with_context(|| format!("invalid subnet or IP '{tok}'"))?;
            Ipv4Net::new(ip, 32)?
        };
        if !out.contains(&net) {
            out.push(net);
        }
    }
    if out.is_empty() {
        bail!("a site needs at least one subnet");
    }
    Ok(out)
}

pub fn format_subnets(nets: &[Ipv4Net]) -> String {
    nets.iter().map(|n| n.to_string()).collect::<Vec<_>>().join(", ")
}

/// Pick the site for an IP: the most specific matching subnet wins; ties go to the lowest site id.
pub fn site_for_ip(sites: &[(i64, Vec<Ipv4Net>)], ip: &str) -> Option<i64> {
    let Ok(IpAddr::V4(v4)) = ip.parse::<IpAddr>() else { return None };
    let mut best: Option<(u8, i64)> = None;
    for (id, nets) in sites {
        for n in nets {
            if IpNet::V4(*n).contains(&IpAddr::V4(v4)) {
                let better = match best {
                    None => true,
                    Some((len, bid)) => n.prefix_len() > len || (n.prefix_len() == len && *id < bid),
                };
                if better {
                    best = Some((n.prefix_len(), *id));
                }
            }
        }
    }
    best.map(|(_, id)| id)
}

/// Comma-separated targets string covering all of a site's subnets (for scanning a site).
pub fn scan_targets(nets: &[Ipv4Net]) -> String {
    nets.iter().map(|n| n.to_string()).collect::<Vec<_>>().join(",")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parsing() {
        let n = parse_subnets("10.20.0.5/24, 10.20.1.7 10.20.0.0/24").unwrap();
        assert_eq!(format_subnets(&n), "10.20.0.0/24, 10.20.1.7/32");
        assert!(parse_subnets("").is_err());
        assert!(parse_subnets("10.0.0.0/33").is_err());
        assert!(parse_subnets("clinic").is_err());
    }

    #[test]
    fn longest_prefix_wins() {
        let sites = vec![
            (1, parse_subnets("10.0.0.0/16").unwrap()),
            (2, parse_subnets("10.0.5.0/24").unwrap()),
            (3, parse_subnets("10.0.5.0/24").unwrap()),
        ];
        assert_eq!(site_for_ip(&sites, "10.0.1.9"), Some(1));
        assert_eq!(site_for_ip(&sites, "10.0.5.9"), Some(2));
        assert_eq!(site_for_ip(&sites, "192.168.1.1"), None);
        assert_eq!(site_for_ip(&sites, "not-an-ip"), None);
    }
}
