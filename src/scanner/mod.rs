//! Agentless network discovery: liveness, open ports, names, MACs, SNMP and fingerprinting.

pub mod arp;
pub mod classify;
pub mod netbios;
pub mod oui;
pub mod probe;
pub mod snmp;
pub mod targets;

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use futures::stream::{self, StreamExt};
use serde::Serialize;

use crate::db::Db;
use probe::PortState;

#[derive(Debug, Clone, Serialize)]
pub struct OpenPort {
    pub port: u16,
    pub service: Option<String>,
    pub banner: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HostResult {
    pub ip: IpAddr,
    pub alive: bool,
    /// How liveness was established: tcp, ping, netbios, snmp, arp.
    pub detected_by: Vec<&'static str>,
    pub ttl: Option<u8>,
    pub mac: Option<String>,
    pub vendor: Option<String>,
    pub hostname: Option<String>,
    pub netbios_name: Option<String>,
    pub netbios_domain: Option<String>,
    pub snmp: Option<snmp::SnmpInfo>,
    pub http_title: Option<String>,
    pub http_server: Option<String>,
    pub ssh_banner: Option<String>,
    pub ports: Vec<OpenPort>,
    pub os_guess: Option<String>,
    pub device_type: Option<String>,
}

impl Default for HostResult {
    fn default() -> Self {
        Self {
            ip: IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            alive: false,
            detected_by: vec![],
            ttl: None,
            mac: None,
            vendor: None,
            hostname: None,
            netbios_name: None,
            netbios_domain: None,
            snmp: None,
            http_title: None,
            http_server: None,
            ssh_banner: None,
            ports: vec![],
            os_guess: None,
            device_type: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub ports: Vec<u16>,
    /// Hosts probed in parallel.
    pub concurrency: usize,
    pub timeout: Duration,
    pub snmp_communities: Vec<String>,
    pub ping: bool,
    /// Credentialed Windows inventory after discovery (None = off). On by default on Windows.
    pub inventory: Option<crate::inventory::InventoryOptions>,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            ports: probe::DEFAULT_PORTS.to_vec(),
            concurrency: 64,
            timeout: Duration::from_millis(800),
            snmp_communities: vec!["public".into()],
            ping: true,
            inventory: crate::inventory::supported().then(crate::inventory::InventoryOptions::default),
        }
    }
}

/// Live progress for a running scan (shared with the web UI).
#[derive(Debug, Default, Serialize)]
pub struct Progress {
    pub total: AtomicUsize,
    pub done: AtomicUsize,
    pub up: AtomicUsize,
    /// Windows devices queued for credentialed inventory after discovery, and how many are done.
    pub inventory_total: AtomicUsize,
    pub inventory_done: AtomicUsize,
    pub finished: AtomicBool,
}

/// Probe a single host. Never fails — unreachable hosts just come back with `alive = false`.
pub async fn scan_host(ip: IpAddr, opts: &ScanOptions) -> HostResult {
    let to = opts.timeout;
    let mut h = HostResult { ip, ..Default::default() };

    let port_fut = futures::future::join_all(
        opts.ports.iter().map(|&p| async move { (p, probe::probe_port(ip, p, to).await) }),
    );
    let ping_fut = async {
        if opts.ping {
            probe::ping(ip, to.max(Duration::from_millis(1000))).await
        } else {
            probe::PingResult::default()
        }
    };
    let nb_fut = netbios::query(ip, to.max(Duration::from_millis(1000)));
    let snmp_fut = async {
        for c in &opts.snmp_communities {
            if let Some(i) = snmp::query(ip, c, to.max(Duration::from_millis(1000))).await {
                return Some(i);
            }
        }
        None
    };
    let (port_states, ping, nb, snmp_info) = tokio::join!(port_fut, ping_fut, nb_fut, snmp_fut);

    let open: Vec<u16> = port_states.iter().filter(|(_, s)| *s == PortState::Open).map(|(p, _)| *p).collect();
    if !open.is_empty() || port_states.iter().any(|(_, s)| *s == PortState::Closed) {
        h.detected_by.push("tcp");
    }
    if ping.alive {
        h.detected_by.push("ping");
        h.ttl = ping.ttl;
    }
    if let Some(nb) = nb {
        h.detected_by.push("netbios");
        h.netbios_name = nb.name;
        h.netbios_domain = nb.domain;
        h.mac = nb.mac;
    }
    if snmp_info.is_some() {
        h.detected_by.push("snmp");
        h.snmp = snmp_info;
    }
    h.alive = !h.detected_by.is_empty();
    if !h.alive {
        return h;
    }
    enrich(&mut h, &open, to).await;
    h
}

/// Collect names and banners for a host already known to be up.
async fn enrich(h: &mut HostResult, open: &[u16], to: Duration) {
    let ip = h.ip;
    let banner_to = to.max(Duration::from_millis(1500));
    let dns_fut = probe::reverse_dns(ip, Duration::from_secs(2));
    let banners_fut = futures::future::join_all(open.iter().map(|&p| async move {
        let banner = match p {
            21 | 22 | 23 | 25 => probe::grab_banner(ip, p, banner_to).await,
            _ => None,
        };
        let http = match p {
            80 | 8000 | 8080 => probe::http_info(ip, p, banner_to).await,
            _ => None,
        };
        (p, banner, http)
    }));
    let (dns, banners) = tokio::join!(dns_fut, banners_fut);
    h.hostname = dns;
    for (p, banner, http) in banners {
        if p == 22 {
            h.ssh_banner = banner.clone();
        }
        let mut port_banner = banner;
        if let Some(info) = http {
            if port_banner.is_none() {
                port_banner = info.server.clone().or_else(|| info.title.clone());
            }
            if h.http_server.is_none() {
                h.http_server = info.server;
            }
            if h.http_title.is_none() {
                h.http_title = info.title;
            }
        }
        h.ports.push(OpenPort { port: p, service: Some(probe::service_name(p).to_string()), banner: port_banner });
    }
}

/// Fill in MAC/vendor/classification once all hosts are probed.
fn finalize(h: &mut HostResult) {
    if let Some(mac) = &h.mac {
        h.vendor = oui::lookup(mac);
    }
    let (dtype, os) = classify::classify(h);
    h.device_type = dtype;
    h.os_guess = os;
}

/// Validate targets and register a scan row. Returns the scan id and parsed IP list.
/// Like `prepare_scan`, recording which site the scan was run for.
pub fn prepare_site_scan(db: &Db, spec: &str, trigger: &str, site_id: Option<i64>) -> Result<(i64, Vec<IpAddr>)> {
    let ips = targets::parse_targets(spec)?;
    let id = db.create_scan_for_site(spec.trim(), trigger, site_id)?;
    Ok((id, ips))
}

/// Run a prepared scan to completion, persisting results.
pub async fn execute_scan(
    db: Db,
    scan_id: i64,
    ips: Vec<IpAddr>,
    opts: ScanOptions,
    progress: Arc<Progress>,
) -> Result<()> {
    progress.total.store(ips.len(), Ordering::Relaxed);
    let target_set: HashSet<IpAddr> = ips.iter().copied().collect();
    let opts = Arc::new(opts);

    let mut results: Vec<HostResult> = stream::iter(ips.clone())
        .map(|ip| {
            let opts = opts.clone();
            let progress = progress.clone();
            async move {
                let h = scan_host(ip, &opts).await;
                progress.done.fetch_add(1, Ordering::Relaxed);
                if h.alive {
                    progress.up.fetch_add(1, Ordering::Relaxed);
                }
                h
            }
        })
        .buffer_unordered(opts.concurrency.max(1))
        .filter(|h| futures::future::ready(h.alive))
        .collect()
        .await;

    // ARP cache is now warm for every local-subnet host we touched.
    let arp = arp::read_arp_table().await;
    let found: HashSet<IpAddr> = results.iter().map(|h| h.ip).collect();
    for h in results.iter_mut() {
        if let Some(mac) = arp.get(&h.ip) {
            h.mac = Some(mac.clone()); // ARP beats NetBIOS (which can report a virtual adapter)
        }
    }
    // Hosts that answered ARP but blocked everything else (typical locked-down endpoints).
    for (ip, mac) in &arp {
        if target_set.contains(ip) && !found.contains(ip) {
            let mut h = HostResult {
                ip: *ip,
                alive: true,
                detected_by: vec!["arp"],
                mac: Some(mac.clone()),
                ..Default::default()
            };
            h.hostname = probe::reverse_dns(*ip, Duration::from_secs(2)).await;
            progress.up.fetch_add(1, Ordering::Relaxed);
            results.push(h);
        }
    }

    let mut seen_ids = HashSet::new();
    let mut new_assets = 0;
    for h in results.iter_mut() {
        finalize(h);
        let (id, is_new) = db.record_host(scan_id, h)?;
        seen_ids.insert(id);
        if is_new {
            new_assets += 1;
        }
    }
    let scanned: HashSet<String> = ips.iter().map(|ip| ip.to_string()).collect();
    db.mark_offline(scan_id, &scanned, &seen_ids)?;
    db.reassign_sites()?; // place new / moved assets into their sites

    if let Some(inv_opts) = &opts.inventory {
        let candidates: Vec<_> = seen_ids
            .iter()
            .filter_map(|id| db.get_asset(*id).ok().flatten())
            .filter(crate::inventory::is_candidate)
            .collect();
        if !candidates.is_empty() {
            progress.inventory_total.store(candidates.len(), Ordering::Relaxed);
            let outcomes = crate::inventory::inventory_many(db.clone(), candidates, inv_opts.clone()).await;
            progress.inventory_done.store(outcomes.len(), Ordering::Relaxed);
            let ok = outcomes.iter().filter(|o| o.ok).count();
            tracing::info!(scan = scan_id, ok, failed = outcomes.len() - ok, "windows inventory finished");
        }
    }
    db.finish_scan(scan_id, "completed", ips.len(), results.len(), new_assets, None)?;
    progress.finished.store(true, Ordering::Relaxed);
    Ok(())
}
