//! Linux inventory over SSH using the system `ssh` client (Windows 10+ ships OpenSSH as ssh.exe).
//!
//! Key-based only: `BatchMode=yes` means ssh never prompts, so a missing/refused key fails fast.
//! Host keys are trusted on first use and pinned in RustSweeper's own known_hosts file.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{bail, Context, Result};

use super::{CollectError, Disk, Nic, Protection, Service, Software, WinInventory};

pub const COLLECT_SH: &str = include_str!("linux.sh");
pub const SSH_TIMEOUT: Duration = Duration::from_secs(120);

/// Folder for RustSweeper's SSH files (known_hosts, generated keys).
pub fn data_dir() -> PathBuf {
    let base = if cfg!(windows) {
        std::env::var_os("PROGRAMDATA").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
    } else {
        std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."))
    };
    base.join(if cfg!(windows) { "RustSweeper" } else { ".rustsweeper" })
}

pub fn known_hosts() -> PathBuf {
    data_dir().join("known_hosts")
}

/// Split collector output into sections keyed by their `@@name` marker.
pub fn sections(out: &str) -> HashMap<String, Vec<String>> {
    let mut map: HashMap<String, Vec<String>> = HashMap::new();
    let mut cur: Option<String> = None;
    for line in out.lines() {
        if let Some(name) = line.strip_prefix("@@") {
            cur = Some(name.trim().to_string());
            map.entry(name.trim().to_string()).or_default();
        } else if let Some(c) = &cur {
            map.entry(c.clone()).or_default().push(line.to_string());
        }
    }
    map
}

fn unquote(v: &str) -> String {
    v.trim().trim_matches('"').trim_matches('\'').to_string()
}

fn first(sec: &HashMap<String, Vec<String>>, k: &str) -> Option<String> {
    sec.get(k)?.iter().map(|l| l.trim()).find(|l| !l.is_empty()).map(str::to_string)
}

/// Map systemd's states onto the Windows-style vocabulary the rest of RustSweeper uses.
fn systemd_services(units: &[String], unitfiles: &[String]) -> Vec<Service> {
    let mut enabled: HashMap<String, String> = HashMap::new();
    for l in unitfiles {
        let mut t = l.split_whitespace();
        if let (Some(unit), Some(state)) = (t.next(), t.next()) {
            enabled.insert(unit.trim_end_matches(".service").to_string(), state.to_string());
        }
    }
    let mut out = Vec::new();
    for l in units {
        let t: Vec<&str> = l.split_whitespace().collect();
        if t.len() < 4 || !t[0].ends_with(".service") {
            continue;
        }
        let name = t[0].trim_end_matches(".service").to_string();
        let (active, sub) = (t[2], t[3]);
        let state = match active {
            "active" => "Running".to_string(),
            "failed" => "Failed".to_string(),
            "activating" | "reloading" => "Starting".to_string(),
            _ => "Stopped".to_string(),
        };
        let start_mode = match enabled.get(&name).map(String::as_str) {
            Some("enabled") | Some("enabled-runtime") => "Auto",
            Some("disabled") | Some("masked") => "Disabled",
            _ => "Manual",
        };
        let desc = t[4..].join(" ");
        out.push(Service {
            name,
            display_name: Some(if desc.is_empty() { sub.to_string() } else { desc }),
            state: Some(state),
            start_mode: Some(start_mode.to_string()),
            start_name: None,
            path: None,
        });
    }
    out
}

/// Turn collector output into the shared inventory structure (platform = "linux").
pub fn parse(out: &str) -> Result<WinInventory, CollectError> {
    let s = sections(out);
    if !s.contains_key("end") {
        let tail: String = out.trim().chars().rev().take(300).collect::<Vec<_>>().into_iter().rev().collect();
        return Err(CollectError::Other(format!("collector output incomplete: {tail}")));
    }
    let mut inv = WinInventory { platform: Some("linux".into()), ..Default::default() };
    inv.computer_name = first(&s, "hostname");

    let osr: HashMap<String, String> = s
        .get("os")
        .map(|v| v.iter().filter_map(|l| l.split_once('=').map(|(k, v)| (k.trim().to_string(), unquote(v)))).collect())
        .unwrap_or_default();
    inv.os_name = osr.get("PRETTY_NAME").or(osr.get("NAME")).cloned().or_else(|| Some("Linux".into()));
    inv.os_version = osr.get("VERSION_ID").cloned();
    if let Some(k) = s.get("kernel") {
        inv.os_build = k.first().map(|x| x.trim().to_string()).filter(|x| !x.is_empty());
        inv.os_arch = k.get(1).map(|x| x.trim().to_string()).filter(|x| !x.is_empty());
    }
    if let (Some(up), Some(now)) = (first(&s, "uptime"), first(&s, "now")) {
        if let (Ok(up), Ok(now)) = (up.parse::<f64>(), now.parse::<i64>()) {
            let boot = now - up as i64;
            inv.last_boot = chrono::DateTime::from_timestamp(boot, 0)
                .map(|t| t.with_timezone(&chrono::Local).format("%Y-%m-%d %H:%M:%S").to_string());
        }
    }
    if let Some(c) = s.get("cpu") {
        let lines: Vec<&str> = c.iter().map(|l| l.trim()).filter(|l| !l.is_empty()).collect();
        for l in &lines {
            if let Ok(n) = l.parse::<u32>() {
                inv.logical_processors = Some(n);
            } else if inv.cpu.is_none() {
                inv.cpu = Some(l.to_string());
            }
        }
    }
    inv.cores = first(&s, "cores").and_then(|c| c.trim().parse().ok());
    inv.memory_bytes = first(&s, "mem")
        .and_then(|m| m.split_whitespace().nth(1).and_then(|kb| kb.parse::<u64>().ok()))
        .map(|kb| kb * 1024);
    let dmi: HashMap<String, String> = s
        .get("dmi")
        .map(|v| v.iter().filter_map(|l| l.split_once('=').map(|(k, v)| (k.to_string(), v.trim().to_string()))).collect())
        .unwrap_or_default();
    let d = |k: &str| dmi.get(k).cloned().filter(|v| !v.is_empty());
    inv.manufacturer = d("sys_vendor");
    inv.model = d("product_name");
    inv.serial_number = d("product_serial");
    inv.bios_version = d("bios_version");
    inv.bios_date = d("bios_date");

    // Disks: real block devices only (skip tmpfs, overlay, squashfs snaps…).
    inv.disks = s
        .get("df")
        .map(|v| {
            v.iter()
                .skip(1)
                .filter_map(|l| {
                    let t: Vec<&str> = l.split_whitespace().collect();
                    if t.len() < 6 || !t[0].starts_with("/dev/") || t[0].starts_with("/dev/loop") {
                        return None;
                    }
                    Some(Disk {
                        drive: Some(t[5..].join(" ")),
                        filesystem: Some(t[0].to_string()),
                        size_bytes: t[1].parse::<u64>().ok().map(|k| k * 1024),
                        free_bytes: t[3].parse::<u64>().ok().map(|k| k * 1024),
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    // NICs: MAC from `ip -o link`, IPv4 from `ip -o -4 addr`.
    let mut nics: Vec<Nic> = Vec::new();
    for l in s.get("link").into_iter().flatten() {
        let t: Vec<&str> = l.split_whitespace().collect();
        if t.len() < 2 {
            continue;
        }
        let name = t[1].trim_end_matches(':').split('@').next().unwrap_or("").to_string();
        if name == "lo" || name.is_empty() {
            continue;
        }
        let mac = t.iter().position(|x| *x == "link/ether").and_then(|i| t.get(i + 1)).map(|m| m.to_uppercase());
        nics.push(Nic { description: Some(name), mac, ips: vec![] });
    }
    for l in s.get("addr").into_iter().flatten() {
        let t: Vec<&str> = l.split_whitespace().collect();
        if let (Some(name), Some(i)) = (t.get(1), t.iter().position(|x| *x == "inet")) {
            if let Some(ip) = t.get(i + 1).map(|c| c.split('/').next().unwrap_or("").to_string()) {
                if let Some(n) = nics.iter_mut().find(|n| n.description.as_deref() == Some(name)) {
                    n.ips.push(ip);
                }
            }
        }
    }
    inv.nics = nics;

    inv.last_user = s.get("who").and_then(|v| v.iter().find_map(|l| l.split_whitespace().next().map(str::to_string)));

    inv.software = s
        .get("pkgs")
        .map(|v| {
            v.iter()
                .filter_map(|l| {
                    let t: Vec<&str> = l.split('\t').collect();
                    if t.len() >= 2 && !t[0].trim().is_empty() {
                        Some(Software {
                            name: t[0].trim().to_string(),
                            version: Some(t[1].trim().to_string()).filter(|x| !x.is_empty()),
                            publisher: None,
                            install_date: None,
                            arch: t.get(2).map(|a| a.trim().to_string()),
                        })
                    } else {
                        // apk info -v: "musl-1.2.4-r2"
                        let l = l.trim();
                        let idx = l.match_indices('-').map(|(i, _)| i).find(|i| l[i + 1..].starts_with(|c: char| c.is_ascii_digit()))?;
                        Some(Software { name: l[..idx].to_string(), version: Some(l[idx + 1..].to_string()), ..Default::default() })
                    }
                })
                .collect()
        })
        .unwrap_or_default();
    if inv.software.is_empty() {
        inv.software_error = Some("no package manager found (dpkg, rpm or apk)".into());
    }

    let units = s.get("units").cloned().unwrap_or_default();
    if units.is_empty() {
        inv.services_error = Some("systemd not available".into());
    } else {
        inv.services = systemd_services(&units, s.get("unitfiles").map(Vec::as_slice).unwrap_or(&[]));
    }

    inv.protection = Some(Protection {
        reboot_pending: first(&s, "reboot").map(|r| r == "yes"),
        ..Default::default()
    });
    Ok(inv)
}

fn categorise_ssh(stderr: &str, code: Option<i32>) -> CollectError {
    let l = stderr.to_lowercase();
    if l.contains("permission denied") || l.contains("too many authentication failures") {
        CollectError::AccessDenied(stderr.trim().to_string())
    } else if l.contains("host key verification failed") || l.contains("remote host identification has changed") {
        CollectError::Other(format!(
            "SSH host key changed — possible re-install or impersonation. If expected, remove the host from {} and retry.",
            known_hosts().display()
        ))
    } else if l.contains("timed out") || l.contains("connection refused") || l.contains("no route to host") || l.contains("could not resolve") {
        CollectError::Unreachable(stderr.trim().to_string())
    } else if l.contains("unprotected private key file") || l.contains("bad permissions") {
        CollectError::Other(format!("ssh refused the key file's permissions — only the account running RustSweeper should be able to read it. {}", stderr.trim()))
    } else {
        CollectError::Other(format!("ssh exited with {}: {}", code.map(|c| c.to_string()).unwrap_or_else(|| "?".into()), stderr.trim()))
    }
}

/// Run the collector on `target` as `user` with private key `key_path`.
pub async fn collect(target: &str, user: &str, key_path: &str) -> Result<WinInventory, CollectError> {
    use tokio::io::AsyncWriteExt;
    let _ = std::fs::create_dir_all(data_dir());
    let mut cmd = tokio::process::Command::new(if cfg!(windows) { "ssh.exe" } else { "ssh" });
    cmd.args([
        "-i", key_path,
        "-o", "BatchMode=yes",
        "-o", "IdentitiesOnly=yes",
        "-o", "ConnectTimeout=10",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", &format!("UserKnownHostsFile={}", known_hosts().display()),
        "-o", "LogLevel=ERROR",
        "-l", user,
        target,
        "sh -s",
    ])
    .stdin(std::process::Stdio::piped())
    .stdout(std::process::Stdio::piped())
    .stderr(std::process::Stdio::piped())
    .kill_on_drop(true);
    #[cfg(windows)]
    cmd.creation_flags(0x0800_0000);
    let mut child = cmd.spawn().map_err(|e| CollectError::Other(format!("could not start ssh (is the OpenSSH client installed?): {e}")))?;
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(COLLECT_SH.as_bytes()).await;
        drop(stdin);
    }
    let out = match tokio::time::timeout(SSH_TIMEOUT, child.wait_with_output()).await {
        Ok(Ok(o)) => o,
        Ok(Err(e)) => return Err(CollectError::Other(format!("ssh failed: {e}"))),
        Err(_) => return Err(CollectError::Unreachable(format!("ssh timed out after {}s", SSH_TIMEOUT.as_secs()))),
    };
    let stdout = String::from_utf8_lossy(&out.stdout);
    if !stdout.contains("@@end") {
        return Err(categorise_ssh(&String::from_utf8_lossy(&out.stderr), out.status.code()));
    }
    parse(&stdout)
}

/// Create a dedicated ed25519 key pair in RustSweeper's data folder. Returns (private key path, public key line).
pub fn generate_key(name: &str) -> Result<(PathBuf, String)> {
    let dir = data_dir().join("keys");
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    let safe: String = name.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' }).collect();
    let path = dir.join(format!("{safe}_ed25519"));
    if path.exists() {
        bail!("{} already exists — pick another name or reuse it with --key", path.display());
    }
    let status = std::process::Command::new(if cfg!(windows) { "ssh-keygen.exe" } else { "ssh-keygen" })
        .args(["-q", "-t", "ed25519", "-N", "", "-C", &format!("rustsweeper-{safe}"), "-f"])
        .arg(&path)
        .status()
        .context("could not run ssh-keygen (is the OpenSSH client installed?)")?;
    if !status.success() {
        bail!("ssh-keygen failed");
    }
    // Windows OpenSSH refuses private keys other users can read, and ProgramData grants Users
    // read access by inheritance. Restrict to the current user, SYSTEM (S-1-5-18) and
    // Administrators (S-1-5-32-544) so a RustSweeper service running as LocalSystem can use it.
    if cfg!(windows) {
        let user = std::env::var("USERNAME").unwrap_or_default();
        let mut cmd = std::process::Command::new("icacls");
        cmd.arg(&path).args(["/inheritance:r", "/grant:r", "*S-1-5-18:F", "/grant:r", "*S-1-5-32-544:F"]);
        if !user.is_empty() {
            cmd.args(["/grant:r", &format!("{user}:F")]);
        }
        let ok = cmd.stdout(std::process::Stdio::null()).status().map(|s| s.success()).unwrap_or(false);
        if !ok {
            bail!("generated {} but could not restrict its permissions with icacls; fix them before use", path.display());
        }
    }
    let public = std::fs::read_to_string(path.with_extension("pub").as_path())
        .or_else(|_| std::fs::read_to_string(format!("{}.pub", path.display())))
        .context("reading the generated public key")?;
    Ok((path, public.trim().to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_collector_sections() {
        let out = "@@hostname\npacs01\n@@os\nPRETTY_NAME=\"Ubuntu 22.04.4 LTS\"\nVERSION_ID=\"22.04\"\n@@kernel\n5.15.0-119-generic\nx86_64\n\
@@uptime\n86400.12\n@@now\n1795700000\n@@cpu\n Intel(R) Xeon(R) Silver 4314 CPU @ 2.40GHz\n8\n@@cores\n 4\n@@mem\nMemTotal:       16314232 kB\n\
@@dmi\nsys_vendor=Dell Inc.\nproduct_name=PowerEdge R650\nproduct_serial=\nbios_version=1.10.2\nbios_date=06/12/2024\n\
@@df\nFilesystem 1024-blocks Used Available Capacity Mounted on\ntmpfs 1000 0 1000 0% /run\n/dev/sda2 102400000 60000000 42400000 59% /\n/dev/loop3 5000 5000 0 100% /snap/core\n/dev/sdb1 2000000000 1990000000 10000000 100% /var/lib/dicom\n\
@@addr\n2: eno1    inet 10.20.0.15/24 brd 10.20.0.255 scope global eno1\\       valid_lft forever preferred_lft forever\n\
@@link\n1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000\\    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n2: eno1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP mode DEFAULT group default qlen 1000\\    link/ether b8:ca:3a:01:02:03 brd ff:ff:ff:ff:ff:ff\n\
@@who\nradadmin pts/0        2026-11-26 09:12 (10.20.0.5)\n@@reboot\nyes\n\
@@pkgs\nopenssh-server\t1:8.9p1-3ubuntu0.10\tamd64\northanc\t1.12.1+dfsg-1\tamd64\n\
@@units\nssh.service loaded active running OpenBSD Secure Shell server\northanc.service loaded failed failed Orthanc DICOM server\napt-daily.service loaded inactive dead Daily apt download activities\n\
@@unitfiles\nssh.service enabled enabled\northanc.service enabled enabled\napt-daily.service static -\n@@end\n";
        let inv = parse(out).unwrap();
        assert_eq!(inv.platform.as_deref(), Some("linux"));
        assert_eq!(inv.computer_name.as_deref(), Some("pacs01"));
        assert_eq!(inv.os_name.as_deref(), Some("Ubuntu 22.04.4 LTS"));
        assert_eq!(inv.os_version.as_deref(), Some("22.04"));
        assert_eq!(inv.os_build.as_deref(), Some("5.15.0-119-generic"));
        assert_eq!(inv.logical_processors, Some(8));
        assert_eq!(inv.cores, Some(4));
        assert!(inv.cpu.as_deref().unwrap().contains("Xeon"));
        assert_eq!(inv.memory_mb(), Some(15931));
        assert_eq!(inv.model.as_deref(), Some("PowerEdge R650"));
        assert!(inv.real_serial().is_none(), "serial needs root; empty is fine");
        assert_eq!(inv.disks.len(), 2, "tmpfs and loop devices skipped");
        assert_eq!(inv.disks[1].drive.as_deref(), Some("/var/lib/dicom"));
        assert!(inv.min_free_pct().unwrap() < 1.0);
        assert_eq!(inv.nics.len(), 1);
        assert_eq!(inv.nics[0].mac.as_deref(), Some("B8:CA:3A:01:02:03"));
        assert_eq!(inv.nics[0].ips, vec!["10.20.0.15"]);
        assert_eq!(inv.last_user.as_deref(), Some("radadmin"));
        assert_eq!(inv.software.len(), 2);
        assert_eq!(inv.software[1].version.as_deref(), Some("1.12.1+dfsg-1"));
        let orthanc = inv.services.iter().find(|s| s.name == "orthanc").unwrap();
        assert_eq!((orthanc.state.as_deref(), orthanc.start_mode.as_deref()), (Some("Failed"), Some("Auto")));
        let apt = inv.services.iter().find(|s| s.name == "apt-daily").unwrap();
        assert_eq!(apt.start_mode.as_deref(), Some("Manual"));
        assert_eq!(inv.protection.as_ref().unwrap().reboot_pending, Some(true));
        assert!(inv.last_boot.is_some());
    }

    #[test]
    fn incomplete_output_and_ssh_errors() {
        assert!(matches!(parse("@@hostname\nx\n"), Err(CollectError::Other(m)) if m.contains("incomplete")));
        assert!(matches!(categorise_ssh("user@10.0.0.5: Permission denied (publickey).", Some(255)), CollectError::AccessDenied(_)));
        assert!(matches!(categorise_ssh("ssh: connect to host 10.0.0.5 port 22: Connection timed out", Some(255)), CollectError::Unreachable(_)));
        assert!(matches!(categorise_ssh("Host key verification failed.", Some(255)), CollectError::Other(m) if m.contains("host key changed")));
    }

    #[test]
    fn apk_and_busybox_style_output() {
        let out = "@@hostname\nalpine\n@@os\nPRETTY_NAME=\"Alpine Linux v3.20\"\n@@kernel\n6.6.0\naarch64\n@@pkgs\nmusl-1.2.5-r0\nbusybox-1.36.1-r29\n@@units\n@@end\n";
        let inv = parse(out).unwrap();
        assert_eq!(inv.software[0].name, "musl");
        assert_eq!(inv.software[1].version.as_deref(), Some("1.36.1-r29"));
        assert_eq!(inv.services_error.as_deref(), Some("systemd not available"));
    }

    /// Runs the real collector with the local shell (no SSH) and parses it end to end.
    #[test]
    fn real_collector_runs_under_sh() {
        if cfg!(windows) {
            return;
        }
        let Ok(out) = std::process::Command::new("sh").arg("-c").arg(COLLECT_SH).output() else { return };
        let inv = parse(&String::from_utf8_lossy(&out.stdout)).expect("collector output parses");
        assert!(inv.computer_name.is_some());
        assert!(inv.os_build.is_some(), "kernel version");
        assert!(inv.memory_bytes.unwrap_or(0) > 0);
    }
}
