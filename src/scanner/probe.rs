//! TCP port probing, banner grabbing, ICMP ping (via the OS `ping` tool) and reverse DNS.

use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::process::Command;
use tokio::time::timeout;

/// Ports probed by default — chosen to fingerprint typical enterprise / clinic networks
/// (Windows, Linux, printers, network gear, databases, remote access, medical/HL7 interfaces).
pub const DEFAULT_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 88, 104, 135, 139, 389, 443, 445, 515, 631, 1433, 2575, 3306, 3389,
    5060, 5432, 5900, 5985, 8000, 8080, 8443, 9100,
];

pub fn service_name(port: u16) -> &'static str {
    match port {
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        53 => "dns",
        80 => "http",
        88 => "kerberos",
        104 => "dicom",
        110 => "pop3",
        135 => "msrpc",
        139 => "netbios-ssn",
        143 => "imap",
        389 => "ldap",
        443 => "https",
        445 => "smb",
        515 => "lpd",
        631 => "ipp",
        636 => "ldaps",
        1433 => "mssql",
        1521 => "oracle",
        2575 => "hl7",
        3306 => "mysql",
        3389 => "rdp",
        5060 => "sip",
        5432 => "postgresql",
        5900 => "vnc",
        5985 => "winrm",
        5986 => "winrm-https",
        8000 | 8080 => "http-alt",
        8443 => "https-alt",
        9100 => "jetdirect",
        _ => "unknown",
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortState {
    Open,
    /// RST received — port closed, but proves the host is up.
    Closed,
    Filtered,
}

pub async fn probe_port(ip: IpAddr, port: u16, to: Duration) -> PortState {
    match timeout(to, TcpStream::connect(SocketAddr::new(ip, port))).await {
        Ok(Ok(_)) => PortState::Open,
        Ok(Err(e)) if e.kind() == ErrorKind::ConnectionRefused => PortState::Closed,
        _ => PortState::Filtered,
    }
}

/// Result of an ICMP echo via the system ping binary (no raw-socket privileges needed).
#[derive(Debug, Clone, Default)]
pub struct PingResult {
    pub alive: bool,
    pub ttl: Option<u8>,
}

pub async fn ping(ip: IpAddr, to: Duration) -> PingResult {
    let ms = to.as_millis().max(200);
    let mut cmd = if cfg!(windows) {
        let mut c = Command::new("ping");
        c.args(["-n", "1", "-w", &ms.to_string(), &ip.to_string()]);
        c
    } else if cfg!(target_os = "macos") {
        let mut c = Command::new("ping");
        c.args(["-c", "1", "-W", &ms.to_string(), &ip.to_string()]);
        c
    } else {
        let mut c = Command::new("ping");
        let secs = ms.div_ceil(1000).max(1);
        c.args(["-c", "1", "-W", &secs.to_string(), &ip.to_string()]);
        c
    };
    #[cfg(windows)]
    {
        // CREATE_NO_WINDOW: don't flash a console per ping when running as a service.
        cmd.creation_flags(0x0800_0000);
    }
    cmd.kill_on_drop(true);
    let out = match timeout(to + Duration::from_millis(1500), cmd.output()).await {
        Ok(Ok(o)) => o,
        _ => return PingResult::default(),
    };
    let text = String::from_utf8_lossy(&out.stdout).to_lowercase();
    // Windows returns exit code 0 for "Destination host unreachable", so require a TTL in the reply.
    match text.find("ttl=") {
        Some(i) => {
            let digits: String = text[i + 4..].chars().take_while(|c| c.is_ascii_digit()).collect();
            PingResult { alive: true, ttl: digits.parse().ok() }
        }
        None => PingResult::default(),
    }
}

pub async fn reverse_dns(ip: IpAddr, to: Duration) -> Option<String> {
    let fut = tokio::task::spawn_blocking(move || dns_lookup::lookup_addr(&ip).ok());
    match timeout(to, fut).await {
        Ok(Ok(Some(name))) if name != ip.to_string() => Some(name.trim_end_matches('.').to_string()),
        _ => None,
    }
}

fn clean(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control() || *c == ' ')
        .collect::<String>()
        .trim()
        .chars()
        .take(200)
        .collect()
}

/// Read the first line a server volunteers on connect (SSH, FTP, SMTP, telnet...).
pub async fn grab_banner(ip: IpAddr, port: u16, to: Duration) -> Option<String> {
    let mut s = timeout(to, TcpStream::connect(SocketAddr::new(ip, port))).await.ok()?.ok()?;
    let mut buf = vec![0u8; 512];
    let n = timeout(to, s.read(&mut buf)).await.ok()?.ok()?;
    let text = String::from_utf8_lossy(&buf[..n]);
    let line = text.lines().next().unwrap_or("");
    let c = clean(line);
    (!c.is_empty()).then_some(c)
}

#[derive(Debug, Clone, Default)]
pub struct HttpInfo {
    pub server: Option<String>,
    pub title: Option<String>,
}

/// Plain-HTTP GET / to collect the Server header and page <title>.
pub async fn http_info(ip: IpAddr, port: u16, to: Duration) -> Option<HttpInfo> {
    let mut s = timeout(to, TcpStream::connect(SocketAddr::new(ip, port))).await.ok()?.ok()?;
    let req = format!(
        "GET / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: RustSweeper/0.1\r\nAccept: text/html\r\nConnection: close\r\n\r\n"
    );
    timeout(to, s.write_all(req.as_bytes())).await.ok()?.ok()?;
    let mut buf = Vec::with_capacity(16 * 1024);
    let mut chunk = [0u8; 4096];
    while buf.len() < 64 * 1024 {
        match timeout(to, s.read(&mut chunk)).await {
            Ok(Ok(0)) | Err(_) | Ok(Err(_)) => break,
            Ok(Ok(n)) => buf.extend_from_slice(&chunk[..n]),
        }
    }
    if buf.is_empty() {
        return None;
    }
    let text = String::from_utf8_lossy(&buf);
    if !text.starts_with("HTTP/") {
        return None;
    }
    let mut info = HttpInfo::default();
    for line in text.lines() {
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            if k.eq_ignore_ascii_case("server") {
                info.server = Some(clean(v));
            }
        }
    }
    let lower = text.to_ascii_lowercase(); // ASCII-only so byte offsets match `text`
    if let Some(start) = lower.find("<title") {
        if let Some(gt) = lower[start..].find('>') {
            let from = start + gt + 1;
            if let Some(end) = lower[from..].find("</title>") {
                let t = clean(&text[from..from + end]);
                if !t.is_empty() {
                    info.title = Some(t);
                }
            }
        }
    }
    Some(info)
}
