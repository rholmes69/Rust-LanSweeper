//! NetBIOS Node Status (NBSTAT) query over UDP/137 — returns the Windows computer name,
//! workgroup/domain and the adapter MAC, even across routed subnets.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::timeout;

#[derive(Debug, Clone, Default, PartialEq)]
pub struct NetbiosInfo {
    pub name: Option<String>,
    pub domain: Option<String>,
    pub mac: Option<String>,
}

pub fn build_request(txid: u16) -> Vec<u8> {
    let mut p = Vec::with_capacity(50);
    p.extend_from_slice(&txid.to_be_bytes());
    p.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    // Encoded wildcard name "*" padded with NULs (first-level encoding, RFC 1001 §14.1).
    p.push(0x20);
    let mut raw = [0u8; 16];
    raw[0] = b'*';
    for b in raw {
        p.push(b'A' + (b >> 4));
        p.push(b'A' + (b & 0x0F));
    }
    p.push(0x00);
    p.extend_from_slice(&[0x00, 0x21, 0x00, 0x01]); // NBSTAT, IN
    p
}

pub fn parse_response(buf: &[u8]) -> Option<NetbiosInfo> {
    // header(12) + name(34) + type(2) class(2) ttl(4) rdlength(2) = 56
    if buf.len() < 57 {
        return None;
    }
    let count = buf[56] as usize;
    let names_start = 57;
    if buf.len() < names_start + count * 18 {
        return None;
    }
    let mut info = NetbiosInfo::default();
    for i in 0..count {
        let e = &buf[names_start + i * 18..names_start + (i + 1) * 18];
        let name = String::from_utf8_lossy(&e[..15]).trim_end().to_string();
        let suffix = e[15];
        let group = e[16] & 0x80 != 0;
        if suffix == 0x00 && !group && info.name.is_none() {
            info.name = Some(name);
        } else if suffix == 0x00 && group && info.domain.is_none() {
            info.domain = Some(name);
        }
    }
    let mac_off = names_start + count * 18;
    if buf.len() >= mac_off + 6 {
        let m = &buf[mac_off..mac_off + 6];
        if m.iter().any(|&b| b != 0) {
            info.mac = Some(
                m.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(":"),
            );
        }
    }
    (info.name.is_some() || info.domain.is_some()).then_some(info)
}

pub async fn query(ip: IpAddr, to: Duration) -> Option<NetbiosInfo> {
    let bind = if ip.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let sock = UdpSocket::bind(bind).await.ok()?;
    let txid: u16 = rand_u16();
    sock.send_to(&build_request(txid), SocketAddr::new(ip, 137)).await.ok()?;
    let mut buf = [0u8; 1024];
    let (n, _) = timeout(to, sock.recv_from(&mut buf)).await.ok()?.ok()?;
    if n < 2 || buf[..2] != txid.to_be_bytes() {
        return None;
    }
    parse_response(&buf[..n])
}

pub(crate) fn rand_u16() -> u16 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let n = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.subsec_nanos()).unwrap_or(0);
    (n ^ (n >> 16)) as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_shape() {
        let r = build_request(0x1234);
        assert_eq!(r.len(), 50);
        assert_eq!(&r[13..15], b"CK"); // '*' = 0x2A -> 'C','K'
        assert_eq!(&r[46..50], &[0, 0x21, 0, 1]);
    }

    #[test]
    fn parses_names_and_mac() {
        let mut b = vec![0u8; 56];
        b.push(2);
        let mut e1 = b"FRONTDESK-01   ".to_vec();
        e1.extend_from_slice(&[0x00, 0x04, 0x00]);
        let mut e2 = b"DELTAHC        ".to_vec();
        e2.extend_from_slice(&[0x00, 0x84, 0x00]);
        b.extend(e1);
        b.extend(e2);
        b.extend_from_slice(&[0x00, 0x50, 0x56, 0xAB, 0xCD, 0xEF]);
        let i = parse_response(&b).unwrap();
        assert_eq!(i.name.as_deref(), Some("FRONTDESK-01"));
        assert_eq!(i.domain.as_deref(), Some("DELTAHC"));
        assert_eq!(i.mac.as_deref(), Some("00:50:56:AB:CD:EF"));
    }
}
