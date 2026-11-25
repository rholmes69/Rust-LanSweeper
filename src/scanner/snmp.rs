//! Minimal SNMP v2c GET of the MIB-II "system" group (sysDescr, sysObjectID, sysContact,
//! sysName, sysLocation). Hand-rolled BER so there are no extra dependencies.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::timeout;

#[derive(Debug, Clone, Default, PartialEq, serde::Serialize)]
pub struct SnmpInfo {
    pub descr: Option<String>,
    pub object_id: Option<String>,
    pub contact: Option<String>,
    pub name: Option<String>,
    pub location: Option<String>,
}

const SYS_DESCR: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 1, 0];
const SYS_OBJECT_ID: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 2, 0];
const SYS_CONTACT: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 4, 0];
const SYS_NAME: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 5, 0];
const SYS_LOCATION: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 6, 0];

// ------------------------------------------------------------------ BER encoding

fn enc_len(len: usize, out: &mut Vec<u8>) {
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes: Vec<u8> = len.to_be_bytes().iter().copied().skip_while(|&b| b == 0).collect();
        out.push(0x80 | bytes.len() as u8);
        out.extend(bytes);
    }
}

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut v = vec![tag];
    enc_len(content.len(), &mut v);
    v.extend_from_slice(content);
    v
}

fn enc_int(n: i64) -> Vec<u8> {
    let mut bytes = n.to_be_bytes().to_vec();
    while bytes.len() > 1
        && ((bytes[0] == 0x00 && bytes[1] & 0x80 == 0) || (bytes[0] == 0xFF && bytes[1] & 0x80 != 0))
    {
        bytes.remove(0);
    }
    tlv(0x02, &bytes)
}

fn enc_oid(oid: &[u32]) -> Vec<u8> {
    let mut c = vec![(oid[0] * 40 + oid[1]) as u8];
    for &arc in &oid[2..] {
        let mut stack = vec![(arc & 0x7F) as u8];
        let mut v = arc >> 7;
        while v > 0 {
            stack.push(((v & 0x7F) as u8) | 0x80);
            v >>= 7;
        }
        c.extend(stack.iter().rev());
    }
    tlv(0x06, &c)
}

pub fn build_get(community: &str, request_id: i32) -> Vec<u8> {
    let mut varbinds = Vec::new();
    for oid in [SYS_DESCR, SYS_OBJECT_ID, SYS_CONTACT, SYS_NAME, SYS_LOCATION] {
        let mut vb = enc_oid(oid);
        vb.extend_from_slice(&[0x05, 0x00]); // NULL
        varbinds.extend(tlv(0x30, &vb));
    }
    let mut pdu = enc_int(request_id as i64);
    pdu.extend(enc_int(0)); // error-status
    pdu.extend(enc_int(0)); // error-index
    pdu.extend(tlv(0x30, &varbinds));
    let mut msg = enc_int(1); // version: v2c
    msg.extend(tlv(0x04, community.as_bytes()));
    msg.extend(tlv(0xA0, &pdu)); // GetRequest-PDU
    tlv(0x30, &msg)
}

// ------------------------------------------------------------------ BER decoding

struct Tlv<'a> {
    tag: u8,
    val: &'a [u8],
}

/// Read one TLV from the front of `buf`; return it and the remainder.
fn read_tlv(buf: &[u8]) -> Option<(Tlv<'_>, &[u8])> {
    let tag = *buf.first()?;
    let first = *buf.get(1)? as usize;
    let (len, hdr) = if first & 0x80 == 0 {
        (first, 2)
    } else {
        let n = first & 0x7F;
        if n == 0 || n > 4 {
            return None;
        }
        let mut l = 0usize;
        for i in 0..n {
            l = (l << 8) | *buf.get(2 + i)? as usize;
        }
        (l, 2 + n)
    };
    let end = hdr.checked_add(len)?;
    if buf.len() < end {
        return None;
    }
    Some((Tlv { tag, val: &buf[hdr..end] }, &buf[end..]))
}

fn dec_oid(b: &[u8]) -> Vec<u32> {
    if b.is_empty() {
        return vec![];
    }
    let mut out = vec![(b[0] / 40) as u32, (b[0] % 40) as u32];
    let mut v: u32 = 0;
    for &x in &b[1..] {
        v = (v << 7) | (x & 0x7F) as u32;
        if x & 0x80 == 0 {
            out.push(v);
            v = 0;
        }
    }
    out
}

fn oid_str(o: &[u32]) -> String {
    o.iter().map(|n| n.to_string()).collect::<Vec<_>>().join(".")
}

pub fn parse_response(buf: &[u8], expect_id: i32) -> Option<SnmpInfo> {
    let (msg, _) = read_tlv(buf)?;
    if msg.tag != 0x30 {
        return None;
    }
    let (_version, rest) = read_tlv(msg.val)?;
    let (_community, rest) = read_tlv(rest)?;
    let (pdu, _) = read_tlv(rest)?;
    if pdu.tag != 0xA2 {
        return None; // not a GetResponse
    }
    let (reqid, rest) = read_tlv(pdu.val)?;
    let id = reqid.val.iter().fold(0i64, |a, &b| (a << 8) | b as i64);
    if id as i32 != expect_id {
        return None;
    }
    let (err, rest) = read_tlv(rest)?;
    if err.val.iter().any(|&b| b != 0) {
        return None;
    }
    let (_erridx, rest) = read_tlv(rest)?;
    let (vbl, _) = read_tlv(rest)?;
    let mut info = SnmpInfo::default();
    let mut cur = vbl.val;
    while let Some((vb, next)) = read_tlv(cur) {
        cur = next;
        let Some((oid, r)) = read_tlv(vb.val) else { continue };
        let Some((val, _)) = read_tlv(r) else { continue };
        let oid = dec_oid(oid.val);
        let text = match val.tag {
            0x04 => {
                let s: String = String::from_utf8_lossy(val.val)
                    .chars()
                    .map(|c| if c.is_control() { ' ' } else { c })
                    .collect();
                let s = s.trim().to_string();
                (!s.is_empty()).then_some(s)
            }
            0x06 => Some(oid_str(&dec_oid(val.val))),
            _ => None, // noSuchObject / noSuchInstance / endOfMibView
        };
        match oid.as_slice() {
            o if o == SYS_DESCR => info.descr = text,
            o if o == SYS_OBJECT_ID => info.object_id = text,
            o if o == SYS_CONTACT => info.contact = text,
            o if o == SYS_NAME => info.name = text,
            o if o == SYS_LOCATION => info.location = text,
            _ => {}
        }
    }
    (info != SnmpInfo::default()).then_some(info)
}

pub async fn query(ip: IpAddr, community: &str, to: Duration) -> Option<SnmpInfo> {
    let bind = if ip.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let sock = UdpSocket::bind(bind).await.ok()?;
    let id = (super::netbios::rand_u16() as i32) | 0x0100_0000;
    sock.send_to(&build_get(community, id), SocketAddr::new(ip, 161)).await.ok()?;
    let mut buf = vec![0u8; 4096];
    let (n, _) = timeout(to, sock.recv_from(&mut buf)).await.ok()?.ok()?;
    parse_response(&buf[..n], id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oid_roundtrip() {
        let o = [1, 3, 6, 1, 4, 1, 9, 1, 516];
        let e = enc_oid(&o);
        assert_eq!(dec_oid(&e[2..]), o.to_vec());
    }

    #[test]
    fn int_encoding() {
        assert_eq!(enc_int(0), vec![2, 1, 0]);
        assert_eq!(enc_int(128), vec![2, 2, 0, 128]);
        assert_eq!(enc_int(-1), vec![2, 1, 0xFF]);
    }

    /// Turn our own GetRequest into a GetResponse with values and make sure we parse it.
    #[test]
    fn parses_synthetic_response() {
        let mk_vb = |oid: &[u32], val: Vec<u8>| {
            let mut v = enc_oid(oid);
            v.extend(val);
            tlv(0x30, &v)
        };
        let mut vbs = Vec::new();
        vbs.extend(mk_vb(SYS_DESCR, tlv(0x04, b"HP ETHERNET MULTI-ENVIRONMENT,JETDIRECT")));
        vbs.extend(mk_vb(SYS_OBJECT_ID, enc_oid(&[1, 3, 6, 1, 4, 1, 11, 2, 3, 9, 1])));
        vbs.extend(mk_vb(SYS_NAME, tlv(0x04, b"NPI4A1B2C")));
        vbs.extend(mk_vb(SYS_LOCATION, vec![0x81, 0x00])); // noSuchInstance-ish
        let mut pdu = enc_int(77);
        pdu.extend(enc_int(0));
        pdu.extend(enc_int(0));
        pdu.extend(tlv(0x30, &vbs));
        let mut msg = enc_int(1);
        msg.extend(tlv(0x04, b"public"));
        msg.extend(tlv(0xA2, &pdu));
        let pkt = tlv(0x30, &msg);
        let i = parse_response(&pkt, 77).unwrap();
        assert!(i.descr.unwrap().contains("JETDIRECT"));
        assert_eq!(i.name.as_deref(), Some("NPI4A1B2C"));
        assert_eq!(i.object_id.as_deref(), Some("1.3.6.1.4.1.11.2.3.9.1"));
        assert!(i.location.is_none());
        assert!(parse_response(&pkt, 78).is_none());
        // And the request we send is well-formed BER.
        assert!(read_tlv(&build_get("public", 5)).is_some());
    }
}
