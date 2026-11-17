use std::fs::File;
use std::io::Read;

use crate::proto::{self, field_bytes, field_str, field_varint};

#[derive(Clone, Debug)]
pub struct Cidr {
    pub ip: Vec<u8>,
    pub prefix: u32,
}

#[derive(Clone, Debug)]
pub struct Domain {
    pub kind: u32,
    pub value: String,
    pub attrs: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct GeoIpEntry {
    pub code: String,
    pub cidrs: Vec<Cidr>,
}

#[derive(Clone, Debug)]
pub struct GeoSiteEntry {
    pub code: String,
    pub domains: Vec<Domain>,
}

pub fn open_error(path: &str, err: std::io::Error) -> String {
    if err.kind() == std::io::ErrorKind::NotFound {
        format!("open {path}: no such file or directory")
    } else {
        format!("open {path}: {err}")
    }
}

pub fn read_file(path: &str) -> Result<Vec<u8>, String> {
    let mut file = File::open(path).map_err(|err| open_error(path, err))?;
    let mut data = Vec::new();
    file.read_to_end(&mut data).map_err(|err| err.to_string())?;
    Ok(data)
}

pub fn is_protobuf(data: &[u8]) -> bool {
    let sample = &data[..data.len().min(1024)];
    sample.iter().any(|byte| *byte < 0x20 && !matches!(*byte, b'\n' | b'\r' | b'\t'))
}

pub fn parse_geoip(body: &[u8]) -> GeoIpEntry {
    let mut entry = GeoIpEntry {
        code: String::new(),
        cidrs: Vec::new(),
    };
    let Some(fields) = proto::parse_message(body) else {
        return entry;
    };
    for field in fields {
        match field.number {
            1 => {
                if let Some(code) = field_str(&field) {
                    entry.code = code;
                }
            }
            2 => {
                if let Some(bytes) = field_bytes(&field) {
                    if let Some(cidr) = parse_cidr(bytes) {
                        entry.cidrs.push(cidr);
                    }
                }
            }
            _ => {}
        }
    }
    entry
}

fn parse_cidr(body: &[u8]) -> Option<Cidr> {
    let fields = proto::parse_message(body)?;
    let mut ip = Vec::new();
    let mut prefix = 0u32;
    for field in fields {
        match field.number {
            1 => {
                if let Some(bytes) = field_bytes(&field) {
                    ip = bytes.to_vec();
                }
            }
            2 => prefix = field_varint(&field).unwrap_or(0) as u32,
            _ => {}
        }
    }
    if ip.is_empty() {
        return None;
    }
    Some(Cidr { ip, prefix })
}

pub fn parse_geosite(body: &[u8]) -> GeoSiteEntry {
    let mut entry = GeoSiteEntry {
        code: String::new(),
        domains: Vec::new(),
    };
    let Some(fields) = proto::parse_message(body) else {
        return entry;
    };
    for field in fields {
        match field.number {
            1 => {
                if let Some(code) = field_str(&field) {
                    entry.code = code;
                }
            }
            2 => {
                if let Some(bytes) = field_bytes(&field) {
                    if let Some(domain) = parse_domain(bytes) {
                        entry.domains.push(domain);
                    }
                }
            }
            _ => {}
        }
    }
    entry
}

fn parse_domain(body: &[u8]) -> Option<Domain> {
    let fields = proto::parse_message(body)?;
    let mut domain = Domain {
        kind: 0,
        value: String::new(),
        attrs: Vec::new(),
    };
    for field in fields {
        match field.number {
            1 => domain.kind = field_varint(&field).unwrap_or(0) as u32,
            2 => domain.value = field_str(&field).unwrap_or_default(),
            3 => {
                if let Some(bytes) = field_bytes(&field) {
                    if let Some(key) = parse_attr(bytes) {
                        if !key.is_empty() {
                            domain.attrs.push(key);
                        }
                    }
                }
            }
            _ => {}
        }
    }
    Some(domain)
}

fn parse_attr(body: &[u8]) -> Option<String> {
    let fields = proto::parse_message(body)?;
    fields.iter().find(|field| field.number == 1).and_then(field_str)
}

#[derive(Clone, Debug)]
pub struct Located {
    pub code: String,
    pub start: usize,
    pub end: usize,
}

pub fn peek_code(body: &[u8]) -> String {
    let mut pos = 0;
    if let Some(key) = proto::read_varint(body, &mut pos) {
        let field = (key >> 3) as u32;
        let wire = (key & 7) as u32;
        if field == 1 && wire == 2 {
            if let Some(len) = proto::read_varint(body, &mut pos) {
                let len = len as usize;
                if pos + len <= body.len() {
                    return String::from_utf8_lossy(&body[pos..pos + len]).into_owned();
                }
            }
        }
    }
    parse_geosite(body).code
}

pub fn locate_v2(data: &[u8]) -> Vec<Located> {
    let mut located = Vec::new();
    let mut pos = 0;
    while pos < data.len() {
        let start = pos;
        let Some(key) = proto::read_varint(data, &mut pos) else {
            break;
        };
        let field = (key >> 3) as u32;
        let wire = (key & 7) as u32;
        if wire != 2 || field == 0 {
            if start == 0 {
                return Vec::new();
            }
            break;
        }
        let Some(len) = proto::read_varint(data, &mut pos) else {
            break;
        };
        let len = len as usize;
        if pos + len > data.len() {
            break;
        }
        let body_start = pos;
        let body_end = pos + len;
        pos = body_end;
        if field == 1 {
            located.push(Located {
                code: peek_code(&data[body_start..body_end]),
                start: body_start,
                end: body_end,
            });
        }
    }
    located
}

pub fn sing_sites(data: &[u8]) -> Option<Vec<GeoSiteEntry>> {
    let mut pos = 1usize;
    let count = proto::read_varint(data, &mut pos)? as usize;
    let mut index = Vec::with_capacity(count);
    for _ in 0..count {
        let code = read_vstring(data, &mut pos)?;
        let offset = proto::read_varint(data, &mut pos)? as usize;
        let items = proto::read_varint(data, &mut pos)? as usize;
        index.push((code, offset, items));
    }
    let base = pos;
    let mut entries = Vec::with_capacity(index.len());
    for (code, offset, items) in index {
        let mut cursor = base + offset;
        let mut domains = Vec::with_capacity(items);
        for _ in 0..items {
            if cursor >= data.len() {
                return None;
            }
            let kind = sing_kind(data[cursor]);
            cursor += 1;
            let mut value = read_vstring(data, &mut cursor)?;
            if kind == 2 && value.starts_with('.') {
                value.remove(0);
            }
            domains.push(Domain {
                kind,
                value,
                attrs: Vec::new(),
            });
        }
        entries.push(GeoSiteEntry { code, domains });
    }
    Some(entries)
}

fn sing_kind(raw: u8) -> u32 {
    match raw {
        0 => 3, // exact domain
        1 => 2, // suffix
        2 => 0, // keyword
        3 => 1, // regex
        _ => 3,
    }
}

fn read_vstring(data: &[u8], pos: &mut usize) -> Option<String> {
    let len = proto::read_varint(data, pos)? as usize;
    if *pos + len > data.len() {
        return None;
    }
    let bytes = &data[*pos..*pos + len];
    *pos += len;
    Some(String::from_utf8_lossy(bytes).into_owned())
}

pub fn encode_geoip(entries: &[GeoIpEntry]) -> Vec<u8> {
    let mut out = Vec::new();
    for entry in entries {
        if entry.cidrs.is_empty() {
            continue;
        }
        let mut body = Vec::new();
        proto::write_string(&mut body, 1, &entry.code);
        for cidr in &entry.cidrs {
            let mut message = Vec::new();
            proto::write_bytes(&mut message, 1, &cidr.ip);
            proto::write_uint(&mut message, 2, u64::from(cidr.prefix));
            proto::write_message(&mut body, 2, &message);
        }
        proto::write_message(&mut out, 1, &body);
    }
    out
}

pub fn encode_geosite(entries: &[GeoSiteEntry]) -> Vec<u8> {
    let mut out = Vec::new();
    for entry in entries {
        if entry.domains.is_empty() {
            continue;
        }
        let mut body = Vec::new();
        proto::write_string(&mut body, 1, &entry.code);
        for domain in &entry.domains {
            let mut message = Vec::new();
            proto::write_uint(&mut message, 1, u64::from(domain.kind));
            proto::write_string(&mut message, 2, &domain.value);
            for attr in &domain.attrs {
                let mut attribute = Vec::new();
                proto::write_string(&mut attribute, 1, attr);
                proto::write_message(&mut message, 3, &attribute);
            }
            proto::write_message(&mut body, 2, &message);
        }
        proto::write_message(&mut out, 1, &body);
    }
    out
}

pub fn text_geoip(path: &str) -> Result<Vec<GeoIpEntry>, String> {
    let text = std::fs::read_to_string(path).map_err(|err| open_error(path, err))?;
    let mut order = Vec::new();
    let mut map: std::collections::HashMap<String, Vec<Cidr>> = std::collections::HashMap::new();
    let mut current = "ALL".to_string();
    order.push(current.clone());
    map.insert(current.clone(), Vec::new());
    for line in text.lines() {
        if let Some(code) = section_code(line) {
            current = code;
            if !map.contains_key(&current) {
                order.push(current.clone());
                map.insert(current.clone(), Vec::new());
            }
            continue;
        }
        if let Some(cidr) = parse_ip_line(line) {
            map.get_mut(&current).unwrap().push(cidr);
        }
    }
    Ok(order
        .into_iter()
        .filter_map(|code| {
            let cidrs = map.remove(&code).unwrap_or_default();
            if cidrs.is_empty() {
                None
            } else {
                Some(GeoIpEntry { code, cidrs })
            }
        })
        .collect())
}

pub fn text_geosite(path: &str) -> Result<Vec<GeoSiteEntry>, String> {
    let text = std::fs::read_to_string(path).map_err(|err| open_error(path, err))?;
    let mut order = Vec::new();
    let mut map: std::collections::HashMap<String, Vec<Domain>> = std::collections::HashMap::new();
    let mut current = "ALL".to_string();
    order.push(current.clone());
    map.insert(current.clone(), Vec::new());
    for line in text.lines() {
        if let Some(code) = section_code(line) {
            current = code;
            if !map.contains_key(&current) {
                order.push(current.clone());
                map.insert(current.clone(), Vec::new());
            }
            continue;
        }
        if let Some(domain) = parse_domain_line(line) {
            map.get_mut(&current).unwrap().push(domain);
        }
    }
    Ok(order
        .into_iter()
        .filter_map(|code| {
            let domains = map.remove(&code).unwrap_or_default();
            if domains.is_empty() {
                None
            } else {
                Some(GeoSiteEntry { code, domains })
            }
        })
        .collect())
}

fn section_code(line: &str) -> Option<String> {
    let trimmed = line.trim();
    let rest = trimmed.strip_prefix('#')?;
    let code = rest.trim();
    if code.is_empty() {
        return None;
    }
    Some(code.to_uppercase())
}

fn parse_domain_line(line: &str) -> Option<Domain> {
    let mut line = line.trim();
    if line.is_empty() {
        return None;
    }
    let kind = if let Some(rest) = line.strip_prefix("full:") {
        line = rest;
        3
    } else {
        2
    };
    let mut parts = line.split('@');
    let value = parts.next()?.trim().to_lowercase();
    if value.is_empty() {
        return None;
    }
    let attrs = parts
        .map(|part| part.trim().to_lowercase())
        .filter(|part| !part.is_empty())
        .collect();
    Some(Domain { kind, value, attrs })
}

fn parse_ip_line(line: &str) -> Option<Cidr> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }
    let (addr, prefix) = if let Some((addr, bits)) = line.split_once('/') {
        let bits: u32 = bits.parse().ok()?;
        (addr, Some(bits))
    } else {
        (line, None)
    };
    if let Ok(ip) = addr.parse::<std::net::Ipv4Addr>() {
        let prefix = prefix.unwrap_or(32);
        if prefix > 32 {
            return None;
        }
        return Some(Cidr {
            ip: ip.octets().to_vec(),
            prefix,
        });
    }
    if let Ok(ip) = addr.parse::<std::net::Ipv6Addr>() {
        let prefix = prefix.unwrap_or(128);
        if prefix > 128 {
            return None;
        }
        return Some(Cidr {
            ip: ip.octets().to_vec(),
            prefix,
        });
    }
    None
}

pub fn format_ip(ip: &[u8]) -> String {
    match ip.len() {
        4 => std::net::Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]).to_string(),
        16 => {
            let octets: [u8; 16] = ip.try_into().unwrap_or([0; 16]);
            let addr = std::net::Ipv6Addr::from(octets);
            if let Some(v4) = addr.to_ipv4_mapped() {
                v4.to_string()
            } else {
                addr.to_string()
            }
        }
        _ => String::new(),
    }
}

pub fn is_ipv4(ip: &[u8]) -> bool {
    ip.len() == 4 || (ip.len() == 16 && std::net::Ipv6Addr::from(<[u8; 16]>::try_from(ip).unwrap_or([0; 16])).to_ipv4_mapped().is_some())
}

pub fn cidr_line(cidr: &Cidr) -> String {
    format!("{}/{}", format_ip(&cidr.ip), cidr.prefix)
}
