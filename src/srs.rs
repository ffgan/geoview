use std::cmp::Ordering;
use std::io::Write;

use flate2::write::ZlibEncoder;
use flate2::Compression;

use crate::domainset::{self, SuccinctSet};
use crate::proto;

#[derive(Clone, Debug, Default)]
pub struct Rules {
    pub domain: Vec<String>,
    pub suffix: Vec<String>,
    pub keyword: Vec<String>,
    pub regex: Vec<String>,
    pub ip: Vec<String>,
}

pub fn ruleset_json(rules: &Rules) -> String {
    let mut fields = Vec::new();
    push_list(&mut fields, "domain", &rules.domain);
    push_list(&mut fields, "domain_suffix", &rules.suffix);
    push_list(&mut fields, "domain_keyword", &rules.keyword);
    push_list(&mut fields, "domain_regex", &rules.regex);
    push_list(&mut fields, "ip_cidr", &rules.ip);
    format!("{{\"version\":3,\"rules\":[{{{}}}]}}\n", fields.join(","))
}

fn push_list(fields: &mut Vec<String>, name: &str, values: &[String]) {
    if values.is_empty() {
        return;
    }
    fields.push(format!("\"{name}\":{}", listable(values)));
}

fn listable(values: &[String]) -> String {
    if values.len() == 1 {
        format!("\"{}\"", json_escape(&values[0]))
    } else {
        let items: Vec<String> = values.iter().map(|value| format!("\"{}\"", json_escape(value))).collect();
        format!("[{}]", items.join(","))
    }
}

fn json_escape(value: &str) -> String {
    let mut out = String::new();
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{000c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '&' => out.push_str("\\u0026"),
            '<' => out.push_str("\\u003c"),
            '>' => out.push_str("\\u003e"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

pub fn ruleset_binary(rules: &Rules) -> Result<Vec<u8>, String> {
    let mut payload = Vec::new();
    proto::write_varint(&mut payload, 1);
    write_default_rule(&mut payload, rules)?;
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
    encoder.write_all(&payload).map_err(|err| err.to_string())?;
    let compressed = encoder.finish().map_err(|err| err.to_string())?;
    let mut out = Vec::with_capacity(4 + compressed.len());
    out.extend_from_slice(b"SRS");
    out.push(3);
    out.extend_from_slice(&compressed);
    Ok(out)
}

fn write_default_rule(out: &mut Vec<u8>, rules: &Rules) -> Result<(), String> {
    out.push(0);
    if !rules.domain.is_empty() || !rules.suffix.is_empty() {
        out.push(2);
        let matcher: SuccinctSet = domainset::matcher(&rules.domain, &rules.suffix);
        domainset::write_matcher(&matcher, out);
    }
    if !rules.keyword.is_empty() {
        out.push(3);
        write_strings(out, &rules.keyword);
    }
    if !rules.regex.is_empty() {
        out.push(4);
        write_strings(out, &rules.regex);
    }
    if !rules.ip.is_empty() {
        out.push(6);
        write_ipset(out, &rules.ip)?;
    }
    out.push(0xff);
    out.push(0);
    Ok(())
}

fn write_strings(out: &mut Vec<u8>, values: &[String]) {
    proto::write_varint(out, values.len() as u64);
    for value in values {
        proto::write_varint(out, value.len() as u64);
        out.extend_from_slice(value.as_bytes());
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Addr {
    V4(u32),
    V6(u128),
}

impl PartialOrd for Addr {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Addr {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Addr::V4(left), Addr::V4(right)) => left.cmp(right),
            (Addr::V6(left), Addr::V6(right)) => left.cmp(right),
            (Addr::V4(_), Addr::V6(_)) => Ordering::Less,
            (Addr::V6(_), Addr::V4(_)) => Ordering::Greater,
        }
    }
}

fn write_ipset(out: &mut Vec<u8>, cidrs: &[String]) -> Result<(), String> {
    let ranges = merge_ranges(cidrs)?;
    out.push(1);
    out.extend_from_slice(&(ranges.len() as u64).to_be_bytes());
    for (start, end) in ranges {
        write_addr(out, start);
        write_addr(out, end);
    }
    Ok(())
}

fn write_addr(out: &mut Vec<u8>, addr: Addr) {
    let bytes = match addr {
        Addr::V4(value) => value.to_be_bytes().to_vec(),
        Addr::V6(value) => value.to_be_bytes().to_vec(),
    };
    proto::write_varint(out, bytes.len() as u64);
    out.extend_from_slice(&bytes);
}

fn merge_ranges(cidrs: &[String]) -> Result<Vec<(Addr, Addr)>, String> {
    let mut ranges = Vec::with_capacity(cidrs.len());
    for (index, cidr) in cidrs.iter().enumerate() {
        let (start, end) = cidr_range(cidr).map_err(|err| format!("{err} [index {index}]"))?;
        ranges.push((start, end));
    }
    if ranges.is_empty() {
        return Ok(ranges);
    }
    ranges.sort();
    let mut merged = vec![ranges[0]];
    for (start, end) in ranges.into_iter().skip(1) {
        let last = merged.last_mut().unwrap();
        let adjacent = next_addr(last.1).is_some_and(|next| start <= next);
        if start <= last.1 || adjacent {
            if end > last.1 {
                last.1 = end;
            }
        } else {
            merged.push((start, end));
        }
    }
    Ok(merged)
}

fn next_addr(addr: Addr) -> Option<Addr> {
    match addr {
        Addr::V4(value) => value.checked_add(1).map(Addr::V4),
        Addr::V6(value) => value.checked_add(1).map(Addr::V6),
    }
}

fn cidr_range(cidr: &str) -> Result<(Addr, Addr), String> {
    let (addr, bits) = if let Some((addr, bits)) = cidr.split_once('/') {
        let bits: u32 = bits.parse().map_err(|_| format!("invalid prefix {cidr}"))?;
        (parse_addr(addr)?, bits)
    } else {
        let addr = parse_addr(cidr)?;
        let bits = match addr {
            Addr::V4(_) => 32,
            Addr::V6(_) => 128,
        };
        (addr, bits)
    };
    match addr {
        Addr::V4(ip) => {
            if bits > 32 {
                return Err(format!("invalid prefix {cidr}"));
            }
            let mask = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
            if ip & mask != ip {
                return Err(format!("invalid prefix {cidr}"));
            }
            let end = ip | !mask;
            Ok((Addr::V4(ip), Addr::V4(end)))
        }
        Addr::V6(ip) => {
            if bits > 128 {
                return Err(format!("invalid prefix {cidr}"));
            }
            let mask = if bits == 0 { 0 } else { u128::MAX << (128 - bits) };
            if ip & mask != ip {
                return Err(format!("invalid prefix {cidr}"));
            }
            let end = ip | !mask;
            Ok((Addr::V6(ip), Addr::V6(end)))
        }
    }
}

fn parse_addr(text: &str) -> Result<Addr, String> {
    if let Ok(ip) = text.parse::<std::net::Ipv4Addr>() {
        return Ok(Addr::V4(u32::from(ip)));
    }
    if let Ok(ip) = text.parse::<std::net::Ipv6Addr>() {
        return Ok(Addr::V6(u128::from(ip)));
    }
    Err(format!("invalid ip {text}"))
}
