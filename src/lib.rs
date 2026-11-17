mod dat;
mod domainset;
mod proto;
mod srs;

use std::collections::{HashMap, HashSet};
use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};

use dat::{Cidr, Domain, GeoIpEntry, GeoSiteEntry};
use srs::Rules;

pub const VERSION: &str = "0.3.0";

struct Flags {
    input: String,
    datatype: String,
    action: String,
    list: String,
    ipv4: bool,
    ipv6: bool,
    regex: bool,
    output: String,
    value: String,
    format: String,
    append: bool,
    strict: bool,
    version: bool,
}

impl Flags {
    fn new() -> Self {
        Self {
            input: String::new(),
            datatype: "geoip".to_string(),
            action: "extract".to_string(),
            list: String::new(),
            ipv4: true,
            ipv6: true,
            regex: false,
            output: String::new(),
            value: String::new(),
            format: "ruleset".to_string(),
            append: false,
            strict: true,
            version: false,
        }
    }
}

pub fn run() -> i32 {
    let args: Vec<String> = std::env::args().collect();
    match run_args(&args) {
        Ok(code) => code,
        Err(message) => {
            if !message.is_empty() {
                eprintln!("Error: {message}");
            }
            1
        }
    }
}

fn run_args(args: &[String]) -> Result<i32, String> {
    let program = args.first().map(String::as_str).unwrap_or("geoview");
    let flags = parse_flags(&args[1..])?;
    if flags.version {
        println!("Geoview {VERSION}");
        return Ok(0);
    }
    if flags.input.is_empty() {
        eprintln!("Error: Input file empty\n");
        eprint!("{}", usage(program));
        return Ok(0);
    }
    match flags.action.as_str() {
        "extract" => {
            if flags.list.is_empty() {
                if let Err(err) = list_codes(&flags) {
                    eprintln!("{err}");
                    return Err(String::new());
                }
            } else {
                let lines = extract(&flags)?;
                emit_text(&flags.output, &lines, flags.append)?;
            }
        }
        "convert" => {
            if flags.list.is_empty() {
                eprintln!("Error: List should not be empty\n");
                eprint!("{}", usage(program));
                return Ok(0);
            }
            convert(&flags)?;
        }
        "lookup" => {
            if flags.value.is_empty() {
                eprintln!("Error: Target should not be empty\n");
                eprint!("{}", usage(program));
                return Ok(0);
            }
            let lines = lookup(&flags)?;
            emit_text(&flags.output, &lines, flags.append)?;
        }
        other => return Err(format!("unknown action: {other}")),
    }
    Ok(0)
}

fn parse_flags(args: &[String]) -> Result<Flags, String> {
    let mut flags = Flags::new();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if let Some(name) = arg.strip_prefix('-') {
            let (name, inline) = match name.strip_prefix('-').unwrap_or(name).split_once('=') {
                Some((name, value)) => (name, Some(value.to_string())),
                None => (name, None),
            };
            let value = |index: &mut usize| -> Result<String, String> {
                if let Some(value) = inline.clone() {
                    Ok(value)
                } else {
                    *index += 1;
                    args.get(*index).cloned().ok_or_else(|| format!("flag needs an argument: -{name}"))
                }
            };
            match name {
                "input" => flags.input = value(&mut index)?,
                "type" => flags.datatype = value(&mut index)?,
                "action" => flags.action = value(&mut index)?,
                "list" => flags.list = value(&mut index)?,
                "output" => flags.output = value(&mut index)?,
                "value" => flags.value = value(&mut index)?,
                "format" => flags.format = value(&mut index)?,
                "ipv4" => flags.ipv4 = take_bool(&mut index, inline, args)?,
                "ipv6" => flags.ipv6 = take_bool(&mut index, inline, args)?,
                "regex" => flags.regex = take_bool(&mut index, inline, args)?,
                "append" => flags.append = take_bool(&mut index, inline, args)?,
                "lowmem" => {
                    let _ = take_bool(&mut index, inline, args)?;
                }
                "strict" => flags.strict = take_bool(&mut index, inline, args)?,
                "version" => flags.version = take_bool(&mut index, inline, args)?,
                _ => {}
            }
        }
        index += 1;
    }
    Ok(flags)
}

fn take_bool(index: &mut usize, inline: Option<String>, args: &[String]) -> Result<bool, String> {
    if let Some(value) = inline {
        return parse_bool(&value).ok_or_else(|| format!("invalid boolean {value}"));
    }
    if let Some(next) = args.get(*index + 1) {
        if let Some(value) = parse_bool(next) {
            *index += 1;
            return Ok(value);
        }
    }
    Ok(true)
}

fn parse_bool(value: &str) -> Option<bool> {
    match value {
        "1" | "t" | "T" | "true" | "TRUE" | "True" => Some(true),
        "0" | "f" | "F" | "false" | "FALSE" | "False" => Some(false),
        _ => None,
    }
}

fn usage(program: &str) -> String {
    format!(
        "\
Usage of {program}:
  -action string
    \taction: extract | convert | lookup (default \"extract\")
  -append
    \tappend to existing file instead of overwriting
  -format string
    \tconvert output format. type: ruleset(srs) | quantumultx(qx) | json | geosite | geoip (default \"ruleset\")
  -input string
    \tdatafile
  -ipv4
    \tenable ipv4 output (default true)
  -ipv6
    \tenable ipv6 output (default true)
  -list string
    \tcomma separated site or geo list, e.g. \"cn,jp\" or \"youtube,google\"
  -lowmem
    \tlow memory mode, reduce memory cost by partial file reading (default true)
  -output string
    \toutput to file, leave empty to print to console
  -regex
    \tallow regex rules in the geosite result
  -strict
    \tstrict mode, non-existent code will result in an error (default true)
  -type string
    \tdatafile type: geoip | geosite (default \"geoip\")
  -value string
    \tip or domain to lookup, required only for lookup action
  -version
    \tprint version
"
    )
}

fn list_codes(flags: &Flags) -> Result<(), String> {
    let data = dat::read_file(&flags.input).map_err(|_| "Can't open input file".to_string())?;
    println!("Available codes:");
    if flags.datatype == "geosite" && data.first() == Some(&0) {
        if let Some(entries) = dat::sing_sites(&data) {
            if !entries.is_empty() {
                for entry in entries {
                    if !entry.code.is_empty() {
                        println!("{}", entry.code);
                    }
                }
                return Ok(());
            }
        }
    }
    for loc in dat::locate_v2(&data) {
        if !loc.code.is_empty() {
            println!("{}", loc.code);
        }
    }
    Ok(())
}

fn extract(flags: &Flags) -> Result<Vec<String>, String> {
    match flags.datatype.as_str() {
        "geoip" => extract_geoip(flags),
        "geosite" => extract_geosite(flags),
        other => Err(format!("unknown type: {other}")),
    }
}

fn extract_geoip(flags: &Flags) -> Result<Vec<String>, String> {
    let entries = selected_geoip(&flags.input, &flags.list)?;
    let lines = geoip_lines(&entries, &flags.list, flags.ipv4, flags.ipv6);
    if lines.is_empty() {
        return Err("no match countrycode found".to_string());
    }
    Ok(lines)
}

fn selected_geoip(path: &str, list: &str) -> Result<Vec<GeoIpEntry>, String> {
    let data = dat::read_file(path)?;
    let (all, wanted) = wanted_codes(list);
    let mut entries = Vec::new();
    for loc in dat::locate_v2(&data) {
        let code = loc.code.to_uppercase();
        if all || wanted.contains(&code) {
            entries.push(dat::parse_geoip(&data[loc.start..loc.end]));
        }
    }
    Ok(entries)
}

fn geoip_lines(entries: &[GeoIpEntry], list: &str, ipv4: bool, ipv6: bool) -> Vec<String> {
    let (all, wanted) = wanted_codes(list);
    let mut lines = Vec::new();
    for entry in entries {
        let code = entry.code.to_uppercase();
        if !all && !wanted.contains(&code) {
            continue;
        }
        for cidr in &entry.cidrs {
            let v4 = dat::is_ipv4(&cidr.ip);
            if (v4 && ipv4) || (!v4 && ipv6) {
                lines.push(dat::cidr_line(cidr));
            }
        }
    }
    lines
}

fn extract_geosite(flags: &Flags) -> Result<Vec<String>, String> {
    let entries = selected_geosite(&flags.input, &flags.list).map_err(|err| format!("Extract failed: {err}"))?;
    let lines = geosite_rules(&entries, &flags.list, flags.regex, false, flags.strict)?;
    let mut values: Vec<String> = lines.into_iter().map(|item| item.value).collect();
    values.sort();
    values.dedup();
    Ok(values)
}

struct Selected {
    value: String,
    kind: u32,
}

fn geosite_rules(
    entries: &[GeoSiteEntry],
    list: &str,
    regex: bool,
    keyword: bool,
    strict: bool,
) -> Result<Vec<Selected>, String> {
    let (all, wanted) = wanted_sites(list);
    if strict && !all {
        for code in wanted.keys() {
            if !entries.iter().any(|entry| entry.code.eq_ignore_ascii_case(code)) {
                return Err(format!("{code} doesn't exist"));
            }
        }
    }
    let mut selected = Vec::new();
    for entry in entries {
        let code = entry.code.to_uppercase();
        let attrs = if all {
            Some([].as_slice())
        } else if let Some(attrs) = wanted.get(&code) {
            Some(attrs.as_slice())
        } else {
            None
        };
        let Some(attrs) = attrs else {
            continue;
        };
        for domain in &entry.domains {
            if keep_domain(domain, attrs, regex, keyword) {
                selected.push(Selected {
                    value: domain.value.clone(),
                    kind: domain.kind,
                });
            }
        }
    }
    Ok(selected)
}

fn keep_domain(domain: &Domain, attrs: &[String], regex: bool, keyword: bool) -> bool {
    match domain.kind {
        1 if !regex => return false,
        0 if !keyword => return false,
        0 | 1 | 2 | 3 => {}
        _ => return false,
    }
    if attrs.is_empty() {
        return true;
    }
    attrs.iter().all(|want| domain.attrs.iter().any(|have| have == want))
}

fn wanted_codes(list: &str) -> (bool, HashSet<String>) {
    let mut all = false;
    let mut codes = HashSet::new();
    for part in list.split(',') {
        let code = part.trim().to_uppercase();
        if code.is_empty() {
            continue;
        }
        if code == "*" {
            all = true;
        }
        codes.insert(code);
    }
    (all, codes)
}

fn wanted_sites(list: &str) -> (bool, HashMap<String, Vec<String>>) {
    let mut all = false;
    let mut sites = HashMap::new();
    for part in list.split(',') {
        let lowered = part.trim().to_lowercase();
        if lowered.is_empty() {
            continue;
        }
        let mut pieces = lowered.split('@');
        let code = pieces.next().unwrap_or_default().to_uppercase();
        if code.is_empty() {
            continue;
        }
        if code == "*" {
            all = true;
        }
        let attrs = pieces.map(|item| item.trim().to_string()).filter(|item| !item.is_empty()).collect();
        sites.insert(code, attrs);
    }
    (all, sites)
}

fn lookup(flags: &Flags) -> Result<Vec<String>, String> {
    match flags.datatype.as_str() {
        "geoip" => lookup_geoip(flags),
        "geosite" => lookup_geosite(flags),
        other => Err(format!("unknown type: {other}")),
    }
}

fn lookup_geoip(flags: &Flags) -> Result<Vec<String>, String> {
    let data = dat::read_file(&flags.input)?;
    let Some(query) = parse_lookup_ip(&flags.value) else {
        return Ok(Vec::new());
    };
    let mut lines = Vec::new();
    for loc in dat::locate_v2(&data) {
        let entry = dat::parse_geoip(&data[loc.start..loc.end]);
        if entry.cidrs.iter().any(|cidr| cidr_contains(cidr, query)) {
            lines.push(entry.code);
        }
    }
    Ok(lines)
}

fn parse_lookup_ip(value: &str) -> Option<std::net::IpAddr> {
    value.trim().parse().ok()
}

fn cidr_contains(cidr: &Cidr, query: std::net::IpAddr) -> bool {
    let text = dat::cidr_line(cidr);
    let Some((addr, bits)) = text.split_once('/') else {
        return false;
    };
    let Ok(bits) = bits.parse::<u32>() else {
        return false;
    };
    let Ok(network) = addr.parse::<std::net::IpAddr>() else {
        return false;
    };
    match (network, query) {
        (std::net::IpAddr::V4(network), std::net::IpAddr::V4(ip)) if bits <= 32 => {
            let mask = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
            let network = u32::from(network);
            if network & mask != network {
                return false;
            }
            u32::from(ip) & mask == network
        }
        (std::net::IpAddr::V6(network), std::net::IpAddr::V6(ip)) if bits <= 128 => {
            let mask = if bits == 0 { 0 } else { u128::MAX << (128 - bits) };
            let network = u128::from(network);
            if network & mask != network {
                return false;
            }
            u128::from(ip) & mask == network
        }
        _ => false,
    }
}

fn lookup_geosite(flags: &Flags) -> Result<Vec<String>, String> {
    let data = dat::read_file(&flags.input).map_err(|_| "Not a valid geosite format".to_string())?;
    let query = flags.value.trim().to_lowercase();
    let mut lines = Vec::new();
    if data.first() == Some(&0) {
        if let Some(entries) = dat::sing_sites(&data) {
            if !entries.is_empty() {
                for entry in &entries {
                    record_site_match(&mut lines, entry, &query);
                }
                return Ok(lines);
            }
        }
    }
    for loc in dat::locate_v2(&data) {
        let entry = dat::parse_geosite(&data[loc.start..loc.end]);
        record_site_match(&mut lines, &entry, &query);
    }
    Ok(lines)
}

fn record_site_match(lines: &mut Vec<String>, entry: &GeoSiteEntry, query: &str) {
    if !entry.domains.iter().any(|domain| domain_matches(domain, query)) {
        return;
    }
    let code = entry.code.to_uppercase();
    lines.push(code.clone());
    let mut attrs: Vec<String> = entry
        .domains
        .iter()
        .filter(|domain| domain_matches(domain, query))
        .flat_map(|domain| domain.attrs.clone())
        .collect();
    attrs.sort();
    attrs.dedup();
    for attr in attrs {
        lines.push(format!("{code}@{attr}"));
    }
}

fn domain_matches(domain: &Domain, query: &str) -> bool {
    match domain.kind {
        3 => query == domain.value,
        2 => suffix_match(&domain.value, query),
        0 => !domain.value.is_empty() && query.contains(&domain.value),
        1 => regex_match(&domain.value, query),
        _ => false,
    }
}

fn suffix_match(pattern: &str, host: &str) -> bool {
    if pattern.is_empty() || !host.ends_with(pattern) {
        return false;
    }
    host.len() == pattern.len() || host.as_bytes()[host.len() - pattern.len() - 1] == b'.'
}

fn regex_match(pattern: &str, host: &str) -> bool {
    regex::Regex::new(pattern).is_ok_and(|re| re.is_match(host))
}

fn convert(flags: &Flags) -> Result<(), String> {
    let format = flags.format.to_lowercase();
    match flags.datatype.as_str() {
        "geoip" => convert_geoip(flags, &format),
        "geosite" => convert_geosite(flags, &format),
        other => Err(format!("unknown type: {other}")),
    }
}

fn load_geoip_for_convert(flags: &Flags) -> Result<Vec<GeoIpEntry>, String> {
    let data = dat::read_file(&flags.input)?;
    if dat::is_protobuf(&data) {
        selected_geoip(&flags.input, &flags.list)
    } else {
        dat::text_geoip(&flags.input)
    }
}

fn load_geosite_for_convert(flags: &Flags) -> Result<Vec<GeoSiteEntry>, String> {
    let data = dat::read_file(&flags.input)?;
    if dat::is_protobuf(&data) {
        selected_geosite(&flags.input, &flags.list)
    } else {
        dat::text_geosite(&flags.input)
    }
}

fn selected_geosite(path: &str, list: &str) -> Result<Vec<GeoSiteEntry>, String> {
    let data = dat::read_file(path)?;
    if data.first() == Some(&0) {
        if let Some(entries) = dat::sing_sites(&data) {
            if !entries.is_empty() {
                return Ok(entries);
            }
        }
    }
    let (all, wanted) = wanted_sites(list);
    let mut entries = Vec::new();
    for loc in dat::locate_v2(&data) {
        let code = loc.code.to_uppercase();
        if all || wanted.contains_key(&code) {
            entries.push(dat::parse_geosite(&data[loc.start..loc.end]));
        }
    }
    Ok(entries)
}


fn convert_geoip(flags: &Flags, format: &str) -> Result<(), String> {
    let entries = load_geoip_for_convert(flags)?;
    match format {
        "json" | "srs" | "ruleset" => {
            let ips = geoip_lines(&entries, &flags.list, flags.ipv4, flags.ipv6);
            if ips.is_empty() {
                return Err("no match countrycode found".to_string());
            }
            let rules = Rules { ip: ips, ..Rules::default() };
            emit_ruleset(&flags.output, format, &rules, flags.append)
        }
        "geoip" => {
            if flags.output.is_empty() {
                return Err("Output file for geoip conversion is required".to_string());
            }
            let (all, wanted) = wanted_codes(&flags.list);
            let selected: Vec<GeoIpEntry> = entries
                .into_iter()
                .filter(|entry| all || wanted.contains(&entry.code.to_uppercase()))
                .filter(|entry| !entry.cidrs.is_empty())
                .collect();
            if selected.is_empty() && flags.strict {
                return Err("no match countrycode found".to_string());
            }
            std::fs::write(&flags.output, dat::encode_geoip(&selected)).map_err(|err| err.to_string())
        }
        "qx" | "quantumultx" => {
            let v4 = if flags.ipv4 { geoip_lines(&entries, &flags.list, true, false) } else { Vec::new() };
            let v6 = if flags.ipv6 { geoip_lines(&entries, &flags.list, false, true) } else { Vec::new() };
            let mut lines = Vec::new();
            if flags.ipv4 && !flags.ipv6 {
                lines.extend(v4.into_iter().map(|cidr| format!("ip-cidr, {cidr}, Proxy")));
            } else if flags.ipv6 && !flags.ipv4 {
                lines.extend(v6.into_iter().map(|cidr| format!("ip6-cidr, {cidr}, Proxy")));
            } else {
                lines.extend(v4.into_iter().map(|cidr| format!("ip-cidr, {cidr}, Proxy")));
                lines.extend(v6.into_iter().map(|cidr| format!("ip6-cidr, {cidr}, Proxy")));
            }
            emit_text(&flags.output, &lines, flags.append)
        }
        _ => Err(format!("converting from {} to {} is not supported", flags.datatype, flags.format)),
    }
}

fn convert_geosite(flags: &Flags, format: &str) -> Result<(), String> {
    let entries = load_geosite_for_convert(flags).map_err(|err| {
        if err.starts_with("open ") {
            format!("Extract failed: {err}")
        } else {
            err
        }
    })?;
    match format {
        "json" | "srs" | "ruleset" => {
            let selected = geosite_rules(&entries, &flags.list, flags.regex, false, flags.strict)?;
            if selected.is_empty() {
                return Err("empty domain set".to_string());
            }
            let mut rules = Rules::default();
            for item in selected {
                match item.kind {
                    3 => rules.domain.push(item.value),
                    2 => rules.suffix.push(item.value),
                    0 => rules.keyword.push(item.value),
                    1 => rules.regex.push(item.value),
                    _ => rules.domain.push(item.value),
                }
            }
            emit_ruleset(&flags.output, format, &rules, flags.append)
        }
        "geosite" => {
            if flags.output.is_empty() {
                return Err("Output file for geosite conversion is required".to_string());
            }
            let (all, wanted) = wanted_sites(&flags.list);
            let mut selected: Vec<GeoSiteEntry> = entries
                .into_iter()
                .filter(|entry| all || wanted.contains_key(&entry.code.to_uppercase()))
                .filter(|entry| !entry.domains.is_empty())
                .collect();
            if selected.is_empty() && flags.strict {
                let missing = wanted.keys().next().cloned().unwrap_or_else(|| "list".to_string());
                return Err(format!("{missing} doesn't exist"));
            }
            selected.sort_by(|left, right| left.code.cmp(&right.code));
            std::fs::write(&flags.output, dat::encode_geosite(&selected)).map_err(|err| err.to_string())
        }
        "qx" | "quantumultx" => {
            let selected = geosite_rules(&entries, &flags.list, false, true, flags.strict)?;
            let lines = selected
                .into_iter()
                .filter_map(|item| match item.kind {
                    3 => Some(format!("host,{},Proxy", item.value)),
                    2 => Some(format!("host-suffix,{},Proxy", item.value)),
                    0 => Some(format!("host-keyword,{},Proxy", item.value)),
                    _ => None,
                })
                .collect::<Vec<_>>();
            emit_text(&flags.output, &lines, flags.append)
        }
        _ => Err(format!("converting from {} to {} is not supported", flags.datatype, flags.format)),
    }
}

fn emit_ruleset(output: &str, format: &str, rules: &Rules, append: bool) -> Result<(), String> {
    let json = format == "json" || output.is_empty();
    if json {
        let mut document = srs::ruleset_json(rules);
        if append && !output.is_empty() {
            document = append_json(output, rules);
        }
        if output.is_empty() {
            print!("{document}");
            Ok(())
        } else {
            std::fs::write(output, document).map_err(|err| err.to_string())
        }
    } else {
        let bytes = srs::ruleset_binary(rules)?;
        std::fs::write(output, bytes).map_err(|err| err.to_string())
    }
}

fn append_json(path: &str, rules: &Rules) -> String {
    let fresh = srs::ruleset_json(rules);
    let Ok(old) = std::fs::read_to_string(path) else {
        return fresh;
    };
    let Some(start) = old.find("\"rules\":[") else {
        return fresh;
    };
    let array_at = start + "\"rules\":".len();
    let Some(end) = matching_bracket(&old, array_at) else {
        return fresh;
    };
    let body = old[array_at + 1..end].trim();
    let new_rule = fresh
        .trim()
        .strip_prefix("{\"version\":3,\"rules\":[")
        .and_then(|rest| rest.strip_suffix("]}"))
        .unwrap_or("");
    if body.is_empty() {
        format!("{{\"version\":3,\"rules\":[{new_rule}]}}\n")
    } else {
        format!("{{\"version\":3,\"rules\":[{body},{new_rule}]}}\n")
    }
}

fn matching_bracket(text: &str, open: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    if bytes.get(open) != Some(&b'[') {
        return None;
    }
    let mut depth = 0i32;
    let mut in_string = false;
    let mut escape = false;
    for (index, byte) in bytes.iter().enumerate().skip(open) {
        if in_string {
            if escape {
                escape = false;
            } else if *byte == b'\\' {
                escape = true;
            } else if *byte == b'"' {
                in_string = false;
            }
            continue;
        }
        match *byte {
            b'"' => in_string = true,
            b'[' | b'{' => depth += 1,
            b']' | b'}' => {
                depth -= 1;
                if depth == 0 && *byte == b']' {
                    return Some(index);
                }
            }
            _ => {}
        }
    }
    None
}

fn emit_text(output: &str, lines: &[String], append: bool) -> Result<(), String> {
    if output.is_empty() {
        for line in lines {
            println!("{line}");
        }
        return Ok(());
    }
    if append {
        append_lines(output, lines)
    } else {
        std::fs::write(output, lines.join("\n")).map_err(|err| err.to_string())
    }
}

fn append_lines(path: &str, lines: &[String]) -> Result<(), String> {
    let mut file = OpenOptions::new().create(true).read(true).write(true).append(true).open(path).map_err(|err| err.to_string())?;
    let len = file.seek(SeekFrom::End(0)).map_err(|err| err.to_string())?;
    if len > 0 {
        file.seek(SeekFrom::Start(len - 1)).map_err(|err| err.to_string())?;
        let mut last = [0u8; 1];
        file.read_exact(&mut last).map_err(|err| err.to_string())?;
        if last[0] != b'\n' {
            file.write_all(b"\n").map_err(|err| err.to_string())?;
        }
    }
    file.write_all(lines.join("\n").as_bytes()).map_err(|err| err.to_string())
}
