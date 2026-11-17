//! sing-box succinct domain matcher, compatible with sagernet/sing v0.8.9.
//!
//! Version 3 rule-sets store suffixes behind a leading '\n' (root label) and
//! exact domains as reversed labels. The bitmap layout is what sing-box reads
//! back out of an SRS file.

const PREFIX_LABEL: u8 = b'\r';
const ROOT_LABEL: u8 = b'\n';

#[derive(Clone, Debug, Default)]
pub struct SuccinctSet {
    pub leaves: Vec<u64>,
    pub label_bitmap: Vec<u64>,
    pub labels: Vec<u8>,
}

struct QueueElt {
    start: usize,
    end: usize,
    col: usize,
}

fn set_bit(bitmap: &mut Vec<u64>, index: usize, value: u64) {
    while index / 64 >= bitmap.len() {
        bitmap.push(0);
    }
    bitmap[index / 64] |= value << (index & 63);
}

fn new_succinct_set(keys: &[String]) -> SuccinctSet {
    let mut set = SuccinctSet::default();
    let mut label_index = 0usize;
    let mut queue = vec![QueueElt {
        start: 0,
        end: keys.len(),
        col: 0,
    }];
    let mut cursor = 0;
    while cursor < queue.len() {
        let mut elt = QueueElt {
            start: queue[cursor].start,
            end: queue[cursor].end,
            col: queue[cursor].col,
        };
        if elt.col == keys[elt.start].len() {
            elt.start += 1;
            set_bit(&mut set.leaves, cursor, 1);
        }
        let mut index = elt.start;
        while index < elt.end {
            let from = index;
            let byte = keys[from].as_bytes()[elt.col];
            while index < elt.end && keys[index].as_bytes()[elt.col] == byte {
                index += 1;
            }
            queue.push(QueueElt {
                start: from,
                end: index,
                col: elt.col + 1,
            });
            set.labels.push(byte);
            set_bit(&mut set.label_bitmap, label_index, 0);
            label_index += 1;
        }
        set_bit(&mut set.label_bitmap, label_index, 1);
        label_index += 1;
        cursor += 1;
    }
    set
}

fn reverse_domain(domain: &str) -> String {
    domain.chars().rev().collect()
}

pub fn matcher(domains: &[String], suffixes: &[String]) -> SuccinctSet {
    let mut seen = std::collections::HashSet::new();
    let mut keys = Vec::new();
    for domain in suffixes {
        if domain.is_empty() || !seen.insert(domain.clone()) {
            continue;
        }
        if domain.as_bytes()[0] == b'.' {
            keys.push(reverse_domain(&format!("{prefix}{domain}", prefix = PREFIX_LABEL as char)));
        } else {
            keys.push(reverse_domain(&format!("{root}{domain}", root = ROOT_LABEL as char)));
        }
    }
    for domain in domains {
        if domain.is_empty() || !seen.insert(domain.clone()) {
            continue;
        }
        keys.push(reverse_domain(domain));
    }
    keys.sort();
    new_succinct_set(&keys)
}

fn write_uvarint(out: &mut Vec<u8>, value: u64) {
    crate::proto::write_varint(out, value);
}

fn write_u64_slice(out: &mut Vec<u8>, values: &[u64]) {
    write_uvarint(out, values.len() as u64);
    for value in values {
        out.extend_from_slice(&value.to_be_bytes());
    }
}

pub fn write_matcher(set: &SuccinctSet, out: &mut Vec<u8>) {
    out.push(0);
    write_u64_slice(out, &set.leaves);
    write_u64_slice(out, &set.label_bitmap);
    write_uvarint(out, set.labels.len() as u64);
    out.extend_from_slice(&set.labels);
}
