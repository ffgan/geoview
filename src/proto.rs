//! Minimal protobuf wire codec for v2ray geoip/geosite messages.

pub fn write_varint(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
}

pub fn read_varint(data: &[u8], pos: &mut usize) -> Option<u64> {
    let mut value = 0u64;
    let mut shift = 0;
    while shift < 64 {
        if *pos >= data.len() {
            return None;
        }
        let byte = data[*pos];
        *pos += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some(value);
        }
        shift += 7;
    }
    None
}

fn write_key(out: &mut Vec<u8>, field: u32, wire: u32) {
    write_varint(out, u64::from((field << 3) | wire));
}

pub fn write_bytes(out: &mut Vec<u8>, field: u32, bytes: &[u8]) {
    write_key(out, field, 2);
    write_varint(out, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

pub fn write_string(out: &mut Vec<u8>, field: u32, value: &str) {
    if !value.is_empty() {
        write_bytes(out, field, value.as_bytes());
    }
}

pub fn write_uint(out: &mut Vec<u8>, field: u32, value: u64) {
    if value != 0 {
        write_key(out, field, 0);
        write_varint(out, value);
    }
}

pub fn write_message(out: &mut Vec<u8>, field: u32, message: &[u8]) {
    write_bytes(out, field, message);
}

#[derive(Clone, Debug)]
pub struct Field {
    pub number: u32,
    #[allow(dead_code)]
    pub wire: u32,
    pub value: FieldValue,
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub enum FieldValue {
    Varint(u64),
    Bytes(Vec<u8>),
    Fixed64(u64),
    Fixed32(u32),
}

pub enum Borrowed<'a> {
    Varint(u64),
    Bytes(&'a [u8]),
}

pub enum Control {
    Continue,
    Break,
}

/// Walk a protobuf message without copying length-delimited fields.
pub fn visit<'a>(data: &'a [u8], mut accept: impl FnMut(u32, Borrowed<'a>) -> Control) -> bool {
    let mut pos = 0;
    while pos < data.len() {
        let Some(key) = read_varint(data, &mut pos) else {
            return false;
        };
        let field = (key >> 3) as u32;
        let wire = (key & 7) as u32;
        if field == 0 {
            return false;
        }
        match wire {
            0 => {
                let Some(value) = read_varint(data, &mut pos) else {
                    return false;
                };
                if matches!(accept(field, Borrowed::Varint(value)), Control::Break) {
                    return true;
                }
            }
            1 => {
                if pos + 8 > data.len() {
                    return false;
                }
                pos += 8;
            }
            2 => {
                let Some(len) = read_varint(data, &mut pos) else {
                    return false;
                };
                let len = len as usize;
                if pos + len > data.len() {
                    return false;
                }
                let bytes = &data[pos..pos + len];
                pos += len;
                if matches!(accept(field, Borrowed::Bytes(bytes)), Control::Break) {
                    return true;
                }
            }
            5 => {
                if pos + 4 > data.len() {
                    return false;
                }
                pos += 4;
            }
            _ => return false,
        }
    }
    true
}

pub fn parse_message(mut data: &[u8]) -> Option<Vec<Field>> {
    let mut fields = Vec::new();
    while !data.is_empty() {
        let mut pos = 0;
        let key = read_varint(data, &mut pos)?;
        data = &data[pos..];
        let number = (key >> 3) as u32;
        let wire = (key & 7) as u32;
        if number == 0 {
            return None;
        }
        let value = match wire {
            0 => {
                let mut pos = 0;
                let value = read_varint(data, &mut pos)?;
                data = &data[pos..];
                FieldValue::Varint(value)
            }
            1 => {
                if data.len() < 8 {
                    return None;
                }
                let mut buf = [0u8; 8];
                buf.copy_from_slice(&data[..8]);
                data = &data[8..];
                FieldValue::Fixed64(u64::from_le_bytes(buf))
            }
            2 => {
                let mut pos = 0;
                let len = read_varint(data, &mut pos)? as usize;
                data = &data[pos..];
                if data.len() < len {
                    return None;
                }
                let bytes = data[..len].to_vec();
                data = &data[len..];
                FieldValue::Bytes(bytes)
            }
            5 => {
                if data.len() < 4 {
                    return None;
                }
                let mut buf = [0u8; 4];
                buf.copy_from_slice(&data[..4]);
                data = &data[4..];
                FieldValue::Fixed32(u32::from_le_bytes(buf))
            }
            _ => return None,
        };
        fields.push(Field { number, wire, value });
    }
    Some(fields)
}

pub fn field_str(field: &Field) -> Option<String> {
    match &field.value {
        FieldValue::Bytes(bytes) => Some(String::from_utf8_lossy(bytes).into_owned()),
        _ => None,
    }
}

pub fn field_varint(field: &Field) -> Option<u64> {
    match field.value {
        FieldValue::Varint(value) => Some(value),
        _ => None,
    }
}

pub fn field_bytes(field: &Field) -> Option<&[u8]> {
    match &field.value {
        FieldValue::Bytes(bytes) => Some(bytes),
        _ => None,
    }
}
