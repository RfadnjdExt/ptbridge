use std::io::{Read, Write};

pub const LTV_NEGOTIATION: i32 = 0;
pub const LTV_AUTH_REQUEST: i32 = 2;
pub const LTV_AUTH_CHALLENGE: i32 = 3;
pub const LTV_AUTH_RESPONSE: i32 = 4;
pub const LTV_AUTH_STATUS: i32 = 5;
pub const LTV_KEEPALIVE: i32 = 6;
pub const LTV_DISCONNECT: i32 = 7;
pub const LTV_IPC_CALL: i32 = 100;
pub const LTV_IPC_ERROR: i32 = 101;
pub const LTV_IPC_RESPONSE: i32 = 102;

pub const ENC_TEXT: i32 = 1;
pub const ENC_BINARY: i32 = 2;
pub const ENC_NONE: i32 = 1;
pub const COMP_NONE: i32 = 1;
pub const AUTH_CLEAR: i32 = 1;
pub const AUTH_SIMPLE: i32 = 2;
pub const AUTH_MD5: i32 = 4;

pub const TAG_VOID: u8 = 0;
pub const TAG_BOOL: u8 = 2;
pub const TAG_INT: u8 = 4;
pub const TAG_DOUBLE: u8 = 7;
pub const TAG_QSTRING: u8 = 9;
pub const TAG_STRING: u8 = 8;
pub const TAG_IP: u8 = 10;
pub const TAG_UUID: u8 = 13;
pub const TAG_PAIR: u8 = 14;
pub const TAG_ARRAY: u8 = 15;

#[derive(Debug, Clone)]
pub enum Wire {
    Void,
    Bool(bool),
    Int(i32),
    Double(f64),
    Str(String),
    Ip([u8; 4]),
    Uuid([u8; 16]),
    Array(u8, Vec<Wire>),
    Pair(Vec<Wire>),
    Handle(String),
    Raw(u8, Vec<u8>),
}

pub fn decode_response(payload: &[u8]) -> Result<(i32, Vec<Wire>), String> {
    if payload.len() < 4 {
        return Err(format!("response too short: {} bytes", payload.len()));
    }
    let msg_id = i32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
    let mut pos = 4usize;
    let mut out = Vec::new();
    while pos < payload.len() {
        out.push(decode_value(payload, &mut pos, payload.len())?);
    }
    Ok((msg_id, out))
}

pub fn decode_status(payload: &[u8]) -> Result<(i32, String, String), String> {
    if payload.len() < 4 {
        return Err(format!("status too short: {} bytes", payload.len()));
    }
    let msg_id = i32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
    let rest = &payload[4..];
    let mut it = rest.splitn(2, |&b| b == 0);
    let class = String::from_utf8_lossy(it.next().unwrap_or(b"")).into_owned();
    let text = String::from_utf8_lossy(it.next().unwrap_or(b"")).into_owned();
    Ok((msg_id, class, text))
}

fn decode_value(buf: &[u8], pos: &mut usize, end: usize) -> Result<Wire, String> {
    if *pos >= end {
        return Err("truncated value".into());
    }
    let tag = buf[*pos];
    *pos += 1;
    match tag {
        TAG_VOID => Ok(Wire::Void),
        TAG_BOOL => {
            let b = take(buf, pos, end, 1)?[0];
            Ok(Wire::Bool(b != 0))
        }
        TAG_INT => {
            let b = take(buf, pos, end, 4)?;
            Ok(Wire::Int(i32::from_be_bytes([b[0], b[1], b[2], b[3]])))
        }
        TAG_DOUBLE => {
            let b = take(buf, pos, end, 8)?;
            let mut a = [0u8; 8];
            a.copy_from_slice(b);
            Ok(Wire::Double(f64::from_be_bytes(a)))
        }
        TAG_STRING | TAG_QSTRING => {
            let start = *pos;
            while *pos < end && buf[*pos] != 0 {
                *pos += 1;
            }
            let s = String::from_utf8_lossy(&buf[start..*pos]).into_owned();
            if *pos < end {
                *pos += 1;
            }
            Ok(Wire::Str(s))
        }
        TAG_IP => {
            let b = take(buf, pos, end, 4)?;
            Ok(Wire::Ip([b[0], b[1], b[2], b[3]]))
        }
        TAG_UUID => {
            let b = take(buf, pos, end, 16)?;
            let mut u = [0u8; 16];
            u.copy_from_slice(b);
            Ok(Wire::Uuid(u))
        }
        TAG_PAIR => {
            let mut vals = Vec::new();
            while *pos < end {
                vals.push(decode_value(buf, pos, end)?);
            }
            Ok(Wire::Pair(vals))
        }
        TAG_ARRAY => {
            if *pos >= end {
                return Err("truncated array".into());
            }
            let elem_tag = buf[*pos];
            *pos += 1;
            let b = take(buf, pos, end, 4)?;
            let count = u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize;
            let mut elems = Vec::with_capacity(count.min(1024));
            for _ in 0..count {
                elems.push(decode_elem(buf, pos, end, elem_tag)?);
            }
            Ok(Wire::Array(elem_tag, elems))
        }
        other => {
            let rest = buf[*pos..end].to_vec();
            *pos = end;
            Ok(Wire::Raw(other, rest))
        }
    }
}

fn decode_elem(buf: &[u8], pos: &mut usize, end: usize, tag: u8) -> Result<Wire, String> {
    let fake = |b: &[u8]| b.to_vec();
    match tag {
        TAG_BOOL => Ok(Wire::Bool(fake(take(buf, pos, end, 1)?)[0] != 0)),
        TAG_INT => {
            let b = fake(take(buf, pos, end, 4)?);
            Ok(Wire::Int(i32::from_be_bytes([b[0], b[1], b[2], b[3]])))
        }
        TAG_DOUBLE => {
            let b = fake(take(buf, pos, end, 8)?);
            let mut a = [0u8; 8];
            a.copy_from_slice(&b);
            Ok(Wire::Double(f64::from_be_bytes(a)))
        }
        TAG_IP => {
            let b = fake(take(buf, pos, end, 4)?);
            Ok(Wire::Ip([b[0], b[1], b[2], b[3]]))
        }
        TAG_UUID => {
            let b = fake(take(buf, pos, end, 16)?);
            let mut u = [0u8; 16];
            u.copy_from_slice(&b);
            Ok(Wire::Uuid(u))
        }
        TAG_STRING | TAG_QSTRING => {
            let start = *pos;
            while *pos < end && buf[*pos] != 0 {
                *pos += 1;
            }
            let s = String::from_utf8_lossy(&buf[start..*pos]).into_owned();
            if *pos < end {
                *pos += 1;
            }
            Ok(Wire::Str(s))
        }
        other => Err(format!("unsupported array element tag {:#04x}", other)),
    }
}

fn take<'a>(buf: &'a [u8], pos: &mut usize, end: usize, n: usize) -> Result<&'a [u8], String> {
    if *pos + n > end {
        return Err(format!("truncated: want {} at {}", n, pos));
    }
    let s = &buf[*pos..*pos + n];
    *pos += n;
    Ok(s)
}

pub fn uuid_string(u: &[u8; 16]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        u[0], u[1], u[2], u[3], u[4], u[5], u[6], u[7],
        u[8], u[9], u[10], u[11], u[12], u[13], u[14], u[15]
    )
}

pub fn ip_string(ip: &[u8; 4]) -> String {
    format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
}

pub struct NegotiationProps {
    pub client_uuid: String,
    pub encoding: i32,
    pub encryption: i32,
    pub compression: i32,
    pub authentication: i32,
    pub timestamp: String,
    pub keepalive_secs: i32,
    pub reserved: String,
}

impl Default for NegotiationProps {
    fn default() -> Self {
        NegotiationProps {
            client_uuid: String::from("6f1d2a90-4c77-4b02-9a3e-1d00a1b2c3d4"),
            encoding: ENC_BINARY,
            encryption: ENC_NONE,
            compression: COMP_NONE,
            authentication: AUTH_MD5,
            timestamp: local_timestamp(),
            keepalive_secs: 60,
            reserved: String::from(":PTVER9.0.0.0810"),
        }
    }
}

pub fn local_timestamp() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let (y, mo, d, h, mi, s) = civil_from_unix(secs);
    format!("{:04}{:02}{:02}{:02}{:02}{:02}", y, mo, d, h, mi, s)
}

fn civil_from_unix(t: i64) -> (i64, i64, i64, i64, i64, i64) {
    let days = t.div_euclid(86400);
    let sod = t.rem_euclid(86400);
    let mut z = days + 719468;
    let era = z.div_euclid(146097);
    z -= era * 146097;
    let doe = z;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d, sod / 3600, (sod % 3600) / 60, sod % 60)
}

pub fn encode_negotiation(props: &NegotiationProps) -> Vec<u8> {
    let mut value = Vec::new();
    let mut field = |s: &str| {
        value.extend_from_slice(s.as_bytes());
        value.push(0);
    };
    field("PTMP");
    field("1");
    field(&props.client_uuid);
    field(&props.encoding.to_string());
    field(&props.encryption.to_string());
    field(&props.compression.to_string());
    field(&props.authentication.to_string());
    field(&props.timestamp);
    field(&props.keepalive_secs.to_string());
    field(&props.reserved);
    let mut body = Vec::new();
    body.extend_from_slice(b"0");
    body.push(0);
    body.extend_from_slice(&value);
    let mut msg = body.len().to_string().into_bytes();
    msg.push(0);
    msg.extend_from_slice(&body);
    msg
}

pub struct Negotiated {
    pub version: i32,
    pub server_uuid: String,
    pub encoding: i32,
    pub encryption: i32,
    pub compression: i32,
    pub authentication: i32,
    pub server_timestamp: String,
    pub keepalive_secs: i32,
    pub raw: String,
}

pub fn parse_negotiation_response(buf: &[u8]) -> Option<Negotiated> {
    let raw = String::from_utf8_lossy(buf).into_owned();
    let tokens: Vec<&str> = raw.split('\0').collect();
    let idx = tokens.iter().position(|t| *t == "PTMP")?;
    if tokens.len() < idx + 10 {
        return None;
    }
    Some(Negotiated {
        version: tokens[idx + 1].parse().unwrap_or(0),
        server_uuid: tokens[idx + 2].to_string(),
        encoding: tokens[idx + 3].parse().unwrap_or(1),
        encryption: tokens[idx + 4].parse().unwrap_or(1),
        compression: tokens[idx + 5].parse().unwrap_or(1),
        authentication: tokens[idx + 6].parse().unwrap_or(4),
        server_timestamp: tokens[idx + 7].to_string(),
        keepalive_secs: tokens[idx + 8].parse().unwrap_or(60),
        raw,
    })
}

pub fn ltv_encode(type_id: i32, value: &[u8]) -> Vec<u8> {
    let len = 4 + value.len();
    let mut out = Vec::with_capacity(4 + len);
    out.extend_from_slice(&(len as i32).to_be_bytes());
    out.extend_from_slice(&type_id.to_be_bytes());
    out.extend_from_slice(value);
    out
}

pub fn read_ltv<R: Read>(r: &mut R) -> std::io::Result<(i32, Vec<u8>)> {
    let mut lenbuf = [0u8; 4];
    r.read_exact(&mut lenbuf)?;
    let len = i32::from_be_bytes(lenbuf);
    if !(4..=16 * 1024 * 1024).contains(&len) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("bad ltv length {}", len),
        ));
    }
    let mut payload = vec![0u8; len as usize];
    r.read_exact(&mut payload)?;
    let type_id = i32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
    Ok((type_id, payload[4..].to_vec()))
}

pub fn put_string(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(s.as_bytes());
    out.push(0);
}

pub fn auth_request(app_id: &str) -> Vec<u8> {
    let mut v = Vec::new();
    put_string(&mut v, app_id);
    ltv_encode(LTV_AUTH_REQUEST, &v)
}

pub fn auth_challenge_value(value: &[u8]) -> String {
    let end = value.iter().position(|&b| b == 0).unwrap_or(value.len());
    String::from_utf8_lossy(&value[..end]).into_owned()
}

pub fn digest_for(auth_type: i32, challenge: &str, secret: &str) -> Vec<u8> {
    match auth_type {
        AUTH_CLEAR => secret.as_bytes().to_vec(),
        AUTH_SIMPLE => {
            let mut v = Vec::with_capacity(secret.len());
            for b in secret.bytes() {
                let c = (158i32 - b as i32) as u32;
                if c < 0x80 {
                    v.push(c as u8);
                } else {
                    let cu = c as u16;
                    let mut buf = [0u8; 3];
                    let s = char::from_u32(cu as u32).unwrap_or('\u{fffd}');
                    let enc = s.encode_utf8(&mut buf);
                    v.extend_from_slice(enc.as_bytes());
                }
            }
            v
        }
        AUTH_MD5 => {
            let mut data = challenge.as_bytes().to_vec();
            data.extend_from_slice(secret.as_bytes());
            md5_hex_upper(&md5(&data)).into_bytes()
        }
        _ => b"0".to_vec(),
    }
}

pub fn auth_response(app_id: &str, digest: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    put_string(&mut v, app_id);
    v.extend_from_slice(digest);
    v.push(0);
    put_string(&mut v, "");
    ltv_encode(LTV_AUTH_RESPONSE, &v)
}

pub struct IpcCall {
    pub msg_id: i32,
    pub name_segments: Vec<String>,
    pub seg_params: Vec<Vec<u8>>,
}

impl IpcCall {
    pub fn new(msg_id: i32, name_segments: &[&str]) -> Self {
        IpcCall {
            msg_id,
            name_segments: name_segments.iter().map(|s| s.to_string()).collect(),
            seg_params: vec![Vec::new(); name_segments.len()],
        }
    }
    fn last_params(&mut self) -> &mut Vec<u8> {
        self.seg_params.last_mut().expect("at least one segment")
    }
    pub fn push_segment(mut self, name: &str) -> Self {
        self.name_segments.push(name.to_string());
        self.seg_params.push(Vec::new());
        self
    }
    pub fn qstring(mut self, s: &str) -> Self {
        let p = self.last_params();
        p.push(TAG_QSTRING);
        put_string(p, s);
        self
    }
    pub fn string(mut self, s: &str) -> Self {
        let p = self.last_params();
        p.push(TAG_STRING);
        put_string(p, s);
        self
    }
    pub fn bool(mut self, v: bool) -> Self {
        let p = self.last_params();
        p.push(TAG_BOOL);
        p.push(u8::from(v));
        self
    }
    pub fn int(mut self, v: i32) -> Self {
        let p = self.last_params();
        p.push(TAG_INT);
        p.extend_from_slice(&v.to_be_bytes());
        self
    }
    pub fn double(mut self, v: f64) -> Self {
        let p = self.last_params();
        p.push(TAG_DOUBLE);
        p.extend_from_slice(&v.to_be_bytes());
        self
    }
    pub fn ip(mut self, dotted: &str) -> Self {
        let octets: [u8; 4] = {
            let parts: Vec<u8> = dotted
                .split('.')
                .map(|p| p.parse::<u8>().expect("ip octet"))
                .collect();
            assert_eq!(parts.len(), 4, "ipv4 dotted quad");
            [parts[0], parts[1], parts[2], parts[3]]
        };
        let p = self.last_params();
        p.push(TAG_IP);
        p.extend_from_slice(&octets);
        self
    }
    pub fn uuid(mut self, s: &str) -> Self {
        let hex: String = s
            .trim()
            .trim_start_matches('{')
            .trim_end_matches('}')
            .chars()
            .filter(|c| c.is_ascii_hexdigit())
            .collect();
        assert_eq!(hex.len(), 32, "uuid must have 32 hex digits");
        let bytes: Vec<u8> = (0..32)
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
            .collect();
        let p = self.last_params();
        p.push(TAG_UUID);
        p.extend_from_slice(&bytes);
        self
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&self.msg_id.to_be_bytes());
        for (seg, params) in self.name_segments.iter().zip(&self.seg_params) {
            put_string(&mut v, seg);
            v.extend_from_slice(params);
            v.push(TAG_VOID);
        }
        ltv_encode(LTV_IPC_CALL, &v)
    }
}

pub fn hexdump(data: &[u8]) -> String {
    let mut out = String::new();
    for (i, chunk) in data.chunks(16).enumerate() {
        out.push_str(&format!("{:08x}  ", i * 16));
        for (j, b) in chunk.iter().enumerate() {
            out.push_str(&format!("{:02x} ", b));
            if j == 7 {
                out.push(' ');
            }
        }
        for _ in chunk.len()..16 {
            out.push_str("   ");
        }
        if chunk.len() <= 8 {
            out.push(' ');
        }
        out.push(' ');
        for b in chunk {
            let c = if b.is_ascii_graphic() || *b == b' ' {
                *b as char
            } else {
                '.'
            };
            out.push(c);
        }
        out.push('\n');
    }
    out
}

fn write_all<W: Write>(w: &mut W, data: &[u8]) -> std::io::Result<()> {
    w.write_all(data)?;
    w.flush()
}

pub fn negotiate<W: Write, R: Read>(
    w: &mut W,
    r: &mut R,
    props: &NegotiationProps,
) -> std::io::Result<Negotiated> {
    write_all(w, &encode_negotiation(props))?;
    let mut buf = vec![0u8; 1024];
    let mut total = 0usize;
    loop {
        match r.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => {
                total += n;
                if parse_negotiation_response(&buf[..total]).is_some() {
                    break;
                }
                if total == buf.len() {
                    break;
                }
            }
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                break
            }
            Err(e) => return Err(e),
        }
    }
    parse_negotiation_response(&buf[..total])
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unparseable negotiation response: {:?}", String::from_utf8_lossy(&buf[..total])),
            )
        })
}

pub fn authenticate<W: Write, R: Read>(
    w: &mut W,
    r: &mut R,
    app_id: &str,
    secret: &str,
    auth_type: i32,
) -> std::io::Result<bool> {
    write_all(w, &auth_request(app_id))?;
    let (t, challenge_val) = read_ltv(r)?;
    if t == LTV_DISCONNECT {
        return Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionAborted,
            "server disconnected during auth challenge",
        ));
    }
    if t != LTV_AUTH_CHALLENGE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("expected auth challenge, got type {}", t),
        ));
    }
    let challenge = auth_challenge_value(&challenge_val);
    let digest = digest_for(auth_type, &challenge, secret);
    write_all(w, &auth_response(app_id, &digest))?;
    let (t, status) = read_ltv(r)?;
    if t == LTV_DISCONNECT {
        return Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionAborted,
            "server disconnected during auth status",
        ));
    }
    if t != LTV_AUTH_STATUS {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("expected auth status, got type {}", t),
        ));
    }
    Ok(!status.is_empty() && status[0] != 0)
}

fn md5(data: &[u8]) -> [u8; 16] {
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
        15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    let mut k = [0u32; 64];
    for (i, item) in k.iter_mut().enumerate() {
        *item = ((i as f64 + 1.0).sin().abs() * 4294967296.0) as u32;
    }
    let mut msg = data.to_vec();
    let bitlen = (data.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bitlen.to_le_bytes());
    let (mut a0, mut b0, mut c0, mut d0) = (0x67452301u32, 0xefcdab89u32, 0x98badcfeu32, 0x10325476u32);
    for chunk in msg.chunks(64) {
        let mut m = [0u32; 16];
        for i in 0..16 {
            m[i] = u32::from_le_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);
        for i in 0..64 {
            let (f, g) = match i / 16 {
                0 => ((b & c) | (!b & d), i),
                1 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                2 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };
            let tmp = d;
            d = c;
            c = b;
            let f2 = f
                .wrapping_add(a)
                .wrapping_add(k[i])
                .wrapping_add(m[g]);
            b = b.wrapping_add(f2.rotate_left(S[i]));
            a = tmp;
        }
        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }
    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&a0.to_le_bytes());
    out[4..8].copy_from_slice(&b0.to_le_bytes());
    out[8..12].copy_from_slice(&c0.to_le_bytes());
    out[12..16].copy_from_slice(&d0.to_le_bytes());
    out
}

fn md5_hex_upper(digest: &[u8; 16]) -> String {
    let mut s = String::with_capacity(32);
    for b in digest {
        s.push_str(&format!("{:02X}", b));
    }
    s
}
