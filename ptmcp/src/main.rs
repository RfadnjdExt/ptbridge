use std::collections::{HashMap, HashSet};
use std::io::{BufRead, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

use ptmp::*;
use serde_json::{json, Value};

const APP_ID: &str = "net.netacad.cisco.ptseplayer";
const SECRET: &str = "AjDi87dHAkda783HD";
const PT_PORT: u16 = 39000;
const PT_PORT_MAX: u16 = 39020;

const DEVICE_TYPES: &[(i32, &str)] = &[
    (0, "Router"),
    (1, "Switch"),
    (2, "Cloud"),
    (3, "Bridge"),
    (4, "Hub"),
    (5, "Repeater"),
    (6, "CoAxialSplitter"),
    (7, "AccessPoint"),
    (8, "PC"),
    (9, "Server"),
    (10, "Printer"),
    (11, "WirelessRouter"),
    (12, "IpPhone"),
    (13, "DslModem"),
    (14, "CableModem"),
    (15, "RemoteNetwork"),
    (16, "MultiLayerSwitch"),
    (17, "Switch3650"),
    (18, "Laptop"),
    (19, "TabletPC"),
    (20, "Pda"),
    (21, "WirelessEndDevice"),
    (22, "WiredEndDevice"),
    (23, "TV"),
    (24, "HomeVoip"),
    (25, "AnalogPhone"),
    (26, "MultiUser"),
    (27, "ASA"),
    (28, "IoE"),
    (29, "HomeGateway"),
    (30, "WirelessRouterNewGen"),
    (31, "CellTower"),
    (32, "CentralOfficeServer"),
    (33, "CiscoAccessPoint"),
    (34, "EmbeddedCiscoAccessPoint"),
    (35, "Sniffer"),
    (36, "MCU"),
    (37, "SBC"),
    (38, "Thing"),
    (39, "MCUComponent"),
    (40, "EmbeddedServer"),
    (41, "WirelessLanController"),
    (42, "Cluster"),
    (43, "GeoIcon"),
    (44, "LightWeightAccessPoint"),
    (45, "PowerDistributionDevice"),
    (46, "PatchPanel"),
    (47, "WallMount"),
    (48, "SecurityAppliance"),
    (49, "MerakiServer"),
    (50, "NetworkController"),
    (51, "PLC"),
];

const CONNECT_TYPES: &[(i32, &str)] = &[
    (8100, "ethernet_straight"),
    (8101, "ethernet_cross"),
    (8102, "ethernet_roll"),
    (8103, "fiber"),
    (8104, "phone"),
    (8105, "cable"),
    (8106, "serial"),
    (8107, "auto"),
    (8108, "console"),
    (8109, "wireless"),
    (8110, "coaxial"),
    (8111, "octal"),
    (8112, "cellular"),
    (8113, "usb"),
    (8114, "custom_io"),
    (8115, "bluetooth_paired"),
    (8116, "bluetooth_broadcast"),
];

const VERIFIED_MODELS: &[(i32, &[&str])] = &[
    (0, &["Router-PT", "2911", "2901", "1941", "1841", "2811", "2621XM", "ISR4321", "ISR4331", "CGR1240"]),
    (1, &["Switch-PT", "Switch-PT-Empty", "2960-24TT", "2950-24", "2950T-24"]),
    (2, &["Cloud-PT", "Cloud-PT-Empty"]),
    (8, &["PC-PT"]),
    (9, &["Server-PT"]),
    (10, &["Printer-PT"]),
    (16, &["3560-24PS", "3650-24PS", "IE-2000"]),
    (18, &["Laptop-PT"]),
    (19, &["TabletPC-PT"]),
    (20, &["SMARTPHONE-PT"]),
    (21, &["WirelessEndDevice-PT"]),
    (22, &["WiredEndDevice-PT"]),
    (23, &["TV-PT"]),
];

#[derive(Clone)]
enum Arg {
    Bool(bool),
    Int(i32),
    Double(f64),
    Str(String),
    QStr(String),
    Ip(String),
    Uuid(String),
}

fn apply_arg(call: IpcCall, a: &Arg) -> IpcCall {
    match a {
        Arg::Bool(v) => call.bool(*v),
        Arg::Int(v) => call.int(*v),
        Arg::Double(v) => call.double(*v),
        Arg::Str(s) => call.string(s),
        Arg::QStr(s) => call.qstring(s),
        Arg::Ip(s) => call.ip(s),
        Arg::Uuid(s) => call.uuid(s),
    }
}

fn w2j(w: &Wire) -> Value {
    match w {
        Wire::Void => Value::Null,
        Wire::Bool(b) => json!(b),
        Wire::Int(i) => json!(i),
        Wire::Double(d) => json!(d),
        Wire::Str(s) => json!(s),
        Wire::Ip(ip) => json!(ip_string(ip)),
        Wire::Uuid(u) => json!(uuid_string(u)),
        Wire::Handle(h) => json!(h),
        Wire::Pair(v) | Wire::Array(_, v) => Value::Array(v.iter().map(w2j).collect()),
        Wire::Raw(t, b) => {
            let hex: String = b.iter().take(64).map(|x| format!("{:02x}", x)).collect();
            json!({"tag": t, "hex": hex})
        }
    }
}

struct Session {
    writer: TcpStream,
    reader: std::io::BufReader<TcpStream>,
    msg_id: i32,
    port: u16,
}

fn connect_once(port: u16, probe: bool) -> Result<Session, String> {
    let stream = TcpStream::connect(("127.0.0.1", port))
        .map_err(|e| format!("io: connect {}: {}", port, e))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(if probe { 2 } else { 30 })))
        .map_err(|e| format!("io: read timeout: {}", e))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(if probe { 2 } else { 30 })))
        .map_err(|e| format!("io: write timeout: {}", e))?;
    let mut writer = stream.try_clone().map_err(|e| format!("io: clone: {}", e))?;
    let mut reader = std::io::BufReader::new(stream);
    let props = NegotiationProps::default();
    let nego = negotiate(&mut writer, &mut reader, &props)
        .map_err(|e| format!("io: negotiate {}: {}", port, e))?;
    let ok = authenticate(&mut writer, &mut reader, APP_ID, SECRET, nego.authentication)
        .map_err(|e| format!("io: authenticate {}: {}", port, e))?;
    if !ok {
        return Err(format!("io: authentication rejected on {}", port));
    }
    Ok(Session {
        writer,
        reader,
        msg_id: 0,
        port,
    })
}

fn session_connect(port: u16, probe: bool) -> Result<Session, String> {
    let attempts: u32 = if probe { 1 } else { 3 };
    let mut last = String::from("no attempt");
    for i in 0..attempts {
        if i > 0 {
            std::thread::sleep(Duration::from_millis(200 * (1 << (i - 1))));
        }
        match connect_once(port, probe) {
            Ok(s) => return Ok(s),
            Err(e) => last = e,
        }
    }
    Err(last)
}

impl Session {

    fn call_once(&mut self, segs: &[(&str, Vec<Arg>)]) -> Result<Value, String> {
        self.msg_id = self.msg_id.wrapping_add(1);
        let mut call = IpcCall::new(self.msg_id, &[segs[0].0]);
        for a in &segs[0].1 {
            call = apply_arg(call, a);
        }
        for (name, args) in segs.iter().skip(1) {
            call = call.push_segment(name);
            for a in args {
                call = apply_arg(call, a);
            }
        }
        let bytes = call.encode();
        self.writer
            .write_all(&bytes)
            .map_err(|e| format!("io: write: {}", e))?;
        self.writer
            .flush()
            .map_err(|e| format!("io: write: {}", e))?;
        loop {
            let (t, v) = read_ltv(&mut self.reader).map_err(|e| format!("io: read: {}", e))?;
            match t {
                LTV_KEEPALIVE => continue,
                LTV_IPC_RESPONSE => {
                    let (mid, vals) =
                        decode_response(&v).map_err(|e| format!("decode response: {}", e))?;
                    if mid != self.msg_id {
                        continue;
                    }
                    return Ok(match vals.len() {
                        0 => Value::Null,
                        1 => w2j(&vals[0]),
                        _ => Value::Array(vals.iter().map(w2j).collect()),
                    });
                }
                LTV_IPC_ERROR => {
                    let (mid, class, text) =
                        decode_status(&v).map_err(|e| format!("decode status: {}", e))?;
                    if std::env::var("PTMCP_DEBUG").is_ok() {
                        eprintln!("raw error: {}", hexdump(&v));
                    }
                    if mid != self.msg_id {
                        continue;
                    }
                    if text.starts_with("IPC Cache entry") {
                        let guid = text.trim_start_matches("IPC Cache entry:");
                        let valid = guid.len() >= 16
                            && guid.chars().all(|c| {
                                c.is_ascii_hexdigit() || c == '-' || c == '{' || c == '}' || c == ' '
                            })
                            && !guid.contains('\0')
                            && guid.chars().any(|c| c.is_ascii_hexdigit());
                        if valid {
                            return Ok(json!({"object": text}));
                        }
                        return Err(format!(
                            "target object not found (bad device/port name?): {}",
                            class
                        ));
                    }
                    return Err(format!("{}: {}", class, text));
                }
                LTV_DISCONNECT => return Err("io: server disconnected".into()),
                other => return Err(format!("unexpected ltv type {}", other)),
            }
        }
    }

    fn call(&mut self, segs: &[(&str, Vec<Arg>)]) -> Result<Value, String> {
        match self.call_once(segs) {
            Err(e) if e.starts_with("io:") => {
                *self = session_connect(self.port, false)?;
                self.call_once(segs)
            }
            other => other,
        }
    }
}

static SESSIONS: LazyLock<Mutex<HashMap<u16, Arc<Mutex<Session>>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static SELECTED_PORT: AtomicU16 = AtomicU16::new(0);

#[derive(Default)]
struct FileState {
    path: Option<String>,
    dirty: Option<bool>,
}

static FILE_STATE: LazyLock<Mutex<FileState>> =
    LazyLock::new(|| Mutex::new(FileState::default()));

// PT's IPC has no note-position getter (verified against the IpcAPI docs shipped
// in PT\help), so note coordinates are bridge-tracked: recorded when add_note
// places them, null for GUI-placed/older notes.
static NOTE_POS: LazyLock<Mutex<HashMap<String, (f64, f64)>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

// switch/router -> its PT-spawned Power Distribution Device, recorded at add
// time so remove_device can take the companion with it (PT does not).
static COMPANIONS: LazyLock<Mutex<HashMap<String, String>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

// MCP notifications/message channel; sender installed in main() before the
// request loop so batch progress etc. can stream mid-request.
static NOTIF_TX: LazyLock<Mutex<Option<mpsc::Sender<String>>>> =
    LazyLock::new(|| Mutex::new(None));

// Ports already reported by the instances tool (for instance_discovered events).
static KNOWN_PORTS: LazyLock<Mutex<HashSet<u16>>> = LazyLock::new(|| Mutex::new(HashSet::new()));

fn notify(level: &str, data: Value) {
    let line = json!({
        "jsonrpc": "2.0",
        "method": "notifications/message",
        "params": {"level": level, "logger": "ptbridge", "data": data}
    })
    .to_string();
    if let Some(tx) = NOTIF_TX.lock().unwrap_or_else(|e| e.into_inner()).clone() {
        let _ = tx.send(line);
    }
}

const READ_ONLY_TOOLS: &[&str] = &[
    "list_types",
    "list_error_codes",
    "get_version",
    "list_devices",
    "get_device",
    "list_ports",
    "list_modules",
    "port_config",
    "list_notes",
    "get_link_count",
    "list_links",
    "cli_prompt",
    "cli_output",
    "wait_for_prompt",
    "instances",
    "select_instance",
    "file_status",
];

fn file_state_lock() -> std::sync::MutexGuard<'static, FileState> {
    FILE_STATE.lock().unwrap_or_else(|e| e.into_inner())
}

fn guard_unsaved(action: &str, force: bool) -> Result<(), String> {
    if force {
        return Ok(());
    }
    let st = file_state_lock();
    if st.dirty == Some(true) {
        let what = st.path.as_deref().unwrap_or("unsaved workspace");
        return Err(format!(
            "{} blocked: unsaved changes in {} - pass \"force\": true to discard, or file_save_as first",
            action, what
        ));
    }
    Ok(())
}

fn discover_ports(max: u16) -> Vec<u16> {
    (PT_PORT..=max)
        .filter_map(|p| session_connect(p, true).ok().map(|_| p))
        .collect()
}

fn resolve_port() -> Result<u16, String> {
    let sel = SELECTED_PORT.load(Ordering::SeqCst);
    if sel != 0 {
        return Ok(sel);
    }
    if TcpStream::connect(("127.0.0.1", PT_PORT)).is_ok() {
        SELECTED_PORT.store(PT_PORT, Ordering::SeqCst);
        return Ok(PT_PORT);
    }
    let found = discover_ports(PT_PORT_MAX).into_iter().next().ok_or_else(|| {
        format!(
            "io: no Packet Tracer instance reachable (scanned ports {}-{}; is Packet Tracer running?)",
            PT_PORT, PT_PORT_MAX
        )
    })?;
    SELECTED_PORT.store(found, Ordering::SeqCst);
    Ok(found)
}

fn with_session<F>(args: &Value, mut f: F) -> Result<Value, String>
where
    F: FnMut(&mut Session) -> Result<Value, String>,
{
    let port = match args.get("instance").and_then(|v| v.as_i64()) {
        Some(v) if v > 0 => v as u16,
        _ => resolve_port()?,
    };
    // Pool layout: the map lock is held only for Arc lookup/insert; the actual
    // IPC runs under the per-session mutex. Concurrent tools (batch ops vs
    // other calls) therefore interleave instead of serializing on the map.
    let existing = SESSIONS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&port)
        .cloned();
    if let Some(slot) = existing {
        let r = {
            let mut se = slot.lock().unwrap_or_else(|e| e.into_inner());
            f(&mut se)
        };
        if !matches!(&r, Err(e) if e.starts_with("io:")) {
            return r;
        }
        // Connection broke: drop it, but only if nobody replaced it meanwhile.
        let mut map = SESSIONS.lock().unwrap_or_else(|e| e.into_inner());
        if map.get(&port).is_some_and(|a| Arc::ptr_eq(a, &slot)) {
            map.remove(&port);
        }
        drop(map);
    }
    let mut se = session_connect(port, false)?;
    let r = f(&mut se);
    if r.is_ok() {
        let mut map = SESSIONS.lock().unwrap_or_else(|e| e.into_inner());
        if !map.contains_key(&port) {
            map.insert(port, Arc::new(Mutex::new(se)));
        }
    }
    r
}

// Force-recycle the pooled session for a port (used when an op is abandoned:
// its thread may still hold the mutex, so the next call must start fresh).
fn drop_session(port: u16) {
    SESSIONS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&port);
}

fn device_type_name(t: i32) -> String {
    DEVICE_TYPES
        .iter()
        .find(|(k, _)| *k == t)
        .map(|(_, n)| n.to_string())
        .unwrap_or_else(|| format!("Unknown({})", t))
}

fn req_str(args: &Value, k: &str) -> Result<String, String> {
    args.get(k)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| format!("missing string argument \"{}\"", k))
}

fn req_uuid(args: &Value, k: &str) -> Result<String, String> {
    let raw = req_str(args, k)?;
    let hex: String = raw
        .trim()
        .trim_start_matches('{')
        .trim_end_matches('}')
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect();
    if hex.len() != 32 {
        return Err(format!(
            "invalid \"{}\": expected a 32-hex-digit id, got {:?}",
            k, raw
        ));
    }
    Ok(raw)
}

fn req_ipv4(args: &Value, k: &str) -> Result<String, String> {
    let raw = req_str(args, k)?;
    let parts: Vec<&str> = raw.split('.').collect();
    let ok = parts.len() == 4
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.parse::<u16>().map(|n| n <= 255).unwrap_or(false));
    if !ok {
        return Err(format!(
            "invalid \"{}\": expected dotted-quad IPv4 (0-255 per octet), got {:?}",
            k, raw
        ));
    }
    Ok(raw)
}

fn req_int(args: &Value, k: &str) -> Result<i32, String> {
    match args.get(k).and_then(|v| v.as_i64()) {
        Some(v) => Ok(v as i32),
        None => Err(format!("missing int argument \"{}\"", k)),
    }
}

fn req_num(args: &Value, k: &str) -> Result<f64, String> {
    match args.get(k) {
        Some(v) if v.is_number() => v
            .as_f64()
            .ok_or_else(|| format!("argument \"{}\" is not a number", k)),
        _ => Err(format!("missing number argument \"{}\"", k)),
    }
}

fn opt_num(args: &Value, k: &str, dflt: f64) -> f64 {
    args.get(k).and_then(|v| v.as_f64()).unwrap_or(dflt)
}

fn opt_bool(args: &Value, k: &str, dflt: bool) -> bool {
    args.get(k).and_then(|v| v.as_bool()).unwrap_or(dflt)
}

fn opt_int(args: &Value, k: &str, dflt: i32) -> i32 {
    args.get(k).and_then(|v| v.as_i64()).map(|v| v as i32).unwrap_or(dflt)
}

// Machine-readable error classification. Generation sites may prefix an
// explicit [code]; everything else is classified by shape so legacy strings
// carry a code too. Wire format: "[code] message".
const ERROR_CODES: &[(&str, &str, bool)] = &[
    ("invalid_arg", "missing/malformed argument or unknown tool - fix the call, retrying unchanged will fail again", false),
    ("not_found", "device/port/link/note/instance does not exist or target already linked - re-list state before retrying", false),
    ("conflict", "name already taken or duplicate object - pick a different name", false),
    ("state", "blocked by workspace state (unsaved changes) - file_save or pass force:true, then retry", false),
    ("limit", "batch/tool limit exceeded - split the request", false),
    ("timeout", "op exceeded timeout_ms budget - session was recycled; safe to retry the op", true),
    ("io", "session/socket failure - the call auto-reconnects once; retry if it still fails", true),
    ("protocol", "unexpected/non-conforming PT IPC response - usually transient or a PT-side version gap", true),
    ("internal", "unclassified bridge error - inspect the message", false),
];

fn error_code(e: &str) -> &'static str {
    if e.starts_with("io:") {
        return "io";
    }
    if let Some(rest) = e.strip_prefix('[') {
        if let Some((c, _)) = rest.split_once(']') {
            if ERROR_CODES.iter().any(|(k, _, _)| *k == c) {
                return ERROR_CODES
                    .iter()
                    .find(|(k, _, _)| *k == c)
                    .map(|(k, _, _)| *k)
                    .unwrap_or("internal");
            }
        }
    }
    let l = e.to_ascii_lowercase();
    if l.starts_with("unknown tool ") {
        return "invalid_arg";
    }
    if l.contains("not found") || l.contains("does not exist") || l.contains("returned false") {
        return "not_found";
    }
    if l.contains("already exists")
        || l.contains("duplicate")
        || l.contains("not unique")
        || l.contains("name taken")
        || l.contains("in use")
    {
        return "conflict";
    }
    if l.contains("unsaved") || l.contains("blocked") {
        return "state";
    }
    if l.contains("limit is") || l.contains("too many") {
        return "limit";
    }
    if l.contains("timed out") || l.contains("timeout") {
        return "timeout";
    }
    if l.contains("missing")
        || l.contains("invalid")
        || l.contains("expected")
        || l.contains("must contain")
        || l.contains("not allowed")
        || l.contains("malformed")
    {
        return "invalid_arg";
    }
    if l.contains("unexpected response") || l.contains("non-string") || l.contains("unexpected ltv") {
        return "protocol";
    }
    "internal"
}

// Wire formatter: one code prefix per error text, never doubled.
fn with_code(e: &str) -> String {
    if e.starts_with('[') {
        e.to_string()
    } else {
        format!("[{}] {}", error_code(e), e)
    }
}

fn as_str(v: &Value) -> Result<String, String> {
    v.as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| format!("unexpected response: {}", v))
}

fn as_int(v: &Value) -> Result<i32, String> {
    v.as_i64()
        .map(|i| i as i32)
        .ok_or_else(|| format!("unexpected response: {}", v))
}

fn as_bool(v: &Value) -> Result<bool, String> {
    match v {
        Value::Bool(b) => Ok(*b),
        Value::Null => Ok(true),
        _ => Err(format!("unexpected response: {}", v)),
    }
}

fn at(i: i32, method: &'static str, margs: Vec<Arg>) -> Vec<(&'static str, Vec<Arg>)> {
    vec![
        ("network", vec![]),
        ("getDeviceAt", vec![Arg::Int(i)]),
        (method, margs),
    ]
}

fn by(name: &str, method: &'static str, margs: Vec<Arg>) -> Vec<(&'static str, Vec<Arg>)> {
    vec![
        ("network", vec![]),
        ("getDevice", vec![Arg::QStr(name.to_string())]),
        (method, margs),
    ]
}

fn on_port(name: &str, p: &str, method: &'static str, margs: Vec<Arg>) -> Vec<(&'static str, Vec<Arg>)> {
    vec![
        ("network", vec![]),
        ("getDevice", vec![Arg::QStr(name.to_string())]),
        ("getPort", vec![Arg::Str(p.to_string())]),
        (method, margs),
    ]
}

fn console_base(dev: &str) -> Vec<(&'static str, Vec<Arg>)> {
    vec![
        ("network", vec![]),
        ("getDevice", vec![Arg::QStr(dev.to_string())]),
        ("getCommandLine", vec![]),
    ]
}

fn console_prompt(se: &mut Session, base: &[(&'static str, Vec<Arg>)]) -> Result<String, String> {
    let mut segs = base.to_vec();
    segs.push(("getPrompt", vec![]));
    Ok(se.call(&segs)?.as_str().unwrap_or("").to_string())
}

fn console_output(se: &mut Session, base: &[(&'static str, Vec<Arg>)]) -> Result<String, String> {
    let mut segs = base.to_vec();
    segs.push(("getOutput", vec![]));
    Ok(se.call(&segs)?.as_str().unwrap_or("").to_string())
}

fn delta_text(before: &str, after: &str) -> String {
    if after.starts_with(before) {
        after[before.len()..]
            .trim_start_matches(['\r', '\n'])
            .to_string()
    } else {
        let lines: Vec<&str> = after.lines().collect();
        lines[before.lines().count().min(lines.len())..].join("\n")
    }
}

fn ios_status(output: &str) -> (i32, &'static str) {
    let lower = output.to_ascii_lowercase();
    if lower.contains("incomplete command") || lower.contains("% incomplete") {
        (3, "incomplete")
    } else if lower.contains("ambiguous command") || lower.contains("% ambiguous") {
        (1, "ambiguous")
    } else if lower.contains("invalid input")
        || lower.contains("% invalid")
        || lower.contains("% unrecognized")
        || lower.contains("unknown command")
    {
        (2, "invalid")
    } else {
        (0, "ok")
    }
}

struct ConsoleRun {
    prompt0: String,
    prompt1: String,
    output: String,
    woken: bool,
    timed_out: bool,
    status: i32,
    status_text: &'static str,
}

// Shared console executor: wake if needed, type the command, then poll the
// output until the prompt reappears as the last line with no new data for one
// poll (command finished, any prompt shape incl. mode changes like enable)
// or until wait_ms budget expires (timed_out=true, partial output returned).
fn console_exec(
    se: &mut Session,
    dev: &str,
    cmd: &str,
    wait_ms: u64,
    poll_ms: u64,
) -> Result<ConsoleRun, String> {
    let base = console_base(dev);
    let mut prompt0 = console_prompt(se, &base)?;
    let mut before = console_output(se, &base)?;
    let mut woken = false;
    if prompt0.trim().is_empty() {
        let mut wake = base.clone();
        wake.push(("enterCommand", vec![Arg::Str(String::new())]));
        se.call(&wake)?;
        std::thread::sleep(Duration::from_millis(300));
        woken = true;
        prompt0 = console_prompt(se, &base)?;
        before = console_output(se, &base)?;
    }
    if !cmd.is_empty() {
        let mut enter = base.clone();
        enter.push(("enterCommand", vec![Arg::Str(cmd.to_string())]));
        se.call(&enter)?;
    }
    let start = std::time::Instant::now();
    let mut after = before.clone();
    let mut timed_out = true;
    let mut ever_grew = false;
    let mut prev_len = before.len();
    while start.elapsed() < Duration::from_millis(wait_ms) {
        std::thread::sleep(Duration::from_millis(poll_ms));
        let cur = console_output(se, &base)?;
        let grew = cur.len() > prev_len;
        prev_len = cur.len();
        if grew {
            ever_grew = true;
        }
        after = cur;
        let last = after
            .lines()
            .rev()
            .find(|l| !l.trim().is_empty())
            .unwrap_or("")
            .trim_end();
        let prompt_like = last.ends_with('>') || last.ends_with('#');
        if prompt_like && (ever_grew || cmd.is_empty()) && !grew {
            timed_out = false;
            break;
        }
        // IOS pager stalled: keep sending space (same as pressing it in the
        // GUI) until the real prompt appears or the budget runs out.
        if !grew && last.contains("--More--") {
            let mut page = base.clone();
            page.push(("enterCommand", vec![Arg::Str(" ".to_string())]));
            se.call(&page)?;
        }
    }
    let prompt1 = console_prompt(se, &base)?;
    let output = delta_text(&before, &after);
    let (status, status_text) = ios_status(&output);
    Ok(ConsoleRun {
        prompt0,
        prompt1,
        output,
        woken,
        timed_out,
        status,
        status_text,
    })
}

fn port_names(se: &mut Session, dev: &str) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for i in 0..32 {
        let v = match se.call(&[
            ("network", vec![]),
            ("getDevice", vec![Arg::QStr(dev.to_string())]),
            ("getPortAt", vec![Arg::Int(i)]),
            ("getName", vec![]),
        ]) {
            Ok(v) => v,
            Err(_) => break,
        };
        match as_str(&v) {
            Ok(n) => out.push(n),
            Err(_) => break,
        }
    }
    Ok(out)
}

fn live_ports(se: &mut Session, dev: &str) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for name in port_names(se, dev)? {
        let up = as_bool(&se.call(&on_port(dev, &name, "isProtocolUp", vec![]))?)?;
        if up {
            out.push(name);
        }
    }
    Ok(out)
}

fn link_chain(i: i32, tail: &[(&'static str, Vec<Arg>)]) -> Vec<(&'static str, Vec<Arg>)> {
    let mut v = vec![
        ("network", vec![]),
        ("getLinkAt", vec![Arg::Int(i)]),
    ];
    v.extend_from_slice(tail);
    v
}

fn connect_type_name(t: i32) -> String {
    CONNECT_TYPES
        .iter()
        .find(|(k, _)| *k == t)
        .map(|(_, n)| n.to_string())
        .unwrap_or_else(|| format!("Unknown({})", t))
}

fn query_link(port: u16, i: i32) -> Option<(i32, Value)> {
    let mut se = session_connect(port, false).ok()?;
    let s1 = se
        .call(&link_chain(i, &[("getPort1", vec![]), ("getName", vec![])]))
        .ok()
        .and_then(|v| v.as_str().map(str::to_string));
    let s2 = se
        .call(&link_chain(i, &[("getPort2", vec![]), ("getName", vec![])]))
        .ok()
        .and_then(|v| v.as_str().map(str::to_string));
    let n1 = se
        .call(&link_chain(
            i,
            &[
                ("getPort1", vec![]),
                ("getOwnerDevice", vec![]),
                ("getName", vec![]),
            ],
        ))
        .ok()
        .and_then(|v| v.as_str().map(str::to_string));
    let n2 = se
        .call(&link_chain(
            i,
            &[
                ("getPort2", vec![]),
                ("getOwnerDevice", vec![]),
                ("getName", vec![]),
            ],
        ))
        .ok()
        .and_then(|v| v.as_str().map(str::to_string));
    if s1.is_none() && s2.is_none() {
        return None;
    }
    let u1 = se
        .call(&link_chain(i, &[("getPort1", vec![]), ("isProtocolUp", vec![])]))
        .ok()
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let u2 = se
        .call(&link_chain(i, &[("getPort2", vec![]), ("isProtocolUp", vec![])]))
        .ok()
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let ct = se
        .call(&link_chain(i, &[("getConnectionType", vec![])]))
        .ok()
        .and_then(|v| v.as_i64());
    Some((
        i,
        json!({
            "index": i,
            "device1": n1,
            "port1": s1,
            "device2": n2,
            "port2": s2,
            "connect_type": ct,
            "connect_type_name": ct.map(|c| connect_type_name(c as i32)),
            "protocol_up_1": u1,
            "protocol_up_2": u2,
            "live": u1 && u2,
        }),
    ))
}

fn run_tool(name: &str, args: &Value) -> Result<Value, String> {
    if name != "batch"
        && name != "file_open"
        && name != "file_save_as"
        && name != "clear_workspace"
        && !READ_ONLY_TOOLS.contains(&name)
    {
        file_state_lock().dirty = Some(true);
    }
    match name {
        "batch" => {
            let ops = args
                .get("ops")
                .and_then(|v| v.as_array())
                .ok_or("`ops` array required")?;
            if ops.is_empty() {
                return Err("`ops` must contain at least 1 item".to_string());
            }
            if ops.len() > 200 {
                return Err("ops limit is 200 per batch".to_string());
            }
            let stop = args
                .get("stop_on_error")
                .and_then(|v| v.as_bool())
                .unwrap_or(true);
            let timeout_ms = opt_int(args, "timeout_ms", 120_000).max(0) as u64;
            let inherited_instance = args.get("instance").cloned();
            let mut results: Vec<Value> = Vec::new();
            let mut ok_count = 0usize;
            let mut failed = 0usize;
            let mut executed = 0usize;
            let batch_start = std::time::Instant::now();
            let mut last_notify = std::time::Instant::now();
            for (i, op) in ops.iter().enumerate() {
                let tool = op.get("tool").and_then(|v| v.as_str()).unwrap_or("");
                let mut op_args = op.get("args").cloned().unwrap_or(json!({}));
                if let (Some(inst), Some(map)) = (inherited_instance.clone(), op_args.as_object_mut()) {
                    map.entry("instance".to_string()).or_insert(inst);
                }
                let bad = if tool.is_empty() {
                    Some("missing tool name".to_string())
                } else if tool == "batch" {
                    Some("nested batch is not allowed".to_string())
                } else {
                    None
                };
                if let Some(e) = bad {
                    failed += 1;
                    executed += 1;
                    results.push(json!({"i": i, "tool": tool, "ok": false, "code": error_code(&e), "error": with_code(&e)}));
                    if stop {
                        break;
                    }
                    continue;
                }
                // Per-op execution: a timeout/panic abandons the worker thread
                // and recycles the pooled session so the next op starts clean.
                let outcome: Result<Value, String> = if timeout_ms == 0 {
                    run_tool(tool, &op_args)
                } else {
                    let t = tool.to_string();
                    let a = op_args.clone();
                    let (tx, rx) = mpsc::channel();
                    // Worker sends its result; a panic drops the sender without
                    // sending, which surfaces here as Disconnected.
                    std::thread::spawn(move || {
                        let _ = tx.send(run_tool(&t, &a));
                    });
                    match rx.recv_timeout(Duration::from_millis(timeout_ms)) {
                        Ok(r) => r,
                        Err(mpsc::RecvTimeoutError::Timeout) => {
                            let port = op_args
                                .get("instance")
                                .and_then(|v| v.as_i64())
                                .map(|v| v as u16)
                                .or_else(|| resolve_port().ok())
                                .unwrap_or(0);
                            if port != 0 {
                                drop_session(port);
                            }
                            notify(
                                "warning",
                                json!({"event": "op_timeout", "i": i, "tool": tool, "timeout_ms": timeout_ms, "session_recycled": port}),
                            );
                            Err(format!(
                                "op timed out after {}ms - abandoned, pooled session recycled for next op",
                                timeout_ms
                            ))
                        }
                        Err(mpsc::RecvTimeoutError::Disconnected) => {
                            let port = op_args
                                .get("instance")
                                .and_then(|v| v.as_i64())
                                .map(|v| v as u16)
                                .or_else(|| resolve_port().ok())
                                .unwrap_or(0);
                            if port != 0 {
                                drop_session(port);
                            }
                            notify(
                                "error",
                                json!({"event": "op_panic", "i": i, "tool": tool, "session_recycled": port}),
                            );
                            Err(
                                "op thread panicked - pooled session recycled for next op".to_string(),
                            )
                        }
                    }
                };
                match outcome {
                    Ok(v) => {
                        ok_count += 1;
                        executed += 1;
                        results.push(json!({"i": i, "tool": tool, "ok": true, "result": v}));
                    }
                    Err(e) => {
                        failed += 1;
                        executed += 1;
                        let code = error_code(&e);
                        results.push(json!({"i": i, "tool": tool, "ok": false, "code": code, "error": with_code(&e)}));
                        if stop {
                            break;
                        }
                    }
                }
                // Progress events: stream once the batch has been running a
                // while, so long builds are visible to the client live.
                if last_notify.elapsed() >= Duration::from_millis(2000) {
                    notify(
                        "info",
                        json!({"event": "batch_progress", "i": i + 1, "total": ops.len(), "tool": tool, "ok": ok_count, "failed": failed, "elapsed_ms": batch_start.elapsed().as_millis() as u64}),
                    );
                    last_notify = std::time::Instant::now();
                }
            }
            if batch_start.elapsed() >= Duration::from_millis(5000) {
                notify(
                    "info",
                    json!({"event": "batch_complete", "ok": ok_count, "failed": failed, "elapsed_ms": batch_start.elapsed().as_millis() as u64}),
                );
            }
            Ok(json!({
                "total": ops.len(),
                "executed": executed,
                "ok": ok_count,
                "failed": failed,
                "stopped_early": failed > 0 && executed < ops.len(),
                "results": results,
            }))
        }

        "list_types" => {
            let types: Vec<Value> = DEVICE_TYPES
                .iter()
                .map(|(k, n)| json!({"type": k, "name": n}))
                .collect();
            let models = VERIFIED_MODELS
                .iter()
                .map(|(k, ms)| json!({"type": k, "models": ms}))
                .collect::<Vec<Value>>();
            Ok(json!({"count": types.len(), "types": types, "verified_models": models}))
        }

        "list_error_codes" => Ok(json!({
            "format": "every error text carries a [code] prefix (classified at the wire); batch per-op results expose the same code as a separate field",
            "count": ERROR_CODES.len(),
            "codes": ERROR_CODES
                .iter()
                .map(|(c, meaning, retry)| json!({"code": c, "meaning": meaning, "retryable": retry}))
                .collect::<Vec<Value>>(),
        })),

        "get_version" => with_session(args, |se| {
            se.call(&[
                ("appWindow", vec![]),
                ("getVersion", vec![]),
            ])
        }),

        "list_devices" => with_session(args, |se| {
            let count = as_int(&se.call(&[("network", vec![]), ("getDeviceCount", vec![])])?)?;
            let mut devices = Vec::new();
            for i in 0..count {
                let name_v = se.call(&at(i, "getName", vec![]))?;
                if name_v.is_null() {
                    continue;
                }
                let name = as_str(&name_v)?;
                let model = as_str(&se.call(&at(i, "getModel", vec![]))?)?;
                let dtype = as_int(&se.call(&at(i, "getType", vec![]))?)?;
                let x = se.call(&at(i, "getXCoordinate", vec![]))?;
                let y = se.call(&at(i, "getYCoordinate", vec![]))?;
                devices.push(json!({
                    "index": i,
                    "name": name,
                    "model": model,
                    "type": dtype,
                    "type_name": device_type_name(dtype),
                    "x": x,
                    "y": y,
                }));
            }
            Ok(json!({"count": count, "devices": devices}))
        }),

        "get_device" => with_session(args, |se| {
            let name = req_str(args, "name")?;
            let model = as_str(&se.call(&by(&name, "getModel", vec![]))?)?;
            let dtype = as_int(&se.call(&by(&name, "getType", vec![]))?)?;
            let x = se.call(&by(&name, "getXCoordinate", vec![]))?;
            let y = se.call(&by(&name, "getYCoordinate", vec![]))?;
            let ports = port_names(se, &name)?.len();
            Ok(json!({
                "name": name,
                "model": model,
                "type": dtype,
                "type_name": device_type_name(dtype),
                "x": x,
                "y": y,
                "port_count": ports,
            }))
        }),

        "add_device" => with_session(args, |se| {
            let dtype = req_int(args, "type")?;
            let model = req_str(args, "model")?;
            let x = req_num(args, "x")?;
            let y = req_num(args, "y")?;
            let pre_count = as_int(&se.call(&[("network", vec![]), ("getDeviceCount", vec![])])?)?;
            let mut name = as_str(&se.call(&[
                ("appWindow", vec![]),
                ("getActiveWorkspace", vec![]),
                ("getLogicalWorkspace", vec![]),
                (
                    "addDevice",
                    vec![
                        Arg::Int(dtype),
                        Arg::Str(model.clone()),
                        Arg::Double(x),
                        Arg::Double(y),
                    ],
                ),
            ])?)?;
            if let Some(want) = args.get("name").and_then(|v| v.as_str()) {
                se.call(&by(&name, "setName", vec![Arg::QStr(want.to_string())]))?;
                name = want.to_string();
            }
            // PT spawns a Power Distribution Device alongside routers/switches
            // (device count +2). Track the pair so remove_device can clean it
            // up; drop the PDD now unless keep_companion=true.
            let mut companion_removed = None;
            let mut companion_kept = None;
            let post_count = as_int(&se.call(&[("network", vec![]), ("getDeviceCount", vec![])])?)?;
            if post_count - pre_count == 2 {
                let keep = opt_bool(args, "keep_companion", false);
                for idx in pre_count..post_count {
                    let t = se
                        .call(&at(idx, "getType", vec![]))
                        .ok()
                        .and_then(|v| v.as_i64());
                    if t != Some(45) {
                        continue;
                    }
                    let Some(cname) = se
                        .call(&at(idx, "getName", vec![]))
                        .ok()
                        .and_then(|v| v.as_str().map(str::to_string))
                    else {
                        continue;
                    };
                    COMPANIONS
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .insert(name.clone(), cname.clone());
                    if keep {
                        companion_kept = Some(cname);
                    } else {
                        let gone = se
                            .call(&[
                                ("appWindow", vec![]),
                                ("getActiveWorkspace", vec![]),
                                ("getLogicalWorkspace", vec![]),
                                ("removeDevice", vec![Arg::QStr(cname.clone())]),
                            ])
                            .ok()
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false);
                        if gone {
                            companion_removed = Some(cname);
                            // Pair is already gone - do not leave a stale record
                            // that remove_device would try to delete again.
                            COMPANIONS
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .remove(&name);
                        } else {
                            companion_kept = Some(cname);
                        }
                    }
                }
            }
            let mut out = json!({
                "name": name,
                "type": dtype,
                "type_name": device_type_name(dtype),
                "model": model,
            });
            if let Some(c) = companion_removed {
                out["companion_removed"] = json!(c);
            }
            if let Some(c) = companion_kept {
                out["companion"] = json!(c);
                out["companion_note"] =
                    json!("PT auto-spawns a Power Distribution Device for switches/routers; remove_device takes it with the device");
            }
            Ok(out)
        }),

        "remove_device" => with_session(args, |se| {
            let name = req_str(args, "name")?;
            let ok = as_bool(&se.call(&[
                ("appWindow", vec![]),
                ("getActiveWorkspace", vec![]),
                ("getLogicalWorkspace", vec![]),
                ("removeDevice", vec![Arg::QStr(name.clone())]),
            ])?)?;
            if !ok {
                return Err(format!(
                    "removeDevice({}) returned false - device name mismatch or already removed",
                    name
                ));
            }
            // Take the PT-spawned companion PDD with its switch/router (PT
            // does not); also drop pair records when either side disappears.
            let companion = {
                let mut map = COMPANIONS.lock().unwrap_or_else(|e| e.into_inner());
                let c = map.remove(&name);
                map.retain(|_, v| v != &name);
                c
            };
            let mut out = json!({"removed": name});
            if let Some(c) = companion {
                let gone = se
                    .call(&[
                        ("appWindow", vec![]),
                        ("getActiveWorkspace", vec![]),
                        ("getLogicalWorkspace", vec![]),
                        ("removeDevice", vec![Arg::QStr(c.clone())]),
                    ])
                    .ok()
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                if gone {
                    out["companion_removed"] = json!(c);
                } else {
                    // removeDevice returns false both for "gone" and "name
                    // mismatch" - probe existence to report the truth.
                    let exists = se
                        .call(&[
                            ("network", vec![]),
                            ("getDevice", vec![Arg::QStr(c.clone())]),
                            ("getName", vec![]),
                        ])
                        .is_ok();
                    if exists {
                        out["companion_removal_failed"] = json!(c);
                    } else {
                        out["companion_already_gone"] = json!(c);
                    }
                }
            }
            Ok(out)
        }),

        "cli_output" => with_session(args, |se| {
            let dev = req_str(args, "device")?;
            let tail = opt_int(args, "tail", 60);
            let v = se.call(&[
                ("network", vec![]),
                ("getDevice", vec![Arg::QStr(dev.clone())]),
                ("getCommandLine", vec![]),
                ("getOutput", vec![]),
            ])?;
            let text = v.as_str().unwrap_or("").to_string();
            let lines: Vec<&str> = text.split('\n').collect();
            let keep = if tail <= 0 { lines.len() } else { tail as usize };
            let start = lines.len().saturating_sub(keep);
            let slice = lines[start..].join("\n");
            Ok(json!({
                "device": dev,
                "total_lines": lines.len(),
                "tail": keep,
                "text": slice,
            }))
        }),

        "cli_prompt" => with_session(args, |se| {
            let dev = req_str(args, "device")?;
            let base = console_base(&dev);
            let mut probe = base.clone();
            probe.push(("getPrompt", vec![]));
            let p = se.call(&probe)?.as_str().unwrap_or("").to_string();
            if !p.trim().is_empty() {
                return Ok(json!(p));
            }
            let mut probe = base;
            probe.push(("getOutput", vec![]));
            let out = se.call(&probe)?.as_str().unwrap_or("").to_string();
            let last = out
                .lines()
                .rev()
                .find(|l| !l.trim().is_empty())
                .unwrap_or("");
            Ok(json!(last.trim_end()))
        }),

        "pc_command" => with_session(args, |se| {
            let dev = req_str(args, "device")?;
            let cmd = req_str(args, "command")?;
            let wait_ms = opt_int(args, "wait_ms", 15_000).clamp(1_000, 120_000) as u64;
            let poll_ms = opt_int(args, "poll_ms", 300).clamp(100, 2_000) as u64;
            let base = console_base(&dev);
            let mut probe = base.clone();
            probe.push(("getPrompt", vec![]));
            let prompt0 = se.call(&probe)?.as_str().unwrap_or("").to_string();
            let mut probe = base.clone();
            probe.push(("getOutput", vec![]));
            let mut before = as_str(&se.call(&probe)?)?;
            if prompt0.is_empty() {
                let mut wake = base.clone();
                wake.push(("enterCommand", vec![Arg::Str(String::new())]));
                se.call(&wake)?;
                std::thread::sleep(Duration::from_millis(300));
                let mut probe = base.clone();
                probe.push(("getOutput", vec![]));
                let b2 = as_str(&se.call(&probe)?)?;
                if b2.len() > before.len() {
                    before = b2;
                }
            }
            let mut enter = base.clone();
            enter.push(("enterCommand", vec![Arg::Str(cmd.clone())]));
            se.call(&enter)?;
            let start = std::time::Instant::now();
            let mut after = before.clone();
            loop {
                std::thread::sleep(Duration::from_millis(poll_ms));
                let mut probe = base.clone();
                probe.push(("getOutput", vec![]));
                let cur = as_str(&se.call(&probe)?)?;
                let grew = cur.len() > after.len() && cur.starts_with(&after);
                after = cur;
                if grew && after != before {
                    let last_line = after
                        .lines()
                        .rev()
                        .find(|l| !l.trim().is_empty())
                        .unwrap_or("");
                    let t = last_line.trim_end();
                    if t.ends_with('>') || t.contains("C:\\") {
                        break;
                    }
                }
                if start.elapsed() >= Duration::from_millis(wait_ms) {
                    break;
                }
            }
            let output = if after.starts_with(&before) {
                after[before.len()..].trim_start_matches(['\r', '\n']).to_string()
            } else {
                let lines: Vec<&str> = after.lines().collect();
                lines[before.lines().count().min(lines.len())..].join("\n")
            };
            Ok(json!({"device": dev, "command": cmd, "output": output}))
        }),

        "cli_type" => with_session(args, |se| {
            let dev = req_str(args, "device")?;
            let cmd = req_str(args, "command")?;
            let wait_ms = opt_int(args, "wait_ms", 5_000).clamp(100, 120_000) as u64;
            let poll_ms = opt_int(args, "poll_ms", 250).clamp(50, 2_000) as u64;
            let r = console_exec(se, &dev, &cmd, wait_ms, poll_ms)?;
            Ok(json!({
                "device": dev,
                "typed": cmd,
                "woken": r.woken,
                "prompt_before": r.prompt0,
                "prompt_after": r.prompt1,
                "console_added": r.output,
                "status": r.status,
                "status_text": r.status_text,
                "timed_out": r.timed_out,
            }))
        }),

        "rename_device" => with_session(args, |se| {
            let old = req_str(args, "name")?;
            let new = req_str(args, "new_name")?;
            se.call(&by(&old, "setName", vec![Arg::QStr(new.clone())]))?;
            Ok(json!({"renamed": old, "to": new}))
        }),

        "list_ports" => with_session(args, |se| {
            let dev = req_str(args, "device")?;
            let names = port_names(se, &dev)?;
            let count = names.len();
            let ports: Vec<Value> = names
                .into_iter()
                .enumerate()
                .map(|(i, n)| json!({"index": i, "name": n}))
                .collect();
            Ok(json!({"device": dev, "count": count, "ports": ports}))
        }),

        "add_module" => with_session(args, |se| {
            let dev = req_str(args, "device")?;
            let module = req_str(args, "module")?;
            let slot = req_int(args, "slot")?;
            let added = as_bool(&se.call(&[
                ("network", vec![]),
                ("getDevice", vec![Arg::QStr(dev.clone())]),
                ("getRootModule", vec![]),
                ("addModuleAt", vec![Arg::Str(module.clone()), Arg::Int(slot)]),
            ])?)?;
            let ports = port_names(se, &dev)?;
            Ok(json!({
                "device": dev,
                "module": module,
                "slot": slot,
                "added": added,
                "ports": ports,
            }))
        }),

        "port_config" => with_session(args, |se| {
            let dev = req_str(args, "device")?;
            let port = req_str(args, "port")?;
            let ip = se
                .call(&on_port(&dev, &port, "getIpAddress", vec![]))
                .unwrap_or(Value::Null);
            let mask = se
                .call(&on_port(&dev, &port, "getSubnetMask", vec![]))
                .unwrap_or(Value::Null);
            let dhcp = se
                .call(&on_port(&dev, &port, "isDhcpClientOn", vec![]))
                .ok()
                .and_then(|v| v.as_bool());
            let up = se
                .call(&on_port(&dev, &port, "isPortUp", vec![]))
                .ok()
                .and_then(|v| v.as_bool());
            let power = se
                .call(&on_port(&dev, &port, "getPower", vec![]))
                .ok()
                .and_then(|v| v.as_bool());
            let proto = se
                .call(&on_port(&dev, &port, "isProtocolUp", vec![]))
                .ok()
                .and_then(|v| v.as_bool());
            let gateway = se
                .call(&[
                    ("network", vec![]),
                    ("getDevice", vec![Arg::QStr(dev.clone())]),
                    ("getProcess", vec![Arg::Str("HostIpProcess".into())]),
                    ("getDefaultGateway", vec![]),
                ])
                .unwrap_or(Value::Null);
            Ok(json!({
                "device": dev,
                "port": port,
                "ip": ip,
                "subnet_mask": mask,
                "gateway": gateway,
                "dhcp": dhcp,
                "power": power,
                "link_up": up,
                "protocol_up": proto,
            }))
        }),

        "auto_connect" => with_session(args, |se| {
            let d1 = req_str(args, "device1")?;
            let d2 = req_str(args, "device2")?;
            let ok = as_bool(&se.call(&[
                ("appWindow", vec![]),
                ("getActiveWorkspace", vec![]),
                ("getLogicalWorkspace", vec![]),
                (
                    "autoConnectDevices",
                    vec![Arg::QStr(d1.clone()), Arg::QStr(d2.clone())],
                ),
            ])?)?;
            std::thread::sleep(Duration::from_millis(500));
            let l1 = live_ports(se, &d1)?;
            let l2 = live_ports(se, &d2)?;
            Ok(json!({
                "connected": ok,
                "device1": d1,
                "device2": d2,
                "device1_live_ports": l1,
                "device2_live_ports": l2,
            }))
        }),

        "set_port_power" => with_session(args, |se| {
            let dev = req_str(args, "device")?;
            let port = req_str(args, "port")?;
            let power = opt_bool(args, "power", true);
            se.call(&on_port(&dev, &port, "setPower", vec![Arg::Bool(power)]))?;
            Ok(json!({"device": dev, "port": port, "power": power}))
        }),

        "set_port_ip" => with_session(args, |se| {
            let dev = req_str(args, "device")?;
            let port = req_str(args, "port")?;
            let ip = req_str(args, "ip")?;
            let mask = req_str(args, "subnet_mask")?;
            let dhcp = opt_bool(args, "dhcp", false);
            if !dhcp {
                req_ipv4(args, "ip")?;
                req_ipv4(args, "subnet_mask")?;
            }
            se.call(&on_port(&dev, &port, "setDhcpClientFlag", vec![Arg::Bool(dhcp)]))?;
            if !dhcp {
                se.call(&on_port(
                    &dev,
                    &port,
                    "setIpSubnetMask",
                    vec![Arg::Ip(ip.clone()), Arg::Ip(mask.clone())],
                ))?;
            }
            let mut out = json!({
                "device": dev.clone(),
                "port": port.clone(),
                "ip": if dhcp { Value::Null } else { json!(ip) },
                "subnet_mask": if dhcp { Value::Null } else { json!(mask) },
                "dhcp": dhcp,
            });
            if let Some(gw) = args.get("gateway").and_then(|v| v.as_str()) {
                req_ipv4(args, "gateway")?;
                se.call(&on_port(&dev, &port, "setDefaultGateway", vec![Arg::Ip(gw.to_string())]))?;
                out["gateway"] = json!(gw);
            }
            Ok(out)
        }),

        "create_link" => with_session(args, |se| {
            let d1 = req_str(args, "device1")?;
            let p1 = req_str(args, "port1")?;
            let d2 = req_str(args, "device2")?;
            let p2 = req_str(args, "port2")?;
            // Auto cable type when not given: like-for-like device pairs (pc-pc,
            // switch-switch, ...) are crossover 8101, mixed pairs straight 8100.
            // The old fixed 8100 default produced dead pc-pc links.
            let ctype = match args.get("connect_type").and_then(|v| v.as_i64()) {
                Some(c) => c as i32,
                None => {
                    let t1 = se.call(&by(&d1, "getType", vec![])).ok().and_then(|v| v.as_i64());
                    let t2 = se.call(&by(&d2, "getType", vec![])).ok().and_then(|v| v.as_i64());
                    match (t1, t2) {
                        (Some(a), Some(b)) if a == b => 8101,
                        _ => 8100,
                    }
                }
            };
            let ctype_given = args.get("connect_type").is_some();
            let ok = as_bool(&se.call(&[
                ("appWindow", vec![]),
                ("getActiveWorkspace", vec![]),
                ("getLogicalWorkspace", vec![]),
                (
                    "createLink",
                    vec![
                        Arg::QStr(d1.clone()),
                        Arg::Str(p1.clone()),
                        Arg::QStr(d2.clone()),
                        Arg::Str(p2.clone()),
                        Arg::Int(ctype),
                    ],
                ),
            ])?)?;
            if !ok {
                return Err(
                    "createLink returned false - check port names (list_ports) and that neither port is already linked"
                        .to_string(),
                );
            }
            std::thread::sleep(Duration::from_millis(300));
            let u1 = se
                .call(&on_port(&d1, &p1, "isProtocolUp", vec![]))
                .ok()
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let u2 = se
                .call(&on_port(&d2, &p2, "isProtocolUp", vec![]))
                .ok()
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let live = u1 && u2;
            let mut out = json!({
                "linked": true,
                "link": format!("{}.{} <-> {}.{}", d1, p1, d2, p2),
                "connect_type": ctype,
                "connect_type_name": connect_type_name(ctype),
                "connect_type_auto": !ctype_given,
                "protocol_up_1": u1,
                "protocol_up_2": u2,
                "live": live,
            });
            if !live {
                out["hint"] = json!("a port came up down - wrong connect_type for this pair? like-for-like pairs need 8101 (cross); mixed pairs 8100 (straight); also check set_port_power");
            }
            Ok(out)
        }),

        "delete_link" => with_session(args, |se| {
            let dev = req_str(args, "device")?;
            let port = req_str(args, "port")?;
            let ok = as_bool(&se.call(&[
                ("appWindow", vec![]),
                ("getActiveWorkspace", vec![]),
                ("getLogicalWorkspace", vec![]),
                ("deleteLink", vec![Arg::QStr(dev.clone()), Arg::Str(port.clone())]),
            ])?)?;
            if !ok {
                return Err(format!("deleteLink({}.{}) returned false", dev, port));
            }
            Ok(json!({"deleted": format!("{}.{}", dev, port)}))
        }),

        "get_link_count" => with_session(args, |se| {
            as_int(&se.call(&[("network", vec![]), ("getLinkCount", vec![])])?).map(|c| json!(c))
        }),

        "enter_command" => with_session(args, |se| {
            let dev = req_str(args, "device")?;
            let cmd = req_str(args, "command")?;
            let wait_ms = opt_int(args, "wait_ms", 5_000).clamp(100, 120_000) as u64;
            let poll_ms = opt_int(args, "poll_ms", 250).clamp(50, 2_000) as u64;
            let r = console_exec(se, &dev, &cmd, wait_ms, poll_ms)?;
            Ok(json!({
                "device": dev,
                "command": cmd,
                "status": r.status,
                "status_text": r.status_text,
                "prompt_before": r.prompt0,
                "prompt_after": r.prompt1,
                "output": r.output,
                "timed_out": r.timed_out,
            }))
        }),

        "skip_boot" => with_session(args, |se| {
            let dev = req_str(args, "device")?;
            let base = vec![
                ("network", vec![]),
                ("getDevice", vec![Arg::QStr(dev.clone())]),
                ("getCommandLine", vec![]),
            ];
            let mut wake = base.clone();
            wake.push(("enterCommand", vec![Arg::Str(String::new())]));
            se.call(&wake).ok();
            std::thread::sleep(Duration::from_millis(300));
            let mut probe = base.clone();
            probe.push(("getOutput", vec![]));
            let out = se
                .call(&probe)?
                .as_str()
                .unwrap_or("")
                .to_string();
            if out.contains("[yes/no]") {
                let mut answer = base.clone();
                answer.push(("enterCommand", vec![Arg::Str("no".into())]));
                se.call(&answer)?;
                std::thread::sleep(Duration::from_millis(400));
            }
            se.call(&by(&dev, "skipBoot", vec![]))?;
            Ok(json!({"device": dev, "skipped": true}))
        }),

        "add_note" => with_session(args, |se| {
            let x = req_int(args, "x")?;
            let y = req_int(args, "y")?;
            let zoom = opt_num(args, "zoom", 100.0);
            let text = req_str(args, "text")?;
            let v = se.call(&[
                ("appWindow", vec![]),
                ("getActiveWorkspace", vec![]),
                ("getLogicalWorkspace", vec![]),
                (
                    "addNote",
                    vec![Arg::Int(x), Arg::Int(y), Arg::Double(zoom), Arg::QStr(text)],
                ),
            ])?;
            if let Some(id) = v.as_str() {
                NOTE_POS
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(id.to_string(), (x as f64, y as f64));
            }
            Ok(json!({"note_id": v, "x": x, "y": y, "coords_source": "bridge-tracked"}))
        }),

        "list_notes" => with_session(args, |se| {
            let ids = se.call(&[
                ("appWindow", vec![]),
                ("getActiveWorkspace", vec![]),
                ("getLogicalWorkspace", vec![]),
                ("getCanvasNoteIds", vec![]),
            ])?;
            let arr = ids.as_array().cloned().unwrap_or_default();
            let pos_map = NOTE_POS.lock().unwrap_or_else(|e| e.into_inner());
            let mut notes = Vec::new();
            for id in arr {
                let Some(id) = id.as_str() else { continue };
                let text = se.call(&[
                    ("appWindow", vec![]),
                    ("getActiveWorkspace", vec![]),
                    ("getLogicalWorkspace", vec![]),
                    ("getCanvasNoteText", vec![Arg::Uuid(id.to_string())]),
                ])?;
                let (x, y) = match pos_map.get(id) {
                    Some(&(x, y)) => (json!(x), json!(y)),
                    None => (Value::Null, Value::Null),
                };
                notes.push(json!({"id": id, "text": text, "x": x, "y": y}));
            }
            drop(pos_map);
            Ok(json!({
                "count": notes.len(),
                "coords_source": "bridge-tracked: x/y filled for notes placed via add_note; null for GUI-placed notes (PT IPC exposes no position getter)",
                "notes": notes
            }))
        }),

        "change_note" => with_session(args, |se| {
            let id = req_uuid(args, "id")?;
            let text = req_str(args, "text")?;
            se.call(&[
                ("appWindow", vec![]),
                ("getActiveWorkspace", vec![]),
                ("getLogicalWorkspace", vec![]),
                (
                    "changeNoteText",
                    vec![Arg::Uuid(id.clone()), Arg::QStr(text.clone())],
                ),
            ])?;
            Ok(json!({"changed": id, "text": text}))
        }),

        "remove_note" => with_session(args, |se| {
            let id = req_uuid(args, "id")?;
            se.call(&[
                ("appWindow", vec![]),
                ("getActiveWorkspace", vec![]),
                ("getLogicalWorkspace", vec![]),
                ("removeCanvasItem", vec![Arg::Uuid(id.clone())]),
            ])?;
            NOTE_POS
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&id);
            Ok(json!({"removed": id}))
        }),

        "file_save_as" => with_session(args, |se| {
            let path = req_str(args, "path")?;
            se.call(&[
                ("appWindow", vec![]),
                ("fileSaveAs", vec![Arg::QStr(path.clone())]),
            ])?;
            std::thread::sleep(Duration::from_millis(500));
            let actual = if std::path::Path::new(&path).exists() {
                path.clone()
            } else {
                let alt = format!("{}.pkt", path);
                if std::path::Path::new(&alt).exists() {
                    alt
                } else {
                    path.clone()
                }
            };
            let exists = std::path::Path::new(&actual).exists();
            if exists {
                let mut st = file_state_lock();
                st.path = Some(actual.clone());
                st.dirty = Some(false);
            }
            Ok(json!({"saved": actual, "exists": exists, "note": "PT appends .pkt unless the path already ends in it"}))
        }),

        "file_open" => {
            let path = req_str(args, "path")?;
            let force = args.get("force").and_then(|v| v.as_bool()).unwrap_or(false);
            guard_unsaved("file_open", force)?;
            let out = with_session(args, |se| {
                se.call(&[
                    ("appWindow", vec![]),
                    ("fileOpen", vec![Arg::QStr(path.clone())]),
                ])?;
                Ok(json!({"opened": path.clone()}))
            })?;
            {
                let mut st = file_state_lock();
                st.path = Some(path.clone());
                st.dirty = Some(false);
            }
            Ok(out)
        }

        "file_status" => with_session(args, |se| {
            let path = match se.call(&[
                ("appWindow", vec![]),
                ("getActiveFile", vec![]),
                ("getSavedFilename", vec![]),
            ]) {
                Ok(v) => as_str(&v)
                    .ok()
                    .map(|s| s.replace("//", "/"))
                    .filter(|s| !s.trim().is_empty()),
                Err(_) => None,
            };
            let count = as_int(&se.call(&[("network", vec![]), ("getDeviceCount", vec![])])?)?;
            let mut st = file_state_lock();
            if st.path.is_none() {
                st.path = path.clone();
            }
            let st_dirty = st.dirty;
            let st_path = st.path.clone();
            drop(st);
            Ok(json!({
                "file": path,
                "device_count": count,
                "workspace_empty": count == 0,
                "dirty": st_dirty,
                "tracked_path": st_path,
                "dirty_note": "bridge-tracked: true after any mutating MCP call since last open/save; null = fresh bridge (unknown); edits made directly in the PT GUI are not detected"
            }))
        }),

        "clear_workspace" => {
            let force = args.get("force").and_then(|v| v.as_bool()).unwrap_or(false);
            guard_unsaved("clear_workspace", force)?;
            let out = with_session(args, |se| {
            let count = as_int(&se.call(&[("network", vec![]), ("getDeviceCount", vec![])])?)?;
            let mut removed = 0;
            let mut failed = Vec::new();
            for _ in 0..count {
                let name_v = se.call(&at(0, "getName", vec![]))?;
                if name_v.is_null() {
                    break;
                }
                let name = as_str(&name_v)?;
                match as_bool(&se.call(&[
                    ("appWindow", vec![]),
                    ("getActiveWorkspace", vec![]),
                    ("getLogicalWorkspace", vec![]),
                    ("removeDevice", vec![Arg::QStr(name.clone())]),
                ])?) {
                    Ok(true) => removed += 1,
                    Ok(false) => failed.push(format!("{}: returned false", name)),
                    Err(e) => failed.push(format!("{}: {}", name, e)),
                }
            }
            Ok(json!({"removed": removed, "failed": failed}))
            })?;
            file_state_lock().dirty = Some(true);
            Ok(out)
        }

        "list_links" => {
            let filter = args
                .get("device")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let port = match args.get("instance").and_then(|v| v.as_i64()) {
                Some(v) if v > 0 => v as u16,
                _ => resolve_port()?,
            };
            let count_v = with_session(args, |se| {
                se.call(&[("network", vec![]), ("getLinkCount", vec![])])
            })?;
            let count = as_int(&count_v)?;
            let (tx, rx) = mpsc::channel::<Option<(i32, Value)>>();
            std::thread::scope(|scope| {
                for chunk in (0..count).collect::<Vec<i32>>().chunks(8) {
                    let chunk = chunk.to_vec();
                    let tx = tx.clone();
                    scope.spawn(move || {
                        for i in chunk {
                            if tx.send(query_link(port, i)).is_err() {
                                break;
                            }
                        }
                    });
                }
                drop(tx);
                let mut collected: HashMap<i32, Value> = HashMap::new();
                for item in rx {
                    if let Some((idx, v)) = item {
                        collected.insert(idx, v);
                    }
                }
                let mut links = Vec::new();
                let mut skipped = 0;
                for i in 0..count {
                    let Some(v) = collected.remove(&i) else {
                        continue;
                    };
                    if let Some(f) = filter.as_deref() {
                        let n1 = v.get("device1").and_then(|x| x.as_str());
                        let n2 = v.get("device2").and_then(|x| x.as_str());
                        if n1 != Some(f) && n2 != Some(f) {
                            skipped += 1;
                            continue;
                        }
                    }
                    links.push(v);
                }
                Ok(json!({
                    "count": count,
                    "returned": links.len(),
                    "skipped_by_filter": skipped,
                    "links": links,
                }))
            })
        },

        "list_modules" => with_session(args, |se| {
            let dev = req_str(args, "device")?;
            let mut sc = by(&dev, "getRootModule", vec![]);
            sc.push(("getSlotCount", vec![]));
            let slot_count = as_int(&se.call(&sc)?).unwrap_or(0);
            let mut mc = by(&dev, "getRootModule", vec![]);
            mc.push(("getModuleCount", vec![]));
            let module_count = as_int(&se.call(&mc)?).unwrap_or(0);
            let mut slots = Vec::new();
            for i in 0..slot_count {
                let mut st = by(&dev, "getRootModule", vec![]);
                st.push(("getSlotTypeAt", vec![Arg::Int(i)]));
                let slot_type = se.call(&st).ok().and_then(|v| v.as_i64());
                let mut md = by(&dev, "getRootModule", vec![]);
                md.push(("getModuleAt", vec![Arg::Int(i)]));
                md.push(("getDescriptor", vec![]));
                md.push(("getModel", vec![]));
                let model = se
                    .call(&md)
                    .ok()
                    .and_then(|v| v.as_str().map(str::to_string))
                    .unwrap_or_default();
                let installed = !model.is_empty();
                slots.push(json!({
                    "slot": i,
                    "slot_type": slot_type,
                    "installed": installed,
                    "model": if installed { json!(model) } else { Value::Null },
                }));
            }
            Ok(json!({
                "device": dev,
                "slot_count": slot_count,
                "module_count": module_count,
                "slots": slots,
            }))
        }),

        "remove_module" => with_session(args, |se| {
            let dev = req_str(args, "device")?;
            let slot = req_int(args, "slot")?;
            let mut before = by(&dev, "getRootModule", vec![]);
            before.push(("getModuleAt", vec![Arg::Int(slot)]));
            before.push(("getDescriptor", vec![]));
            before.push(("getModel", vec![]));
            let before_model = se
                .call(&before)
                .ok()
                .and_then(|v| v.as_str().map(str::to_string))
                .unwrap_or_default();
            if before_model.is_empty() {
                let ports = port_names(se, &dev)?;
                return Ok(json!({
                    "device": dev,
                    "slot": slot,
                    "removed": false,
                    "already_empty": true,
                    "ports": ports,
                }));
            }
            let mut rm = by(&dev, "getRootModule", vec![]);
            rm.push(("removeModuleAt", vec![Arg::Int(slot)]));
            se.call(&rm)?;
            let mut after = by(&dev, "getRootModule", vec![]);
            after.push(("getModuleAt", vec![Arg::Int(slot)]));
            after.push(("getDescriptor", vec![]));
            after.push(("getModel", vec![]));
            let after_model = se
                .call(&after)
                .ok()
                .and_then(|v| v.as_str().map(str::to_string))
                .unwrap_or_default();
            let ports = port_names(se, &dev)?;
            Ok(json!({
                "device": dev,
                "slot": slot,
                "removed": after_model != before_model,
                "was": before_model,
                "ports": ports,
            }))
        }),

        "move_device" => with_session(args, |se| {
            let name = req_str(args, "name")?;
            let x = req_int(args, "x")?;
            let y = req_int(args, "y")?;
            let moved = as_bool(&se.call(&by(
                &name,
                "moveToLocation",
                vec![Arg::Int(x), Arg::Int(y)],
            ))?)?;
            let rx = se.call(&by(&name, "getXCoordinate", vec![]))?;
            let ry = se.call(&by(&name, "getYCoordinate", vec![]))?;
            Ok(json!({
                "device": name,
                "moved": moved,
                "x": rx,
                "y": ry,
            }))
        }),

        "wait_for_prompt" => with_session(args, |se| {
            let dev = req_str(args, "device")?;
            let pattern = req_str(args, "pattern")?;
            let timeout_ms = opt_int(args, "timeout_ms", 10_000).clamp(100, 120_000) as u64;
            let poll_ms = opt_int(args, "poll_ms", 250).clamp(50, 5_000) as u64;
            let start = std::time::Instant::now();
            let deadline = start + Duration::from_millis(timeout_ms);
            let mut attempts = 0u32;
            loop {
                attempts += 1;
                let text = se
                    .call(&[
                        ("network", vec![]),
                        ("getDevice", vec![Arg::QStr(dev.clone())]),
                        ("getCommandLine", vec![]),
                        ("getOutput", vec![]),
                    ])
                    .ok()
                    .and_then(|v| v.as_str().map(str::to_string))
                    .unwrap_or_default();
                let last = text
                    .lines()
                    .rev()
                    .find(|l| !l.trim().is_empty())
                    .unwrap_or("");
                let elapsed = start.elapsed().as_millis() as u64;
                if last.contains(&pattern) {
                    return Ok(json!({
                        "device": dev,
                        "matched": true,
                        "line": last.trim_end(),
                        "attempts": attempts,
                        "elapsed_ms": elapsed,
                    }));
                }
                if std::time::Instant::now() >= deadline {
                    let lines: Vec<&str> = text
                        .lines()
                        .filter(|l| !l.trim().is_empty())
                        .collect();
                    let tail: Vec<String> = lines
                        .iter()
                        .rev()
                        .take(5)
                        .rev()
                        .map(|s| s.to_string())
                        .collect();
                    return Ok(json!({
                        "device": dev,
                        "matched": false,
                        "pattern": pattern,
                        "attempts": attempts,
                        "elapsed_ms": elapsed,
                        "tail": tail,
                    }));
                }
                std::thread::sleep(Duration::from_millis(poll_ms));
            }
        }),

        "instances" => {
            let ports = discover_ports(PT_PORT_MAX);
            let mut known = KNOWN_PORTS.lock().unwrap_or_else(|e| e.into_inner());
            for p in &ports {
                if known.insert(*p) {
                    notify(
                        "info",
                        json!({"event": "instance_discovered", "port": p}),
                    );
                }
            }
            drop(known);
            let sel = SELECTED_PORT.load(Ordering::SeqCst);
            let mut list = Vec::new();
            for p in &ports {
                let mut se = session_connect(*p, false)?;
                let ver = se
                    .call(&[("appWindow", vec![]), ("getVersion", vec![])])
                    .ok()
                    .and_then(|v| v.as_str().map(str::to_string));
                let devs = se
                    .call(&[("network", vec![]), ("getDeviceCount", vec![])])
                    .ok()
                    .and_then(|v| v.as_i64());
                list.push(json!({"port": p, "version": ver, "device_count": devs}));
            }
            Ok(json!({
                "instances": list,
                "selected": if sel == 0 { Value::Null } else { json!(sel) },
                "note": "PT binds 39000, 39001, ... per instance. select_instance(port) pins tools to one; 0 = auto (first live)."
            }))
        }

        "select_instance" => {
            let port = req_int(args, "port")?;
            let pinned = if port <= 0 { 0 } else { port as u16 };
            SELECTED_PORT.store(pinned, Ordering::SeqCst);
            Ok(json!({
                "selected": if pinned == 0 { Value::Null } else { json!(pinned) },
                "mode": if pinned == 0 { "auto" } else { "pinned" },
            }))
        }

        other => Err(format!("unknown tool {}", other)),
    }
}

fn tools() -> Value {
    json!([
        {
            "name": "batch",
            "description": "Run multiple ptbridge tools in ONE call, sequentially, in order. Each op is {\"tool\": name, \"args\": {...}} - args are identical to calling the tool directly. Stops at first error unless stop_on_error=false (then errors are recorded and execution continues). Use this to add N devices / set N IPs / connect N links without N separate MCP round-trips. Nested batch not allowed. Results: per-op {i, tool, ok, result|error, code on error}. Errors and error texts carry a [code] prefix (list_error_codes).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "ops": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "tool": {"type": "string"},
                                "args": {"type": "object"}
                            },
                            "required": ["tool"]
                        },
                        "minItems": 1,
                        "maxItems": 200
                    },
                    "stop_on_error": {"type": "boolean", "default": true, "description": "false = record error and continue with remaining ops"},
                    "timeout_ms": {"type": "integer", "default": 120000, "description": "per-op budget; 0 = unlimited. On timeout/panic the op is abandoned, its error recorded, and the pooled session recycled so the next op reconnects fresh"},
                    "instance": {"type": "integer", "description": "PT listener port, inherited by every op that does not set its own"}
                },
                "required": ["ops"]
            }
        },
        {
            "name": "list_types",
            "description": "DeviceType enum (0-51) plus model strings verified live per type. Call before add_device.",
            "inputSchema": {"type": "object", "properties": {}, "required": []}
        },
        {
            "name": "list_error_codes",
            "description": "All ptbridge error codes with meaning and retryable flag. Every error text is prefixed [code]; batch results carry the code as its own field.",
            "inputSchema": {"type": "object", "properties": {}, "required": []}
        },
        {
            "name": "get_version",
            "description": "Packet Tracer version string (session health check).",
            "inputSchema": {"type": "object", "properties": {}, "required": []}
        },
        {
            "name": "list_devices",
            "description": "All devices in the logical workspace with name, model, type, coordinates.",
            "inputSchema": {"type": "object", "properties": {}, "required": []}
        },
        {
            "name": "get_device",
            "description": "Details for one device by name, including port count.",
            "inputSchema": {
                "type": "object",
                "properties": {"name": {"type": "string", "description": "device name, e.g. Router0"}},
                "required": ["name"]
            }
        },
        {
            "name": "add_device",
            "description": "Place a device. type is DeviceType enum, model is e.g. Router-PT / Switch-PT / PC-PT. Returns created name. Switches/routers make PT auto-spawn a Power Distribution Device companion; it is removed automatically unless keep_companion=true (tracked pairs are also taken with the device by remove_device).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "type": {"type": "integer", "enum": DEVICE_TYPES.iter().map(|(k, _)| json!(k)).collect::<Vec<Value>>(),
                             "description": "see list_types for names: 0=Router 1=Switch 8=PC 9=Server 16=MultiLayerSwitch 18=Laptop ... 45=PowerDistributionDevice"},
                    "model": {"type": "string", "description": "e.g. Router-PT, Switch-PT, PC-PT"},
                    "x": {"type": "number"},
                    "y": {"type": "number"},
                    "name": {"type": "string", "description": "optional: rename the device right after adding (must be unique)"},
                    "keep_companion": {"type": "boolean", "default": false, "description": "true = keep PT's auto-spawned Power Distribution Device instead of removing it"}
                },
                "required": ["type", "model", "x", "y"]
            }
        },
        {
            "name": "remove_device",
            "description": "Remove a device by exact name. Fails if the name does not match. If the device's Power Distribution Device companion was tracked at add time, it is removed too (companion_removed in the result).",
            "inputSchema": {
                "type": "object",
                "properties": {"name": {"type": "string"}},
                "required": ["name"]
            }
        },
        {
            "name": "pc_command",
            "description": "Type a command into a PC/Server/Laptop Desktop Command Prompt and return its full output. Polls the console until the C:\\> prompt reappears (command finished) or wait_ms expires - no more truncated ping output. Raise wait_ms for traceroute.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "device": {"type": "string"},
                    "command": {"type": "string"},
                    "wait_ms": {"type": "integer", "default": 15000, "description": "1000..120000 total budget"},
                    "poll_ms": {"type": "integer", "default": 300, "description": "100..2000 console poll interval"}
                },
                "required": ["device", "command"]
            }
        },
        {
            "name": "cli_type",
            "description": "Type a command into the device console like a human typing in the GUI CLI tab (echo + output land in the visible console). Auto-wakes an idle console, then polls until the prompt returns as the last idle line (command finished - any prompt shape, incl. mode changes like enable) or wait_ms expires. Returns console delta, IOS status markers, and timed_out flag.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "device": {"type": "string"},
                    "command": {"type": "string", "description": "empty string sends RETURN"},
                    "wait_ms": {"type": "integer", "default": 5000, "description": "100..120000 total budget until prompt returns"},
                    "poll_ms": {"type": "integer", "default": 250, "description": "50..2000 console poll interval"}
                },
                "required": ["device", "command"]
            }
        },
        {
            "name": "cli_output",
            "description": "Raw console text of a device CLI tab (same buffer the GUI shows), optional tail of N lines.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "device": {"type": "string"},
                    "tail": {"type": "integer", "default": 60, "description": "0 = full buffer"}
                },
                "required": ["device"]
            }
        },
        {
            "name": "cli_prompt",
            "description": "Current CLI prompt string of a device (e.g. Router-Utama(config-if)#). Falls back to the last console output line when PT's prompt field is empty - all CLI tools (enter_command, cli_type, pc_command) share one console channel.",
            "inputSchema": {
                "type": "object",
                "properties": {"device": {"type": "string"}},
                "required": ["device"]
            }
        },
        {
            "name": "rename_device",
            "description": "Rename a device (e.g. PC3 -> PC-A). Name must be unique.",
            "inputSchema": {
                "type": "object",
                "properties": {"name": {"type": "string"}, "new_name": {"type": "string"}},
                "required": ["name", "new_name"]
            }
        },
        {
            "name": "list_ports",
            "description": "Port names of a device, in index order. Enumerates until the device runs out (getPortCount can be stale after adding modules).",
            "inputSchema": {
                "type": "object",
                "properties": {"device": {"type": "string"}},
                "required": ["device"]
            }
        },
        {
            "name": "add_module",
            "description": "Install a hardware module into a router slot (Module::addModuleAt). On a fresh 2811: module 'NM-2E2W', slot 1 adds Ethernet1/0 and Ethernet1/1 (slot 0 rejects it). Returns the new port list.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "device": {"type": "string"},
                    "module": {"type": "string", "description": "model string, e.g. NM-2E2W"},
                    "slot": {"type": "integer", "description": "slot index (0-based)"}
                },
                "required": ["device", "module", "slot"]
            }
        },
        {
            "name": "port_config",
            "description": "Read IP/subnet/default gateway/DHCP/link state of one port (gateway comes from HostIpProcess, host devices only - null on routers/switches).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "device": {"type": "string"},
                    "port": {"type": "string", "description": "e.g. FastEthernet0 or FastEthernet0/0"}
                },
                "required": ["device", "port"]
            }
        },
        {
            "name": "set_port_power",
            "description": "Turn a port NIC on/off (Port::setPower). PC ports are off by default until powered - link stays down otherwise.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "device": {"type": "string"},
                    "port": {"type": "string"},
                    "power": {"type": "boolean", "default": true}
                },
                "required": ["device", "port"]
            }
        },
        {
            "name": "set_port_ip",
            "description": "Set static IPv4 + subnet mask on a port, optional default gateway.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "device": {"type": "string"},
                    "port": {"type": "string"},
                    "ip": {"type": "string", "description": "dotted quad"},
                    "subnet_mask": {"type": "string", "description": "dotted quad"},
                    "gateway": {"type": "string"},
                    "dhcp": {"type": "boolean", "default": false, "description": "false = manual/static (default when ip given), true = obtain via DHCP (ip/mask ignored)"}
                },
                "required": ["device", "port", "ip", "subnet_mask"]
            }
        },
        {
            "name": "auto_connect",
            "description": "PT's own auto-connect: picks suitable free ports on both devices and makes a LIVE link (protocol up). Prefer this over create_link, which draws a cable but leaves the link dead.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "device1": {"type": "string"},
                    "device2": {"type": "string"}
                },
                "required": ["device1", "device2"]
            }
        },
        {
            "name": "create_link",
            "description": "Draw a cable between two named ports. connect_type defaults to auto: like-for-like device pairs (pc-pc, switch-switch) get 8101 crossover, mixed pairs 8100 straight - the old fixed-8100 default is what left pc-pc links dead. Result reports live/protocol_up per port with a hint when a port comes up down.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "device1": {"type": "string"},
                    "port1": {"type": "string"},
                    "device2": {"type": "string"},
                    "port2": {"type": "string"},
                    "connect_type": {"type": "integer", "enum": CONNECT_TYPES.iter().map(|(k, _)| json!(k)).collect::<Vec<Value>>(),
                                     "description": "omit = auto (like-for-like -> 8101 cross, mixed -> 8100 straight). 8100 straight, 8101 crossover, 8103 fiber, 8106 serial, 8108 console, 8109 wireless"}
                },
                "required": ["device1", "port1", "device2", "port2"]
            }
        },
        {
            "name": "delete_link",
            "description": "Remove the link attached to a device port.",
            "inputSchema": {
                "type": "object",
                "properties": {"device": {"type": "string"}, "port": {"type": "string"}},
                "required": ["device", "port"]
            }
        },
        {
            "name": "get_link_count",
            "description": "Number of links in the workspace.",
            "inputSchema": {"type": "object", "properties": {}, "required": []}
        },
        {
            "name": "enter_command",
            "description": "Type a command into the device console (same channel as cli_type, state persists between calls). Polls until the prompt returns (command finished) or wait_ms expires - no more truncated output on slow commands. Status is derived from IOS console markers: % Invalid input / % Ambiguous / % Incomplete. Returns status, prompt before/after, console delta, and timed_out flag.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "device": {"type": "string"},
                    "command": {"type": "string"},
                    "wait_ms": {"type": "integer", "default": 5000, "description": "100..120000 budget until prompt returns"},
                    "poll_ms": {"type": "integer", "default": 250, "description": "50..2000 console poll interval"}
                },
                "required": ["device", "command"]
            }
        },
        {
            "name": "skip_boot",
            "description": "Skip the boot sequence of a device so commands run immediately.",
            "inputSchema": {
                "type": "object",
                "properties": {"device": {"type": "string"}},
                "required": ["device"]
            }
        },
        {
            "name": "add_note",
            "description": "Place a text note on the workspace canvas. Returns note_id plus the placed x/y (bridge-tracked coordinates).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "x": {"type": "integer"},
                    "y": {"type": "integer"},
                    "zoom": {"type": "number", "default": 100},
                    "text": {"type": "string"}
                },
                "required": ["x", "y", "text"]
            }
        },
        {
            "name": "list_notes",
            "description": "Canvas notes with id, text and x/y. Coordinates are bridge-tracked (filled for notes placed via add_note); null for GUI-placed notes because PT's IPC exposes no position getter.",
            "inputSchema": {"type": "object", "properties": {}, "required": []}
        },
        {
            "name": "change_note",
            "description": "Replace the text of an existing canvas note.",
            "inputSchema": {
                "type": "object",
                "properties": {"id": {"type": "string"}, "text": {"type": "string"}},
                "required": ["id", "text"]
            }
        },
        {
            "name": "remove_note",
            "description": "Delete a canvas note by id (from list_notes / add_note).",
            "inputSchema": {
                "type": "object",
                "properties": {"id": {"type": "string"}},
                "required": ["id"]
            }
        },
        {
            "name": "file_status",
            "description": "Workspace/file state: which .pkt is open (live from PT IPC), device count, and dirty flag (bridge-tracked: true after any mutating MCP call since last open/save, null = fresh bridge). Check this before file_open/clear_workspace - destructive calls are blocked while dirty unless force=true.",
            "inputSchema": {"type": "object", "properties": {}, "required": []}
        },
        {
            "name": "file_save_as",
            "description": "Save the current workspace to a .pka/.pkt path (overwrites existing file).",
            "inputSchema": {
                "type": "object",
                "properties": {"path": {"type": "string", "description": "absolute Windows path"}},
                "required": ["path"]
            }
        },
        {
            "name": "file_open",
            "description": "Open a workspace file, replacing the current topology. BLOCKED with an error while the workspace has unsaved changes (check file_status) unless force=true - force discards them.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "absolute Windows path"},
                    "force": {"type": "boolean", "default": false, "description": "discard unsaved changes"}
                },
                "required": ["path"]
            }
        },
        {
            "name": "clear_workspace",
            "description": "Remove every device (leaves links/notes; run before a fresh topology). BLOCKED with an error while the workspace has unsaved changes (check file_status) unless force=true.",
            "inputSchema": {
                "type": "object",
                "properties": {"force": {"type": "boolean", "default": false, "description": "discard unsaved changes"}},
                "required": []
            }
        },
        {
            "name": "list_links",
            "description": "Every cable in the workspace: both device/port endpoints, cable type, and per-side protocol state. Queried in parallel (up to 8 links at once, own connection per link) - much faster than sequential IPC chains. Optional device filter returns only links touching it.",
            "inputSchema": {
                "type": "object",
                "properties": {"device": {"type": "string", "description": "optional: only links attached to this device"}},
                "required": []
            }
        },
        {
            "name": "list_modules",
            "description": "Hardware slots of a device: per-slot type and installed module model (Module::getSlotTypeAt + getModuleAt().getDescriptor().getModel()). Empty slots show installed=false, model=null.",
            "inputSchema": {
                "type": "object",
                "properties": {"device": {"type": "string"}},
                "required": ["device"]
            }
        },
        {
            "name": "remove_module",
            "description": "Remove the module installed in a slot (Module::removeModuleAt). Returns the port list after removal so you can see the ports disappear. already_empty=true if nothing was in the slot.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "device": {"type": "string"},
                    "slot": {"type": "integer", "description": "slot index (0-based), see list_modules"}
                },
                "required": ["device", "slot"]
            }
        },
        {
            "name": "move_device",
            "description": "Move a device to canvas coordinates (Device::moveToLocation) and read back the resulting position.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "x": {"type": "integer"},
                    "y": {"type": "integer"}
                },
                "required": ["name", "x", "y"]
            }
        },
        {
            "name": "wait_for_prompt",
            "description": "Poll a device console until its last non-empty line contains the pattern (plain substring, e.g. '#' or 'Router-Bab2(config)#' or '[yes/no]'), or the timeout expires. Returns matched=false plus the last output lines on timeout - pair with cli_type/enter_command to sync on prompt boundaries.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "device": {"type": "string"},
                    "pattern": {"type": "string", "description": "substring that must appear in the current prompt line"},
                    "timeout_ms": {"type": "integer", "default": 10000, "description": "100..120000"},
                    "poll_ms": {"type": "integer", "default": 250, "description": "50..5000 poll interval"}
                },
                "required": ["device", "pattern"]
            }
        },
        {
            "name": "instances",
            "description": "List live Packet Tracer instances (one listener port each, 39000+). Tools follow select_instance, or the first live instance in auto mode.",
            "inputSchema": {"type": "object", "properties": {}, "required": []}
        },
        {
            "name": "select_instance",
            "description": "Pin all subsequent tools to one PT instance port (e.g. 39001). port=0 restores auto (first live instance).",
            "inputSchema": {
                "type": "object",
                "properties": {"port": {"type": "integer", "description": "39000 = first instance, 39001 = second, ... 0 = auto"}},
                "required": ["port"]
            }
        }
    ])
}

fn reply(id: Option<&Value>, result: Option<Value>, error: Option<Value>) -> String {
    let mut msg = json!({"jsonrpc": "2.0"});
    match id {
        Some(v) => msg["id"] = v.clone(),
        None => msg["id"] = Value::Null,
    }
    if let Some(r) = result {
        msg["result"] = r;
    }
    if let Some(e) = error {
        msg["error"] = e;
    }
    msg.to_string()
}

fn handle(msg: &Value) -> Option<String> {
    let method = msg.get("method")?.as_str()?.to_string();
    let id = msg.get("id");
    let params = msg.get("params").cloned().unwrap_or(json!({}));

    match method.as_str() {
        "initialize" => {
            let version = params
                .get("protocolVersion")
                .and_then(|v| v.as_str())
                .unwrap_or("2024-11-05")
                .to_string();
            Some(reply(
                id,
                Some(json!({
                    "protocolVersion": version,
                    "capabilities": {
                        "tools": {"listChanged": false},
                        "logging": {}
                    },
                    "serverInfo": {"name": "ptmcp", "version": "0.1.0"}
                })),
                None,
            ))
        }
        "tools/list" => Some(reply(id, Some(json!({"tools": tools()})), None)),
        "tools/call" => {
            let name = params
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let args = params.get("arguments").cloned().unwrap_or(json!({}));
            match run_tool(&name, &args) {
                Ok(v) => {
                    let text = if v.is_string() {
                        v.as_str().unwrap().to_string()
                    } else {
                        v.to_string()
                    };
                    Some(reply(
                        id,
                        Some(json!({"content": [{"type": "text", "text": text}], "isError": false})),
                        None,
                    ))
                }
                Err(e) => Some(reply(
                    id,
                    Some(json!({"content": [{"type": "text", "text": with_code(&e)}], "isError": true})),
                    None,
                )),
            }
        }
        "ping" => Some(reply(id, Some(json!({})), None)),
        m if m.starts_with("notifications/") => None,
        other if id.is_some() => Some(reply(
            id,
            None,
            Some(json!({"code": -32601, "message": format!("method not found: {}", other)})),
        )),
        _ => None,
    }
}

#[cfg(windows)]
mod watchdog {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::ptr::null;

    use windows_sys::Win32::Foundation::{
        CloseHandle, GetLastError, ERROR_ALREADY_EXISTS, HANDLE, WAIT_ABANDONED, WAIT_OBJECT_0,
    };
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };
    use windows_sys::Win32::System::Threading::{
        CreateEventW, CreateMutexW, GetCurrentProcessId, OpenEventW, SetEvent, WaitForSingleObject,
        EVENT_MODIFY_STATE, INFINITE,
    };

    const INVALID_HANDLE_VALUE: isize = -1;
    const ACQUIRE_TIMEOUT_MS: u32 = 5000;

    fn wide(name: &str) -> Vec<u16> {
        let mut v: Vec<u16> = OsStr::new(name).encode_wide().collect();
        v.push(0);
        v
    }

    fn parent_pid() -> Option<u32> {
        unsafe {
            let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if snap == INVALID_HANDLE_VALUE as HANDLE {
                return None;
            }
            let mut entry: PROCESSENTRY32W = std::mem::zeroed();
            entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
            let cur = GetCurrentProcessId();
            let mut found = None;
            if Process32FirstW(snap, &mut entry) != 0 {
                loop {
                    if entry.th32ProcessID == cur {
                        found = Some(entry.th32ParentProcessID);
                        break;
                    }
                    if Process32NextW(snap, &mut entry) == 0 {
                        break;
                    }
                }
            }
            CloseHandle(snap);
            found
        }
    }

    pub fn install() {
        let Some(ppid) = parent_pid() else {
            return;
        };
        let mutex_name = format!("ptmcp.watch.{}", ppid);
        let kick_name = format!("ptmcp.kick.{}", ppid);
        let mutex_w = wide(&mutex_name);
        let kick_w = wide(&kick_name);

        for _ in 0..5 {
            unsafe {
                let mutex = CreateMutexW(null(), 0, mutex_w.as_ptr());
                if mutex.is_null() {
                    return;
                }
                let err = GetLastError();
                if err != ERROR_ALREADY_EXISTS {
                    install_waiter(kick_w.as_ptr());
                    let _ = mutex;
                    return;
                }
                let kick = OpenEventW(EVENT_MODIFY_STATE, 0, kick_w.as_ptr());
                if !kick.is_null() {
                    SetEvent(kick);
                    CloseHandle(kick);
                }
                let r = WaitForSingleObject(mutex, ACQUIRE_TIMEOUT_MS);
                CloseHandle(mutex);
                if r == WAIT_OBJECT_0 || r == WAIT_ABANDONED {
                    continue;
                }
                return;
            }
        }
    }

    fn install_waiter(kick_name: *const u16) {
        unsafe {
            let ev = CreateEventW(null(), 0, 0, kick_name);
            if ev.is_null() {
                return;
            }
            let ev_bits = ev as usize;
            std::thread::spawn(move || {
                let ev = ev_bits as HANDLE;
                let r = WaitForSingleObject(ev, INFINITE);
                if r == WAIT_OBJECT_0 {
                    std::process::exit(0);
                }
            });
        }
    }
}

fn main() {
    #[cfg(windows)]
    watchdog::install();
    if let Ok(v) = std::env::var("PTMCP_PORT") {
        if let Ok(p) = v.parse::<u16>() {
            SELECTED_PORT.store(p, Ordering::SeqCst);
        }
    }
    // Notification writer: receives notifications/message lines and writes them
    // to stdout under the stdout lock, so they can stream mid-request without
    // interleaving into a partial response line.
    let (ntx, nrx) = mpsc::channel::<String>();
    *NOTIF_TX.lock().unwrap_or_else(|e| e.into_inner()) = Some(ntx);
    std::thread::spawn(move || {
        for line in nrx {
            let mut o = std::io::stdout().lock();
            let _ = writeln!(o, "{}", line);
            let _ = o.flush();
        }
    });
    let stdin = std::io::stdin();
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        if line.trim().is_empty() {
            continue;
        }
        let msg: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                let r = reply(
                    None,
                    None,
                    Some(json!({"code": -32700, "message": format!("parse error: {}", e)})),
                );
                let mut o = std::io::stdout().lock();
                let _ = writeln!(o, "{}", r);
                let _ = o.flush();
                continue;
            }
        };
        if let Some(r) = handle(&msg) {
            let mut o = std::io::stdout().lock();
            let _ = writeln!(o, "{}", r);
            let _ = o.flush();
        }
    }
}
