use std::io::{BufRead, Write};
use std::net::TcpStream;
use std::sync::Mutex;
use std::time::Duration;

use ptmp::*;
use serde_json::{json, Value};

const APP_ID: &str = "net.netacad.cisco.ptseplayer";
const SECRET: &str = "AjDi87dHAkda783HD";
const PT_PORT: u16 = 39000;

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
}

impl Session {
    fn connect() -> Result<Session, String> {
        let stream =
            TcpStream::connect(("127.0.0.1", PT_PORT)).map_err(|e| format!("connect: {}", e))?;
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .map_err(|e| format!("read timeout: {}", e))?;
        stream
            .set_write_timeout(Some(Duration::from_secs(30)))
            .map_err(|e| format!("write timeout: {}", e))?;
        let mut writer = stream.try_clone().map_err(|e| format!("clone: {}", e))?;
        let mut reader = std::io::BufReader::new(stream);
        let props = NegotiationProps::default();
        let nego = negotiate(&mut writer, &mut reader, &props)
            .map_err(|e| format!("negotiate: {}", e))?;
        let ok = authenticate(&mut writer, &mut reader, APP_ID, SECRET, nego.authentication)
            .map_err(|e| format!("authenticate: {}", e))?;
        if !ok {
            return Err("authentication rejected".into());
        }
        Ok(Session {
            writer,
            reader,
            msg_id: 0,
        })
    }

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
                *self = Session::connect()?;
                self.call_once(segs)
            }
            other => other,
        }
    }
}

static SESSION: Mutex<Option<Session>> = Mutex::new(None);

fn with_session<F>(f: F) -> Result<Value, String>
where
    F: FnOnce(&mut Session) -> Result<Value, String>,
{
    let mut guard = SESSION.lock().unwrap_or_else(|e| e.into_inner());
    if guard.is_none() {
        *guard = Some(Session::connect()?);
    }
    f(guard.as_mut().expect("session set"))
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
    v.as_bool().ok_or_else(|| format!("unexpected response: {}", v))
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

fn run_tool(name: &str, args: &Value) -> Result<Value, String> {
    match name {
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

        "get_version" => with_session(|se| {
            se.call(&[
                ("appWindow", vec![]),
                ("getVersion", vec![]),
            ])
        }),

        "list_devices" => with_session(|se| {
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

        "get_device" => with_session(|se| {
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

        "add_device" => with_session(|se| {
            let dtype = req_int(args, "type")?;
            let model = req_str(args, "model")?;
            let x = req_num(args, "x")?;
            let y = req_num(args, "y")?;
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
            Ok(json!({
                "name": name,
                "type": dtype,
                "type_name": device_type_name(dtype),
                "model": model,
                "note": "routers/switches also spawn a Power Distribution Device companion; use list_devices to see it",
            }))
        }),

        "remove_device" => with_session(|se| {
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
            Ok(json!({"removed": name}))
        }),

        "cli_output" => with_session(|se| {
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

        "cli_prompt" => with_session(|se| {
            let dev = req_str(args, "device")?;
            se.call(&[
                ("network", vec![]),
                ("getDevice", vec![Arg::QStr(dev.clone())]),
                ("getCommandLine", vec![]),
                ("getPrompt", vec![]),
            ])
        }),

        "pc_command" => with_session(|se| {
            let dev = req_str(args, "device")?;
            let cmd = req_str(args, "command")?;
            let wait_ms = opt_int(args, "wait_ms", 4000);
            let base = vec![
                ("network", vec![]),
                ("getDevice", vec![Arg::QStr(dev.clone())]),
                ("getCommandLine", vec![]),
            ];
            let mut segs = base.clone();
            segs.push(("getOutput", vec![]));
            let before = as_str(&se.call(&segs)?)?;
            let mut segs = base.clone();
            segs.push(("enterCommand", vec![Arg::Str(cmd.clone())]));
            se.call(&segs)?;
            std::thread::sleep(Duration::from_millis(
                u64::try_from(wait_ms.max(0)).unwrap_or(0),
            ));
            let mut segs = base;
            segs.push(("getOutput", vec![]));
            let after = as_str(&se.call(&segs)?)?;
            let output = if after.starts_with(&before) {
                after[before.len()..].trim_start_matches(['\r', '\n']).to_string()
            } else {
                after
            };
            Ok(json!({"device": dev, "command": cmd, "output": output}))
        }),

        "cli_type" => with_session(|se| {
            let dev = req_str(args, "device")?;
            let cmd = req_str(args, "command")?;
            let base = vec![
                ("network", vec![]),
                ("getDevice", vec![Arg::QStr(dev.clone())]),
                ("getCommandLine", vec![]),
            ];
            let mut probe = base.clone();
            probe.push(("getPrompt", vec![]));
            let prompt0 = se
                .call(&probe)?
                .as_str()
                .unwrap_or("")
                .to_string();
            let mut probe = base.clone();
            probe.push(("getOutput", vec![]));
            let before = se
                .call(&probe)?
                .as_str()
                .unwrap_or("")
                .to_string();

            let mut woken = false;
            if prompt0.is_empty() {
                let mut wake = base.clone();
                wake.push(("enterCommand", vec![Arg::Str(String::new())]));
                se.call(&wake)?;
                std::thread::sleep(Duration::from_millis(300));
                woken = true;
            }
            let mut enter = base.clone();
            enter.push(("enterCommand", vec![Arg::Str(cmd.clone())]));
            se.call(&enter)?;
            std::thread::sleep(Duration::from_millis(400));

            let mut probe = base.clone();
            probe.push(("getOutput", vec![]));
            let after = se
                .call(&probe)?
                .as_str()
                .unwrap_or("")
                .to_string();
            let mut probe = base;
            probe.push(("getPrompt", vec![]));
            let prompt1 = se
                .call(&probe)?
                .as_str()
                .unwrap_or("")
                .to_string();

            let added = if after.starts_with(&before) {
                after[before.len()..].trim_start_matches(['\r', '\n']).to_string()
            } else {
                let lines: Vec<&str> = after.lines().collect();
                lines[before.lines().count().min(lines.len())..].join("\n")
            };
            Ok(json!({
                "device": dev,
                "typed": cmd,
                "woken": woken,
                "prompt_before": prompt0,
                "prompt_after": prompt1,
                "console_added": added,
            }))
        }),

        "rename_device" => with_session(|se| {
            let old = req_str(args, "name")?;
            let new = req_str(args, "new_name")?;
            se.call(&by(&old, "setName", vec![Arg::QStr(new.clone())]))?;
            Ok(json!({"renamed": old, "to": new}))
        }),

        "list_ports" => with_session(|se| {
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

        "add_module" => with_session(|se| {
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

        "port_config" => with_session(|se| {
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

        "auto_connect" => with_session(|se| {
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

        "set_port_power" => with_session(|se| {
            let dev = req_str(args, "device")?;
            let port = req_str(args, "port")?;
            let power = opt_bool(args, "power", true);
            se.call(&on_port(&dev, &port, "setPower", vec![Arg::Bool(power)]))?;
            Ok(json!({"device": dev, "port": port, "power": power}))
        }),

        "set_port_ip" => with_session(|se| {
            let dev = req_str(args, "device")?;
            let port = req_str(args, "port")?;
            let ip = req_str(args, "ip")?;
            let mask = req_str(args, "subnet_mask")?;
            let dhcp = opt_bool(args, "dhcp", false);
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
                se.call(&on_port(&dev, &port, "setDefaultGateway", vec![Arg::Ip(gw.to_string())]))?;
                out["gateway"] = json!(gw);
            }
            Ok(out)
        }),

        "create_link" => with_session(|se| {
            let d1 = req_str(args, "device1")?;
            let p1 = req_str(args, "port1")?;
            let d2 = req_str(args, "device2")?;
            let p2 = req_str(args, "port2")?;
            let ctype = opt_int(args, "connect_type", 8100);
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
            Ok(json!({
                "linked": true,
                "link": format!("{}.{} <-> {}.{}", d1, p1, d2, p2),
                "connect_type": ctype,
            }))
        }),

        "delete_link" => with_session(|se| {
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

        "get_link_count" => with_session(|se| {
            as_int(&se.call(&[("network", vec![]), ("getLinkCount", vec![])])?).map(|c| json!(c))
        }),

        "enter_command" => with_session(|se| {
            let dev = req_str(args, "device")?;
            let cmd = req_str(args, "command")?;
            let mode = args
                .get("mode")
                .and_then(|v| v.as_str())
                .unwrap_or("enable")
                .to_string();
            let v = se.call(&by(
                &dev,
                "enterCommand",
                vec![Arg::Str(cmd.clone()), Arg::Str(mode)],
            ))?;
            let pair = v
                .as_array()
                .ok_or_else(|| format!("enterCommand returned non-pair: {}", v))?;
            let status = pair
                .first()
                .and_then(|x| x.as_i64())
                .ok_or_else(|| "enterCommand pair missing status".to_string())? as i32;
            let output = pair.get(1).cloned().unwrap_or(Value::Null);
            let status_text = match status {
                0 => "ok",
                1 => "ambiguous",
                2 => "invalid",
                3 => "incomplete",
                4 => "not_implemented",
                other => return Err(format!("unknown CommandStatus {}", other)),
            };
            Ok(json!({
                "device": dev,
                "command": cmd,
                "status": status,
                "status_text": status_text,
                "output": output,
            }))
        }),

        "skip_boot" => with_session(|se| {
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

        "add_note" => with_session(|se| {
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
            Ok(json!({"note_id": v}))
        }),

        "list_notes" => with_session(|se| {
            let ids = se.call(&[
                ("appWindow", vec![]),
                ("getActiveWorkspace", vec![]),
                ("getLogicalWorkspace", vec![]),
                ("getCanvasNoteIds", vec![]),
            ])?;
            let arr = ids.as_array().cloned().unwrap_or_default();
            let mut notes = Vec::new();
            for id in arr {
                let Some(id) = id.as_str() else { continue };
                let text = se.call(&[
                    ("appWindow", vec![]),
                    ("getActiveWorkspace", vec![]),
                    ("getLogicalWorkspace", vec![]),
                    ("getCanvasNoteText", vec![Arg::Uuid(id.to_string())]),
                ])?;
                notes.push(json!({"id": id, "text": text}));
            }
            Ok(json!({"count": notes.len(), "notes": notes}))
        }),

        "change_note" => with_session(|se| {
            let id = req_str(args, "id")?;
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

        "remove_note" => with_session(|se| {
            let id = req_str(args, "id")?;
            se.call(&[
                ("appWindow", vec![]),
                ("getActiveWorkspace", vec![]),
                ("getLogicalWorkspace", vec![]),
                ("removeCanvasItem", vec![Arg::Uuid(id.clone())]),
            ])?;
            Ok(json!({"removed": id}))
        }),

        "file_save_as" => with_session(|se| {
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
            Ok(json!({"saved": actual, "exists": exists, "note": "PT appends .pkt unless the path already ends in it"}))
        }),

        "file_open" => with_session(|se| {
            let path = req_str(args, "path")?;
            se.call(&[
                ("appWindow", vec![]),
                ("fileOpen", vec![Arg::QStr(path.clone())]),
            ])?;
            Ok(json!({"opened": path}))
        }),

        "clear_workspace" => with_session(|se| {
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
        }),

        "list_links" => with_session(|se| {
            let count = as_int(&se.call(&[("network", vec![]), ("getLinkCount", vec![])])?)?;
            let filter = args.get("device").and_then(|v| v.as_str()).map(|s| s.to_string());
            let mut links = Vec::new();
            let mut skipped = 0;
            for i in 0..count {
                let p1r = link_chain(i, &[("getPort1", vec![]), ("getName", vec![])]);
                let p2r = link_chain(i, &[("getPort2", vec![]), ("getName", vec![])]);
                let d1r = link_chain(
                    i,
                    &[
                        ("getPort1", vec![]),
                        ("getOwnerDevice", vec![]),
                        ("getName", vec![]),
                    ],
                );
                let d2r = link_chain(
                    i,
                    &[
                        ("getPort2", vec![]),
                        ("getOwnerDevice", vec![]),
                        ("getName", vec![]),
                    ],
                );
                let s1 = se.call(&p1r).ok().and_then(|v| v.as_str().map(str::to_string));
                let s2 = se.call(&p2r).ok().and_then(|v| v.as_str().map(str::to_string));
                let n1 = se.call(&d1r).ok().and_then(|v| v.as_str().map(str::to_string));
                let n2 = se.call(&d2r).ok().and_then(|v| v.as_str().map(str::to_string));
                if s1.is_none() && s2.is_none() {
                    continue;
                }
                if let Some(f) = filter.as_deref() {
                    if n1.as_deref() != Some(f) && n2.as_deref() != Some(f) {
                        skipped += 1;
                        continue;
                    }
                }
                let u1 = as_bool(
                    &se.call(&link_chain(i, &[("getPort1", vec![]), ("isProtocolUp", vec![])]))
                        .unwrap_or(Value::Bool(false)),
                )
                .unwrap_or(false);
                let u2 = as_bool(
                    &se.call(&link_chain(i, &[("getPort2", vec![]), ("isProtocolUp", vec![])]))
                        .unwrap_or(Value::Bool(false)),
                )
                .unwrap_or(false);
                let ct = se
                    .call(&link_chain(i, &[("getConnectionType", vec![])]))
                    .ok()
                    .and_then(|v| v.as_i64());
                links.push(json!({
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
                }));
            }
            Ok(json!({
                "count": count,
                "returned": links.len(),
                "skipped_by_filter": skipped,
                "links": links,
            }))
        }),

        "list_modules" => with_session(|se| {
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

        "remove_module" => with_session(|se| {
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

        "move_device" => with_session(|se| {
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

        "wait_for_prompt" => with_session(|se| {
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

        other => Err(format!("unknown tool {}", other)),
    }
}

fn tools() -> Value {
    json!([
        {
            "name": "list_types",
            "description": "DeviceType enum (0-51) plus model strings verified live per type. Call before add_device.",
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
            "description": "Place a device. type is DeviceType enum, model is e.g. Router-PT / Switch-PT / PC-PT. Returns created name.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "type": {"type": "integer", "enum": DEVICE_TYPES.iter().map(|(k, _)| json!(k)).collect::<Vec<Value>>(),
                             "description": "see list_types for names: 0=Router 1=Switch 8=PC 9=Server 16=MultiLayerSwitch 18=Laptop ... 45=PowerDistributionDevice"},
                    "model": {"type": "string", "description": "e.g. Router-PT, Switch-PT, PC-PT"},
                    "x": {"type": "number"},
                    "y": {"type": "number"},
                    "name": {"type": "string", "description": "optional: rename the device right after adding (must be unique)"}
                },
                "required": ["type", "model", "x", "y"]
            }
        },
        {
            "name": "remove_device",
            "description": "Remove a device by exact name. Fails if the name does not match.",
            "inputSchema": {
                "type": "object",
                "properties": {"name": {"type": "string"}},
                "required": ["name"]
            }
        },
        {
            "name": "pc_command",
            "description": "Type a command into a PC/Server/Laptop Desktop Command Prompt (Cisco Packet Tracer PC Command Line) and return its output. wait_ms default 4000 - raise it for ping/traceroute.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "device": {"type": "string"},
                    "command": {"type": "string"},
                    "wait_ms": {"type": "integer", "default": 4000}
                },
                "required": ["device", "command"]
            }
        },
        {
            "name": "cli_type",
            "description": "Type a command into the device console like a human typing in the GUI CLI tab (echo + output land in the visible console). Auto-wakes an idle console. Returns the console lines it produced.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "device": {"type": "string"},
                    "command": {"type": "string", "description": "empty string sends RETURN"}
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
            "description": "Current CLI prompt string of a device (e.g. Router-Utama(config-if)#).",
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
            "description": "Draw a cable between two named ports (connect_type default 8100 straight; Switch-PT Vlan1 rejects). Observed to leave the link dead (protocol down, lights off) - prefer auto_connect for working links.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "device1": {"type": "string"},
                    "port1": {"type": "string"},
                    "device2": {"type": "string"},
                    "port2": {"type": "string"},
                    "connect_type": {"type": "integer", "enum": CONNECT_TYPES.iter().map(|(k, _)| json!(k)).collect::<Vec<Value>>(),
                                     "description": "8100 straight, 8101 crossover, 8103 fiber, 8106 serial, 8108 console, 8109 wireless"}
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
            "description": "Run a CLI command on a device (mode: enable | global | config...). Returns status + raw output. Call skip_boot first on freshly added devices.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "device": {"type": "string"},
                    "command": {"type": "string"},
                    "mode": {"type": "string", "default": "enable"}
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
            "description": "Place a text note on the workspace canvas.",
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
            "description": "Canvas notes with id and text.",
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
            "description": "Open a workspace file, replacing the current topology (unsaved changes are lost).",
            "inputSchema": {
                "type": "object",
                "properties": {"path": {"type": "string", "description": "absolute Windows path"}},
                "required": ["path"]
            }
        },
        {
            "name": "clear_workspace",
            "description": "Remove every device (leaves links/notes; run before a fresh topology).",
            "inputSchema": {"type": "object", "properties": {}, "required": []}
        },
        {
            "name": "list_links",
            "description": "Every cable in the workspace: both device/port endpoints, cable type, and per-side protocol state. Optional device filter returns only links touching it.",
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
                    "capabilities": {"tools": {"listChanged": false}},
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
                    Some(json!({"content": [{"type": "text", "text": e}], "isError": true})),
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

fn main() {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
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
                let _ = writeln!(out, "{}", r);
                let _ = out.flush();
                continue;
            }
        };
        if let Some(r) = handle(&msg) {
            let _ = writeln!(out, "{}", r);
            let _ = out.flush();
        }
    }
}
