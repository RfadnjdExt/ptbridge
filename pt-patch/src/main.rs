// language: Rust, file: pt-patch/src/main.rs, target: Windows 11
// Unified binary patcher PacketTracer 9.0.1.858: login skip + multi-user question + canvas rev4.
// std only, no deps.
// Login: call 0x142494CB0 @0x14249AEB3 -> mov al,1;nop;nop;nop. Return value feeds [rsp+0xBA]
// which gates the CNetspaceLogin ctor; al=1 reproduces the true-return register state exactly.
// Quest: memo guard @0x1424431F9 ("Would you like to run multi-user...") -> store memo=0
// (identical to clicking No) + jmp tail@0x1424432B9; function never blocks the main thread.
// Canvas: jae@0x14264c70e (pristine -> 0x14264c9e7) retargeted to cave@0x142602620 (rev4 blob,
// rip-relative, ASLR-safe), restore-site 9e7 kept pristine, rejoin 0x14264c9e9.
// Every site pattern-guarded: pristine -> patch, already -> skip, foreign -> abort. Idempotent.
use std::env;
use std::fs;
use std::path::Path;
use std::process::exit;

const IMAGEBASE: u64 = 0x1_4000_0000;

const LOGIN_VA: u64 = 0x14249AEB3;
const LOGIN_ORIG: [u8; 5] = [0xE8, 0xF8, 0x9D, 0xFF, 0xFF];
const LOGIN_PATCHED: [u8; 5] = [0xB0, 0x01, 0x90, 0x90, 0x90];
const LOGIN_TARGET: u64 = 0x142494CB0;

const QUEST_VA: u64 = 0x1424431F9;
const QUEST_ORIG: [u8; 15] = [
    0x8B, 0x05, 0x85, 0xED, 0x38, 0x01, // mov eax, [0x1437D1F84]
    0x83, 0xF8, 0xFF,                   // cmp eax, -1
    0x0F, 0x85, 0xB1, 0x00, 0x00, 0x00, // jne 0x1424432B9
];
const QUEST_PATCHED: [u8; 15] = [
    0xC7, 0x05, 0x81, 0xED, 0x38, 0x01, 0x00, 0x00, 0x00, 0x00, // mov dword [0x1437D1F84], 0
    0xE9, 0xB1, 0x00, 0x00, 0x00,                               // jmp 0x1424432B9
];
const QUEST_MEMO_VA: u64 = 0x1437D1F84;
const QUEST_TAIL_VA: u64 = 0x1424432B9;

const HIJACK_VA: u64 = 0x14264C70E;
const HIJACK_LEN: usize = 6;
const RESTORE_VA: u64 = 0x14264C9E7;
const RESTORE_ORIG: [u8; 5] = [0x32, 0xC0, 0x48, 0x8B, 0x9C];
const REJOIN_VA: u64 = 0x14264C9E9;
const CAVE_VA: u64 = 0x142602620;
const FIND_VA: u64 = 0x1426320B0;
const LOOKUP_VA: u64 = 0x1427B6591;

const CAVE_HEX: &str = concat!(
    "4883ec504889f24889f9e881fa02004885c00f841d0100004889c3488b03ff5050",
    "3d4e0400000f843c0000003d590400000f844b0000003d530400000f845a000000",
    "3d520400000f84690000003d580400000f84780000003d510400000f8487000000",
    "e9cd0000004c8d0d512e1d014c8d054a2d1d014c8d15a3e50100e9820000004c8d",
    "0d57141e014c8d05302d1d014c8d15f9a60400e9680000004c8d0d6d2d1d014c8d",
    "05162d1d014c8d156fe30100e94e0000004c8d0dc3071e014c8d05fc2c1d014c8d",
    "1585e40100e9340000004c8d0d612d1d014c8d05e22c1d014c8d154be60100e91a",
    "0000004c8d0df72c1d014c8d05c82c1d014c8d1561e70100e900000000c7442420",
    "000000004c8954242831d24889d9e8563e1b004885c00f84110000004889f94889",
    "c2ff542428b001e90200000031c04883c450e989a20400"
);

struct Section {
    vsize: u32,
    va: u32,
    raw_size: u32,
    raw_ptr: u32,
}

fn die(msg: &str) -> ! {
    eprintln!("{}", msg);
    exit(1);
}

fn hex_to_bytes(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn rel32(site_va: u64, target_va: u64, instr_len: u64) -> [u8; 4] {
    let disp = target_va as i64 - (site_va + instr_len) as i64;
    (disp as i32).to_le_bytes()
}

fn i32_at(b: &[u8], off: usize) -> i32 {
    i32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

fn u16_at(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([b[off], b[off + 1]])
}

fn u32_at(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

fn parse_sections(data: &[u8]) -> Result<Vec<Section>, String> {
    if data.len() < 0x40 || &data[0..2] != b"MZ" {
        return Err("not MZ".into());
    }
    let pe = u32_at(data, 0x3C) as usize;
    if pe + 24 > data.len() || &data[pe..pe + 4] != b"PE\0\0" {
        return Err("not PE".into());
    }
    let nsec = u16_at(data, pe + 6) as usize;
    let opt_size = u16_at(data, pe + 20) as usize;
    let opt = pe + 24;
    if opt + 2 > data.len() || u16_at(data, opt) != 0x20B {
        return Err("not PE32+".into());
    }
    let mut secs = Vec::with_capacity(nsec);
    let table = opt + opt_size;
    for i in 0..nsec {
        let s = table + i * 40;
        if s + 40 > data.len() {
            return Err("section table truncated".into());
        }
        secs.push(Section {
            vsize: u32_at(data, s + 8),
            va: u32_at(data, s + 12),
            raw_size: u32_at(data, s + 16),
            raw_ptr: u32_at(data, s + 20),
        });
    }
    Ok(secs)
}

fn rva_to_off(secs: &[Section], rva: u64) -> Result<usize, String> {
    let rva = rva as u32;
    for s in secs {
        let span = s.vsize.max(s.raw_size);
        if rva >= s.va && rva < s.va.saturating_add(span) {
            return Ok((s.raw_ptr + (rva - s.va)) as usize);
        }
    }
    Err(format!("rva {rva:#x} not in any section"))
}

fn verify_cave_self() -> Result<Vec<u8>, String> {
    let b = hex_to_bytes(CAVE_HEX);
    if b.len() != 320 {
        return Err(format!("cave len {}", b.len()));
    }
    if b[0..4] != [0x48, 0x83, 0xEC, 0x50] {
        return Err("cave head".into());
    }
    for (off, target) in [(10usize, FIND_VA), (278, LOOKUP_VA)] {
        if b[off] != 0xE8 {
            return Err(format!("cave call opcode @ {off}"));
        }
        let land = CAVE_VA + off as u64 + 5 + i32_at(&b, off + 1) as u64;
        if land != target {
            return Err(format!("cave call @ {off} -> {land:#x}, want {target:#x}"));
        }
    }
    if b[315] != 0xE9 {
        return Err("cave tail jmp".into());
    }
    let rejoin = CAVE_VA + 320 + i32_at(&b, 316) as u64;
    if rejoin != REJOIN_VA {
        return Err(format!("cave rejoin {rejoin:#x}, want {REJOIN_VA:#x}"));
    }
    Ok(b)
}

fn verify_quest_self() -> Result<(), String> {
    let p = &QUEST_PATCHED;
    if p[0] != 0xC7 || p[1] != 0x05 {
        return Err("quest patch: not rip-rel mov dword".into());
    }
    let store_next = QUEST_VA + 10;
    let store_tgt = store_next + i32_at(p, 2) as u64;
    if store_tgt != QUEST_MEMO_VA {
        return Err(format!("quest patch store -> {store_tgt:#x}, want {QUEST_MEMO_VA:#x}"));
    }
    if p[10] != 0xE9 {
        return Err("quest patch: no tail jmp".into());
    }
    let land = QUEST_VA + 15 + i32_at(p, 11) as u64;
    if land != QUEST_TAIL_VA {
        return Err(format!("quest patch jmp -> {land:#x}, want {QUEST_TAIL_VA:#x}"));
    }
    let o = &QUEST_ORIG;
    if o[9] != 0x0F || o[10] != 0x85 {
        return Err("quest orig: not jne".into());
    }
    let jne_land = QUEST_VA + 15 + i32_at(o, 11) as u64;
    if jne_land != QUEST_TAIL_VA {
        return Err(format!("quest orig jne -> {jne_land:#x}, want {QUEST_TAIL_VA:#x}"));
    }
    Ok(())
}

enum SiteState {
    Already,
    Patched,
}

fn patch_site(cur: &[u8], orig: &[u8], patched: &[u8], label: &str, dry: bool) -> SiteState {
    if cur == patched {
        println!("{label}: already patched");
        SiteState::Already
    } else if cur == orig {
        if !dry {
            println!("{label}: stub written");
        } else {
            println!("{label}: pristine (would patch)");
        }
        SiteState::Patched
    } else {
        die(&format!(
            "{label}: FOREIGN bytes {} — abort",
            cur.iter().map(|b| format!("{b:02x}")).collect::<String>()
        ));
    }
}

fn main() {
    let mut exe = r"C:\Program Files\Cisco Packet Tracer 9.0.1\bin\PacketTracer.exe".to_string();
    let mut dry = false;
    let mut args = env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--exe" => exe = args.next().expect("--exe PATH"),
            "--verify-only" => dry = true,
            other => die(&format!("unknown arg {other}")),
        }
    }

    let cave = match verify_cave_self() {
        Ok(c) => c,
        Err(e) => die(&format!("cave self-check FAILED: {e}")),
    };
    if let Err(e) = verify_quest_self() {
        die(&format!("quest self-check FAILED: {e}"));
    }

    let path = Path::new(&exe);
    if !path.is_file() {
        die(&format!("not found: {exe}"));
    }

    let bak = format!("{exe}.bak");
    if !dry && !Path::new(&bak).is_file() {
        fs::copy(path, &bak).unwrap_or_else(|e| die(&format!("backup failed: {e}")));
        println!("backup -> {bak}");
    }

    let mut data = fs::read(path).unwrap_or_else(|e| die(&format!("read: {e}")));
    let secs = parse_sections(&data).unwrap_or_else(|e| die(&format!("pe: {e}")));

    let off_login = rva_to_off(&secs, LOGIN_VA - IMAGEBASE).unwrap_or_else(|e| die(&e));
    let off_quest = rva_to_off(&secs, QUEST_VA - IMAGEBASE).unwrap_or_else(|e| die(&e));
    let off_hijack = rva_to_off(&secs, HIJACK_VA - IMAGEBASE).unwrap_or_else(|e| die(&e));
    let off_restore = rva_to_off(&secs, RESTORE_VA - IMAGEBASE).unwrap_or_else(|e| die(&e));
    let off_cave = rva_to_off(&secs, CAVE_VA - IMAGEBASE).unwrap_or_else(|e| die(&e));

    let mut changed = false;

    // login
    let cur = &data[off_login..off_login + 5];
    let login_state = patch_site(cur, &LOGIN_ORIG, &LOGIN_PATCHED, "login", dry);
    if matches!(login_state, SiteState::Patched) {
        let land = LOGIN_VA + 5 + i32_at(cur, 1) as u64;
        if land != LOGIN_TARGET {
            die(&format!(
                "login: rel32 target {land:#x} != expected {LOGIN_TARGET:#x}, abort"
            ));
        }
        if !dry {
            data[off_login..off_login + 5].copy_from_slice(&LOGIN_PATCHED);
        }
        changed = true;
    }

    // multi-user question (3-state, 15 bytes)
    let cur = &data[off_quest..off_quest + 15];
    let quest_state = patch_site(cur, &QUEST_ORIG, &QUEST_PATCHED, "quest", dry);
    if matches!(quest_state, SiteState::Patched) {
        if !dry {
            data[off_quest..off_quest + 15].copy_from_slice(&QUEST_PATCHED);
        }
        changed = true;
    }

    // canvas hijack (3-state)
    let cur = &data[off_hijack..off_hijack + HIJACK_LEN].to_vec();
    if cur[0] != 0x0F || cur[1] != 0x83 {
        die(&format!(
            "canvas: hijack bytes {} not jae, abort",
            cur.iter().map(|b| format!("{b:02x}")).collect::<String>()
        ));
    }
    let tgt = HIJACK_VA + HIJACK_LEN as u64 + i32_at(cur, 2) as u64;
    if tgt == CAVE_VA {
        println!("canvas: hijack already -> cave");
    } else if tgt == RESTORE_VA {
        println!("canvas: jae rel32 -> cave written (pristine fail-path 9e7)");
        if !dry {
            data[off_hijack + 2..off_hijack + 6].copy_from_slice(&rel32(HIJACK_VA, CAVE_VA, HIJACK_LEN as u64));
        }
        changed = true;
    } else {
        die(&format!(
            "canvas: jae targets {tgt:#x}, expected cave {CAVE_VA:#x} or pristine {RESTORE_VA:#x}, abort"
        ));
    }

    // restore-site
    if data[off_restore..off_restore + 5] != RESTORE_ORIG {
        println!("canvas: restore-site rewritten to pristine");
        if !dry {
            data[off_restore..off_restore + 5].copy_from_slice(&RESTORE_ORIG);
        }
        changed = true;
    } else {
        println!("canvas: restore-site pristine");
    }

    // cave
    if data[off_cave..off_cave + cave.len()] != cave[..] {
        changed = true;
    }
    println!("canvas: cave {} bytes @ {CAVE_VA:#x} (head {:02x}{:02x}{:02x}{:02x})",
        cave.len(), cave[0], cave[1], cave[2], cave[3]);
    if !dry {
        data[off_cave..off_cave + cave.len()].copy_from_slice(&cave);
    }

    if !dry && changed {
        fs::write(path, &data).unwrap_or_else(|e| die(&format!("write: {e}")));
    }

    // final verify from disk
    let disk = fs::read(path).unwrap_or_else(|e| die(&format!("reread: {e}")));
    let secs2 = parse_sections(&disk).unwrap_or_else(|e| die(&e));
    let ok_login = disk[rva_to_off(&secs2, LOGIN_VA - IMAGEBASE).unwrap()..][..5] == LOGIN_PATCHED;
    let q = rva_to_off(&secs2, QUEST_VA - IMAGEBASE).unwrap();
    let ok_quest = disk[q..q + 15] == QUEST_PATCHED;
    let h = rva_to_off(&secs2, HIJACK_VA - IMAGEBASE).unwrap();
    let ok_hijack = disk[h] == 0x0F
        && disk[h + 1] == 0x83
        && HIJACK_VA + HIJACK_LEN as u64 + i32_at(&disk, h + 2) as u64 == CAVE_VA;
    let r = rva_to_off(&secs2, RESTORE_VA - IMAGEBASE).unwrap();
    let ok_restore = disk[r..r + 5] == RESTORE_ORIG;
    let c = rva_to_off(&secs2, CAVE_VA - IMAGEBASE).unwrap();
    let ok_cave = disk[c..c + 4] == [0x48, 0x83, 0xEC, 0x50];

    println!(
        "final: login={} quest={} canvas-hijack={} restore={} cave-head={}",
        flag(ok_login), flag(ok_quest), flag(ok_hijack), flag(ok_restore), flag(ok_cave)
    );
    if !(ok_login && ok_quest && ok_hijack && ok_restore && ok_cave) {
        exit(1);
    }
    println!("ALL OK{}", if dry { " (verify-only)" } else { "" });
}

fn flag(b: bool) -> &'static str {
    if b { "OK" } else { "FAIL" }
}
