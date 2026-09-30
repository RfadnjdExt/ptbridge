# ptbridge

Local MCP server that turns a running Cisco Packet Tracer 9.0.0 session into tools: build topology, set addressing, cable devices, drive CLIs, read state, manage notes and files.

## Crates

| crate | role |
|---|---|
| `ptmp` | session wire codec |
| `ptmcp` | the MCP server, 34 tools over stdio JSON-RPC |

## Build

```
cargo build --release
cargo clippy --release
```

The server binary is `target/release/ptmcp.exe`. Release profile: `lto = true`, `codegen-units = 1`, `panic = "abort"`.

## Run

1. Start Packet Tracer and open the workspace first. The server attaches to the running app; do not kill or restart PT while it is attached.
2. Register the server as a local MCP entry pointing at `target/release/ptmcp.exe`.
3. Restart the client so the tool list reloads.

## Tools (34)

Topology: `list_types`, `get_version`, `list_devices`, `get_device`, `add_device`, `remove_device`, `rename_device`, `move_device`, `clear_workspace`

Ports and addressing: `list_ports`, `port_config`, `set_port_ip`, `set_port_power`

Modules: `add_module`, `list_modules`, `remove_module`

Cabling: `list_links`, `get_link_count`, `auto_connect`, `create_link`, `delete_link`

CLI: `enter_command`, `cli_type`, `cli_output`, `cli_prompt`, `skip_boot`, `wait_for_prompt`, `pc_command`

Notes and files: `add_note`, `list_notes`, `change_note`, `remove_note`, `file_save_as`, `file_open`

### Typical build order

1. `list_types` to check the DeviceType enum and verified model strings.
2. `add_device` for the router, switches, hosts.
3. `set_port_power` on host NICs before cabling, ports start down.
4. `auto_connect` to link pairs. It picks free ports and brings the link up.
5. `set_port_ip` per port, gateway optional and host scoped.
6. `skip_boot` on routers, then `cli_type` or `enter_command`.
7. `wait_for_prompt` to sync on prompt boundaries before the next command.
8. `list_links`, `port_config`, `pc_command` to verify.
9. `file_save_as` to save, path must end in `.pkt`.

## Behavior notes

- `getPortCount` reports stale numbers after `add_module`. `list_ports` enumerates ports until the first miss instead of trusting the count, so always use it for port names.
- A fresh 2811 boots into the initial configuration dialog and swallows typed commands. `skip_boot` wakes the console, answers `no`, then skips boot.
- `file_save_as` checks the disk for the real path: PT appends `.pkt` unless the path already ends in it. The reply reports the actual path.
- `auto_connect` creates a live link (protocol up). `create_link` draws a cable that stays down. Prefer `auto_connect` for anything you want to pass traffic on.
- The `gateway` field of `port_config` reads the device default gateway and is null on routers and switches.
- On a fresh 2811, `NM-2E2W` fits slot 1 only, slot 0 rejects it. `list_modules` shows installed state per slot, `remove_module` frees a slot and returns the port list so you can see the ports disappear.
- Adding a router spawns a Power Distribution Device companion that `remove_device` leaves behind. Sweep `list_devices` for it after temp tests.
- `wait_for_prompt` matches a plain substring against the current last line of console output, for example `#`, `Router0(config)#`, `[yes/no]`. On timeout it returns `matched` false plus the last lines instead of failing.

## Layout

```
ptbridge/
  Cargo.toml          workspace
  Cargo.lock
  ptmp/src/lib.rs
  ptmcp/src/main.rs
  README.md
```
