# Router: per-app internet selector for Windows

[![CI](https://github.com/kylehesi/app-router/actions/workflows/ci.yml/badge.svg)](https://github.com/kylehesi/app-router/actions/workflows/ci.yml)

Router keeps several internet connections up at the same time (built-in Wi-Fi, a USB Wi-Fi
dongle, USB tethering from a phone, Ethernet...) and lets you choose which one each
application uses.

> **Hardware requirement:** every internet connection needs its own network adapter. A single
> Wi-Fi card can only join one network at a time.

## Architecture

```
+----------------+  named pipe (JSON)  +----------------------------------------------+
| router-ui      | <-----------------> | router-service  (Windows service, SYSTEM)    |
| Slint, Rust    |                     |  - ipc    : talks to the UI                  |
| normal user    |                     |  - rules  : exe -> adapter GUID rules        |
+----------------+                     |  - engine : TUN + routing                    |
                                       +----------------------------------------------+
```

| Crate | Purpose |
|---|---|
| `crates/common` | Shared types and the IPC protocol |
| `crates/sys` | Windows APIs: adapters + SSID, processes, socket->PID tables, interface address/MTU/routes, firewall rule, privileges, policy |
| `crates/engine` | Wintun TUN, packet parsing and rewriting, TCP NAT, UDP sessions, interface-bound sockets (`IP_UNICAST_IF`) |
| `crates/service` | Background service + diagnostic commands |
| `crates/ui` | Desktop UI |

### How routing works

- A Wintun TUN adapter is created at `198.18.0.1/30`. This is the RFC 2544 benchmarking range,
  so it does not clash with home or office networks.
- Routes `0.0.0.0/1` and `128.0.0.0/1` send IPv4 traffic into the TUN. They are more specific
  than the default route, so the real default routes stay untouched. `2000::/3` covers IPv6.
- **TCP** uses "system stack" NAT: packets are rewritten in place (with incremental checksum
  updates) and handed to a local listener in Windows' own TCP stack. Windows keeps handling
  windowing and congestion control; the service only relays bytes to the chosen adapter.
- **UDP** gets one interface-bound socket per application port (full cone), so games, QUIC and
  STUN work.
- For every new connection: socket -> PID -> exe -> rule -> adapter.
- Outbound sockets are pinned to their adapter with `IP_UNICAST_IF`, so they never loop back
  into the TUN.
- The TUN MTU is 9000.
- **Failover:** the service listens for Windows network change notifications. When an adapter
  stops being usable (unplugged, disconnected, lost its IPv4 gateway), every TCP connection on
  it is reset with RST and every UDP session on it is closed. Apps reconnect right away and the
  new connections follow the rule's fallback instead of hanging on a dead link. A UDP session
  also ends as soon as sending through its adapter fails.
- **IPv6 is not carried yet.** Internet IPv6 is still routed into the TUN and TCP attempts are
  rejected with RST, so applications fall back to IPv4 and rules cannot be bypassed over IPv6.
- If the service stops or crashes, the routes and the TUN disappear and networking returns to
  normal.

### Why this design

- **No driver signing needed:** Wintun is signed by WireGuard and shipped next to the exe.
- **Rust:** C/C++ speed without garbage collector pauses, plus memory safety.
- **Statically linked CRT** (`crt-static`): no VC++ Redistributable to install.

## Download

Tagged versions are built by CI and published on the
[Releases](https://github.com/kylehesi/app-router/releases) page as
`router-windows-x64.zip` (`router-service.exe`, `router-ui.exe`, `wintun.dll`, `Router.bat`).
Extract it anywhere and double-click `Router.bat`.

## Continuous integration

Every push and pull request runs `cargo fmt --check`, `cargo clippy -D warnings`, the tests
and a release build on Windows. Pushing a tag such as `v0.2.0` also publishes a release.

## Requirements

- Windows 10/11 x64
- Visual Studio 2022 Build Tools (C++ and Windows SDK)
- Rust (stable, MSVC)

> **Note:** Windows Smart App Control can block build scripts (`os error 4551`). It must be
> turned off on the development machine.

## Building

```powershell
cargo build --release
powershell -ExecutionPolicy Bypass -File scripts\fetch-wintun.ps1
```

`fetch-wintun.ps1` downloads Wintun 0.14.1 from wintun.net, verifies its WireGuard LLC
Authenticode signature and copies `wintun.dll` into `target\debug` and `target\release`.

## Running

The easiest way is to double-click `Router.bat`. It asks for administrator rights and shows a
menu to:

- start routing + the UI
- run the engine test (optionally with a specific adapter)
- list adapters
- show the public IP through a given adapter
- list applications using the network
- run the system check (doctor)
- add the firewall rule

Or manually, from an administrator terminal (in `target\release`):

```powershell
router-service firewall        # once
router-service run --engine
router-ui
```

Press Ctrl+C in the service window to stop routing; normal networking is restored right away.

Permanent install:

```powershell
router-service install         # auto-start, restart on crash, policy + firewall rule
router-service uninstall
```

`install` also sets the policy that allows simultaneous connections
(`fMinimizeConnections=0`) and adds the firewall rule.

## Diagnostic commands

```powershell
router-service adapters                  # adapters, SSIDs, IPs, gateways
router-service apps                      # applications using the network
router-service probe "<adapter>"         # public IP through this adapter
router-service doctor                    # is the system ready?
router-service tun-test                  # does Wintun work? (administrator)
router-service engine-test ["<adapter>"] # end-to-end engine test (administrator)
router-service watch                     # show adapters becoming available/unavailable live
```

`engine-test` routes only a few test addresses into the TUN and checks TCP, UDP/DNS, IPv6
rejection and failover (an open connection is reset when its adapter is marked unavailable)
end to end; all other traffic is left untouched.

## Files

- Rules: `%ProgramData%\Router\rules.json`
- Service log: `%ProgramData%\Router\service.log`

## Firewall rule

The `Router TUN` rule allows inbound TCP only from `198.18.0.2` to `198.18.0.1`. It is needed
because TCP is relayed through a local listener.

## Known limitations

- IPv4 only. IPv6 is rejected as described above. On Windows a rejected IPv6 connect takes
  about 2 s because Windows retries the SYN, but address ordering makes applications prefer
  IPv4 anyway.
- Fragmented IPv4 packets are dropped.
- Rule changes apply to new connections only.
- Unsigned exes may be blocked by Smart App Control on end-user machines (Authenticode signing
  is planned).

## Roadmap

- [x] **Phase 1, skeleton:** adapter and SSID list, application list, rule storage, IPC, Windows
      service, UI, interface-bound sockets, Wintun
- [x] **Phase 2, data path:** TUN routes, TCP "system stack" NAT, UDP sessions, socket->process
      lookup, IPv6 leak protection, end-to-end engine test
- [ ] **Phase 3:** full IPv6, tray icon, failover when an adapter drops, per-adapter speed
      graph, child processes inheriting rules, socket->process lookup cache, MSI installer +
      code signing
