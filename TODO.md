# To-do

All planned improvements. Items are taken one at a time in the priority order below; the rest
will be ordered in later rounds.
Effort: **S** about a day, **M** a few days, **L** a week or more.

## Round 1 (priority order)

1. A2 — Instant failover when an adapter drops *(implemented; real unplug test pending)*
2. E4 — GitHub Actions CI *(done)*
3. A4 — Fast, exact socket -> process lookup *(done)*
4. A3 — "Connected but no internet" detection
5. A1 — Ping/tracert support
6. C6 — Priority list
7. A10 — Kill switch
8. C2 — Start/stop routing from the UI
9. E6 — Logging and diagnostics
10. D1 — Cleaner app list
11. A5 — Child/helper processes inherit rules
12. E1 — Installer (MSI)
13. E5 — Choose a license

## A. Reliability

- [ ] **A1 — Ping/tracert support** (M)
  ICMP is dropped in full mode, so `ping` and `tracert` don't work. Answer echo requests through
  the chosen adapter (e.g. `IcmpSendEcho2Ex`).
- [ ] **A2 — Instant failover when an adapter drops** (M)
  Replace the 3 s adapter polling with `NotifyIpInterfaceChange`; reset open connections on the
  lost adapter so apps reconnect over the fallback right away.
- [ ] **A3 — "Connected but no internet" detection** (M)
  Periodic health checks per adapter (captive portals, ISP outages); treat a failing adapter as
  unavailable.
- [x] **A4 — Fast, exact socket -> process lookup** (M-L)
  Every new connection used to scan the whole TCP table (about 5 ms with ~2000 sockets).
  Concurrent lookups now share scans and exe names are cached per process instance: 50
  simultaneous lookups take ~20 ms instead of ~245 ms, exe lookup 2 us instead of ~40 us.
  ETW was considered and rejected: its events are delivered in batches (up to about a second
  late), too late for a decision that has to be made when the connection opens.
- [ ] **A5 — Child/helper processes inherit rules** (M)
  Apps such as Chrome, Discord and Steam do their networking in helper exes
  (e.g. `steamwebhelper.exe`). Inherit the parent's rule or support app groups.
- [ ] **A6 — Apply rule now** (S)
  Option to close an app's open connections so a rule change takes effect immediately.
- [ ] **A7 — Per-app DNS** (L)
  DNS is always resolved through Windows' default connection, so an app pinned to another
  adapter may get CDN servers chosen for the wrong ISP. Resolve through the app's adapter.
- [ ] **A8 — Full IPv6 support** (L)
  Carry IPv6 through the TUN with NAT instead of rejecting it with RST.
- [ ] **A9 — Fragmented IPv4 packets** (S-M)
  Reassemble fragments instead of dropping them (large UDP datagrams from some games/VPNs).
- [ ] **A10 — Kill switch** (S)
  Expose the existing `Fallback::Block` in the UI: if the assigned connection is unavailable,
  the app gets no internet at all.

## B. Performance and technology

- [ ] **B1 — Benchmark tool** (S)
  Measure throughput, latency and CPU so optimizations are driven by numbers.
- [ ] **B2 — Event push instead of UI polling** (M)
  The UI makes the service scan every process and socket every 2 s; push changes instead.
- [ ] **B3 — Faster UDP (USO/URO)** (M)
  Use Windows 11 UDP segmentation/receive coalescing and batched I/O for QUIC and games.
- [ ] **B4 — Dependency updates** (S)
  Rust edition 2024, newer `windows-sys` and other crates.
- [ ] **B5 — ARM64 build** (S)
  Windows on ARM laptops; Wintun ships an ARM64 DLL.

## C. New features

- [ ] **C1 — System tray icon** (M)
  Run in the background, start with Windows, notify when a connection drops or comes back.
- [ ] **C2 — Start/stop routing from the UI** (M)
  One toggle and a visible engine status instead of an administrator terminal.
- [ ] **C3 — Mobile data quota** (M)
  Daily/monthly limit for the phone connection; warn or disable the adapter when reached.
- [ ] **C4 — Per-app traffic and speed** (M)
  Bytes per app per adapter and a live speed graph.
- [ ] **C5 — Load balancing** (M)
  Spread an app's connections across adapters so multi-connection downloads (Steam, torrents,
  download managers) use the combined bandwidth. Does not speed up a single connection.
- [ ] **C6 — Priority list** (S)
  Ordered fallbacks per app ("phone, else Wi-Fi, else Ethernet") instead of one adapter + fallback.
- [ ] **C7 — Profiles** (S)
  Rule sets such as "Home", "Away", "Gaming" with one-click switching.
- [ ] **C8 — Destination-based rules** (M)
  Rules by site, IP or port regardless of the app (e.g. all game servers through the phone).
- [ ] **C9 — Default for new apps** (S)
  Choose which connection apps without a rule use.
- [ ] **C10 — Wi-Fi management in the app** (M)
  Scan for and join networks with a second (USB) Wi-Fi adapter from the UI.
- [ ] **C11 — Rule import/export** (S)
  Back up rules or move them to another PC.
- [ ] **C12 — Localization infrastructure** (S)
  English base strings with translations (Slint `@tr()`), so a Turkish translation can be added.

## D. Design and usability

- [ ] **D1 — Cleaner app list** (S)
  Move system processes (`lsass`, `services.exe`, ...) to a separate section; add search and
  sorting by name or traffic.
- [ ] **D2 — Icons and real names** (S-M)
  Show the app icon and "Google Chrome" instead of `chrome.exe`.
- [ ] **D3 — Rules for apps that aren't running** (S)
  Pick an exe with a file dialog and create the rule in advance.
- [ ] **D4 — Colored adapter cards** (M)
  A color per connection, live speed and data used on the cards; the same color on app rows.
- [ ] **D5 — First-run wizard** (M)
  Run the `doctor` checks in the UI (firewall rule, simultaneous connections policy, two
  connections) with one-click fixes.
- [ ] **D6 — Windows 11 look** (S)
  Follow the system light/dark theme, Mica background, app icon.

## E. Distribution and infrastructure

- [ ] **E1 — Installer (MSI)** (M)
  Installs the service, firewall rule, policy and Start menu shortcut; cleans everything up on
  uninstall. Replaces `Router.bat` for end users.
- [ ] **E2 — Code signing** (S + cost)
  Authenticode signing so Smart App Control and SmartScreen don't block the app (not the same as
  driver signing; low-cost monthly options exist).
- [ ] **E3 — Auto-update** (M)
  New versions from GitHub Releases.
- [x] **E4 — GitHub Actions CI** (S)
  Build, clippy and tests on every push; release binaries on tags.
- [ ] **E5 — Choose a license** (S)
  The repo is public but has no license, which legally means "all rights reserved".
- [ ] **E6 — Logging and diagnostics** (S)
  Rotating log files, log viewer in the UI, crash reports.
- [ ] **E7 — Automated end-to-end tests** (M)
  Engine tests that run automatically on every change.
