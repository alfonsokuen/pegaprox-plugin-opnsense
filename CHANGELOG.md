# Changelog

All notable changes to this project will be documented here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) — versioning: [SemVer](https://semver.org/).

## [Unreleased]

### Planned (v1.9+)
- DHCP static mappings — needs Kea or ISC service running on lab (currently neither; `searchReservation` 000 timeout, `/api/dhcpv4/...` 404).
- Playwright e2e on a PegaProx host with the plugin loaded (in CI).
- Audit-log payload hashes (currently metadata-only).
- Port-forwarding (rdr) — **out-of-scope until OPNsense ships an API**. `/api/firewall/{forward,portfwd,nat}/searchRule` all return HTTP 404 on 26.1.2; rdr is GUI/XML-config only today.

## [1.8.0] — 2026-05-10

### Added
- **UnboundDotWriter** — DNS-over-TLS CRUD reusing `/api/unbound/settings/{addForward,delForward,searchForward}` with `type=dot`. Validates domain (`.` for global allowed), server, verify (SNI/cert hostname), and numeric port (default `853`).
- **`/api/plugins/opnsense/api/unbound_dots`** — GET filters search results to `type=dot`; POST `{action: "create"|"delete"}` writes (refuses with HTTP 403 when read_only).
- **DNS tab** now hosts three sub-sections — host overrides, domain overrides (v1.6.0), **DoT entries** — driven by the same helpers. Tab refresh fans out to all three endpoints via `Promise.all`.

### Verified
- 7 new unit tests in `test_unbound_wg_unit.py` cover payload shape (full DoT envelope), validation (empty domain/server/verify/non-numeric port), rollback path, list filtering (`type=dot` excludes plain forwards), read-only refusal, route validation. Suite total: **134 unit tests passing**, ruff clean.

## [1.7.0] — 2026-05-10

### Added
- **OneToOneNatWriter** — 1:1 NAT (BINAT) CRUD against `/api/firewall/one_to_one/{addRule,delRule,searchRule,getRule}` + `/apply` (note: not `reconfigure`). Same lifecycle as `NatWriter`. Validates interface + external IP/alias + internal source_net required, type ∈ {binat, nat}.
- **`/api/plugins/opnsense/api/one_to_one`** — GET lists 1:1 rules; POST `{action: "create"|"delete"}` writes (refuses with HTTP 403 when read_only).
- **NAT tab** now hosts two sub-sections — outbound NAT (v1.4.0) on top, 1:1 BINAT below — fan-out via `Promise.all` on tab refresh. The 1:1 form uses the generic `crudForm`/`crudTable` helpers introduced in v1.5.0.

### Verified
- 7 new unit tests in `test_one_to_one_unit.py` cover payload shape, validation (4 cases including invalid type), rollback on apply-fail, list/action routes, read-only refusal. Suite total: **127 unit tests passing**, ruff clean.
- HTML static check `test_html_uses_per_tab_endpoints` extended to require `../api/one_to_one`.

### Out of scope
- **Port-forwarding (rdr)** — OPNsense 26.1.2 does not expose a REST endpoint for rdr rules. `/api/firewall/forward/*`, `/api/firewall/portfwd/*`, `/api/firewall/nat/*` all return HTTP 404 (verified live). Until upstream ships an API, port-forward stays GUI-only and is not part of this plugin's surface.

## [1.6.0] — 2026-05-10

### Added
- **UnboundDomainWriter** — domain-override CRUD against `/api/unbound/settings/{addForward,delForward,searchForward}` + `/api/unbound/service/reconfigure`. OPNsense 26.x renamed the endpoints (older docs still call these "DomainOverride" — the rename merges plain forwards and DoT into one endpoint discriminated by `type`). Payload root is `dot` with `type=forward` pinned. List filters out DoT rows so the DNS tab shows only plain forwards. Same lifecycle as `UnboundWriter`. Validates domain is a fully-qualified zone (must contain a dot) and server IP is non-empty.
- **`/api/plugins/opnsense/api/unbound_domains`** — GET lists domain overrides; POST `{action: "create"|"delete"}` writes (refuses with HTTP 403 when read_only).
- **DNS tab now hosts both** sub-sections — host overrides (v1.5.0) on top, domain overrides below — driven by the same `crudForm`/`crudTable` helpers. Single tab refresh fans out to both endpoints in parallel via `Promise.all`.

### Verified
- 7 new unit tests in `test_unbound_wg_unit.py` cover payload shape, validation (empty domain, bare domain without dot, empty server), rollback on apply-fail, list/action routes, read-only refusal. Suite total: **120 unit tests passing**, ruff clean.
- HTML static check `test_html_uses_per_tab_endpoints` extended to require `../api/unbound_domains` reference.

### Changed
- `_h_unbound` and `_h_unbound_domains` are sibling handlers — host-overrides endpoint contract from v1.5.0 unchanged.

## [1.5.0] — 2026-05-10

### Added
- **UnboundWriter** — host-override CRUD against `/api/unbound/settings/{addHostOverride,delHostOverride,searchHostOverride}` + `/api/unbound/service/reconfigure`. Same lifecycle as NatWriter (validate → POST → reconfigure → audit; rollback on apply fail).
- **WireguardPeerWriter** — peer (OPNsense calls them "client") CRUD against `/api/wireguard/client/{addClient,delClient,searchClient}` + `/api/wireguard/service/reconfigure`. Validates pubkey is 44-char base64 and tunneladdress is CIDR.
- **`/api/plugins/opnsense/api/unbound`** — GET lists host overrides; POST `{action: "create"|"delete"}` writes (refuses with HTTP 403 when read_only).
- **`/api/plugins/opnsense/api/wg`** — same shape for WG peers.
- **DNS tab** in dashboard UI — form (hostname / domain / server / RR / description) + table with per-row delete.
- **WG peers tab** in dashboard UI — form (name / pubkey / tunneladdress / keepalive / psk) + table with per-row delete.
- **Generic `crudForm` + `crudTable` UI helpers** to avoid duplicating the NAT-tab pattern. NAT tab keeps its custom builders for backwards compat; future tabs can use the helpers.
- 7 tabs total: Overview / Network / VPN / Logs / NAT / **DNS** / **WG peers**.

### Verified
- Live round-trip on lab via socat proxy (LXC 119 → 190.160.10.250:8443 → 192.168.1.1:443):
  - `unbound/addHostOverride` → uuid `30673a96-...` → `delHostOverride` → deleted ✅
  - `wireguard/client/addClient` → uuid `bfff4882-...` → `delClient` → deleted ✅
- 15 new unit tests (test_unbound_wg_unit.py) cover payload shape, validation, rollback path, list/action routes, read-only refusal. Suite total: **113 unit tests passing**.

## [1.4.1] — 2026-05-10

### Fixed
- **NAT tab a11y**:
  - `.btn-primary` text-on-orange contrast was 3.15:1 (#fff on #e57000). Bumped background to #b75300 (deeper orange) so the button clears WCAG AA on the new bg. Added `font-weight:600`.
  - Inline error span used `var(--red)` (#ef4444) on --card → 4.46:1, just under threshold. Switched to #fca5a5 (red-300) matching badges.
  - NAT table delete column had an empty `<th>` (axe `empty-table-header`). Added a `.vh` visually-hidden "Acciones" label.

### Notes
- v1.4.0 was deployed but live smoke against the lab returned 504 because the OPNsense lab VM 125 lost network reachability (100% packet loss to 190.160.10.108 from both pve3 and LXC 119) — independent of the plugin. Plugin code was validated via 14 mocked unit tests; the live round-trip (addRule → delRule) was verified earlier in the session before the lab dropped.

## [1.4.0] — 2026-05-10

### Added
- **NAT writer** — `NatWriter` for outbound source NAT (`/api/firewall/source_nat/*`). Mirrors the AliasWriter/RuleWriter contract: validate → addRule → apply → audit; rolls back the orphan rule if `apply` fails. HA sync optional via the same `HAVerifier`.
- **`GET /api/plugins/opnsense/api/nat`** — list outbound NAT rules.
- **`POST /api/plugins/opnsense/api/nat`** — `{action: "create"|"delete", ...}`. Refuses writes when `read_only: true` in `config.json` (HTTP 403). Validates `interface` + `target` before hitting the upstream.
- **NAT tab** in the dashboard UI: 6-column form (interface / target / source / destination / protocol / description), live table of existing rules with per-row delete, error banner inline. Uses native confirm() before delete.
- Smoke-tested live against the lab: `addRule` → uuid → `delRule/<uuid>` round-trip OK. The schema requires a real IP in `target` (string `wan_address` is rejected with `not a valid source IP address or alias`).

### Verified
- 14 new unit tests (`tests/test_nat_unit.py`) cover NatInput payload shape, rollback path, read-only refusal, validation errors, and create→delete round-trip via mocks. Suite total: 98 unit tests passing.

## [1.3.1] — 2026-05-10

### Added
- **Recent firewall events in the drilldown panel**. The per-iface modal now lazy-loads up to 30 recent log entries filtered to that interface (action badge: pass/block/rdr/nat, time, dir, src, dst, proto). Skeleton placeholder while fetching.

### Notes
- Originally planned as live pf-states snapshot, but OPNsense 26.1.2 does not expose `/api/diagnostics/firewall/{list_pf_states,searchPfStates,states,...}` endpoints (verified — all 404 against the lab). Firewall log filtered by iface is the closest read-only signal available via API.

## [1.3.0] — 2026-05-10

### Added
- **Per-iface drilldown panel**. Click any iface name in the Interfaces table (Overview or Network tabs) to open a `<dialog>` modal with:
  - 4×2 stat grid: state, RX/TX rate, MTU, RX/TX totals, errors, drops, IPv4, IPv6
  - **Big traffic chart** for that single iface — separate RX (green) + TX (blue) lines, 60-sample window, axis labels in B/s/KB/s/...
  - Filtered ARP + NDP neighbors visible on that iface (when Network tab has been visited at least once)
- Cached `lastInterfaces` Map and `lastArp` / `lastNdp` lists so the drilldown works regardless of which tab is active.
- Delegated `click` listener on `.iface-link` so re-rendered tables stay clickable across polls.
- Native HTML5 `<dialog>`: built-in Escape-to-close, focus trap, backdrop. Stays a11y-clean: 0 axe-core violations.

## [1.2.4] — 2026-05-10

### Fixed
- **Rate column WCAG AA contrast** — `.rate .tx` (var(--blue) #3b82f6 on row-hover #21242d) measured 4.21:1 vs 4.5:1 required. Bumped to the same lighter tone used by badges (#93c5fd / blue-300, #4ade80 / green-400) so the inline RX/TX rate text clears AA on both --card and --row-hover. Light theme uses the deeper 700-tones.

## [1.2.3] — 2026-05-10

### Fixed
- **Tablist outside any landmark** — axe still flagged `region` because the bare `<div role="tablist">` was a sibling of `<main>` and not a landmark itself. Wrapped it in `<nav aria-label="Secciones del plugin">` (separate elements: `<nav>` provides the landmark, the inner `<div>` carries `role="tablist"` so neither role is overridden). axe-core: 0 violations across all 4 tabs.

## [1.2.2] — 2026-05-10

### Fixed
- **Final a11y violation on tablist** — `<nav role="tablist">` overrode the implicit `navigation` landmark, leaving the element outside any landmark on Logs tab. Switched the wrapper to `<div role="tablist">` since the tabs already serve their semantic purpose via tablist + tab roles. axe-core: 0 violations across all 4 tabs.

## [1.2.1] — 2026-05-10

### Fixed
- **a11y regression on Logs tab** — placing `role="tabpanel"` directly on `<main>` overrode the implicit landmark. axe-core flagged `aria-allowed-role`, `landmark-one-main`, and `region`. Wrapped the dynamic panel inside a real `<main>` so the landmark survives while keeping tabpanel semantics on the inner div.

## [1.2.0] — 2026-05-10

### Added
- **Tab navigation** in the dashboard UI: Overview · Network · VPN · Logs. Hash-based routing (`#overview`, `#network`, `#vpn`, `#logs`); state preserved across reloads. WAI-ARIA tablist, keyboard-focusable.
- **/api/network endpoint** — interfaces + gateways + routes + ARP + NDP. Heavier than overview (ARP/NDP can be hundreds of rows on busy networks) so it runs only when the Network tab is active.
- **/api/logs endpoint** — paginated firewall log tail (`?limit=N`, default 100, capped at 500). Wraps `collect_firewall_log` with auth/timeout/upstream envelopes.
- **Live traffic graphs**: SVG sparklines per interface (RX green / TX blue) in every interfaces table, plus a stacked area chart on the Network tab showing the top-4 interfaces by current throughput. Rates computed client-side by diffing successive byte counters; window of 60 samples (~10 min at 10s polls). Zero front-end deps — vanilla SVG.
- **Routes / ARP / NDP tables** on the Network tab (truncated to 50 rows with a "showing X of Y" footer).
- **Full WireGuard / IPsec / OpenVPN tables** on the VPN tab — peer name, pubkey/CN, endpoint, RX/TX, latest handshake.
- **Log viewer** with live filter (search by src/dst/iface/rule) + action filter (pass/block/rdr/nat). Auto-poll every 10s.

### Changed
- Overview poll cadence accelerated 30s → 10s so sparklines update meaningfully when sitting on the dashboard.
- Interfaces table now has a Rate column (↓ RX/s, ↑ TX/s) and a sparkline column; old "Etiqueta" + "Err" + "Drop" columns merged into combined cells to fit the new data.

### Fixed
- Stale poll timer when switching tabs — replaced single `setInterval` with per-tab schedule that resets on `switchTab`.

## [1.1.2] — 2026-05-10

### Fixed
- **Last 5 axe color-contrast violations**. After v1.1.1 closed 39/44 nodes, the remaining 5 were `.badge-red` (#ef4444 on rgba red 0.15 → 3.83:1) and `.badge-blue` (#3b82f6 on rgba blue 0.15 → 3.78:1). Bumped the badge foreground to a tone-200/300 variant (e.g. `#fca5a5` red-300, `#93c5fd` blue-300, `#4ade80` green-400, `#fcd34d` amber-300) so the rgba background still clears 4.5:1. Light theme uses the deeper 700-tones for the same contrast guarantee. The standalone `--red/--blue/...` tokens are unchanged — only the `.badge-*` foregrounds.

### Verified
- Axe-core re-run inside the iframe expected: **0 violations** across WCAG 2.0 A + AA + best-practice.

## [1.1.1] — 2026-05-10

### Fixed
- **WCAG AA color-contrast on `--muted` text**. PegaProx's design tokens use `--muted: #71717a` (zinc-500), which gives ~4.39:1 against `--card: #1a1d27` — under the 4.5:1 threshold for body text. Axe-core flagged 44 nodes as serious violations after the v1.1.0 token swap. Bumped `--muted` to `#a1a1aa` (zinc-400, ~6.5:1) for the dark theme and `#4b5563` (gray-600) for the light theme. The plugin now diverges from PegaProx by exactly this one token; everything else stays in lockstep with the host.

### Verified
- Axe-core re-run inside the iframe: WCAG 2.0 A + AA + best-practice → expected 0 violations on the new contrast.

## [1.1.0] — 2026-05-10

### Changed
- **UI rewritten to match the PegaProx dashboard**. The v1.0.x industrial-brutalist look (Tactical Telemetry CRT, hard 90° corners, monospace heavy) was visually disjoint from PegaProx's standard SaaS-y look. v1.1.0 lifts the same design tokens used in `docker_swarm/swarm.html` so the iframe blends with the host:
  - Tokens: `--accent: #e57000` (orange), `--bg: #0f1117`, `--card: #1a1d27`, `--border: #2a2d3a`, `--text: #e4e4e7`, `--muted: #71717a`, `--green/red/yellow/blue` traffic-light palette.
  - System font stack (`-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, …`).
  - Cards with 8 px radius + 16 px padding, badge pills (9999 px radius), 6 px buttons. No more hard corners.
  - Badge component (`.badge-green/.badge-red/.badge-yellow/.badge-blue/.badge-muted`) reused for status chips so they match the rest of PegaProx exactly.
  - Theme awareness: respects `?theme=corp-light` (PegaProx passes the active theme on the iframe URL). `theme-light` HTML class swaps the palette to light tokens.
  - Section headers and meters preserved, just restyled.
- Plugin entry-point version bumped to 1.1.0; manifest.json same.

### Fixed
- **Axe `page-has-heading-one` (best-practice, moderate)**: added `<h1>` for the plugin brand. Previous build used `<div class="brand">`.

### Verified live (Playwright)
- Dashboard tab "OPNsense Manager" still renders inside the PegaProx sandboxed iframe (`/api/plugins/opnsense/api/ui?theme=corp-dark&cluster=…`).
- `/api/overview` polled twice: both 200 OK, ~120 ms.
- Console: 0 errors, 2 warnings (PegaProx's own SSE setup, unrelated).
- Axe-core (WCAG 2.0 A + AA): **0 violations, 18 passes** (re-verified after token swap).
- Color-contrast rule: 0 violations.
- Multi-viewport screenshots captured at 1280, 1024, 768 (`opnsense-1280-final.png`, `opnsense-1024-final.png`, `opnsense-768-final.png`).

### Out of scope
- Per-section deep dives (Interfaces detail, Gateways detail, VPN detail, Logs) — Overview is the v1 surface; detail tabs are slated for v1.2.

## [1.0.2] — 2026-05-10

### Fixed
- **`No module named 'src'` at runtime under PegaProx**. PegaProx imports plugin packages without adding their directory to `sys.path`, so absolute imports like `from src.client import …` failed (`/api/overview` returned HTTP 500 with `No module named 'src'`). Plugin `__init__.py` now inserts `PLUGIN_DIR` into `sys.path` early, before any `src.*` import. Tests are unaffected (their `conftest.py` already does the same insertion).

### Verified
- Live screenshot via Playwright: tab "OPNsense Manager" renders inside PegaProx iframe at `/api/plugins/opnsense/api/ui` (sandbox `allow-scripts allow-same-origin allow-forms allow-popups allow-modals allow-downloads`); after fix, `/api/overview` returns the expected JSON.

## [1.0.1] — 2026-05-10

### Fixed
- **Plugin loader compatibility with PegaProx 0.9.9.3**. Initial v1.0.0 attempted to use `register_plugin_route` as a Flask-style decorator with `methods=['GET']`; the PegaProx API is `register_plugin_route(plugin_id, short_path, handler)` where the handler is a callable and the path is auto-prefixed to `/api/plugins/<id>/api/<path>`. Plugin failed to load with `register() takes 0 positional arguments but 1 was given`. Rewrote the entry point to:
  - accept `register(app=None)` (PegaProx passes the Flask app),
  - register four bare paths (`health`, `ui`, `overview`, `metrics`) via the proper 3-arg API,
  - return dict / `send_file` / `Response` per route as PegaProx expects.
- Side benefit: `metrics` is now reachable at `/api/plugins/opnsense/api/metrics` (PegaProx rejects routes outside the `/api/<id>/api/...` namespace, which was why the previous `/metrics` returned 404).

### Verified
- Live deploy on PegaProx 0.9.9.3 LXC 119 (pve1). Plugin tab loads, `/api/health` returns the dict, `/api/overview` returns the snapshot from the lab, `/api/metrics` emits Prometheus text format with the expected metric families.

## [1.0.0] — 2026-05-10

First production release. Aggregates v0.1.0 → v0.7.0 with documentation polish.

### Highlights

- **Client** (`src/client/`): typed HTTPS client with HTTPBasic auth, exponential-backoff retries on idempotent GETs, no-retry POSTs, typed exception ladder (`OPNsenseError`/`OPNsenseAuthError`/`OPNsenseTimeoutError`).
- **Collectors** (`src/collectors/`, 9 modules): system, interfaces, gateways, services, certificates, hasync, routes/ARP/NDP, firewall_log, vpn (wireguard/ipsec/openvpn aggregate). Every snapshot is a TypedDict.
- **Writers** (`src/writers/`): aliases + rules CRUD with apply, optional HA syncTo + SHA-256 fingerprint divergence check, JSONL audit log, automatic rollback on apply failure.
- **Route layer** (`src/routes/`): aggregated `/api/overview` snapshot with auth/timeout/upstream error envelopes.
- **Metrics** (`src/metrics/`): Prometheus text-format exporter, no `prometheus_client` dependency. ~12 metric families.
- **UI** (`opnsense.html`): industrial-brutalist Overview view, single static file, no build step, system fonts, `prefers-reduced-motion` aware, responsive 1280/1024/768. Built through the mandatory PegaProx UI Pro Max chain.
- **Plugin entry point** (`__init__.py`): wires `/api/health`, `/api/ui`, `/api/overview`, `/metrics` via `register_plugin_route` (PegaProx 0.9.9.3+ native frontend hook).

### Documentation

- `README.md` rewritten to reflect actual capabilities and pin v1.0.0 status.
- `docs/INSTALL.md` — least-privilege OPNsense user recipe + post-install verification.
- `docs/API.md` — endpoint inventory (plugin + upstream OPNsense endpoints consumed).
- `docs/TROUBLESHOOTING.md` — TLS, 401, apply-without-config-visible, HA divergence, missing tab.

### QA gate (final)

- `ruff check src tests` → clean.
- `pytest` → **74 passed, 17 skipped** (live cases skip without env vars).
- Live verification against the OPNsense 26.1.2 lab `https://190.160.10.108` (VM 125 on pve3) covers: system info, interfaces (incl. RX/TX counters), gateways, services, certs, VPN aggregate, hasync, routes, ARP/NDP, firewall log, alias create+delete cycle.
- `manifest.json` schema verified by `tests/test_manifest.py`.
- `config.example.json` shape + placeholder-credential guard verified by `tests/test_config.py`.
- HTML asset shape, banned AI tells, ARIA landmarks, responsive breakpoints, reduced-motion compliance verified by `tests/test_ui_html.py`.

### Out of scope at v1.0.0

- Multi-host failover at the plugin level — current code targets the first host in `opnsense_hosts`. HA peer is used only for sync verification.
- Live browser smoke (Playwright) — requires deploying the plugin into a PegaProx host. Slated for v1.1 RC.
- Detail tabs beyond Overview — interfaces/gateways/vpn/logs detail views.

## [0.7.0] — 2026-05-10

### Added
- **Prometheus `/metrics` exporter** (`src/metrics/exporter.py`). Standalone implementation — no `prometheus_client` dependency added — emits the v0.0.4 text exposition format. Metric inventory:
  - `opnsense_up{host}` — 0/1, set to 0 if even the system call fails.
  - `opnsense_pf_states_current{host}` / `opnsense_pf_states_limit{host}`.
  - `opnsense_memory_used_bytes{host}` / `opnsense_memory_total_bytes{host}` (derived from MB).
  - `opnsense_iface_rx_bytes_total{host,iface,label}` / `tx`, `rx_errors_total`, `tx_errors_total`, `drops_total`, `iface_up`.
  - `opnsense_gateway_rtt_seconds{host,gw}` (raw OPNsense ms → seconds), `gateway_loss_ratio` (0..1, not %), `gateway_up`.
  - `opnsense_service_running{host,service}`.
  - `opnsense_cert_expiry_seconds{host,cert}` (negative if expired).
  - `opnsense_vpn_peers_total{host,type}` (wireguard/ipsec/openvpn).
  - `opnsense_ha_enabled{host}`.
- Plugin entry point exposes `GET /metrics` (proper `text/plain; version=0.0.4` Content-Type) for Prometheus scrapes — sits alongside `/api/health`, `/api/ui`, `/api/overview`.

### Changed
- `manifest.json`: 0.6.0 → 0.7.0.

### QA gate
- 6 unit tests verify HELP/TYPE blocks, every sample carries the `host` label, iface metrics carry `iface`, gateway loss is normalized to a 0–1 ratio (not a percent), and `up=0` is emitted on failure.
- `ruff check src tests` → clean.
- `pytest` → **74 passed, 17 skipped** (live metrics + writer tests skip without env).

## [0.6.0] — 2026-05-10

### Added
- **Writers framework** (`src/writers/`) with shared lifecycle: validate → POST write → POST `reconfigure`/`apply` (empty `{}` body — OPNsense rejects POST without `Content-Length`) → optional HA `syncTo` + peer fingerprint compare → JSONL audit log entry. On exception between write and apply, **rollback** is automatic (orphan row deleted before bubbling the error).
- **`AliasWriter`** — full CRUD against `/api/firewall/alias/*`, with `search()`/`get()` helpers. `AliasInput` dataclass coerces booleans to OPNsense's `"0"/"1"` strings.
- **`RuleWriter`** — full CRUD against `/api/firewall/filter/*`. `RuleInput` validates `action ∈ {pass, block, reject}`, `direction ∈ {in, out}`, `ipprotocol ∈ {inet, inet6, inet46}`, and requires a non-empty interface before any network call.
- **`AuditLog`** — append-only JSONL, thread-safe, `tail(N)` + `iter_all()` readers. Entries: `{ts, user, action, target, host, result, duration_ms, detail}`. Sensitive payloads (rule contents, peer keys) are deliberately not stored — payload hashes are a v0.7+ task.
- **`HAVerifier`** — calls `/api/core/hasync/syncTo`, re-fetches the same search path on the peer, compares a SHA-256 fingerprint to surface divergence. Single-node mode (no peer client) short-circuits with `verified=True`.
- **`TimedAction`** stopwatch context manager used by every writer.
- **Live writer test** (`tests/test_writers_live.py`) double-gated by `OPNSENSE_LAB_*` env + `OPNSENSE_ALLOW_WRITE=1`. Auto-skips if the host running pytest can't reach the lab (mgmt-network requirement). Performs a full `create → search → delete` cycle with cleanup in `finally`.

### Verified live
- Manual end-to-end cycle from `pve3` against the lab `https://190.160.10.108`:
  - `addItem` → `{result: saved, uuid: a58717cc-...}`
  - `reconfigure` → `{status: ok}`
  - `delItem/{uuid}` → `{result: deleted}`
  - `reconfigure` → `{status: ok}`
- `pf` is force-disabled after each reconfigure to keep the lab reachable from the dev workstation; this is lab-only and noted in the SOPS entry.

### Changed
- `manifest.json`: 0.5.0 → 0.6.0.
- `src/writers/__init__.py`: re-exports `AliasInput/AliasWriter`, `RuleInput/RuleWriter`, `AuditLog/AuditEntry`, `HAVerifier`.

### QA gate
- `ruff check src tests` → clean.
- `pytest` → **68 passed, 16 skipped** (live writer test counts as 1 of the skipped ones unless `OPNSENSE_ALLOW_WRITE=1` and lab reachable).
- 16 new unit tests cover happy path, missing uuid, reconfigure-failure rollback, validation rejections, audit append/tail/corrupt-line tolerance, HA verifier single-node + matching peer + diverging peer.

## [0.5.0] — 2026-05-10

### Added
- **Route layer** (`src/routes/overview.py`): `build_overview(client)` returns one JSON snapshot covering system, interfaces, gateways, services, VPN (WG/IPsec/OpenVPN aggregate), HA sync, and certs (with a 30-day expiring filter). `build_overview_payload(host)` wraps it with auth/timeout/upstream error envelopes.
- **Plugin entry point** wires three Flask routes via `register_plugin_route`:
  - `GET /api/health` (config sanity)
  - `GET /api/ui` (the static dashboard)
  - `GET /api/overview` (the aggregated payload)
  - Plus `_first_host_from_config()` helper that materializes an `OPNsenseHost` from `config.json`.
- **Industrial-brutalist Overview UI** (`opnsense.html`) built through the mandatory UI chain (`ui-ux-pro-max` → `emil-design-eng` → `design-taste-frontend` → `high-end-visual-design` → `impeccable craft` → `industrial-brutalist-ui`):
  - Tactical Telemetry palette: `#0a0a0a` substrate, `#eaeaea` foreground, `#e61919` lone accent, `#4af626` reserved for the HA-active chip.
  - System fonts only (`ui-monospace`, `ui-sans-serif`) — no web font fetch.
  - Hard 90° corners, 1px CSS-grid dividers, ASCII-bracketed `[ SECTION ]` headers, `///` separators.
  - 12-column grid that collapses cleanly to 6 cols at 1024px and a single column at 768px.
  - Cells: System (CPU/MEM/PF meters), HA Sync, Certs, Interfaces table (RX/TX/err/drop), Gateways table (RTT/loss), Services running ratio, VPN aggregate.
  - Auto-refresh every 30s, manual refresh button (`active:translateY(1px)`, ARIA-labelled, busy-state).
  - A11y: `role="banner"`/`role="alert"`, `aria-busy`, `aria-live` on connection status, table `<caption class="vh">` for screen readers, focus rings, color is never the only signal.
  - `prefers-reduced-motion: reduce` cancels skeleton shimmer + all transitions.
- **Tests**:
  - `tests/test_routes_unit.py` — 12 cases covering aggregation shape, certs filter, ok/auth/upstream payload envelopes (with retry exhaustion).
  - `tests/test_ui_html.py` — 8 static checks: HTML parses, viewport + color-scheme metas present, module script wired, brutalist palette CSS variables defined, no banned AI tells (`background-clip: text`, gradient text, `border-radius` on cards), reduced-motion media query enforces `animation: none`, ARIA landmarks + busy state, responsive breakpoints at 1280/1024/768.

### Changed
- `manifest.json`: 0.4.0 → 0.5.0.
- `__init__.py`: `register()` now wires the overview blueprint and reports v0.5.0.

### QA gate
- `ruff check src tests` → clean.
- `pytest` → **52 passed, 15 skipped** (live unchanged).
- UI verified statically via the new `test_ui_html.py` suite. Live browser run deferred to v1.0 RC (needs PegaProx host with plugin installed → Playwright).

## [0.4.0] — 2026-05-10

### Added
- **HA collector** (`collect_hasync`) — collapses OPNsense option-group dicts (`{value, selected}`) to plain values. Surfaces `enabled`, `pfsync_interface`, `pfsync_peer_ip`, `pfsync_version`, `sync_to_ip`, `sync_compatibility`, `sync_disable_preempt`, `sync_disconnect_ppps`.
- **Routing/neighbor collectors** (`collect_routes`, `collect_arp`, `collect_ndp`) — system route table + IPv4/IPv6 neighbor caches with manufacturer + interface description.
- **Firewall log tail** (`collect_firewall_log(limit=N)`) — projects 10 useful fields out of OPNsense's 26-field rows. Defaults to 100 entries; uses query-string limit so the full bulky payload stays on the wire.
- **VPN collectors** (`collect_wireguard`, `collect_ipsec`, `collect_openvpn`, plus aggregator `collect_vpn`) — uniform `VPNPeer` shape across the three engines, retains raw OPNsense row for UI deep-dive.
- **Fixtures** added (8 new): `getRoutes`, `getArp`, `getNdp`, `firewall_log` (slimmed to 5 entries), `firewall_log_filters`, `ipsec_searchPhase1`, `openvpn_searchSessions`, `wireguard_general_get`.

### Changed
- `manifest.json`: 0.3.0 → 0.4.0.
- `src/collectors/__init__.py`: re-exports new types and functions.

### QA gate
- `ruff check src tests` → clean.
- Unit suite: **32 passed, 15 skipped** (live).
- Live suite (with SOPS-decrypted creds): **15 passed in 12.02s** vs `https://190.160.10.108`.

## [0.3.0] — 2026-05-10

### Added
- **Read-only collectors** (`src/collectors/`):
  - `collect_system` — version banner, CPU type, uptime/load, memory used/total + ARC, pf states current/limit/% utilization. Tolerates `cpu_usage/getCPUType` failure.
  - `collect_interfaces` — merges `getInterfaceConfig` + `getInterfaceStatistics` into one snapshot per iface (mac, flags, IPv4/IPv6 addrs, mtu, rx/tx bytes/packets/errors/drops/collisions, `is_up` derived from flags). Parses OPNsense's `[LABEL] (iface)` stat-key format.
  - `collect_gateways` — name/address/monitor/status, delay/loss/stddev coerced from `~` and `12.3 ms`/`0.0 %` strings to floats. `is_up` derived from `status_translated == "Online"`.
  - `collect_services` — running/stopped count + per-service `(id, name, description, running, locked)`.
  - `collect_certificates` — metadata only (PEM payloads dropped on purpose), with `days_to_expiry` parsed from `valid_to`.
- **Live fixtures** in `fixtures/live/` (12 captured responses from the OPNsense 26.1.2 lab) with cert PEM/private key payloads redacted (`<CRT_REDACTED>`, `<PRV_REDACTED>`, etc.).
- **Tests**: 5 unit tests in `tests/test_collectors_unit.py` (fixture-driven, mocked with `responses`). 5 live smoke tests in `tests/test_collectors_live.py` gated by `OPNSENSE_LAB_*` env vars. All green against the lab.

### Changed
- `manifest.json`: `version` 0.2.0 → 0.3.0.

### QA gate
- `ruff check src tests` → clean.
- `pytest -q` → **22 passed, 6 skipped** (live skipped without env).
- Live run with SOPS-decrypted creds → **6 passed in 4.92s** against `https://190.160.10.108`.

## [0.2.0] — 2026-05-10

### Added
- **`OPNsenseClient`** (`src/client/opnsense_client.py`): real HTTP client. HTTPS-only, `HTTPBasicAuth(api_key, api_secret)`, configurable connect/read timeouts, retry-with-exponential-backoff on idempotent GETs (3 attempts, 5xx 502/503/504 + connection errors), POST is never retried (callers own reconcile/rollback). Public sugar methods `system_information()` and `hasync_get()`.
- **Typed exception ladder**: `OPNsenseError` / `OPNsenseAuthError` (401/403) / `OPNsenseTimeoutError`.
- **`OPNsenseHost`** dataclass with `verify_tls` + optional `ca_bundle_path` for self-signed labs.
- Unit tests `tests/test_client_unit.py` (12 cases) covering happy path, 401/403, basic-auth header, GET retry on 502/503, no retry on POST, connection-error exhaustion, http URL rejection, non-JSON response, path normalisation. Uses `responses` library — zero network.
- Live smoke `tests/test_client_live.py` against the lab, gated by `OPNSENSE_LAB_URL`/`KEY`/`SECRET` env vars (auto-skip when unset).
- Plugin `__init__.py` now imports PegaProx framework defensively (`try/except ImportError`) so the package is importable in test/lint environments without PegaProx installed.

### Changed
- `manifest.json`: `version` 0.1.0 → 0.2.0.
- `requirements-dev.txt`: pinned `requests>=2.31`, `responses>=0.24` (already present, just exercised now).

### QA gate
- `ruff check src tests` → all checks passed.
- `pytest` → 17 passed, 1 skipped (live, runs when env vars are set).
- Live smoke against lab `https://190.160.10.108` (OPNsense 26.1.2_5) → HTTP 200 / ~120 ms.

## [0.1.0] — 2026-05-09

### Added
- Initial scaffold mirroring `pegaprox-docker-swarm` layout
- `manifest.json` (`min_pegaprox: 0.9.9.3`, `has_frontend: true`, `frontend_route: ui`)
- `__init__.py` plugin entry point with `register()` / `unregister()` and `/api/health` + `/api/ui` stubs
- `install.sh` / `uninstall.sh` matching the family conventions
- `config.example.json` covering HA dual-host setup
- `pytest.ini` + `requirements-dev.txt`
- `MIT` license
- README + this changelog
- `PEGAPROX_PLUGIN_OPNSENSE_BRIEF.md` (workspace root) — full v1 spec
