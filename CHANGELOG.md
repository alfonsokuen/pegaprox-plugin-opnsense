# Changelog

All notable changes to this project will be documented here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) — versioning: [SemVer](https://semver.org/).

## [Unreleased]

### Planned (v1.0.0)
- Additional writers: NAT, DHCP, Unbound, WireGuard peers (same pattern as Aliases/Rules).
- Prometheus `/metrics` exporter.
- Playwright e2e on a PegaProx host with the plugin loaded.
- Detail tabs (Interfaces, Gateways, VPN, Logs).

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
