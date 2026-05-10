# Changelog

All notable changes to this project will be documented here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) — versioning: [SemVer](https://semver.org/).

## [Unreleased]

### Planned (v1.0.0)
- Writers: aliases, rules, NAT, DHCP, Unbound, WireGuard
- HA sync with post-sync verification
- Audit log + UI tab
- Prometheus `/metrics` exporter
- UI built through the Pro Max chain (industrial-brutalist style)
- Playwright e2e against OPNsense lab

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
