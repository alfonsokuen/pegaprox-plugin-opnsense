# Changelog

All notable changes to this project will be documented here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) — versioning: [SemVer](https://semver.org/).

## [Unreleased]

### Planned (v1.0.0)
- OPNsense HTTP client (key+secret, retries, TLS pinning)
- Collectors: overview, interfaces, gateways, VPN, services, logs
- Writers: aliases, rules, NAT, DHCP, Unbound, WireGuard
- HA sync with post-sync verification
- Audit log + UI tab
- Prometheus `/metrics` exporter
- UI built through the Pro Max chain (industrial-brutalist style)
- Playwright e2e against OPNsense lab

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
