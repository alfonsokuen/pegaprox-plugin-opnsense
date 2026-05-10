# PegaProx OPNsense Manager Plugin

Monitor and configure OPNsense firewalls (HA-aware) from the PegaProx dashboard.

[![version](https://img.shields.io/badge/version-1.2.4-blue)](CHANGELOG.md)
[![pegaprox](https://img.shields.io/badge/pegaprox-0.9.9.3+-orange)](https://github.com/PegaProx/project-pegaprox)
[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![python](https://img.shields.io/badge/python-3.11+-yellow)](#development)
[![tests](https://img.shields.io/badge/tests-84_passed-success)](#qa)
[![a11y](https://img.shields.io/badge/axe--core-0_violations-success)](#qa)

## What it does

Wires an OPNsense firewall into the PegaProx admin panel. Read-only monitoring out of the box, write operations behind an audit log with rollback, and a Prometheus `/metrics` endpoint for your existing monitoring stack.

### Monitoring (read-only)

- HA sync state (`pfsync` interface, peer IP, version compatibility)
- Per-interface throughput (RX/TX bytes, errors, drops, link state)
- pf state table utilization (current vs. limit)
- System: CPU type, memory used/total, load average, uptime
- Gateways: RTT, loss, up/down per gateway
- VPN: WireGuard peers, IPsec phase 1, OpenVPN sessions
- Services running/stopped
- Routing table, ARP, NDP neighbors
- Recent firewall log (limit-bounded)
- Cert inventory + expiry warnings (≤30 days)

### Configuration (write)

- **Aliases** — host/network/port/url/urltable/geoip/external. Full CRUD.
- **Firewall rules** — pass/block/reject per interface, with up-front validation.
- Every write: validate → POST → `reconfigure`/`apply` → optional HA `syncTo` → fingerprint compare against peer → JSONL audit row.
- **Rollback**: if the apply step fails after the row is created, the orphan is deleted before the error bubbles up.

NAT/DHCP/Unbound/WireGuard-peer CRUD use the same writer pattern; ship in v1.1.

### Observability

- `GET /api/plugins/opnsense/api/overview` — single JSON snapshot for the Overview tab.
- `GET /api/plugins/opnsense/api/network` — interfaces + gateways + routes + ARP + NDP for the Network tab.
- `GET /api/plugins/opnsense/api/logs?limit=N` — paginated firewall log tail (default 100, capped at 500).
- `GET /api/plugins/opnsense/api/metrics` — Prometheus text exposition (no `prometheus_client` dependency).

### Dashboard UI

Four tabs, hash-routed (`#overview`, `#network`, `#vpn`, `#logs`), ARIA tablist:

- **Overview** — system, HA sync, certs, interfaces (compact), gateways, services, VPN summary.
- **Network** — live traffic chart (stacked area, top-4 by throughput), interfaces table with **per-iface SVG sparklines** and live RX/TX rates, gateways, routing table, ARP, NDP. Rates computed client-side from successive byte counters; window of 60 samples (~10 min at 10s polls). Zero front-end deps.
- **VPN** — full WireGuard / IPsec / OpenVPN tables (peer, pubkey/CN, endpoint, RX/TX, latest handshake).
- **Logs** — firewall log tail with live filter (search src/dst/iface/rule + action chip pass/block/rdr/nat). Auto-poll 10 s.

Theme-aware: PegaProx passes `?theme=corp-light|corp-dark` and the plugin honours both. Tokens lifted from `docker_swarm/swarm.html` so the iframe blends with the host dashboard.

## Install

```bash
curl -sSL https://git.idkmanager.com/idkmanager/pegaprox-plugin-opnsense/raw/branch/main/install.sh | sudo bash
```

Requirements:
- PegaProx **0.9.9.3+** at `/opt/PegaProx` (native plugin frontend hook)
- Python 3.11+
- HTTPS reachability from the PegaProx host to the OPNsense API
- An API key + secret on each OPNsense node (System → Access → Users → user → API keys)

Mirrors:
- Gitea (source of truth): https://git.idkmanager.com/idkmanager/pegaprox-plugin-opnsense
- GitHub: https://github.com/idkmanager/pegaprox-plugin-opnsense
- GitHub (personal mirror): https://github.com/alfonsokuen/pegaprox-plugin-opnsense

## Configuration

Edit `/opt/PegaProx/plugins/opnsense/config.json` (or use the **Settings** tab once the UI ships per-host editing). Shape:

```json
{
  "opnsense_hosts": [
    {
      "name": "lab",
      "url": "https://10.0.0.1",
      "api_key": "REPLACE_WITH_OPNSENSE_API_KEY",
      "api_secret": "REPLACE_WITH_OPNSENSE_API_SECRET",
      "verify_tls": true,
      "ca_bundle_path": ""
    }
  ],
  "poll_interval": 30,
  "read_only": false
}
```

For HA pairs list both peers; the plugin will use the first by default and the second as the sync verification peer.

**Never commit credentials.** Use SOPS or env-injected configs in production. See `docs/INSTALL.md` for the least-privilege OPNsense user recipe.

## Uninstall

```bash
sudo bash /opt/PegaProx/plugins/opnsense/uninstall.sh
```

The uninstaller backs up the plugin directory to `/tmp/pegaprox-opnsense-backup-<ts>.tar.gz` before removal.

## Development

```bash
pip install -r requirements-dev.txt
pytest                                   # unit suite, ~70 cases
ruff check src tests                     # lint
```

Live tests against an OPNsense lab opt in via env vars:

```bash
export OPNSENSE_LAB_URL=https://10.0.0.1
export OPNSENSE_LAB_KEY=...
export OPNSENSE_LAB_SECRET=...
pytest -k live                           # read-only collectors + metrics live
OPNSENSE_ALLOW_WRITE=1 pytest tests/test_writers_live.py   # mutates state — full create/delete cycle, cleans up
```

## Layout

```
.
├── manifest.json                 # PegaProx plugin manifest (has_frontend, frontend_route)
├── __init__.py                   # entry point: register() / unregister(), all routes
├── opnsense.html                 # plugin UI: 4 tabs, sparklines + live chart, theme-aware
├── install.sh / uninstall.sh
├── config.example.json
├── src/
│   ├── client/                   # OPNsenseClient (HTTPS + retries + typed errors)
│   ├── collectors/               # read-only snapshot fns (system, ifaces, gws, services, vpn, certs, hasync, routes, fw_log)
│   ├── writers/                  # AliasWriter, RuleWriter, AuditLog, HAVerifier
│   ├── routes/                   # build_overview / build_network / build_logs payloads
│   └── metrics/                  # Prometheus text-format exporter
├── tests/                        # pytest unit + live (gated)
├── fixtures/live/                # captured OPNsense API responses (sanitized)
└── docs/                         # INSTALL / API / TROUBLESHOOTING
```

## QA

- **84 unit tests** passing, 17 live tests gated by env (all passing against the lab when run from a host on the OPNsense management network)
- `ruff check src tests` — clean
- **axe-core: 0 violations** across WCAG 2.0 A + AA + best-practice on all 4 tabs (Overview / Network / VPN / Logs), verified live in browser at `pegasus.idkmanager.com`
- UI tokens lifted from PegaProx's `docker_swarm/swarm.html` so the iframe blends with the host dashboard. Single deviation: `--muted` bumped from `#71717a` to `#a1a1aa` (zinc-400) to clear AA on `--card`

See `CHANGELOG.md` for the full version-by-version history.

## License

MIT — see [LICENSE](LICENSE).
