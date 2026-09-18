# PegaProx OPNsense Manager Plugin

Monitor and configure OPNsense firewalls (HA-aware) from the PegaProx dashboard.

[![version](https://img.shields.io/badge/version-1.16.1-blue)](CHANGELOG.md)
[![pegaprox](https://img.shields.io/badge/pegaprox-0.9.9.3+-orange)](https://github.com/PegaProx/project-pegaprox)
[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![python](https://img.shields.io/badge/python-3.11+-yellow)](#development)
[![tests](https://img.shields.io/badge/tests-pytest-success)](#qa)
[![a11y](https://img.shields.io/badge/axe--core-0_violations-success)](#qa)
[![audit](https://img.shields.io/badge/audit_log-sha256-success)](#audit-log)

## What it does

Wires an OPNsense firewall into the PegaProx admin panel. Read-only monitoring out of the box, write operations with audit evidence and explicit application/rollback outcomes, and a Prometheus `/metrics` endpoint for your existing monitoring stack.

### Monitoring (read-only)

- HA sync state (`pfsync` interface, peer IP, version compatibility)
- Per-interface throughput (RX/TX bytes, errors, drops, link state)
- pf state table utilization (current vs. limit)
- System: CPU, memory, load average, uptime
- Gateways: RTT, loss, up/down per gateway
- VPN: WireGuard peers, IPsec phase 1, OpenVPN sessions
- Services running/stopped
- Routing table, ARP, NDP neighbors
- Recent firewall log (limit-bounded)
- Cert inventory + expiry warnings (≤30 days)

### Configuration (write)

| Writer | Endpoint | Surface |
|---|---|---|
| `AliasWriter` | `/api/firewall/alias/*` | host/network/port/url/urltable/geoip/external |
| `RuleWriter` | `/api/firewall/filter/*` | pass/block/reject per interface |
| `VerifiedFirewallWriter` (DNAT) | `/api/firewall/d_nat/*` | destination NAT with canonical readback and revision checks |
| `DhcpSubnetWriter` | `/api/kea/dhcpv4/*Subnet` | Kea DHCPv4 subnets |
| `NatWriter` | `/api/firewall/source_nat/*` | outbound NAT |
| `OneToOneNatWriter` | `/api/firewall/one_to_one/*` | BINAT / 1:1 NAT |
| `UnboundWriter` | `/api/unbound/settings/{add,del,search}HostOverride` | DNS host overrides |
| `UnboundDomainWriter` | `/api/unbound/settings/{add,del,search}Forward` (type=forward) | DNS domain overrides (forwarding) |
| `UnboundDotWriter` | same endpoint with type=dot | DNS-over-TLS upstreams |
| `WireguardPeerWriter` | `/api/wireguard/client/*` | WireGuard peers (clients) |
| `DhcpReservationWriter` | `/api/kea/dhcpv4/{add,del,search}Reservation` | Kea DHCPv4 static mappings |

Legacy writers use the lifecycle below. The new DNAT/rules/aliases routes additionally verify JSON acknowledgement, readback, revision conflicts and peer convergence; see [management API](docs/FIREWALL_MANAGEMENT.md).

```
validate → POST → apply/reconfigure → (optional) HA syncTo → audit
                       │
                       └─ on fail: rollback the orphan + record error
```

**Audit log** (`state/audit.jsonl`) — append-only JSONL with `payload_sha256` per row: SHA-256 of the canonical-JSON sent to OPNsense. Correlates a known payload with the recorded operation without storing that payload; this is not a cryptographically authenticated log chain. An auditor replaying a known input can verify the historical write referenced that exact payload.

Destination NAT uses the native `/api/firewall/d_nat/*` API, qualified on OPNsense 26.1.2. Older or unsupported endpoints return an explicit error; the plugin does not rewrite XML configuration.

### Observability

- `GET /api/plugins/opnsense/api/overview` — single JSON snapshot for the Overview tab
- `GET /api/plugins/opnsense/api/vpn` — WireGuard, IPsec and OpenVPN status without a full overview request
- `GET /api/plugins/opnsense/api/network` — interfaces + gateways + routes + ARP + NDP
- `GET /api/plugins/opnsense/api/logs?limit=N` — paginated firewall log tail (default 100, capped at 500)
- `GET /api/plugins/opnsense/api/metrics` — Prometheus text exposition (no `prometheus_client` dependency)
- `GET /api/plugins/opnsense/api/health` — plugin liveness + config presence

### Dashboard UI — 9 tabs

Hash-routed (`#overview`, `#network`, `#vpn`, `#logs`, `#nat`, `#firewall`, `#dns`, `#dhcp`, `#wg`), ARIA tablist wrapped in `<nav aria-label>`, zero front-end dependencies:

| Tab | Content |
|---|---|
| **Overview** | system, HA sync, certs, interfaces (compact), gateways, services, VPN summary |
| **Network** | live traffic chart (stacked area, top-4 by throughput), interfaces with **per-iface SVG sparklines** + live RX/TX rates, gateways, routing table, ARP, NDP. Rates computed client-side from successive byte counters; 60-sample window. **Per-iface drilldown** modal (`<dialog>`) with RX/TX chart + neighbors + lazy-loaded firewall events filtered by iface. |
| **VPN** | full WireGuard / IPsec / OpenVPN tables (peer, pubkey/CN, endpoint, RX/TX, latest handshake) |
| **Logs** | firewall log tail with live filter (search src/dst/iface/rule + action chip pass/block/rdr/nat). Auto-poll 10 s |
| **NAT** | Destination NAT create/edit/delete, plus existing outbound NAT and 1:1 BINAT |
| **Firewall** | Filter rules and aliases create/edit/delete; explicit read-only state |
| **DNS** | three sub-sections — host overrides + domain overrides + **DoT entries** |
| **DHCP** | Kea DHCPv4 reservations (subnet UUID + IP + MAC + hostname) and subnets |
| **WG peers** | WireGuard peer list/create/delete (name, pubkey, tunnel address, keepalive, optional PSK) |

Theme-aware: PegaProx passes `?theme=corp-light|corp-dark|cloud` and the plugin honours all three (the **cloud** value repaints it with the Modern view tokens — deep-blue surfaces, cyan accent). Tokens lifted from `docker_swarm/swarm.html` so the iframe blends with the host dashboard.

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

Edit `/opt/PegaProx/plugins/opnsense/config.json`:

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

For HA pairs configure `cluster_mode: "auto"`. Reads use the primary CARP VIP selection. New management writes require both peers reachable with complementary roles on every VIP, then verify the changed object on the peer. Mixed or unknown ownership blocks writes.

**`read_only: true`** disables every write endpoint (HTTP 403 from the route layer before the writer even runs). Useful as a guard rail in shared production environments.

**Never commit credentials.** Use SOPS or env-injected configs in production. See `docs/INSTALL.md` for the least-privilege OPNsense user recipe.

## Audit log

Every successful write records a single JSONL line in `state/audit.jsonl`:

```json
{
  "ts": "2026-05-10T22:30:06Z",
  "user": "plugin",
  "action": "dhcp_reservation.create",
  "target": "91365bf5-bfc9-4ca5-8246-9b091c47d6d0",
  "host": "lab",
  "result": "ok",
  "duration_ms": 164,
  "detail": "v1.10.0 live smoke",
  "payload_sha256": "0cf3b02debdb6d8abd3e6550267a3c33f8422cef5b96d3b7ee2880c505affeff"
}
```

`payload_sha256` is the hex SHA-256 of the canonical-JSON body sent to OPNsense (sorted keys, no whitespace). Deterministic across runs and independent of key order in the original dict. Delete operations leave it empty since they carry no payload.

## Uninstall

```bash
sudo bash /opt/PegaProx/plugins/opnsense/uninstall.sh
```

The uninstaller backs up the plugin directory to `/tmp/pegaprox-opnsense-backup-<ts>.tar.gz` before removal.

## Development

```bash
pip install -r requirements-dev.txt
pytest                                   # default unit/regression suite
ruff check src tests                     # lint
```

### Live tests against an OPNsense lab

Read-only collectors + metrics:

```bash
export OPNSENSE_LAB_URL=https://10.0.0.1
export OPNSENSE_LAB_KEY=...
export OPNSENSE_LAB_SECRET=...
pytest -k live
```

Write-path (mutates state, creates + cleans up):

```bash
OPNSENSE_ALLOW_WRITE=1 pytest tests/test_writers_live.py
```

### Browser e2e smoke (Playwright, opt-in)

Gated by `RUN_E2E=1`. Walks the 8 tabs, asserts the ARIA state, and filters console errors:

```bash
pip install playwright && playwright install chromium
RUN_E2E=1 \
PEGAPROX_URL=https://pegasus.example.com \
PEGAPROX_USER=alfonso \
PEGAPROX_PASS=... \
pytest tests/test_e2e_smoke.py::test_e2e_login_and_visit_all_tabs
```

Adds a write-path round-trip (creates + deletes a host override) when `RUN_E2E_WRITE=1` is also set. **Lab only — never against prod.**

## Layout

```
.
├── manifest.json                 # PegaProx plugin manifest (version, has_frontend, frontend_route)
├── __init__.py                   # entry point: register() / unregister(), 12 routes
├── opnsense.html                 # plugin UI: 9 tabs, verified management, theme-aware
├── install.sh / uninstall.sh
├── config.example.json
├── src/
│   ├── client/                   # OPNsenseClient (HTTPS + retries + typed errors)
│   ├── collectors/               # read-only snapshot fns
│   ├── writers/                  # 9 writers + AuditLog (with payload_sha256) + HAVerifier
│   ├── routes/                   # build_*_payload functions per endpoint
│   └── metrics/                  # Prometheus text-format exporter
├── tests/
│   ├── test_*_unit.py            # unit/regression tests
│   └── test_e2e_smoke.py         # Playwright browser e2e (opt-in)
├── fixtures/live/                # captured OPNsense API responses (sanitized)
└── docs/                         # INSTALL / API / TROUBLESHOOTING
```

## QA

- Unit/regression tests run by default; live tests remain opt-in. `RUN_LOCAL_E2E=1` enables browser ? Flask ? HTTPS simulator tests.
- `ruff check` — clean
- **axe-core: 0 violations** across WCAG 2.0 A + AA on every tab (Overview / Network / VPN / Logs / NAT / DNS / DHCP / WG peers), live-verified at `pegasus.idkmanager.com`
- **Live round-trips verified** against OPNsense 26.1.2 lab: aliases, rules, source NAT, 1:1 NAT, Unbound host + domain + DoT, Kea reservation, WireGuard peer. Each round-trip records the SHA-256 in the JSONL.
- UI tokens lifted from PegaProx's `docker_swarm/swarm.html` so the iframe blends with the host dashboard. Single deviation: `--muted` bumped from `#71717a` to `#a1a1aa` to clear AA contrast on `--card`.

### OPNsense 26.x gotchas baked into the writers

- **Unbound endpoint rename**: 26.x collapsed `addDomainOverride` into `addForward` with a `type` discriminator (`forward` | `dot`). The plugin uses the new endpoint and filters list results by `type`.
- **`type=dot` coercion bug** (upstream): 26.1.2 silently stores DoT entries with `type=forward`. Plugin code is correct; the DoT filter will start surfacing rows automatically when upstream fixes it. Tracked in CHANGELOG.
- **Kea subnet management** is available through the DHCP tab; advanced DHCP options remain GUI-managed.
- **`one_to_one` apply path** uses `/apply` not `/reconfigure` (different from `source_nat`).
- **Bare-root domain `.`** is rejected by Unbound DoT validation; use a real FQDN.

See `CHANGELOG.md` for the full version-by-version history.

## License

MIT — see [LICENSE](LICENSE).
