# PegaProx OPNsense Manager Plugin

Monitor and configure OPNsense firewalls (HA-aware) from the PegaProx dashboard.

> **Status**: scaffold v0.1.0 — see `PEGAPROX_PLUGIN_OPNSENSE_BRIEF.md` (workspace) for the full v1.0.0 spec.

## Features (v1 scope)

**Monitoring (read-only)**
- HA status (master/backup, last sync, divergence)
- Per-interface throughput, errors, drops
- pf states, top talkers
- CPU / RAM / disk / temp
- Gateways (RTT, loss, up/down)
- VPN tunnels (IPsec, WireGuard, OpenVPN)
- Services + log streaming
- Cert expiry tracking

**Configuration (write)**
- Aliases, firewall rules, NAT (CRUD)
- DHCP static mappings
- Unbound host/domain overrides
- WireGuard peers (CRUD)
- Apply + HA sync + post-sync verify
- Audit log of every write

## Install

```bash
curl -sSL https://git.idkmanager.com/idkmanager/pegaprox-plugin-opnsense/raw/branch/main/install.sh | sudo bash
```

Requirements:
- PegaProx 0.9.9.3+ at `/opt/PegaProx`
- Python 3
- Network reachability to OPNsense API (HTTPS)

## Configuration

Edit `/opt/PegaProx/plugins/opnsense/config.json` (or use the **Settings** tab in the plugin UI).

Each OPNsense host needs:
- `url` — `https://<host-or-vip>`
- `api_key` + `api_secret` — generate in OPNsense → System → Access → Users → + key
- `verify_tls` — keep `true` in prod; provide `ca_bundle_path` for self-signed CAs

For HA setups, list both peers and optionally a `ha_active_url` (VIP).

**Never store plaintext credentials in this repo.** Use SOPS or env-injected configs in production. See workspace `CLAUDE.md` §1 rule #7.

## Uninstall

```bash
sudo bash /opt/PegaProx/plugins/opnsense/uninstall.sh
```

## Development

```bash
pip install -r requirements-dev.txt
pytest
```

Tests live in `tests/`. Fixtures of OPNsense API responses go in `fixtures/`.

## Layout

```
.
├── manifest.json              # PegaProx plugin manifest
├── __init__.py                # entry point (register/unregister)
├── opnsense.html              # plugin UI shell
├── install.sh / uninstall.sh
├── config.example.json
├── src/
│   ├── client/                # OPNsense HTTP client
│   ├── collectors/            # poll workers
│   ├── writers/               # CRUD + apply + HA sync
│   ├── routes/                # REST exposed to the UI
│   ├── metrics/               # Prometheus exporter
│   └── ui/                    # frontend (built via Pro Max chain)
├── tests/                     # pytest unit + integration
├── fixtures/                  # canned OPNsense responses
└── docs/                      # INSTALL / API / TROUBLESHOOTING
```

## License

MIT — see `LICENSE`.

## Companion plugin

[`pegaprox-docker-swarm`](https://github.com/alfonsokuen/pegaprox-docker-swarm) — Docker Swarm/standalone manager from the same plugin family.
