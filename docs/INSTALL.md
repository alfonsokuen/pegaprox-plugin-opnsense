# Install

See `install.sh` at the repo root or run the one-liner from the README. This file expands on the prerequisites and post-install verification.

## Prerequisites
- PegaProx 0.9.9.3+ at `/opt/PegaProx`.
- Python 3 in the PegaProx host.
- HTTPS reachability from PegaProx host to the OPNsense API endpoint(s).
- An API key + secret on each OPNsense node (System → Access → Users → User → API keys).

## OPNsense user privileges (least privilege)
Create a dedicated user `pegaprox-bot` with only the privileges your plugin policy demands:
- Read-only audit: `Status: *` + `Diagnostics: *` are enough for monitoring.
- Configuration: add the specific `Firewall: *`, `Services: DHCP*`, `Services: Unbound*`, `VPN: WireGuard*`, `System: HASync` privileges that the plugin needs.

Keep the API key + secret in SOPS, **never** in this repo.

## Verify
```bash
curl -sk https://YOUR_PEGAPROX/api/plugins/opnsense/api/health | jq
```
Expected:
```json
{"plugin":"opnsense","version":"0.1.0","configured":true,"read_only":false}
```
