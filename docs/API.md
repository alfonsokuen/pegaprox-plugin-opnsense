# API surface

Plugin endpoints (mounted under `/api/plugins/opnsense`):

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/health` | Plugin status + config sanity (scaffold-ready) |
| GET | `/api/ui` | UI shell (`opnsense.html`) |
| GET | `/api/overview` | Aggregated dashboard payload _(v1)_ |
| GET | `/api/interfaces` | Per-iface stats _(v1)_ |
| GET | `/api/gateways` | Gateway monitor table _(v1)_ |
| GET | `/api/vpn/{type}` | WireGuard / IPsec / OpenVPN peers _(v1)_ |
| GET | `/api/logs` | Filtered log stream _(v1)_ |
| GET\|POST\|PUT\|DELETE | `/api/aliases[/{uuid}]` | CRUD aliases _(v1)_ |
| GET\|POST\|PUT\|DELETE | `/api/rules[/{uuid}]` | CRUD firewall rules _(v1)_ |
| POST | `/api/apply` | Apply pending changes + sync HA + verify _(v1)_ |
| GET | `/metrics` | Prometheus exporter _(v1)_ |

## Upstream OPNsense endpoints consumed
Validate names against your installed OPNsense version. Starting set:

- `/api/diagnostics/system/system_information`
- `/api/core/hasync/get` + `/api/core/hasync/syncTo`
- `/api/diagnostics/traffic/interface`
- `/api/diagnostics/firewall/pf_states`
- `/api/diagnostics/system/systemResources`
- `/api/routes/gateway/status`
- `/api/diagnostics/interface/getRoutes`
- `/api/ipsec/sessions/search_phase1` + `_phase2`
- `/api/wireguard/service/show`
- `/api/openvpn/service/searchSessions`
- `/api/core/service/search`
- `/api/diagnostics/firewall/log`
- `/api/trust/cert/search`
- `/api/firewall/alias/{addItem,delItem,setItem,reconfigure}`
- `/api/firewall/filter/{addRule,delRule,setRule,apply}`

All requests use `Authorization: Basic base64(key:secret)` over HTTPS.
