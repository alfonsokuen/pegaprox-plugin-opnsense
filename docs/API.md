# API surface

All routes use `/api/plugins/opnsense/api/` as prefix and require a PegaProx session or API token with `plugins.view`.

| Methods | Route | Purpose |
|---|---|---|
| GET | `health` | Version from manifest, configuration presence and read-only state |
| GET | `ui` | Plugin HTML |
| GET | `overview`, `cluster` | Monitoring and HA state |
| GET | `network`, `logs` | Interfaces, gateways, routes, neighbors and log tail |
| GET | `metrics` | Prometheus exporter |
| GET, POST | `port_forward`, `rules`, `aliases` | Verified firewall management added in 1.15.0 |
| GET, POST | `nat`, `one_to_one` | Existing source NAT and 1:1 NAT management |
| GET, POST | `unbound`, `unbound_domains`, `unbound_dots` | DNS overrides and forwarding |
| GET, POST | `dhcp`, `dhcp_subnet`, `wg` | Kea reservations/subnets and WireGuard peers |

The new management routes additionally require `plugins.manage` for POST and explicit `read_only:false`. Update/delete use POST actions with UUID and original revision; they are not HTTP PUT/DELETE endpoints. See [full management contract](FIREWALL_MANAGEMENT.md).

Requests to OPNsense use API key/secret Basic authentication over HTTPS. Native DNAT is `/api/firewall/d_nat/*`; rules use `/api/firewall/filter/*`; aliases use `/api/firewall/alias/*`. Availability and permissions are reported separately. The new routes observe HA propagation rather than invoking an unsupported core sync action.
