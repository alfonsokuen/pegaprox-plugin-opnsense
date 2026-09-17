# Firewall management, v1.15.0

Native Python implementation using the official OPNsense API. AdmixCentral informed the feature comparison; this plugin does not embed it or require its PHP stack.

## Routes and access

All paths use `/api/plugins/opnsense/api/` as prefix. `GET port_forward`, `GET rules`, `GET aliases` return an `ok` envelope with `data.rules` or `data.aliases`, `total`, `read_only`, `supported` and capabilities. Automatic/non-editable objects have `editable:false`. Editable rows contain canonical values retrieved from the object's detail endpoint. Sensitive alias credentials are omitted.

`POST` to the same paths accepts `action: create|update|delete`. Update/delete require a canonical UUID and the original row's `revision` hash. A stale revision returns 409 before mutation; reopen the object after reviewing its current state. Creation/update require `rule` or `alias`. PUT/DELETE methods are not accepted. PegaProx authenticates the session; writes additionally require its `plugins.manage` permission and explicit `read_only:false` in the plugin config. HTTP headers supplied by users cannot select the audit actor.

Example (documentation addresses only):

```json
{
  "action": "create",
  "rule": {
    "interface": "wan",
    "ipprotocol": "inet",
    "protocol": "tcp",
    "source_net": "192.0.2.0/24",
    "source_port": "",
    "destination_net": "wanip",
    "destination_port": "8443",
    "target": "198.51.100.10",
    "target_port": "443",
    "description": "Application HTTPS",
    "enabled": false,
    "filter_association": "",
    "log": true,
    "sequence": 1
  }
}
```

DNAT association is explicit: empty leaves filtering to separately managed rules; `pass` or `rule` selects the native OPNsense option. Do not assume translation alone permits traffic. Rules use the existing `RuleInput` fields plus logging/quick; aliases use name/type/content/description/enabled/proto.

## Outcome guarantees and limits

- Update/delete compare the original revision against a fresh read under a local process lock. Locks are per resolved host and resource within one process; they do not serialize across failover or multiple processes. External OPNsense actors can still race the subsequent write because the server API has no conditional-write/CAS primitive.
- HA readback defaults to six attempts with 0.5-second increasing backoff (7.5 seconds total waiting, plus request time). Configure `ha_verify_attempts` (1-10) and `ha_verify_backoff` (0-2 seconds). Enable the relevant XMLRPC synchronization sections in OPNsense.
- Audit intent is persisted before mutation. Mutating POSTs are never automatically retried.
- A successful HTTP status is insufficient: JSON acknowledgement and validation errors are checked, apply/reconfigure is checked, then stored fields are read back.
- A failed create can be compensated only when the outcome is definite and the created UUID is known. The response reports whether rollback was attempted and verified. Updates/deletes and ambiguous timeouts require reconciliation; there is no blanket rollback guarantee.
- `data.verified` concerns stored configuration, not packet delivery. `data.applied` reports successful apply acknowledgement. If peer verification fails, the request reports partial local success as an error with sync details, not a green success.
- HA writes require a fresh unambiguous master/backup pair with identical VIP sets. Mixed ownership, maintenance mode, missing peers or more than two nodes are blocked.
- The new routes observe OPNsense's configured automatic HA propagation by reading the actual peer. They do not restart unrelated services or call `core/hasync/syncTo`, which is absent from the official 26.1.2 core controller. Legacy routes share the permission, read-only and fresh CARP gates, but their apply/sync/readback behavior has not been migrated to the new verified writer.

Missing or invalid `read_only` values fail closed; enabling writes requires JSON boolean `false`. A create with uncertain acceptance blocks another create until explicit reconciliation in the UI.

The production deployment can remain read-only. A deployment does not authorize firewall traffic changes or disable this setting.

## Validation

```powershell
python -m pip install -r requirements-e2e.txt
python -m playwright install chromium
python -m pytest -q
ruff check src tests
$env:RUN_LOCAL_E2E='1'
python -m pytest tests/test_firewall_e2e.py -v
```

Local E2E uses the real browser, Flask handlers, writers and HTTPS client against a stateful simulator. It is not evidence of a hardware firewall round-trip. Live production smoke must preserve configuration and exercise only reads and blocked writes. For live write qualification, use a positively identified isolated lab and verify actual packet forwarding, filter association, cleanup and HA propagation before enabling production writes.

Primary contracts: [firewall API](https://docs.opnsense.org/development/api/core/firewall.html), [26.1.2 DNAT controller](https://github.com/opnsense/core/blob/26.1.2/src/opnsense/mvc/app/controllers/OPNsense/Firewall/Api/DNatController.php), [core API](https://docs.opnsense.org/development/api/core/core.html).
