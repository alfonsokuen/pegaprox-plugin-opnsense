# Firewall management, v1.15.2

Native Python implementation using the official OPNsense API. AdmixCentral informed the feature comparison; this plugin does not embed it or require its PHP stack.

## Routes and access

All paths use `/api/plugins/opnsense/api/` as prefix. `GET port_forward`, `GET rules`, `GET aliases` return an `ok` envelope with `data.rules` or `data.aliases`, `total`, `read_only`, `supported` and capabilities. Automatic/non-editable objects have `editable:false`. Editable rows contain canonical values retrieved from the object's detail endpoint. Sensitive alias credentials are omitted.

### Listing scale boundary

Each listing performs one search plus one sequential detail request per editable object (N+1). Detail reads supply canonical values and revision hashes; the release does not implement pagination or lazy editor loading. Only small inventories have been qualified. There is no measured safe maximum or latency guarantee for hundreds of objects: network timeouts and read retries can occupy a worker for minutes. Measure listing latency on the intended inventory before adoption; large or slow inventories require a paginated/lazy-detail implementation first. If an object disappears between search and detail, the complete request fails with an upstream error; refresh after concurrent changes settle. Do not interpret this as an empty inventory.

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

- Update/delete compare the original revision against a fresh read under a local process lock shared by the three resources for the configured pair. Locks do not serialize multiple processes. External OPNsense actors can still race the subsequent write because the server API has no conditional-write/CAS primitive.
- HA readback defaults to six attempts with 0.5-second increasing backoff (7.5 seconds total waiting, plus request time). Configure `ha_verify_attempts` (1-10) and `ha_verify_backoff` (0-2 seconds). Enable the relevant XMLRPC synchronization sections in OPNsense.
- Audit intent is persisted before mutation. Mutating POSTs are never automatically retried.
- A successful HTTP status is insufficient: JSON acknowledgement and validation errors are checked, apply/reconfigure is checked, then stored fields are read back.
- A failed create can be compensated only when the outcome is definite and the created UUID is known. The response reports whether rollback was attempted and verified. Updates/deletes and ambiguous timeouts require reconciliation; there is no blanket rollback guarantee.
- `data.verified` concerns stored configuration, not packet delivery. `data.applied` reports successful apply acknowledgement. If peer verification fails, the request reports partial local success as an error with sync details, not a green success.
- Readback does not prove durable storage across immediate power loss. OPNsense 26.1.2 saves with `fflush`, not `fsync`; the lab's ZFS transaction interval was 90 seconds. An immediate hard stop lost recent local changes while the peer retained them. Power-loss qualification must distinguish this upstream storage behavior from CARP failover after a storage barrier.
- HA writes require a fresh unambiguous master/backup pair with identical VIP sets. Mixed ownership, maintenance mode, missing peers or more than two nodes are blocked.
- Default `ha_sync_mode: "automatic"` only observes independently configured synchronization. OPNsense 26.1.2 apply/reconfigure does **not** itself trigger XMLRPC; selecting synchronization sections alone is insufficient. Use the explicit mode below when its constraints match the pair. Legacy routes share the permission, read-only and fresh CARP gates, but their apply/sync/readback behavior has not been migrated to the new verified writer.

## Explicit XMLRPC synchronization

Set `ha_sync_mode: "xmlrpc_pf"` only for a qualified pair. The plugin invokes the native `core/hasync_status/restart/pf` action once after local apply and readback, then verifies the object on the actual peer. That action copies **all selected XMLRPC sections**, regenerates peer templates and reloads PF. Native XMLRPC also reconfigures routing and resolver settings; this is not a PF-only side effect. It does not invoke the restart-all-services action.

Requirements checked before mutation and again before the trigger:

- The selected master has a literal peer IP (or HTTPS URL with a literal IP) as its XMLRPC target. It must belong exclusively to the peer's interface addresses, excluding CARP VIPs. DNS names and credential-bearing URLs are rejected.
- The peer has no reverse XMLRPC target. The required section is selected (`aliases`, `rules`, or `nat`), and the selection contains only those three firewall sections. Broader selections are rejected rather than changed by the plugin.
- All CARP VIPs match and remain MASTER locally/BACKUP remotely. A failover does not reverse XMLRPC automatically. Management writes remain blocked until the configured primary is safely restored.
- A DISABLED VIP also blocks management writes, even when disabled on both nodes; the gate deliberately requires every VIP to have the expected active role.

A changed direction/scope or failed/uncertain trigger returns a partial result; it does not remove an already applied create. The OPNsense trigger acknowledgement cannot prove synchronization by itself, so peer readback remains mandatory. The checks cannot eliminate a race with external administrators between API requests.

OPNsense 26.1.2 XMLRPC preserves the final peer DNAT when the primary's `nat/rule` branch disappears. For this case only, the plugin can delete that exact UUID directly on the peer after normal synchronization and polling. Before local deletion both nodes must contain exactly that one real DNAT with identical canonical revisions. Before peer cleanup the primary must be empty and the peer must still contain only that unchanged UUID, with HA checks still valid. The response and audit report `sync.peer_cleanup`; one peer delete and one acknowledged apply are followed by absence verification on both nodes. Ambiguous failures are not retried. Unknown grid rows, divergence or concurrent edits block cleanup.

The normal bounded polling window is retained before direct peer cleanup to allow native convergence first. Real lab qualification also covered deleting the sole editable alias and the sole API filter rule: both converged without direct peer cleanup. These results apply to the tested firmware; a future non-convergent alias/filter deletion returns `ha_unverified` and requires reconciliation against both nodes, without automatic retry or generalized peer deletion.

Native contracts: [HA action controller](https://github.com/opnsense/core/blob/26.1.2/src/opnsense/mvc/app/controllers/OPNsense/Core/Api/HasyncStatusController.php), [XMLRPC section synchronization](https://github.com/opnsense/core/blob/26.1.2/src/etc/rc.filter_synchronize).

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
