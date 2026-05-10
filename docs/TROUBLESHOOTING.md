# Troubleshooting

## "Not configured" health
- `config.json` does not list any `opnsense_hosts`. Edit it or use the Settings tab.

## TLS errors (self-signed)
- Set `verify_tls: false` only for lab. In prod set `ca_bundle_path` to a PEM containing the OPNsense CA.

## 401 Unauthorized
- Wrong `api_key`/`api_secret`. OPNsense uses `Authorization: Basic base64(key:secret)`.
- The OPNsense user has the API keys revoked or lacks the privilege for the endpoint.

## Apply succeeds but config not visible
- Always pair CRUD with the corresponding `reconfigure` / `apply` call. Plugin tests guard this for known modules; if you add a new writer, add the reconfigure step or the test will block release.

## HA sync 200 OK but peer divergent
- `syncTo` may return success with partial sync. After every write the plugin re-fetches the affected section's hash on both peers and surfaces divergence in the UI.

## Plugin tab missing
- PegaProx version < 0.9.9.3 → the native plugin frontend hook (PR #381) is not present. Upgrade PegaProx.
- DB row missing in `plugin_state` → run `Settings > Plugins > Rescan > Enable` in PegaProx UI.

## Logs
```bash
journalctl -u pegaprox -f | grep plugin.opnsense
```
