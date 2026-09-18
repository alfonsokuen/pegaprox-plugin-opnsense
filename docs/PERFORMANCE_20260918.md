# Response time and feature availability

## Design and scope

Improve the existing plugin without changing firewall configuration, HA synchronization policy or production read-only mode. The feature inventory is the plugin's exposed API and UI, not every OPNsense/AdmixCentral module.

- The UI requests a summary list with one upstream search. Canonical detail and optimistic revision are fetched only when opening an editor or preparing a confirmed delete. The default full-list API remains compatible.
- Browser GETs share only concurrent requests. No durable read cache can conceal changes or reuse write authorization. Tab navigation must not wait for unrelated slow requests or render outdated responses.
- VPN has a dedicated endpoint, independent of the cluster overview envelope. Existing services, certificate and VPN data remain visible in cluster mode.
- Network collectors run concurrently, bounded to five independently owned sessions; each session closes after its collector completes. No concurrency is added to mutation operations.
- Known volatile alias traffic counters and timestamps are excluded from optimistic revision hashes. Hidden/advanced configuration fields remain included, preserving stale-edit protection.
- Every management section explains read-only/permission restrictions. Legacy action errors survive successful list refreshes. Unsupported endpoints must remain errors, not successful empty inventories.

## Baseline

Authenticated production sample before changes: aliases 2.975 s, DNAT 1.221 s, rules 1.108 s, network 3.326 s, cluster 2.178 s. These are individual observations, not percentile or load-test guarantees. All existing exposed feature endpoints responded HTTP 200 in that sample. Browser feature checks are separate from endpoint reachability.

## Acceptance

1. A summary list makes one upstream search regardless of object count; editing fetches one canonical detail, retains drafts on failure and preserves revision conflicts.
2. All existing management sections and supported options remain accessible; readonly controls are disabled with a reason.
3. VPN data renders in cluster mode; services and certificates remain inspectable.
4. Existing regression/E2E suite passes, with negative cases for detail failure, stale forms and navigation races.
5. Read-only production benchmark and browser smoke confirm the deployed behavior. No production firewall object is created, edited or removed.

## Verification before rollout

- Full suite with `RUN_LOCAL_E2E=1`: 476 passed, 19 skipped; 23 browser cases included. Skipped tests require separate live/environment prerequisites. Ruff and `git diff --check` pass.
- Legacy form contracts: 14 cases execute the shipped JavaScript, actual builders/writers and intercepted HTTP. Enabled/disabled survives JSON serialization; source NAT preserves IPv4/IPv6 selection. These are contract tests, not live firewall mutations.
- Read-only comparison on the installed OPNsense pair: DNAT 7 rows / 4 editable, filter rules 2 / 2, aliases 22 / 8. Every checked display column matches canonical detail, including enabled state, ports and targets. Summary rendering does not discard those fields.
- Reproduced and fixed the flat-health envelope mismatch, VPN collector/render field mismatch and late GET erasing current permissions. Browser coverage includes both HA columns, partial node data, detail failures, retained drafts, stale revisions, three themes and mobile layout.
- Independent Fable and Codex review uses artifact SHA-256 `5eec533554fe36c31a0b629b3b94fa0c72f8b5f29b5bc9443566ce05eac5d36b`. Initial VPN mismatch was found by both; flat health by Codex; late-read invalidation by Fable. Other Fable concerns were closed with guarded partial data, actual legacy contracts, native column parity and removal of an unused client.

Production rollout and timing results are recorded below after verification. Production write authorization and existing HA policy are unchanged.
