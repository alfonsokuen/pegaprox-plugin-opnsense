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

Production write authorization and existing HA policy are unchanged.

## Final corrections and QA

The expanded production checks exposed native WireGuard field names and mixed interface/peer rows, plus mobile layout defects. These were reproduced with browser/collector regressions and corrected in 1.16.1–1.16.3. A no-overflow assertion alone was insufficient: visual inspection found a 34 px summary card, so the regression also requires a readable width. Wide tables now scroll inside their cards.

- Full suite after the collector correction: **478 passed, 19 skipped**. Final CSS-only changes: **47 affected UI tests passed, including 25 browser cases**. Ruff and whitespace checks pass. An earlier UI run reported failures and stalled; it was interrupted, not counted as successful. A complete repeat passed; no product change was made to conceal that interrupted run.
- Independent Codex and actual Fable CLI reviews approved the runtime deltas. Shared artifact hashes: `1fe7f656c31b3e4ef702be7deb39a33cc9ffcdf96d1f5e35eaf8750d221eaf73` (1.16.1), `047e7cb5665d198ac90ca697b4c61a4cfe711cfc1c6c439424392ff051f7be5e` (1.16.2), `c6054dfe6fd208edb1d9d75c545c6f2be3832ae5324745359bc439aed3422b41` (1.16.3).
- Fable's final overlay-clipping concern was checked in the actual HTML: the only absolute-positioned element is the visually hidden utility; the interface drilldown is a native `dialog` outside the grid, opened with `showModal()`. There are no in-card custom dropdown overlays. Native selects retain browser rendering. Final UI suite satisfies the reviewers' test condition.
- WireGuard live checks verify real peer counts, native public-key prefixes, online state, counters and handshake age. IPsec/OpenVPN inventories are empty in this installation; their nonempty rendering is covered by fixtures, not claimed as live tunnel qualification.
- Reused production data with the candidate CSS in Chromium: all nine tabs at 390 px had page width 390 px, no page overflow and readable cards. This check made GET requests only.

Performance is qualified for the current small inventory and a single viewer. Five network sessions per refresh are bounded and closed, but this is not a concurrent-user capacity test. The default full-list API retains canonical details and its previous per-row requests; the UI selects the new summary route.

## Deployed result

**1.16.3**, runtime commit `825621a6c8a532e8417b24c708f99c3d87d8cbb3`, deployed and verified: 49 runtime file hashes match the release; configuration is unchanged; the service is active with no post-restart tracebacks. Gitea is the canonical remote and the GitHub mirror matches. Production remains `read_only:true`.

Authenticated HTTP timings below compare one pre-change observation with the median of three final observations. Ranges retain the slower first requests; these are observations, not latency guarantees.

| UI data | Before (s) | After median (s) | After range (s) | Reduction |
|---|---:|---:|---:|---:|
| Aliases | 2.975 | 0.582 | 0.540–1.598 | 80% |
| Filter rules | 1.108 | 0.846 | 0.684–0.928 | 24% |
| Destination NAT | 1.221 | 0.463 | 0.431–0.475 | 62% |
| Network | 3.326 | 0.973 | 0.831–1.127 | 71% |

Dedicated VPN data: median 1.480 s, range 1.472–2.543 s; no directly comparable working VPN baseline. Browser tab timing also includes rendering and concurrent cluster reads, so it is not interchangeable with the HTTP table.

Final deployed Chromium smoke passed all nine tabs on desktop and at 390 px: Overview, Network, VPN, Logs, NAT, Firewall, DNS, DHCP and WG peers. Both HA columns and the cluster bar are visible; no JavaScript errors, failed plugin HTTP requests or page overflow. Real WireGuard fields render, and write controls remain disabled with explanatory read-only notices. All browser plugin requests were GET. No production firewall object was changed.

Availability refers to the plugin's existing supported functions, not full OPNsense or AdmixCentral feature parity. Mutation permissions, existing legacy writer limitations and production HA policy are not expanded by this release.
