# AdmixCentral parity implementation plan

**Goal:** Close and verify functional gaps against AdmixCentral commit `033c676ef730c3276c46fe4959d3adcb02fdccc1`, without claiming advertised or stubbed upstream operations as working parity.

**Architecture:** Extend the native Python plugin, host authentication and existing visual system. Use an explicit resource catalog backed by official OPNsense 26.1.2 controllers/models, a verified management service, and a lazy-loaded administrative workspace. Preserve existing nine views. No browser-supplied upstream paths, local evaluation of configuration or credentials in listings. Native privileged configuration fields (for example Monit commands) remain explicit allowlisted administrative fields sent only to their documented OPNsense API. Separate device features from platform features (fleet/company/pfSense), whose scope is being clarified while common device work proceeds.

**Stack:** Python/Flask host handlers, existing HTTPS client, vanilla JavaScript, pytest and Chromium Playwright. Official source checkout is research only; do not ship or execute upstream application code.

## Work and ownership

- [x] Snapshot main at `3f9433b`, create backup ref and isolated worktree.
- [x] Pin AdmixCentral source and fetch OPNsense 26.1.2 official models/controllers.
- [ ] Inventory actual adapters, UI reachability, unsupported operations and existing coverage.
- [ ] Implement catalog with explicit resource IDs, API paths, fields, sensitive fields and application actions. Catalog owner: inventory worker after research.
- [ ] Implement management engine with canonical detail/revision, field validation, no-retry writes, application acknowledgement, readback, audit and explicit partial outcomes. Engine owner: backend worker.
- [ ] Implement native administrative workspace with search/group navigation, typed editors, details, pagination, clear unsupported/auth/offline states and permission gates. UI owner: frontend worker.
- [ ] Integrate authenticated handlers and fixed asset routes. Integrator owns `__init__.py` and release metadata.
- [ ] Exercise real handlers and HTTPS simulator from browser; fail-closed authorization, validation failure, stale revisions, uncertain writes and failed apply must be observed before completion.
- [ ] Qualify available modules against isolated OPNsense laboratory, distinguishing API contract tests from live functional tests. Production stays read-only.
- [ ] Close additional operations and platform gaps from the inventory; unsupported upstream behavior is documented separately, never replaced by empty-success responses.
- [ ] Independent QA, regression suite, backup/restore verification, release, push and deployed smoke. Do not report full parity while any in-scope capability or required live qualification remains unresolved.

## Shared API contract

Fixed authenticated routes: `catalog`, `manage`, `workspace`, `workspace_js`, `workspace_css`.

- `GET catalog` returns `{ok:true,data:{resources:[public resource metadata],read_only:boolean}}` without querying every firewall module.
- `GET manage?resource=<id>` returns `{ok:true,data:{rows:[],total:N,read_only:boolean}}`; `uuid=<UUID>` returns `{item:{},revision:<sha256>,fields:[]}`; `defaults=1` returns `{item:{},fields:[]}` for the explicit default-object endpoint.
- `POST manage` accepts `{resource,action:create|update|delete,uuid?,revision?,values?:{}}`. Update/delete require a canonical revision. Error responses use `{ok:false,error,detail}` with `partial` and operation stage when a mutation may have occurred. No automatic mutation retry or speculative rollback.
- Resource metadata uses `id,label,group,base,search,get,add,set,delete,key,apply,fields,columns`. Fields use `name,label,kind,required,secret` and optional static options. No live secret values in public metadata or list/detail responses. Blank secret values preserve existing secrets on update.
- Lists use a bounded `rowCount` and page, not detail-per-row requests. Dynamic OPNsense select options come from the default/detail form response. Entity writes preserve unknown current fields on update but accept only catalog fields from the browser.
- Unknown modules, upstream permissions, missing plugins, timeout and malformed responses remain distinct failures. A registered module is not evidence it is supported by the selected firewall.

## Exit evidence

For each capability record source contract, implementation files, positive and negative tests, UI journey and live qualification status. Add a matrix with explicit implemented/partial/unsupported/pending values. Simulation is not real firewall traffic, a saved configuration is not an applied service, and a single-node write is not HA convergence.
