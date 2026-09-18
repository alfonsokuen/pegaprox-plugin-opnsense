"""Static checks for the Overview UI HTML.

We don't render the page in a real browser here — that requires a Flask
host and Playwright. These checks catch obvious regressions: the file
parses, the script is type=module, the table headers are present, the
banned design tells aren't sneaking back in.
"""
from __future__ import annotations

import pathlib
import re
from html.parser import HTMLParser


HTML_PATH = pathlib.Path(__file__).parent.parent / "opnsense.html"


class _MinimalParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.errors: list[str] = []
        self.tags: list[str] = []
        self.has_module_script = False
        self.has_viewport_meta = False
        self.has_color_scheme_meta = False
        self.selected_tabs = 0

    def error(self, message: str) -> None:  # pragma: no cover - parser API
        self.errors.append(message)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append(tag)
        attr_dict = {k: v for k, v in attrs}
        if tag == "button" and attr_dict.get("role") == "tab" and attr_dict.get("aria-selected") == "true":
            self.selected_tabs += 1
        if tag == "script" and attr_dict.get("type") == "module":
            self.has_module_script = True
        if tag == "meta":
            if attr_dict.get("name") == "viewport":
                self.has_viewport_meta = True
            if attr_dict.get("name") == "color-scheme":
                self.has_color_scheme_meta = True


def _content() -> str:
    return HTML_PATH.read_text(encoding="utf-8")


def test_html_parses_without_errors():
    p = _MinimalParser()
    p.feed(_content())
    assert not p.errors


def test_html_has_required_meta_and_module_script():
    p = _MinimalParser()
    p.feed(_content())
    assert p.has_viewport_meta, "missing viewport meta"
    assert p.has_color_scheme_meta, "missing color-scheme meta"
    assert p.has_module_script, "main script must be type=module"


def test_html_uses_opnsense_overview_endpoint():
    body = _content()
    # Endpoint resolves under /api/plugins/opnsense/api/overview when served
    # by PegaProx; we only assert the relative path here.
    assert "../api/overview" in body


def test_html_uses_pegaprox_design_tokens():
    body = _content()
    # The plugin must blend with PegaProx's dashboard. Keep the same token
    # names + values lifted from docker_swarm/swarm.html so a future PegaProx
    # palette refresh affects us in lockstep.
    for token in (
        "--accent: #e57000",
        "--bg: #0f1117",
        "--card: #1a1d27",
        "--border: #2a2d3a",
        "--text: #e4e4e7",
        # --muted is bumped to zinc-400 (#a1a1aa) over PegaProx's #71717a so
        # body text on --card clears WCAG AA contrast (4.5:1).
        "--muted: #a1a1aa",
        "--green: #22c55e",
        "--red: #ef4444",
        "--yellow: #eab308",
        "--blue: #3b82f6",
    ):
        assert token in body, f"missing PegaProx token: {token}"


def test_html_supports_theme_query_param():
    body = _content()
    # PegaProx passes ?theme=corp-light|corp-dark when embedding the iframe.
    # The plugin must honour at least the light variant.
    assert "theme-light" in body
    assert 'params.get("theme")' in body or "params.get('theme')" in body


def test_html_avoids_banned_ai_tells():
    body = _content().lower()
    # No gradient text trick.
    assert "background-clip: text" not in body
    assert "-webkit-background-clip: text" not in body
    # No purple-to-blue glow gradient.
    assert "linear-gradient(45deg, purple" not in body


def test_html_respects_reduced_motion():
    body = _content()
    assert "prefers-reduced-motion: reduce" in body
    # The shimmer animation must be cancelled under reduced motion.
    assert re.search(r"prefers-reduced-motion:\s*reduce[^}]*animation:\s*none", body, re.S)


def test_html_includes_aria_landmarks_and_busy_state():
    body = _content()
    assert 'role="banner"' in body
    assert 'aria-busy="true"' in body
    # Refresh button must be accessible (label may be ES or EN).
    assert ('aria-label="Refresh overview"' in body
            or 'aria-label="Refrescar overview"' in body
            or 'aria-label="Refrescar vista"' in body)


def test_html_has_tablist_with_nine_tabs():
    body = _content()
    assert 'role="tablist"' in body, "missing tablist landmark"
    for tab in ("overview", "network", "vpn", "logs", "nat", "firewall", "dns", "dhcp", "wg"):
        assert f'data-tab="{tab}"' in body, f"missing tab: {tab}"
    # Exactly one tab must declare aria-selected="true" in markup
    # (excluding the CSS selector that also contains the same string).
    parser = _MinimalParser()
    parser.feed(body)
    assert parser.selected_tabs == 1


def test_html_uses_per_tab_endpoints():
    body = _content()
    for ep in ("../api/overview", "../api/network", "../api/logs",
               "../api/nat", "../api/one_to_one", "../api/port_forward",
               "../api/rules", "../api/aliases",
               "../api/unbound", "../api/unbound_domains", "../api/unbound_dots",
               "../api/dhcp", "../api/dhcp_subnet", "../api/wg",
               # v1.13.0 — health probe + cluster bar
               "../api/health", "../api/cluster"):
        assert ep in body, f"missing endpoint reference: {ep}"


def test_html_has_cluster_bar_and_render_helpers():
    """v1.13.0 — cluster banner DOM + dual-column render path exist."""
    body = _content()
    assert 'id="cluster-bar"' in body
    assert 'aria-label="Estado del cluster HA"' in body
    assert "renderClusterBar" in body
    assert "renderClusterOverview" in body
    # Frequent refreshes must not replay decorative entrance animations.
    assert "card-stagger-in" not in body
    assert "prepareView" in body


def test_html_has_dns_and_wg_tabs():
    body = _content()
    assert "renderDnsTab" in body
    assert "renderWgTab" in body
    assert "dnsCreate" in body and "dnsDelete" in body
    assert "wgCreate" in body and "wgDelete" in body
    # v1.6.0 — domain overrides in DNS tab
    assert "dnsDomCreate" in body and "dnsDomDelete" in body
    # v1.8.0 — DoT entries in DNS tab
    assert "dnsDotCreate" in body and "dnsDotDelete" in body


def test_html_has_nat_tab_and_form():
    body = _content()
    assert 'data-tab="nat"' in body
    assert "renderNatTab" in body
    assert "natCreate" in body
    assert "natDelete" in body
    # v1.7.0 — 1:1 NAT (BINAT) sub-section under NAT tab
    assert "oneToOneCreate" in body and "oneToOneDelete" in body


def test_html_drilldown_loads_recent_firewall_events():
    body = _content()
    # v1.3.1 — drilldown lazy-loads firewall events filtered by iface.
    assert "fetchLogsForIface" in body
    assert "appendLogsCard" in body


def test_html_has_drilldown_dialog():
    body = _content()
    # Native <dialog> for accessible per-iface modal.
    assert '<dialog id="drilldown"' in body
    assert 'aria-labelledby="dl-title"' in body
    # The iface-link button class is what triggers the drilldown.
    assert "iface-link" in body
    # Body must include both delegated handler and dl-close click hook.
    assert "openDrilldown" in body
    assert "showModal()" in body


def test_html_has_responsive_breakpoints():
    body = _content()
    for px in (1280, 1024, 768):
        assert f"max-width: {px}px" in body, f"missing breakpoint at {px}px"


def _run_javascript(source: str) -> None:
    """Exercise the shipped JS directly, with only network/DOM boundaries stubbed."""
    import shutil
    import subprocess
    import pytest

    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js is required for UI concurrency checks")
    result = subprocess.run([node, "--input-type=module"], input=source,
                            text=True, capture_output=True, timeout=15)
    assert result.returncode == 0, result.stderr


def test_flat_production_health_is_accepted_only_for_health_endpoint():
    body = _content()
    helpers = body[body.index("  const legacyAccess"):body.index("  // ---------- shared header")]
    _run_javascript('''
import assert from 'node:assert/strict';
const ENDPOINTS={health:'/health',vpn:'/vpn'};
const payload={plugin:'opnsense',cluster_mode:true,hosts_configured:2};
const fetch=async()=>({ok:true,status:200,json:async()=>payload});
''' + helpers + '''
assert.equal((await fetchJson('/health')).cluster_mode,true);
await assert.rejects(fetchJson('/vpn'));
''')


def test_pending_reads_are_shared_but_never_cached_across_writes():
    body = _content()
    helpers = body[body.index("  const legacyAccess"):body.index("  // ---------- shared header")]
    _run_javascript('''
import assert from 'node:assert/strict';
const ENDPOINTS = {nat: '/nat'};
let calls = [];
globalThis.fetch = (url, options) => new Promise(resolve => calls.push({url, options, resolve}));
const response = data => ({ok:true, status:200, json:async()=>({ok:true,data})});
''' + helpers + '''
const first = fetchJson('/nat'), shared = fetchJson('/nat');
assert.equal(first, shared); assert.equal(calls.length, 1);
calls[0].resolve(response({read_only:false})); await first;
assert.equal(legacyCan('nat'), true);
const fresh = fetchJson('/nat'); assert.equal(calls.length, 2);
calls[1].resolve(response({read_only:true})); await fresh;
assert.equal(legacyCan('nat'), false);
const obsolete = fetchJson('/nat');
const staleCheck = assert.rejects(obsolete, /obsoleta/);
fetchWrite('/nat', {method:'POST'});
const afterWrite = fetchJson('/nat'); assert.equal(calls.length, 5);
calls[2].resolve(response({read_only:false})); await staleCheck;
calls[4].resolve(response({read_only:true})); await afterWrite;
assert.equal(legacyCan('nat'), false);
const old = fetchJson('/nat');
const oldCheck = assert.rejects(old, /obsoleta/);
fetchWrite('/nat', {method:'POST'});
const current = fetchJson('/nat');
calls[7].resolve(response({read_only:false})); await current;
assert.equal(legacyCan('nat'), true);
calls[5].resolve(response({read_only:true})); await oldCheck;
assert.equal(legacyCan('nat'), true, 'obsolete result must not erase current authorization');
''')


def test_tab_navigation_does_not_wait_for_cluster_or_accept_old_render():
    body = _content()
    loader = body[body.index("  async function loadCurrentTab()"):body.index("  function schedulePolling()")]
    _run_javascript('''
import assert from 'node:assert/strict';
let currentTab='overview', activeLoad=null, loadSequence=0;
const managedBusy=()=>false;
const cluster={enabled:true}; const ENDPOINTS={cluster:'/cluster'};
let resolveHealth; const clusterBoot=new Promise(resolve=>resolveHealth=resolve);
const pending={}; const fetchJson=url=>new Promise(resolve=>pending[url]=resolve);
const rendered=[]; const grid={setAttribute(){},replaceChildren(...nodes){rendered.push(...nodes)}};
const button={setAttribute(){}}; const $=selector=>selector==='#grid'?grid:button;
const prepareView=()=>{}, renderHeader=()=>{}, ingestInterfaces=()=>{}, renderClusterBar=()=>{};
const renderClusterOverview=()=>['cluster']; const renderError=error=>{throw error};
const TAB_CONFIG={overview:{endpoint:'/overview'},network:{endpoint:'/network',render:()=>['network']},vpn:{endpoint:'/vpn',render:()=>['vpn']}};
''' + loader + '''
const overview=loadCurrentTab();
currentTab='network'; const network=loadCurrentTab();
assert.ok(pending['/network'], 'network starts while health is pending');
pending['/network']({}); await network; assert.deepEqual(rendered,['network']);
resolveHealth(); await overview; assert.equal(pending['/cluster'],undefined);
currentTab='overview'; const slow=loadCurrentTab(); await Promise.resolve();
assert.ok(pending['/cluster']);
currentTab='vpn'; const vpn=loadCurrentTab(); pending['/vpn']({}); await vpn;
pending['/cluster']({}); await slow;
assert.deepEqual(rendered,['network','vpn']); assert.equal(button.disabled,false);
''')


def test_detail_failure_preserves_draft_and_stale_editor_blocks_delete():
    body = _content()
    handlers = body[body.index("  async function managedDetail("):body.index("  function managedSections(")]
    _run_javascript('''
import assert from 'node:assert/strict';
const ENDPOINTS={rules:'/rules'}, managedSpecs={rules:{tab:'firewall',title:'Rules',fields:[],defaults:{}}};
const state={draft:{description:'unsaved'},dirty:true,uuid:'id',revision:'old',loaded:true,readOnly:false,capabilities:{update:true,delete:true}};
const managedState={rules:state}; const currentTab='firewall';
const managedBusy=()=>state.busy;
const managedCan=(key,action)=>!state.readOnly && state.capabilities[action];
const renderManagedTab=()=>{}, managedFocus=()=>{};
const document={getElementById:()=>null}; let confirms=0,writes=0;
const confirm=()=>{confirms++;return true};
let fetchJson=async()=>{throw new Error('detail unavailable')};
let fetchWrite=async()=>{writes++;throw new Error('unexpected write')};
const managedList=async()=>{};
''' + handlers + '''
await managedEdit('rules',{uuid:'id',editable:true});
assert.equal(state.draft.description,'unsaved'); assert.equal(state.revision,'old');
assert.equal(state.dirty,true); assert.match(state.error,/detail unavailable/);
fetchJson=async()=>({read_only:false,capabilities:{delete:true},item:{uuid:'id',revision:'new',editable:true}});
confirms=0; await managedWrite('rules','delete','id');
assert.match(state.error,/cambió/); assert.equal(confirms,0); assert.equal(writes,0);
assert.equal(state.draft.description,'unsaved'); assert.equal(state.busy,false);
state.uuid='another-entry'; let sent;
fetchWrite=async(url,options)=>{
  assert.equal(confirms,1); sent=JSON.parse(options.body); writes++;
  return {ok:true,json:async()=>({ok:true,data:{verified:true,applied:true}})};
};
await managedWrite('rules','delete','id');
assert.equal(sent.revision,'new'); assert.equal(sent.uuid,'id'); assert.equal(writes,1);
assert.equal(state.draft.description,'unsaved');
''')


def test_legacy_write_failure_keeps_error_and_draft_without_refresh():
    body = _content()
    for key in ("nat", "oneToOne", "dns", "dnsDom", "dnsDot", "dhcp", "dhcpSubnet", "wg"):
        start = body.index(f"  async function {key}Create()")
        end = body.index("\n  }", start) + len("\n  }")
        handler = body[start:end]
        endpoint = {"dns": "unbound", "dnsDom": "unboundDomains", "dnsDot": "unboundDots"}.get(key, key)
        form = "natFormState" if key == "nat" else key + "Form"
        tab = {"oneToOne": "Nat", "nat": "Nat", "dns": "Dns", "dnsDom": "Dns", "dnsDot": "Dns",
               "dhcp": "Dhcp", "dhcpSubnet": "Dhcp", "wg": "Wg"}[key]
        listing = "dhcp" if key == "dhcpSubnet" else key
        _run_javascript(f'''
import assert from 'node:assert/strict';
const ENDPOINTS={{{endpoint}:'/write'}};
let {key}Busy=false, {key}Error='', {form}={{description:'keep draft'}};
let refreshes=0; const {listing}List=async()=>{{refreshes++; {key}Error=''}};
const render{tab}Tab=()=>{{}}; const legacyCan=()=>true;
const fetchWrite=async()=>({{json:async()=>({{ok:false,detail:'upstream validation failure'}})}});
{handler}
await {key}Create();
assert.equal({key}Error,'upstream validation failure');
assert.equal({form}.description,'keep draft'); assert.equal(refreshes,0);
assert.equal({key}Busy,false);
''')


def test_legacy_checkbox_and_ip_family_preserve_typed_values():
    body = _content()
    helper = body[body.index("  function legacyInput("):body.index("  function crudForm(")]
    _run_javascript('''
import assert from 'node:assert/strict';
const document={createElement:tag=>({tag,style:{},children:[],handlers:{},
  appendChild(child){this.children.push(child)},setAttribute(){},
  addEventListener(event,handler){this.handlers[event]=handler}})};
const el=(tag,props)=>({...props,tag});
const asBool=value=>value===true || value===1 || value==='1';
''' + helper + '''
const draft={enabled:true,ipprotocol:'inet'};
const checkbox=legacyInput({key:'enabled',type:'checkbox',label:'Habilitado'},draft);
assert.equal(checkbox.checked,true); checkbox.checked=false; checkbox.handlers.input();
assert.equal(draft.enabled,false);
assert.equal(legacyInput({key:'enabled',type:'checkbox'},draft).checked,false);
const select=legacyInput({key:'ipprotocol',options:[['inet','IPv4'],['inet6','IPv6']]},draft);
assert.equal(select.tag,'select'); assert.equal(select.value,'inet');
assert.deepEqual(select.children.map(option=>option.value),['inet','inet6']);
select.value='inet6'; select.handlers.input(); assert.equal(draft.ipprotocol,'inet6');
assert.equal(JSON.parse(JSON.stringify(draft)).enabled,false);
''')
