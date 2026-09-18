"""Design contracts against the shipped HTML; read payloads are explicit fixtures.

Reuses the real local HTTP stack and Playwright lifecycle. No production access.
"""
import os
from pathlib import Path
import re

import pytest

pytest_plugins = ["tests.test_firewall_e2e"]
pytestmark = pytest.mark.skipif(os.getenv("RUN_LOCAL_E2E") != "1", reason="set RUN_LOCAL_E2E=1")
THEMES = ("corp-dark", "corp-light", "cloud")
WIDTHS = (390, 768, 1024, 1440)
TABS = ("overview", "network", "vpn", "logs", "nat", "firewall", "dns", "dhcp", "wg")
VERSION = "9.87.6"


def _design_reads(page, *, health=True, can_write=False):
    vpn = {"wireguard_enabled": True, "wireguard_peers": [], "ipsec_phase1": [], "openvpn_sessions": []}
    nodes = {}
    for side, name, role in (("a", "Firewall A", "master"), ("b", "Firewall B", "backup")):
        nodes[side] = {"name": name, "ok": True, "snap": {
            "system": {"name": name, "version": "26.1.2", "uptime": "2 days"},
            "carp": {"enabled": True, "role": role, "vhids": [{"vhid": 1}]},
            "hasync": {"enabled": True},
            "services": {"running": 2, "total": 3, "stopped": 1,
                         "items": [{"name": "unbound", "running": True}, {"name": "test", "running": False}]},
            "certs": {"total": 2, "expiring_soon_count": 1}, "vpn": vpn,
        }}
    cluster = {"master": "Firewall A", "names": {"a": "Firewall A", "b": "Firewall B"},
               "nodes": nodes, "divergence": []}
    page.route("**/api/cluster", lambda route: route.fulfill(json={"ok": True, "data": cluster}))
    page.route("**/api/overview", lambda route: route.fulfill(json={"ok": True, "data": cluster}))
    page.route("**/api/vpn", lambda route: route.fulfill(json={"ok": True, "data": {"vpn": vpn}}))
    page.route("**/api/network", lambda route: route.fulfill(json={"ok": True, "data": {
        "interfaces": [], "gateways": [], "routes": [], "arp": [], "ndp": []}}))
    if health:
        page.route("**/api/health", lambda route: route.fulfill(json={
            "plugin": "opnsense", "version": VERSION, "cluster_mode": True,
            "hosts_configured": 2, "read_only": not can_write, "can_write": can_write,
        }))
    return cluster


def _settled(page):
    from playwright.sync_api import expect

    expect(page.locator("#grid")).to_have_attribute("aria-busy", "false")
    expect(page.locator("#btn-refresh")).to_be_enabled()


def _no_horizontal_page_scroll(page):
    metrics = page.evaluate("""() => ({viewport: innerWidth,
        page: document.documentElement.scrollWidth, body: document.body.scrollWidth})""")
    assert metrics["page"] <= metrics["viewport"] + 1, metrics
    assert metrics["body"] <= metrics["viewport"] + 1, metrics


@pytest.mark.parametrize("theme", THEMES)
@pytest.mark.parametrize("width", WIDTHS)
def test_nine_destinations_and_ha_panels_remain_readable(page, stack, theme, width):
    from playwright.sync_api import expect

    stack.readonly = True
    page.set_viewport_size({"width": width, "height": 1000})
    _design_reads(page)
    page.goto(stack.url + f"/ui?theme={theme}#overview")
    _settled(page)
    expect(page.locator("#plugin-version")).to_contain_text(VERSION)
    expect(page.locator("#access-mode")).to_contain_text(re.compile("solo lectura", re.I))
    expected_class = {"corp-light": "theme-light", "cloud": "theme-cloud"}.get(theme)
    if expected_class:
        expect(page.locator("html")).to_have_class(re.compile(expected_class))
    else:
        expect(page.locator("html")).not_to_have_class(re.compile("theme-light|theme-cloud"))

    tabs = page.get_by_role("tab")
    expect(tabs).to_have_count(9)
    dimensions = tabs.evaluate_all("""elements => elements.map(e => {
        const r=e.getBoundingClientRect(); return {name:e.dataset.tab, x:r.x,
            right:r.right, height:r.height, width:r.width}; })""")
    for tab in dimensions:
        assert tab["height"] >= 44 and tab["width"] >= 44, tab
        assert tab["x"] >= -1 and tab["right"] <= width + 1, tab
    strip = page.get_by_role("tablist")
    assert strip.evaluate("e => e.scrollWidth <= e.clientWidth + 1")

    panels = page.locator(".node-col")
    expect(panels).to_have_count(2)
    for panel in panels.all():
        geometry = panel.evaluate("""e => {
            const r=e.getBoundingClientRect(), s=getComputedStyle(e);
            const inner=e.clientWidth-parseFloat(s.paddingLeft)-parseFloat(s.paddingRight);
            return {width:r.width, inner, head:e.querySelector('.col-head').getBoundingClientRect().width,
              cards:[...e.querySelectorAll(':scope > .card')].map(c=>({
                width:c.getBoundingClientRect().width, right:c.getBoundingClientRect().right,
                compact:c.matches('.node-system, .node-role')})), right:r.right};
        }""")
        assert geometry["inner"] >= 280, geometry
        assert abs(geometry["head"] - geometry["inner"]) <= 2, geometry
        assert len(geometry["cards"]) >= 5, geometry
        for card in geometry["cards"]:
            assert card["width"] >= geometry["inner"] * (0.45 if card["compact"] else 0.9), geometry
            assert card["width"] >= 140, geometry
            assert card["right"] <= geometry["right"] + 1, geometry
    _no_horizontal_page_scroll(page)

    directory = os.getenv("E2E_ARTIFACT_DIR")
    if directory:
        Path(directory).mkdir(parents=True, exist_ok=True)
        page.screenshot(path=str(Path(directory) / f"design-ha-{theme}-{width}.png"),
                        full_page=True, animations="disabled")

    for tab in TABS:
        button = page.locator(f'[data-tab="{tab}"]')
        expect(button).to_be_visible()
        button.click()
        expect(button).to_have_attribute("aria-selected", "true")
        _settled(page)
        expect(page.locator("#grid > .banner")).to_have_count(0)
        if tab != "overview":
            expect(page.locator("#grid > .card")).to_have_count({
                "network": 6, "vpn": 5, "logs": 2, "nat": 6,
                "firewall": 4, "dns": 6, "dhcp": 4, "wg": 2,
            }[tab])
        _no_horizontal_page_scroll(page)
        if tab == "firewall":
            for key in ("firewallRules", "firewallAliases"):
                form = page.locator(f"#{key}-form")
                expect(form.get_by_role("button", name="Crear", exact=True)).to_be_disabled()
                assert form.evaluate("e => !!(e.previousElementSibling?.classList.contains('managed-table'))")
        if tab in ("nat", "dns", "dhcp", "wg"):
            creates = page.locator("#grid").get_by_role("button", name="Crear", exact=True)
            assert creates.count() > 0
            for create in creates.all():
                expect(create).to_be_disabled()
                assert create.evaluate("e => !!e.closest('.card').previousElementSibling?.querySelector('table')")
    assert page.console_errors == []


@pytest.mark.parametrize("theme", THEMES)
def test_theme_text_contrast_keyboard_focus_and_reduced_motion(page, stack, theme):
    from playwright.sync_api import expect

    _design_reads(page)
    page.emulate_media(reduced_motion="reduce")
    page.goto(stack.url + f"/ui?theme={theme}#overview")
    _settled(page)
    # Composite actual backgrounds, including translucent selected tabs/badges.
    # This is a targeted contrast check, not a claim of a complete WCAG audit.
    contrasts = page.locator(
        ".tab, #plugin-version, #access-mode, .col-head h2, .col-head .accent, "
        ".node-col .title, .node-col .sub, .node-col .badge"
    ).evaluate_all("""elements => {
        const rgba=v=>{const n=v.match(/[\\d.]+/g).map(Number); return [n[0],n[1],n[2],n[3]??1];};
        const mix=(a,b)=>a.slice(0,3).map((v,i)=>v*a[3]+b[i]*(1-a[3]));
        const luminance=c=>c.map(v=>{v/=255;return v<=0.04045?v/12.92:((v+0.055)/1.055)**2.4;})
            .reduce((sum,v,i)=>sum+v*[0.2126,0.7152,0.0722][i],0);
        return elements.filter(e=>e.getBoundingClientRect().width&&e.textContent.trim()).map(e=>{
            let chain=[], node=e;
            while(node){chain.unshift(node);node=node.parentElement;}
            let bg=[255,255,255];
            for(const item of chain) bg=mix(rgba(getComputedStyle(item).backgroundColor),bg);
            const style=getComputedStyle(e),fg=mix(rgba(style.color),bg);
            const a=luminance(fg),b=luminance(bg),large=parseFloat(style.fontSize)>=24 ||
                (parseFloat(style.fontSize)>=18.66&&parseInt(style.fontWeight)>=700);
            return {text:e.textContent.trim(),ratio:(Math.max(a,b)+0.05)/(Math.min(a,b)+0.05),
                minimum:large?3:4.5,color:style.color,bg};
        });
    }""")
    assert contrasts
    failures = [row for row in contrasts if row["ratio"] + 0.01 < row["minimum"]]
    assert not failures, failures

    overview = page.locator('[data-tab="overview"]')
    overview.focus()
    overview.press("ArrowRight")
    network = page.locator('[data-tab="network"]')
    expect(network).to_be_focused()
    expect(network).to_have_attribute("aria-selected", "true")
    focus = network.evaluate("""e=>{const s=getComputedStyle(e);return {
        visible:e.matches(':focus-visible'), outline:s.outlineStyle,
        outlineWidth:parseFloat(s.outlineWidth), shadow:s.boxShadow};}""")
    assert focus["visible"] and ((focus["outline"] != "none" and focus["outlineWidth"] >= 2)
                                 or focus["shadow"] != "none"), focus
    _settled(page)
    network.press("End")
    expect(page.locator('[data-tab="wg"]')).to_be_focused()
    _settled(page)
    page.locator('[data-tab="wg"]').press("Home")
    expect(overview).to_be_focused()
    _settled(page)
    animations = page.locator("#grid .card").evaluate_all(
        "elements=>elements.map(e=>getComputedStyle(e).animationName)")
    assert animations and all(name == "none" for name in animations), animations


@pytest.mark.parametrize("state", ["pending", "failed", "denied", "allowed"])
def test_header_discovery_never_invents_write_access(page, stack, state):
    from playwright.sync_api import expect

    _design_reads(page, health=False)
    pending = []
    if state == "pending":
        page.route("**/api/health", lambda route: pending.append(route))
    elif state == "failed":
        page.route("**/api/health", lambda route: route.fulfill(status=503, json={"ok": False}))
    else:
        page.route("**/api/health", lambda route: route.fulfill(json={
            "plugin": "opnsense", "version": VERSION, "cluster_mode": False,
            "hosts_configured": 1, "read_only": False, "can_write": state == "allowed"}))
    page.goto(stack.url + "/ui#network", wait_until="domcontentloaded")
    _settled(page)
    label = page.locator("#access-mode")
    expect(label).to_be_visible()
    if state == "allowed":
        expect(label).to_contain_text(re.compile("escritura", re.I))
    elif state == "denied":
        expect(label).to_contain_text(re.compile("solo lectura|sin permiso de escritura", re.I))
    else:
        expect(label).not_to_have_text(re.compile(r"^\s*$"))
        expect(label).not_to_contain_text(re.compile("escritura habilitada|escritura activa|lectura y escritura", re.I))
    if state in ("allowed", "denied"):
        expect(page.locator("#plugin-version")).to_contain_text(VERSION)
    for route in pending:
        route.fulfill(status=503, json={"ok": False})


@pytest.mark.parametrize("role,available,label", [
    ("master", True, "MASTER"), ("backup", True, "BACKUP"),
    (None, True, "SIN CONFIRMAR"), ("disabled", True, "DESACTIVADO"),
    ("backup", False, "SIN CONEXIÓN"),
])
def test_ha_node_header_uses_observed_role_not_master_inference(page, stack, role, available, label):
    from playwright.sync_api import expect

    cluster = _design_reads(page)
    # Cluster summary still calls A master; B must use its own observed state.
    cluster["nodes"]["b"]["snap"]["carp"]["role"] = role
    cluster["nodes"]["b"]["ok"] = available
    if not available:
        cluster["nodes"]["b"].update(snap=None, error="timeout", detail="Node unavailable")
    page.goto(stack.url + "/ui#overview")
    _settled(page)
    panel = page.locator('.node-col[aria-label="Firewall B"]')
    expect(panel.locator(".col-head .badge")).to_have_text(label)
    if not available:
        expect(panel.locator(".err-card")).to_contain_text("Node unavailable")
    if label != "BACKUP":
        expect(panel.locator(".col-head")).not_to_contain_text("BACKUP")
