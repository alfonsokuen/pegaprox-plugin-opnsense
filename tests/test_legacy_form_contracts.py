"""Shipped form JS -> route -> writer -> intercepted HTTP payload contracts.

Only DOM/network boundaries are stubbed. No live firewall is contacted.
"""
import json
from pathlib import Path
import shutil
import subprocess

import pytest
import responses

from src.client import OPNsenseHost
from src.routes import nat, one_to_one, unbound, wg


HOST = OPNsenseHost(name="contract", url="https://opnsense.test",
                    api_key="test-key", api_secret="test-secret", verify_tls=False)
HTML = Path(__file__).parents[1] / "opnsense.html"
CASES = [
    ("nat", nat.build_nat_action_payload, "rule", "rule", "nat", "Nat",
     {"interface": "wan", "target": "192.0.2.1", "ipprotocol": "inet"},
     "/api/firewall/source_nat/addRule", "/api/firewall/source_nat/apply"),
    ("nat", nat.build_nat_action_payload, "rule", "rule", "nat", "Nat",
     {"interface": "wan", "target": "2001:db8::1", "ipprotocol": "inet6"},
     "/api/firewall/source_nat/addRule", "/api/firewall/source_nat/apply"),
    ("oneToOne", one_to_one.build_one_to_one_action_payload, "rule", "rule", "oneToOne", "Nat",
     {"interface": "wan", "external": "192.0.2.1", "source_net": "198.51.100.1"},
     "/api/firewall/one_to_one/addRule", "/api/firewall/one_to_one/apply"),
    ("dns", unbound.build_unbound_action_payload, "host", "host", "unbound", "Dns",
     {"hostname": "host", "domain": "example.test", "server": "192.0.2.2"},
     "/api/unbound/settings/addHostOverride", "/api/unbound/service/reconfigure"),
    ("dnsDom", unbound.build_unbound_domain_action_payload, "domain", "dot", "unboundDomains", "Dns",
     {"domain": "example.test", "server": "192.0.2.2"},
     "/api/unbound/settings/addForward", "/api/unbound/service/reconfigure"),
    ("dnsDot", unbound.build_unbound_dot_action_payload, "dot", "dot", "unboundDots", "Dns",
     {"domain": "example.test", "server": "192.0.2.2", "verify": "resolver.example.test", "port": "853"},
     "/api/unbound/settings/addForward", "/api/unbound/service/reconfigure"),
    ("wg", wg.build_wg_action_payload, "peer", "client", "wg", "Wg",
     {"name": "contract-peer", "pubkey": "A" * 43 + "=", "tunneladdress": "192.0.2.3/32"},
     "/api/wireguard/client/addClient", "/api/wireguard/service/reconfigure"),
]


def _form_request(key, endpoint, tab, draft, enabled):
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js required to execute shipped form handlers")
    source = HTML.read_text(encoding="utf-8")
    start = source.index(f"  async function {key}Create()")
    handler = source[start:source.index("\n  }", start) + len("\n  }")]
    helper = source[source.index("  function legacyInput("):source.index("  function crudForm(")]
    boolean = next(line for line in source.splitlines() if "const asBool =" in line)
    form = "natFormState" if key == "nat" else key + "Form"
    script = f"""
const ENDPOINTS = {{{json.dumps(endpoint)}: '/write'}};
let {key}Busy = false, {key}Error = '', {form} = {json.dumps(draft)};
const legacyCan = () => true;
const {key}List = async () => {{}};
const render{tab}Tab = () => {{}};
const document = {{createElement: () => ({{style: {{}}, handlers: {{}},
  appendChild() {{}}, setAttribute() {{}},
  addEventListener(event, handler) {{this.handlers[event] = handler;}} }})}};
const el = (tag, props) => props;
{boolean}
{helper}
const checkbox = legacyInput({{key:'enabled',type:'checkbox',label:'Habilitado'}}, {form});
checkbox.checked = {json.dumps(enabled)};
checkbox.handlers.input();
if ({json.dumps(key)} === 'nat') {{
  const family = legacyInput({{key:'ipprotocol',options:['inet','inet6']}}, {form});
  family.value = {json.dumps(draft.get('ipprotocol', 'inet'))};
  family.handlers.input();
}}
let sent;
const fetchWrite = async (url, options) => {{
  sent = options.body;
  return {{json: async () => ({{ok:true}})}};
}};
{handler}
await {key}Create();
if ({key}Error) throw new Error({key}Error);
console.log(sent);
"""
    result = subprocess.run([node, "--input-type=module"], input=script,
                            capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


@pytest.mark.parametrize("enabled", [True, False], ids=["enabled", "disabled"])
@pytest.mark.parametrize("case", CASES, ids=["nat-v4", "nat-v6", "binat", "dns-host", "dns-domain", "dns-dot", "wireguard"])
@responses.activate
def test_form_flags_reach_upstream_payload(tmp_path, case, enabled):
    key, builder, request_key, upstream_key, endpoint, tab, draft, add, apply = case
    body = _form_request(key, endpoint, tab, draft, enabled)
    assert body[request_key]["enabled"] is enabled
    responses.add(responses.POST, HOST.url + add, json={"result": "saved", "uuid": "contract-id"})
    responses.add(responses.POST, HOST.url + apply, json={"status": "ok"})

    code, result = builder(HOST, str(tmp_path), body)

    assert code == 200 and result["ok"], result
    assert [call.request.url for call in responses.calls] == [HOST.url + add, HOST.url + apply]
    sent = json.loads(responses.calls[0].request.body)[upstream_key]
    if key == "nat":
        assert sent["disabled"] == ("0" if enabled else "1")
        assert sent["ipprotocol"] == draft["ipprotocol"]
        assert sent["target"] == draft["target"]
    else:
        assert sent["enabled"] == ("1" if enabled else "0")
    if key in ("dnsDom", "dnsDot"):
        assert sent["type"] == ("forward" if key == "dnsDom" else "dot")
