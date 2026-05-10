"""Manifest sanity — guards the plugin contract with PegaProx."""
import json
import os

PLUGIN_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load():
    with open(os.path.join(PLUGIN_ROOT, 'manifest.json'), 'r', encoding='utf-8') as f:
        return json.load(f)


def test_manifest_required_keys():
    m = _load()
    for k in ('name', 'version', 'author', 'description', 'min_pegaprox', 'license'):
        assert k in m, f'manifest missing key: {k}'


def test_manifest_frontend_route_native_hook():
    m = _load()
    assert m.get('has_frontend') is True
    assert m.get('frontend_route') == 'ui'


def test_manifest_min_pegaprox_supports_native_plugin_frontend():
    m = _load()
    parts = tuple(int(x) for x in m['min_pegaprox'].split('.') if x.isdigit())
    assert parts >= (0, 9, 9, 3), 'native plugin frontend hook lands in PegaProx 0.9.9.3'
