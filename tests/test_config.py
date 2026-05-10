"""config.example.json shape guard."""
import json
import os

PLUGIN_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_config_example_shape():
    with open(os.path.join(PLUGIN_ROOT, 'config.example.json'), 'r', encoding='utf-8') as f:
        cfg = json.load(f)

    assert isinstance(cfg.get('opnsense_hosts'), list)
    assert len(cfg['opnsense_hosts']) >= 1

    for host in cfg['opnsense_hosts']:
        assert host['url'].startswith('https://'), 'OPNsense API must be HTTPS'
        for key in ('name', 'api_key', 'api_secret', 'verify_tls'):
            assert key in host, f'host missing key: {key}'
        assert isinstance(host['verify_tls'], bool)


def test_config_example_no_real_secrets():
    """Belt-and-suspenders: example must contain placeholders, never real keys."""
    with open(os.path.join(PLUGIN_ROOT, 'config.example.json'), 'r', encoding='utf-8') as f:
        raw = f.read()
    assert 'REPLACE_WITH_OPNSENSE_API_KEY' in raw
    assert 'REPLACE_WITH_OPNSENSE_API_SECRET' in raw
