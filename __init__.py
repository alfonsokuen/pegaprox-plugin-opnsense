# -*- coding: utf-8 -*-
"""
OPNsense Manager — PegaProx Plugin
Monitor and configure OPNsense firewalls from PegaProx.

Talks to OPNsense REST API (/api/<module>/<controller>/<action>) using API
key + secret over HTTPS. HA-aware: can target an active VIP or both peer
nodes (NODOA/NODOB) and surface divergence.

Features (v1 scope — see PLUGIN_BRIEF.md):
  - Overview: HA role, throughput, gateways, VPN peers, certs, services
  - Interfaces: per-iface stats with sparklines
  - Rules / Aliases / NAT (CRUD)
  - DHCP static mappings
  - Unbound host/domain overrides
  - WireGuard peers (CRUD)
  - Apply config + sync HA + post-sync verify
  - Audit log of every write
  - Prometheus /metrics exporter
"""

import os
import json
import logging
import threading

# These imports only resolve inside a PegaProx host. Guard them so the
# package can still be imported in unit-test / linting contexts without
# pulling in PegaProx internals.
try:  # pragma: no cover - exercised only on PegaProx hosts
    from flask import request, jsonify  # noqa: F401
    from pegaprox.api.plugins import register_plugin_route
    from pegaprox.utils.audit import log_audit  # noqa: F401
except ImportError:  # pragma: no cover
    register_plugin_route = None  # type: ignore[assignment]

PLUGIN_ID = 'opnsense'
PLUGIN_NAME = 'OPNsense Manager'
PLUGIN_DIR = os.path.dirname(os.path.abspath(__file__))
STATE_DIR = os.path.join(PLUGIN_DIR, 'state')
CONFIG_PATH = os.path.join(PLUGIN_DIR, 'config.json')

log = logging.getLogger(f'plugin.{PLUGIN_ID}')

# In-memory cache (short TTL — near-realtime feel for the overview view)
_cache = {}
_cache_lock = threading.Lock()
CACHE_TTL_FAST = 5      # overview / realtime tab
CACHE_TTL_SLOW = 30     # background poll for sidebar health chip
CACHE_TTL_COLD = 300    # certs, services list, routes

# Background polling thread
_bg_thread = None
_bg_stop = threading.Event()


def _load_config():
    """Load plugin config from CONFIG_PATH (JSON). Returns dict with defaults."""
    if not os.path.exists(CONFIG_PATH):
        return {'opnsense_hosts': [], 'poll_interval': 30, 'read_only': False}
    try:
        with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        log.error('Failed to load config: %s', e)
        return {'opnsense_hosts': [], 'poll_interval': 30, 'read_only': False}


def _first_host_from_config():
    """Build an OPNsenseHost dataclass from the first entry in config.json.

    Imported lazily so unit tests of routes don't need a config file present.
    """
    from src.client import OPNsenseHost  # local import to keep top-level light
    cfg = _load_config()
    hosts = cfg.get('opnsense_hosts') or []
    if not hosts:
        return None
    h = hosts[0]
    return OPNsenseHost(
        name=str(h.get('name', 'opnsense')),
        url=str(h.get('url', '')),
        api_key=str(h.get('api_key', '')),
        api_secret=str(h.get('api_secret', '')),
        verify_tls=bool(h.get('verify_tls', True)),
        ca_bundle_path=h.get('ca_bundle_path') or None,
    )


# ---------------------------------------------------------------------------
# Plugin registration entry point
# ---------------------------------------------------------------------------
# PegaProx 0.9.9.3+ calls register() on plugin load. Routes are scaffold
# stubs — real handlers land in src/routes/ and are wired here in v1.0.0.

def register():
    if register_plugin_route is None:
        raise RuntimeError(
            'PegaProx framework not available — register() must run inside a PegaProx host'
        )
    log.info('%s v0.5.0 loading', PLUGIN_NAME)
    os.makedirs(STATE_DIR, exist_ok=True)

    from flask import jsonify  # local import to keep top-level test-safe
    from src.routes import build_overview_payload  # noqa: WPS433 — host-only

    @register_plugin_route(PLUGIN_ID, '/api/health', methods=['GET'])
    def _health():
        cfg = _load_config()
        return jsonify({
            'plugin': PLUGIN_ID,
            'version': '0.5.0',
            'configured': bool(cfg.get('opnsense_hosts')),
            'read_only': cfg.get('read_only', False),
        })

    @register_plugin_route(PLUGIN_ID, '/api/ui', methods=['GET'])
    def _ui():
        from flask import send_file
        return send_file(os.path.join(PLUGIN_DIR, 'opnsense.html'))

    @register_plugin_route(PLUGIN_ID, '/api/overview', methods=['GET'])
    def _overview():
        host = _first_host_from_config()
        if host is None:
            return jsonify({'ok': False, 'error': 'unconfigured',
                            'detail': 'No opnsense_hosts in config.json — '
                                      'edit it via Settings tab.'}), 400
        status, payload = build_overview_payload(host)
        return jsonify(payload), status

    @register_plugin_route(PLUGIN_ID, '/metrics', methods=['GET'])
    def _metrics():
        from flask import Response
        from src.client import OPNsenseClient
        from src.metrics import render_metrics
        host = _first_host_from_config()
        if host is None:
            return Response(
                "# opnsense plugin: no opnsense_hosts configured\n"
                "opnsense_up{host=\"unknown\"} 0\n",
                mimetype="text/plain; version=0.0.4",
            )
        try:
            body = render_metrics(OPNsenseClient(host), host_label=host.name)
        except Exception as e:
            body = (f"# opnsense plugin: render_metrics failed: {e}\n"
                    f"opnsense_up{{host=\"{host.name}\"}} 0\n")
        return Response(body, mimetype="text/plain; version=0.0.4")

    log.info('%s registered', PLUGIN_NAME)


def unregister():
    log.info('%s unloading', PLUGIN_NAME)
    _bg_stop.set()
