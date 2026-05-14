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
import sys
import json
import logging
import threading

PLUGIN_ID = 'opnsense'
PLUGIN_NAME = 'OPNsense Manager'
PLUGIN_DIR = os.path.dirname(os.path.abspath(__file__))
STATE_DIR = os.path.join(PLUGIN_DIR, 'state')
CONFIG_PATH = os.path.join(PLUGIN_DIR, 'config.json')

# PegaProx imports plugin packages via importlib without adding their
# directory to sys.path, so absolute `from src.X import Y` calls inside
# the plugin would fail with `No module named 'src'`. Inject the plugin
# directory ourselves so `src.*` resolves both under PegaProx and during
# pytest (where conftest.py also adds it).
if PLUGIN_DIR not in sys.path:
    sys.path.insert(0, PLUGIN_DIR)

# These imports only resolve inside a PegaProx host. Guard them so the
# package can still be imported in unit-test / linting contexts without
# pulling in PegaProx internals.
try:  # pragma: no cover - exercised only on PegaProx hosts
    from flask import request, jsonify  # noqa: F401
    from pegaprox.api.plugins import register_plugin_route
    from pegaprox.utils.audit import log_audit  # noqa: F401
except ImportError:  # pragma: no cover
    register_plugin_route = None  # type: ignore[assignment]

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


def _host_from_dict(h: dict):
    from src.client import OPNsenseHost
    return OPNsenseHost(
        name=str(h.get('name', 'opnsense')),
        url=str(h.get('url', '')),
        api_key=str(h.get('api_key', '')),
        api_secret=str(h.get('api_secret', '')),
        verify_tls=bool(h.get('verify_tls', True)),
        ca_bundle_path=h.get('ca_bundle_path') or None,
    )


def _is_cluster_mode(cfg: dict) -> bool:
    """v1.13.0 cluster mode is on when ≥2 hosts AND (`cluster_mode: auto`
    OR legacy `monitor_both_nodes: true`)."""
    hosts = cfg.get('opnsense_hosts') or []
    if len(hosts) < 2:
        return False
    mode = str(cfg.get('cluster_mode', '')).lower()
    if mode == 'off':
        return False
    if mode in ('auto', 'cluster', 'ha'):
        return True
    return bool(cfg.get('monitor_both_nodes', False))


# Master-resolution cache: avoids a CARP probe round-trip on every request.
# 10s TTL is short enough that CARP failovers (typical ~3-5s detection) surface
# within one or two polling ticks, while sparing the lab from a probe storm.
_master_cache: dict = {'side': None, 'ts': 0.0}
_MASTER_TTL_S = 10


def _resolved_master_side(host_a, host_b, name_a: str, name_b: str):
    """Return 'a' or 'b'. Cached 10s. Probes both nodes' CARP status on miss."""
    import time
    from src.client import OPNsenseClient, OPNsenseClusterClient
    now = time.monotonic()
    if _master_cache['side'] is not None and (now - _master_cache['ts']) < _MASTER_TTL_S:
        return _master_cache['side']
    cluster = OPNsenseClusterClient(
        OPNsenseClient(host_a), OPNsenseClient(host_b), name_a=name_a, name_b=name_b,
    )
    try:
        side = cluster.master_side()
    except Exception as e:  # noqa: BLE001
        log.warning('master resolution failed (%s); defaulting to A', e)
        side = 'a'
    _master_cache['side'] = side
    _master_cache['ts'] = now
    return side


def _first_host_from_config():
    """Resolve the target OPNsense host for reads + writes.

    - Single-host config: returns hosts[0].
    - Cluster mode (≥2 hosts + cluster_mode/monitor_both_nodes flag): returns
      the current CARP master. Cached 10s to avoid probe-per-request.

    Returns None when no hosts are configured (caller emits 400 unconfigured).
    """
    cfg = _load_config()
    hosts = cfg.get('opnsense_hosts') or []
    if not hosts:
        return None
    if not _is_cluster_mode(cfg):
        return _host_from_dict(hosts[0])
    h_a, h_b = _host_from_dict(hosts[0]), _host_from_dict(hosts[1])
    name_a = str(hosts[0].get('name', 'NODOA'))
    name_b = str(hosts[1].get('name', 'NODOB'))
    side = _resolved_master_side(h_a, h_b, name_a, name_b)
    return h_a if side == 'a' else h_b


def _cluster_hosts_from_config():
    """Return (host_a, host_b, name_a, name_b) when cluster mode is configured.

    Returns None when single-host or unconfigured.
    """
    cfg = _load_config()
    if not _is_cluster_mode(cfg):
        return None
    hosts = cfg['opnsense_hosts']
    return (
        _host_from_dict(hosts[0]),
        _host_from_dict(hosts[1]),
        str(hosts[0].get('name', 'NODOA')),
        str(hosts[1].get('name', 'NODOB')),
    )


# ---------------------------------------------------------------------------
# Plugin registration entry point
# ---------------------------------------------------------------------------
# PegaProx 0.9.9.3+ calls `register(app)` on plugin load and expects
# `register_plugin_route(plugin_id, short_path, handler)` calls. Paths are
# auto-prefixed to /api/plugins/<id>/api/<path>. Auth is enforced
# upstream (plugins.view permission).

# ---- handlers (no-arg callables) -------------------------------------------

def _h_health():
    cfg = _load_config()
    return {
        'plugin': PLUGIN_ID,
        'version': '1.14.0',
        'configured': bool(cfg.get('opnsense_hosts')),
        'read_only': cfg.get('read_only', False),
        'cluster_mode': _is_cluster_mode(cfg),
        'hosts_configured': len(cfg.get('opnsense_hosts') or []),
    }


def _h_ui():
    from flask import send_file
    return send_file(os.path.join(PLUGIN_DIR, 'opnsense.html'),
                     mimetype='text/html')


def _unconfigured_response():
    from flask import jsonify
    return jsonify({'ok': False, 'error': 'unconfigured',
                    'detail': 'No opnsense_hosts in config.json — '
                              'edit /opt/PegaProx/plugins/opnsense/config.json'}), 400


def _h_overview():
    from flask import jsonify
    from src.routes.overview import build_overview_payload, build_overview_payload_cluster
    cluster = _cluster_hosts_from_config()
    if cluster is not None:
        host_a, host_b, name_a, name_b = cluster
        status, payload = build_overview_payload_cluster(host_a, host_b, name_a, name_b)
        return jsonify(payload), status
    host = _first_host_from_config()
    if host is None:
        return _unconfigured_response()
    status, payload = build_overview_payload(host)
    return jsonify(payload), status


def _h_cluster():
    """Dedicated cluster endpoint. Always returns cluster shape when 2 hosts
    are configured (regardless of cluster_mode flag) so the UI can render a
    cluster status banner even when full cluster_mode is off."""
    from flask import jsonify
    from src.routes.overview import build_overview_payload_cluster
    cfg = _load_config()
    hosts = cfg.get('opnsense_hosts') or []
    if len(hosts) < 2:
        return jsonify({'ok': False, 'cluster': False,
                        'error': 'single_host',
                        'detail': 'Cluster endpoint requires ≥2 opnsense_hosts.'}), 400
    host_a, host_b = _host_from_dict(hosts[0]), _host_from_dict(hosts[1])
    name_a = str(hosts[0].get('name', 'NODOA'))
    name_b = str(hosts[1].get('name', 'NODOB'))
    status, payload = build_overview_payload_cluster(host_a, host_b, name_a, name_b)
    return jsonify(payload), status


def _h_network():
    from flask import jsonify
    from src.routes import build_network_payload
    host = _first_host_from_config()
    if host is None:
        return _unconfigured_response()
    status, payload = build_network_payload(host)
    return jsonify(payload), status


def _h_logs():
    from flask import jsonify, request
    from src.routes import build_logs_payload
    host = _first_host_from_config()
    if host is None:
        return _unconfigured_response()
    status, payload = build_logs_payload(host, limit=request.args.get('limit', 100))
    return jsonify(payload), status


def _h_nat():
    from flask import jsonify, request
    from src.routes import build_nat_action_payload, build_nat_list_payload
    host = _first_host_from_config()
    if host is None:
        return _unconfigured_response()
    if request.method == 'GET':
        status, payload = build_nat_list_payload(host)
        return jsonify(payload), status
    body = request.get_json(silent=True) or {}
    cfg = _load_config()
    status, payload = build_nat_action_payload(
        host, PLUGIN_DIR, body,
        actor='plugin', read_only=bool(cfg.get('read_only', False)),
    )
    return jsonify(payload), status


def _h_unbound():
    from flask import jsonify, request
    from src.routes import build_unbound_action_payload, build_unbound_list_payload
    host = _first_host_from_config()
    if host is None:
        return _unconfigured_response()
    if request.method == 'GET':
        status, payload = build_unbound_list_payload(host)
        return jsonify(payload), status
    body = request.get_json(silent=True) or {}
    cfg = _load_config()
    status, payload = build_unbound_action_payload(
        host, PLUGIN_DIR, body,
        actor='plugin', read_only=bool(cfg.get('read_only', False)),
    )
    return jsonify(payload), status


def _h_dhcp_subnet():
    from flask import jsonify, request
    from src.routes import build_dhcp_subnet_action_payload, build_dhcp_subnet_list_payload
    host = _first_host_from_config()
    if host is None:
        return _unconfigured_response()
    if request.method == 'GET':
        status, payload = build_dhcp_subnet_list_payload(host)
        return jsonify(payload), status
    body = request.get_json(silent=True) or {}
    cfg = _load_config()
    status, payload = build_dhcp_subnet_action_payload(
        host, PLUGIN_DIR, body,
        actor='plugin', read_only=bool(cfg.get('read_only', False)),
    )
    return jsonify(payload), status


def _h_dhcp():
    from flask import jsonify, request
    from src.routes import build_dhcp_action_payload, build_dhcp_list_payload
    host = _first_host_from_config()
    if host is None:
        return _unconfigured_response()
    if request.method == 'GET':
        status, payload = build_dhcp_list_payload(host)
        return jsonify(payload), status
    body = request.get_json(silent=True) or {}
    cfg = _load_config()
    status, payload = build_dhcp_action_payload(
        host, PLUGIN_DIR, body,
        actor='plugin', read_only=bool(cfg.get('read_only', False)),
    )
    return jsonify(payload), status


def _h_one_to_one():
    from flask import jsonify, request
    from src.routes import (
        build_one_to_one_action_payload,
        build_one_to_one_list_payload,
    )
    host = _first_host_from_config()
    if host is None:
        return _unconfigured_response()
    if request.method == 'GET':
        status, payload = build_one_to_one_list_payload(host)
        return jsonify(payload), status
    body = request.get_json(silent=True) or {}
    cfg = _load_config()
    status, payload = build_one_to_one_action_payload(
        host, PLUGIN_DIR, body,
        actor='plugin', read_only=bool(cfg.get('read_only', False)),
    )
    return jsonify(payload), status


def _h_unbound_domains():
    from flask import jsonify, request
    from src.routes import (
        build_unbound_domain_action_payload,
        build_unbound_domain_list_payload,
    )
    host = _first_host_from_config()
    if host is None:
        return _unconfigured_response()
    if request.method == 'GET':
        status, payload = build_unbound_domain_list_payload(host)
        return jsonify(payload), status
    body = request.get_json(silent=True) or {}
    cfg = _load_config()
    status, payload = build_unbound_domain_action_payload(
        host, PLUGIN_DIR, body,
        actor='plugin', read_only=bool(cfg.get('read_only', False)),
    )
    return jsonify(payload), status


def _h_unbound_dots():
    from flask import jsonify, request
    from src.routes import (
        build_unbound_dot_action_payload,
        build_unbound_dot_list_payload,
    )
    host = _first_host_from_config()
    if host is None:
        return _unconfigured_response()
    if request.method == 'GET':
        status, payload = build_unbound_dot_list_payload(host)
        return jsonify(payload), status
    body = request.get_json(silent=True) or {}
    cfg = _load_config()
    status, payload = build_unbound_dot_action_payload(
        host, PLUGIN_DIR, body,
        actor='plugin', read_only=bool(cfg.get('read_only', False)),
    )
    return jsonify(payload), status


def _h_wg():
    from flask import jsonify, request
    from src.routes import build_wg_action_payload, build_wg_list_payload
    host = _first_host_from_config()
    if host is None:
        return _unconfigured_response()
    if request.method == 'GET':
        status, payload = build_wg_list_payload(host)
        return jsonify(payload), status
    body = request.get_json(silent=True) or {}
    cfg = _load_config()
    status, payload = build_wg_action_payload(
        host, PLUGIN_DIR, body,
        actor='plugin', read_only=bool(cfg.get('read_only', False)),
    )
    return jsonify(payload), status


def _h_metrics():
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


def register(app=None):  # noqa: ARG001 — app passed by PegaProx loader
    """Called by PegaProx 0.9.9.3+ when the plugin is enabled.

    Accepts the Flask `app` for forward compatibility but doesn't use it
    today; everything goes through `register_plugin_route`.
    """
    if register_plugin_route is None:
        raise RuntimeError(
            'PegaProx framework not available — register() must run inside a PegaProx host'
        )
    log.info('%s v1.12.0 loading', PLUGIN_NAME)
    os.makedirs(STATE_DIR, exist_ok=True)

    routes = {
        # short path → handler. PegaProx auto-prefixes to
        # /api/plugins/opnsense/api/<path>
        'health': _h_health,
        'ui': _h_ui,
        'overview': _h_overview,
        'cluster': _h_cluster,
        'network': _h_network,
        'logs': _h_logs,
        'dhcp': _h_dhcp,
        'dhcp_subnet': _h_dhcp_subnet,
        'nat': _h_nat,
        'one_to_one': _h_one_to_one,
        'unbound': _h_unbound,
        'unbound_domains': _h_unbound_domains,
        'unbound_dots': _h_unbound_dots,
        'wg': _h_wg,
        'metrics': _h_metrics,
    }
    for path, handler in routes.items():
        register_plugin_route(PLUGIN_ID, path, handler)

    log.info('%s registered (%d routes)', PLUGIN_NAME, len(routes))


def unregister():
    log.info('%s unloading', PLUGIN_NAME)
    _bg_stop.set()
