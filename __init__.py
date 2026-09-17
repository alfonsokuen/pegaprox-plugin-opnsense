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
with open(os.path.join(PLUGIN_DIR, 'manifest.json'), encoding='utf-8') as _manifest_file:
    PLUGIN_VERSION = json.load(_manifest_file)['version']

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
        return {'opnsense_hosts': [], 'poll_interval': 30, 'read_only': True}
    try:
        with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
            cfg = json.load(f)
        if not isinstance(cfg, dict):
            raise ValueError('config.json must contain an object')
        cfg['read_only'] = cfg.get('read_only') is not False
        return cfg
    except Exception as e:
        log.error('Failed to load config: %s', e)
        return {'opnsense_hosts': [], 'poll_interval': 30, 'read_only': True}


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
        'version': PLUGIN_VERSION,
        'configured': bool(cfg.get('opnsense_hosts')),
        'read_only': cfg.get('read_only') is not False,
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


def _firewall_can_write():
    """Use the host's permission resolver, never a client-supplied identity."""
    try:
        from pegaprox.utils.auth import require_auth
        return require_auth(perms=['plugins.manage'])(lambda: True)() is True
    except ImportError:
        return False
    except Exception as exc:
        # Permission implementations may abort instead of returning a response.
        # A permission probe must fail closed without breaking read-only views.
        log.warning('Plugin write permission check failed: %s', type(exc).__name__)
        return False


def _firewall_target(cfg, write=False):
    """Resolve new management operations from one config snapshot.

    Writes require a fresh, unambiguous master across all configured CARP VIPs.
    Read-only snapshots retain the existing cached primary-VIP selection.
    """
    from src.client import OPNsenseClient
    from src.collectors.carp import collect_carp_status

    hosts = cfg.get('opnsense_hosts') or []
    if not hosts:
        return None, None
    if not _is_cluster_mode(cfg):
        return _host_from_dict(hosts[0]), None
    if write and len(hosts) != 2:
        raise ValueError('Las escrituras HA requieren exactamente dos nodos configurados.')
    a, b = _host_from_dict(hosts[0]), _host_from_dict(hosts[1])
    if not write:
        side = _resolved_master_side(a, b, a.name, b.name)
        return (a, b) if side == 'a' else (b, a)
    left = collect_carp_status(OPNsenseClient(a))
    right = collect_carp_status(OPNsenseClient(b))
    def vip_states(status):
        return {(v['vhid'], v.get('ipaddr', '')): v['status'] for v in status['vhids']}
    la, rb = vip_states(left), vip_states(right)
    if (not left['enabled'] or not right['enabled'] or not la or la.keys() != rb.keys()
            or left['maintenance_mode'] or right['maintenance_mode']):
        raise ValueError('No se puede confirmar un par HA disponible con los mismos VIPs.')
    if set(la.values()) == {'MASTER'} and set(rb.values()) == {'BACKUP'}:
        return a, b
    if set(la.values()) == {'BACKUP'} and set(rb.values()) == {'MASTER'}:
        return b, a
    raise ValueError('Estado CARP ambiguo o mixto: no se realizará ninguna escritura.')


def _management_context():
    """One config snapshot and authorization gate for every mutation handler."""
    from flask import jsonify, request
    from src.client import OPNsenseError

    cfg = _load_config()
    read_only = cfg.get('read_only') is not False
    if request.method not in ('GET', 'POST'):
        return None, (jsonify({'ok': False, 'error': 'method_not_allowed'}), 405)
    write = request.method == 'POST'
    if write and read_only:
        return None, (jsonify({'ok': False, 'error': 'read_only',
                              'detail': 'El plugin está configurado en modo de solo lectura.'}), 403)
    if write and not _firewall_can_write():
        return None, (jsonify({'ok': False, 'error': 'forbidden',
                              'detail': 'Se requiere el permiso plugins.manage.'}), 403)
    body = request.get_json(silent=True) if write else None
    if write and not isinstance(body, dict):
        return None, (jsonify({'ok': False, 'error': 'bad_request',
                              'detail': 'Se requiere un objeto JSON.'}), 400)
    try:
        host, peer = _firewall_target(cfg, write=write)
    except (ValueError, KeyError, TypeError) as exc:
        return None, (jsonify({'ok': False, 'error': 'ha_unsafe', 'detail': str(exc)}), 409)
    except OPNsenseError as exc:
        return None, (jsonify({'ok': False, 'error': 'ha_unavailable', 'detail': str(exc)}), 502)
    if host is None:
        return None, _unconfigured_response()
    return {
        'cfg': cfg, 'read_only': read_only, 'write': write, 'body': body,
        'host': host, 'peer': peer,
        'actor': str(getattr(request, 'session', {}).get('user', 'plugin')),
    }, None


def _h_firewall_management(resource):
    from flask import jsonify
    from src.routes.firewall import build_firewall_action_payload, build_firewall_list_payload

    context, denied = _management_context()
    if denied is not None:
        return denied
    if not context['write']:
        status, payload = build_firewall_list_payload(context['host'], resource)
        if payload.get('ok'):
            payload['data']['read_only'] = context['read_only'] or not _firewall_can_write()
        return jsonify(payload), status
    cfg = context['cfg']
    status, payload = build_firewall_action_payload(
        context['host'], PLUGIN_DIR, context['body'], resource=resource, actor=context['actor'],
        read_only=context['read_only'], peer_host=context['peer'],
        ha_verify_attempts=cfg.get('ha_verify_attempts', 6),
        ha_verify_backoff=cfg.get('ha_verify_backoff', 0.5),
    )
    return jsonify(payload), status


def _h_legacy_management(list_builder, action_builder):
    """Keep legacy writer behavior behind the same permission and HA gate."""
    from flask import jsonify

    context, denied = _management_context()
    if denied is not None:
        return denied
    if not context['write']:
        status, payload = list_builder(context['host'])
    else:
        status, payload = action_builder(
            context['host'], PLUGIN_DIR, context['body'],
            actor=context['actor'], read_only=context['read_only'],
        )
    return jsonify(payload), status


def _h_port_forward():
    return _h_firewall_management('port_forward')


def _h_rules():
    return _h_firewall_management('rules')


def _h_aliases():
    return _h_firewall_management('aliases')


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
    from src.routes import build_nat_action_payload, build_nat_list_payload
    return _h_legacy_management(build_nat_list_payload, build_nat_action_payload)


def _h_unbound():
    from src.routes import build_unbound_action_payload, build_unbound_list_payload
    return _h_legacy_management(build_unbound_list_payload, build_unbound_action_payload)


def _h_dhcp_subnet():
    from src.routes import build_dhcp_subnet_action_payload, build_dhcp_subnet_list_payload
    return _h_legacy_management(build_dhcp_subnet_list_payload, build_dhcp_subnet_action_payload)


def _h_dhcp():
    from src.routes import build_dhcp_action_payload, build_dhcp_list_payload
    return _h_legacy_management(build_dhcp_list_payload, build_dhcp_action_payload)


def _h_one_to_one():
    from src.routes import build_one_to_one_action_payload, build_one_to_one_list_payload
    return _h_legacy_management(build_one_to_one_list_payload, build_one_to_one_action_payload)


def _h_unbound_domains():
    from src.routes import build_unbound_domain_action_payload, build_unbound_domain_list_payload
    return _h_legacy_management(build_unbound_domain_list_payload, build_unbound_domain_action_payload)


def _h_unbound_dots():
    from src.routes import build_unbound_dot_action_payload, build_unbound_dot_list_payload
    return _h_legacy_management(build_unbound_dot_list_payload, build_unbound_dot_action_payload)


def _h_wg():
    from src.routes import build_wg_action_payload, build_wg_list_payload
    return _h_legacy_management(build_wg_list_payload, build_wg_action_payload)


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
    log.info('%s v%s loading', PLUGIN_NAME, PLUGIN_VERSION)
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
        'port_forward': _h_port_forward,
        'rules': _h_rules,
        'aliases': _h_aliases,
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
