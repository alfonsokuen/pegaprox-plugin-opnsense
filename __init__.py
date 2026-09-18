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
    read_only = cfg.get('read_only') is not False
    can_write = not read_only and _firewall_can_write()
    return {
        'plugin': PLUGIN_ID,
        'version': PLUGIN_VERSION,
        'configured': bool(cfg.get('opnsense_hosts')),
        'read_only': cfg.get('read_only') is not False,
        'cluster_mode': _is_cluster_mode(cfg),
        'hosts_configured': len(cfg.get('opnsense_hosts') or []),
        'can_write': can_write,
        'write_restriction': 'read_only' if read_only else 'permission' if not can_write else None,
    }


def _h_ui():
    from flask import send_file
    return send_file(os.path.join(PLUGIN_DIR, 'opnsense.html'),
                     mimetype='text/html')


def _workspace_asset(filename, mimetype):
    from flask import jsonify, request, send_file
    if request.method != 'GET':
        return jsonify({'ok': False, 'error': 'method_not_allowed'}), 405
    response = send_file(os.path.join(PLUGIN_DIR, filename), mimetype=mimetype)
    response.headers['Cache-Control'] = 'private, no-cache'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response


def _h_workspace():
    return _workspace_asset('workspace.html', 'text/html')


def _h_workspace_js():
    return _workspace_asset('workspace.js', 'application/javascript')


def _h_workspace_css():
    return _workspace_asset('workspace.css', 'text/css')


def _management_resources():
    from src.management.catalog import RESOURCES
    from src.management.identity_catalog import IDENTITY_RESOURCES
    from src.management.crl import CRL_RESOURCE
    return {**RESOURCES, **IDENTITY_RESOURCES, 'trust_crl': CRL_RESOURCE}


def _h_catalog():
    from flask import jsonify, request
    from src.management.operations import OPERATIONS
    if request.method != 'GET':
        return jsonify({'ok': False, 'error': 'method_not_allowed'}), 405
    cfg = _load_config()
    readonly = cfg.get('read_only') is not False or not _firewall_can_write()
    public = []
    for spec in _management_resources().values():
        metadata = {key: spec[key] for key in ('id', 'label', 'group', 'fields', 'columns', 'singleton') if key in spec}
        ha_blocked = _is_cluster_mode(cfg) and spec.get('ha_safe') is not True
        metadata.update(read_only=readonly or ha_blocked,
                        write_restriction='read_only' if readonly else 'ha_unqualified' if ha_blocked else None,
                        operations=[action for action, key in (('create', 'add'), ('update', 'set'), ('delete', 'delete')) if spec.get(key)])
        public.append(metadata)
    operations = [{key: value for key, value in spec.items()
                   if key in ('id', 'label', 'group', 'method', 'fields', 'confirm', 'description')}
                  for spec in OPERATIONS.values()]
    return jsonify({'ok': True, 'data': {'resources': public, 'operations': operations,
                                       'backups': {'available': _firewall_can_write()}, 'read_only': readonly}})


def _h_backups():
    from flask import jsonify, request, Response
    from src.management.backups import BackupStore
    from src.management.engine import ManagementError
    from src.writers.audit import AuditLog

    if request.method not in ('GET', 'POST'):
        return jsonify({'ok': False, 'error': 'method_not_allowed'}), 405
    if not _firewall_can_write():
        return jsonify({'ok': False, 'error': 'forbidden', 'detail': 'Se requiere el permiso plugins.manage.'}), 403
    try:
        store = BackupStore(os.path.join(STATE_DIR, 'backups'),
                            AuditLog(os.path.join(STATE_DIR, 'audit.jsonl')),
                            str(getattr(request, 'session', {}).get('user', 'plugin')))
        if request.method == 'GET':
            if request.args.get('download') == '1':
                payload = store.read(request.args.get('id'))
                response = Response(payload, mimetype='application/xml')
                response.headers['Content-Disposition'] = 'attachment; filename="opnsense-backup.xml"'
                response.headers['X-Content-Type-Options'] = 'nosniff'
            else:
                response = jsonify({'ok': True, 'data': {'items': store.list()}})
        else:
            body = request.get_json(silent=True)
            if not isinstance(body, dict) or body.get('action') not in ('create', 'delete'):
                return jsonify({'ok': False, 'error': 'bad_request'}), 400
            if body['action'] == 'create':
                host, _ = _firewall_target(_load_config(), write=False)
                if host is None:
                    return _unconfigured_response()
                data = store.create(host)
            else:
                data = store.delete(body.get('id'))
            response = jsonify({'ok': True, 'data': data})
        response.headers['Cache-Control'] = 'no-store'
        return response, 200
    except ManagementError as exc:
        return jsonify(exc.as_dict()), exc.status
    except Exception:
        log.exception('Backup operation failed')
        return jsonify({'ok': False, 'error': 'internal', 'detail': 'No se pudo procesar el respaldo.'}), 500


def _h_operate():
    from flask import jsonify, request
    from src.client import OPNsenseClient
    from src.management.engine import ManagementError
    from src.management.operations import OPERATIONS, execute_operation
    from src.writers.audit import AuditLog

    body = request.get_json(silent=True) if request.method == 'POST' else None
    operation = body.get('operation') if isinstance(body, dict) else request.args.get('operation')
    if not isinstance(operation, str) or operation not in OPERATIONS:
        return jsonify({'ok': False, 'error': 'unknown_operation', 'detail': 'Selecciona una operación válida.'}), 404
    if request.method != OPERATIONS[operation]['method']:
        return jsonify({'ok': False, 'error': 'method_not_allowed'}), 405
    context, denied = _management_context(mutation=OPERATIONS[operation].get('mutation', request.method == 'POST'))
    if denied is not None:
        return denied
    values = body.get('values', {}) if isinstance(body, dict) else {key: value for key, value in request.args.items() if key != 'operation'}
    client = OPNsenseClient(context['host'])
    try:
        data = execute_operation(client, AuditLog(os.path.join(STATE_DIR, 'audit.jsonl')),
                                 context['actor'], operation, values)
        data['target'] = context['host'].name
        response = jsonify({'ok': True, 'data': data})
        response.headers['Cache-Control'] = 'no-store'
        return response, 200
    except ManagementError as exc:
        return jsonify(exc.as_dict()), exc.status
    except Exception:
        log.exception('Device operation failed for %s', operation)
        return jsonify({'ok': False, 'error': 'internal', 'detail': 'No se pudo completar la operación.'}), 500
    finally:
        client.close()


def _h_manage():
    from flask import jsonify, request
    from src.client import OPNsenseClient
    from src.management.engine import ManagementError, ManagementService
    from src.writers.audit import AuditLog

    body = request.get_json(silent=True) if request.method == 'POST' else None
    resource = body.get('resource') if isinstance(body, dict) else request.args.get('resource')
    resources = _management_resources()
    if not isinstance(resource, str) or resource not in resources:
        return jsonify({'ok': False, 'error': 'unknown_resource', 'detail': 'Selecciona un módulo válido.'}), 404
    context, denied = _management_context()
    if denied is not None:
        return denied
    spec = resources[resource]
    client = OPNsenseClient(context['host'])
    peer = OPNsenseClient(context['peer']) if context['peer'] else None
    try:
        if resource == 'trust_crl':
            from src.management.crl import CrlService
            crl = CrlService(client, AuditLog(os.path.join(STATE_DIR, 'audit.jsonl')),
                             actor=context['actor'], peer=peer)
            if context['write']:
                data = crl.mutate(body)
            elif request.args.get('defaults') == '1':
                return jsonify({'ok': False, 'error': 'bad_request',
                                'detail': 'CRL requiere la referencia de la CA.'}), 400
            elif 'uuid' in request.args:
                data = crl.detail(request.args['uuid'])
            else:
                try:
                    page = int(request.args.get('page', '1'))
                    row_count = int(request.args.get('row_count', '50'))
                except ValueError:
                    return jsonify({'ok': False, 'error': 'bad_request',
                                    'detail': 'PÃ¡gina o tamaÃ±o de pÃ¡gina invÃ¡lido.'}), 400
                data = crl.list(page=page, row_count=row_count, search=request.args.get('search', ''))
            if not context['write']:
                data.update(read_only=context['read_only'] or not _firewall_can_write(),
                            write_restriction='read_only' if context['read_only'] else None)
            response = jsonify({'ok': True, 'data': data})
            response.headers['Cache-Control'] = 'no-store'
            return response, 200
        service = ManagementService(client, AuditLog(os.path.join(STATE_DIR, 'audit.jsonl')),
                                    actor=context['actor'], peer=peer)
        if context['write']:
            data = service.mutate(spec, body)
        elif request.args.get('defaults') == '1':
            data = service.detail(spec)
        elif 'uuid' in request.args:
            data = service.detail(spec, request.args['uuid'])
        else:
            try:
                page = int(request.args.get('page', '1'))
                row_count = int(request.args.get('row_count', '50'))
                if page < 1 or not 1 <= row_count <= 200:
                    raise ValueError()
            except ValueError:
                return jsonify({'ok': False, 'error': 'bad_request', 'detail': 'Página o tamaño de página inválido.'}), 400
            data = service.list(spec, page=page, row_count=row_count, search=request.args.get('search', ''))
        if not context['write']:
            ha_blocked = peer is not None and spec.get('ha_safe') is not True
            readonly = context['read_only'] or not _firewall_can_write()
            data.update(read_only=readonly or ha_blocked,
                        write_restriction='read_only' if readonly else 'ha_unqualified' if ha_blocked else None)
        response = jsonify({'ok': True, 'data': data})
        response.headers['Cache-Control'] = 'no-store'
        return response, 200
    except ManagementError as exc:
        return jsonify(exc.as_dict()), exc.status
    except Exception:
        log.exception('Management operation failed for resource %s', resource)
        return jsonify({'ok': False, 'error': 'internal', 'detail': 'No se pudo completar la operación.'}), 500
    finally:
        client.close()
        if peer:
            peer.close()


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


def _management_context(*, mutation=None):
    """One config snapshot and authorization gate for every mutation handler."""
    from flask import jsonify, request
    from src.client import OPNsenseError

    cfg = _load_config()
    read_only = cfg.get('read_only') is not False
    if request.method not in ('GET', 'POST'):
        return None, (jsonify({'ok': False, 'error': 'method_not_allowed'}), 405)
    write = request.method == 'POST' if mutation is None else bool(mutation)
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
    from flask import jsonify, request
    from src.routes.firewall import build_firewall_action_payload, build_firewall_list_payload

    context, denied = _management_context()
    if denied is not None:
        return denied
    if not context['write']:
        if 'uuid' in request.args:
            from src.routes.firewall import build_firewall_detail_payload
            status, payload = build_firewall_detail_payload(context['host'], resource, request.args['uuid'])
        elif request.args.get('view') == 'summary':
            status, payload = build_firewall_list_payload(context['host'], resource, summary=True)
        else:
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
        ha_sync_mode=cfg.get('ha_sync_mode', 'automatic'),
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
        if payload.get('ok'):
            payload['data']['read_only'] = context['read_only'] or not _firewall_can_write()
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


def _h_vpn():
    from flask import jsonify
    from src.routes.vpn import build_vpn_payload
    host = _first_host_from_config()
    if host is None:
        return _unconfigured_response()
    status, payload = build_vpn_payload(host)
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
        'workspace': _h_workspace,
        'workspace_js': _h_workspace_js,
        'workspace_css': _h_workspace_css,
        'catalog': _h_catalog,
        'manage': _h_manage,
        'operate': _h_operate,
        'backups': _h_backups,
        'overview': _h_overview,
        'cluster': _h_cluster,
        'network': _h_network,
        'vpn': _h_vpn,
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
