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

from flask import request, jsonify

from pegaprox.api.plugins import register_plugin_route
from pegaprox.utils.audit import log_audit

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


# ---------------------------------------------------------------------------
# Plugin registration entry point
# ---------------------------------------------------------------------------
# PegaProx 0.9.9.3+ calls register() on plugin load. Routes are scaffold
# stubs — real handlers land in src/routes/ and are wired here in v1.0.0.

def register():
    log.info('%s v0.1.0 (scaffold) loading', PLUGIN_NAME)
    os.makedirs(STATE_DIR, exist_ok=True)

    @register_plugin_route(PLUGIN_ID, '/api/health', methods=['GET'])
    def _health():
        cfg = _load_config()
        return jsonify({
            'plugin': PLUGIN_ID,
            'version': '0.1.0',
            'configured': bool(cfg.get('opnsense_hosts')),
            'read_only': cfg.get('read_only', False),
        })

    @register_plugin_route(PLUGIN_ID, '/api/ui', methods=['GET'])
    def _ui():
        from flask import send_file
        return send_file(os.path.join(PLUGIN_DIR, 'opnsense.html'))

    log.info('%s registered', PLUGIN_NAME)


def unregister():
    log.info('%s unloading', PLUGIN_NAME)
    _bg_stop.set()
