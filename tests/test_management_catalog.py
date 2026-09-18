"""Contract fixtures for native OPNsense API adapters (core tag 26.1.2).

These protect known endpoint/body differences, not firewall functionality.
Live qualification belongs to the isolated appliance suite.
"""

import re

import pytest

from src.management.catalog import RESOURCES


@pytest.mark.parametrize('resource,base,search,get,key,apply', [
    ('wireguard_servers', '/api/wireguard/server', 'searchServer', 'getServer',
     'server', '/api/wireguard/service/reconfigure'),
    ('wireguard_clients', '/api/wireguard/client', 'searchClient', 'getClient',
     'client', '/api/wireguard/service/reconfigure'),
    ('shaper_pipes', '/api/trafficshaper/settings', 'searchPipes', 'getPipe',
     'pipe', '/api/trafficshaper/service/reconfigure'),
    ('shaper_queues', '/api/trafficshaper/settings', 'searchQueues', 'getQueue',
     'queue', '/api/trafficshaper/service/reconfigure'),
    ('shaper_rules', '/api/trafficshaper/settings', 'searchRules', 'getRule',
     'rule', '/api/trafficshaper/service/reconfigure'),
    ('vips', '/api/interfaces/vip_settings', 'searchItem', 'getItem',
     'vip', '/api/interfaces/vip_settings/reconfigure'),
    ('static_routes', '/api/routes/routes', 'searchroute', 'getroute',
     'route', '/api/routes/routes/reconfigure'),
    ('ids_rules', '/api/ids/settings', 'searchUserRule', 'getUserRule',
     'rule', '/api/ids/service/reconfigure'),
    ('ipsec_children', '/api/ipsec/connections', 'searchChild', 'getChild',
     'child', '/api/ipsec/service/reconfigure'),
    ('syslog_destinations', '/api/syslog/settings', 'searchDestinations', 'getDestination',
     'destination', '/api/syslog/service/reconfigure'),
    ('cron_jobs', '/api/cron/settings', 'searchJobs', 'getJob',
     'job', '/api/cron/service/reconfigure'),
])
def test_native_endpoint_and_body_contract(resource, base, search, get, key, apply):
    spec = RESOURCES[resource]
    assert (spec['base'], spec['search'], spec['get'], spec['key'], spec['apply']) == (
        base, search, get, key, apply)


def fields(resource):
    return {field['name']: field for field in RESOURCES[resource]['fields']}


def test_wireguard_fields_use_native_names_and_preserve_sensitive_semantics():
    server = fields('wireguard_servers')
    client = fields('wireguard_clients')
    assert server['privkey']['secret'] is True
    assert server['privkey']['required'] is True
    assert server['pubkey']['secret'] is False
    assert server['pubkey']['readonly'] is True
    assert server['pubkey']['generated'] is True
    assert client['psk']['secret'] is True
    assert 'port' in server and 'listenport' not in server
    assert server['peers']['multiple'] is True
    assert 'instance' not in server  # AutoNumberField assigned by appliance
    assert not {'cnfFilename', 'statFilename', 'interface'} & server.keys()


def test_vip_uses_controller_network_overlay_not_hidden_model_subnet():
    vip = fields('vips')
    assert 'network' in vip
    assert 'subnet' not in vip and 'subnet_bits' not in vip
    assert vip['password']['secret'] is True
    assert vip['mode']['options'] == [
        {'value': 'ipalias', 'label': 'IP Alias'},
        {'value': 'carp', 'label': 'CARP'},
        {'value': 'proxyarp', 'label': 'Proxy ARP'},
    ]
    assert (vip['vhid']['min'], vip['vhid']['max']) == (1, 255)


def test_automatic_and_volatile_fields_are_not_browser_editable():
    assert 'deviceId' not in fields('loopbacks')
    assert 'vlanif' not in fields('vlans')
    assert 'laggif' not in fields('laggs')
    assert 'origin' not in fields('cron_jobs')
    for resource in ('shaper_pipes', 'shaper_queues', 'shaper_rules'):
        assert not {'number', 'origin'} & fields(resource).keys()


def test_dynamic_relations_and_native_enum_values():
    assert fields('laggs')['members']['multiple'] is True
    assert fields('monit_services')['tests']['multiple'] is True
    versions = fields('ipsec_connections')['version']['options']
    assert [option['value'] for option in versions] == ['0', '1', '2']
    assert fields('static_routes')['gateway']['kind'] == 'select'
    assert fields('cron_jobs')['command']['kind'] == 'select'
    assert fields('portal_zones')['authservers']['kind'] == 'select'


def test_categories_explicitly_save_metadata_without_claiming_service_apply():
    assert RESOURCES['categories']['apply'] is None
    assert RESOURCES['categories']['persistence_only'] is True
    assert all(spec['apply'] or spec.get('persistence_only') for spec in RESOURCES.values())


def test_catalog_cannot_supply_browser_controlled_paths_or_secret_columns():
    for ident, spec in RESOURCES.items():
        assert spec['id'] == ident
        assert re.fullmatch(r'/api/[a-z]+/[a-z_]+', spec['base'])
        for operation in ('search', 'get', 'add', 'set', 'delete'):
            assert spec[operation] is None or re.fullmatch(r'[a-zA-Z]+', spec[operation])
        names = fields(ident)
        assert len(names) == len(spec['fields'])
        for column in spec['columns']:
            assert column in names and names[column]['secret'] is False
        assert spec['source']['tag'] == '26.1.2'
        assert spec['qualification'] == 'contract_only'


def test_unimplemented_admix_wrappers_are_not_registered_as_real_resources():
    assert not {'haproxy', 'acme', 'tunables', 'gateway_groups', 'schedules'} & RESOURCES.keys()


@pytest.mark.parametrize('resource,key,base', [
    ('wireguard_general', 'general', '/api/wireguard/general'),
    ('unbound_general', 'unbound.general', '/api/unbound/settings'),
    ('dnsmasq_general', 'dnsmasq', '/api/dnsmasq/settings'),
    ('ids_general', 'ids.general', '/api/ids/settings'),
    ('monit_general', 'monit.general', '/api/monit/settings'),
    ('syslog_general', 'syslog.general', '/api/syslog/settings'),
    ('ha_settings', 'hasync', '/api/core/hasync'),
])
def test_singleton_get_set_uses_native_model_nesting(resource, key, base):
    spec = RESOURCES[resource]
    assert spec['singleton'] is True
    assert spec['key'] == key and spec['base'] == base
    assert spec['get'] == 'get' and spec['set'] == 'set'
    assert spec['search'] is None and spec['add'] is None and spec['delete'] is None
    assert spec['ha_safe'] is False


def test_singleton_fields_do_not_allow_replacing_entity_collections():
    dnsmasq = fields('dnsmasq_general')
    assert 'enable' in dnsmasq and 'enabled' not in dnsmasq
    assert not {'hosts', 'domain', 'ranges', 'options'} & dnsmasq.keys()
    assert set(fields('wireguard_general')) == {'enabled'}
    assert fields('monit_general')['httpdPassword']['secret'] is True
    assert fields('monit_general')['mmonitUrl']['secret'] is True
    assert fields('ha_settings')['password']['secret'] is True
    assert fields('ha_settings')['syncitems']['multiple'] is True


def test_openvpn_does_not_advertise_unimplemented_create_or_update():
    spec = RESOURCES['openvpn_instances']
    assert (spec['base'], spec['search'], spec['get'], spec['delete'], spec['key']) == (
        '/api/openvpn/instances', 'search', 'get', 'del', 'instance')
    assert spec['add'] is None and spec['set'] is None
    assert 'role' in fields('openvpn_instances')


def test_dnsmasq_host_body_is_singular_but_model_collection_is_plural():
    spec = RESOURCES['dnsmasq_hosts']
    assert spec['key'] == 'host'
    assert spec['source']['node'] == 'hosts'
    assert spec['search'] == 'searchHost' and spec['get'] == 'getHost'
    assert 'ip' in fields('dnsmasq_hosts')
