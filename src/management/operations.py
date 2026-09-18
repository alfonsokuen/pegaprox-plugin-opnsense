"""Allowlisted operational API contracts from opnsense/core tag 26.1.2.

Transport acknowledgements are not evidence of asynchronous completion.
Authentication/read-only authorization belongs to the host route.
"""
from __future__ import annotations

import ipaddress
import re
import time
from urllib.parse import quote

from src.management.engine import ManagementError, ManagementService
from src.writers.audit import AuditEntry, hash_payload
from src.writers.verified import validate_uuid


OPERATIONS = {}


def _register(ident, label, group, method, path, *, fields=(), confirm=False,
              verify=None, ack=None, body_key=None, segment=None, mutation=None):
    OPERATIONS[ident] = dict(id=ident, label=label, group=group, method=method,
                            path=path, fields=list(fields), confirm=confirm,
                            verify=verify, ack=ack, body_key=body_key, segment=segment,
                            mutation=method == 'POST' if mutation is None else mutation,
                            qualification='contract_only', source_tag='26.1.2')


for _service, _label in (
    ('wireguard', 'WireGuard'), ('ids', 'IDS/IPS'), ('monit', 'Monit'),
    ('dnsmasq', 'Dnsmasq'), ('syslog', 'Syslog'), ('ipsec', 'IPsec'),
    ('captiveportal', 'Portal cautivo'),
):
    _base = f'/api/{_service}/service/'
    _register(f'{_service}_status', f'Estado {_label}', 'Servicios', 'GET', _base + 'status')
    for _action, _caption in (('start', 'Iniciar'), ('stop', 'Detener'),
                              ('restart', 'Reiniciar'), ('reconfigure', 'Aplicar configuración')):
        _expected = ['stopped', 'disabled'] if _action == 'stop' else ['running']
        # Reconfigure can legitimately leave a disabled service stopped. It is
        # acknowledged but not claimed as a verified service configuration.
        _verify = None if _action == 'reconfigure' else dict(path=_base + 'status', expected=_expected)
        _ack = dict(key='status' if _action == 'reconfigure' else 'response', values=['ok'])
        if _service == 'wireguard' and _action == 'reconfigure':
            _ack['key'] = 'result'
        _register(f'{_service}_{_action}', f'{_caption}: {_label}', 'Servicios', 'POST',
                  _base + _action, confirm=True, verify=_verify, ack=_ack)

for _action, _label in (('status', 'Estado de firmware'), ('info', 'Paquetes y versión'),
                        ('upgradestatus', 'Progreso de actualización')):
    _register('firmware_' + _action, _label, 'Sistema', 'GET', '/api/core/firmware/' + _action)
for _action, _label in (('check', 'Buscar actualizaciones'), ('audit', 'Auditar paquetes'),
                        ('update', 'Actualizar firmware'), ('upgrade', 'Actualizar versión mayor'),
                        ('reboot', 'Reiniciar firewall'), ('poweroff', 'Apagar firewall')):
    _register('firmware_' + _action, _label, 'Sistema', 'POST', '/api/core/firmware/' + _action,
              confirm=True, ack=dict(key='status', values=['ok']))

for _ident, _label, _path in (
    ('activity', 'Actividad del sistema', '/api/diagnostics/activity/getActivity'),
    ('arp', 'Tabla ARP', '/api/diagnostics/interface/searchArp'),
    ('ndp', 'Tabla NDP', '/api/diagnostics/interface/searchNdp'),
    ('routes', 'Rutas del kernel', '/api/diagnostics/interface/getRoutes'),
    ('ipsec_sad', 'IPsec SAD', '/api/ipsec/sad/search'),
    ('ipsec_spd', 'IPsec SPD', '/api/ipsec/spd/search'),
    ('ipsec_leases', 'Concesiones IPsec', '/api/ipsec/leases/search'),
    ('ipsec_sessions', 'Sesiones IPsec', '/api/ipsec/sessions/searchPhase1'),
    ('ping_jobs', 'Trabajos ping', '/api/diagnostics/ping/searchJobs'),
):
    _register(_ident, _label, 'Diagnóstico', 'GET', _path)

_register('states', 'Estados del firewall', 'Diagnóstico', 'POST',
          '/api/diagnostics/firewall/queryStates', mutation=False,
          fields=[dict(name='rowCount', label='Filas', kind='integer', min=1, max=200, default=50),
                  dict(name='current', label='Página', kind='integer', min=1, max=100000, default=1)])
_register('reverse_dns', 'DNS inverso', 'Diagnóstico', 'GET', '/api/diagnostics/dns/reverseLookup',
          fields=[dict(name='address', label='Dirección IP', kind='ip', required=True)])

_HOST = dict(name='hostname', label='Hostname o IP', kind='hostname', required=True)
_SOURCE = dict(name='source_address', label='Dirección de origen', kind='ip', required=False)
_register('traceroute', 'Traceroute', 'Diagnóstico', 'POST', '/api/diagnostics/traceroute/set',
          fields=[_HOST, _SOURCE,
                  dict(name='ipproto', label='Familia', kind='select', default='inet',
                       options=[dict(value='inet', label='IPv4'), dict(value='inet6', label='IPv6')]),
                  dict(name='protocol', label='Protocolo', kind='select', default='udp',
                       options=[dict(value='udp', label='UDP'), dict(value='icmp', label='ICMP')])],
          body_key='traceroute.settings', ack=dict(key='result', values=['ok']), confirm=True)
_register('ping_create', 'Preparar trabajo ping', 'Diagnóstico', 'POST', '/api/diagnostics/ping/set',
          fields=[_HOST, _SOURCE,
                  dict(name='fam', label='Familia', kind='select', default='ip',
                       options=[dict(value='ip', label='IPv4'), dict(value='ip6', label='IPv6')]),
                  dict(name='packetsize', label='Tamaño', kind='integer', min=1, max=65535),
                  dict(name='interval', label='Intervalo', kind='integer', min=1, max=120)],
          body_key='ping.settings', ack=dict(key='result', values=['ok']), confirm=True)
for _action, _label in (('start', 'Iniciar ping'), ('stop', 'Detener ping'), ('remove', 'Eliminar trabajo ping')):
    _register('ping_' + _action, _label, 'Diagnóstico', 'POST', '/api/diagnostics/ping/' + _action,
              fields=[dict(name='jobid', label='UUID del trabajo', kind='uuid', required=True)],
              segment='jobid', confirm=True, ack=dict(key='status', values=['ok']))

# Session IDs originate in searchPhase1 rows; native configdpRun receives them
# as a single argument. No request can supply the module, controller or action.
for _action, _label in (('connect', 'Conectar IPsec'), ('disconnect', 'Desconectar IPsec')):
    _register('ipsec_' + _action, _label, 'VPN', 'POST', '/api/ipsec/sessions/' + _action,
              fields=[dict(name='id', label='ID de sesión', kind='identifier', required=True)],
              segment='id', confirm=True, ack=dict(key='result', values=['ok']))


_SECRET = re.compile(r'password|passwd|priv(?:ate)?[_-]?key|api[_-]?key|secret|token|credential|authorization|cookie|psk', re.I)


def _sanitize(value, depth=0):
    if depth > 16:
        raise ManagementError('invalid_response', 'Respuesta demasiado anidada.', 502)
    if isinstance(value, dict):
        return {str(key): _sanitize(item, depth + 1) for key, item in value.items()
                if not _SECRET.search(str(key))}
    if isinstance(value, list):
        return [_sanitize(item, depth + 1) for item in value]
    if isinstance(value, str):
        if re.search(r'-----BEGIN .*PRIVATE KEY-----|https?://[^\s/]+:[^\s/]+@', value, re.I):
            return '[redacted]'
        return value
    if value is None or isinstance(value, (int, float, bool)):
        return value
    raise ManagementError('invalid_response', 'Tipo de respuesta inválido.', 502)


def _values(spec, values):
    if not isinstance(values, dict):
        raise ManagementError('bad_request', 'Valores inválidos.')
    fields = {field['name']: field for field in spec['fields']}
    if set(values) - fields.keys():
        raise ManagementError('bad_request', 'Campo de operación no permitido.')
    result = {}
    for name, field in fields.items():
        value = values.get(name, field.get('default'))
        if value is None or value == '':
            if field.get('required'):
                raise ManagementError('bad_request', 'Falta un campo obligatorio.')
            continue
        kind = field['kind']
        if kind == 'integer':
            if isinstance(value, bool) or not re.fullmatch(r'\d+', str(value)):
                raise ManagementError('bad_request', 'Número inválido.')
            value = int(value)
            if not field['min'] <= value <= field['max']:
                raise ManagementError('bad_request', 'Número fuera de rango.')
        elif not isinstance(value, str) or len(value) > 253 or '\x00' in value:
            raise ManagementError('bad_request', 'Texto inválido.')
        elif kind == 'uuid':
            try:
                validate_uuid(value)
            except ValueError:
                raise ManagementError('bad_request', 'UUID inválido.') from None
        elif kind == 'ip':
            try:
                ipaddress.ip_address(value)
            except ValueError:
                raise ManagementError('bad_request', 'Dirección IP inválida.') from None
        elif kind == 'hostname':
            try:
                ipaddress.ip_address(value)
            except ValueError:
                if not re.fullmatch(r'(?=.{1,253}\.?$)[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?\.?', value):
                    raise ManagementError('bad_request', 'Hostname inválido.') from None
        elif kind == 'identifier' and not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}', value):
            raise ManagementError('bad_request', 'Identificador inválido.')
        elif kind == 'select' and value not in [option['value'] for option in field['options']]:
            raise ManagementError('bad_request', 'Opción inválida.')
        result[name] = value
    return result


def execute_operation(client, audit, actor, operation, values):
    """Execute one known operation; caller must authorize before invocation."""
    if not isinstance(operation, str) or operation not in OPERATIONS:
        raise ManagementError('unsupported', 'Operación no disponible.', 404)
    spec = OPERATIONS[operation]
    payload = _values(spec, values)
    path = spec['path']
    if spec['segment']:
        path += '/' + quote(payload.pop(spec['segment']), safe='')
    if spec['body_key']:
        for part in reversed(spec['body_key'].split('.')):
            payload = {part: payload}
    service = ManagementService(client, audit, actor)
    started = time.monotonic()
    digest = hash_payload(values)
    posted = False

    def record(result, detail):
        try:
            audit.append(AuditEntry.now(user=actor, action='operation.' + operation,
                                       target=operation, host=getattr(getattr(client, 'host', None), 'name', 'firewall'),
                                       result=result, duration_ms=int((time.monotonic() - started) * 1000),
                                       detail=detail, payload_sha256=digest))
        except Exception:
            error = ManagementError('audit', 'No se pudo registrar la operación.', 503,
                                    partial=posted, stage='audit')
            error.audit_failure = True
            raise error from None

    if spec['method'] == 'POST':
        record('attempt', 'Solicitud validada; pendiente de envío.')
    try:
        if spec['method'] == 'POST':
            posted = True
            response = service._call('post', path, payload)
        else:
            response = service._call('get', path, **payload)
        if not isinstance(response, (dict, list)):
            raise ManagementError('invalid_response', 'Respuesta de operación inválida.', 502)
        if isinstance(response, dict):
            if response.get('validations'):
                raise ManagementError('validation', 'OPNsense rechazó los valores.', 422)
            if response.get('error') or response.get('errorMessage'):
                raise ManagementError('upstream', 'OPNsense rechazó la operación.', 502)
            if any(str(response.get(key, '')).lower() in ('failed', 'failure', 'error')
                   for key in ('status', 'result')):
                raise ManagementError('upstream', 'OPNsense rechazó la operación.', 502)
        if spec['ack']:
            ack = spec['ack']
            if not isinstance(response, dict) or str(response.get(ack['key'], '')).lower() not in ack['values']:
                raise ManagementError('upstream', 'OPNsense no confirmó la solicitud.', 502)
            if operation == 'monit_reconfigure' and (
                    response.get('template') != 'OK' or response.get('result') != 'Control file syntax OK'):
                raise ManagementError('upstream', 'Monit no confirmó una configuración válida.', 502)
        verified = False
        state = 'accepted' if spec['method'] == 'POST' and spec['mutation'] else 'observed'
        if spec['verify']:
            status = service._call('get', spec['verify']['path'])
            if not isinstance(status, dict) or status.get('status') not in spec['verify']['expected']:
                raise ManagementError('verification', 'El estado del servicio no coincide con lo solicitado.', 502,
                                      partial=True, stage='verify')
            verified, state = True, status['status']
        result = dict(operation=operation, accepted=spec['method'] == 'POST', verified=verified,
                      state=state, result=_sanitize(response))
        if spec['method'] == 'POST':
            record('ok', 'Estado verificado.' if verified else 'Respuesta recibida; sin afirmar aplicación.')
        return result
    except ManagementError as error:
        error.partial = error.partial or (posted and error.error not in ('validation', 'auth'))
        error.stage = error.stage or ('operation' if posted else 'read')
        if posted and not error.audit_failure:
            try:
                record('error', error.error)
            except ManagementError:
                error.audit_failure = True
        raise
