"""Native trust/CRL adapter, backed by OPNsense core 26.1.2 CrlController.

CRLs are addressed by CA refid (13 hex digits), not the CRL's own refid.
set creates or replaces a CRL and schedules trust regeneration asynchronously.
"""
from __future__ import annotations

import copy
import re
import threading
import time

from cryptography import x509

from src.management.engine import ManagementError, ManagementService
from src.writers.audit import AuditEntry, hash_payload


_BASE = '/api/trust/crl/'
_LOCK = threading.RLock()
_REASONS = ('Sin especificar', 'Clave comprometida', 'CA comprometida', 'Cambio de afiliación',
            'Sustituido', 'Cese de operaciones', 'Certificado suspendido')
CRL_RESOURCE = dict(
    id='trust_crl', label='Listas de revocación CRL', group='Certificados', id_kind='refid',
    qualification='contract_only', ha_safe=False,
    fields=[dict(name='caref', label='Referencia CA', kind='text', readonly=True),
            dict(name='descr', label='Descripción', kind='text', required=True),
            dict(name='crlmethod', label='Método', kind='select', required=True,
                 options=[dict(value='internal', label='Generar internamente'),
                          dict(value='existing', label='Importar CRL PEM')]),
            dict(name='serial', label='Número de CRL', kind='integer', readonly=True),
            dict(name='lifetime', label='Vigencia en días', kind='integer', required=True, min=1, max=36500),
            dict(name='text', label='CRL PEM', kind='text')]
    + [dict(name=f'revoked_reason_{number}', label=label, kind='select', multiple=True)
       for number, label in enumerate(_REASONS)],
    columns=['descr', 'crl_descr'],
    source='opnsense/core@26.1.2:Trust/Api/CrlController.php',
)


def _refid(value):
    if not isinstance(value, str) or not re.fullmatch(r'[0-9a-f]{13}', value):
        raise ManagementError('bad_request', 'La referencia CA/certificado debe tener 13 dígitos hexadecimales.')
    return value


def _selected(value):
    if value == []:
        return ''
    if isinstance(value, dict):
        return ','.join(str(key) for key, option in value.items()
                        if isinstance(option, dict) and option.get('selected') in ('1', 1, True))
    if isinstance(value, str):
        return value
    raise ManagementError('invalid_response', 'Selector CRL inválido.', 502)


class CrlService:
    def __init__(self, client, audit, actor='plugin', peer=None):
        self.client, self.audit, self.actor, self.peer = client, audit, actor, peer
        self.service = ManagementService(client, audit, actor)

    def list(self, page=1, row_count=50, search=''):
        if (isinstance(page, bool) or not isinstance(page, int) or not 1 <= page <= 100000
                or isinstance(row_count, bool) or not isinstance(row_count, int) or not 1 <= row_count <= 200
                or not isinstance(search, str) or len(search) > 256):
            raise ManagementError('bad_request', 'Paginación CRL inválida.')
        response = self.service._call('get', _BASE + 'search', current=page,
                                      rowCount=row_count, searchPhrase=search)
        if not isinstance(response, dict) or not isinstance(response.get('rows'), list):
            raise ManagementError('invalid_response', 'Listado CRL inválido.', 502)
        rows = []
        for row in response['rows']:
            if not isinstance(row, dict):
                raise ManagementError('invalid_response', 'Fila CRL inválida.', 502)
            try:
                ident = _refid(row.get('refid'))
            except ManagementError:
                raise ManagementError('invalid_response', 'Referencia CRL inválida.', 502) from None
            rows.append(dict(uuid=ident, refid=ident,
                             **{key: row[key] for key in ('descr', 'crl_descr') if isinstance(row.get(key), str)}))
        total = response.get('total')
        if isinstance(total, bool) or not str(total).isdigit() or int(total) < len(rows):
            raise ManagementError('invalid_response', 'Total CRL inválido.', 502)
        return dict(rows=rows, total=int(total), page=page, row_count=row_count)

    def _raw(self, caref):
        caref = _refid(caref)
        response = self.service._call('get', _BASE + 'get/' + caref)
        raw = response.get('crl') if isinstance(response, dict) else None
        if not isinstance(raw, dict) or raw.get('caref') != caref:
            raise ManagementError('invalid_response', 'No se recibió la CA/CRL solicitada.', 502)
        item = {'caref': caref}
        for name in ('descr', 'serial', 'lifetime', 'text'):
            value = raw.get(name, '' if name in ('descr', 'text') else None)
            if not isinstance(value, str):
                raise ManagementError('invalid_response', 'Detalle CRL inválido.', 502)
            item[name] = value
        if not item['serial'].isdigit() or not item['lifetime'].isdigit():
            raise ManagementError('invalid_response', 'Contadores CRL inválidos.', 502)
        if 'PRIVATE KEY' in item['text']:
            raise ManagementError('invalid_response', 'La respuesta contiene material no permitido.', 502)
        item['crlmethod'] = _selected(raw.get('crlmethod'))
        if item['crlmethod'] not in ('internal', 'existing'):
            raise ManagementError('invalid_response', 'Método CRL inválido.', 502)
        choices = {}
        for number in range(7):
            name = f'revoked_reason_{number}'
            options = raw.get(name)
            if options == []:
                options = {}
            if not isinstance(options, dict):
                raise ManagementError('invalid_response', 'Referencias de revocación inválidas.', 502)
            choices[name] = []
            for ref, option in options.items():
                try:
                    _refid(ref)
                except ManagementError:
                    raise ManagementError('invalid_response', 'Referencia de certificado inválida.', 502) from None
                if not isinstance(option, dict) or not isinstance(option.get('value'), str):
                    raise ManagementError('invalid_response', 'Opción de revocación inválida.', 502)
                choices[name].append(dict(value=ref, label=option['value']))
            item[name] = _selected(options)
        return item, choices

    def detail(self, caref):
        item, choices = self._raw(caref)
        fields = copy.deepcopy(CRL_RESOURCE['fields'])
        for field in fields:
            if field['name'] in choices:
                field['options'] = choices[field['name']]
        return dict(item=dict(item, uuid=caref), fields=fields, revision=hash_payload([item, choices]),
                    exists=bool(item['descr']))

    @staticmethod
    def _validate(values, current, choices):
        allowed = {field['name'] for field in CRL_RESOURCE['fields'] if not field.get('readonly')}
        if not isinstance(values, dict) or set(values) - allowed:
            raise ManagementError('bad_request', 'Campo CRL no permitido.')
        payload = {**current, **values}
        if not isinstance(payload['descr'], str) or not 1 <= len(payload['descr']) <= 255 or any(
                ord(char) < 32 for char in payload['descr']):
            raise ManagementError('bad_request', 'Descripción CRL inválida.')
        if payload['crlmethod'] not in ('internal', 'existing'):
            raise ManagementError('bad_request', 'Método CRL inválido.')
        lifetime = payload['lifetime']
        if isinstance(lifetime, bool) or not str(lifetime).isdigit() or not 1 <= int(lifetime) <= 36500:
            raise ManagementError('bad_request', 'Vigencia CRL inválida.')
        payload['lifetime'] = str(lifetime)
        seen = set()
        for number in range(7):
            name = f'revoked_reason_{number}'
            value = payload[name]
            refs = value if isinstance(value, list) else value.split(',') if isinstance(value, str) and value else []
            if not isinstance(value, (list, str)) or len(refs) > 5000:
                raise ManagementError('bad_request', 'Lista de certificados inválida.')
            allowed_refs = {choice['value'] for choice in choices[name]}
            for ref in refs:
                _refid(ref)
                if ref not in allowed_refs or ref in seen:
                    raise ManagementError('bad_request', 'Certificado ajeno a la CA o motivo duplicado.')
                seen.add(ref)
            payload[name] = ','.join(refs)
        if payload['crlmethod'] == 'existing':
            text = payload.get('text')
            if not isinstance(text, str) or len(text) > 1024 * 1024:
                raise ManagementError('bad_request', 'CRL PEM inválida.')
            try:
                x509.load_pem_x509_crl(text.encode('ascii'))
            except (ValueError, UnicodeError):
                raise ManagementError('bad_request', 'CRL PEM inválida.') from None
        else:
            payload.pop('text', None)
        return payload

    def mutate(self, body):
        if self.peer is not None:
            raise ManagementError('ha_unqualified', 'La escritura CRL no está calificada para HA.', 409)
        if not isinstance(body, dict) or body.get('action') not in ('create', 'update', 'delete', 'revoke'):
            raise ManagementError('bad_request', 'Acción CRL inválida.')
        caref = _refid(body.get('uuid'))
        revision = body.get('revision')
        if not isinstance(revision, str) or not re.fullmatch(r'[0-9a-f]{64}', revision):
            raise ManagementError('bad_request', 'Se requiere la revisión CRL vigente.')
        action = body['action']
        started, posted = time.monotonic(), False

        def record(result, digest):
            try:
                self.audit.append(AuditEntry.now(user=self.actor, action='crl.' + action, target=caref,
                                                host=self.client.host.name, result=result,
                                                duration_ms=int((time.monotonic() - started) * 1000),
                                                payload_sha256=digest))
            except Exception:
                error = ManagementError('audit', 'No se pudo registrar la operación CRL.', 503,
                                        partial=posted, stage='audit')
                error.audit_failure = True
                raise error from None

        with _LOCK:
            current, choices = self._raw(caref)
            if hash_payload([current, choices]) != revision:
                raise ManagementError('conflict', 'La CRL cambió; recargue antes de guardar.', 409)
            exists = bool(current['descr'])
            if action == 'create' and exists or action in ('update', 'delete', 'revoke') and not exists:
                raise ManagementError('conflict', 'El estado de la CRL cambió.', 409)
            values = body.get('values', {})
            if action == 'revoke':
                if not isinstance(values, dict) or set(values) != {'certificate', 'reason'}:
                    raise ManagementError('bad_request', 'Se requieren certificado y motivo.')
                cert = _refid(values['certificate'])
                reason = str(values['reason'])
                if reason not in {str(i) for i in range(7)} or current['crlmethod'] != 'internal':
                    raise ManagementError('bad_request', 'Motivo inválido o CRL importada.')
                values = {f'revoked_reason_{i}': [ref for ref in current[f'revoked_reason_{i}'].split(',')
                                                if ref and ref != cert] for i in range(7)}
                values['revoked_reason_' + reason].append(cert)
            payload = {} if action == 'delete' else self._validate(values, current, choices)
            digest = hash_payload(payload)
            record('attempt', digest)
            try:
                posted = True
                response = self.service._call('post', _BASE + ('del/' if action == 'delete' else 'set/') + caref,
                                              {} if action == 'delete' else {'crl': payload})
                if isinstance(response, dict) and response.get('validations'):
                    raise ManagementError('validation', 'OPNsense rechazó la CRL.', 422)
                expected = 'deleted' if action == 'delete' else 'saved'
                if not isinstance(response, dict) or response.get('status') != expected:
                    raise ManagementError('upstream', 'OPNsense no confirmó la operación CRL.', 502)
                after, _ = self._raw(caref)
                if action == 'delete':
                    matches = not after['descr'] and not after['text'] and after['serial'] == '0'
                else:
                    matches = all(after[name] == payload[name] for name in ('descr', 'lifetime', 'crlmethod'))
                    if payload['crlmethod'] == 'internal':
                        matches = matches and all(set(after[f'revoked_reason_{i}'].split(',')) == set(
                            payload[f'revoked_reason_{i}'].split(',')) for i in range(7))
                    else:
                        matches = matches and after['text'].strip() == payload['text'].strip()
                    matches = matches and int(after['serial']) == int(current['serial']) + 1
                if not matches:
                    raise ManagementError('verification', 'La CRL guardada no coincide con lo solicitado.', 502)
                record('ok', digest)
                return dict(uuid=caref, caref=caref, config_saved=True, verified=True, applied=False,
                            ha_verified=False, state='config_verified_trust_regeneration_pending')
            except (ManagementError, ValueError) as exc:
                error = exc if isinstance(exc, ManagementError) else ManagementError(
                    'invalid_response', 'La revisión CRL recibida es inválida.', 502)
                error.partial = error.error not in ('validation', 'auth')
                error.stage = error.stage or 'crl_write'
                if not error.audit_failure:
                    try:
                        record('error', digest)
                    except ManagementError:
                        error.audit_failure = True
                raise error from None
