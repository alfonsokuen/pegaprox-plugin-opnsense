"""Catalog-driven management; POSTs are never retried or speculatively rolled back."""
from __future__ import annotations

import copy
import threading
import time

from src.client import OPNsenseAuthError, OPNsenseError, OPNsenseTimeoutError
from src.writers.audit import AuditEntry, hash_payload
from src.writers.verified import validate_revision, validate_uuid

_GUARD = threading.Lock()
_LOCKS = {}
SINGLETON_UUID = '00000000-0000-0000-0000-000000000000'


def selected(value):
    """Canonical form values, including PHP JSON arrays for numeric options."""
    if isinstance(value, (dict, list)):
        if not value:
            return ''
        items = value.items() if isinstance(value, dict) else enumerate(value)
        items = list(items)
        if all(isinstance(child, dict) and 'selected' in child for _, child in items):
            return ','.join(str(key) for key, child in items if str(child['selected']) == '1')
        if isinstance(value, dict):
            return {key: selected(child) for key, child in items}
        return [selected(child) for _, child in items]
    return value


class ManagementError(Exception):
    def __init__(self, error, detail, status=400, *, partial=False, stage=None):
        super().__init__(detail)
        self.error, self.detail, self.status = error, detail, status
        self.partial, self.stage = partial, stage
        self.audit_failure = False
        self.validations = {}
        self.uuid = None

    def as_dict(self):
        result = dict(ok=False, error=self.error, detail=self.detail,
                      partial=self.partial, stage=self.stage)
        if self.audit_failure:
            result['audit_failure'] = True
        if self.validations:
            result['validations'] = self.validations
        if self.uuid:
            result['uuid'] = self.uuid
        return result


def _get(data, name, default=None):
    if name in data:
        return data[name]
    value = data
    for part in name.split('.'):
        if not isinstance(value, dict) or part not in value:
            return default
        value = value[part]
    return value


def _put(data, name, value):
    if name in data:
        data[name] = value
        return
    parts = name.split('.')
    for part in parts[:-1]:
        if not isinstance(data.get(part), dict):
            data[part] = {}
        data = data[part]
    data[parts[-1]] = value


def _drop(data, name):
    if name in data:
        data.pop(name)
        return
    parts = name.split('.')
    for part in parts[:-1]:
        data = data.get(part, {})
        if not isinstance(data, dict):
            return
    data.pop(parts[-1], None)


def _path(spec, operation, uuid=None):
    path = spec.get(operation)
    if not isinstance(path, str) or not path:
        raise ManagementError('unsupported', 'Esta operación no está disponible.', 405)
    path = path if path.startswith('/api/') else spec['base'].rstrip('/') + '/' + path
    return path.rstrip('/') + ('/' + uuid if uuid and not spec.get('singleton') else '')


def _ack(response, spec, *, apply=False):
    if not isinstance(response, dict):
        raise ManagementError('invalid_response', 'Respuesta de operación inválida.', 502)
    if response.get('validations'):
        error = ManagementError('validation', 'OPNsense rechazó los valores enviados.', 422)
        validations = response['validations']
        if isinstance(validations, dict):
            for field in spec['fields']:
                name = field['name']
                if name in validations or spec['key'] + '.' + name in validations:
                    error.validations[name] = 'Valor rechazado por OPNsense'
        raise error
    if apply and spec.get('apply_ack'):
        if all(response.get(key) in permitted for key, permitted in spec['apply_ack'].items()):
            return
        raise ManagementError('upstream', 'OPNsense no confirmó la aplicación.', 502)
    markers = [str(response[key]).lower() for key in ('status', 'result') if key in response]
    if not markers or any(value not in ('ok', 'saved', 'deleted', 'done', 'success') for value in markers):
        raise ManagementError('upstream', 'OPNsense no confirmó la operación.', 502)


class ManagementService:
    def __init__(self, client, audit, actor='plugin', peer=None):
        self.client, self.audit, self.actor, self.peer = client, audit, actor, peer

    def _call(self, method, path, *args, **kwargs):
        try:
            return getattr(self.client, method)(path, *args, **kwargs)
        except OPNsenseAuthError:
            raise ManagementError('auth', 'OPNsense denegó acceso a esta operación.', 401) from None
        except OPNsenseTimeoutError:
            raise ManagementError('timeout', 'OPNsense no respondió a tiempo.', 504) from None
        except OPNsenseError as exc:
            missing = 'HTTP 404' in str(exc)
            raise ManagementError('unsupported' if missing else 'upstream',
                                  'La API no está disponible.' if missing else 'Falló la comunicación con OPNsense.',
                                  502) from None

    def _raw(self, spec, uuid=None):
        response = self._call('get', _path(spec, 'get', uuid))
        raw = _get(response, spec['key']) if isinstance(response, dict) else None
        if not isinstance(raw, dict) or not raw:
            raise ManagementError('invalid_response', 'No se recibió el objeto solicitado.', 502)
        return raw

    def _public(self, spec, raw, listing=False):
        item = {}
        if isinstance(raw.get('uuid'), str):
            item['uuid'] = raw['uuid']
        for field in spec['fields']:
            name = field['name']
            if field.get('secret') or field.get('write_only'):
                if not listing:
                    item[name] = ''
                continue
            value = _get(raw, name)
            if value == {}:
                value = ''
            if value is not None and isinstance(value, (str, bool, int, float)):
                item[name] = value
        return item

    def list(self, spec, page=1, row_count=50, search=''):
        if isinstance(page, bool) or not isinstance(page, int) or not 1 <= page <= 100000:
            raise ManagementError('bad_request', 'Página inválida.')
        if isinstance(row_count, bool) or not isinstance(row_count, int) or not 1 <= row_count <= 200:
            raise ManagementError('bad_request', 'Tamaño de página inválido.')
        if not isinstance(search, str) or len(search) > 256 or '\x00' in search:
            raise ManagementError('bad_request', 'Texto de búsqueda inválido.')
        if spec.get('singleton'):
            detail = self.detail(spec, SINGLETON_UUID)
            return dict(rows=[detail['item']], total=1, page=page, row_count=row_count)
        out = self._call('get', _path(spec, 'search'), current=page, rowCount=row_count, searchPhrase=search)
        if not isinstance(out, dict) or not isinstance(out.get('rows'), list) or any(not isinstance(row, dict) for row in out['rows']):
            raise ManagementError('invalid_response', 'Lista de objetos inválida.', 502)
        try:
            total = int(out['total'])
            if isinstance(out['total'], bool) or total < len(out['rows']):
                raise ValueError()
        except (KeyError, TypeError, ValueError):
            raise ManagementError('invalid_response', 'Total de objetos inválido.', 502) from None
        return dict(rows=[self._public(spec, selected(row), True) for row in out['rows']],
                    total=total, page=page, row_count=row_count)

    def detail(self, spec, uuid=None):
        if uuid is not None:
            try:
                uuid = validate_uuid(uuid)
            except (ValueError, TypeError):
                raise ManagementError('bad_request', 'UUID inválido.') from None
        if spec.get('singleton'):
            if uuid not in (None, SINGLETON_UUID):
                raise ManagementError('bad_request', 'Identificador de configuración inválido.')
            uuid = SINGLETON_UUID
        raw = self._raw(spec, uuid)
        canonical = selected(raw)
        fields = copy.deepcopy(spec['fields'])
        for field in fields:
            options = _get(raw, field['name'])
            if not field.get('secret') and isinstance(options, (dict, list)) and options:
                items = list(options.items() if isinstance(options, dict) else enumerate(options))
                if all(isinstance(value, dict) and 'selected' in value for _, value in items):
                    if field.get('options'):
                        permitted = {str(option['value']) for option in field['options']}
                        items = [(key, value) for key, value in items if str(key) in permitted]
                    field['options'] = [{'value': str(key), 'label': str(value.get('value', key))} for key, value in items]
        result = dict(item=self._public(spec, canonical), fields=fields)
        for field in fields:
            default_name = 'edit_default' if uuid else 'create_default'
            if default_name in field:
                result['item'][field['name']] = field[default_name]
        if uuid:
            result['item']['uuid'] = uuid
            result['revision'] = hash_payload(canonical)
        return result

    def _values(self, spec, values, current, creating):
        if not isinstance(values, dict):
            raise ManagementError('bad_request', 'Se requiere un objeto values.')
        fields = {field['name']: field for field in spec['fields']}
        if set(values) - fields.keys():
            raise ManagementError('bad_request', 'Hay campos no permitidos.')
        if creating:
            # Form GETs include derived/controller-only fields. They are not
            # creation input; use only catalogued fields and their defaults.
            merged = {}
            for name, field in fields.items():
                if field.get('readonly'):
                    continue
                value = _get(current, name, field.get('default'))
                if value is not None:
                    _put(merged, name, copy.deepcopy(value))
        else:
            merged = copy.deepcopy(current)
        def normalize_empty_options(value):
            if isinstance(value, dict):
                return {key: '' if child == {} else normalize_empty_options(child) for key, child in value.items()}
            return value
        merged = normalize_empty_options(merged)
        for name, field in fields.items():
            if field.get('readonly') or field.get('write_only'):
                _drop(merged, name)
        for name, value in values.items():
            field = fields[name]
            if field.get('generated') and value in ('', None):
                continue
            if field.get('readonly'):
                raise ManagementError('bad_request', 'Un campo de solo lectura no admite cambios.')
            if (field.get('secret') or field.get('write_only')) and value in ('', None) and not creating:
                continue
            kind = field.get('kind', 'text')
            if field.get('multiple'):
                if isinstance(value, list) and all(isinstance(item, str) for item in value):
                    value = ','.join(value)
                if not isinstance(value, str) or len(value) > 65536 or '\x00' in value:
                    raise ManagementError('bad_request', 'Selección múltiple inválida.')
            elif kind in ('boolean', 'checkbox'):
                if not isinstance(value, bool):
                    raise ManagementError('bad_request', 'Un campo booleano tiene un valor inválido.')
                value = '1' if value else '0'
            elif kind in ('number', 'integer'):
                if value == '' and not field.get('required'):
                    _put(merged, name, '')
                    continue
                if isinstance(value, bool) or not str(value).lstrip('-').isdigit():
                    raise ManagementError('bad_request', 'Un campo numérico tiene un valor inválido.')
                value = str(value)
                if ('min' in field and int(value) < field['min']) or ('max' in field and int(value) > field['max']):
                    raise ManagementError('bad_request', 'Valor numérico fuera de rango.')
            elif not isinstance(value, str) or len(value) > 65536 or '\x00' in value:
                raise ManagementError('bad_request', 'Valor de campo inválido.')
            if field.get('options') and value != '':
                permitted = {str(option['value']) for option in field['options']}
                choices = value.split(',') if field.get('multiple') else [value]
                if any(choice not in permitted for choice in choices):
                    raise ManagementError('bad_request', 'Selección fuera de las opciones permitidas.')
            _put(merged, name, value)
        for name, field in fields.items():
            if field.get('required') and not (field.get('write_only') and not creating) and _get(merged, name) in (None, ''):
                raise ManagementError('bad_request', 'Falta un campo obligatorio.')
        return merged

    def _audit(self, spec, action, uuid, result, payload, started):
        try:
            self.audit.append(AuditEntry.now(user=self.actor, action=spec['id'] + '.' + action,
                target=uuid, host=self.client.host.name, result=result,
                duration_ms=int((time.monotonic() - started) * 1000), payload_sha256=hash_payload(payload)))
        except (OSError, AttributeError):
            raise ManagementError('audit', 'No se pudo persistir la auditoría.', 503) from None

    def mutate(self, spec, body):
        if self.peer is not None and spec.get('ha_safe') is not True:
            raise ManagementError('ha_unqualified', 'Este módulo aún no tiene escritura HA verificada.', 409)
        if not isinstance(body, dict) or body.get('action') not in ('create', 'update', 'delete'):
            raise ManagementError('bad_request', 'Acción inválida.')
        action = body['action']
        if spec.get('singleton') and action != 'update':
            raise ManagementError('unsupported', 'Esta configuración solo admite actualización.', 405)
        uuid = ''
        revision = ''
        if action != 'create':
            try:
                uuid, revision = validate_uuid(body.get('uuid')), validate_revision(body.get('revision'))
            except (ValueError, TypeError):
                raise ManagementError('bad_request', 'UUID o revisión inválidos.') from None
            if spec.get('singleton') and uuid != SINGLETON_UUID:
                raise ManagementError('bad_request', 'Identificador de configuración inválido.')
        operation = dict(create='add', update='set', delete='delete')[action]
        _path(spec, operation, uuid)
        if not spec.get('apply') and spec.get('persistence_only') is not True:
            raise ManagementError('unsupported', 'No hay acción de aplicación verificada.', 405)
        key = (self.client.host.url, spec['id'])
        with _GUARD:
            lock = _LOCKS.setdefault(key, threading.Lock())
        with lock:
            return self._mutate(spec, body, action, operation, uuid, revision)

    def _mutate(self, spec, body, action, operation, uuid, revision):
        started = time.monotonic()
        current = selected(self._raw(spec, uuid or None))
        if action != 'create' and hash_payload(current) != revision:
            raise ManagementError('conflict', 'El objeto cambió; vuelve a cargarlo.', 409)
        expected = self._values(spec, body.get('values'), current, action == 'create') if action != 'delete' else None
        if expected is not None and spec.get('prepare'):
            expected = spec['prepare'](spec, expected, current, action)
        payload = {}
        if expected is not None:
            _put(payload, spec['key'], expected)
        self._audit(spec, action, uuid, 'started', payload, started)
        stage, partial, confirmed_uuid = 'save', False, None
        try:
            partial = True
            response = self._call('post', _path(spec, operation, uuid), payload)
            _ack(response, spec)
            if action == 'create':
                try:
                    uuid = validate_uuid(response.get('uuid'))
                except (ValueError, TypeError):
                    raise ManagementError('invalid_response', 'Creación sin UUID confirmado; revisa el estado.', 502) from None
            confirmed_uuid = uuid
            stage = 'apply'
            apply = spec.get('apply')
            paths = apply if isinstance(apply, list) else [apply] if apply else []
            if not paths and spec.get('persistence_only') is not True:
                raise ManagementError('unsupported', 'No hay acción de aplicación verificada.', 502)
            for path in paths:
                _ack(self._call('post', path, {}), spec, apply=True)
            stage = 'verify'
            if action == 'delete':
                # Exhaustively scan bounded pages; a partial page cannot prove absence.
                page = 1
                observed_count = 0
                while True:
                    listing = self.list(spec, page=page, row_count=200)
                    observed_count += len(listing['rows'])
                    if any(row.get('uuid', '').lower() == uuid for row in listing['rows']):
                        raise ManagementError('unverified', 'El objeto sigue presente tras eliminarlo.', 502)
                    if observed_count >= listing['total']:
                        break
                    if len(listing['rows']) < 200 or page >= 1000:
                        raise ManagementError('unverified', 'No se pudo verificar la lista completa.', 502)
                    page += 1
            else:
                actual = selected(self._raw(spec, uuid))
                for field in spec['fields']:
                    name = field['name']
                    if name not in body.get('values', {}) or field.get('volatile') or field.get('readonly') or field.get('write_only'):
                        continue
                    if field.get('generated') and body['values'][name] in ('', None):
                        continue
                    if _get(expected, name) is None:
                        continue
                    observed, desired = _get(actual, name, ''), _get(expected, name, '')
                    observed = '' if observed == {} else str(observed)
                    desired = '' if desired == {} else str(desired)
                    if field.get('multiple'):
                        observed, desired = sorted(observed.split(',')), sorted(desired.split(','))
                    if observed != desired:
                        raise ManagementError('unverified', 'La lectura posterior no coincide con el cambio.', 502)
                if spec.get('verify'):
                    spec['verify'](spec, actual, expected, action)
            if self.peer is not None:
                peer_service = ManagementService(self.peer, self.audit, self.actor)
                if action == 'delete':
                    page = 1
                    observed_count = 0
                    while True:
                        listing = peer_service.list(spec, page=page, row_count=200)
                        observed_count += len(listing['rows'])
                        if any(row.get('uuid', '').lower() == uuid for row in listing['rows']):
                            raise ManagementError('ha_unverified', 'El peer todavía contiene el objeto.', 409)
                        if observed_count >= listing['total']:
                            break
                        if len(listing['rows']) < 200 or page >= 1000:
                            raise ManagementError('ha_unverified', 'No se verificó la lista completa del peer.', 409)
                        page += 1
                elif hash_payload(selected(peer_service._raw(spec, uuid))) != hash_payload(actual):
                    raise ManagementError('ha_unverified', 'El objeto del peer no coincide.', 409)
            self._audit(spec, action, uuid, 'ok', payload, started)
            result = dict(ok=True, uuid=uuid, action=action, applied=bool(paths), config_saved=True, verified=True)
            if any(field.get('write_only') and body.get('values', {}).get(field['name']) not in (None, '') for field in spec['fields']):
                result.update(secret_change_acknowledged=True, secret_verified=False)
            return result
        except ManagementError as exc:
            if exc.error == 'validation' and stage == 'save':
                partial = False
            exc.partial, exc.stage = partial, stage
            exc.uuid = confirmed_uuid
            try:
                self._audit(spec, action, uuid, 'error', payload, started)
            except ManagementError:
                exc.audit_failure = True
            raise
