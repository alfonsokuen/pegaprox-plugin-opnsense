"""Encrypted local copies of OPNsense's latest historical configuration backup.

This does not export the current live configuration or restore a firewall.
The caller must enforce administrator authorization for every method.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import threading
from datetime import datetime, timezone
from uuid import UUID, uuid4
from urllib.parse import urlsplit

import requests
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from defusedxml import ElementTree

from src.management.engine import ManagementError
from src.writers.audit import AuditEntry

MAX_XML = 16 * 1024 * 1024
MAX_ENVELOPE = 23 * 1024 * 1024
_LOCK = threading.RLock()


def _error(detail='No se pudo procesar el respaldo.', status=502):
    return ManagementError('backup', detail, status)


def _xml(payload):
    if not payload or len(payload) > MAX_XML:
        raise _error('El respaldo está vacío o excede 16 MiB.')
    try:
        tree = ElementTree.fromstring(payload, forbid_dtd=True, forbid_entities=True, forbid_external=True)
        if tree.tag != 'opnsense':
            raise ValueError()
    except Exception:
        raise _error('El archivo no es un respaldo XML válido de OPNsense.') from None


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')


class BackupStore:
    def __init__(self, root, audit, actor):
        supplied = Path(root).absolute()
        self.root = supplied.resolve()
        if os.path.normcase(str(supplied)) != os.path.normcase(str(self.root)):
            raise _error('El directorio de respaldos no puede usar enlaces.', 400)
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.root, 0o700)
        self.parent = self.root.parent
        self.key_path = self.parent / 'backups.key'
        self._root_id = self._identity(self.root)
        self._parent_id = self._identity(self.parent)
        self.audit, self.actor = audit, actor

    @staticmethod
    def _identity(path):
        info = path.stat()
        return info.st_dev, info.st_ino

    def _pinned(self):
        try:
            valid = (not self.root.is_symlink() and not self.parent.is_symlink()
                     and self.root.resolve() == self.root
                     and self._identity(self.root) == self._root_id
                     and self._identity(self.parent) == self._parent_id)
        except OSError:
            valid = False
        if not valid:
            raise _error('El directorio de respaldos cambió.', 409)

    def _path(self, ident):
        try:
            if not isinstance(ident, str) or str(UUID(ident)) != ident:
                raise ValueError()
        except (ValueError, AttributeError):
            raise _error('Identificador de respaldo inválido.', 400) from None
        self._pinned()
        path = self.root / (ident + '.enc')
        if path.is_symlink() or path.parent != self.root:
            raise _error('Ruta de respaldo inválida.', 400)
        return path

    def _record(self, action, ident='', digest=''):
        try:
            self.audit.append(AuditEntry.now(user=self.actor, action='backup.' + action,
                                            target=ident, host='local-store', result='attempt',
                                            duration_ms=0, payload_sha256=digest))
        except Exception:
            raise ManagementError('audit', 'No se pudo registrar el acceso al respaldo.', 503) from None

    def _key(self, create=False):
        self._pinned()
        if self.key_path.is_symlink():
            raise _error('Llave de respaldos inválida.', 409)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if create and not self.key_path.exists():
            if any(self.root.glob('*.enc')):
                raise _error('Falta la llave de los respaldos existentes; no se generará otra.', 409)
            try:
                fd = os.open(self.key_path, flags, 0o600)
            except FileExistsError:
                pass
            else:
                with os.fdopen(fd, 'wb') as stream:
                    stream.write(secrets.token_bytes(32))
                    stream.flush()
                    os.fsync(stream.fileno())
                os.chmod(self.key_path, 0o600)
        try:
            fd = os.open(self.key_path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
            with os.fdopen(fd, 'rb') as stream:
                value = stream.read(33)
            if len(value) != 32:
                raise ValueError()
            return value
        except (OSError, ValueError):
            raise _error('La llave de respaldos no está disponible o es inválida.', 409) from None

    @staticmethod
    def _download(host):
        if not isinstance(host.url, str) or not host.url.startswith('https://'):
            raise _error('El firewall requiere HTTPS.', 400)
        parsed = urlsplit(host.url)
        if not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise _error('La dirección del firewall no es válida.', 400)
        try:
            with requests.Session() as session:
                session.auth = (host.api_key, host.api_secret)
                with session.get(host.url.rstrip('/') + '/api/core/backup/download/this',
                                 verify=host.ca_bundle_path or host.verify_tls,
                                 timeout=(host.connect_timeout, host.read_timeout),
                                 allow_redirects=False, stream=True) as response:
                    if response.status_code in (401, 403):
                        raise ManagementError('auth', 'OPNsense denegó acceso al respaldo.', 401)
                    if response.status_code != 200:
                        raise _error('OPNsense no entregó el respaldo.')
                    declared = response.headers.get('Content-Length')
                    if declared is not None and (not declared.isdigit() or int(declared) > MAX_XML):
                        raise _error('El respaldo excede el tamaño permitido.')
                    chunks, size = [], 0
                    for chunk in response.iter_content(65536):
                        size += len(chunk)
                        if size > MAX_XML:
                            raise _error('El respaldo excede 16 MiB.')
                        chunks.append(chunk)
                    payload = b''.join(chunks)
        except requests.Timeout:
            raise ManagementError('timeout', 'OPNsense no entregó el respaldo a tiempo.', 504) from None
        except requests.RequestException:
            raise _error('Falló la descarga del respaldo.') from None
        _xml(payload)
        return payload

    def create(self, host):
        self._pinned()
        self._record('create')
        payload = self._download(host)
        ident = str(uuid4())
        metadata = dict(id=ident, date=datetime.now(timezone.utc).isoformat(),
                        host=re.sub(r'[^\w .-]', '', host.name)[:80],
                        sha256=hashlib.sha256(payload).hexdigest(), size=len(payload),
                        source='latest_historical_backup', format='opnsense-xml')
        with _LOCK:
            key = self._key(create=True)
            nonce = secrets.token_bytes(12)
            ciphertext = AESGCM(key).encrypt(nonce, payload, _canonical(metadata))
            envelope = dict(version=1, metadata=metadata,
                            nonce=base64.b64encode(nonce).decode('ascii'),
                            ciphertext=base64.b64encode(ciphertext).decode('ascii'))
            target = self._path(ident)
            temp = self.root / ('.' + ident + '.tmp')
            try:
                fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, 'wb') as stream:
                    stream.write(_canonical(envelope))
                    stream.flush()
                    os.fsync(stream.fileno())
                self._pinned()
                os.replace(temp, target)
                os.chmod(target, 0o600)
            except OSError:
                raise _error('No se pudo guardar el respaldo cifrado.', 503) from None
            finally:
                if temp.exists() and not temp.is_symlink():
                    temp.unlink()
        return metadata

    def _load(self, ident):
        path = self._path(ident)
        try:
            fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
            with os.fdopen(fd, 'rb') as stream:
                raw = stream.read(MAX_ENVELOPE + 1)
            if len(raw) > MAX_ENVELOPE:
                raise ValueError()
            envelope = json.loads(raw)
            metadata = envelope['metadata']
            if envelope['version'] != 1 or metadata['id'] != ident:
                raise ValueError()
            nonce = base64.b64decode(envelope['nonce'], validate=True)
            ciphertext = base64.b64decode(envelope['ciphertext'], validate=True)
            if len(nonce) != 12:
                raise ValueError()
            payload = AESGCM(self._key()).decrypt(nonce, ciphertext, _canonical(metadata))
            if len(payload) != metadata['size'] or hashlib.sha256(payload).hexdigest() != metadata['sha256']:
                raise ValueError()
            _xml(payload)
            return metadata, payload
        except FileNotFoundError:
            raise _error('Respaldo no encontrado.', 404) from None
        except (OSError, ValueError, KeyError, TypeError, InvalidTag):
            raise _error('El respaldo está dañado o no puede autenticarse.', 409) from None

    def list(self):
        self._pinned()
        results = []
        for path in sorted(self.root.glob('*.enc')):
            metadata, _ = self._load(path.stem)
            results.append(metadata)
        return sorted(results, key=lambda item: item['date'], reverse=True)

    def read(self, ident):
        self._path(ident)
        self._record('download', ident)
        _, payload = self._load(ident)
        return payload

    def restore_decrypt(self, ident):
        """Decrypt for an authorized caller; does not restore a firewall."""
        return self.read(ident)

    def delete(self, ident):
        path = self._path(ident)
        self._record('delete', ident)
        self._load(ident)  # Authenticate before deleting the requested record.
        try:
            self._pinned()
            path.unlink()
        except OSError:
            raise _error('No se pudo eliminar el respaldo.', 503) from None
        return dict(id=ident, deleted=True)
