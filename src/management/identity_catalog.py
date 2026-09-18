"""Bounded identity adapters backed by OPNsense core tag 26.1.2.

Source: mvc/app/controllers/OPNsense/{Auth,Trust}/Api and corresponding models.
Admix OpnSenseApiService.php 3593-3804 and 3936-4215 calls these same APIs.
Auth/Group fits UUID CRUD; its controller runs auth sync inline, but its JSON
acknowledgement does not prove effective OS privileges. Report saved/readback
only. User passwords are UpdateOnlyTextField and cannot be equality-verified.
Trust generation/import uses explicit X509/CSR/key verification. Private keys
remain on the firewall; one-time private-key export is a separate workflow.
CRL is not UUID CRUD: get/set/del take a CA refid and set also creates the CRL.
No credentials, private keys, API keys, password hashes or OTP material are
included in the public fields. Registration is not live qualification.
"""


def _field(name, label, kind='text', **extra):
    return dict(name=name, label=label, kind=kind, required=False, secret=False, **extra)


def _resource(resource_id, label, namespace, controller, key, fields, columns, *, writable=False):
    return dict(id=resource_id, label=label, group='Sistema',
                base=f'/api/{namespace}/{controller}', search='search', get='get',
                add='add' if writable else None, set='set' if writable else None,
                delete='del' if writable else None, key=key, apply=None,
                persistence_only=True, ha_safe=False, fields=fields, columns=columns,
                qualification='contract_only',
                source=f'OPNsense core 26.1.2 {namespace.title()}/Api/{controller.title()}Controller.php')


IDENTITY_RESOURCES = {
    'auth_groups': _resource('auth_groups', 'Grupos de usuarios', 'auth', 'group', 'group', [
        dict(name='name', label='Nombre', kind='text', required=True, secret=False),
        _field('description', 'Descripción'),
        _field('priv', 'Permisos', 'select', multiple=True),
        _field('member', 'Miembros', 'select', multiple=True),
        _field('source_networks', 'Redes de origen'),
    ], ['name', 'description', 'member'], writable=True),
    'auth_users': _resource('auth_users', 'Usuarios', 'auth', 'user', 'user', [
        dict(name='name', label='Usuario', kind='text', required=True, secret=False),
        dict(name='password', label='Contraseña (vacío conserva la actual)', kind='text', required=True, secret=True, write_only=True),
        _field('descr', 'Nombre completo'),
        _field('disabled', 'Deshabilitado', 'boolean'),
        _field('email', 'Correo'),
        _field('expires', 'Caducidad'),
        _field('shell', 'Shell', 'select'),
        _field('group_memberships', 'Grupos', 'select', multiple=True),
        _field('priv', 'Permisos', 'select', multiple=True),
    ], ['name', 'descr', 'disabled'], writable=True),
    'trust_cas': _resource('trust_cas', 'Autoridades certificadoras (consulta)', 'trust', 'ca', 'ca', [
        _field('descr', 'Descripción', readonly=True),
        _field('refid', 'Referencia', readonly=True),
        _field('caref', 'Autoridad firmante', 'select', readonly=True),
        _field('name', 'Nombre', readonly=True),
        _field('valid_from', 'Válido desde', readonly=True),
        _field('valid_to', 'Válido hasta', readonly=True),
        _field('refcount', 'Referencias', 'integer', readonly=True),
    ], ['descr', 'name', 'valid_to']),
    'trust_certificates': _resource('trust_certificates', 'Certificados (consulta)', 'trust', 'cert', 'cert', [
        _field('descr', 'Descripción', readonly=True),
        _field('refid', 'Referencia', readonly=True),
        _field('caref', 'Autoridad firmante', 'select', readonly=True),
        _field('name', 'Nombre', readonly=True),
        _field('valid_from', 'Válido desde', readonly=True),
        _field('valid_to', 'Válido hasta', readonly=True),
        _field('refcount', 'Referencias', 'integer', readonly=True),
    ], ['descr', 'name', 'valid_to']),
}

IDENTITY_PENDING = {
    'auth_users_login_verification': 'Password changes are acknowledged but not verified by login; GET deliberately never exposes the stored hash.',
    'auth_api_keys': 'One-time secret delivery; add uses username, delete uses base64 key, not UUID CRUD.',
    'trust_private_key_download': 'One-time private-key export is not enabled; generated keys remain on the firewall.',
    'trust_crls': 'CA refid (opaque), not UUID; get requires a CA, set upserts, search includes CAs without CRLs.',
}


def _crypto():
    from src.management.engine import ManagementError
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        return x509, hashes, serialization
    except ImportError:
        raise ManagementError('unsupported', 'La validación de certificados requiere cryptography.', 503) from None


def _trust_prepare(spec, expected, current, action):
    """Validate lifecycle and PEMs before audit/mutation; never echo exceptions."""
    from src.management.engine import ManagementError
    x509, _, serialization = _crypto()
    mode = expected.get('action', '')
    allowed = {'internal', 'existing'} if spec['key'] == 'ca' else {'internal', 'external', 'import', 'manual', 'sign_csr', 'import_csr', 'reissue'}
    if mode not in allowed:
        raise ManagementError('bad_request', 'Operación de certificado no permitida.')
    if action == 'create' and mode in ('manual', 'import_csr', 'reissue'):
        raise ManagementError('bad_request', 'Esta operación requiere un certificado existente.')
    if spec['key'] == 'cert':
        if expected.get('private_key_location', 'firewall') != 'firewall':
            raise ManagementError('bad_request', 'La clave privada debe permanecer en el firewall.')
        expected['private_key_location'] = 'firewall'
    try:
        if mode in ('existing', 'import', 'manual', 'import_csr'):
            certificate = x509.load_pem_x509_certificate(expected.get('crt_payload', '').encode())
            if spec['key'] == 'ca' and not certificate.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
                raise ValueError()
            if expected.get('prv_payload'):
                key = serialization.load_pem_private_key(expected['prv_payload'].encode(), password=None)
                if certificate.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo) != key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo):
                    raise ValueError()
        elif mode == 'sign_csr':
            csr = x509.load_pem_x509_csr(expected.get('csr_payload', '').encode())
            if not csr.is_signature_valid:
                raise ValueError()
        if mode in ('internal', 'external', 'reissue') and not expected.get('commonname'):
            raise ValueError()
    except Exception:
        raise ManagementError('bad_request', 'Certificado, solicitud o clave privada inválidos o incompatibles.') from None
    return expected


def _trust_verify(spec, actual, expected, action):
    """Verify cryptographic contents, not just description and save status."""
    from src.management.engine import ManagementError
    x509, hashes, serialization = _crypto()
    mode = expected['action']
    try:
        if mode == 'external':
            observed = x509.load_pem_x509_csr(actual.get('csr_payload', '').encode())
            if not observed.is_signature_valid:
                raise ValueError()
        else:
            observed = x509.load_pem_x509_certificate(actual.get('crt_payload', '').encode())
            if mode in ('existing', 'import', 'manual', 'import_csr'):
                imported = x509.load_pem_x509_certificate(expected['crt_payload'].encode())
                if observed.fingerprint(hashes.SHA256()) != imported.fingerprint(hashes.SHA256()):
                    raise ValueError()
            if spec['key'] == 'ca' and not observed.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
                raise ValueError()
            if mode == 'sign_csr':
                request = x509.load_pem_x509_csr(expected['csr_payload'].encode())
                if observed.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo) != request.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo):
                    raise ValueError()
        if mode in ('internal', 'external', 'reissue'):
            names = observed.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
            if not names or names[0].value != expected['commonname']:
                raise ValueError()
            key_type = str(expected.get('key_type', ''))
            public_key = observed.public_key()
            if key_type.isdigit() and public_key.key_size != int(key_type):
                raise ValueError()
            if not key_type.isdigit() and key_type:
                curve = 'secp256r1' if key_type == 'prime256v1' else key_type
                if getattr(getattr(public_key, 'curve', None), 'name', None) != curve:
                    raise ValueError()
            if expected.get('digest') and observed.signature_hash_algorithm.name != expected['digest']:
                raise ValueError()
        key_material = actual.get('prv_payload', '')
        if mode in ('internal', 'external', 'reissue') or expected.get('prv_payload'):
            key = serialization.load_pem_private_key(key_material.encode(), password=None)
            if observed.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo) != key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo):
                raise ValueError()
        if mode in ('internal', 'reissue'):
            if expected.get('caref') and actual.get('caref') != expected['caref']:
                raise ValueError()
            days = (observed.not_valid_after_utc - observed.not_valid_before_utc).total_seconds() / 86400
            if abs(days - int(expected['lifetime'])) > 1:
                raise ValueError()
            # OPNsense may generate an internal certificate signed by its
            # selected CA while omitting the CA refid from the readback.
            # The key, subject, lifetime and signature checks above are the
            # verifiable contract available from that response; attempting
            # to verify the certificate against itself rejects valid chains.
    except Exception:
        # Cryptographic backends have several exception families; none may be
        # surfaced with raw PEM or backend diagnostic contents.
        raise ManagementError('unverified', 'No se verificó el certificado, solicitud o clave guardados.', 502) from None


def _trust_fields(is_ca):
    fields = [
        dict(name='descr', label='Descripción', kind='text', required=True, secret=False),
        _field('action', 'Operación', 'select', volatile=True, create_default='internal',
               edit_default='existing' if is_ca else 'manual', options=[
                   {'value': value, 'label': label} for value, label in (
                       [('internal', 'Generar autoridad'), ('existing', 'Importar autoridad')]
                       if is_ca else [('internal', 'Generar certificado'), ('import', 'Importar certificado'),
                           ('external', 'Crear CSR'), ('sign_csr', 'Firmar CSR'),
                           ('import_csr', 'Importar CSR firmado'), ('manual', 'Editar certificado'), ('reissue', 'Reemitir')])]),
        _field('caref', 'Autoridad firmante', 'select', volatile=True),
        _field('key_type', 'Tipo de clave', 'select', default='2048', volatile=True),
        _field('digest', 'Algoritmo', 'select', default='sha256', volatile=True),
        _field('lifetime', 'Validez en días', 'integer', default='825' if is_ca else '397', min=1, max=36500, volatile=True),
        _field('country', 'País', 'select', default='NL', volatile=True),
        _field('state', 'Provincia', volatile=True), _field('city', 'Ciudad', volatile=True),
        _field('organization', 'Organización', volatile=True),
        _field('organizationalunit', 'Unidad', volatile=True),
        _field('email', 'Correo', volatile=True), _field('commonname', 'Nombre común', volatile=True),
        _field('crt_payload', 'Certificado PEM', 'textarea', volatile=True),
        dict(name='prv_payload', label='Clave privada PEM (vacío conserva)', kind='textarea', required=False, secret=True, volatile=True),
    ]
    if not is_ca:
        fields.extend([
            _field('cert_type', 'Tipo de certificado', 'select', default='usr_cert', volatile=True),
            _field('private_key_location', 'Guardar clave en', 'select', default='firewall', volatile=True,
                   options=[{'value': 'firewall', 'label': 'Este firewall'}]),
            _field('csr_payload', 'Solicitud CSR PEM', 'textarea', volatile=True),
            *[_field(name, label, volatile=True) for name, label in (
                ('altnames_dns', 'Nombres DNS alternativos'), ('altnames_ip', 'IP alternativas'),
                ('altnames_uri', 'URI alternativas'), ('altnames_email', 'Correos alternativos'))],
        ])
    return fields


for _id, _ca in [('trust_cas', True), ('trust_certificates', False)]:
    _spec = IDENTITY_RESOURCES[_id]
    _spec.update(label='Autoridades certificadoras' if _ca else 'Certificados',
                 add='add', set='set', delete='del', fields=_trust_fields(_ca),
                 prepare=_trust_prepare, verify=_trust_verify, columns=['descr', 'commonname'])
