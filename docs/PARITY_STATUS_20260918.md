# Estado de paridad AdmixCentral — 2026-09-18

La referencia auditada es AdmixCentral en el commit `033c676ef730c3276c46fe4959d3adcb02fdccc1` y el núcleo OPNsense 26.1.2. La matriz de módulos está en [ADMIX_PARITY_MATRIX.md](ADMIX_PARITY_MATRIX.md).

## Implementado

- Catálogo de 30 recursos y 386 campos con allowlists, campos de solo lectura, selectores, secretos redactados y paginación acotada.
- 62 operaciones de dispositivo con métodos fijos, confirmación explícita, resultado `accepted`/`verified` y errores sanitizados.
- CRUD con revisión optimista, auditoría de intento/resultado, validación de respuesta y bloqueo HA cuando el recurso no está calificado.
- Identidad: grupos, usuarios, contraseñas write-only, CA, certificados y CRL. Las claves privadas se generan y permanecen en el firewall.
- Backups históricos cifrados localmente con AES-256-GCM, límites de tamaño, XML endurecido y sin restauración automática sobre el firewall.
- Workspace responsive con búsqueda, paginación, edición, modo solo lectura, estados de operación y cobertura de los recursos catalogados.

## Evidencia QA/E2E

- Batería del repositorio: **todos los tests ejecutables pasan**; los casos marcados `skip` requieren OPNsense/laboratorio. Ruff y `node --check workspace.js` pasan.
- Laboratorio OPNsense aislado: 19 recursos completaron crear/editar/borrar y rechazo de revisión obsoleta, incluyendo WireGuard, shaping, loopback, VLAN, VXLAN, VIP, Monit, IDS, IPsec, syslog, portal cautivo y dnsmasq.
- Laboratorio de identidad: grupos, usuarios y CA completaron crear/editar/borrar. Certificados completaron crear/borrar; la actualización del certificado fue rechazada por el endpoint upstream durante el readback y queda pendiente de adaptar al ciclo exacto de OPNsense.
- El E2E de handlers/UI cubre navegación, filtros, CRUD, secretos, permisos, modo solo lectura, operaciones GET/POST y estados aceptado/no verificado.

## Límites declarados

La paridad verificada es la superficie nativa OPNsense que AdmixCentral realmente ejecuta. No se presentan como completas las funciones que AdmixCentral deja como stub o que dependen de otro producto: multiempresa/fleet, pfSense paralelo, PWA/WebSocket de plataforma, HAProxy/ACME no efectivos en el adaptador OPNsense, ni exportación de claves privadas. OpenVPN y algunas operaciones de firmware/servicios requieren una pasada live adicional antes de calificarse como verificadas.

Producción conserva `read_only: true` y no se modifica durante estas pruebas.
