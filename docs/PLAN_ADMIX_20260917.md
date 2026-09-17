# Integración nativa DNAT y firewall — plan de ejecución

Fecha: 2026-09-17. Autorización vigente: analizar, construir, E2E, QA dual Fable/Codex, commit, push y deploy. Se ejecuta la primera entrega de la propuesta del 2026-09-16; WireGuard ampliado, shaping y multiempresa permanecen como fases posteriores.

## Diseño aprobado por continuidad de la petición

Mantener el plugin Python, la sesión y el tema de PegaProx. Añadir DNAT a NAT y una pestaña Firewall para reglas y aliases. API nativa OPNsense, sin dependencia de AdmixCentral ni copia de código PHP. Escrituras explícitas: validación, aplicación comprobada, lectura posterior y resultado HA. Un fallo o timeout no se convierte en éxito; no repetir escrituras automáticamente.

Contrato: GET/POST `port_forward`, `rules`, `aliases`; POST `{action:create|update|delete,uuid?,revision?,rule|alias:{...}}` (revision obligatoria en update/delete). GET devuelve `{ok:true,data:{rules|aliases:[...],total:N}}`. Respuesta de escritura incluye UUID, acción, verificación y sync cuando procede; el UI debe mostrar fallo parcial y conservar el formulario. Modo read_only bloquea toda escritura. DNAT usa nombres normalizados en UI y traduce al modelo oficial (incluidos source/destination y local-port). Regla de filtrado explícita: permitir asociación mediante opción nativa de DNAT, sin crear reglas permisivas ocultas.

## Ejecución y archivos

- [x] Inspeccionar Git; backup `backup/pre-admix-integration-20260917` en 4156d82; worktree aislado.
- [x] Baseline pytest/lint; verificar destinos actuales y acceso, sin usar secretos de notas históricas.
- [x] Backend: `src/writers/port_forward.py`, helpers de escritura verificada, `src/routes/firewall.py`, tests negativos y CRUD. Revisar contrato contra controlador/modelo oficial OPNsense.
- [x] Integración: handlers y registro en `__init__.py`, identidad del actor, read_only y selección segura de master HA.
- [x] UI: `opnsense.html`, formularios CRUD de DNAT/reglas/aliases, etiquetas, errores inline, loading, edición/cancelación, temas existentes y móvil.
- [x] Pruebas de backend y E2E con Flask real y simulador HTTP de OPNsense: validación 200 fallida, apply fallido, timeout, rollback fallido, 403/404, read_only y HA no convergente. E2E live de lectura y round-trip exclusivo de laboratorio cuando se confirme su identidad.
- [x] QA dual independiente sobre el mismo artefacto: Fable mediante CLI real y Codex. Reproducir hallazgos y corregir; conservar informes y hash del artefacto.
- [x] Versión 1.15.0, changelog, documentación coherente; escaneo diff, commit y push sin force ni saltar hooks.
- [x] Backup remoto restaurable del plugin, preservación config/state, despliegue propio y reload controlado. Comparar hashes, health, logs y UI servida; rollback si falla.
- [x] Registrar evidencia, SHA, destinos, limitaciones y estado final en memoria.

## Puertas de salida

Tests existentes y nuevos verdes; ninguna escritura de prueba en firewall productivo; E2E sobre handlers reales; QA dual con hallazgos cerrados o límites expresos; publicación confirmada por SHA; versión desplegada coincidente y smoke posterior verde. Si falla un acceso se continúa trabajo independiente y se documenta el bloqueo real, sin declarar deploy o QA ejecutado.

## Evidencia de construcci?n

Suite final local: 399 pass / 19 skipped, incluidos 15 E2E Chromium contra simulador HTTPS. Ver `QA_ADMIX_20260917.md` para panel dual, decisiones y l?mites. No hay laboratorio OPNsense disponible: la antigua VM de lab fue reutilizada; round-trip f?sico de escritura queda pendiente y no se sustituye por pruebas en producci?n. Se conserva readonly.

## Cierre de publicaci?n y despliegue

C?digo publicado y desplegado: `c8880d2113ea2abd68f01360204d025613aaac41`, versi?n 1.15.0. Push fast-forward a origin/main confirmado contra remoto, sin force. Backup remoto del plugin extra?do y comparado antes de instalar. Los 48 archivos de runtime coinciden por SHA256 con los blobs Git; configuraci?n preservada exactamente, servicio activo y reload autenticado correcto.

Smoke HTTP real: health 1.15.0 / readonly true; DNAT, reglas y aliases 200; POST vac?o rechazado403 readonly en las tres rutas. Smoke Chromium real: Firewall y NAT visibles, formularios nuevos bloqueados, sin errores JavaScript y sin desbordamiento horizontal de p?gina a390px. Journal de los ?ltimos diez minutos: cero tracebacks. Evidencia privada detallada y capturas almacenadas fuera del repositorio; resultado y l?mites registrados en memoria del proyecto.

La prueba de tr?fico y escritura en hardware sigue excluida del cierre: no existe un laboratorio disponible y no se alter? el firewall productivo. Habilitar escrituras requiere resolver acceso del peer y realizar esa calificaci?n.
