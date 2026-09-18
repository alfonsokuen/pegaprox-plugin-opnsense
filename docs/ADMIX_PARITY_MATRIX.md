# AdmixCentral: inventario de paridad por evidencia de codigo

2026-09-18. Lectura estatica, no ejecucion del proyecto externo ni prueba contra firewall. Fuente Admix `033c676ef730c3276c46fe4959d3adcb02fdccc1`; plugin `3f9433bcdec3aae2e204ae8002339bc928bfd465` (v1.17.0). Las rutas/metodos presentes prueban implementacion, no funcionamiento real.

Prefijos fuente: `O` = app/Services/OpnSenseApiService.php; `P` = app/Services/PfSenseApiService.php; `C` = app/Http/Controllers. Las vistas correspondientes estan en resources/views. Catalogo de rutas: routes/web.php.

## Advertencia sobre la referencia

P:313 retorna HTTP logico 200/data[] para GET no mapeados en OPNsense; POST/PATCH/DELETE desconocidos lanzan unsupported (388/454/503). Por tanto una pagina o wrapper generico NO demuestra soporte OPNsense. Varias funciones anunciadas son pfSense-only o vistas con api-not-supported. No copiar ese fallback silencioso.

## Matriz OPNsense

| Grupo | Admix realmente conectado a OPNsense | Plugin 1.17.0 / laguna |
|---|---|---|
| Estado y HA | Sistema, interfaces, gateways, servicios, CARP/VIP y hasync; configuracion hasync y accion CARP. O:170,616,659,2111,5252; C/SystemController, StatusController | Estado A/B, divergencias, trafico, servicios, certificados y HA ya visibles. Sin administracion servicios/HA desde UI. |
| Firewall | Aliases y reglas CRUD/apply. O:742-1161. C/FirewallRuleController:259 mueve reglas intercambiando payloads por indice; hay que probar semantica OPNsense, no asumir reorder nativo. Categorias CRUD O:2246. | CRUD aliases/reglas implementado src/routes/firewall.py y writers. Faltan categorias y mover reglas. |
| NAT | DNAT, outbound, 1:1 CRUD/toggle; modo outbound get/set. O:1188-1920 | DNAT/outbound/1:1 implementados; verificar paridad modo y toggle/campos avanzados. |
| VIP | List/detail/create/update/delete O:2687-2761; C/FirewallVirtualIpController | Solo observacion CARP/VIP; falta CRUD VIP. |
| Routing | Rutas estaticas CRUD O:3814-3884; lectura gateways. | Lectura rutas/gateways; falta CRUD rutas estaticas. CRUD gateways y gateway groups NO soportado en Admix OPNsense (P:863, O:3891). |
| Interfaces virtuales | VLAN y LAGG list/create/delete O:2596-2676; update generico no tiene mapping. Loopback y VXLAN CRUD/reconfigure O:3240-3429 | Interfaces lectura; faltan esas 4 familias de gestion. Bridges/GRE/wireless/asignaciones/grupos genericos no mapeados OPNsense. |
| WireGuard | General get/set, service status/control, keypair, tunnels CRUD/toggle, peers CRUD/toggle O:2341-2585; C/VpnWireGuardController, vpn/wireguard/index.blade.php | Peers CRUD y estado ya. Faltan tuneles/general/keypair/control. No encontre QR/exportacion en rutas/controller/vista WireGuard; no tratar como paridad existente. |
| OpenVPN | Listado servidores/clientes, estado y delete instancia O:3451-3514, P:1860-1910. tests/Feature/OpenVpnOpnSenseTest.php prueba solo estos. CreateServer llama endpoint pfSense no mapeado; updateOpenVpnServer no definido. | Estado ya; faltan listado configuraciones/detail/delete. CRUD completo seria superar referencia OPNsense, no copiar supuesto soporte. |
| IPsec | Estado SAD/SPD/leases, connect/disconnect, delete SAD, restart/reconfigure; phase1 y phase2 list/create/delete O:4222-4587. C/VpnIpsecController y StatusController | Monitorizacion ya; falta gestion conexiones/children y operaciones de estado. |
| DNS Unbound | Configuracion general get/set y host overrides list/create/delete O:3117-3224 | Hosts, dominios y DoT ya; falta general. Plugin supera referencia en algunas operaciones de overrides. |
| DNS forwarder | Dnsmasq settings/status/service y host overrides list/create/delete O:4712-4805; rutas publican index/create/delete hosts | Falta Dnsmasq. Diferenciar metodos servicio de operaciones realmente expuestas UI. |
| DHCP | Lectura leases O:2772. Configuracion DHCP generica pfSense no mapeada; vistas DHCPv6 unsupported. | Reservas y subredes Kea ya implementadas: mas cobertura OPNsense que referencia en gestion. |
| IDS/IPS | Estado/config/alerts, control/reconfigure/update rules, rulesets toggle, userrules list/create/toggle/delete. O:2801-2928; C/ServicesIdsController; routes:504-524. Update metodo existe pero no ruta UI. | Ausente. |
| Monit | Configuracion, estado/control, servicios y alertas list/create/toggle/delete; tests lectura. O:2933-3094; C/ServicesMonitController; routes:527-553 | Ausente. |
| Shaper | Pipes CRUD, queues/rules list/create/delete y reconfigure O:4821-5072; limiters adaptados a pipes | Ausente. |
| Captive portal | Metodos zones CRUD/sessions/status/reconfigure O:4597-4704, pero C/ServicesCaptivePortalController y ruta UI SOLO index/listado. | Ausente; no presentar CRUD como funcionalidad UI real Admix. |
| Cron | CRUD/reconfigure O:2139-2237 y rutas toggle | Ausente. |
| Certificados | CA list/import/generate/delete; certificados idem; CRL list/create/delete O:3934-4213; certificate manager controllers/routes | Solo inventario certificados; falta administracion. |
| Usuarios firewall | Usuarios/grupos CRUD O:3591-3790; UserManager controllers/routes | Ausente; no confundir con usuarios PegaProx. |
| Firmware/paquetes | Estado/info/check/upgrade/audit, install/remove/reinstall/lock/unlock/changelog O:2047-2102 | Version lectura; resto ausente. |
| Logs | Firewall y sistema O:3537-3554. Syslog config/destinos/status/stats/reconfigure O:5086-5220. Rutas UI publican destinos create/delete | Logs firewall ya; faltan sistema/syslog. |
| Diagnosticos | ARP/NDP/states/routes/activity, ping/traceroute/reverse DNS, reboot/halt O:1952-2038,2304-2332,3440,5234 | Rutas observacion parcial; faltan herramientas y estados. Captura paquetes usa endpoints pfSense no mapeados; shell devuelve texto unsupported. |
| Backup | Descarga XML O:2013 y DiagnosticsBackupController. Restore P:3001 hace passthrough '/api/v1/diagnostics/restore' pfSense hacia OPNsense; no adaptador nativo ni evidencia funcional | Ausente. Descarga es paridad clara; restauracion requiere diseno/probe seguro, no asumir funcional referencia. |

## Lo que no debe contarse como soporte OPNsense de Admix

- HAProxy: C/ServicesHaproxyController usa /services/haproxy/*; P no lo mapea. GET vacio, escritura unsupported.
- ACME: C/ServicesAcmeController lee installedpackages/acme via shell pfSense; shell OPNsense expresamente unsupported.
- Tunables: P:714-735 usa /system/tunables y /system/tunable sin mapping OPNsense.
- Gateway groups/schedules: O:3891-3928 lectura vacia y mutaciones explicitamente unsupported. Gateway CRUD tambien unsupported P:863-879.
- Asignaciones interfaces, bridges, GRE, wireless, grupos; NTP/SNMP/UPnP, FreeRADIUS y DHCP relay/configuracion: wrappers pfSense sin mapping OPNsense (no equivalencia demostrada).
- Dynamic DNS, IGMP, DHCPv6, router advertisement, PPPoE, WOL, L2TP y diversas paginas diagnosticas tienen vistas `x-api-not-supported`. Algunos nombres de vistas antiguas conviven con controllers nuevos; confirmar la ruta efectiva antes de clasificar toda familia como stub.
- QR/export WireGuard no aparece en controller/rutas/vista revisados.

## Plataforma (distinta de gestion de un firewall)

Admix es Laravel multiempresa: Company/Firewall/User models + migraciones, EnsureTenantScope y CheckRole, CRUD inventario, dashboard flota y bulk actions, auth/2FA/magic link, customizacion y backup del propio sistema. Plugin delega identidad/autorizacion/hosting a PegaProx y configura un par A/B; no tiene multiempresa ni driver pfSense. Una paridad TOTAL tambien incluye estos aspectos y requiere definir integracion con capacidades host, no afirmar que CRUD OPNsense equivale a producto entero.

PWA real: manifest dinamico routes/web.php y public/sw.js (cache shell/imagen, network-first navegacion; no prueba offline completo).
WebSocket: rutas ws/device, Reverb, DeviceConnection, eventos y dispatcher presentes. DeviceCommandDispatcher:73 TODO espera de respuestas; WebSocket/DeviceWebSocketController:166 TODO guardar respuestas. Envio devuelve success al broadcast, no confirma ejecucion. No replicar falso exito.

## Orden de construccion recomendado

1. Catalogo capabilities tipado, proteccion read-only/roles, errores explicitos unavailable/unsupported; sin proxy arbitrario de endpoints.
2. Cerrar familias de bajo riesgo: categorias, rutas estaticas, VLAN/LAGG/loopback/VXLAN, cron, VIP; validar payload y apply/readback en laboratorio aislado.
3. WG tuneles/general, Unbound general/Dnsmasq, servicios y logs/syslog; preservar secretos y auditoria.
4. IDS/Monit/shaper, IPsec/OpenVPN, certificados/usuarios/firmware y backup; acciones disruptivas con pruebas laboratorio y confirmacion contextual UI.
5. Plataforma flota/multiempresa/PWA/WebSocket: integrar host y especificar alcance separado; no sustituirlo por placeholders.

Cada fila necesita pruebas por operacion: validacion, readonly/roles, upstream HTTP200 error, apply error, readback mismatch, UI errores/draft y e2e exito. No contar tests de mocks como prueba real contra OPNsense.
