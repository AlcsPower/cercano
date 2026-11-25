# Plan de trabajo — F3.5: Agente Cercano y aplicación de escritorio genérica

**Versión:** 0.1 (propuesta) · **Fecha:** 2026-11-25 · **Decisión:** [ADR-015](adr/015-agente-y-cliente-generico.md) (Propuesto)
**Depende de:** aprobación de ADR-015; F3-19a y F3-19 (cliente Windows real compilado en la máquina propia); F3-07, F3-08, F3-09, F3-13; F4-07; F4.5-03.

**Objetivo (M2.5):** una misma aplicación Cercano, descargable, funciona con cualquier servidor. Cada
organización genera desde su consola web un **paquete etiquetado** (agente + aplicación) que, sin
recompilar ni volver a firmar, vincula el equipo a su servidor y aplica su rol, política, auditoría,
chat y marca. Sin agente, la aplicación funciona en **modo libre** con configuración manual.

## 1. Alcance

**Dentro:** agente `cercano-agent` para Windows (servicio, vinculación, canal local, política,
auditoría, latido, transporte del chat, diagnóstico por línea de comandos); puente en la aplicación y
retirada de las direcciones y la clave compiladas; marca en tiempo de ejecución; etiquetado de
paquetes en `cercano-build` y `cercano-api`; formulario en `console-web`; guía y revisión de seguridad.

**Fuera:** agente para macOS y Linux (se planifica al cerrar F3.5); actualización automática del agente;
cliente web; cualquier cambio del protocolo de sesión con hbbs/hbbr.

## 2. Relación con F3

| Tarea F3 | Qué pasa |
|---|---|
| F3-19a, F3-19 | Siguen igual y son requisito: el paquete genérico necesita el cliente Windows real |
| F3-20 | Sigue igual; se aplica también al paquete genérico (sin binarios reales no se publica) |
| F3-21 | Se amplía en F3.5-15 con los estados gestionado, libre y bloqueado |
| F3-22 | **Se sustituye por F3.5-10** (marca entregada por el agente). Queda `Diferida` al aprobarse ADR-015 |
| F3-11 | Se actualiza en F3.5-13 |

## 3. Tareas

| ID | Tarea | Dep. | Rol | Verifica |
|---|---|---|---|---|
| F3.5-01 | ADR-015, plan y casos de prueba propuestos | — | Coordinador | Dueño + Seguridad |
| F3.5-02 | Spike S9: etiquetado de paquetes sin romper Authenticode | F3.5-01, F3-19 | Builder | Seguridad |
| F3.5-03 | Contrato del canal local y formato de la etiqueta (`docs/specs/agente-ipc.md`) | F3.5-01 | Coordinador + Cliente + ControlPlane | Seguridad |
| F3.5-04 | Esqueleto de `agent/`: servicio Windows, almacén fijado, logs y CLI de diagnóstico | F3.5-03 | Cliente | QA |
| F3.5-05 | Vinculación: `POST /api/agent/enroll` y lado del agente | F3.5-04, F3-09, F3-13, F4.5-03 | ControlPlane + Cliente | Seguridad |
| F3.5-06 | Servidor del canal local con verificación mutua de firma | F3.5-04 | Cliente | Seguridad |
| F3.5-07 | Política efectiva, latido y cola de auditoría en el agente | F3.5-05, F3.5-06 | Cliente | QA |
| F3.5-08 | Transporte del chat en el agente; la interfaz Flutter usa el canal local | F3.5-06, F3.5-05 | Cliente | QA |
| F3.5-09 | Parche 013 del cliente: puente con el agente, estados gestionado/libre/bloqueado, sin direcciones ni clave compiladas | F3.5-06, F3-19a | Cliente | Seguridad |
| F3.5-10 | Marca en tiempo de ejecución (sustituye F3-22) | F3.5-09 | Cliente | QA |
| F3.5-11 | `cercano-build`: paquete genérico firmado y comando `tag` | F3.5-02, F3.5-03, F3-20 | Builder | QA |
| F3.5-12 | Generador en el servidor: `cercano-api` etiqueta y `console-web` define los parámetros | F3.5-11, F3-07, F3-08, F4-07 | ControlPlane + Web | QA |
| F3.5-13 | Guía de despliegue y diagnóstico con PowerShell (actualiza F3-11) | F3.5-04, F3.5-12 | Coordinador | QA |
| F3.5-14 | Revisión de seguridad: canal local, confianza en el primer uso, etiquetado | F3.5-05…12 | Seguridad | Coordinador |
| F3.5-15 | E2E en Windows 10/11 y cierre de fase | F3.5-01…14 | QA | Coordinador |

### Detalle

**F3.5-01 ADR, plan y casos.**
Redactar ADR-015, este plan y la lista de casos de la sección 4, y actualizar `ARQUITECTURA.md`,
`ROADMAP.md` y `status/TAREAS.md`. Al aprobarse: ADR-015 pasa a `Aprobado`, ADR-005 a «Reemplazado en
parte por ADR-015», F3-22 a `Diferida`, y QA pasa los casos a `PLAN-DE-PRUEBAS.md`.
*CA:* el Coordinador, el Dueño y Seguridad aprueban por escrito; no queda contradicción entre ADR-005,
ADR-015, el plan F3 y la arquitectura.

**F3.5-02 Spike S9: etiquetado.**
`docs/spikes/S9-etiquetado.md`. Comparar en Windows 10 y 11, con `EnableCertPaddingCheck` activado y
desactivado, con SmartScreen y Defender: (A) etiqueta en un certificado o atributo no autenticado del
PKCS#7 del `.exe`; (B) `.msi` firmado con propiedad `CERCANO_CONFIG` o `.mst`; (C) instalador genérico
más `cercano-org.json` o código de configuración. Medir tamaño máximo de la etiqueta y documentar cómo
la lee el instalador. Implementación propia o con dependencias de licencia compatible con AGPL; nada de
código de procedencia dudosa.
*CA:* para cada variante, `Get-AuthenticodeSignature` da `Valid` tras etiquetar y la instalación
funciona; recomendación aprobada por el Coordinador; la variante C queda siempre como respaldo.

**F3.5-03 Contrato del canal local y de la etiqueta.**
`docs/specs/agente-ipc.md`: nombre de la tubería, DACL, verificación mutua (llamante: imagen en el
directorio de instalación y mismo firmante; servidor: servicio `CercanoAgent` como `SYSTEM` y mismo
firmante), mensajes con prefijo de longitud y tamaño máximo, versión de protocolo negociada,
operaciones (`hello`, `get_config`, `get_branding`, `get_role`, `get_policy`, `chat.*`,
`audit.submit`, `status`) y sus errores. Formato de la etiqueta: perfil firmado (esquema F3-01 más
`profile_signing_public_key`, `enroll_token`, `branding`). JSON Schema y ejemplos válidos e inválidos.
*CA:* el esquema valida los ejemplos; no existe ninguna operación de escritura de configuración desde
la aplicación; Seguridad aprueba la lista de operaciones.

**F3.5-04 Esqueleto del agente.**
Crate `agent/` (AGPL-3.0, cabecera en cada archivo) con binario `cercano-agent`: servicio `CercanoAgent`
(`install`, `uninstall`, `run`), almacén en `%ProgramData%\Cercano\agent\` con ACL `SYSTEM` y
`Administradores`, logs rotados sin secretos, y CLI `status`, `test-connection`, `policy show`,
`logs --tail N`, `enroll`, `re-enroll`, `export-diagnostics`, todos con `--json`. Los comandos que
cambian estado exigen administrador.
*CA:* `cargo fmt`, `clippy -D warnings`, `test` y `deny check` en verde; el servicio se instala, arranca,
se detiene y se desinstala sin restos; un usuario estándar puede ejecutar `status` pero no `re-enroll`;
`export-diagnostics` no contiene claves ni tokens (búsqueda automática de secretos).

**F3.5-05 Vinculación.**
`POST /api/agent/enroll` en `cercano-api`: recibe token de registro, clave pública del dispositivo,
`installer_id` e inventario básico; comprueba token (vigencia, usos, revocación), rol e instalador;
registra `device_id` ↔ `installer_id` ↔ `role` y emite la credencial. Eventos `agent.enrolled`,
`agent.enroll_denied`. En el agente: par Ed25519 protegido con DPAPI de máquina, fijación de clave de
perfiles, clave de servidor y hosts, y autenticación posterior por reto y firma.
*CA:* token caducado, agotado o revocado → rechazo auditado; un perfil firmado con otra clave tras la
fijación → rechazado; reinstalar sin derechos de administrador no cambia la clave fijada; revocar el
instalador corta al agente en menos de 60 s (objetivo F3-09).

**F3.5-06 Canal local.**
Implementar el contrato de F3.5-03 en el agente: `FILE_FLAG_FIRST_PIPE_INSTANCE`, DACL, verificación
del llamante con `GetNamedPipeClientProcessId` y `WinVerifyTrust`, límites de tamaño y tasa.
*CA:* un proceso sin firmar o de otro firmante no obtiene respuesta y queda registrado; un proceso que
cree antes la tubería no es aceptado por la aplicación; mensajes malformados no tumban el servicio
(*fuzzing* básico incluido en las pruebas).

**F3.5-07 Política, latido y auditoría en el agente.**
Mudar al agente la lógica de `CachedEffectivePolicy` (parche 012) con el perfil como techo (ADR-012),
el latido (parche 003) y una cola persistente de auditoría con reenvío y deduplicación por `event_id`.
Los eventos del cliente (parche 004) entran por `audit.submit`.
*CA:* TC-F5-024 y TC-F5-025 siguen en verde con la política servida por el agente; sin red, los eventos
se encolan y se envían al volver sin duplicados ni pérdidas; la cadena se verifica con
`cercano-audit verify`.

**F3.5-08 Chat en el agente.**
Mudar al agente el transporte del chat (parche 008: reto/firma, REST, SSE con reconexión, token solo en
memoria, solo HTTPS) y exponerlo por el canal local; la interfaz del parche 009 consume el canal en vez
del FFI directo.
*CA:* la suite de F4.5 del cliente pasa con el transporte en el agente; el token de chat no aparece en
disco, logs ni respuestas del canal.

**F3.5-09 Parche 013 del cliente.**
Nuevo módulo `cercano_agent_bridge.rs` (parche aditivo): en el proceso de interfaz y en el servicio
heredado, si existe la marca `HKLM\SOFTWARE\Cercano\Agent`, obtener configuración, rol y política del
agente y aplicarlos en `OVERWRITE_SETTINGS`; si el agente no responde o no está vinculado, estado
**bloqueado** (sin conexiones entrantes nuevas y aviso de diagnóstico); sin marca, estado **libre** con
Ajustes → Red editables y aviso «No gestionado». Retirar las direcciones `127.0.0.1` del parche 003 y
dejar la clave compilada del parche 005 solo para pruebas. Registrar en `patches/INDEX.md` y ajustar
los parches 003, 005, 008 y 012.
*CA:* el mismo `cercano.exe` funciona en libre con un servidor configurado a mano y en gestionado con
el agente; detener el servicio del agente deja la aplicación bloqueada y no libre; `tools/apply-patches`
idempotente.

**F3.5-10 Marca en tiempo de ejecución.**
La aplicación muestra el nombre y el logo de la organización y el color de acento que entrega el agente,
en la ventana principal, el instalador interactivo y el chat, con «Powered by Cercano» y el Acerca de
con repositorio y versión (lo que pedía F3-22). El icono del ejecutable y de la barra de tareas sigue
siendo el de Cercano. Logo validado (PNG, dimensiones y tamaño máximo) al generar y al recibir.
*CA:* cambiar la marca en la consola y regenerar el paquete cambia lo visible sin recompilar; en libre
se ve Cercano; un logo inválido se rechaza al generar.

**F3.5-11 `cercano-build`: paquete genérico y etiquetado.**
El build de la máquina Windows (F3-19) produce el paquete genérico firmado (agente + aplicación, `.exe`
y `.msi`). Nuevo subcomando `cercano-build tag --package <base> --profile <perfil.signed.json> --out
<dir>` que aplica la variante elegida en S9 sin tocar las zonas firmadas, y se ejecuta en Linux.
*CA:* el paquete etiquetado conserva `Valid` en `Get-AuthenticodeSignature`; el etiquetado es
determinista; un perfil sin firma válida no se etiqueta; tiempo < 5 s (objetivo propuesto).

**F3.5-12 Generador en el servidor.**
`cercano-api` usa `tag` en su servicio de build (F3-07); `console-web` amplía el formulario de F4-07
con los parámetros del ADR-015 §2.11 y muestra hash y huella de clave en la descarga. Permisos
`builder:create:soporte`/`tecnico`; auditoría `build.*`; descarga con caducidad.
*CA:* desde la consola, en un servidor Linux sin herramientas de Windows, se obtiene un paquete que
instala y vincula en Windows 11; sin permiso del rol pedido → 403 y `auth.denied`.

**F3.5-13 Guía de despliegue y diagnóstico.**
Actualizar la guía de F3-11: paquete etiquetado, `.msi` con propiedad o `.mst` para GPO/Intune, modo
libre, comprobación con `cercano-agent status --json | ConvertFrom-Json`, problemas habituales
(tubería, vinculación, política caducada, revocación) y desinstalación.
*CA:* un agente que no la escribió despliega y diagnostica en el laboratorio siguiéndola de cero.

**F3.5-14 Revisión de seguridad.**
Ampliar el modelo de amenazas (`ARQUITECTURA.md` §6 y `specs/threat-model-roles-elevation.md`):
suplantación de la tubería, llamante no firmado, reetiquetado con servidor ajeno, robo del paquete,
detener el agente para saltarse la política, rotación y robo de la clave fijada. *Fuzzing* del canal
local y del lector de etiquetas. Informe `docs/status/informes/F3.5-14.md`.
*CA:* sin hallazgos críticos o altos abiertos; medios y bajos con plan.

**F3.5-15 E2E y cierre.**
En Windows 10 y 11, con y sin Defender: libre contra un servidor configurado a mano; gestionado
`soporte` y `tecnico` con paquetes generados desde la consola; bloqueado al detener el agente;
revocación; chat; auditoría; desinstalación limpia. Informe `docs/status/informes/F3.5-15.md`.
*CA:* casos TC-F3.5-* en verde; gate de la sección 5 cumplido.

## 4. Casos de prueba propuestos (QA los pasa a `PLAN-DE-PRUEBAS.md`)

| ID | Caso | Resultado esperado |
|---|---|---|
| TC-F3.5-001 | Aplicación sin agente, servidor configurado a mano | Conecta en modo libre; se ve «No gestionado» |
| TC-F3.5-002 | Aplicación sin agente ni configuración | Pide servidor; no intenta `127.0.0.1` |
| TC-F3.5-003 | Paquete etiquetado, instalación interactiva | Muestra organización, host y huella antes de confirmar |
| TC-F3.5-004 | Paquete etiquetado con un byte de la etiqueta alterado | Instalación rechazada; firma Authenticode intacta |
| TC-F3.5-005 | Perfil nuevo firmado con otra clave tras la fijación | Rechazado y auditado |
| TC-F3.5-006 | Token de registro caducado, agotado o revocado | Vinculación denegada y `agent.enroll_denied` |
| TC-F3.5-007 | Proceso sin firmar se conecta a la tubería | Sin respuesta; registrado |
| TC-F3.5-008 | Proceso que suplanta la tubería antes que el agente | La aplicación lo rechaza y queda bloqueada |
| TC-F3.5-009 | Detener el servicio `CercanoAgent` | Aplicación bloqueada; no acepta conexiones entrantes nuevas |
| TC-F3.5-010 | Política caducada sin red | Fallo cerrado (equivale a TC-F5-024) |
| TC-F3.5-011 | Auditoría sin red y reconexión | Eventos enviados sin pérdida ni duplicados; cadena verificable |
| TC-F3.5-012 | Cambio de marca en la consola y nuevo paquete | Nueva marca visible sin recompilar; icono de Cercano intacto |
| TC-F3.5-013 | `cercano-agent export-diagnostics` | Sin claves, tokens ni secretos |
| TC-F3.5-014 | Usuario estándar ejecuta `re-enroll` | Denegado |
| TC-F3.5-015 | Paquete etiquetado con `EnableCertPaddingCheck` activado | `Get-AuthenticodeSignature` = `Valid` (o variante C documentada) |

## 5. Gate F3.5 (M2.5)

- El mismo binario de la aplicación funciona en modo libre con un servidor cualquiera y en modo
  gestionado con un paquete generado desde la consola, en Windows 10 y 11.
- El servidor genera paquetes sin compilar, sin herramientas de Windows y sin el certificado de firma
  de código; los paquetes conservan la firma Authenticode válida.
- Ninguna clave privada, token ni credencial en artefactos, repositorio, logs o salidas de diagnóstico
  (verificación automática).
- Revisión de seguridad sin hallazgos críticos o altos abiertos.
- `patches/INDEX.md` actualizado y la deriva contra `vendor/` igual o menor que antes de F3.5.
