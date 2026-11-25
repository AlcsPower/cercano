# Plan de trabajo — F3.5: Agente Cercano y aplicación de escritorio genérica

**Versión:** 0.1 (propuesta) · **Fecha:** 2026-11-25 · **Decisión:** [ADR-015](adr/015-agente-y-cliente-generico.md) (Propuesto)
**Depende de:** aprobación de ADR-015; F3-19a y F3-19 (cliente Windows real compilado en la máquina propia); F3-07, F3-08, F3-09, F3-13; F4-07; F4.5-03.

**Objetivo (M2.5):** una misma aplicación Cercano, descargable, funciona con cualquier servidor. Cada
organización genera desde su consola web una **configuración firmada** (`cercano-org.json` o código)
que, junto al paquete genérico (agente + aplicación) y sin recompilar ni volver a firmar nada,
vincula el equipo a su servidor y aplica su rol, política, auditoría,
chat y marca. Sin agente, la aplicación funciona en **modo libre** con configuración manual.

## 1. Alcance

**Dentro:** agente `cercano-agent` para Windows (servicio, vinculación, canal local, política,
auditoría, latido, transporte del chat, diagnóstico por línea de comandos); puente en la aplicación y
retirada de las direcciones y la clave compiladas; marca en tiempo de ejecución; paquete genérico en
`cercano-build`; configuración firmada en `cercano-api`; formulario en `console-web`; guía y revisión
de seguridad.

**Fuera:** instalador etiquetado de un solo archivo (diferido, ADR-015 §2.3); agente para macOS y
Linux (se planifica al cerrar F3.5); actualización automática del agente;
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
| F3.5-02 | ~~Spike S9: etiquetado de paquetes~~ **Diferida** (ADR-015 §2.3) | — | Builder | Seguridad |
| F3.5-03 | Contrato del canal local y formato de la configuración (`docs/specs/agente-ipc.md`) | F3.5-01 | Coordinador + Cliente + ControlPlane | Seguridad |
| F3.5-04 | Esqueleto de `agent/`: servicio Windows, almacén fijado, logs y CLI de diagnóstico | F3.5-03 | Cliente | QA |
| F3.5-05 | Vinculación: `POST /api/agent/enroll` y lado del agente | F3.5-04, F3-09, F3-13, F4.5-03 | ControlPlane + Cliente | Seguridad |
| F3.5-06 | Servidor del canal local con verificación mutua de firma | F3.5-04 | Cliente | Seguridad |
| F3.5-07 | Política efectiva, latido y cola de auditoría en el agente | F3.5-05, F3.5-06 | Cliente | QA |
| F3.5-08 | Transporte del chat en el agente; la interfaz Flutter usa el canal local | F3.5-06, F3.5-05 | Cliente | QA |
| F3.5-09 | Parche 013 del cliente: puente con el agente, estados gestionado/libre/bloqueado, sin direcciones ni clave compiladas | F3.5-06, F3-19a | Cliente | Seguridad |
| F3.5-10 | Marca en tiempo de ejecución (sustituye F3-22) | F3.5-09 | Cliente | QA |
| F3.5-11 | `cercano-build`: paquete genérico firmado que lee `cercano-org.json` o `CERCANO_CONFIG` | F3.5-03, F3.5-04, F3-20 | Builder | QA |
| F3.5-12 | Generador en el servidor: `cercano-api` firma la configuración y `console-web` define los parámetros | F3.5-11, F3-07, F3-08, F4-07 | ControlPlane + Web | QA |
| F3.5-13 | Guía de despliegue y diagnóstico con PowerShell (actualiza F3-11) | F3.5-04, F3.5-12 | Coordinador | QA |
| F3.5-14 | Revisión de seguridad: canal local, confianza en el primer uso, configuración | F3.5-05…12 | Seguridad | Coordinador |
| F3.5-15 | E2E en Windows 10/11 y cierre de fase | F3.5-01…14 | QA | Coordinador |

### Detalle

**F3.5-01 ADR, plan y casos.**
Redactar ADR-015, este plan y la lista de casos de la sección 4, y actualizar `ARQUITECTURA.md`,
`ROADMAP.md` y `status/TAREAS.md`. Al aprobarse: ADR-015 pasa a `Aprobado`, ADR-005 a «Reemplazado en
parte por ADR-015», F3-22 a `Diferida`, y QA pasa los casos a `PLAN-DE-PRUEBAS.md`.
*CA:* el Coordinador, el Dueño y Seguridad aprueban por escrito; no queda contradicción entre ADR-005,
ADR-015, el plan F3 y la arquitectura.

**F3.5-02 Spike S9: etiquetado — Diferida.**
El plan usa solo la configuración aparte (ADR-015 §2.3). Si más adelante se quiere un instalador de un
solo archivo, se retoma como spike: etiqueta en la zona no autenticada del PKCS#7 o `.mst`, probada con
`EnableCertPaddingCheck`, SmartScreen y Defender en Windows 10 y 11.

**F3.5-03 Contrato del canal local y de la configuración.**
`docs/specs/agente-ipc.md`: nombre de la tubería, DACL, verificación mutua (llamante: imagen en el
directorio de instalación y mismo firmante; servidor: servicio `CercanoAgent` como `SYSTEM` y mismo
firmante), mensajes con prefijo de longitud y tamaño máximo, versión de protocolo negociada,
operaciones (`hello`, `get_config`, `get_branding`, `get_role`, `get_policy`, `chat.*`,
`audit.submit`, `status`) y sus errores. Formato de la configuración (`cercano-org.json` y su código
base64url): perfil firmado con el esquema F3-01 más `profile_signing_public_key`, `enroll_token` y
`organization_name`, **sin logo**, con tamaño máximo que quepa en una línea de `msiexec` (objetivo
propuesto: 4 KiB codificado). JSON Schema y ejemplos válidos e inválidos.
*CA:* el esquema valida los ejemplos; un código de configuración de tamaño máximo pasa por
`msiexec /i … CERCANO_CONFIG=<código>`; no existe ninguna operación de escritura de configuración desde
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
El agente descarga logo y color de acento de `cercano-api` tras vincularse (el nombre viene en el
perfil). La aplicación muestra lo que entrega el agente en la ventana principal y el chat (el
instalador interactivo muestra el nombre), con «Powered by Cercano» y el Acerca de
con repositorio y versión (lo que pedía F3-22). El icono del ejecutable y de la barra de tareas sigue
siendo el de Cercano. Logo validado (PNG, dimensiones y tamaño máximo) al generar y al recibir.
*CA:* cambiar la marca en la consola cambia lo visible en los equipos ya instalados sin recompilar ni
reinstalar; en libre se ve Cercano; un logo inválido se rechaza al subirlo y al recibirlo.

**F3.5-11 `cercano-build`: paquete genérico.**
El build de la máquina Windows (F3-19) produce el paquete genérico firmado (agente + aplicación, `.exe`
y `.msi`), igual para todas las organizaciones. Al instalar, busca la configuración en este orden:
propiedad `CERCANO_CONFIG` del `.msi`, `cercano-org.json` en la carpeta del instalador; sin ninguna,
instala solo la aplicación en modo libre. Con configuración, la valida (firma y caducidad), muestra
organización, host y huella en modo interactivo, e instala y vincula el agente.
*CA:* `Get-AuthenticodeSignature` = `Valid` en `.exe` y `.msi`; una configuración alterada o caducada
aborta la instalación sin dejar restos; sin configuración queda en modo libre.

**F3.5-12 Generador en el servidor.**
`cercano-api` firma el perfil (servicio de build F3-07, ahora sin compilar ni empaquetar) y ofrece
`cercano-org.json`, el código de configuración y el `.zip` con el instalador genérico; `console-web`
amplía el formulario de F4-07 con los parámetros del ADR-015 §2.11 y muestra hash del instalador y
huella de clave en la descarga. Permisos `builder:create:soporte`/`tecnico`; auditoría `build.*`;
descarga con caducidad.
*CA:* desde la consola, en un servidor Linux sin herramientas de Windows, se obtiene una configuración
que, con el instalador genérico, instala y vincula en Windows 11; sin permiso del rol pedido → 403 y
`auth.denied`.

**F3.5-13 Guía de despliegue y diagnóstico.**
Actualizar la guía de F3-11: instalador genérico con `cercano-org.json` o `.zip`, `.msi` con
`CERCANO_CONFIG` para GPO/Intune, `cercano-agent enroll --config` para equipos ya instalados, modo
libre, comprobación con `cercano-agent status --json | ConvertFrom-Json`, problemas habituales
(tubería, vinculación, política caducada, revocación) y desinstalación.
*CA:* un agente que no la escribió despliega y diagnostica en el laboratorio siguiéndola de cero.

**F3.5-14 Revisión de seguridad.**
Ampliar el modelo de amenazas (`ARQUITECTURA.md` §6 y `specs/threat-model-roles-elevation.md`):
suplantación de la tubería, llamante no firmado, configuración ajena junto al instalador genérico,
robo de la configuración (token de registro), detener el agente para saltarse la política, rotación y
robo de la clave fijada. *Fuzzing* del canal local y del lector de configuración. Informe `docs/status/informes/F3.5-14.md`.
*CA:* sin hallazgos críticos o altos abiertos; medios y bajos con plan.

**F3.5-15 E2E y cierre.**
En Windows 10 y 11, con y sin Defender: libre contra un servidor configurado a mano; gestionado
`soporte` y `tecnico` con configuraciones generadas desde la consola; bloqueado al detener el agente;
revocación; chat; auditoría; desinstalación limpia. Informe `docs/status/informes/F3.5-15.md`.
*CA:* casos TC-F3.5-* en verde; gate de la sección 5 cumplido.

## 4. Casos de prueba propuestos (QA los pasa a `PLAN-DE-PRUEBAS.md`)

| ID | Caso | Resultado esperado |
|---|---|---|
| TC-F3.5-001 | Aplicación sin agente, servidor configurado a mano | Conecta en modo libre; se ve «No gestionado» |
| TC-F3.5-002 | Aplicación sin agente ni configuración | Pide servidor; no intenta `127.0.0.1` |
| TC-F3.5-003 | Instalador genérico con `cercano-org.json`, instalación interactiva | Muestra organización, host y huella antes de confirmar |
| TC-F3.5-004 | `cercano-org.json` o código con un byte alterado | Instalación rechazada sin restos; firma Authenticode intacta |
| TC-F3.5-005 | Perfil nuevo firmado con otra clave tras la fijación | Rechazado y auditado |
| TC-F3.5-006 | Token de registro caducado, agotado o revocado | Vinculación denegada y `agent.enroll_denied` |
| TC-F3.5-007 | Proceso sin firmar se conecta a la tubería | Sin respuesta; registrado |
| TC-F3.5-008 | Proceso que suplanta la tubería antes que el agente | La aplicación lo rechaza y queda bloqueada |
| TC-F3.5-009 | Detener el servicio `CercanoAgent` | Aplicación bloqueada; no acepta conexiones entrantes nuevas |
| TC-F3.5-010 | Política caducada sin red | Fallo cerrado (equivale a TC-F5-024) |
| TC-F3.5-011 | Auditoría sin red y reconexión | Eventos enviados sin pérdida ni duplicados; cadena verificable |
| TC-F3.5-012 | Cambio de marca en la consola | Nueva marca visible en equipos ya instalados sin reinstalar; icono de Cercano intacto |
| TC-F3.5-013 | `cercano-agent export-diagnostics` | Sin claves, tokens ni secretos |
| TC-F3.5-014 | Usuario estándar ejecuta `re-enroll` | Denegado |
| TC-F3.5-015 | `msiexec /i cercano.msi /qn CERCANO_CONFIG=<código de tamaño máximo>` | Instala y vincula en silencio |

## 5. Gate F3.5 (M2.5)

- El mismo binario de la aplicación funciona en modo libre con un servidor cualquiera y en modo
  gestionado con una configuración generada desde la consola, en Windows 10 y 11.
- El servidor genera configuraciones sin compilar, sin herramientas de Windows y sin el certificado de
  firma de código; los binarios publicados son los mismos que salen de la máquina de compilación.
- Ninguna clave privada, token ni credencial en artefactos, repositorio, logs o salidas de diagnóstico
  (verificación automática).
- Revisión de seguridad sin hallazgos críticos o altos abiertos.
- `patches/INDEX.md` actualizado y la deriva contra `vendor/` igual o menor que antes de F3.5.
