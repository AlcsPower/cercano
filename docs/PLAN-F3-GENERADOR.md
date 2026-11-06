# Plan de trabajo — F3: Generador de instaladores personalizados

**Versión:** 0.3 · **Fecha:** 2026-11-06 · Depende de: F1 cerrado, veredicto de S4 (H4) y F2-08 (auditoría de la API).

**Objetivo (M2):** a partir de un perfil JSON se obtienen **dos tipos de instalador Windows** —uno para recibir soporte y otro para el equipo técnico—, firmados, preconfigurados con servidor, clave y política, auditados y revocables.

## 1. Tipos de instalador

El generador produce dos tipos, elegidos con el campo `role` del perfil. Los nombres de producto son provisionales (decisión D1).

| | **Soporte** (`role: "soporte"`) · «Cercano Soporte» | **Técnico** (`role: "tecnico"`) · «Cercano Técnico» |
|---|---|---|
| Quién lo usa | La persona usuaria cuyo equipo recibe asistencia | El personal de TI que da la asistencia |
| Recibir conexiones | Sí. Por defecto con aprobación de la persona usuaria en cada sesión; el modo desatendido solo si el perfil lo habilita | Sí, opcional (soporte entre técnicos) |
| Iniciar conexiones | **No** | Sí, solo con sesión iniciada en `cercano-api` |
| Libreta y lista de dispositivos | No | Sí |
| Archivos, terminal, puerto, cámara | Solo como equipo controlado, según la política del perfil | Como controlador, según los permisos de su cuenta |
| Elevación con credenciales de administrador (sección 3) | Receptor: la persona usuaria la aprueba | Emisor: solicita y envía; requiere el permiso `elev:use` |
| Cuenta de usuario | No necesita (ID más código temporal o aprobación) | Obligatoria; 2FA obligatoria cuando exista (F4) |
| Ajustes de servidor, clave y red | Bloqueados | Bloqueados; solo se cambian generando un instalador nuevo |
| Indicador de sesión activa | Siempre visible | Siempre visible |
| Quién puede generarlo | Permiso `builder:create:soporte` | Permiso `builder:create:tecnico` (solo rol administrador) |
| Caducidad por defecto (objetivo propuesto) | Sin caducidad, revocable | 90 días, revocable |
| Artefactos | `cercano-soporte-<versión>.exe` y `.msi` | `cercano-tecnico-<versión>.exe` y `.msi` |

**El rol se aplica en el servidor, no solo en el instalador.** El `role` viaja dentro del perfil firmado y el `installer_id` se registra en `cercano-api` junto con su rol. El servidor rechaza las operaciones de técnico (iniciar una conexión, enviar una elevación) si vienen de un instalador `soporte`, y registra la violación como alarma. Editar la configuración local de un instalador `soporte` no lo convierte en técnico. Ver ADR-008 en `ARQUITECTURA.md`.

## 2. Requisitos funcionales del perfil

| Entrada del perfil | Descripción |
|---|---|
| **Rol** | `soporte` o `tecnico`; fija las capacidades de la sección 1 |
| Servidor | Hosts de rendezvous, relay y API; clave pública del servidor |
| Identidad visual | Nombre visible, icono (por defecto `branding/png/cercano-icon.ico`), textos de «acerca de» (siempre con atribución AGPL) |
| Política inicial | Acceso desatendido sí/no (solo `soporte`), política de contraseñas, aprobación de conexiones, permisos por defecto (archivos, portapapeles, audio, terminal), ocultar o no ajustes de red |
| Elevación | Activada o no; si es `soporte`, si admite elevación desatendida (desactivada por defecto) |
| Instalación | Modo (instalador, portable), ruta, inicio automático, acceso directo, silencioso |
| Identificación | Grupo/etiqueta del dispositivo y propietario predeterminado |
| Caducidad | Fecha de caducidad del perfil y límite de usos opcionales |

| Salida | Descripción |
|---|---|
| Artefacto | `.exe` y `.msi` (para GPO/Intune/RMM) por rol en Windows; Linux (.deb/AppImage) y macOS (.dmg) en fases posteriores |
| Metadatos | Hash SHA-256, ID de instalador, **rol**, perfil usado, SBOM, firma Authenticode |
| Evidencia | Eventos `build.*` encadenados en la auditoría |

## 3. Elevación con credenciales de administrador

**Qué resuelve.** Durante una sesión, el técnico necesita hacer en el equipo del cliente algo que pide permisos de administrador de Windows (instalar un programa, cambiar un servicio, aceptar un aviso de UAC). El técnico envía credenciales de administrador al equipo del cliente para esa acción, sin que la persona usuaria las vea ni las conozca.

**Flujo.**
1. El técnico pulsa «Solicitar elevación» e indica el motivo (texto obligatorio, y número de ticket opcional).
2. La persona usuaria ve un aviso con el nombre del técnico, el motivo y la hora, y acepta o rechaza. Sin su aprobación no se envía nada.
3. El técnico escribe usuario y contraseña en un diálogo seguro de la consola técnica. No se guardan, no se copian y se descartan al terminar.
4. Las credenciales viajan dentro del canal cifrado de extremo a extremo de la sesión. No pasan por `cercano-api` y el relay solo ve datos cifrados.
5. El servicio de Cercano en el equipo cliente (que corre con privilegios de sistema) las usa para **una sola acción** y las borra de memoria de inmediato.
6. Cada paso queda en la auditoría como evento `elev.*`, sin el secreto.

**Reglas no negociables.**
- **Consentimiento:** cada solicitud la aprueba la persona usuaria. La elevación desatendida solo existe si un administrador la habilita en el perfil del instalador `soporte`; queda desactivada por defecto y toda su actividad se audita.
- **Sin persistencia:** las credenciales nunca se escriben a disco, logs, portapapeles, variables de entorno ni volcados de error; se borran de memoria al terminar (`zeroize`).
- **Nunca visibles a la persona usuaria,** ni en pantalla ni en capturas o grabaciones de sesión (F2-15): el diálogo de credenciales se enmascara.
- **Mínimo privilegio:** por defecto la elevación vale para una acción y caduca en 60 s (objetivo propuesto). Una «sesión elevada» de varias acciones requiere el permiso adicional `elev:session` y un segundo consentimiento.
- **Límites:** máximo 3 intentos fallidos por solicitud, para no bloquear cuentas de dominio; limitación de tasa por técnico y por dispositivo.
- **Permisos:** solo cuentas técnicas con `elev:use`, desde un instalador `tecnico`. Un instalador `soporte` nunca puede emitir una elevación.
- **Cercano no captura lo que la persona usuaria escribe:** no hay registro de pulsaciones ni de contraseñas del usuario final.
- **Habilitación por fases:** la función se entrega **desactivada por defecto**. Solo se activa en el laboratorio durante F3. Para activarla en producción hacen falta 2FA obligatoria para técnicos (F4) y la revisión de F3-18 sin hallazgos altos.

**Origen de las credenciales.**

| Opción | Descripción | Cuándo |
|---|---|---|
| A. Tecleo manual | El técnico las escribe en cada solicitud | F3 (valor por defecto, decisión D8) |
| B. Windows LAPS | `cercano-api` obtiene la contraseña local de administrador gestionada por LAPS, con permiso `elev:laps` y auditoría | F5, con identidad y control de acceso |
| C. Bóveda propia | Cercano guardaría credenciales cifradas | Fuera de alcance salvo decisión expresa: guardar credenciales de administrador es el mayor riesgo de la función |

**Mecanismo en el equipo cliente.** No está decidido. El spike S6 (dentro de F3-16) compara: completar el aviso de credenciales de UAC desde el servicio, lanzar un proceso con las credenciales (`LogonUser` / `CreateProcessAsUser`) y ejecutar una acción predefinida desde el servicio sin credenciales. El Coordinador aprueba el mecanismo antes de implementar.

**Eventos de auditoría** (categoría `elev`): `elev.requested`, `elev.consented`, `elev.denied`, `elev.sent`, `elev.applied`, `elev.failed`, `elev.expired`. Registran técnico, equipo, persona usuaria, cuenta objetivo (el nombre, nunca la contraseña ni su hash), motivo, ticket, alcance y resultado.

## 4. Enfoque técnico (sujeto a S4)

**Estrategia A (recomendada si H4 se confirma): compilar una vez, configurar muchas.**
Se compila un binario base por versión. El generador añade/empaqueta un *perfil firmado* (Ed25519, clave del generador) que el cliente verifica al arrancar contra una clave pública incluida en el binario base. El rol y las capacidades salen de ese perfil. Resultado: generación en segundos.

**Estrategia B (fallback o para cambios de recursos como icono y nombre):** compilación completa por perfil en un runner de CI, con caché agresiva. Resultado: minutos.

**Firma de código:** integración enchufable (signtool, osslsigncode o HSM/servicio en la nube). Mientras no exista certificado (D4), se usa uno de pruebas y los artefactos se etiquetan «NO PARA PRODUCCIÓN».

**Revocación:** cada instalador lleva un `installer_id`; `cercano-api` mantiene lista de revocación y el servidor rechaza registros y conexiones de instaladores revocados o caducados. Se puede revocar un instalador concreto o todos los de un rol.

## 5. Reglas de seguridad del generador

- El instalador nunca oculta su presencia: icono/indicador visible y entrada en «Programas y características».
- Los perfiles no incluyen credenciales de administrador; solo claves públicas y tokens de registro de menor privilegio, con caducidad.
- Las claves de firma del generador y de Authenticode no salen del servicio de firma y no se guardan en el repositorio ni en artefactos.
- Cada generación exige un usuario autenticado con el permiso del rol pedido (`builder:create:soporte` o `builder:create:tecnico`) y queda auditada (quién, rol, perfil, resultado, hash).
- Los instaladores generados se pueden rastrear hasta el perfil y el usuario que los creó.
- Un instalador `tecnico` filtrado es más peligroso que uno `soporte`: caduca antes, exige cuenta y se revoca por separado.

## 6. Tareas

| ID | Tarea | Dep. | Rol | Verifica |
|---|---|---|---|---|
| F3-01 | Esquema y versionado del perfil | F0-07 | Builder | Seguridad |
| F3-02 | Cliente: lectura y verificación de perfil firmado | F3-01 | Cliente | Seguridad |
| F3-03 | Binario base reproducible y publicación de artefactos base | F0-05, F0-03 | Builder | QA |
| F3-04 | CLI `cercano-build` | F3-01, F3-02, F3-03 | Builder | QA |
| F3-05 | Empaquetado Windows (.exe y .msi) | F3-04 | Builder | QA |
| F3-06 | Firma Authenticode enchufable | F3-05 | Builder | Seguridad |
| F3-07 | Servicio de build en `cercano-api`: cola, jobs, almacenamiento | F3-04, F1-04 | ControlPlane | QA |
| F3-08 | Auditoría `build.*` | F3-07, F2-02 | ControlPlane | QA |
| F3-09 | Revocación y caducidad | F3-02, F3-07 | ControlPlane + Servidor | Seguridad |
| F3-10 | SBOM y verificación de procedencia | F3-04 | Builder | Seguridad |
| F3-11 | Guía de despliegue masivo | F3-05, F3-14, F3-15 | Coordinador | QA |
| F3-12 | Pruebas de extremo a extremo y cierre | F3-01…11, F3-13…18 | QA | Coordinador |
| F3-13 | Roles de instalador: perfil y aplicación en el servidor | F3-01, F3-02, F3-07 | ControlPlane + Servidor | Seguridad |
| F3-14 | Cliente en modo soporte | F3-02, F3-13 | Cliente | QA |
| F3-15 | Cliente en modo técnico | F3-02, F3-13, F1-04 | Cliente | QA |
| F3-16 | Spike S6 y elevación con credenciales | F3-14, F3-15 | Cliente | Seguridad |
| F3-17 | Auditoría `elev.*` y alarmas de elevación | F3-16, F2-02, F2-07 | ControlPlane | QA |
| F3-18 | Revisión de seguridad de roles y elevación | F3-13…17 | Seguridad | Coordinador |

### Detalle

**F3-01 Esquema del perfil.**
JSON Schema `docs/specs/cercano-profile.schema.json` con versión, el campo `role` (`soporte` o `tecnico`), los campos de la sección 2, valores por defecto y reglas de validación (hosts válidos, longitudes, caracteres permitidos, combinaciones de capacidades permitidas por rol). Política de compatibilidad hacia atrás entre versiones del perfil.
*CA:* ejemplos válidos e inválidos cubiertos por pruebas; un perfil `soporte` que declare capacidades de técnico se rechaza; perfiles con campos desconocidos se rechazan o ignoran según política documentada.

**F3-02 Cliente: perfil firmado.**
Parche mínimo: al arrancar, localizar el perfil embebido, verificar firma y caducidad, leer el rol, aplicar la configuración y rechazar perfiles manipulados. La clave pública de verificación es configurable en tiempo de compilación.
*CA:* perfil alterado en un solo byte → rechazado y evento registrado; perfil caducado → rechazado; perfil válido → configuración aplicada; cambiar el rol sin volver a firmar → rechazado (TC-F3-001…008).

**F3-03 Binario base reproducible.**
Pipeline de CI que produce el binario base por versión y plataforma, con caché de dependencias, SBOM y hashes publicados. Documentar cómo reproducir el build localmente.
*CA:* dos builds del mismo commit producen el mismo hash (o la diferencia queda explicada y acotada).

**F3-04 CLI `cercano-build`.**
`cercano-build --profile perfil.json --out dist/` produce artefacto y metadatos para el rol del perfil; modo `--dry-run` valida el perfil; salida determinista para el mismo perfil y base.
*CA:* genera en < 30 s con la estrategia A (objetivo propuesto); errores claros ante perfiles inválidos; los artefactos llevan el nombre del rol.

**F3-05 Empaquetado Windows.**
`.exe` (instalador) y `.msi` por rol, con instalación silenciosa y parámetros documentados; actualización sobre una instalación previa; desinstalación limpia. Se puede tener instalado el instalador `soporte` y el `tecnico` en equipos distintos sin que se confundan; en un mismo equipo, el segundo reemplaza al primero con aviso.
*CA:* instalación, actualización y desinstalación en Windows 10 y 11 limpios sin restos (verificado por QA en el laboratorio); `.msi` desplegable por línea de comandos.

**F3-06 Firma enchufable.**
Interfaz de firmante con implementaciones para signtool/osslsigncode; la clave solo vive en el servicio de firma. Sello de tiempo obligatorio.
*CA:* la firma se verifica con `Get-AuthenticodeSignature`; si falla la firma, el job falla y no se publica el artefacto.

**F3-07 Servicio de build.**
Endpoints `POST /builds`, `GET /builds/{id}`, descarga firmada con caducidad; cola con límite de concurrencia; almacenamiento de artefactos con retención configurable; permisos `builder:create:soporte`, `builder:create:tecnico` y `builder:download`.
*CA:* flujo completo por API; un usuario sin permiso del rol pedido recibe 403 y queda un evento `auth.denied`; solo un administrador puede pedir un instalador `tecnico`.

**F3-08 Auditoría `build.*`.**
Eventos `build.requested`, `build.started`, `build.completed`, `build.failed`, `build.downloaded`, `build.revoked`, con ID de instalador, rol, hash, perfil (sin secretos) y actor.
*CA:* cada ejecución deja la secuencia completa y verificable.

**F3-09 Revocación y caducidad.**
`cercano-api` publica la lista de revocados; hbbs la consulta (con caché y degradación segura configurable) y rechaza registros/conexiones de instaladores revocados o caducados; evento por cada rechazo. Se revoca un instalador o todos los de un rol.
*CA:* tras revocar, el instalador deja de poder registrarse en menos de 60 s (objetivo propuesto); rechazo auditado.

**F3-10 SBOM y procedencia.**
SBOM (CycloneDX o SPDX) por artefacto, hashes y atestación de procedencia del build en CI.
*CA:* cada artefacto publicado trae SBOM y hash verificables.

**F3-11 Guía de despliegue masivo.**
Guía para GPO, Intune y herramientas RMM: cuándo usar cada rol, parámetros silenciosos, verificación posterior, desinstalación, actualización y manejo de antivirus/SmartScreen. Incluye cómo distribuir el instalador `tecnico` solo a quien corresponde.
*CA:* un agente que no la escribió la sigue de cero y logra el despliegue de ambos roles en el laboratorio.

**F3-12 Pruebas E2E y cierre.**
Casos TC-F3-*: perfil → instalador → instalación → registro → conexión → auditoría → revocación, para cada rol; manipulación de perfiles; instaladores caducados; fallo de firma; reproducibilidad; roles y elevación.
*CA:* suite verde; informe `docs/status/F3-cierre.md`.

**F3-13 Roles de instalador.**
Registrar el `installer_id` con su rol en `cercano-api` al primer arranque; el servidor (hbbs y `cercano-api`) comprueba el rol en cada operación de técnico y rechaza las que vengan de un `soporte`; alarma `alarm.role_violation` en cada rechazo. Diseño según ADR-008.
*CA:* un `soporte` no puede iniciar una conexión ni enviar una elevación aunque se modifique su configuración local o se manipule el tráfico; cada rechazo queda auditado (TC-F3-060…064).

**F3-14 Cliente en modo soporte.**
Interfaz y capacidades restringidas según la sección 1: sin libreta, sin iniciar conexiones, ajustes de servidor/clave/red bloqueados, indicador visible de sesión, aprobación de la persona usuaria en cada sesión salvo que el perfil habilite el modo desatendido, y aviso de elevación entrante. Parches mínimos y con *feature flag*.
*CA:* la matriz de la sección 1, columna «Soporte», se cumple en el laboratorio; la persona usuaria puede terminar la sesión en cualquier momento.

**F3-15 Cliente en modo técnico.**
Inicio de sesión con cuenta de `cercano-api`, libreta y capacidades avanzadas según los permisos de la cuenta; ajustes de servidor bloqueados; cierre de sesión que limpia el estado local. La 2FA se exige en cuanto exista (F4).
*CA:* la columna «Técnico» de la sección 1 se cumple; sin sesión iniciada no se puede iniciar ninguna conexión; los permisos de la cuenta limitan las capacidades visibles.

**F3-16 Spike S6 y elevación con credenciales.**
Primero el spike S6 (`docs/spikes/S6-elevacion.md`): comparar los mecanismos de la sección 3 en el laboratorio con Windows 10 y 11, con cuentas locales y de dominio, y proponer uno con sus límites. El Coordinador aprueba. Después, implementar el flujo completo: solicitud con motivo, consentimiento de la persona usuaria, diálogo seguro del técnico, envío por el canal cifrado, uso único por el servicio del equipo cliente y borrado de memoria.
*CA:* se cumplen todas las reglas no negociables de la sección 3, demostradas con evidencia: las credenciales no aparecen en disco, logs, volcados de memoria tras el borrado, tráfico de red capturado ni grabaciones; un rechazo de la persona usuaria no envía nada; el límite de 3 intentos funciona (TC-F3-070…079).

**F3-17 Auditoría `elev.*` y alarmas.**
Primero extender el esquema de eventos ya publicado en F2-01 (`docs/specs/audit-events.schema.json` y `audit-events.md`): añadir la categoría `elev`, sus acciones y la expresión permitida para `action`, sin invalidar los eventos existentes. Después emitir los eventos de la sección 3 y añadir alarmas: elevaciones repetidas del mismo técnico en poco tiempo, solicitudes rechazadas seguidas, intentos fallidos agotados, elevación fuera del horario configurado. Los eventos nunca contienen el secreto ni su hash.
*CA:* el esquema valida los eventos `elev.*` y `cercano-audit verify` sigue verificando cadenas que mezclan eventos antiguos y nuevos; cada paso del flujo genera su evento encadenado; una revisión automática de la base de auditoría no encuentra contraseñas (TC-F3-080…084).

**F3-18 Revisión de seguridad de roles y elevación.**
Ampliar el modelo de amenazas con el abuso de la elevación, un técnico comprometido, un instalador `tecnico` robado y la escalada de `soporte` a `tecnico`; fuzzing del mensaje de elevación; pruebas de abuso en el laboratorio. Informe `docs/status/informes/F3-18.md`.
*CA:* sin hallazgos críticos o altos abiertos; los medios y bajos con plan; la activación en producción queda condicionada a 2FA (F4).

**Gate F3 (M2):** flujo completo demostrado en el laboratorio para ambos roles; la matriz de la sección 1 verificada por QA; ninguna clave privada ni credencial presente en artefactos, repositorio ni auditoría (verificación automática); revisión de seguridad sin hallazgos altos; SBOM y firmas verificables; elevación entregada desactivada por defecto.

## 7. Fuera de alcance en F3

Generación para Linux y macOS (se planifica al cierre de F3), interfaz web del generador (F4), notarización de macOS, bóveda propia de credenciales (opción C), integración con Windows LAPS (opción B, F5) y elevación en equipos que no sean Windows.
