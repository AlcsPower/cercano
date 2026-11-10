# Plan de trabajo — F5: Identidad y control de acceso

**Versión:** 0.1 · **Fecha:** 2026-11-10 · **Estado:** propuesta para revisión del Coordinador · **Duración estimada:** 4–5 semanas  
**Objetivo:** habilitar directorio de dispositivos, grupos, políticas centralizadas y federación de identidad, manteniendo el control de acceso en el servidor y la auditoría verificable.  
**Depende de:** cierre de F4 y F4.5; F1-04, F1-05, F2-02, F2-08, F3-01/02/09/13 y F4 (RBAC/2FA) disponibles. La integración con Windows LAPS queda sujeta al análisis de seguridad de F5-01/F5-10.  
**Referencias:** `docs/ROADMAP.md`, `docs/ARQUITECTURA.md`, `docs/PLAN-F4-CONSOLA.md`, `docs/PLAN-F3-GENERADOR.md`, `docs/PLAN-F4.5-CHAT.md`, `docs/specs/api.yaml`, `docs/specs/cercano-profile.md` y `docs/PLAN-DE-PRUEBAS.md`.

## 1. Alcance y límites

Incluye libreta de direcciones técnica, agrupación de usuarios/dispositivos, estrategias centralizadas, autorización entre grupos, login administrativo OIDC y LDAP, evaluación de cambio de ID de dispositivo y el trabajo de identidad necesario para Windows LAPS. Las reglas se validan en `cercano-api`; ocultar una acción en la consola o en el cliente no sustituye la autorización del servidor.

No incluye multi-tenant, roles totalmente configurables, cliente web remoto, ni almacenamiento propio de contraseñas de administrador. No se debe cambiar el contrato ni el comportamiento de roles de instalador (ADR-008) sin ADR y revisión del dueño. OIDC y LDAP son proveedores de identidad alternativos, no una sincronización automática de credenciales.

### Invariantes de seguridad

- Denegación por defecto: ausencia de grupo, estrategia, atributo o proveedor disponible nunca amplía permisos.
- Toda lectura y escritura se limita por rol, pertenencia y alcance; se prueban IDOR y escaladas entre grupos.
- La política efectiva se calcula y aplica en el backend. El cliente puede cachear configuración para disponibilidad, pero no es autoridad.
- Los cambios de identidad, política, grupo, proveedor y acceso privilegiado generan eventos de auditoría sin contraseñas, tokens, secretos OIDC/LDAP ni credenciales LAPS.
- Las políticas centrales no pueden habilitar capacidades prohibidas por el perfil firmado o por el rol de instalador.
- Las cuentas locales y el procedimiento de recuperación del administrador deben seguir disponibles según una ruta explícita, protegida y auditada.

## 2. Modelo funcional propuesto

- **Grupos:** contenedores administrables de dispositivos y usuarios; las relaciones tienen IDs estables y se auditan. Un dispositivo pertenece a cero o más grupos según reglas aprobadas en F5-01.
- **Libreta:** entradas visibles para el operador autorizado con nombre, dispositivo/grupo, etiquetas y datos de conexión necesarios; no duplica secretos ni material de autenticación.
- **Estrategia:** documento versionado de ajustes con ámbito definido (global, grupo o dispositivo), autor, vigencia y precedencia. Precedencia propuesta: límites del producto/perfil firmado → política global → grupo → dispositivo; el valor más restrictivo prevalece en permisos de seguridad. La decisión final y los conflictos deben quedar documentados antes de implementar.
- **Acceso entre grupos:** permisos explícitos de lectura y operación entre grupos; sin regla explícita, no hay acceso. El rol global no omite los registros de auditoría.
- **Federación:** OIDC como opción preferida cuando exista proveedor; LDAP como alternativa para directorios que no expongan OIDC. Vinculación de cuentas por identificador estable del emisor/directorio, no solo por nombre de usuario o correo.
- **Cambio de ID:** no se implementa hasta que F5-09 determine impacto, invariantes, compatibilidad y mecanismo de recuperación. Si es inseguro o ambiguo, se difiere con justificación.
- **LAPS:** solo lectura puntual de contraseña administrada por Windows LAPS, sin copia persistente ni caché, si la política y el entorno lo permiten. No se desarrolla una bóveda propia.

## 3. Tareas

| ID | Tarea | Dep. | Rol | Verifica |
|---|---|---|---|---|
| F5-01 | Aprobar modelo de grupos, libreta, estrategias, federación, LAPS y orden de migraciones; actualizar ADR/specs y catálogo de pruebas | F4, F4.5 | Coordinador + Seguridad | Dueño/QA |
| F5-02 | Migración aditiva 009 y modelos de grupos, membresías, libreta y estrategias | F5-01 | ControlPlane | QA |
| F5-03 | API CRUD de grupos y libreta con paginación, validación y eventos de auditoría | F5-02, F4-05 | ControlPlane | QA |
| F5-04 | Enforcement de alcance por rol/grupo y permisos entre grupos | F5-02/03 | ControlPlane | Seguridad |
| F5-05 | Servicio de estrategias: versionado, resolución, precedencia, asignación y explicación de política efectiva | F5-01/02 | ControlPlane | Seguridad/QA |
| F5-06 | Cliente: descarga, cacheo acotado y aplicación de estrategia; rechazo de configuración incompatible | F5-05, F3-02/13 | Cliente | QA/Seguridad |
| F5-07 | Inicio de sesión OIDC: descubrimiento, Authorization Code + PKCE, callback y vinculación de identidad | F5-01, F4 | ControlPlane | Seguridad |
| F5-08 | Autenticación LDAP sobre TLS, mapeo explícito de grupos y límites de disponibilidad | F5-01, F4 | ControlPlane | Seguridad |
| F5-09 | Evaluar cambio de ID de dispositivo; ADR con decisión implementar/diferir y pruebas de migración si procede | F5-01, F1-05 | Coordinador + Servidor | Seguridad/Dueño |
| F5-10 | Evaluar e integrar Windows LAPS con aprobación por solicitud y `elev:l aps`/permiso equivalente definido en especificación | F5-01, F3-16/17, F4 | ControlPlane + Cliente | Seguridad |
| F5-11 | Consola: grupos, libreta, estrategias, asignaciones, acceso federado y diagnóstico de política efectiva | F5-03…08 | Web | QA |
| F5-12 | Pruebas de integración, autorización, migración, abuso de identidad y laboratorio LAN | F5-03…11 | QA + Seguridad | Coordinador |
| F5-13 | Documentación de operador, recuperación de identidad y gate F5 | F5-12 | Coordinador | Dueño |

> Corrección editorial pendiente antes de aprobar: en F5-10 el permiso se denominará de forma consistente `elev:laps` (sin espacio) en la especificación y el código.

## 4. Criterios de aceptación por tarea

- **F5-01:** matriz de datos/permisos, precedencia de políticas, configuración de OIDC/LDAP, modelo de amenazas y migraciones aprobados. Definir qué claims se aceptan, cómo se vinculan cuentas, qué pasa cuando el IdP/directorio no está disponible y cómo se conserva el acceso de emergencia. La decisión sobre cambio de ID y LAPS incluye amenazas y límites explícitos.
- **F5-02:** migración 009 solo se aplica después de 007 y 008; funciona desde BD vacía y desde una copia con migraciones previas; es aditiva, reversible o tiene procedimiento de recuperación documentado, conserva datos y crea índices/constraints verificados.
- **F5-03/04:** cada endpoint comprueba autorización en servidor; pruebas positivas y negativas para admin/operator/auditor y varios grupos; una referencia a un ID de otro grupo no revela ni modifica el recurso; todas las operaciones de escritura y denegaciones relevantes quedan auditadas.
- **F5-05/06:** resolución determinista, versionada y explicable. Una estrategia caducada, malformada o no disponible no concede permisos; el cliente no puede editar ni elevar una política firmada; se documenta la duración de caché y el comportamiento sin red.
- **F5-07:** OIDC valida emisor, audiencia, `state`, `nonce`, PKCE, firma/rotación de claves y callback exacto; no se acepta login CSRF ni vinculación automática por correo; secretos no aparecen en URL persistente, logs, auditoría o frontend. Revocar/desvincular una identidad invalida sesiones según política.
- **F5-08:** LDAP usa TLS con validación de certificado; no hay bind simple sin TLS ni persistencia de contraseñas; límites de tiempo y errores no filtran si una cuenta existe. El mapeo de grupos es allowlist y el fallo del directorio no crea sesiones privilegiadas.
- **F5-09:** ADR con escenarios de colisión, historial de auditoría, referencias, perfiles/instaladores y recuperación. Si se implementa, el cambio es transaccional, autorizado y auditado; el ID anterior no puede apropiarse ni reutilizarse silenciosamente.
- **F5-10:** si se aprueba, cada consulta LAPS requiere técnico autenticado con 2FA, permiso dedicado, consentimiento y alcance explícitos; el secreto solo se entrega para una solicitud, no se almacena ni se audita en claro, y la acción queda limitada/expira. Si no puede garantizarse el flujo, se difiere; no se crea una bóveda propia.
- **F5-11:** estados de carga/vacío/error, permisos reflejados, navegación accesible y diagnósticos sin datos secretos. Ninguna vista presenta un permiso como efectivo si el API lo rechaza.
- **F5-12/13:** pruebas en CI y laboratorio; documentación reproducible por otra persona; informe `docs/status/F5-cierre.md` y cero hallazgos críticos/altos abiertos.

## 5. Casos de prueba y gate

Crear `tests/cases/TC-F5-*.md` y registrar los casos en `docs/PLAN-DE-PRUEBAS.md` durante F5-01. Cobertura mínima:

| Grupo | Verificación mínima |
|---|---|
| Datos y migración | 009 sobre BD limpia y versiones 007/008; constraints, rollback/recuperación y conservación |
| Autorización | Matriz rol × operación × grupo; IDOR, enumeración y acceso cruzado denegados y auditados |
| Estrategias | Precedencia determinista; política caducada/inválida; cliente offline; la política no amplía rol/perfil |
| OIDC | `state`/`nonce`/PKCE, emisor/audiencia erróneos, claves rotadas, callback y vinculación de cuentas |
| LDAP | TLS obligatorio, timeout, credencial inválida, servidor caído, mapeo allowlist y sin escalada |
| Cambio de ID | Solo si aprobado: colisión, replay, revocación, referencias e historial; caso diferido justificado si no se entrega |
| LAPS | Solo si aprobado: consentimiento, 2FA, permiso, caducidad, alcance, no persistencia y ausencia de secreto en logs/auditoría |
| Consola | Accesibilidad, permisos, estados, filtros y coherencia con API |

**Gate F5:** 100 % de tareas `Hecho` o `Diferida` con justificación; casos en verde; migración validada; auditoría `cercano-audit verify` en verde; ningún hallazgo crítico/alto abierto; documentación e informe publicados. Una integración de identidad incompleta o una ruta de recuperación no probada impide activar SSO/LDAP en producción.

## 6. Riesgos y decisiones

| Riesgo | Mitigación |
|---|---|
| Error de precedencia amplía acceso o debilita políticas | Reglas formales, deny-by-default, pruebas de propiedades y enforcement servidor |
| Confusión o toma de cuentas federadas | Identificador estable issuer+subject, vinculación explícita y auditoría |
| Caída/latencia del directorio bloquea acceso | Timeouts, salud observada, cuenta break-glass controlada y procedimiento probado |
| Secreto LAPS expuesto a un técnico o al backend | Consentimiento y alcance, exposición efímera, sin almacenamiento; diferir si no es demostrable |
| Cambios de ID rompen historial/instaladores | Evaluación independiente; no implementar hasta resolver identidad y recuperación |
| Migraciones de F4/F4.5 concurrentes | Orden de versión fijado por Coordinador; migración 009 posterior a 007/008 |

## 7. Fuera de alcance

Multi-tenant, roles definidos por usuario, bóveda propia de credenciales, aprovisionamiento SCIM, sincronización bidireccional de directorio y cambio de ID no aprobado explícitamente. Linux/macOS LAPS y autenticación federada del cliente controlado también quedan fuera salvo decisión posterior.
