# Modelo de Amenazas — Roles de Instalador y Elevación de Privilegios

**Versión:** 1.0 · **Fecha:** 2026-11-10 · **Estado:** Aprobado · **Rol:** Agente-Seguridad  
**Documentos de referencia:** `docs/ARQUITECTURA.md` (§6, ADR-008, ADR-009), `docs/PLAN-F3-GENERADOR.md` (§1, §3, F3-18), `docs/spikes/S6-elevacion.md`.

---

## 1. Resumen Ejecutivo y Alcance

Este documento formaliza y amplía el modelo de amenazas del sistema Cercano para la **Fase 3 (Generador de Instaladores Personalizados)**, evaluando en profundidad las fronteras de confianza, vectores de ataque, riesgos de privacidad y contramedidas implementadas para:
1. La segregación estricta de roles de instalador (`soporte` vs `tecnico`).
2. El mecanismo de elevación supervisada de privilegios en el endpoint mediante credenciales administrativas efímeras (Opción A: canal E2E + servicio local).

La evaluación sigue una adaptación formal de las metodologías **STRIDE** (foco en seguridad e integridad) y **LINDDUN** (foco en privacidad y confidencialidad de la persona usuaria y del técnico).

---

## 2. Fronteras de Confianza y Arquitectura de Datos

```
+-----------------------------------------------------------------------------------+
| ZONA NO CONFIABLE / CLIENTE SOPORTE (Endpoint controlado)                         |
|  - Proceso de usuario (Medium Integrity)                                         |
|  - Perfil firmado embebido (`cercano-profile.signed.json`)                        |
|  - Consentimiento interactivo modal (aprobación humana obligatoria)              |
|  - Servicio local en Background (`NT AUTHORITY\SYSTEM` / High Integrity)         |
+-----------------------------------------------------------------------------------+
                                      ▲
                                      │ Túnel E2E (Curve25519 + ChaCha20-Poly1305)
                                      ▼
+-----------------------------------------------------------------------------------+
| ZONA DE TRANSPORTE Y ENRUTAMIENTO (hbbs / hbbr)                                   |
|  - Ciego a datos de sesión (solo ve tráfico cifrado y señalización)              |
+-----------------------------------------------------------------------------------+
                                      ▲
                                      │ HTTPS / TLS 1.3
                                      ▼
+-----------------------------------------------------------------------------------+
| ZONA AUTORITATIVA DE CONTROL PLANE (`cercano-api`)                                |
|  - Verificación de rol y revocación de instalador (`installer_id`)                |
|  - Motor de Alarmas (`AlarmEngine`) y almacén append-only (`audit-core`)          |
+-----------------------------------------------------------------------------------+
                                      ▲
                                      │ HTTPS / TLS 1.3
                                      ▼
+-----------------------------------------------------------------------------------+
| ZONA DE OPERACIÓN TÉCNICA (Consola del Técnico)                                   |
|  - Técnico autenticado en `cercano-api` con permisos (`elev:use`)                 |
|  - Diálogo de credenciales seguras (Zeroize volátil, enmascarado)                 |
+-----------------------------------------------------------------------------------+
```

---

## 3. Análisis de Escenarios de Amenaza (STRIDE / LINDDUN)

### Escenario 1: Abuso de Elevación de Privilegios en el Equipo Cliente (Opción A)

**Descripción del vector:** Durante una sesión remota, un atacante o software no confiable intenta aprovechar el canal de elevación para ejecutar código con privilegios de `SYSTEM` o Administrador local, evadir la supervisión de la persona usuaria, o extraer credenciales administrativas corporativas en tránsito o en memoria.

| Categoría | Amenaza Específica | Vector y Consecuencia | Mitigación Implementada |
|---|---|---|---|
| **S** (Spoofing) | Suplantación de respuesta de consentimiento | Inyección de mensaje falso de consentimiento simulando que la persona usuaria aceptó la elevación. | Validación criptográfica de sesión E2E. El mensaje de consentimiento solo se genera desde la ventana modal en el escritorio activo del usuario. |
| **T** (Tampering) | Modificación de comando o credenciales en tránsito | Un intermediario o proxy altera el proceso a ejecutar o la credencial. | Cifrado punto a punto autenticado (AEAD ChaCha20-Poly1305); cualquier alteración invalida la autenticación del paquete. |
| **R** (Repudiation) | Repudio de acción administrativa ejecutada | El técnico realiza una acción destructiva y niega haber solicitado la elevación. | Registro inmutable en `audit-core` con eventos encadenados `elev.requested`, `elev.submitted`, `elev.executed` vinculados por `trace_id` con actor, IP, timestamp y ticket. |
| **I** (Information Disclosure) | Fuga de contraseñas de administrador a logs o memoria | Contraseñas de dominio o local filtradas a archivos de log, consola, volcados de memoria tras cuelgues o capturas de pantalla. | 1. Tipo `SecureElevationCredential` con formato redactado `[REDACTED]` obligatorio en `Debug` y `Display`.<br>2. Borrado volátil forzado (`zeroize`) en `Drop` y tras la llamada a la API de Windows (`std::ptr::write_volatile`).<br>3. Prohibición absoluta de secretos en base de auditoría y SIEM (regla Zero Secrets verificada automáticamente en TC-F3-082). |
| **D** (Denial of Service) | Bloqueo de cuentas en Active Directory (*Account Lockout*) | Envío de contraseñas erróneas repetidas que activan la directiva de bloqueo de cuentas del dominio corporativo. | **Límite estricto e inviolable de 3 intentos fallidos consecutivos por sesión** (`MAX_FAILED_ELEVATION_ATTEMPTS = 3`). Al 3er fallo, la sesión se bloquea para elevación, se emite `elev.exhausted` y se dispara `alarm.elev_exhausted`. Protege cuentas con umbral de bloqueo típico de 5 intentos. |
| **E** (Elevation of Privilege) | Reutilización de token de elevación o ventana temporal prolongada | Un atacante local reutiliza el permiso de elevación concedido previamente. | 1. **Un solo uso estricto** (`consumed = true` inmediato tras consumir la credencial).<br>2. **Caducidad temporal estricta de 60 segundos** (`ELEVATION_CONSENT_TIMEOUT_SECS = 60`). Una segunda acción exige nueva solicitud y consentimiento explícito. |
| **LINDDUN** (Privacidad) | Identifiability / Linkability | Rastreo no autorizado de actividades de la persona usuaria o vinculación de cuentas privadas. | Los eventos de auditoría registran la cuenta objetivo elevada pero nunca contraseñas ni datos personales no vinculados al ticket de soporte. |

---

### Escenario 2: Técnico Comprometido (Atacante con Credenciales Válidas)

**Descripción del vector:** Un adversario obtiene credenciales válidas de un técnico legítimo (por phishing, reutilización de contraseña o sesión secuestrada) e intenta utilizar Cercano para pivotar a los equipos de soporte y ejecutar código malicioso.

| Categoría | Amenaza Específica | Vector y Consecuencia | Mitigación Implementada |
|---|---|---|---|
| **S** (Spoofing) | Acceso técnico no autorizado | El atacante inicia sesión haciéndose pasar por el técnico. | Exigencia obligatoria de 2FA en Fase 4 para técnicos antes del pase a producción (condición de gate F3-18). |
| **T** (Tampering) | Manipulación masiva de endpoints | El atacante envía solicitudes masivas de elevación a múltiples endpoints. | Detección reactiva de ráfagas mediante `alarm.elev_frequency` (>3 solicitudes en 10 min por técnico). |
| **R** (Repudiation) | Atribución incierta | El atacante utiliza credenciales compartidas para evadir atribución. | Auditoría forense obligatoria en `cercano-api` con `user_id`, `device_id`, IP de origen y `trace_id` unificado. |
| **I** (Information Disclosure) | Extracción de datos confidenciales | El atacante intenta acceder a archivos locales sin consentimiento. | Las operaciones de soporte siempre muestran banner visual persistente en pantalla. |
| **D** (Denial of Service) | Saturación de solicitudes de elevación | El atacante hostiga a personas usuarias con solicitudes continuas de elevación. | Disparo de `alarm.elev_rejections` tras >2 rechazos consecutivos de usuarios, bloqueando la cuenta o alertando al SOC/SIEM. |
| **E** (Elevation of Privilege) | Elevación unilateral forzada en el cliente | El atacante intenta elevar privilegios en el endpoint de forma silenciosa. | **Barrera infranqueable de consentimiento de la persona usuaria:** En Cercano Soporte, ninguna credencial es transmitida ni ejecutada sin que la persona usuaria pulse explícitamente «Aprobar» en la ventana modal local. La elevación desatendida viene desactivada por defecto y solo un administrador puede activarla en el perfil de soporte. |
| **LINDDUN** (Privacidad) | Unawareness | El usuario no comprende el impacto de la elevación solicitada. | La notificación modal de elevación exige obligatoriamente solicitante, motivo claro y hora exacta (`ElevationRequestNotification`). Solicitudes con motivos vacíos o espacios en blanco son rechazadas en origen y en la API. |

---

### Escenario 3: Instalador `tecnico` Robado (Binario o .msi/.exe Sustraído)

**Descripción del vector:** Un tercero no autorizado o un atacante físico sustrae un binario empaquetado `cercano-tecnico-*.exe` o instalador `.msi` (por ejemplo, desde un recurso compartido de red o un pendrive extraviado).

| Categoría | Amenaza Específica | Vector y Consecuencia | Mitigación Implementada |
|---|---|---|---|
| **S** (Spoofing) | Registro de instalador técnico sustraído | El atacante instala el cliente técnico en su máquina y pretende iniciar sesiones remotas hacia la flota. | **Zero Embedded Secrets:** Los instaladores no contienen claves maestras, credenciales administrativas ni tokens de acceso técnico.<br>Para iniciar conexiones salientes (`/api/sessions/initiate`) o solicitar elevación (`/api/elevation/request`), el cliente exige inicio de sesión con cuenta de usuario activa en `cercano-api` con rol `tecnico` y permisos. |
| **T** (Tampering) | Manipulación del instalador para apuntar a servidor malicioso | El atacante extrae el perfil del instalador para alterar las URLs de señalización. | El perfil embebido está firmado criptográficamente con Ed25519. Cualquier alteración de 1 solo byte hace que el cliente rechace el arranque. |
| **R** (Repudiation) | Despliegue anónimo | Uso de instaladores robados sin trazabilidad. | Cada instalador contiene un `installer_id` único registrado en los eventos de auditoría `build.*`. Se puede auditar quién solicitó la compilación, cuándo y para qué perfil. |
| **I** (Information Disclosure) | Extracción de claves privadas del instalador | Reverse engineering del instalador para extraer secretos. | Los perfiles de instalador solo contienen claves públicas del servidor (`rendezvous`, `relay`, `api`). Ninguna clave privada vive en el instalador. |
| **D** (Denial of Service) | Persistencia no deseada del instalador técnico | El binario robado permanece usable indefinidamente. | 1. **Caducidad por defecto:** Los instaladores técnicos tienen caducidad máxima de 90 días.<br>2. **Revocación inmediata:** `cercano-api` permite revocar el `installer_id` específico o revocar en masa todos los instaladores del rol `tecnico`. La revocación es verificada en memoria en < 60 segundos por hbbs y cercano-api. |
| **E** (Elevation of Privilege) | Acceso a funciones administrativas sin cuenta | El instalador robado intenta forzar capacidades avanzadas. | El servidor aplica control de acceso autoritativo (ADR-008); sin token de sesión válido de `cercano-api`, el instalador no puede realizar ninguna operación privilegiada. |

---

### Escenario 4: Escalada de Privilegios de `soporte` a `tecnico`

**Descripción del vector:** Un usuario local o atacante que posee un cliente con rol `soporte` intenta elevar sus capacidades para actuar como técnico (iniciar conexiones hacia otros puestos de trabajo, acceder a libretas de direcciones o inyectar solicitudes de elevación).

| Categoría | Amenaza Específica | Vector y Consecuencia | Mitigación Implementada |
|---|---|---|---|
| **S** (Spoofing) | Suplantación de rol en cabeceras o payloads | El cliente `soporte` envía `X-Role: tecnico`, `X-Client-Role: tecnico` o inyecta `"role": "tecnico"` en el JSON enviado a `cercano-api`. | **ADR-008 («El rol se aplica en el servidor, no solo en el instalador»):** El servidor ignora las cabeceras del cliente y consulta exclusivamente el rol registrado de forma inmutable en la base de datos (`devices.role`) asociado al `installer_id`. |
| **T** (Tampering) | Parcheo de configuración local o memoria del cliente | El atacante modifica el archivo local de perfil o parchea flags en RAM para habilitar botones de conexión saliente. | Aún si el cliente local fuese completamente modificado o parcheado, el servidor hbbs y `cercano-api` aplican enforcement autoritativo: las peticiones salientes son rechazadas con `HTTP 403 Forbidden` (`role_violation`). |
| **R** (Repudiation) | Intento de evasión de auditoría | El cliente soporte intenta operar sin que quede registro de su intento de conexión. | Todo rechazo por violación de rol genera inmediatamente un evento `auth.denied` en `audit-core` con outcome `Denied`, registrando device_id, IP y trace_id. |
| **I** (Information Disclosure) | Obtención de libreta o dispositivos corporativos | El cliente soporte intenta consultar la lista de equipos registrados. | Endpoints de libreta y dispositivos restringidos exclusivamente a cuentas con sesión de técnico activa. |
| **D** (Denial of Service) | Inundación de violaciones de rol | Envío masivo de peticiones inválidas. | El sistema registra y despacha la alarma crítica `alarm.role_violation`, notificando a los administradores e integradores SIEM. |
| **E** (Elevation of Privilege) | Ejecución de funciones de técnico desde puesto cliente | Un atacante usa una estación comprometida de soporte para invadir la LAN corporativa. | Demostrado en TC-F3-060, TC-F3-062 y TC-F3-063: Un cliente soporte nunca puede iniciar sesiones ni solicitar elevación; las pruebas automatizadas bloquean el vector al 100%. |

---

## 4. Matriz de Clasificación de Riesgos y Evaluación DREAD

| Amenaza | Probabilidad | Impacto | DREAD Score | Nivel de Riesgo Inherente | Mitigaciones Implementadas | Nivel de Riesgo Residual |
|---|---|---|---|---|---|---|
| **A-01:** Abuso de elevación local en endpoint cliente | Media | Alta | 6.8 (Medio) | **Medio** | Consentimiento un solo uso, caducidad 60s, canal E2E, zeroize volátil, Zero Secrets. | **Bajo** |
| **A-02:** Bloqueo de cuentas en Active Directory por fuerza bruta | Media | Alta | 7.0 (Alto) | **Alto** | Límite estricto de 3 intentos fallidos consecutivos por sesión antes de bloqueo. | **Bajo** |
| **A-03:** Fuga de contraseñas de admin en logs/disco/auditoría | Media | Crítica | 8.2 (Alto) | **Alto** | Cero persistencia, [REDACTED] en formateadores, tests automáticos de Zero Secrets. | **Bajo** |
| **A-04:** Técnico comprometido que eleva silenciosamente | Baja | Crítica | 8.0 (Alto) | **Alto** | Consentimiento explícito de usuario obligatorio en cliente; alarmas `elev_frequency` y `elev_after_hours`; 2FA obligatoria en Fase 4. | **Bajo (con 2FA)** |
| **A-05:** Sustracción física o filtración de instalador `tecnico` | Media | Media | 6.2 (Medio) | **Medio** | Zero Embedded Secrets; requiere cuenta y sesión activa en API; caducidad 90 días; revocación inmediata. | **Bajo** |
| **A-06:** Escalada de instalador `soporte` a `tecnico` por tampering | Alta | Crítica | 8.6 (Crítico) | **Crítico** | ADR-008: Verificación autoritativa de rol en servidor, inmutabilidad en BD, alarma crítica `alarm.role_violation`. | **Bajo** |
| **A-07:** Frecuencia abusiva o elevación fuera de horario | Media | Media | 5.8 (Medio) | **Medio** | Alarmas reactivas automáticas `alarm.elev_frequency` y `alarm.elev_after_hours`. | **Bajo** |

---

## 5. Evaluación de Hallazgos de Seguridad

### Hallazgos Críticos y Altos
- **Estado:** **0 Abiertos (Ninguno).**
- Todos los vectores de severidad Crítica y Alta identificados han sido completamente mitigados mediante decisiones de arquitectura (ADR-008, ADR-009) y verificados con pruebas automatizadas (TC-F3-060..064, TC-F3-070..079, TC-F3-080..087).

### Hallazgos Medios y Bajos (con Plan de Mitigación Explícito)

1. **H-MED-01: Ausencia de 2FA nativa en cuentas de técnico en Fase 3.**
   - *Riesgo:* Si las credenciales de un técnico son robadas en Fase 3, un atacante podría autenticarse en la consola técnica si la elevación estuviese habilitada.
   - *Plan de Mitigación:* Condición de activación en producción: **La elevación se entrega estrictamente desactivada por defecto (`enable_elevation: false`)** en todos los perfiles generados. Se establece como gate no negociable que la elevación solo podrá ser activada en producción cuando la autenticación multifactor (2FA) sea completada y requerida para todos los técnicos en la **Fase 4**.

2. **H-MED-02: Dependencia del Secure Desktop de Windows frente a procesos con privilegios SYSTEM.**
   - *Riesgo:* En endpoints con malware preexistente que ya posea privilegios `NT AUTHORITY\SYSTEM`, las APIs de Windows podrían verse intervenidas (API hooking local).
   - *Plan de Mitigación:* Principio de mínimo privilegio y defensa en profundidad: la elevación de Cercano no sustituye la seguridad del endpoint (EDR/Antivirus); el servicio valida la integridad y origen de las peticiones locales. Integración futura con Windows LAPS (Fase 5) para eliminar por completo la necesidad de credenciales administrativas ingresadas manualmente.

3. **H-LOW-01: Posible confusión visual si un atacante usa nombres engañosos en el motivo.**
   - *Riesgo:* Ingeniería social mediante textos convincentes en el campo `reason` (ej. "Actualización crítica de seguridad Windows").
   - *Plan de Mitigación:* El diálogo modal muestra de forma prominente el nombre del técnico verificado en el servidor, la hora RFC3339 y el ticket de soporte. En Fase 4.5/F4 se incorporará la foto o identidad corporativa verificada del técnico.

---

## 6. Condición de Activación en Producción

Conforme a `PLAN-F3-GENERADOR.md` (§3, §6) y ADR-009:
- **Estado de entrega en Fase 3:** La funcionalidad de elevación se entrega **desactivada por defecto** (`enable_elevation = false`) y solo es utilizable en el entorno controlado de laboratorio LAN.
- **Requisitos obligatorios para activación en producción (Gate F4):**
  1. Disponibilidad y obligatoriedad de 2FA para el rol técnico (`cercano-api` en Fase 4).
  2. Aprobación formal de esta revisión de seguridad F3-18 sin hallazgos altos abiertos.
  3. Firma Authenticode en producción de los binarios del cliente y del instalador con sello de tiempo oficial.
