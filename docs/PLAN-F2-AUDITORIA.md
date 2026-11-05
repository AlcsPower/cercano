# Plan de trabajo — F2: Auditoría y traza

**Versión:** 0.2 · **Fecha:** 2026-11-05 · Depende de: cierre de F1 (M0) y resultados de S3/S5.

**Objetivo (M1):** toda sesión, transferencia, intento fallido y acción administrativa genera eventos encadenados, consultables por API y verificables offline.

**Especificación de referencia:** `ARQUITECTURA.md` §4 (esquema, integridad, cobertura mínima). Este plan se ajustará con lo que S3 haya revelado sobre los hooks del cliente.

| ID | Tarea | Dep. | Rol | Verifica |
|---|---|---|---|---|
| F2-01 | Especificación del esquema de eventos | F1 cerrado | ControlPlane | Seguridad |
| F2-02 | Núcleo `audit-core`: almacén append-only y cadena de hashes | F2-01 | ControlPlane | QA |
| F2-03 | Checkpoints firmados y `cercano-audit verify` | F2-02 | ControlPlane | Seguridad |
| F2-04 | Endpoints de ingestión (conexión, archivo, alarma) | F2-02, F0-06 | ControlPlane | QA |
| F2-05 | Parches al cliente para hooks faltantes | F2-04 | Cliente | QA |
| F2-06 | Correlación y `trace_id` | F2-04, F0-08 | Servidor + Cliente | QA |
| F2-07 | Motor de alarmas | F2-04 | ControlPlane | QA |
| F2-08 | Auditoría de la API y la consola | F2-02, F1-04 | ControlPlane | QA |
| F2-09 | API de consulta y exportación | F2-04, F2-08 | ControlPlane | QA |
| F2-10 | Exportadores SIEM | F2-02 | ControlPlane | QA |
| F2-11 | Retención y archivado | F2-02 | ControlPlane | Seguridad |
| F2-12 | Nota de sesión | F2-04, F2-05 | Cliente + ControlPlane | QA |
| F2-13 | Pruebas de manipulación, carga y reloj | F2-03…11 | QA + Seguridad | Coordinador |
| F2-14 | Guía de auditoría y cierre | F2-13 | Coordinador | Dueño |
| F2-15 *(opcional)* | Grabación de sesión vinculada a eventos | F2-05 | Cliente + ControlPlane | Seguridad |

### Detalle

**F2-01 Especificación del esquema de eventos.**
JSON Schema versionado en `docs/specs/audit-events.schema.json` y documento explicativo con una entrada por `action` (campos obligatorios, ejemplos, qué componente la emite). Reglas de canonicalización JSON (orden de claves, codificación de números y fechas) para el cálculo del hash.
*CA:* esquema valida los ejemplos; revisión de Seguridad confirma que no se registran secretos (contraseñas, tokens, contenido de archivos).

**F2-02 `audit-core`.**
Crate con: modelo de evento, canonicalización, cálculo de hash encadenado, almacenamiento append-only (tabla sin `UPDATE`/`DELETE` permitidos por la capa de acceso, con triggers de defensa en BD), escritura serializada para garantizar orden, y API interna `append(event)`.
*CA:* cadena válida tras 100 000 eventos; cualquier alteración o borrado de una fila se detecta en la verificación (TC-F2-001…004); `append` es seguro bajo concurrencia.

**F2-03 Checkpoints y verificador.**
Checkpoint firmado con Ed25519 cada N eventos o T minutos (configurable); clave de firma separada de la BD y rotable (registro de la rotación en la propia cadena). CLI `cercano-audit verify` que valida cadena y firmas leyendo un volcado exportado, sin servidor.
*CA:* la verificación detecta eventos alterados, eliminados, reordenados o truncados; funciona offline; la rotación de clave deja evidencia verificable.

**F2-04 Endpoints de ingestión.**
Endpoints compatibles con lo que S3 descubrió para eventos de conexión, archivo y alarma; validación estricta, autenticación del origen, idempotencia (reintentos del cliente no duplican), conversión al esquema común y `append`. Los eventos del servidor (hbbs/hbbr) entran por un canal interno autenticado.
*CA:* eventos reales del cliente quedan registrados; reintentos y payloads inválidos tienen comportamiento definido (TC-F2-010…015).

**F2-05 Parches al cliente.**
Solo si S3 marcó carencias: emitir eventos de inicio y fin de sesión, tipo de sesión (escritorio, archivos, puerto, cámara, terminal), método de autenticación, resultado de 2FA, fallos de login, transferencias (dirección, ruta, tamaño/cantidad) y copiar/pegar de archivos. Parches pequeños, registrados, con *feature flag*.
*CA:* cada tipo de sesión de `ARQUITECTURA.md` §4 genera su evento esperado en el laboratorio.

**F2-06 Correlación y `trace_id`.**
Según el veredicto de S5: propagar `trace_id` desde el cliente controlador; si no es posible, correlacionar por (ID controlador, ID controlado, ventana de tiempo) con regla determinista y documentada.
*CA:* dado un `trace_id`, la API devuelve el conjunto completo de eventos de una sesión (cliente, rendezvous, relay si lo hubo, API).

**F2-07 Motor de alarmas.**
Reglas configurables: acceso fuera de lista blanca de IP; más de 30 intentos consecutivos; múltiples intentos en un minuto; ráfagas desde un prefijo IPv6; fallos o simultaneidad de logins de Terminal con privilegios; violación del alcance de sesión; en cuentas, intentos masivos por minuto/hora. Cada alarma genera un evento `alarm.*` y notifica por los exportadores.
*CA:* cada regla se dispara en una prueba controlada y no se dispara con tráfico legítimo (TC-F2-020…028); umbrales configurables.

**F2-08 Auditoría de API y consola.**
Todo cambio administrativo genera evento `console.*` o `auth.*`: login/logout, usuarios, grupos, dispositivos, desconexión forzada, libreta, roles, 2FA, restablecimiento de contraseñas.
*CA:* matriz «acción administrativa → evento» con 100 % de cobertura sobre los endpoints existentes; verificación automática que falla si un endpoint de escritura no audita.

**F2-09 API de consulta y exportación.**
Filtros por categoría, acción, actor, sujeto, `trace_id`, rango de fechas y resultado; paginación por cursor; exportación CSV y JSONL; endpoint para obtener el último checkpoint y la prueba de integridad de un rango. Permisos: rol de auditor de solo lectura.
*CA:* consultas con 1 M de eventos responden en tiempo razonable (objetivo propuesto: p95 < 500 ms con filtros indexados); un auditor no puede modificar nada.

**F2-10 Exportadores SIEM.**
Syslog (RFC 5424) sobre UDP/TCP/TLS, CEF, JSONL rotatorio en disco y webhook con firma HMAC. Cola con reintentos y sin pérdida si el destino cae.
*CA:* eventos llegan a un receptor de prueba en cada formato; una caída de 10 minutos del receptor no pierde eventos.

**F2-11 Retención y archivado.**
Política por categoría (p. ej. conexión 1 año, consola 3 años), archivado a ficheros firmados y comprimidos que conservan la verificación de la cadena, y purga controlada que deja un evento `audit.purge` y un nuevo punto de partida verificable.
*CA:* tras purgar, `verify` sigue pasando sobre archivo + cadena viva.

**F2-12 Nota de sesión.**
El lado controlador puede añadir una nota libre durante o después de la sesión; se almacena como evento vinculado al `trace_id` (no modifica el original).
*CA:* la nota aparece asociada a la sesión y queda encadenada.

**F2-13 Pruebas de manipulación, carga y reloj.**
Intentos de alteración directa de la BD, borrado, reordenación; carga sostenida (objetivo propuesto: 500 eventos/s en hardware modesto); desfase de reloj entre cliente y servidor (el servidor añade su propia marca de tiempo y registra la discrepancia); caída del proceso durante `append`.
*CA:* ver casos TC-F2-030…045; ninguna manipulación pasa la verificación; la carga objetivo se sostiene sin pérdida.

**F2-14 Guía de auditoría y cierre.**
Guía para auditores y operadores (cómo consultar, verificar, exportar y conservar evidencias) e informe `docs/status/F2-cierre.md`.

**F2-15 (opcional) Grabación de sesión.**
Si el cliente permite grabación, subida cifrada al servidor, almacenamiento cifrado en reposo, enlace desde el evento de sesión y política de retención.
*CA:* se decide al cerrar F2-13 según esfuerzo y hallazgos de S3; si se difiere, queda en el backlog de F5.

**Gate F2 (M1):** las pruebas TC-F2-* en verde; matriz de cobertura de eventos al 100 % para lo definido en `ARQUITECTURA.md` §4; revisión de seguridad sin hallazgos altos; guía validada por un agente externo a la tarea.
