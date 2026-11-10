# Plan de trabajo — F6: Optimización LAN y relays

**Versión:** 0.2 · **Fecha:** 2026-11-10 · **Estado:** revisado por el Coordinador el 2026-11-10; pendiente de aprobación del dueño · **Duración estimada:** 3 semanas  
**Objetivo:** mejorar la selección y resiliencia de rutas en redes corporativas/LAN mediante descubrimiento controlado, varios relays y evaluación de WebSocket, sin sacrificar consentimiento, cifrado, roles ni trazabilidad.  
**Depende de:** M0 (conexión directa y relay), F2 (auditoría/`trace_id`), F3 (roles/revocación) y entorno reproducible de `tests/lab/`. F6-01…F6-05 pueden ir en paralelo con F5; F6-06 y el cierre de F6 esperan la política efectiva de F5 (F5-05).  
**Referencias:** `docs/ROADMAP.md`, `docs/ARQUITECTURA.md`, `docs/PLAN-DE-PRUEBAS.md`, `docs/PLAN-F0-F1.md`, `docs/PLAN-F3-GENERADOR.md` y `patches/INDEX.md`.

## 1. Alcance y principios

- Descubrimiento LAN opt-in y acotado a interfaces/redes permitidas por el administrador; no escanear redes externas ni anunciar información sensible.
- Configurar múltiples relays y seleccionar una ruta por salud/latencia, con reglas deterministas, telemetría mínima y decisión auditable.
- Mantener conexión directa como preferencia cuando sea viable y permitida; el relay no puede descifrar el contenido de extremo a extremo.
- Reintentos y cambio de ruta no deben duplicar sesiones o eventos; conservar `trace_id` y registrar ruta/resultado sin payloads ni credenciales.
- WebSocket es una evaluación: implementar solo si existe necesidad comprobada y se documentan autenticación, proxy, límites y degradación. No se añade por paridad nominal.
- No se cambia el protocolo upstream de forma incompatible sin spike, parche pequeño y pruebas de interoperabilidad.

## 2. Tareas

| ID | Tarea | Dep. | Rol | Verifica |
|---|---|---|---|---|
| F6-01 | Spike de topologías, descubrimiento y transporte; fijar métricas, amenazas y compatibilidad | F1-09, F2-06, F3-13 | Servidor + Seguridad | QA/Coordinador |
| F6-02 | Configuración versionada de sitios LAN, rangos/interfaces autorizados y nodos relay | F6-01 | ControlPlane | Seguridad |
| F6-03 | Descubrimiento LAN limitado, autenticado cuando corresponda y con interruptor administrativo | F6-01/02 | Servidor + Cliente | Seguridad/QA |
| F6-04 | Registro de salud de relays, heartbeats, capacidad y retiro seguro de nodos | F6-02 | Servidor | QA |
| F6-05 | Selector multi-relay: elegibilidad, puntuación de latencia/salud, desempate y fallback | F6-04 | Servidor | QA |
| F6-06 | Integración de cliente: obtener opciones, conectar/reintentar y conservar política/`trace_id` | F6-05, F3-13, F5-05 | Cliente | Seguridad/QA |
| F6-07 | Evaluar WebSocket; implementar solo con ADR aprobado y criterio de necesidad medible | F6-01 | Servidor + Cliente | Seguridad |
| F6-08 | Telemetría operativa y auditoría de rutas; métricas agregadas y sin datos identificables innecesarios | F6-03…07, F2 | ControlPlane + Servidor | Seguridad |
| F6-09 | Pruebas de rendimiento, resiliencia, red y compatibilidad en laboratorio | F6-03…08 | QA | Coordinador |
| F6-10 | Guía de operación de LAN/relay y cierre F6 | F6-09 | Coordinador | Dueño |

## 3. Criterios de aceptación

- **F6-01:** informe reproducible compara ruta directa, relay único/múltiple y WebSocket si aplica, con latencia, jitter, pérdida, consumo, amenazas y compatibilidad con clientes. Umbrales de selección y objetivos de rendimiento se acuerdan antes de medir.
- **F6-02:** configuración validada y versionada; no acepta hosts/rangos fuera de la política; el operador puede retirar un relay sin reiniciar todo el servicio; cambios quedan auditados. F6-01 define cómo se autentica un relay ante hbbs y el cliente (clave o identidad fijada por el administrador) y F6-02 lo implementa: un relay no registrado no se selecciona. Las tablas nuevas usan DDL portable (sin `datetime('now')`, `strftime` ni `AUTOINCREMENT`) porque F8 portará el esquema.
- **F6-03:** el descubrimiento está desactivado o limitado por política, interfaz y rango explícitos; no propaga credenciales, claves privadas ni listas globales de equipos; no amplía el alcance de acceso; un anuncio descubierto nunca otorga confianza: solo sirve para intentar la conexión normal, que valida claves, consentimiento y rol; mecanismo de apagado probado.
- **F6-04/05:** nodos no saludables o revocados no se seleccionan; la selección es estable ante mediciones equivalentes; se respeta preferencia de conexión directa y las restricciones por sitio; al no haber relay válido, se informa fallo seguro en vez de seleccionar uno arbitrario.
- **F6-06:** cambio de ruta no reinicia consentimiento ni privilegios; revocación y rol del instalador se vuelven a comprobar; el `trace_id` correlaciona intentos y ruta efectiva; reintentos no producen duplicados de sesión/auditoría.
- **F6-07:** decisión ADR documenta evidencia a favor/en contra, requisitos de proxy/TLS, autenticación, límites y modo fallback. Si se implementa, WebSocket conserva autorización y cifrado, no crea una vía de bypass de controles y tiene pruebas de proxy y corte.
- **F6-08:** métricas de disponibilidad/latencia/capacidad no incluyen contenido, tokens ni claves; eventos distinguen ruta propuesta, elegida y resultado, con retención alineada a auditoría.
- **F6-09/10:** resultados comparados con baseline F5; regresiones mayores al 20 % explicadas y aprobadas según `PLAN-DE-PRUEBAS.md`; informe `docs/status/F6-cierre.md` y guía probada desde cero.

## 4. Pruebas

Crear `tests/cases/TC-F6-*.md` y añadirlos al catálogo `docs/PLAN-DE-PRUEBAS.md` en F6-01. Ejecutar solo en el laboratorio LAN propio.

| Grupo | Escenarios mínimos |
|---|---|
| Descubrimiento | Desactivado, rango permitido, interfaz no permitida, anuncio falsificado, duplicados y apagado de emergencia |
| Multi-relay | Dos o más relays, distintos RTT, capacidad agotada, relay caído/revocado y empate determinista |
| Resiliencia | Pérdida, jitter, latencia, corte, UDP bloqueado, reconexión y degradación a ruta disponible |
| Seguridad | Autorización, rol `soporte`/`tecnico`, consentimiento conservado, no selección de relay revocado, sin secretos en trazas |
| Trazabilidad | Un `trace_id` para intento/ruta/sesión; eventos no duplicados y cadena válida |
| Interoperabilidad | Versiones soportadas del cliente/servidor y compatibilidad directa/relay; pruebas de regresión de parches |
| WebSocket | Si aprobado: proxy inverso, timeout, cierre, autenticación, límites y fallback; si diferido, evidencia y decisión ADR |
| Rendimiento | Comparación de p50/p95 y CPU/memoria con baseline; carga sostenida y recuperación |

**Gate F6:** 100 % tareas cerradas o diferidas justificadamente; suite en CI y laboratorio; sin hallazgos críticos/altos; `cercano-audit verify` correcto; guía operativa y evidencia de métricas entregadas. El descubrimiento y WebSocket no se activan por defecto sin aprobación de política.

## 5. Riesgos y decisiones

| Riesgo | Mitigación |
|---|---|
| Descubrimiento filtra inventario o amplía la superficie | Opt-in, alcance de red explícito, mínimos datos y límites de frecuencia |
| Selección dirige tráfico a relay hostil/no autorizado | Lista de nodos administrada, autenticación, claves fijadas, revocación y contenido E2E cifrado |
| Cambio de ruta altera consentimiento o control | Permisos/consentimiento ligados a sesión y revalidación servidor |
| Mediciones fluctúan y causan oscilación | Histéresis, ventanas, desempate estable y límites de cambio |
| WebSocket aumenta exposición o se vuelve fallback inseguro | ADR con evidencia y revisión de seguridad; opción de diferir |
| Diferencias de protocolo upstream | Spike temprano, cambios aislados y registro en `patches/INDEX.md` |

## 6. Fuera de alcance

Cliente web integrado, red mesh autónoma, relay público de Cercano, descubrimiento fuera de LAN autorizada, selección basada en geolocalización y cambios de protocolo que rompan compatibilidad sin aprobación. WebSocket no se considera entrega comprometida hasta aprobar F6-07.
