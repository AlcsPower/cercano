# Cercano — Roadmap

**Versión:** 0.6 · **Fecha:** 2026-11-10 · **Coordinador:** Claude · **Dueño del producto:** AlcsPower
**Repositorio:** `AlcsPower/cercano` · **Licencia prevista:** AGPL-3.0 (heredada de upstream; ver §8 sobre el archivo `LICENSE`)

---

## 1. Visión

Cercano es una plataforma de soporte remoto para equipos de TI, derivada de RustDesk (cliente y servidor), con tres diferenciadores:

1. **Auditable:** cada sesión, transferencia, intento fallido y acción administrativa deja un registro verificable e inalterable (cadena de hashes) con trazabilidad extremo a extremo.
2. **Seguro por defecto:** consentimiento, control de acceso, 2FA, instaladores firmados, sin persistencia oculta.
3. **LAN-first:** conexión directa y relay local optimizados para redes internas, sin depender de internet.

Objetivo funcional: ofrecer en código abierto lo que RustDesk reserva a **Server Pro**, en particular **auditoría/traza** y **generador de instaladores personalizados**.

## 2. Principios de ingeniería

- **Diff mínimo contra upstream.** Todo cambio al código heredado va como parche pequeño, etiquetado y documentado (ver `AGENTS.md`). El código nuevo vive en componentes propios.
- **Clean-room para funciones Pro.** Se implementa a partir del comportamiento público documentado. Prohibido usar binarios, código filtrado o descompilación de Server Pro (ver `ARQUITECTURA.md` §7).
- **Todo es verificable:** cada tarea tiene criterios de aceptación y pruebas; ninguna fase cierra sin pasar su *gate*.
- **Planificación en olas:** F0–F3 están detalladas; F4–F7 se detallan al cerrar la fase anterior, con lo aprendido.

## 3. Mapa de paridad con Server Pro

Referencia: documentación pública y página de precios de RustDesk (nov. 2026).

| Función en Server Pro | Estado en Cercano | Fase |
|---|---|---|
| API de servidor (control plane) | Nuevo: `cercano-api` | F1 |
| Registro de dispositivos (heartbeat/sysinfo) | Nuevo | F1 |
| Logs de conexión (RD, archivos, puerto, cámara, terminal, fallos de login) | Nuevo + hash chain | F2 |
| Logs de transferencia de archivos | Nuevo | F2 |
| Alarmas (whitelist IP, ráfagas de intentos, terminal, alcance de sesión) | Nuevo | F2 |
| Logs de operaciones de consola | Nuevo | F2 |
| Nota de sesión del lado controlador | Nuevo | F2 |
| **Generador de clientes personalizados** | ✅ Implementado: `cercano-build` (.exe/.msi, Authenticode, SBOM, ADR-008) | F3 |
| Consola web | Nuevo: `console-web` | F4 |
| 2FA, roles de admin y de control | Nuevo | F4 |
| Libreta de direcciones | Nuevo | F5 |
| Estrategias (ajustes centralizados) | Nuevo | F5 |
| Control de acceso, acceso entre grupos | Nuevo | F5 |
| OIDC (SSO) y LDAP | Nuevo | F5 |
| Cambio de ID de dispositivo | Evaluar | F5 |
| Múltiples relays, selección del más cercano | Nuevo / extensión de hbbr | F6 |
| Soporte WebSocket | Evaluar | F6 |
| Cliente web integrado | **Fuera de alcance v1** | — |
| **Cercano Chat** (chat de soporte con el técnico) | Nuevo: `cercano-api` + cliente + `console-web` | F4.5 |
| Respaldo, restauración y verificación desde la consola | Nuevo: `cercano-api` + `console-web` | F8 |
| Migración asistida de motor (PostgreSQL, SQL Server) | Nuevo | F8 |

**Extras sobre Pro (diferenciadores):** cadena de hashes con checkpoints firmados, verificador offline (`cercano-audit verify`), `trace_id` extremo a extremo, exportación a SIEM (syslog/CEF/JSONL/webhook), auditoría de la propia generación de instaladores, revocación de instaladores, **dos tipos de instalador (soporte y técnico) con el rol aplicado también en el servidor**, **elevación con credenciales de administrador de Windows**, con consentimiento de la persona usuaria y auditoría completa (su activación en producción queda condicionada a la 2FA de F4), y **Cercano Chat** para resolver problemas pequeños sin sesión remota, con nombre natural del contacto, adjuntos, notificaciones y escalado auditado a la sesión remota; y **respaldo, restauración y migración de motor gestionados desde la consola**, con PostgreSQL y SQL Server (F8).

## 4. Fases e hitos

Duraciones orientativas, a ajustar tras F0 (suponen 3–5 agentes en paralelo).

| Fase | Nombre | Duración est. | Hito de salida |
|---|---|---|---|
| **F0** | Fundación y spikes técnicos | 1–2 sem | Repo con gobernanza, CI, laboratorio LAN y 5 spikes que validan o refutan las hipótesis H1–H5 |
| **F1** | Núcleo: servidor + control plane + cliente rebrandeado | 3–4 sem | **M0:** dos equipos en LAN se conectan (directo y por relay) usando binarios de Cercano, registrados en `cercano-api` |
| **F2** | Auditoría y traza | 3–4 sem | **M1:** toda sesión genera eventos encadenados, consultables y verificables por API y CLI |
| **F3** | Generador de instaladores | 4–5 sem | **M2 (reabierto 2026-11-16, B-002):** desde un perfil JSON se obtiene un instalador Windows firmado, preconfigurado y revocable, en dos tipos: soporte (solo recibe) y técnico (funciones avanzadas, con elevación con credenciales desactivada por defecto) |
| **F4** | Consola web, RBAC y 2FA | 4 sem | **M3:** administración completa (usuarios, dispositivos, auditoría, generador) desde navegador |
| **F4.5** | Cercano Chat (complemento) | 2–3 sem | **M3.5:** una persona con Cercano Soporte resuelve un problema pequeño por chat con un técnico, con adjuntos, notificaciones y escalado auditado |
| **F5** | Identidad y control de acceso | 4–5 sem | Libreta, estrategias, OIDC/LDAP, acceso entre grupos |
| **F6** | Optimización LAN y relays | 3 sem | Descubrimiento LAN, multi-relay, pruebas con pérdida/latencia |
| **F7** | Endurecimiento y release | 3 sem | **M4:** beta pública: pentest interno, SBOM, firma, documentación, guía de migración |
| **F8** | Portabilidad y respaldos gestionados (extra post-v1) | 4–6 sem | **M5:** un administrador crea, verifica y restaura respaldos y migra el control plane de SQLite a PostgreSQL (y a SQL Server si el spike lo valida) desde la consola, sin pérdida de datos y con auditoría completa |

Total estimado: 27–35 semanas (F3 pasa de 3 a 4–5 por los roles de instalador y la elevación con credenciales; F4.5 añade 2–3). **F8 añade 4–6 semanas después de v1 y no bloquea M4.**

## 5. Criterios de salida (gates)

Una fase cierra solo si se cumple todo:

- 100 % de tareas en estado `Hecho` o explícitamente diferidas con justificación.
- Suite de pruebas de la fase en verde en CI y en el laboratorio LAN (ver `PLAN-DE-PRUEBAS.md`).
- Sin hallazgos de seguridad críticos o altos abiertos.
- Documentación de usuario/operador actualizada.
- Informe de cierre de fase del Coordinador en `docs/status/`.

## 6. Riesgos principales

| ID | Riesgo | Prob. | Impacto | Mitigación |
|---|---|---|---|---|
| R1 | El cliente OSS no expone todos los hooks de auditoría que necesitamos | Media | Alto | Spike S3 en F0; parches mínimos al cliente en F2-05 |
| R2 | Deriva respecto a upstream encarece las actualizaciones | Alta | Medio | Parches pequeños y etiquetados; rebase trimestral; `docs/upstream-sync.md` |
| R3 | Problemas de licencia o marca | Baja | Alto | AGPL-3.0 en todo; clean-room; no usar nombre ni logo de RustDesk en distribuibles |
| R4 | Antivirus/SmartScreen marcan los instaladores | Alta | Medio | Firma Authenticode, reputación, guía de excepciones para TI |
| R5 | Cercano es un objetivo atractivo (acceso remoto) | Media | Alto | Modelo de amenazas, revisión de seguridad por fase, 2FA, mínimos privilegios |
| R6 | Compilación del cliente (Flutter + vcpkg) lenta y frágil | Alta | Medio | Spike S2, caché de CI, runners dedicados |
| R7 | Alcance excesivo | Media | Medio | Paridad por fases; cliente web fuera de v1 |
| R8 | La elevación con credenciales de administrador amplía el daño de un técnico o un instalador `tecnico` comprometido | Media | Alto | Consentimiento por solicitud, sin persistencia, un solo uso, auditoría `elev.*`, desactivada por defecto hasta tener 2FA (F4), revisión F3-18 |
| R9 | Cercano Chat expone conversaciones o adjuntos, o se usa para abuso | Media | Alto | TLS obligatorio, identidad por dispositivo con clave fijada, permisos, límites de tasa, retención, auditoría sin contenido y antivirus como extensión (F4.5) |
| R10 | Deriva entre motores de base de datos (SQL distinto por dialecto) | Media | Alto | Fingerprint de esquema por motor en CI; matriz de pruebas con los motores soportados en cada PR que toque SQL (F8-03, F8-09) |
| R11 | Restauración o migración destructiva con pérdida de datos | Baja | Crítico | Snapshot firmado previo obligatorio, verificación antes del corte, origen intacto como rollback, confirmación tipada y reautenticación (F8-06, F8-07) |
| R12 | SQL Server queda fuera de F8: `sqlx 0.8` no tiene driver MSSQL (retirado en la 0.7) | Baja | Bajo | Cerrado en F8-01: SQL Server diferido, PostgreSQL no se ve afectado; si se retoma, capa `tiberius` con spike y decisión aparte |

## 7. Decisiones pendientes del dueño

El equipo arranca con los valores por defecto indicados; si cambia alguno, avisar al Coordinador.

| ID | Decisión | Valor por defecto asumido |
|---|---|---|
| D1 | Nombre comercial y marca definitivos | «Cercano»; logo provisional en `branding/` (pendiente: contraste del cursor, ver `branding/README.md` §2) |
| D2 | Plataforma prioritaria del instalador | Windows primero; Linux y macOS después |
| D3 | Base de datos | SQLite por defecto (despliegues pequeños/LAN); PostgreSQL soportado como motor alternativo con migración asistida desde la consola (F8); SQL Server **diferido** en F8-01 (no hay driver MSSQL en `sqlx 0.8`) |
| D4 | Certificado de firma de código (Authenticode) | **Sin definir:** hasta tenerlo, los instaladores se firman con certificado de pruebas |
| D5 | Acceso de los agentes al repositorio `AlcsPower/cercano` | **Resuelto** el 2026-11-05 |
| D6 | Versión base de upstream | Última etiqueta estable de ambos repos en la fecha de F0-02 |
| D7 | Texto de licencia | **Resuelto** el 2026-11-05: `LICENSE` contiene el texto oficial de AGPL-3.0 |
| D8 | Origen de las credenciales de administrador para la elevación (ver `PLAN-F3-GENERADOR.md` §3) | Tecleo manual del técnico en cada solicitud, sin almacenar nada; Windows LAPS en F5; bóveda propia descartada |
| D9 | Alcance y ubicación de Cercano Chat | **Resuelto 2026-11-09:** chat embebido en el cliente Cercano, gestión en `console-web`, adjuntos (imágenes/PDF), notificaciones y escalado remoto; fase F4.5 después de F4. Nombre y Apellido del contacto se piden la primera vez, se guardan localmente y como snapshot en la conversación. |
| D10 | Motores de base de datos de F8 | PostgreSQL obligatorio; SQL Server **diferido** en F8-01: `sqlx 0.8`/`0.9` no tienen driver MSSQL y no hay nada que validar; retomarlo exige una capa `tiberius` con decisión y spike propios (guía de arranque en `adr/011-portabilidad-bd.md` §7). SQLite sigue siendo el motor de instalación por defecto |
| D11 | Destino y retención de respaldos | `./data/backups`, 30 copias / 30 días; copia fuera del equipo cifrada por el operador; las claves se respaldan por el procedimiento aparte (`docs/guias/rotacion-claves.md`) |

## 8. Estado actual

- **Repositorio:** `AlcsPower/cercano` (privado) accesible para los agentes desde el 2026-11-05. Se trabaja en la rama `docs/F0-01-gobernanza`, no en `main`. `status/TAREAS.md` da F0 y F1 por `Hecho`.
- **Por reconciliar (2026-11-06):** F0-05 a F0-08 y F0-10 figuran como `Hecho`, pero no hay informe en `status/informes/` ni documento en `docs/spikes/` (solo existe S1), y `docs/adr/` está vacío. F3 depende del veredicto de S4 (H4); hasta verlo, el diseño de F3 sigue siendo una propuesta.
- **Licencia:** el repositorio se distribuye bajo **AGPL-3.0** (verificado con `tools/check-license.sh`). Bloqueo B-001 resuelto.
- **Marca:** logo, iconos y guía de uso en `branding/`.
- **Cercano Chat (F4.5):** diseño, contrato y planificación en `PLAN-F4.5-CHAT.md`, `specs/chat.md` y `adr/010-cercano-chat.md`; la implementación queda encolada después de cerrar F4.
- **F4:** plan detallado en `PLAN-F4-CONSOLA.md`; RBAC y 2FA pueden ir en paralelo con F3; solo el generador (F4-07) espera F3-07.
- **F8 (extra post-v1):** plan en `PLAN-F8-PORTABILIDAD.md`, decisión en `adr/011-portabilidad-bd.md`, contrato en `specs/db-portabilidad.md` y operación en `guias/respaldos-y-migracion.md`, por petición del dueño (2026-11-10): respaldos gestionados y migración asistida a PostgreSQL desde la consola. Se detalla antes de tiempo respecto a la regla de olas de §2; no bloquea M4. **F8-01 (2026-11-10):** inventario de las 142 sentencias y SQL Server diferido porque `sqlx 0.8` no tiene driver MSSQL (ver `status/informes/F8-01.md`).
- **Documentos relacionados:** `ARQUITECTURA.md`, `../AGENTS.md`, `PLAN-F0-F1.md`, `PLAN-F2-AUDITORIA.md`, `PLAN-F3-GENERADOR.md`, `PLAN-F4-CONSOLA.md`, `PLAN-F4.5-CHAT.md`, `PLAN-F8-PORTABILIDAD.md`, `adr/011-portabilidad-bd.md`, `specs/db-portabilidad.md`, `guias/respaldos-y-migracion.md`, `PLAN-DE-PRUEBAS.md`, `status/TAREAS.md`, `status/BLOCKERS.md`.
