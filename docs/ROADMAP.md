# Cercano — Roadmap

**Versión:** 0.2 · **Fecha:** 2026-11-05 · **Coordinador:** Claude · **Dueño del producto:** AlcsPower
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
| **Generador de clientes personalizados** | Nuevo: `cercano-builder` | F3 |
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

**Extras sobre Pro (diferenciadores):** cadena de hashes con checkpoints firmados, verificador offline (`cercano-audit verify`), `trace_id` extremo a extremo, exportación a SIEM (syslog/CEF/JSONL/webhook), auditoría de la propia generación de instaladores, revocación de instaladores.

## 4. Fases e hitos

Duraciones orientativas, a ajustar tras F0 (suponen 3–5 agentes en paralelo).

| Fase | Nombre | Duración est. | Hito de salida |
|---|---|---|---|
| **F0** | Fundación y spikes técnicos | 1–2 sem | Repo con gobernanza, CI, laboratorio LAN y 5 spikes que validan o refutan las hipótesis H1–H5 |
| **F1** | Núcleo: servidor + control plane + cliente rebrandeado | 3–4 sem | **M0:** dos equipos en LAN se conectan (directo y por relay) usando binarios de Cercano, registrados en `cercano-api` |
| **F2** | Auditoría y traza | 3–4 sem | **M1:** toda sesión genera eventos encadenados, consultables y verificables por API y CLI |
| **F3** | Generador de instaladores | 3 sem | **M2:** desde un perfil JSON se obtiene un instalador Windows firmado, preconfigurado y revocable |
| **F4** | Consola web, RBAC y 2FA | 4 sem | **M3:** administración completa (usuarios, dispositivos, auditoría, generador) desde navegador |
| **F5** | Identidad y control de acceso | 4–5 sem | Libreta, estrategias, OIDC/LDAP, acceso entre grupos |
| **F6** | Optimización LAN y relays | 3 sem | Descubrimiento LAN, multi-relay, pruebas con pérdida/latencia |
| **F7** | Endurecimiento y release | 3 sem | **M4:** beta pública: pentest interno, SBOM, firma, documentación, guía de migración |

Total estimado: 24–30 semanas.

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

## 7. Decisiones pendientes del dueño

El equipo arranca con los valores por defecto indicados; si cambia alguno, avisar al Coordinador.

| ID | Decisión | Valor por defecto asumido |
|---|---|---|
| D1 | Nombre comercial y marca definitivos | «Cercano»; logo provisional en `branding/` (pendiente: contraste del cursor, ver `branding/README.md` §2) |
| D2 | Plataforma prioritaria del instalador | Windows primero; Linux y macOS después |
| D3 | Base de datos | SQLite por defecto (despliegues pequeños/LAN), PostgreSQL opcional |
| D4 | Certificado de firma de código (Authenticode) | **Sin definir:** hasta tenerlo, los instaladores se firman con certificado de pruebas |
| D5 | Acceso de los agentes al repositorio `AlcsPower/cercano` | **Resuelto** el 2026-11-05 |
| D6 | Versión base de upstream | Última etiqueta estable de ambos repos en la fecha de F0-02 |
| D7 | Texto de licencia | **Bloqueante para F0-02:** reemplazar el `LICENSE` actual (MIT) por el texto oficial de AGPL-3.0 (ver §8) |

## 8. Estado actual

- **Repositorio:** `AlcsPower/cercano` (privado) accesible para los agentes desde el 2026-11-05. F0-01 en curso en la rama `docs/F0-01-gobernanza`.
- **Licencia:** el repo se creó con `LICENSE` MIT. RustDesk y su servidor son AGPL-3.0, por lo que el repo debe pasar a AGPL-3.0 **antes de importar código upstream (F0-02)**. El texto oficial no pudo descargarse desde el entorno de los agentes y no se reescribe de memoria; ver `docs/status/BLOCKERS.md` (B-001).
- **Marca:** logo, iconos y guía de uso en `branding/`.
- **Documentos relacionados:** `ARQUITECTURA.md`, `../AGENTS.md`, `PLAN-F0-F1.md`, `PLAN-F2-AUDITORIA.md`, `PLAN-F3-GENERADOR.md`, `PLAN-DE-PRUEBAS.md`, `status/TAREAS.md`, `status/BLOCKERS.md`.
