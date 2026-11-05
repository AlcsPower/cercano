# Plan de trabajo — F0 (Fundación) y F1 (Núcleo)

**Versión:** 0.2 · **Fecha:** 2026-11-05 · Reglas de ejecución: `AGENTS.md`

Columnas: **Dep.** = dependencias · **Rol** = quién ejecuta · **Verifica** = quién valida. Los criterios de aceptación (CA) son verificables y las pruebas referencian `PLAN-DE-PRUEBAS.md`.

---

## F0 — Fundación y spikes técnicos (1–2 semanas)

**Objetivo:** dejar el repositorio listo para trabajar en paralelo y validar las hipótesis H1–H5 antes de comprometer el diseño.

| ID | Tarea | Dep. | Rol | Verifica |
|---|---|---|---|---|
| F0-01 | Gobernanza del repo | — | Builder | QA |
| F0-02 | Importar upstream | F0-01, **B-001** | Servidor | QA |
| F0-03 | CI base | F0-01 | Builder | QA |
| F0-04 | Spike S1: build del servidor y despliegue en LAN | F0-02 | Servidor | QA |
| F0-05 | Spike S2: build del cliente Windows | F0-02 | Cliente | QA |
| F0-06 | Spike S3: hooks de heartbeat y auditoría del cliente | F0-05 | Cliente | Seguridad |
| F0-07 | Spike S4: configuración embebida y verificación | F0-05 | Cliente | Seguridad |
| F0-08 | Spike S5: propagación de `trace_id` | F0-04, F0-05 | Servidor | QA |
| F0-09 | Laboratorio de pruebas LAN | F0-01 | QA | Coordinador |
| F0-10 | Ratificación de ADR y cierre de F0 | F0-04…09 | Coordinador | Dueño |

**B-001** es el bloqueo abierto de `docs/status/BLOCKERS.md`: el `LICENSE` debe ser el texto oficial de AGPL-3.0 (se comprueba con `tools/check-license.sh`) antes de importar código de upstream.

### Detalle

**F0-01 Gobernanza del repo.**
Crear en `AlcsPower/cercano`: `LICENSE` (AGPL-3.0, ver B-001), `NOTICE` (atribución a RustDesk y sus autores), `README.md` (visión, estado, cómo contribuir), `SECURITY.md`, `CONTRIBUTING.md`, `CODEOWNERS`, plantillas de PR e issues, estructura de carpetas de `ARQUITECTURA.md` §2, y copiar `docs/` y `AGENTS.md` desde el Project.
*CA:* el repo contiene todo lo anterior; rama principal protegida (PR obligatorio); `docs/status/TAREAS.md` creado con todas las tareas de F0–F3 en `Pendiente`.
*Estado (2026-11-05):* todo entregado en la rama `docs/F0-01-gobernanza` salvo el reemplazo del texto de `LICENSE` (B-001) y la protección de la rama principal, que requieren al dueño del repo.

**F0-02 Importar upstream.**
Seleccionar la última etiqueta estable de `rustdesk/rustdesk` y `rustdesk/rustdesk-server`, importarlas en `vendor/` con `git subtree` (o equivalente aprobado), registrar commits base en `vendor/UPSTREAM.md`, crear `patches/INDEX.md` y `tools/apply-patches`. **No iniciar hasta que `tools/check-license.sh` termine con código 0.**
*CA:* `vendor/` compila sin cambios (se prueba en F0-04/05); `UPSTREAM.md` indica repositorio, etiqueta, hash y fecha; `apply-patches` es idempotente con 0 parches.

**F0-03 CI base.**
Workflows: `cargo fmt --check`, `clippy -D warnings`, `cargo test`, `cargo deny check`, `cargo audit`; build del servidor en Linux con caché; verificación de encabezados de licencia; ejecución de `tools/check-license.sh`.
*CA:* un PR de prueba pasa todos los jobs; un PR con una dependencia de licencia incompatible falla.

**F0-04 Spike S1: servidor.**
Compilar hbbs, hbbr y utils desde `vendor/`; crear `deploy/docker-compose.yml` provisional; desplegar en el laboratorio; conectar dos clientes upstream de prueba. Documentar puertos, claves y tiempos de build.
*CA:* informe `docs/spikes/S1-servidor.md` con instrucciones reproducibles; conexión directa y por relay demostradas (TC-F0-001, TC-F0-002).

**F0-05 Spike S2: cliente Windows.**
Compilar el cliente Flutter desde `vendor/` en Windows (y en Linux si es viable), documentando toolchains, vcpkg, tiempos y consumo de disco/RAM; proponer estrategia de caché para CI.
*CA:* informe `docs/spikes/S2-cliente.md`; binario ejecutable que conecta con el servidor de S1; estimación de tiempo de build en CI.

**F0-06 Spike S3: hooks de heartbeat y auditoría (H1–H3).**
Inventariar en el código abierto del cliente todas las llamadas HTTP a un servidor de API configurable (heartbeat, sysinfo, auditoría de conexión, de archivos, de alarmas, subida de grabaciones u otras). Levantar un **API stub** que registre las peticiones, apuntar el cliente a él y provocar cada tipo de evento (conexión, archivo, fallo de login, etc.). Documentar rutas, métodos, cuerpos JSON, cabeceras y condiciones de disparo.
*CA:* `docs/spikes/S3-hooks-auditoria.md` con tabla *evento del cliente → petición observada* y lista de eventos del `ARQUITECTURA.md` §4 que **no** están cubiertos; veredicto explícito sobre H1, H2 y H3. Solo se usa código abierto y tráfico propio; ningún binario de Server Pro.

**F0-07 Spike S4: configuración embebida (H4).**
Estudiar cómo el cliente carga configuración personalizada (nombre de archivo, config embebida, archivo de configuración, variables) y cómo, si existe, verifica su autenticidad. Probar generar un binario con servidor/clave preconfigurados y con una clave de verificación propia.
*CA:* `docs/spikes/S4-config-embebida.md` con el mecanismo recomendado, límites (qué es configurable sin recompilar y qué no) y veredicto sobre H4.

**F0-08 Spike S5: `trace_id` (H5).**
Evaluar si se puede añadir un identificador de traza al flujo de conexión (rendezvous, relay, handshake del cliente) sin romper compatibilidad con upstream; prototipo mínimo.
*CA:* `docs/spikes/S5-trace-id.md` con diseño, prototipo y veredicto sobre H5; alternativa de correlación por ventana de tiempo descrita.

**F0-09 Laboratorio de pruebas LAN.**
Definir y automatizar (`tests/lab/`) una topología reproducible: red aislada con servidor, ≥2 clientes Windows, ≥2 clientes Linux, API stub, y emulación de pérdida/latencia (`tc netem` o equivalente). Scripts para crear, reiniciar y destruir el entorno; documentación para que cualquier agente lo levante.
*CA:* `tests/lab/README.md`; el entorno se levanta con un solo comando y ejecuta el smoke test de F0-04.

**F0-10 Ratificación y cierre.**
El Coordinador consolida resultados, actualiza `ARQUITECTURA.md` (hipótesis → hechos), formaliza ADR 001–007 en `docs/adr/`, ajusta F1–F3 según hallazgos y presenta decisiones D1–D7 al dueño.
*CA:* ADR publicados; informe de cierre `docs/status/F0-cierre.md`; plan de F1–F3 revisado.

**Gate F0:** todas las tareas `Hecho`; veredicto documentado de H1–H5; laboratorio operativo.

---

## F1 — Núcleo: servidor, control plane y cliente (3–4 semanas)

**Objetivo (M0):** dos equipos en LAN se conectan usando binarios de Cercano, ambos registrados en `cercano-api`.

| ID | Tarea | Dep. | Rol | Verifica |
|---|---|---|---|---|
| F1-01 | Rebranding mínimo del servidor | F0-10 | Servidor | QA |
| F1-02 | Empaquetado del servidor | F1-01 | Builder | QA |
| F1-03 | Esqueleto de `cercano-api` | F0-10 | ControlPlane | QA |
| F1-04 | Autenticación y usuarios | F1-03 | ControlPlane | Seguridad |
| F1-05 | Registro de dispositivos | F1-03, F0-06 | ControlPlane | QA |
| F1-06 | Gestión de claves del servidor | F1-01, F1-03 | Servidor | Seguridad |
| F1-07 | Rebranding del cliente | F0-10 | Cliente | QA |
| F1-08 | Cliente apuntando a `cercano-api` | F1-05, F1-07 | Cliente | QA |
| F1-09 | Smoke test E2E automatizado | F1-02, F1-08, F0-09 | QA | Coordinador |
| F1-10 | Guía de despliegue y cierre | F1-09 | Coordinador | Dueño |

### Detalle

**F1-01 Rebranding mínimo del servidor.**
Aplicar mediante parches: nombre del producto en cadenas de versión y logs. Mantener nombres de binario `hbbs`/`hbbr` o prefijarlos (`cercano-hbbs`) según la decisión de F0-10, documentando el motivo.
*CA:* `--version` y logs muestran Cercano y la versión base de upstream; parche registrado en `patches/INDEX.md`; las pruebas upstream que existan siguen pasando.

**F1-02 Empaquetado del servidor.**
`deploy/`: Dockerfile multi-etapa, `docker-compose.yml` (hbbs, hbbr, cercano-api, volumen de datos), unidades systemd, healthchecks, política de reinicio, usuario no privilegiado.
*CA:* `docker compose up` deja el servicio operativo; los contenedores no corren como root; los puertos expuestos coinciden con `ARQUITECTURA.md` §1.

**F1-03 Esqueleto de `cercano-api`.**
Crate axum con configuración por archivo y variables, endpoint `/healthz`, migraciones sqlx (SQLite), especificación OpenAPI generada, logging estructurado JSON con `trace_id` de petición, apagado ordenado.
*CA:* arranca y responde `/healthz`; migraciones se aplican en BD vacía; OpenAPI publicado en `docs/specs/api.yaml`; cobertura de pruebas unitarias ≥ 70 % del esqueleto.

**F1-04 Autenticación y usuarios.**
Alta inicial del administrador (bootstrap seguro), usuarios con contraseñas Argon2id, sesiones/tokens con caducidad y revocación, limitación de intentos y bloqueo temporal.
*CA:* pruebas de login correcto/incorrecto/bloqueo; contraseñas jamás en logs; revisión de Seguridad sin hallazgos altos (TC-F1-010…014).

**F1-05 Registro de dispositivos.**
Endpoints que el cliente usa para anunciarse (heartbeat y datos de sistema), con las rutas y formatos descubiertos en S3. Persistencia de dispositivo, última conexión y estado en línea/fuera de línea.
*CA:* un cliente real aparece en la lista con su ID y estado; se marca fuera de línea tras el tiempo de gracia configurable; pruebas contra el stub y contra cliente real.

**F1-06 Gestión de claves del servidor.**
Generación del par de claves de hbbs en el primer arranque, exposición de la clave pública a la API, procedimiento de rotación y respaldo cifrado.
*CA:* la clave privada nunca sale por la API ni por logs; la rotación se documenta y se prueba (clientes con clave antigua son rechazados y el motivo queda registrado).

**F1-07 Rebranding del cliente.**
Por parches: nombre visible, identificador de aplicación, rutas de configuración (para no colisionar con una instalación upstream), iconos propios de Cercano tomados de `branding/png/` (`cercano-icon.ico` en Windows; `cercano-icon-512.png` y `-1024.png` como origen para Flutter), cadenas de «acerca de» con atribución y enlace al código fuente (AGPL). Seguir las reglas de `branding/README.md`.
*CA:* el cliente se instala junto a upstream sin conflicto; no aparece la marca de RustDesk en interfaz ni instalador, salvo atribución legal; parches registrados.

**F1-08 Cliente apuntando a `cercano-api`.**
Configuración por defecto (servidor, clave, API) y, si S3 mostró carencias, parches mínimos para el heartbeat.
*CA:* tras instalar y configurar, el cliente figura en la API (TC-F1-020).

**F1-09 Smoke test E2E.**
Automatizar en el laboratorio: levantar servidor, registrar dos clientes, abrir sesión directa en LAN, abrir sesión por relay (bloqueando UDP directo), verificar registro de dispositivos, cerrar sesión.
*CA:* `tests/e2e/smoke` pasa en CI nocturno y bajo demanda; informe con tiempos de conexión.

**F1-10 Guía de despliegue y cierre.**
Guía para operadores (`docs/guias/despliegue.md`), informe de cierre `docs/status/F1-cierre.md`, ajuste del plan de F2–F3.

**Gate F1 (M0):** smoke test verde en el laboratorio; sin hallazgos altos de seguridad abiertos; guía de despliegue validada por un agente que no la escribió (siguiéndola desde cero).
