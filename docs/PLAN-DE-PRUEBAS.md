# Cercano — Plan de pruebas

**Versión:** 0.5 · **Fecha:** 2026-11-10 · Aplica a todas las fases. Roles y reglas: `AGENTS.md`.

## 1. Principios

- Ninguna tarea se cierra sin pruebas y evidencia.
- **Quien implementa no verifica:** Agente-QA (o Seguridad) ejecuta las pruebas de aceptación de tareas ajenas.
- Las pruebas son automáticas siempre que sea posible; las manuales se documentan paso a paso para que otro agente las repita.
- Las pruebas de seguridad ofensivas se hacen solo en el laboratorio propio.

## 2. Pirámide

| Nivel | Qué cubre | Dónde corre | Cuándo |
|---|---|---|---|
| Unitarias | Funciones y módulos (`audit-core`, canonicalización, validación de perfiles, etc.) | CI | Cada commit |
| Integración | `cercano-api` + BD, ingestión de eventos, exportadores contra receptores simulados | CI (contenedores) | Cada PR |
| E2E | Servidor + clientes reales + API en el laboratorio LAN | Laboratorio | Nocturno y bajo demanda |
| Seguridad | SAST, `cargo audit`, `cargo deny`, fuzzing de parsers, pruebas de manipulación | CI + laboratorio | PR y por fase |
| Rendimiento | Carga de ingestión, latencia de conexión, consumo del servidor | Laboratorio | Por fase |
| Compatibilidad | Matriz de sistemas operativos y versiones | Laboratorio | Por fase y antes de cada release |
| Actualización | Migraciones de BD y de perfiles; actualización del cliente | Laboratorio | Por fase |

## 3. Laboratorio LAN (F0-09)

- Red aislada con: servidor (hbbs, hbbr, cercano-api), ≥2 clientes Windows (10 y 11), ≥2 Linux (Ubuntu 22.04 y 24.04), API stub, receptor SIEM de prueba.
- Emulación de condiciones de red con `tc netem` o equivalente: latencia, jitter, pérdida, corte de enlace y bloqueo de UDP para forzar relay.
- Todo se crea, reinicia y destruye con un comando; los resultados se guardan como artefactos.
- Datos de prueba sintéticos; ninguna credencial real.

## 4. Matriz de compatibilidad (mínimo)

| Rol | Sistemas |
|---|---|
| Servidor | Linux x86_64 (Debian/Ubuntu LTS), contenedor Docker |
| Cliente (F1–F3) | Windows 10 y 11 |
| Cliente (F4+) | Ubuntu 22.04/24.04; macOS (cuando se planifique) |

## 5. Convención de casos de prueba

`TC-<fase>-<número>`: p. ej. `TC-F2-003`. Cada caso en `tests/cases/` con: objetivo, precondiciones, pasos, resultado esperado, automatizable (sí/no) y tarea asociada.

## 6. Catálogo inicial de casos

### F0–F1 (núcleo)

| ID | Caso | Resultado esperado |
|---|---|---|
| TC-F0-001 | Conexión directa en LAN entre dos clientes | Sesión establecida sin pasar por relay |
| TC-F0-002 | Conexión forzada por relay (UDP bloqueado) | Sesión establecida vía hbbr |
| TC-F0-010 | `tools/check-license.sh` sobre el `LICENSE` del repo | Código de salida 0 (texto oficial de AGPL-3.0); condición previa de F0-02 |
| TC-F1-001 | `--version` y logs del servidor | Muestran Cercano y versión base |
| TC-F1-002 | `docker compose up` desde cero | Servicios sanos; sin procesos root |
| TC-F1-010 | Login correcto | Token emitido con caducidad |
| TC-F1-011 | Login incorrecto repetido | Bloqueo temporal; sin contraseñas en logs |
| TC-F1-012 | Token revocado | Solicitud rechazada |
| TC-F1-013 | Alta de administrador inicial | Solo posible una vez y de forma segura |
| TC-F1-014 | Contraseña almacenada | Hash Argon2id; sin texto plano en BD |
| TC-F1-020 | Cliente nuevo aparece en la API | Dispositivo con ID y estado «en línea» |
| TC-F1-021 | Cliente apagado | Pasa a «fuera de línea» tras el tiempo de gracia |
| TC-F1-030 | Cliente Cercano e instalación upstream coexisten | Sin conflictos de configuración |
| TC-F1-031 | Rotación de clave del servidor | Clientes con clave antigua rechazados y evento registrado |
| TC-F1-040 | Marca del cliente | Icono e identidad de Cercano según `branding/README.md`; sin marca de RustDesk salvo atribución |

### F2 (auditoría)

| ID | Caso | Resultado esperado |
|---|---|---|
| TC-F2-001 | Cadena de 100 000 eventos | `verify` pasa |
| TC-F2-002 | Alterar un campo de un evento en la BD | `verify` falla indicando el evento |
| TC-F2-003 | Borrar un evento intermedio | `verify` falla |
| TC-F2-004 | Reordenar eventos | `verify` falla |
| TC-F2-005 | Truncar el final de la cadena | Detectado mediante el último checkpoint |
| TC-F2-010 | Sesión de escritorio remoto | Eventos de inicio, fin, autenticación y duración correctos |
| TC-F2-011 | Transferencia de archivos (dedicada y copiar/pegar) | Evento con dirección, ruta y tamaño/cantidad |
| TC-F2-012 | Sesión de terminal, de puerto y de cámara | Un evento por tipo, con tipo correcto |
| TC-F2-013 | Autenticación fallida | Evento «sin sesión» con IP de origen |
| TC-F2-014 | Reintento del mismo evento por el cliente | No se duplica (idempotencia) |
| TC-F2-015 | Payload malformado o demasiado grande | Rechazo definido; sin caída del servicio |
| TC-F2-020…028 | Una prueba por regla de alarma (positiva y negativa) | Se dispara solo cuando corresponde |
| TC-F2-030 | Carga sostenida de 500 eventos/s durante 10 min | Sin pérdida ni corrupción de la cadena |
| TC-F2-031 | Caída del proceso durante `append` | Cadena consistente al reiniciar |
| TC-F2-032 | Desfase de reloj cliente/servidor | Se registra marca del servidor y discrepancia |
| TC-F2-040 | Exportación a syslog, CEF, JSONL y webhook | Receptores reciben todos los eventos |
| TC-F2-041 | Receptor caído 10 min | Sin pérdida al recuperarse |
| TC-F2-042 | Purga por retención | `verify` pasa sobre archivo + cadena viva |
| TC-F2-043 | Auditor de solo lectura intenta modificar | Denegado y auditado |
| TC-F2-044 | Cada endpoint de escritura | Genera evento de auditoría (comprobación automática) |
| TC-F2-045 | Consulta por `trace_id` | Devuelve todos los eventos de la sesión |

### F3 (generador)

| ID | Caso | Resultado esperado |
|---|---|---|
| TC-F3-001 | Perfil válido | Cliente aplica la configuración |
| TC-F3-002 | Perfil con un byte alterado | Rechazado y evento registrado |
| TC-F3-003 | Perfil caducado | Rechazado |
| TC-F3-004 | Perfil firmado con clave ajena | Rechazado |
| TC-F3-005 | Perfil inválido contra el esquema | Error claro en `cercano-build` |
| TC-F3-006 | Perfil sin firma | Rechazado y evento registrado |
| TC-F3-007 | Perfil con campos desconocidos | Se rechaza o se ignora según la política documentada en F3-01 |
| TC-F3-008 | Reloj del sistema adelantado o atrasado respecto a la caducidad del perfil | Comportamiento definido y documentado; sin aceptar perfiles caducados por manipulación simple del reloj cuando hay hora de referencia del servidor |
| TC-F3-010 | Instalación, actualización y desinstalación en Windows 10 y 11 | Sin restos; entrada visible en Programas |
| TC-F3-011 | Instalación silenciosa del `.msi` | Código de salida 0; configuración correcta |
| TC-F3-020 | Firma Authenticode | Verificación válida; si falla, no se publica |
| TC-F3-021 | Dos builds del mismo commit | Mismo hash o diferencia explicada |
| TC-F3-030 | Usuario sin permiso solicita build | 403 y evento de denegación |
| TC-F3-031 | Secuencia `build.*` completa | Presente y verificable en la cadena |
| TC-F3-040 | Revocar un instalador | Rechazado en < 60 s y auditado |
| TC-F3-050 | Búsqueda de claves privadas en artefactos y repo | Ninguna encontrada (automático) |
| TC-F3-060 | Instalador `soporte` intenta iniciar una conexión | Rechazado por el servidor y alarma `role_violation` |
| TC-F3-061 | Se modifica la configuración local de un `soporte` para que parezca técnico | Sigue sin poder actuar como técnico |
| TC-F3-062 | Perfil con el `role` cambiado sin volver a firmar | Rechazado por el cliente |
| TC-F3-063 | Usuario sin permiso `builder:create:tecnico` pide un instalador técnico | 403 y evento de denegación |
| TC-F3-064 | Revocar todos los instaladores de un rol | Rechazados en < 60 s y auditado |
| TC-F3-065 | Matriz de capacidades de `PLAN-F3-GENERADOR.md` §1 para cada rol | Cada celda se cumple (lista de comprobación de QA) |
| TC-F3-070 | Elevación aceptada por la persona usuaria | Acción elevada aplicada; eventos `requested`, `consented`, `sent`, `applied` |
| TC-F3-071 | La persona usuaria rechaza la elevación | No se envía nada; evento `denied` |
| TC-F3-072 | La persona usuaria no responde | Caduca; evento `expired`; nada enviado |
| TC-F3-073 | Contraseña incorrecta tres veces | Se detiene en 3 intentos; la cuenta de dominio de pruebas no se bloquea; evento `failed` |
| TC-F3-074 | Buscar la contraseña usada en disco, logs, volcados de memoria tras el borrado y tráfico capturado | No aparece en ningún sitio (automático) |
| TC-F3-075 | Grabación de sesión durante una elevación (si existe F2-15) | Diálogo de credenciales enmascarado |
| TC-F3-076 | Elevación solicitada desde un instalador `soporte` | Rechazada y auditada |
| TC-F3-077 | Técnico sin permiso `elev:use` | Rechazada y auditada |
| TC-F3-078 | Segunda acción elevada tras la primera | Requiere nueva solicitud salvo permiso `elev:session` |
| TC-F3-079 | Elevación sin usar durante más de 60 s | Credencial descartada; la acción posterior se rechaza |
| TC-F3-080 | Secuencia `elev.*` completa | Presente y verificable en la cadena |
| TC-F3-081 | Buscar contraseñas en la base de auditoría y en los exportadores SIEM | Ninguna encontrada (automático) |
| TC-F3-082 | Ráfaga de elevaciones del mismo técnico | Se dispara la alarma |
| TC-F3-083 | Elevación desatendida en un `soporte` con el perfil por defecto | Rechazada; solo se acepta si el perfil la habilita |
| TC-F3-084 | Fuzzing del mensaje de elevación | Sin caídas ni fugas de información |
| TC-F3-090 | `cercano-build` sin `--base-binary` | Error claro; no se genera instalador |
| TC-F3-091 | `--allow-stub` | Artefactos `*-STUB.*`, `"stub": true` en la procedencia y aviso; no se firma con la clave de producción |
| TC-F3-092 | `--base-binary` con un archivo que no es PE o de tamaño ínfimo | Rechazado |
| TC-F3-093 | La API ofrece la descarga de un artefacto stub fuera de modo desarrollo | Denegada; la consola avisa |
| TC-F3-094 | Windows 10 y 11 limpios: instalar `.exe` y `.msi`, abrir, perfil verificado, conectar, desinstalar | Todo correcto con el cliente real |


### F4 — Consola, RBAC y 2FA (v0.2: F4-11…F4-13)

Casos detallados en `tests/cases/TC-F4-*.md`; resumen en `docs/PLAN-F4-CONSOLA.md` §8.

| ID | Caso | Resultado esperado |
|---|---|---|
| TC-F4-008 | Rol obligatorio sin factor | Sesión limitada; solo enrolar; resto 403 `mfa_enrollment_required` |
| TC-F4-009 | Autorrevocación de 2FA | Denegada a admin/operator y auditada; un admin puede desvincular y la cuenta reenrola |
| TC-F4-012 | Secreto TOTP en reposo | Cifrado en BD y respaldo; sin clave no arranca; clave errónea no abre el 2FA |
| TC-F4-013 | Matriz vs código | `permissions.rs`, `GET /api/roles` y el plan coinciden; grants auditados |
| TC-F4-014 | `mfa_verified` | Falso sin 2FA; elevación (F3) y reautenticación (F8) lo exigen |

### F4.5 (Cercano Chat)

Los casos detallados viven en `tests/cases/TC-F4.5-*.md` durante la implementación. La suite se ejecuta en el laboratorio con TLS, un cliente Soporte, un cliente Técnico y dos cuentas técnicas.

| ID | Caso | Resultado esperado |
|---|---|---|
| TC-F4.5-001 | Registro de dispositivo válido | Clave fijada; evento `chat.device.registered`; token de chat emitido |
| TC-F4.5-002 | Registro con otra clave para el mismo `device_id` | 409 `key_mismatch`, sin cambios, evento de denegación |
| TC-F4.5-003 | Nonce reutilizado | 401; no se emite token |
| TC-F4.5-004 | Nonce caducado (>120 s) | 401; no se emite token |
| TC-F4.5-005 | Firma inválida | 401; evento `chat.auth.failed` |
| TC-F4.5-006 | Token de chat expirado o revocado | 401 en REST y cierre de SSE |
| TC-F4.5-010 | Crear conversación con primer mensaje | 201, estado `waiting`, eventos `chat.opened` y `chat.message.created` |
| TC-F4.5-011 | Segundo `POST /conversations` con una abierta | 200 con la misma conversación; mensaje añadido; sin duplicados |
| TC-F4.5-012 | Paginación de mensajes | Orden correcto, `next_before` y sin solapamientos |
| TC-F4.5-013 | Dos técnicos reclaman a la vez | Uno obtiene 200; el otro 409 `already_assigned` |
| TC-F4.5-014 | Asignar, liberar y reasignar | Estado y `assigned_user_id` correctos; eventos |
| TC-F4.5-015 | Cerrar y reabrir | Cerrada de solo lectura; reapertura solo `chat:manage` |
| TC-F4.5-016 | Dispositivo A intenta leer la conversación de B | 403/404; sin fuga |
| TC-F4.5-017 | Técnico sin permiso intenta leer una conversación ajena | 403; evento `chat.denied` |
| TC-F4.5-018 | Primer uso sin Nombre/Apellido | El cliente no deja crear la conversación; la API devuelve 400 si faltan |
| TC-F4.5-019 | Segundo uso con nombre guardado | Se precarga y se reutiliza; editarlo aplica solo a conversaciones nuevas |
| TC-F4.5-020 | Snapshot del nombre y respaldo | La conversación conserva el nombre aunque el equipo cambie; sin nombre, la consola muestra el equipo |
| TC-F4.5-021 | Buscar el nombre en auditoría, logs, telemetría y notificaciones | No aparece; solo está en la conversación y en la configuración local |
| TC-F4.5-030 | Adjuntar PNG/JPEG/WebP/PDF | 201; mensaje con adjunto; imagen visible/PDF descargable |
| TC-F4.5-031 | Adjuntar SVG/EXE/ZIP o un archivo con MIME falso | 415; no se guarda |
| TC-F4.5-032 | Adjunto >10 MiB | 413; no se guarda |
| TC-F4.5-033 | Nombre con `../`, barras o caracteres de control | Se sanea; no hay escritura fuera del directorio |
| TC-F4.5-034 | Descargar un adjunto ajeno | 403/404 |
| TC-F4.5-035 | Verificar SHA-256 y tamaño guardados | Coinciden con el archivo |
| TC-F4.5-036 | Fallo de transacción tras escribir el archivo | No queda archivo huérfano |
| TC-F4.5-040 | Ráfaga de mensajes por dispositivo | 429 con `Retry-After`; evento `chat.rate_limited` |
| TC-F4.5-041 | Límite diario de conversaciones | 429; no se crea |
| TC-F4.5-042 | Límite diario de adjuntos | 429; no se guarda |
| TC-F4.5-043 | Reintento tras `Retry-After` | Se acepta cuando pasa la ventana |
| TC-F4.5-050 | Cadena con eventos `chat.*`, de conexión y de administración | `cercano-audit verify` en verde |
| TC-F4.5-051 | Buscar cuerpos de mensajes en la base de auditoría | Ninguno encontrado |
| TC-F4.5-052 | Buscar tokens, claves y nombres de archivo en auditoría/logs | Ninguno encontrado |
| TC-F4.5-053 | Purga de una conversación cerrada antigua | Mensajes y adjuntos borrados; auditoría intacta |
| TC-F4.5-054 | Conversación abierta antigua | No se purga |
| TC-F4.5-060 | Mensaje nuevo para el técnico asignado | Recibe el poke y refetchea |
| TC-F4.5-061 | Mensaje nuevo para el dispositivo dueño | Recibe el poke y refetchea |
| TC-F4.5-062 | Poke para un tercero | No lo recibe |
| TC-F4.5-063 | Reconexión SSE tras corte | Refetch sin pérdida de mensajes |
| TC-F4.5-064 | Consumidor atrasado | Recibe `resync` y refetchea |
| TC-F4.5-065 | Revocación del token con SSE abierta | El stream se cierra en ≤60 s |
| TC-F4.5-070 | Consola: filtros, búsqueda por nombre/equipo y badge | Resultados y contadores correctos |
| TC-F4.5-071 | Notificación con la pestaña oculta | Se muestra sin cuerpo ni nombre; al pulsar enfoca la conversación |
| TC-F4.5-072 | Reclamar, cerrar y escalar desde la consola | Acciones correctas y auditadas |
| TC-F4.5-073 | Navegación por teclado y lector de pantalla | Foco visible, `aria-live`, todos los controles accesibles |
| TC-F4.5-074 | Tema claro/oscuro y `prefers-reduced-motion` | Sin regresiones visuales ni movimiento no deseado |
| TC-F4.5-075 | Modo demostración de la consola | «Chat no disponible»; no inventa conversaciones |
| TC-F4.5-076 | Corte de SSE en la consola | Banner de reconexión y recuperación |
| TC-F4.5-080 | Entrada «Chat de soporte» en el cliente | Abre la ventana dedicada y carga la conversación abierta |
| TC-F4.5-081 | Enviar y recibir texto | Orden, estados y sin duplicados |
| TC-F4.5-082 | Enviar imagen y PDF | Imagen en línea; PDF descargable |
| TC-F4.5-083 | Llegada de mensaje con la ventana minimizada | Toast genérico; al abrir, mensaje visible |
| TC-F4.5-084 | Corte de red en el cliente | Reconexión y refetch; los mensajes enviados no se duplican |
| TC-F4.5-085 | Perfil con `chat.enabled=false` | El cliente no muestra el chat y el servidor rechaza |
| TC-F4.5-086 | Escalar a sesión remota | Abre `cercano://`; consentimiento normal; `trace_id` compartido |
| TC-F4.5-087 | Cambio de idioma del cliente | Claves nuevas presentes; textos en español/inglés |
| TC-F4.5-088 | Ventana y diseño con marca configurada | Cabecera/logo/acento/textos desde la configuración admin; sin marca fija; sin typing/presencia |
| TC-F4.5-089 | Doble check de leído | Un check al enviar; doble cuando `other_last_read_at` cubre el mensaje |
| TC-F4.5-090 | E2E completo: chat → adjunto → respuesta → cierre → escalado | Todo correcto y `cercano-audit verify` en verde |
| TC-F4.5-091 | Corte de red entre cliente/API y API/consola | Sin pérdida; reconexión |
| TC-F4.5-092 | Cliente con `api_server` HTTP | Chat rechazado con aviso claro |
| TC-F4.5-093 | Técnico sin 2FA intenta atender | Rechazado en producción (F4) |
| TC-F4.5-094 | Buscar secretos y cuerpos en logs del cliente, API y consola | Ninguno encontrado |
| TC-F4.5-095 | Notificación con cuerpo/nombre | No aparece ninguno de los dos |
| TC-F4.5-096 | GET /api/chat/branding devuelve defaults/config | Sin auth devuelve objeto con defaults o config guardada; estructura correcta |
| TC-F4.5-097 | PUT /api/chat/branding con `chat:manage` | 200 y objeto actualizado; 403 sin permiso; validación color `#RRGGBB`, URL https, longitudes |
| TC-F4.5-098 | Cliente refleja cambio de marca y fallback | Al reabrir/refrescar la ventana usa la nueva marca; si la API falla usa fallback (perfil/built-in) |

### F5 (identidad, grupos y federación)

Fuente: [`PLAN-F5-IDENTIDAD.md`](PLAN-F5-IDENTIDAD.md) y [`specs/identidad.md`](specs/identidad.md). Los detalles viven en `tests/cases/TC-F5-*.md` y se escriben con la tarea que implementa cada caso.

| ID | Caso | Resultado esperado |
|---|---|---|
| TC-F5-001 | Migración 009 sobre base vacía | Siete tablas, índices y constraints creados; `schema_migrations` = 9 |
| TC-F5-002 | Migración 009 sobre base con 001–008 | Sin pérdida de datos; constraints e índices válidos |
| TC-F5-003 | Reversión documentada de 009 | Tablas nuevas eliminadas; ninguna tabla previa alterada |
| TC-F5-010 | Matriz rol × operación × grupo (admin/operator/auditor/legacy) | Permitido o 403 auditado; nunca 200 sin permiso |
| TC-F5-011 | IDOR: grupo ajeno (leer, editar, borrar, añadir miembro) | 404 sin cambios y `authz.denied` |
| TC-F5-012 | Detalle de dispositivo y política efectiva fuera de alcance | 404; sin fuga de nombre ni estado |
| TC-F5-013 | Concesión `read`/`operate` entre grupos | Con concesión: lectura/operación; sin ella: denegado |
| TC-F5-014 | Pertenencia a grupo no eleva rol | `operator` en grupo no obtiene `groups:manage` |
| TC-F5-020 | Conflicto global/grupo/dispositivo | Gana el valor más restrictivo; explicación por clave correcta |
| TC-F5-021 | Dos grupos con valores opuestos | Resultado determinista (restrictivo; empate por `group_id` menor) |
| TC-F5-022 | Política caducada, revocada, malformada o con hash alterado | No participa; no concede; evento registrado |
| TC-F5-023 | Política intenta ampliar el perfil firmado | `unattended_access`/elevación siguen en `false` |
| TC-F5-024 | Cliente sin red: caché vigente y caché caducada | Vigente: aplica copia; caducada: falla cerrado para conexiones nuevas |
| TC-F5-025 | Cliente edita la política localmente | Sin efecto; el servidor y el perfil mandan |
| TC-F5-030 | OIDC: `state`/`nonce` ausente, reutilizado o caducado | 401; sin sesión; sin consumo del código |
| TC-F5-031 | OIDC: emisor/audiencia/firma incorrectos; `kid` rotado | Rechazo; recarga de JWKS solo con `kid` desconocido |
| TC-F5-032 | OIDC: correo coincide con otra cuenta | `identity_exists`; sin vinculación automática |
| TC-F5-033 | Proveedor OIDC caído | 503 con `Retry-After`; sesiones vigentes intactas; admin local funciona |
| TC-F5-040 | LDAP sin TLS | Configuración rechazada; no se guarda |
| TC-F5-041 | LDAP: credencial inválida y cuenta inexistente | Mismo error genérico; sin enumeración |
| TC-F5-042 | LDAP caído o timeout | 503; sin sesión; sin escalada de rol |
| TC-F5-043 | LDAP: grupo fuera de allowlist y entrada explícita de admin | Sin allowlist: rol por defecto o denegación; entrada explícita: rol concedido |
| TC-F5-044 | Login LDAP correcto sin TOTP | 202 y TOTP exigido antes de la sesión |
| TC-F5-050 | Cambio de ID de dispositivo (diferido) | ADR de diferimiento presente; sin rutas ni permisos nuevos |
| TC-F5-051 | LAPS (diferido) | Sin tabla, endpoint ni secreto en logs; ADR de diferimiento |
| TC-F5-060 | Consola F5: carga, vacío, error, permisos y accesibilidad | Coherente con el API; 403 no se presenta como permitido |
| TC-F5-061 | Diagnóstico de política efectiva en consola | Coincide con el API; sin datos secretos |

### F6 (LAN y relays)

Fuente: [`PLAN-F6-LAN-RELAYS.md`](PLAN-F6-LAN-RELAYS.md) y [`spikes/S7-lan-relays.md`](spikes/S7-lan-relays.md) (umbrales de §3). Los detalles viven en `tests/cases/TC-F6-*.md` y se escriben con la tarea que implementa cada caso. Todo en el laboratorio propio.

| ID | Caso | Resultado esperado |
|---|---|---|
| TC-F6-001 | Descubrimiento desactivado (default) | No anuncia, no escucha; ninguna ruta se amplía |
| TC-F6-002 | Rango permitido y host fuera de rango | Anuncia solo dentro del rango e interfaz autorizados |
| TC-F6-003 | Interfaz de red no permitida | Ignorada; sin anuncio ni error que filtre datos |
| TC-F6-004 | Anuncio falsificado en la LAN | No concede confianza; la conexión normal valida claves, consentimiento y rol |
| TC-F6-005 | Apagado de emergencia durante el anuncio | Deja de anunciar de inmediato; sin reinicio del servicio |
| TC-F6-010 | Dos relays con RTT distinto | Elige el mejor y se mantiene estable (histéresis ≥ 20 %) |
| TC-F6-011 | Relay elegido detenido | Fallback ≤ 5 s al siguiente, mismo `trace_id` |
| TC-F6-012 | Relay revocado o no registrado | No se anuncia ni se selecciona |
| TC-F6-013 | Capacidad agotada en el mejor relay | No se selecciona; se informa el fallo seguro |
| TC-F6-014 | Métricas equivalentes entre relays | Desempate determinista y repetible |
| TC-F6-020 | Pérdida y jitter dentro y fuera de umbral | Sesión estable o degradación informada según S7 §3 |
| TC-F6-021 | UDP bloqueado en el cliente | Ruta por relay en ≤ 10 s, sin duplicar sesión ni evento |
| TC-F6-022 | Corte y reconexión de red | Reconecta sin duplicar sesión ni evento de auditoría |
| TC-F6-023 | Relay caído a mitad de sesión | Reconexión por otra ruta conservando política y `trace_id` |
| TC-F6-030 | Cambio de ruta con rol `soporte`/`tecnico` | Rol y permisos revalidados; sin escalada |
| TC-F6-031 | Conmutación durante una sesión con consentimiento | No reinicia ni salta el consentimiento |
| TC-F6-032 | Relay hostil o suplantado en la ruta | Contenido E2E intacto; límite documentado en S7 §6 |
| TC-F6-033 | Búsqueda de secretos en trazas de ruta | Sin claves, tokens ni credenciales |
| TC-F6-040 | Un `trace_id` de intento a ruta y sesión | Correlación completa en auditoría |
| TC-F6-041 | Reintentos de conexión | Sin sesiones ni eventos duplicados |
| TC-F6-050 | Cliente soportado y versión mínima | Directa y relay funcionan; versión no soportada se rechaza |
| TC-F6-051 | Parches 001–007 tras F6 | Siguen aplicando y la suite permanece verde |
| TC-F6-060 | WebSocket con proxy, TLS y corte (si se aprueba) | Autenticación, límites y fallback; sin bypass de controles |
| TC-F6-061 | WebSocket diferido | ADR con los números de S7 §3 y decisión explícita |
| TC-F6-070 | p50/p95, CPU y RAM frente a baseline F5 | Dentro de S7 §3; regresiones > 20 % explicadas |
| TC-F6-071 | Carga sostenida y recuperación | Sin degradación no informada; recuperación sin reinicio |

### F8 (portabilidad y respaldos)

Fuente: [`PLAN-F8-PORTABILIDAD.md`](PLAN-F8-PORTABILIDAD.md) y [`specs/db-portabilidad.md`](specs/db-portabilidad.md). La columna «Motores» indica dónde debe correr el caso; SQL Server solo si F8-01 lo aprueba.

| ID | Caso | Resultado esperado | Motores |
|---|---|---|---|
| TC-F8-001 | Migrar una base vacía y una con 001–008 | Esquema aplicado sin errores y `schema_migrations` correcta | SQLite, PG, MSSQL |
| TC-F8-002 | Fingerprint de esquema por motor | Coincide con el archivo versionado; una columna de más lo hace fallar | idem |
| TC-F8-003 | `UPDATE audit_events` | Falla; la fila no cambia; el error es claro | idem |
| TC-F8-004 | `DELETE audit_events` | Falla; la fila no cambia | idem |
| TC-F8-005 | Suite completa de la API sobre PostgreSQL | Todo en verde; sin consultas con sintaxis SQLite | PG |
| TC-F8-006 | Suite completa de la API sobre SQL Server | Todo en verde | MSSQL (si aplica) |
| TC-F8-007 | Migración de datos legados de timestamps | Formato canónico; `audit_events` intacta; idempotente | SQLite, PG |
| TC-F8-008 | Consulta con `?` dentro de un literal | El reescritor no toca el literal | unitaria |
| TC-F8-010 | Crear respaldo | Archivo firmado, manifiesto con conteos y hashes por tabla | idem |
| TC-F8-011 | Verificar el respaldo recién creado | Válido, con la tabla y el número de filas esperados | idem |
| TC-F8-012 | Alterar una fila del archivo | Rechazado con la tabla y la fila señaladas | idem |
| TC-F8-013 | Alterar el manifiesto o `archive_sha256` | Rechazado por firma/hash | idem |
| TC-F8-014 | Archivo con `format: 2` | Rechazado con mensaje explícito | idem |
| TC-F8-015 | Archivo con `schema_version` mayor | Rechazado antes de leer datos | idem |
| TC-F8-016 | Respaldo con y sin adjuntos | Manifiesto refleja `included`; el compañero de adjuntos existe solo cuando corresponde | idem |
| TC-F8-017 | Descargar respaldo con `operator` o `auditor` | 403 y evento; la pestaña no se muestra | consola |
| TC-F8-018 | Nombre de archivo con `../` o caracteres fuera de `[A-Za-z0-9._-]` | Rechazado; sin escritura fuera del directorio | idem |
| TC-F8-019 | Retención con más copias que el límite | Borra las más antiguas verificadas; conserva la más reciente; audita | idem |
| TC-F8-020 | Disco lleno a mitad de respaldo | Error `db.storage_full`; `.tmp` identificable; la BD intacta | idem |
| TC-F8-021 | Programación: esperar un intervalo y reiniciar el proceso | La copia se ejecuta; el estado persiste; no se duplica | idem |
| TC-F8-030 | Restaurar en una instalación limpia | Conteos coinciden; `cercano-audit verify` en verde | idem |
| TC-F8-031 | Restaurar con firma inválida | Aborta antes de escribir; la base actual no se toca | idem |
| TC-F8-032 | Restaurar sin snapshot previo posible | Se rechaza la operación | idem |
| TC-F8-033 | Restaurar con un build en curso | 409 `db.job_in_progress` | idem |
| TC-F8-034 | Restaurar con contraseña incorrecta o confirmación de motor errónea | 403/422; nada cambia | idem |
| TC-F8-035 | Restaurar con adjuntos ausentes | BD restaurada; aviso explícito de adjuntos fuera | idem |
| TC-F8-040 | Preflight contra destino no vacío | `ok: false` con el chequeo fallido; no se escribe | PG, MSSQL |
| TC-F8-041 | Migración SQLite → PostgreSQL | Sin pérdida; conteos y cadena verificados; reinicio en el destino | PG |
| TC-F8-042 | Interrumpir el proceso durante `copying` | Estado incompleto informado; el origen sigue siendo la fuente; no se reanuda solo | PG |
| TC-F8-043 | Rollback tras `verifying` fallido | Destino descartado; servicio en el origen; evento | PG |
| TC-F8-044 | Corte | `requires_restart: true`; tras reiniciar, `status` informa el motor destino | PG |
| TC-F8-045 | Fallo al escribir el TOML | `db.migration_cutover_failed`; servicio en el origen; sale de mantenimiento | PG |
| TC-F8-046 | Escrituras y latidos durante mantenimiento | 503 con `Retry-After`; lecturas OK; equipos `offline` tras la gracia | PG |
| TC-F8-050 | Cadena de eventos `db.*` | Presentes, verificables y sin contenido de datos | idem |
| TC-F8-051 | Buscar secretos, `target_url` y credenciales en archivo, logs y auditoría | Ninguno encontrado | idem |
| TC-F8-052 | Archivo de respaldo y claves | El archivo no contiene `id_ed25519` ni `audit_signing_key`; la consola avisa | idem |
| TC-F8-060 | Consola: ciclo completo con `admin` | Respaldo, verificación, descarga, restauración y migración guiadas | consola |
| TC-F8-061 | Consola con `operator` y `auditor` | Sin pestaña «Mantenimiento»; 403 en la API | consola |
| TC-F8-062 | Progreso y error en la consola | Barra y tabla avanzan; tras un fallo inyectado se muestra el código | consola |
| TC-F8-063 | Accesibilidad, modo oscuro y `prefers-reduced-motion` en la pestaña | Foco visible, `aria-live` en el progreso, sin regresiones | consola |

## 7. Pruebas de seguridad por fase

- **Siempre en CI:** `cargo audit`, `cargo deny`, SAST (clippy con reglas de seguridad, semgrep), detección de secretos.
- **Por fase (Agente-Seguridad):** revisión del modelo de amenazas, fuzzing de los parsers nuevos (perfiles, ingestión de eventos), pruebas de autorización (cada endpoint con cada rol), intentos de manipulación de logs y perfiles.
- **F7:** pentest interno completo y revisión de cadena de suministro.

## 8. Informes y criterios de gate

- Cada ejecución de la suite genera informe (JUnit + resumen) archivado como artefacto.
- Los fallos se registran con ID, tarea asociada, severidad y evidencia.
- Un gate de fase exige: 100 % de casos de la fase en verde, 0 defectos críticos o altos abiertos, y plan de resolución para los defectos medios y bajos.
- Los resultados de rendimiento se comparan con el punto de referencia de la fase anterior; una regresión > 20 % requiere justificación.
