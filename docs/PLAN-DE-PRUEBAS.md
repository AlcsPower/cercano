# Cercano — Plan de pruebas

**Versión:** 0.3 · **Fecha:** 2026-11-06 · Aplica a todas las fases. Roles y reglas: `AGENTS.md`.

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

## 7. Pruebas de seguridad por fase

- **Siempre en CI:** `cargo audit`, `cargo deny`, SAST (clippy con reglas de seguridad, semgrep), detección de secretos.
- **Por fase (Agente-Seguridad):** revisión del modelo de amenazas, fuzzing de los parsers nuevos (perfiles, ingestión de eventos), pruebas de autorización (cada endpoint con cada rol), intentos de manipulación de logs y perfiles.
- **F7:** pentest interno completo y revisión de cadena de suministro.

## 8. Informes y criterios de gate

- Cada ejecución de la suite genera informe (JUnit + resumen) archivado como artefacto.
- Los fallos se registran con ID, tarea asociada, severidad y evidencia.
- Un gate de fase exige: 100 % de casos de la fase en verde, 0 defectos críticos o altos abiertos, y plan de resolución para los defectos medios y bajos.
- Los resultados de rendimiento se comparan con el punto de referencia de la fase anterior; una regresión > 20 % requiere justificación.
