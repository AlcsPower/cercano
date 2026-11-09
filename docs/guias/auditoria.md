# Guía oficial de auditoría y administración de Cercano

**Alcance:** F2-14 · M1  
**Estado:** en verificación. Esta guía describe las capacidades previstas y distingue la evidencia disponible de lo que aún no está validado.

## 1. Principios y alcance

Cercano registra eventos de autenticación, sesiones, transferencias, alarmas y acciones administrativas en una cadena append-only. Cada evento conserva `prev_hash` y `hash`; los checkpoints firmados permiten demostrar integridad. No deben registrarse contraseñas, tokens, claves ni contenido de archivos.

El auditor trabaja con permisos de solo lectura. El administrador conserva claves de firma separadas del almacén, limita el acceso a exportaciones y documenta cada custodia.

## 2. Preparar una evidencia

1. Defina el intervalo, `trace_id`, actores y sistemas incluidos.
2. Obtenga un volcado autenticado de la API o una copia del archivo firmado, sin editarlo.
3. Registre fecha, responsable, origen, hash del archivo y medio de transporte en la cadena de custodia.
4. Conserve el checkpoint y la clave pública correspondiente a la firma. Nunca copie una clave privada al repositorio ni a la evidencia.

Los eventos pueden consultarse por categoría, acción, actor, sujeto, `trace_id`, fechas y resultado. Use paginación por cursor y, para un intervalo grande, exporte por partes consecutivas.

## 3. Verificación offline

La verificación no necesita el servidor ni la base de datos en ejecución. Sobre un archivo exportado:

```text
cercano-audit verify evidencia.jsonl --pubkey <clave_publica_hex>
```

El comando comprueba continuidad de secuencia, canonicalización y enlaces SHA-256. Para validar las firmas digitales Ed25519 de los checkpoints incluidos, es imprescindible proporcionar la clave pública mediante el argumento obligatorio `--pubkey <hex>`. Si se omite `--pubkey`, el comando valida únicamente la integridad de la cadena de hashes, advirtiendo que las firmas no han sido verificadas. Un código de salida cero significa que la evidencia es verificable; cualquier alteración, borrado, reordenación, truncamiento o firma inválida produce fallo. Conserve también la salida del comando y su versión.

> El formato de entrada debe ser el exportado por Cercano. No reordene líneas ni vuelva a serializar JSON antes de verificar.

## 4. Archivos firmados y retención

Los archivos de archivado deben conservar su compresión, firma, checkpoint y relación con la cadena viva. Para cada archivo registre: período, categorías, primer/último evento, hash del archivo, clave pública, algoritmo, responsable y ubicación secundaria. Pruebe la lectura desde una copia restaurada antes de retirar la copia primaria.

La política de retención aprobada por categoría genera un evento auditable `retention.purge_approved` (con `executed: false`), que documenta formalmente los eventos elegibles para el ciclo de vida sin alterar destructivamente el almacén append-only mientras no exista un mecanismo de truncamiento con checkpoint verificado. No elimine manualmente filas ni archivos.

## 5. Exportación JSONL y CSV

- **JSONL:** formato recomendado para verificación, automatización y SIEM; una línea representa un evento y mantiene los campos de integridad.
- **CSV:** formato de revisión humana e intercambio tabular; incluye neutralización de fórmulas (prefijo `'` en celdas de riesgo) y cabecera de paginación `X-Next-Cursor`. No lo use como sustituto de la prueba firmada si se perdió la información de cadena.

Antes de entregar una exportación, compare cantidad de eventos, rango temporal, primer/último `seq` y hash del archivo con la consulta original. Proteja las exportaciones como datos sensibles y elimínelas conforme a la retención aprobada.

## 6. Integración con SIEM

Cercano incluye exportadores para Syslog RFC 5424 (transporte UDP y TCP operativos; transporte TLS en planificación), JSONL continuo y webhooks con firma criptográfica HMAC-SHA256. El cursor de exportación se persiste atómicamente en base de datos (`audit_export_checkpoint`) para evitar duplicaciones o pérdida de eventos tras reinicios del servicio. Mantenga el archivo local o firmado como fuente de evidencia: un SIEM es una copia operativa, no reemplaza la cadena.

Documente destino, formato, identidad del receptor, ventana de retención y respuesta ante caída. Verifique periódicamente que el número de eventos enviados y aceptados coincida. Una caída no debe provocar pérdida; si la cola no es persistente en la versión instalada, trátela como riesgo y conserve exportaciones locales.

## 7. Trazas de sesión y notas

Use `trace_id` para reunir eventos del cliente, rendezvous/relay, API y consola. Si la versión no puede propagarlo extremo a extremo, aplique únicamente la regla determinista documentada (IDs de controlador/controlado y ventana temporal) y marque la correlación como inferida.

El controlador puede añadir una nota durante o después de la sesión. La nota se almacena como evento nuevo vinculado al `trace_id`; nunca se modifica el evento original. Las notas deben ser objetivas, fechadas y no contener secretos ni datos innecesarios.

### Emisión desde el cliente de escritorio

El cliente envía los eventos heredados a `POST /api/audit/conn`, `POST /api/audit/file` y `POST /api/audit/alarm`. Para que la API los acepte, aprovisione en el cliente la opción de configuración `api-token` con el token de ingestión del servidor; el cliente lo envía como `X-Cercano-Internal-Token` y nunca lo escribe en los registros. Sin ese valor, la API responde 401 y el evento no queda registrado. Use siempre `api-server` sobre HTTPS fuera del laboratorio.

Los eventos de archivo llevan dirección, volumen y, cuando el evento cubre un único fichero con ruta local resoluble, su SHA-256; nunca se envía el contenido. Los lotes multiarchivo conservan el volumen y la lista de nombres, pero no un hash por fichero. El fin de sesión incluye el tipo de conexión (`remote`, `file_transfer`, `port_forward`, `view_camera`, `terminal`); el tipo se confirma en el evento `conn.auth`.

## 8. Gate M1: evidencia de cierre

Para proponer el cierre de F2, el expediente debe incluir:

- resultados TC-F2-030…045 de manipulación, carga, reloj y recuperación de `append`;
- evidencia de que `verify` rechaza alteración, borrado, reordenación y truncamiento;
- matriz de cobertura de eventos al 100 % para `ARQUITECTURA.md` §4;
- pruebas de exportación CSV/JSONL y recepción Syslog/CEF/JSONL/webhook;
- prueba de archivos firmados, retención y purga verificable;
- revisión de seguridad sin hallazgos altos;
- validación de esta guía por un agente externo a F2-14.

Mientras falte cualquiera de estos elementos, el estado correcto es **En verificación**, no **Hecho**.

## 9. Estado y bloqueadores conocidos

F2-14 se encuentra en verificación. F2-05 (hooks del cliente) y F2-13 (pruebas de manipulación, carga y reloj) siguen en verificación, por lo que no se declara cerrado el Gate M1. Además, algunas pruebas Rust pueden no enlazar en Windows si falta `link.exe` de MSVC; registre esa limitación junto con el resultado y repita en un entorno con las herramientas MSVC instaladas.

Referencias: `docs/PLAN-F2-AUDITORIA.md`, `docs/specs/audit-events.md`, `docs/ARQUITECTURA.md` §4 y `docs/status/TAREAS.md`.
